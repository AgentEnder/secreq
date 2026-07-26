//! Tier-1 declarative provider execution (§6).
//!
//! A provider has two capabilities:
//! - **retrieve** — required. `provider.retrieve` is an argv template with a
//!   `{locator}` placeholder; the command is run and its stdout is the secret
//!   value (one trailing newline stripped, matching `op read`/`security`).
//! - **store** — optional. `provider.store` (if present) is a [write
//!   capability descriptor](crate::manifest::StoreCapability): an argv template
//!   with `{field}` placeholders, a declared field schema, a value-delivery
//!   mode (argv or stdin), and a template that builds the retrieve-side
//!   locator from the same field inputs so a later [`retrieve`] finds it.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::manifest::{BatchRetrieve, Provider, StoreCapability, ValueMode};
use crate::secret::SecretValue;

/// Placeholder substituted by the secret's locator in a `retrieve` template.
const LOCATOR_PLACEHOLDER: &str = "{locator}";

/// Placeholder substituted by the secret value in a `store` template when its
/// `value_mode` is [`ValueMode::Arg`].
const VALUE_PLACEHOLDER: &str = "{value}";

/// Outcome of attempting to resolve one secret through its provider.
///
/// `Debug` is safe to derive because `SecretValue`'s own `Debug` redacts the
/// inner string — the formatted output is `Found(SecretValue(***))`, never
/// the actual value. The derive is required for `unwrap`/`expect` callers
/// (mostly tests) to produce useful error messages.
#[derive(Debug)]
pub enum RetrieveOutcome {
    /// The provider returned a value.
    Found(SecretValue),
    /// The provider ran but reported the secret as absent (non-zero exit).
    NotFound { status: String, stderr: String },
}

/// Wall-clock breakdown of one [`retrieve_batch`] call.
///
/// `subprocess` is the load-bearing figure for a slow 1Password read: it's
/// the time spent in the provider's batch command (e.g. `op run … printenv`),
/// which is where `op` resolves every `op://` reference. `parse` is the time
/// spent splitting that command's stdout back into `KEY=VALUE` pairs — it
/// should be negligible, and a surprising value there points at pathological
/// output size rather than at 1Password itself.
#[derive(Clone, Copy, Debug)]
pub struct BatchTiming {
    /// Time the batch subprocess (e.g. `op run … printenv`) took to run.
    pub subprocess: Duration,
    /// Time spent parsing the subprocess's stdout into resolved values.
    pub parse: Duration,
}

/// Everything one [`retrieve_batch`] call produced.
///
/// The resolver holds this across the salvage-and-fold stretch that follows a
/// batch, so the pair wants a name there rather than an
/// `Option<(BTreeMap<…>, BatchTiming)>` whose halves are told apart by
/// position. It also lets each half carry its own contract in rustdoc instead
/// of both being described in [`retrieve_batch`]'s prose.
#[derive(Debug)]
pub struct RetrievedBatch {
    /// One entry per request: `Found` when the value appeared in the batch
    /// output, `NotFound` when it didn't. A `NotFound` here is not a failure —
    /// it tells the resolver to apply a default or retry that name through a
    /// per-secret retrieve, which is also how a multi-line value gets salvaged.
    pub outcomes: BTreeMap<String, RetrieveOutcome>,
    /// Where the wall-clock went, for the daemon's `resolve` log line.
    pub timing: BatchTiming,
}

/// Run `provider`'s retrieve template against `locator`.
///
/// Returns [`RetrieveOutcome::NotFound`] when the command runs but exits
/// non-zero (the store doesn't have it); returns `Err` only when the command
/// could not be executed at all (e.g. the provider CLI is not installed).
pub fn retrieve(provider: &Provider, locator: &str) -> Result<RetrieveOutcome> {
    let argv = substitute_locator(&provider.retrieve, locator);
    let (program, args) = argv
        .split_first()
        .context("provider retrieve template is empty")?;

    let output = Command::new(program)
        .args(args)
        // Mark this as an internal secreq resolution so a wrapped provider
        // CLI (e.g. `op`) passes through instead of re-gating. See
        // `crate::RESOLVING_ENV`.
        .env(crate::RESOLVING_ENV, "1")
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "provider `{}`: failed to run `{}`: {e} (is it installed and on PATH?)",
                provider.name,
                program
            )
        })?;

    if output.status.success() {
        let value = strip_one_trailing_newline(output.stdout);
        let text = String::from_utf8(value)
            .with_context(|| format!("provider `{}` returned non-UTF-8 output", provider.name))?;
        Ok(RetrieveOutcome::Found(SecretValue::new(text)))
    } else {
        Ok(RetrieveOutcome::NotFound {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

/// Confirm the provider's retrieve program exists on PATH (used by `doctor`).
pub fn retrieve_program(provider: &Provider) -> Option<&str> {
    provider.retrieve.first().map(std::string::String::as_str)
}

/// Reject an empty argv early with a clear message.
pub fn validate(provider: &Provider) -> Result<()> {
    if provider.retrieve.is_empty() {
        bail!(
            "provider `{}` has an empty retrieve template",
            provider.name
        );
    }
    Ok(())
}

// ── retrieve_batch: resolve many secrets in one invocation ────────────────

/// Resolve every `(name, locator)` in `requests` through `provider`'s
/// [`BatchRetrieve`] capability in a single process invocation. The classic
/// use case is `op run -- printenv`, which resolves every `op://` ref in env
/// after one biometric prompt regardless of how many secrets are involved.
///
/// **Protocol** (see [`BatchRetrieve`] docs):
/// 1. Each `(name, locator)` becomes a synthetic env entry `name=value`,
///    where `value` is `env_value_template` with `{locator}` substituted.
/// 2. `command` is spawned with the inherited environment plus those entries.
/// 3. The child's stdout is parsed as `KEY=VALUE` lines; lines whose key
///    matches one of our requested names yield the resolved value.
///
/// See [`RetrievedBatch`] for what comes back: an outcome per request, plus
/// the [`BatchTiming`] the daemon logs so a slow read can be attributed to the
/// provider subprocess rather than to our own parsing.
///
/// Errors propagate out of `Command::spawn` failures and non-zero exits — the
/// caller is expected to fall back to per-secret retrieve in those cases.
pub fn retrieve_batch(
    provider: &Provider,
    requests: &[(String, String)],
) -> Result<RetrievedBatch> {
    let cap: &BatchRetrieve = provider.retrieve_batch.as_ref().with_context(|| {
        format!(
            "provider `{}` has no retrieve_batch capability",
            provider.name
        )
    })?;
    let (program, args) = cap
        .command
        .split_first()
        .context("retrieve_batch command is empty")?;

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Internal resolution marker — see `crate::RESOLVING_ENV`.
        .env(crate::RESOLVING_ENV, "1");
    // Layer synthetic env on top of the inherited environment.
    for (name, locator) in requests {
        let val = cap.env_value_template.replace("{locator}", locator);
        cmd.env(name, val);
    }

    let subprocess_started = Instant::now();
    let output = cmd.output().map_err(|e| {
        anyhow::anyhow!(
            "provider `{}`: failed to run `{}`: {e} (is it installed and on PATH?)",
            provider.name,
            program
        )
    })?;
    let subprocess = subprocess_started.elapsed();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        bail!(
            "provider `{}` retrieve_batch failed ({}){}",
            provider.name,
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }

    let parse_started = Instant::now();
    // The batch's whole stdout: every requested value, in plaintext, in one
    // buffer — the largest single plaintext allocation on the resolve path, and
    // it outlives each individual `SecretValue` built out of it. `Zeroizing`
    // for the reason `secret.rs` gives. `String::from_utf8` reuses the `Vec`'s
    // allocation rather than copying, so this wraps the buffer the child's
    // output was read into, not a copy of it.
    //
    // The scrub is a volatile byte-wise memset — measured ~1.8 GB/s, so ~36µs
    // for a 64 KiB `printenv` dump — charged once per batch, after `parse`
    // below is taken. It is invisible to `BatchTiming` for that reason, and
    // four orders of magnitude under the subprocess it follows.
    let text = Zeroizing::new(String::from_utf8(output.stdout).with_context(|| {
        format!(
            "provider `{}` retrieve_batch returned non-UTF-8 output",
            provider.name
        )
    })?);

    // Parse KEY=VALUE per line; keep only lines whose key was requested. The
    // batch command (e.g. `printenv`) emits the entire inherited env, so most
    // lines we see are noise.
    let requested: std::collections::BTreeSet<&str> =
        requests.iter().map(|(n, _)| n.as_str()).collect();
    let mut outcomes: BTreeMap<String, RetrieveOutcome> = BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if requested.contains(k) {
                outcomes.insert(
                    k.to_owned(),
                    RetrieveOutcome::Found(SecretValue::new(v.to_owned())),
                );
            }
        }
    }
    // Requests that didn't appear in the output get NotFound; the caller
    // applies the default or hard-errors per the resolution rules. This
    // doubles as the multi-line-value safety net: a value with an internal
    // newline would mis-parse, leaving its name missing from `outcomes`, which
    // tells the resolver to fall back to per-secret retrieve.
    for (name, _) in requests {
        outcomes
            .entry(name.clone())
            .or_insert_with(|| RetrieveOutcome::NotFound {
                status: "not present in batch output (multi-line value? command misconfigured?)"
                    .to_owned(),
                stderr: String::new(),
            });
    }
    let parse = parse_started.elapsed();
    Ok(RetrievedBatch {
        outcomes,
        timing: BatchTiming { subprocess, parse },
    })
}

// ── store: persist a new value through a provider ─────────────────────────

/// Persist `value` through `provider`'s store capability.
///
/// Validates `field_inputs` against the provider's [`StoreCapability::fields`]
/// schema (filling in defaults, erroring on missing required), substitutes
/// `{field}` placeholders into the command argv, delivers the value per the
/// capability's [`ValueMode`], and returns the computed retrieve-locator
/// (built from `locator_template` with the same field substitutions).
///
/// Errors if the provider has no `store` capability declared, if a required
/// field is missing, or if the underlying command fails.
pub fn store(
    provider: &Provider,
    field_inputs: &BTreeMap<String, String>,
    value: &SecretValue,
) -> Result<String> {
    let cap = provider
        .store
        .as_ref()
        .with_context(|| format!("provider `{}` has no `store` capability", provider.name))?;

    let resolved = resolve_fields(&provider.name, cap, field_inputs)?;
    let argv = substitute_fields_and_value(&cap.command, &resolved, value, cap.value_mode);
    let (program, args) = argv
        .split_first()
        .context("provider store template is empty")?;
    let program = program.as_str();

    let mut cmd = Command::new(program);
    cmd.args(args.iter().map(|arg| arg.as_str()));
    // Internal resolution marker — see `crate::RESOLVING_ENV`.
    cmd.env(crate::RESOLVING_ENV, "1");
    if cap.value_mode == ValueMode::Stdin {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| {
        anyhow::anyhow!(
            "provider `{}`: failed to run `{}`: {e} (is it installed and on PATH?)",
            provider.name,
            program
        )
    })?;

    if cap.value_mode == ValueMode::Stdin {
        let mut stdin = child
            .stdin
            .take()
            .context("internal: failed to open child stdin")?;
        stdin.write_all(value.expose().as_bytes())?;
        // Some CLIs (e.g. `pass insert -e`) read a single line; ensure newline.
        if !value.expose().ends_with('\n') {
            stdin.write_all(b"\n")?;
        }
        drop(stdin); // closes stdin so the child sees EOF
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        bail!(
            "provider `{}` store failed ({}){}",
            provider.name,
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }

    Ok(substitute_fields(&cap.locator_template, &resolved))
}

/// Persist `value` at exactly `locator` through `provider`'s store capability.
///
/// The bridge feature 1 (`secreq run --prompt-unresolved`) builds on: given a
/// `secret://provider/locator` reference that resolves to nothing, we want to
/// write the freshly-prompted value to *where the locator points* so the next
/// run resolves it normally. To do that we run [`store`] "backwards": the store
/// capability's `locator_template` describes how a locator is *built* from the
/// field inputs, so we parse `locator` against that template to recover those
/// same field inputs ([`fields_from_locator`]), then call [`store`] with them.
///
/// Errors when the provider is read-only (no `store` capability), when the
/// locator doesn't match the store's `locator_template`, when a required store
/// field isn't captured by the template (surfaced by [`store`]'s own field
/// validation — e.g. keychain's `account`, which its `{service}` template can't
/// recover), or when the underlying store command fails.
pub fn store_at_locator(provider: &Provider, locator: &str, value: &SecretValue) -> Result<()> {
    let cap = provider.store.as_ref().with_context(|| {
        format!(
            "provider `{}` is read-only (no `store` capability); cannot save a value for `{locator}`",
            provider.name
        )
    })?;
    let fields = fields_from_locator(cap, locator)?;
    let computed = store(provider, &fields, value)?;
    // The retrieve-locator `store` computed must point back at exactly where we
    // were asked to write, or a subsequent resolve won't find the value. If a
    // provider's `locator_template` doesn't round-trip (e.g. it references a
    // field the template can't recover), fail loudly rather than silently
    // writing to the wrong address.
    if computed != locator {
        bail!(
            "provider `{}`: stored value's retrieve-locator `{computed}` does not match the \
             requested locator `{locator}` (the store `locator_template` does not round-trip)",
            provider.name
        );
    }
    Ok(())
}

/// Recover a [`StoreCapability`]'s field inputs by parsing `locator` against
/// its `locator_template` — the inverse of the `{field}` substitution [`store`]
/// applies when it *builds* a locator.
///
/// The template is a sequence of literal spans and `{field}` placeholders
/// (e.g. `{name}`, or `{vault}/{item}/{field}`). Each placeholder's value is
/// the text between its surrounding literals: a trailing placeholder takes the
/// rest of the locator, and an interior one runs up to the next literal.
///
/// Only fields the template mentions are recovered; a required store field the
/// template doesn't reference (keychain's `account`) is left for [`store`]'s
/// own `resolve_fields` to flag. Two adjacent placeholders with no literal
/// between them are genuinely ambiguous and error here.
pub fn fields_from_locator(
    cap: &StoreCapability,
    locator: &str,
) -> Result<BTreeMap<String, String>> {
    let tokens = tokenize_locator_template(&cap.locator_template);
    let mut fields = BTreeMap::new();
    let mut rest = locator;
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            TemplateToken::Literal(lit) => {
                rest = rest.strip_prefix(lit.as_str()).with_context(|| {
                    format!(
                        "locator `{locator}` does not match store template `{}` \
                         (expected literal `{lit}`)",
                        cap.locator_template
                    )
                })?;
                i += 1;
            }
            TemplateToken::Field(name) => match tokens.get(i + 1) {
                None => {
                    // Trailing placeholder: it takes whatever is left.
                    fields.insert(name.clone(), rest.to_owned());
                    rest = "";
                    i += 1;
                }
                Some(TemplateToken::Literal(lit)) => {
                    let idx = rest.find(lit.as_str()).with_context(|| {
                        format!(
                            "locator `{locator}` does not match store template `{}` \
                             (looking for `{lit}` after `{{{name}}}`)",
                            cap.locator_template
                        )
                    })?;
                    fields.insert(name.clone(), rest[..idx].to_owned());
                    rest = &rest[idx..];
                    i += 1;
                }
                Some(TemplateToken::Field(_)) => {
                    bail!(
                        "store template `{}` has adjacent placeholders with no separator; \
                         cannot unambiguously recover fields from locator `{locator}`",
                        cap.locator_template
                    );
                }
            },
        }
    }
    if !rest.is_empty() {
        bail!(
            "locator `{locator}` has trailing content `{rest}` not matched by store template `{}`",
            cap.locator_template
        );
    }
    Ok(fields)
}

/// One span of a `locator_template`: literal text or a `{field}` placeholder.
#[derive(Debug, PartialEq)]
enum TemplateToken {
    Literal(String),
    Field(String),
}

/// Split a `locator_template` into its literal and `{field}` spans. Mirrors the
/// `{key}` replacement [`substitute_fields`] performs: an unclosed `{` is
/// treated as literal text.
fn tokenize_locator_template(template: &str) -> Vec<TemplateToken> {
    let mut tokens = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        if open > 0 {
            tokens.push(TemplateToken::Literal(rest[..open].to_owned()));
        }
        if let Some(close_rel) = rest[open..].find('}') {
            let close = open + close_rel;
            tokens.push(TemplateToken::Field(rest[open + 1..close].to_owned()));
            rest = &rest[close + 1..];
        } else {
            // No closing brace — the remainder is literal.
            tokens.push(TemplateToken::Literal(rest[open..].to_owned()));
            rest = "";
            break;
        }
    }
    if !rest.is_empty() {
        tokens.push(TemplateToken::Literal(rest.to_owned()));
    }
    tokens
}

/// Apply the provider's field schema to the caller's inputs: defaults fill in
/// for absent fields; required fields with no input and no default error.
fn resolve_fields(
    provider_name: &str,
    cap: &StoreCapability,
    inputs: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (field_name, spec) in &cap.fields {
        if let Some(value) = inputs.get(field_name) {
            out.insert(field_name.clone(), value.clone());
        } else if let Some(default) = &spec.default {
            out.insert(field_name.clone(), default.clone());
        } else if spec.required {
            bail!(
                "provider `{provider_name}`.store requires field `{field_name}` (pass it as `--field {field_name}=…`)"
            );
        }
    }
    // Accept extra inputs the schema doesn't know about — they just stay
    // unsubstituted in the template (no-op). That's friendlier than erroring
    // if the user passes a field the provider doesn't declare.
    for (k, v) in inputs {
        out.entry(k.clone()).or_insert_with(|| v.clone());
    }
    Ok(out)
}

/// Substitute `{locator}` into every arg.
fn substitute_locator(template: &[String], locator: &str) -> Vec<String> {
    template
        .iter()
        .map(|arg| arg.replace(LOCATOR_PLACEHOLDER, locator))
        .collect()
}

/// Substitute `{field}` placeholders into a single template string.
fn substitute_fields(template: &str, fields: &BTreeMap<String, String>) -> String {
    let mut out = template.to_owned();
    for (key, value) in fields {
        out = out.replace(&format!("{{{key}}}"), value);
    }
    out
}

/// Substitute `{field}` placeholders into the argv. When `mode == Arg`, also
/// substitute `{value}` in argv; when `Stdin`, `{value}` is left in place so a
/// stray literal in argv is visible (rather than silently swallowed).
///
/// The elements are [`Zeroizing`] because under [`ValueMode::Arg`] one of them
/// holds the plaintext value, and the property belongs on the type rather than
/// on a scrub at this one call site — the same choice `exec.rs` and `mask.rs`
/// made. Under [`ValueMode::Stdin`] nothing here is secret and the wrapper
/// costs a memset of a template string; a uniform return type is worth more
/// than that. Note this scrubs *our* copy only: [`store`] hands these to
/// `Command`, which keeps its own `CString` of every argument, and under `Arg`
/// the value then lands in a child's argv where the process table has it. See
/// `secret.rs`.
fn substitute_fields_and_value(
    template: &[String],
    fields: &BTreeMap<String, String>,
    value: &SecretValue,
    mode: ValueMode,
) -> Vec<Zeroizing<String>> {
    template
        .iter()
        .map(|arg| {
            let mut s = arg.clone();
            for (key, val) in fields {
                s = s.replace(&format!("{{{key}}}"), val);
            }
            if mode == ValueMode::Arg {
                // Field substitution runs first deliberately: every `replace`
                // drops the string it replaced, so doing the value last means
                // no intermediate ever held the plaintext un-zeroized.
                s = s.replace(VALUE_PLACEHOLDER, value.expose());
            }
            Zeroizing::new(s)
        })
        .collect()
}

/// The provider's own URI scheme, read off its `retrieve` template: the
/// literal text preceding `{locator}` in the first argument that mentions it
/// (`"op://{locator}"` → `op://`).
///
/// Only scheme-shaped prefixes (ending in `://`) count. A template like
/// `--secret={locator}` yields `None`, because stripping a flag off a pasted
/// locator would be a false positive; a bare `{locator}` yields `None` too.
pub fn native_locator_prefix(provider: &Provider) -> Option<&str> {
    let arg = provider
        .retrieve
        .iter()
        .find(|arg| arg.contains(LOCATOR_PLACEHOLDER))?;
    let prefix = &arg[..arg.find(LOCATOR_PLACEHOLDER)?];
    prefix.ends_with("://").then_some(prefix)
}

/// Clean up a locator a human pasted into a prompt.
///
/// Every affordance a store gives you hands over a *native reference*, not the
/// bare locator our templates want: 1Password's "Copy Secret Reference" yields
/// `op://Vault/Item/field`, and its docs show it quoted inside `op read "…"`.
/// Substituted raw into `op://{locator}`, that produces the doubled nonsense
/// `op://"op://Vault/Item/field"`, which `op` rejects. So we peel, in order:
/// surrounding whitespace, one layer of matched quotes, then whichever prefix
/// applies — our own `secret://<provider>/` or the provider's native scheme.
///
/// Only the *selected* provider's scheme is stripped. A locator carrying some
/// other store's scheme passes through untouched, for the caller's
/// resolvability check to flag.
pub fn normalize_pasted_locator(provider: &Provider, raw: &str) -> String {
    let mut s = raw.trim();

    // One layer of matched quotes — `op`'s own docs quote the reference.
    for quote in ['"', '\''] {
        if let Some(inner) = s.strip_prefix(quote).and_then(|r| r.strip_suffix(quote)) {
            s = inner.trim();
            break;
        }
    }

    // Our own ref form, e.g. `secret://op/Vault/Item/field`.
    let ours = format!("{}{}/", crate::reference::SCHEME, provider.name);
    if let Some(rest) = s.strip_prefix(&ours) {
        return rest.to_owned();
    }

    // The provider's native scheme, e.g. `op://Vault/Item/field`.
    if let Some(prefix) = native_locator_prefix(provider) {
        if let Some(rest) = s.strip_prefix(prefix) {
            return rest.to_owned();
        }
    }

    s.to_owned()
}

/// Strip exactly one trailing line ending (`\n` or `\r\n`). Stores append a
/// newline to the value; we remove just that one, never trimming real content.
fn strip_one_trailing_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{FieldSpec, StoreCapability};

    fn retrieve_only_provider(retrieve: &[&str]) -> Provider {
        Provider {
            name: "test".to_owned(),
            retrieve: retrieve.iter().map(|s| (*s).to_owned()).collect(),
            store: None,
            retrieve_batch: None,
        }
    }

    fn op_provider() -> Provider {
        retrieve_only_provider(&["op", "read", "op://{locator}"])
    }

    #[test]
    fn native_prefix_is_read_off_the_retrieve_template() {
        assert_eq!(native_locator_prefix(&op_provider()), Some("op://"));
    }

    #[test]
    fn native_prefix_is_absent_when_the_template_takes_a_bare_locator() {
        let keychain = retrieve_only_provider(&["security", "find-generic-password", "{locator}"]);
        assert_eq!(native_locator_prefix(&keychain), None);
    }

    #[test]
    fn native_prefix_ignores_non_scheme_literals() {
        // `--secret=` is a flag, not a URI scheme; stripping it off a pasted
        // locator would be a false positive.
        let odd = retrieve_only_provider(&["vault", "--secret={locator}"]);
        assert_eq!(native_locator_prefix(&odd), None);
    }

    #[test]
    fn normalize_leaves_a_plain_locator_untouched() {
        assert_eq!(
            normalize_pasted_locator(&op_provider(), "Private/GitHub CLI PAT/token"),
            "Private/GitHub CLI PAT/token"
        );
    }

    #[test]
    fn normalize_strips_the_providers_own_scheme() {
        assert_eq!(
            normalize_pasted_locator(&op_provider(), "op://Private/GitHub CLI PAT/token"),
            "Private/GitHub CLI PAT/token"
        );
    }

    #[test]
    fn normalize_strips_quotes_around_a_pasted_native_ref() {
        // The reported bug: 1Password hands over a quoted `op://…` reference,
        // which used to be re-prefixed into `op://"op://…"`.
        assert_eq!(
            normalize_pasted_locator(&op_provider(), "\"op://Private/GitHub CLI PAT/token\""),
            "Private/GitHub CLI PAT/token"
        );
        assert_eq!(
            normalize_pasted_locator(&op_provider(), "'op://Private/GitHub CLI PAT/token'"),
            "Private/GitHub CLI PAT/token"
        );
    }

    #[test]
    fn normalize_strips_our_own_secret_scheme_for_this_provider() {
        assert_eq!(
            normalize_pasted_locator(&op_provider(), "secret://test/Private/GitHub/token"),
            "Private/GitHub/token"
        );
    }

    #[test]
    fn normalize_trims_surrounding_whitespace() {
        assert_eq!(
            normalize_pasted_locator(&op_provider(), "  op://Private/GitHub/token \n"),
            "Private/GitHub/token"
        );
    }

    #[test]
    fn normalize_keeps_another_providers_scheme_as_a_literal_locator() {
        // Only the selected provider's own prefix is stripped; anything else
        // passes through so the caller's resolvability check can flag it.
        let keychain = retrieve_only_provider(&["security", "{locator}"]);
        assert_eq!(
            normalize_pasted_locator(&keychain, "op://Private/GitHub/token"),
            "op://Private/GitHub/token"
        );
    }

    #[test]
    fn normalize_does_not_strip_a_scheme_from_the_middle_of_a_locator() {
        assert_eq!(
            normalize_pasted_locator(&op_provider(), "Private/weird op:// name/token"),
            "Private/weird op:// name/token"
        );
    }

    #[test]
    fn pasted_native_ref_no_longer_doubles_the_scheme_in_the_final_argv() {
        // Regression: pasting 1Password's quoted reference straight into the
        // `wrap` locator prompt used to build `op read op://"op://…"`, which
        // op rejected with `invalid character in secret reference: '"'`.
        let op = op_provider();
        let pasted = "\"op://Private/GitHub CLI PAT/token\"";
        let argv = substitute_locator(&op.retrieve, &normalize_pasted_locator(&op, pasted));
        assert_eq!(
            argv,
            vec!["op", "read", "op://Private/GitHub CLI PAT/token"]
        );
    }

    #[test]
    fn substitutes_locator_into_template() {
        assert_eq!(
            substitute_locator(&["echo".into(), "op://{locator}".into()], "Work/Stripe/key"),
            vec!["echo", "op://Work/Stripe/key"]
        );
    }

    #[test]
    fn strips_a_single_trailing_newline_only() {
        assert_eq!(strip_one_trailing_newline(b"value\n".to_vec()), b"value");
        assert_eq!(strip_one_trailing_newline(b"value\r\n".to_vec()), b"value");
        assert_eq!(
            strip_one_trailing_newline(b"value\n\n".to_vec()),
            b"value\n"
        );
        assert_eq!(strip_one_trailing_newline(b"value".to_vec()), b"value");
    }

    #[test]
    fn retrieve_returns_value_from_command_stdout() {
        // `printf` echoes the locator exactly — a stand-in provider.
        let p = retrieve_only_provider(&["printf", "%s", "{locator}"]);
        match retrieve(&p, "s3cr3t").unwrap() {
            RetrieveOutcome::Found(v) => assert_eq!(v.expose(), "s3cr3t"),
            RetrieveOutcome::NotFound { .. } => panic!("expected Found"),
        }
    }

    #[test]
    fn retrieve_sets_the_recursion_guard_env_on_the_child() {
        // The provider subprocess must run with SECREQ_RESOLVING set so a
        // wrapped provider CLI (e.g. `op`) passes through instead of
        // re-gating. We prove it by having the "provider" echo the var.
        let p = retrieve_only_provider(&["sh", "-c", "printf %s \"$SECREQ_RESOLVING\""]);
        match retrieve(&p, "ignored").unwrap() {
            RetrieveOutcome::Found(v) => assert_eq!(v.expose(), "1"),
            RetrieveOutcome::NotFound { .. } => panic!("expected Found"),
        }
    }

    #[test]
    fn retrieve_reports_not_found_on_nonzero_exit() {
        let p = retrieve_only_provider(&["false", "{locator}"]);
        match retrieve(&p, "missing").unwrap() {
            RetrieveOutcome::NotFound { .. } => {}
            RetrieveOutcome::Found(_) => panic!("expected NotFound"),
        }
    }

    #[test]
    fn retrieve_errors_when_program_missing() {
        let p = retrieve_only_provider(&["secreq-no-such-binary-xyz", "{locator}"]);
        assert!(retrieve(&p, "x").is_err());
    }

    /// A provider whose `store` command is `sh -c 'cat > FILE'` — captures the
    /// value piped on stdin into a file we can inspect.
    fn stdin_capture_provider(file: &std::path::Path) -> Provider {
        Provider {
            name: "stdin-cap".to_owned(),
            retrieve: vec!["printf".into(), "%s".into(), "{locator}".into()],
            store: Some(StoreCapability {
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    format!("cat > {}", file.display()),
                ],
                fields: BTreeMap::from([(
                    "name".to_owned(),
                    FieldSpec {
                        required: true,
                        default: None,
                    },
                )]),
                value_mode: ValueMode::Stdin,
                locator_template: "{name}".to_owned(),
            }),
            retrieve_batch: None,
        }
    }

    #[test]
    fn store_with_stdin_value_pipes_value_and_returns_computed_locator() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("captured");
        let p = stdin_capture_provider(&target);
        let value = SecretValue::new("hunter2".to_owned());
        let fields = BTreeMap::from([("name".to_owned(), "myservice".to_owned())]);

        let locator = store(&p, &fields, &value).unwrap();
        assert_eq!(locator, "myservice", "locator_template substitution");
        let written = std::fs::read_to_string(&target).unwrap();
        // The provider got the value via stdin, NOT via argv.
        assert_eq!(written.trim_end_matches('\n'), "hunter2");
    }

    #[test]
    fn store_with_arg_value_substitutes_into_argv() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("captured");
        let p = Provider {
            name: "arg-cap".to_owned(),
            retrieve: vec!["printf".into(), "%s".into(), "{locator}".into()],
            store: Some(StoreCapability {
                // Writes the substituted value into a file via argv.
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    format!("printf %s \"$0\" > {}", target.display()),
                    "{value}".into(),
                ],
                fields: BTreeMap::from([(
                    "key".to_owned(),
                    FieldSpec {
                        required: true,
                        default: None,
                    },
                )]),
                value_mode: ValueMode::Arg,
                locator_template: "{key}".to_owned(),
            }),
            retrieve_batch: None,
        };
        let fields = BTreeMap::from([("key".to_owned(), "k1".to_owned())]);
        let value = SecretValue::new("argvalue".to_owned());
        let locator = store(&p, &fields, &value).unwrap();
        assert_eq!(locator, "k1");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "argvalue");
    }

    #[test]
    fn store_errors_when_required_field_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = stdin_capture_provider(&dir.path().join("x"));
        let err = store(&p, &BTreeMap::new(), &SecretValue::new("v".into())).unwrap_err();
        assert!(err.to_string().contains("requires field `name`"));
    }

    #[test]
    fn store_errors_when_provider_has_no_store_capability() {
        let p = retrieve_only_provider(&["printf", "%s", "{locator}"]);
        let err = store(&p, &BTreeMap::new(), &SecretValue::new("v".into())).unwrap_err();
        assert!(err.to_string().contains("no `store` capability"));
    }

    fn store_cap(locator_template: &str, fields: &[(&str, FieldSpec)]) -> StoreCapability {
        StoreCapability {
            command: vec!["true".into()],
            fields: fields
                .iter()
                .map(|(n, s)| ((*n).to_owned(), s.clone()))
                .collect(),
            value_mode: ValueMode::Stdin,
            locator_template: locator_template.to_owned(),
        }
    }

    #[test]
    fn fields_from_locator_recovers_a_single_whole_field() {
        // The `pass`/`op` shape: `locator_template: "{name}"`.
        let cap = store_cap("{name}", &[("name", FieldSpec::default())]);
        let fields = fields_from_locator(&cap, "myservice").unwrap();
        assert_eq!(
            fields,
            BTreeMap::from([("name".to_owned(), "myservice".to_owned())])
        );
    }

    #[test]
    fn fields_from_locator_splits_on_interior_literals() {
        let cap = store_cap(
            "{vault}/{item}/{field}",
            &[
                ("vault", FieldSpec::default()),
                ("item", FieldSpec::default()),
                ("field", FieldSpec::default()),
            ],
        );
        let fields = fields_from_locator(&cap, "Work/Stripe/api_key").unwrap();
        assert_eq!(
            fields,
            BTreeMap::from([
                ("vault".to_owned(), "Work".to_owned()),
                ("item".to_owned(), "Stripe".to_owned()),
                ("field".to_owned(), "api_key".to_owned()),
            ])
        );
    }

    #[test]
    fn fields_from_locator_honors_leading_and_trailing_literals() {
        let cap = store_cap("kv/{name}.txt", &[("name", FieldSpec::default())]);
        let fields = fields_from_locator(&cap, "kv/token.txt").unwrap();
        assert_eq!(
            fields,
            BTreeMap::from([("name".to_owned(), "token".to_owned())])
        );
    }

    #[test]
    fn fields_from_locator_recovers_only_templated_fields() {
        // keychain: `{service}` template, but `account` is also a store field.
        // We recover `service`; `account` is left for `store` to flag.
        let cap = store_cap(
            "{service}",
            &[
                (
                    "service",
                    FieldSpec {
                        required: true,
                        default: None,
                    },
                ),
                (
                    "account",
                    FieldSpec {
                        required: true,
                        default: None,
                    },
                ),
            ],
        );
        let fields = fields_from_locator(&cap, "github.com").unwrap();
        assert_eq!(
            fields,
            BTreeMap::from([("service".to_owned(), "github.com".to_owned())])
        );
        assert!(!fields.contains_key("account"));
    }

    #[test]
    fn fields_from_locator_errors_on_a_missing_literal() {
        let cap = store_cap("{vault}/{item}", &[]);
        let err = fields_from_locator(&cap, "no-slash-here").unwrap_err();
        assert!(err.to_string().contains("does not match store template"));
    }

    #[test]
    fn fields_from_locator_errors_on_adjacent_placeholders() {
        let cap = store_cap("{a}{b}", &[]);
        let err = fields_from_locator(&cap, "whatever").unwrap_err();
        assert!(err.to_string().contains("adjacent placeholders"));
    }

    #[test]
    fn store_at_locator_writes_and_round_trips_the_locator() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("captured");
        let p = stdin_capture_provider(&target);
        store_at_locator(&p, "myservice", &SecretValue::new("hunter2".into())).unwrap();
        let written = std::fs::read_to_string(&target).unwrap();
        assert_eq!(written.trim_end_matches('\n'), "hunter2");
    }

    #[test]
    fn store_at_locator_errors_on_a_read_only_provider() {
        let p = retrieve_only_provider(&["printf", "%s", "{locator}"]);
        let err = store_at_locator(&p, "anything", &SecretValue::new("v".into())).unwrap_err();
        assert!(
            err.to_string().contains("read-only"),
            "expected a read-only error, got: {err}"
        );
    }

    #[test]
    fn store_at_locator_surfaces_a_required_field_the_template_cannot_recover() {
        // A `{service}` template with a second required `account` field: the
        // locator recovers `service` only, so `store` must error on `account`.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("captured");
        let p = Provider {
            name: "keychain-like".to_owned(),
            retrieve: vec!["printf".into(), "%s".into(), "{locator}".into()],
            store: Some(StoreCapability {
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    format!("cat > {}", target.display()),
                ],
                fields: BTreeMap::from([
                    ("service".to_owned(), required_field_spec()),
                    ("account".to_owned(), required_field_spec()),
                ]),
                value_mode: ValueMode::Stdin,
                locator_template: "{service}".to_owned(),
            }),
            retrieve_batch: None,
        };
        let err = store_at_locator(&p, "github.com", &SecretValue::new("v".into())).unwrap_err();
        assert!(
            err.to_string().contains("requires field `account`"),
            "expected the store's required-field error, got: {err}"
        );
    }

    fn required_field_spec() -> FieldSpec {
        FieldSpec {
            required: true,
            default: None,
        }
    }

    fn batch_provider_echoing_env() -> Provider {
        // Test stand-in for `op run -- printenv`: a shell that simply echoes
        // its inherited environment as `KEY=VALUE\n` per entry. Our resolver
        // supplies the synthetic env, so this provider effectively returns
        // whatever locators we asked for as values — perfect for asserting
        // that the batch wiring (env synthesis + parse) works.
        Provider {
            name: "echobatch".to_owned(),
            retrieve: vec!["printf".into(), "%s".into(), "{locator}".into()],
            store: None,
            retrieve_batch: Some(BatchRetrieve {
                command: vec!["sh".into(), "-c".into(), "printenv".into()],
                env_value_template: "echoed::{locator}".to_owned(),
            }),
        }
    }

    #[test]
    fn retrieve_batch_resolves_many_names_in_one_invocation() {
        let p = batch_provider_echoing_env();
        let reqs = vec![
            ("FOO".to_owned(), "foo-locator".to_owned()),
            ("BAR".to_owned(), "bar-locator".to_owned()),
            ("BAZ".to_owned(), "baz-locator".to_owned()),
        ];
        let out = retrieve_batch(&p, &reqs).unwrap().outcomes;
        for (name, locator) in &reqs {
            match out.get(name).unwrap() {
                RetrieveOutcome::Found(v) => {
                    assert_eq!(v.expose(), format!("echoed::{locator}"));
                }
                _ => panic!("expected Found for {name}"),
            }
        }
    }

    #[test]
    fn retrieve_batch_filters_other_env_vars_out_of_results() {
        // The synthetic env layers on top of the inherited env; `printenv`
        // emits the whole lot. We must keep only the requested names.
        let p = batch_provider_echoing_env();
        let reqs = vec![("FOO".to_owned(), "x".to_owned())];
        let out = retrieve_batch(&p, &reqs).unwrap().outcomes;
        assert_eq!(out.len(), 1, "only the requested name should appear");
        assert!(matches!(out.get("FOO"), Some(RetrieveOutcome::Found(_))));
    }

    #[test]
    fn retrieve_batch_marks_names_missing_from_output_as_not_found() {
        // Provider whose command emits only `FOO=…`; BAR is requested but
        // never returned. Caller should see NotFound and can fall back.
        let p = Provider {
            name: "partial".to_owned(),
            retrieve: vec!["true".into()],
            store: None,
            retrieve_batch: Some(BatchRetrieve {
                command: vec!["sh".into(), "-c".into(), "printf 'FOO=only\\n'".into()],
                env_value_template: "{locator}".to_owned(),
            }),
        };
        let reqs = vec![
            ("FOO".to_owned(), "f".to_owned()),
            ("BAR".to_owned(), "b".to_owned()),
        ];
        let out = retrieve_batch(&p, &reqs).unwrap().outcomes;
        assert!(matches!(out.get("FOO"), Some(RetrieveOutcome::Found(_))));
        assert!(matches!(
            out.get("BAR"),
            Some(RetrieveOutcome::NotFound { .. })
        ));
    }

    #[test]
    fn retrieve_batch_errors_on_nonzero_exit_so_resolver_can_fall_back() {
        let p = Provider {
            name: "fail".to_owned(),
            retrieve: vec!["true".into()],
            store: None,
            retrieve_batch: Some(BatchRetrieve {
                command: vec!["false".into()],
                env_value_template: "{locator}".to_owned(),
            }),
        };
        let reqs = vec![("A".to_owned(), "a".to_owned())];
        assert!(retrieve_batch(&p, &reqs).is_err());
    }

    #[test]
    fn retrieve_batch_errors_when_provider_has_no_batch_capability() {
        let p = retrieve_only_provider(&["printf", "%s", "{locator}"]);
        let err = retrieve_batch(&p, &[("A".to_owned(), "a".to_owned())]).unwrap_err();
        assert!(err.to_string().contains("no retrieve_batch capability"));
    }

    #[test]
    fn store_field_default_fills_in_when_input_absent() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("captured");
        let mut p = stdin_capture_provider(&target);
        // Make the field optional with a default.
        let cap = p.store.as_mut().unwrap();
        cap.fields.insert(
            "name".to_owned(),
            FieldSpec {
                required: false,
                default: Some("defaulted".to_owned()),
            },
        );
        let locator = store(&p, &BTreeMap::new(), &SecretValue::new("v".into())).unwrap();
        assert_eq!(locator, "defaulted");
    }
}
