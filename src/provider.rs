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

use anyhow::{bail, Context, Result};

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

// `read` kept temporarily as the historical alias used by `resolve`.
pub use RetrieveOutcome as ReadOutcome;

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

/// Back-compat alias for the previous `read` name; new code should call
/// [`retrieve`] directly.
pub fn read(provider: &Provider, locator: &str) -> Result<RetrieveOutcome> {
    retrieve(provider, locator)
}

/// Confirm the provider's retrieve program exists on PATH (used by `doctor`).
pub fn retrieve_program(provider: &Provider) -> Option<&str> {
    provider.retrieve.first().map(|s| s.as_str())
}

/// Back-compat alias for `retrieve_program`.
pub fn read_program(provider: &Provider) -> Option<&str> {
    retrieve_program(provider)
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
/// The returned map has one entry per request: `Found` when the value
/// appeared in output, `NotFound` when it didn't (the caller decides whether
/// to apply a default or fall back to per-secret retrieve).
///
/// Errors propagate out of `Command::spawn` failures and non-zero exits — the
/// caller is expected to fall back to per-secret retrieve in those cases.
pub fn retrieve_batch(
    provider: &Provider,
    requests: &[(String, String)],
) -> Result<BTreeMap<String, RetrieveOutcome>> {
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

    let output = cmd.output().map_err(|e| {
        anyhow::anyhow!(
            "provider `{}`: failed to run `{}`: {e} (is it installed and on PATH?)",
            provider.name,
            program
        )
    })?;

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

    let text = String::from_utf8(output.stdout).with_context(|| {
        format!(
            "provider `{}` retrieve_batch returned non-UTF-8 output",
            provider.name
        )
    })?;

    // Parse KEY=VALUE per line; keep only lines whose key was requested. The
    // batch command (e.g. `printenv`) emits the entire inherited env, so most
    // lines we see are noise.
    let requested: std::collections::BTreeSet<&str> =
        requests.iter().map(|(n, _)| n.as_str()).collect();
    let mut found: BTreeMap<String, RetrieveOutcome> = BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if requested.contains(k) {
                found.insert(
                    k.to_owned(),
                    RetrieveOutcome::Found(SecretValue::new(v.to_owned())),
                );
            }
        }
    }
    // Requests that didn't appear in the output get NotFound; the caller
    // applies the default or hard-errors per the resolution rules. This
    // doubles as the multi-line-value safety net: a value with an internal
    // newline would mis-parse, leaving its name missing from `found`, which
    // tells the resolver to fall back to per-secret retrieve.
    for (name, _) in requests {
        found
            .entry(name.clone())
            .or_insert_with(|| RetrieveOutcome::NotFound {
                status: "not present in batch output (multi-line value? command misconfigured?)"
                    .to_owned(),
                stderr: String::new(),
            });
    }
    Ok(found)
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

    let mut cmd = Command::new(program);
    cmd.args(args);
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
fn substitute_fields_and_value(
    template: &[String],
    fields: &BTreeMap<String, String>,
    value: &SecretValue,
    mode: ValueMode,
) -> Vec<String> {
    template
        .iter()
        .map(|arg| {
            let mut s = arg.clone();
            for (key, val) in fields {
                s = s.replace(&format!("{{{key}}}"), val);
            }
            if mode == ValueMode::Arg {
                s = s.replace(VALUE_PLACEHOLDER, value.expose());
            }
            s
        })
        .collect()
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
        let out = retrieve_batch(&p, &reqs).unwrap();
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
        let out = retrieve_batch(&p, &reqs).unwrap();
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
        let out = retrieve_batch(&p, &reqs).unwrap();
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
