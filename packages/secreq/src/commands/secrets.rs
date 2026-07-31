//! The verbs whose product is a secret *value* rather than a running
//! command: `secreq read`, and the two ends of the remote secret agent —
//! `secreq agent open` on the host and `secreq resolve` in the guest.
//!
//! [`read`] goes through the local consent daemon and prints JSON.
//! [`agent_open`] binds a scoped socket and serves it; [`resolve`] is what
//! a guest runs against that socket. The three share no code on purpose:
//! see [`resolve`]'s "Why this doesn't share `read`'s path".

use std::io::Write as _;
use std::path::Path;

use anyhow::{bail, Context, Result};
use zeroize::Zeroize as _;

use crate::audit::{self, AuditEntry};
use crate::consent::Decision;
use crate::daemon::client as daemon_client;
use crate::provenance;
use crate::reference::Reference;
use crate::scoped_agent::client as agent_client;
use crate::scoped_agent::proto::{Request as AgentRequest, Response as AgentResponse};

use super::{build_ask, load_config_or_default, AskSpec};

/// `secreq agent open --scope <name> --allow <ref>… [--sock <path>]` — bind a
/// scoped, ephemeral socket serving `secret://` refs to a guest, and serve it
/// until the process is interrupted.
///
/// This is the host-side end of the remote secret agent (design:
/// `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md`). The scope name and
/// allowlist are declared here and are immutable for the socket's life; the
/// guest can only ask, never widen. Blocks — the socket's lifetime *is* this
/// process's lifetime — so the caller (brain, at sandbox start) backgrounds
/// it and kills it when the sandbox goes away.
///
/// `sock` is an explicit override; `None` defaults it into
/// [`crate::paths::scoped_agent_socket`], beside every other socket secreq
/// binds. Either way the resolved path is printed to stdout before serving
/// starts, so the caller reads the path back rather than reconstructing it.
pub fn agent_open(
    scope: &str,
    allow: &[String],
    sock: Option<&Path>,
    config_path: Option<&Path>,
) -> Result<i32> {
    // Parse every ref up front so a typo in the host's own declaration fails
    // loudly at open time, rather than turning into a mysterious deny for the
    // guest hours later.
    let mut refs: Vec<Reference> = Vec::with_capacity(allow.len());
    for raw in allow {
        let reference = Reference::parse_arg(raw).with_context(|| {
            format!("`{raw}` is not a valid reference (expected `secret://provider/locator` or `provider/locator`)")
        })?;
        if !refs.contains(&reference) {
            refs.push(reference);
        }
    }

    let scope = crate::scoped_agent::Scope::new(scope, refs)?;
    // An explicit --sock wins: brain picks a path so it can `ssh -R` it into
    // the guest. Otherwise this socket lives where every other secreq socket
    // does, rather than being the one path that ignores `paths`.
    let sock = match sock {
        Some(path) => path.to_path_buf(),
        None => crate::paths::scoped_agent_socket(scope.name())?,
    };
    let config = load_config_or_default(config_path)?;
    // The gate resolves through the user's configured providers; the daemon
    // supplies only the decision.
    let gate = std::sync::Arc::new(crate::scoped_agent::DaemonGate::new(
        config.providers.clone(),
    ));

    eprintln!(
        "secreq: scope `{}` serving {} ref(s) at {}",
        scope.name(),
        scope.allowed_refs().len(),
        sock.display()
    );

    // Reported from `on_bound` rather than here: this must be true when the
    // caller reads it, and here is still before the bind. `open` hands it back
    // once the socket is bound and 0600, so a caller can `ssh -R` the path the
    // moment it reads the line instead of polling for the file to appear.
    crate::scoped_agent::open(&sock, scope, gate, |bound| {
        // The path, alone, on stdout — the human line above went to stderr —
        // so a caller backgrounding this reads one clean, machine-readable
        // line. Flushed because `open` then blocks forever: an unflushed path
        // would strand the caller waiting on a line sitting in our buffer.
        println!("{}", bound.display());
        std::io::stdout()
            .flush()
            .context("failed to report the scoped agent socket path")
    })?;
    Ok(0)
}

/// Exit code for a **denied** `secreq resolve`, distinct from the `1` an
/// error exits with.
///
/// The protocol splits `Denied` from `Error` on purpose — a denial is a
/// normal policy answer and a guest that retried it would be manufacturing
/// the click-training the design forbids — and that split is worth nothing if
/// the shell can't see it. A script can branch: `3` means "the host said no,
/// stop asking"; `1` means "something is broken, maybe fix it and retry".
const RESOLVE_DENIED_EXIT: i32 = 3;

/// `secreq resolve <secret://ref>` / `secreq resolve --list` — the **guest**
/// side of the remote secret agent: ask the host, over `$SECREQ_SOCK`, for a
/// ref the host declared this sandbox may have.
///
/// Design: `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md` (build step C).
/// The host side is [`agent_open`]; the protocol is
/// [`crate::scoped_agent::proto`].
///
/// ## Output discipline
///
/// **The value, and only the value, goes to stdout** — every diagnostic, every
/// error, every denial goes to stderr. That's not tidiness, it's the whole
/// interface: this command exists to be substituted into a shell, and a single
/// stray "resolving…" line on stdout would land inside the token.
///
/// ```sh
/// export GH_TOKEN="$(secreq resolve secret://op/Dev/gh/token)"
/// ```
///
/// The value is written with a trailing newline (`op read`'s convention, and
/// what a terminal needs); `$(…)` strips it, so the substitution above gets
/// the value exactly. `--list` prints the allowed ref names one per line —
/// stdout again, since that's the answer.
///
/// ## Why this doesn't share `read`'s path
///
/// [`read`] resolves through the *local* daemon: it needs a config, a
/// provider, and a consent window. A guest has none of the three — it has a
/// socket. Everything policy-shaped (the allowlist, the prompt, the
/// decision's TTL, the audit row) happens on the host, and nothing this
/// function does can influence any of it.
pub fn resolve(reference: Option<&str>, list: bool) -> Result<i32> {
    if list == reference.is_some() {
        bail!("secreq resolve: give exactly one of <ref> or --list (usage: secreq resolve <secret://provider/locator>)");
    }

    // Parse before dialling: a typo should read as a typo, with the shape it
    // should have had, rather than as a socket error (when there's no agent)
    // or a remote refusal (when there is) — neither of which is about the
    // typo. Sending the canonical form also means the host parses exactly
    // what we validated. `parse_arg` accepts the bare `provider/locator`
    // shorthand, matching `read` and `agent open --allow`.
    let reference = reference
        .map(|raw| {
            Reference::parse_arg(raw).with_context(|| {
                format!("`{raw}` is not a valid reference (expected `secret://provider/locator` or `provider/locator`)")
            })
        })
        .transpose()?;

    let socket = agent_client::socket_from_env()?;
    let mut agent = agent_client::AgentClient::connect(&socket)?;

    match reference {
        Some(reference) => resolve_one(&mut agent, &reference),
        None => resolve_list(&mut agent),
    }
}

/// `secreq resolve <ref>`: one gated resolve, value to stdout.
fn resolve_one(agent: &mut agent_client::AgentClient, reference: &Reference) -> Result<i32> {
    let request = AgentRequest::resolve_claiming(
        reference.to_string(),
        // A claim, and the host treats it as one — see
        // [`agent_client::self_reported_chain`].
        agent_client::self_reported_chain(),
    );

    match agent.request(&request)? {
        AgentResponse::Value { mut value } => {
            let mut stdout = std::io::stdout().lock();
            // Write, then scrub our copy — the same care the host takes with
            // the value it sent. `write!` rather than `print!` because a
            // closed pipe (`secreq resolve … | head -c 4`) must be an error
            // we report, not a panic in a formatting macro.
            let written = writeln!(stdout, "{value}").and_then(|()| stdout.flush());
            value.zeroize();
            written.context("write the resolved secret to stdout")?;
            Ok(0)
        }
        // A refusal: the reason goes to stderr and stdout stays empty, so a
        // caller that ignored the exit code substitutes an empty string
        // rather than an error message.
        AgentResponse::Denied { message } => {
            eprintln!("secreq: {reference}: denied by the host: {message}");
            Ok(RESOLVE_DENIED_EXIT)
        }
        AgentResponse::Error { message } => {
            bail!("the scoped secret agent could not answer for {reference}: {message}")
        }
        AgentResponse::Refs { .. } => {
            bail!("the scoped secret agent answered a resolve with a ref listing")
        }
    }
}

/// `secreq resolve --list`: the scope's allowed ref names, one per line.
///
/// Free on the host — no prompt, no consent, no audit row — because it
/// releases nothing the host didn't already declare to this very socket.
fn resolve_list(agent: &mut agent_client::AgentClient) -> Result<i32> {
    match agent.request(&AgentRequest::List)? {
        AgentResponse::Refs { refs } => {
            let mut stdout = std::io::stdout().lock();
            for reference in &refs {
                writeln!(stdout, "{reference}").context("write the ref listing to stdout")?;
            }
            stdout.flush().context("write the ref listing to stdout")?;
            Ok(0)
        }
        AgentResponse::Denied { message } => {
            eprintln!("secreq: listing denied by the host: {message}");
            Ok(RESOLVE_DENIED_EXIT)
        }
        AgentResponse::Error { message } => {
            bail!("the scoped secret agent could not list this scope's refs: {message}")
        }
        // Listing must never carry material. If one arrives, the far end is
        // not a scoped agent — so print nothing and say so.
        AgentResponse::Value { .. } => {
            bail!("the scoped secret agent answered a listing with a secret value; refusing to print it")
        }
    }
}

/// `secreq read <ref>…` — resolve one or more secret references and print
/// their values as a JSON object, mirroring `op read` but for every store.
///
/// Each `<ref>` is either a full `secret://provider/locator` reference or the
/// bare `provider/locator` shorthand. Resolution **always** goes through the
/// consent daemon — there is deliberately no `--yes` bypass: a `read` is a
/// raw secret exfiltration primitive, so every call must be gated and audited.
/// The output is always a JSON object keyed by each ref exactly as typed
/// (even for a single ref), so callers can pipe it straight into `jq`.
pub fn read(refs: &[String], config_path: Option<&Path>) -> Result<i32> {
    if refs.is_empty() {
        bail!("secreq read: no references given (usage: secreq read <ref>… )");
    }

    // Re-entrancy guard: we're inside secreq's own resolution (a provider CLI
    // the daemon spawned has `SECREQ_RESOLVING` set). Calling back into the
    // daemon now would deadlock, and unlike `run` there is no client-side
    // path to fall through to — so refuse, fail-closed.
    if std::env::var_os(crate::RESOLVING_ENV).is_some() {
        bail!("secreq read: refusing to run during secret resolution (re-entrant call)");
    }

    let config = load_config_or_default(config_path)?;

    // Parse every arg up front so a malformed ref fails before any daemon
    // contact. Dedupe by the typed string (preserving order) so a repeated
    // ref can't produce duplicate JSON keys.
    let mut parsed: Vec<(String, crate::wraps::ResolvedRef)> = Vec::with_capacity(refs.len());
    let mut seen: Vec<String> = Vec::new();
    for raw in refs {
        // The config is already in hand here, so a bare `secreq read
        // github_token` resolves through the `secrets` block on the same rule
        // a wrap's `env` uses — no-slash means a declared name.
        let resolved = config.resolve_arg(raw)?;
        if seen.contains(raw) {
            continue;
        }
        seen.push(raw.clone());
        parsed.push((raw.clone(), resolved));
    }

    let cwd = std::env::current_dir().context("could not determine current directory")?;
    let chain = provenance::caller_chain();

    // The argv shown in the consent prompt: `read` plus the refs (locators,
    // never values — safe to display).
    let mut command = vec!["read".to_owned()];
    command.extend(seen.iter().cloned());

    let ask = build_ask(
        AskSpec {
            dedupe_wrap: "read".to_owned(),
            command: command.clone(),
            refs: &parsed,
            reason: None,
            allow_remember: false,
            ignore_remembered: false,
        },
        &chain.frames,
        &cwd,
        &config,
    );
    let outcome = daemon_client::request_consent(ask, config.wait_indicator_enabled())
        .context("daemon consent request failed")?;
    let _ = audit::append(
        &AuditEntry::new("read", &command, &chain, &seen, outcome.decision)
            .with_reason(outcome.reason.clone())
            .with_rule_id(outcome.rule_id.clone()),
    );

    if !outcome.decision.approved() {
        if outcome.decision == Decision::DenyAuto {
            let rule_name = outcome.rule_name.as_deref().unwrap_or("(unknown)");
            match outcome.reason.as_deref() {
                Some(msg) => eprintln!("secreq: denied by rule '{rule_name}': {msg}"),
                None => eprintln!("secreq: denied by rule '{rule_name}'"),
            }
        } else if let Some(reason) = outcome.reason.as_deref() {
            eprintln!("secreq: denied: {reason}");
        } else {
            eprintln!("secreq: denied");
        }
        return Ok(1);
    }

    // Assemble `(ref-as-typed, value)` pairs in input order. The daemon errors
    // out (surfaced as `Err` above) on any resolution failure, so on approval
    // every requested name must be present; a gap is an internal invariant
    // break, not a user-facing "not found".
    let mut pairs: Vec<(String, String)> = Vec::with_capacity(parsed.len());
    for (typed, _) in &parsed {
        let value = outcome.secrets.get(typed).with_context(|| {
            format!("internal: daemon approved but returned no value for `{typed}`")
        })?;
        pairs.push((typed.clone(), value.clone()));
    }

    print!("{}", render_read_json(&pairs));
    Ok(0)
}

/// Render resolved `(ref-as-typed, value)` pairs as a pretty JSON object,
/// preserving input order (a plain `serde_json::Map` would sort keys, since
/// the crate isn't built with `preserve_order`). Keys and values are escaped
/// by `serde_json::to_string`, which never fails for a `String`.
fn render_read_json(pairs: &[(String, String)]) -> String {
    if pairs.is_empty() {
        return "{}\n".to_owned();
    }
    let mut out = String::from("{\n");
    for (i, (key, value)) in pairs.iter().enumerate() {
        let key_json = serde_json::to_string(key).expect("String always serializes");
        let value_json = serde_json::to_string(value).expect("String always serializes");
        out.push_str("  ");
        out.push_str(&key_json);
        out.push_str(": ");
        out.push_str(&value_json);
        if i + 1 < pairs.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_read_json_emits_object_even_for_a_single_ref() {
        let out = render_read_json(&[("op/Work/key".to_owned(), "s3cr3t".to_owned())]);
        assert_eq!(out, "{\n  \"op/Work/key\": \"s3cr3t\"\n}\n");
        // Round-trips through a real JSON parser.
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["op/Work/key"], "s3cr3t");
    }

    #[test]
    fn render_read_json_preserves_input_order_not_sorted() {
        // Keys deliberately out of sorted order; output must keep input order.
        let out = render_read_json(&[
            ("zeta/b".to_owned(), "1".to_owned()),
            ("alpha/a".to_owned(), "2".to_owned()),
        ]);
        let zeta = out.find("zeta/b").unwrap();
        let alpha = out.find("alpha/a").unwrap();
        assert!(zeta < alpha, "input order must be preserved, got: {out}");
    }

    #[test]
    fn render_read_json_escapes_keys_and_values() {
        // A value with a quote, backslash, and newline must be valid JSON.
        let out =
            render_read_json(&[("secret://op/a\"b".to_owned(), "line1\nline2\"\\".to_owned())]);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["secret://op/a\"b"], "line1\nline2\"\\");
    }
}
