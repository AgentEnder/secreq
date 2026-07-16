//! Append-only audit log (§8, §11).
//!
//! Every grant decision is recorded as one JSON line: when, where, what command,
//! the caller chain, the secret **names** released, and the decision. Secret
//! **values never appear** here — only names, per the threat model (§11).

use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::consent::Decision;
use crate::provenance::Caller;

/// One audit record. Serialized as a single JSON line.
///
/// `Deserialize` is on for the daemon UI's history view, which streams the
/// log back in to surface "last time this wrap ran from a similar caller"
/// next to a pending request. Names only, never values — same as on write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Seconds since the Unix epoch.
    pub ts_unix: u64,
    /// Working directory of the `run`.
    pub cwd: String,
    /// The wrap that ran (the binary name registered in `wraps.json5`).
    pub wrap: String,
    /// The wrapped argv passed through after the binary — what the user
    /// actually typed. Empty for an admin path where args aren't
    /// applicable.
    #[serde(default)]
    pub args: Vec<String>,
    /// Caller process chain, nearest-first. Carries pid + command so the
    /// audit view can render the full process tree that triggered this
    /// request rather than just a stack of process names.
    pub callers: Vec<AuditCaller>,
    /// Names of the secrets granted (never their values).
    pub secrets: Vec<String>,
    /// The consent decision.
    pub decision: String,
    /// Stable id of the auto-rule that produced this decision, if any.
    /// `Some(...)` for `approve+auto` / `deny+auto`; `None` for every
    /// other decision shape. `#[serde(default)]` so logs written by an
    /// older `secreq` deserialize cleanly here.
    #[serde(default)]
    pub rule_id: Option<String>,
    /// SHA256 fingerprint of the public key, set only for SSH-agent sign
    /// rows (`Some("SHA256:…")`); `None` for every wrap-run row. This is a
    /// public-key fingerprint — never the private key and never the
    /// signature bytes. `#[serde(default)]` so older logs (and every
    /// non-SSH row, which omits it) deserialize cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// One process in the audit-time caller chain. Mirrors the runtime
/// [`crate::provenance::Caller`] but only the fields a post-hoc reader
/// needs: pid (to disambiguate identical names across the chain) plus
/// `command` (the argv the consent UI showed at decision time) and
/// `name` (the bare process name; still the load-bearing identifier
/// for the cache + history-summary key).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditCaller {
    pub pid: u32,
    pub name: String,
    pub command: String,
}

impl AuditCaller {
    pub fn from_runtime(caller: &Caller) -> AuditCaller {
        AuditCaller {
            pid: caller.pid,
            name: caller.name.clone(),
            command: caller.command.clone(),
        }
    }
}

impl AuditEntry {
    /// Assemble an entry from the pieces a `run` already has. Rule
    /// linkage is attached via [`AuditEntry::with_rule_id`] when the
    /// decision came from an auto-rule.
    pub fn new(
        wrap: &str,
        args: &[String],
        callers: &[Caller],
        secret_names: &[String],
        decision: Decision,
    ) -> AuditEntry {
        AuditEntry {
            ts_unix: now_unix(),
            cwd: std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            wrap: wrap.to_owned(),
            args: args.to_vec(),
            callers: callers.iter().map(AuditCaller::from_runtime).collect(),
            secrets: secret_names.to_vec(),
            decision: decision.as_str().to_owned(),
            rule_id: None,
            fingerprint: None,
        }
    }

    /// Assemble an SSH-agent **sign** audit row. There is no wrap client on
    /// the SSH path, so the daemon writes this itself (the one documented
    /// exception to "the daemon never writes audit rows" — see `CLAUDE.md`).
    ///
    /// The row carries the identity (`wrap = "ssh:<key_id>"`), the public
    /// key's SHA256 `fingerprint`, the `decision`, and the caller `chain`.
    /// It carries **no secret material**: `secrets` is empty (the private
    /// key is resolved fresh, signed from, and zeroized — never named here),
    /// and the signature bytes are never recorded.
    pub fn ssh_sign(
        key_id: &str,
        fingerprint: &str,
        callers: &[Caller],
        decision: Decision,
    ) -> AuditEntry {
        AuditEntry {
            ts_unix: now_unix(),
            cwd: String::new(),
            wrap: format!("ssh:{key_id}"),
            args: Vec::new(),
            callers: callers.iter().map(AuditCaller::from_runtime).collect(),
            secrets: Vec::new(),
            decision: decision.as_str().to_owned(),
            rule_id: None,
            fingerprint: Some(fingerprint.to_owned()),
        }
    }

    /// Assemble a **scoped-agent resolve** audit row — one release attempt
    /// by a guest against a scoped socket (see [`crate::scoped_agent`]).
    ///
    /// This is *not* a new daemon-writes-audit exception: the scoped agent
    /// is a client of the consent daemon, like the wrap client, so it writes
    /// its own rows.
    ///
    /// The row carries the **scope** (`wrap = "agent:<scope>"`, the
    /// principal the prompt gated on), the **ref** (in `secrets` — an
    /// address, never a value), and the **decision**. It carries `callers:
    /// []` deliberately: a guest has no host-verifiable caller chain, and
    /// this row must not imply one existed (see the provenance section of
    /// `dev-docs/plans/2026-07-16-remote-secret-agent.md`).
    pub fn agent_resolve(scope: &str, reference: &str, decision: Decision) -> AuditEntry {
        AuditEntry {
            ts_unix: now_unix(),
            // A guest has no host cwd.
            cwd: String::new(),
            wrap: format!("agent:{scope}"),
            args: Vec::new(),
            callers: Vec::new(),
            secrets: vec![reference.to_owned()],
            decision: decision.as_str().to_owned(),
            rule_id: None,
            fingerprint: None,
        }
    }

    /// Assemble an **abandoned** audit row. The requesting process exited
    /// before the user decided, so there is no live wrap client to write
    /// this row — the daemon writes it directly (the second documented
    /// exception to "the daemon never writes audit rows", alongside
    /// [`AuditEntry::ssh_sign`] — see `CLAUDE.md`).
    ///
    /// Unlike [`AuditEntry::new`], `cwd` is passed in rather than read from
    /// the daemon's own process: the row must record the *requesting*
    /// process's working directory (carried on the ask), not the daemon's.
    /// The row carries no secret material — only the secret **names** the
    /// ask would have released, same as every other wrap-run row.
    pub fn abandoned(
        wrap: &str,
        args: &[String],
        cwd: &str,
        callers: &[AuditCaller],
        secret_names: &[String],
    ) -> AuditEntry {
        AuditEntry {
            ts_unix: now_unix(),
            cwd: cwd.to_owned(),
            wrap: wrap.to_owned(),
            args: args.to_vec(),
            callers: callers.to_vec(),
            secrets: secret_names.to_vec(),
            decision: Decision::Abandoned.as_str().to_owned(),
            rule_id: None,
            fingerprint: None,
        }
    }

    /// Chainable setter for the firing rule's id. Used on
    /// `ApproveAuto` / `DenyAuto` paths so the audit row links back
    /// to the rule that fired.
    pub fn with_rule_id(mut self, rule_id: Option<String>) -> AuditEntry {
        self.rule_id = rule_id;
        self
    }
}

/// Append an entry to the audit log, creating the state dir if needed. Audit
/// failures are non-fatal to the user's command but are surfaced to the caller.
pub fn append(entry: &AuditEntry) -> Result<()> {
    let path = crate::paths::audit_log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create state dir {}", parent.display()))?;
    }
    let line = serde_json::to_string(entry).context("failed to serialize audit entry")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open audit log {}", path.display()))?;
    writeln!(file, "{line}")
        .with_context(|| format!("failed to write audit log {}", path.display()))
}

/// mtime of the audit log, or `None` if it doesn't exist yet. The daemon's
/// history view uses this to decide whether to re-read the file (cheap stat
/// vs. full reparse) between paints.
pub fn audit_log_mtime() -> Option<SystemTime> {
    let path = crate::paths::audit_log_path().ok()?;
    std::fs::metadata(path).ok()?.modified().ok()
}

/// Stream the audit log into memory, newest-last. Corrupt lines (anything
/// that doesn't parse as `AuditEntry`) are skipped silently — the audit
/// log spans daemon versions, and a single bad line shouldn't blank the
/// history view. Missing file returns an empty vec, not an error.
pub fn read_history(limit: Option<usize>) -> Result<Vec<AuditEntry>> {
    let path = crate::paths::audit_log_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read audit log {}", path.display()))?;
    let mut entries: Vec<AuditEntry> = text
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            if t.is_empty() {
                None
            } else {
                serde_json::from_str::<AuditEntry>(t).ok()
            }
        })
        .collect();
    if let Some(max) = limit {
        if entries.len() > max {
            let drop_n = entries.len() - max;
            entries.drain(..drop_n);
        }
    }
    Ok(entries)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run `f` with `$XDG_STATE_HOME` pointed at a fresh tempdir, so any audit
/// append during `f` lands there instead of the user's real state dir, and
/// [`read_history`] inside `f` reads it back. Restores the previous value
/// afterwards.
///
/// A single process-wide lock serializes every caller: `$SECREQ_HOME` is
/// process-global, so two of these running at once (e.g. a `state` test and
/// a `server` test in the same binary) would otherwise clobber each other's
/// target dir. Shared here — not duplicated per module — so *all* audit-
/// writing tests contend on the one lock.
#[cfg(test)]
pub(crate) fn with_temp_log<R>(f: impl FnOnce() -> R) -> R {
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir");
    let prev = std::env::var_os(crate::paths::SECREQ_HOME_ENV);
    std::env::set_var(crate::paths::SECREQ_HOME_ENV, dir.path());
    let out = f();
    match prev {
        Some(v) => std::env::set_var(crate::paths::SECREQ_HOME_ENV, v),
        None => std::env::remove_var(crate::paths::SECREQ_HOME_ENV),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn write_log(text: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(text.as_bytes()).expect("write");
        f.flush().expect("flush");
        f
    }

    fn read_path(path: &PathBuf, limit: Option<usize>) -> Vec<AuditEntry> {
        // Internal variant of read_history that doesn't depend on XDG paths.
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let mut entries: Vec<AuditEntry> = text
            .lines()
            .filter_map(|l| {
                let t = l.trim();
                if t.is_empty() {
                    None
                } else {
                    serde_json::from_str::<AuditEntry>(t).ok()
                }
            })
            .collect();
        if let Some(max) = limit {
            if entries.len() > max {
                let drop_n = entries.len() - max;
                entries.drain(..drop_n);
            }
        }
        entries
    }

    #[test]
    fn ssh_sign_entry_carries_identity_not_key_or_signature() {
        // An SSH-sign row must record the key id, the public-key
        // fingerprint, the decision, and the full caller chain — and must
        // leak NEITHER the private key NOR the signature bytes. We construct
        // the entry the way the daemon does and assert on its serialized
        // JSON (the exact on-disk shape).
        let callers = vec![
            Caller {
                pid: 4242,
                name: "git".to_owned(),
                command: "git push origin main".to_owned(),
                exe: None,
                start_time: 1,
            },
            Caller {
                pid: 4000,
                name: "zsh".to_owned(),
                command: "-zsh".to_owned(),
                exe: None,
                start_time: 1,
            },
        ];
        // A made-up PEM + signature blob that must NOT appear in the row.
        let secret_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----DEADBEEF";
        let secret_signature = "c2lnbmF0dXJlLWJ5dGVz";

        let entry = AuditEntry::ssh_sign(
            "ssh.deploy",
            "SHA256:Nh0Me49Zh9fDwabc",
            &callers,
            Decision::ApproveCached,
        );
        let json = serde_json::to_string(&entry).expect("serialize ssh-sign entry");

        // Identity + fingerprint + decision present.
        assert!(json.contains("\"wrap\":\"ssh:ssh.deploy\""), "json: {json}");
        assert!(
            json.contains("\"fingerprint\":\"SHA256:Nh0Me49Zh9fDwabc\""),
            "json: {json}"
        );
        assert!(
            json.contains("\"decision\":\"approve+cached\""),
            "json: {json}"
        );
        // Caller chain present (names + pids).
        assert!(json.contains("\"pid\":4242"), "json: {json}");
        assert!(json.contains("git push origin main"), "json: {json}");
        // No secrets are named on an SSH-sign row.
        assert!(json.contains("\"secrets\":[]"), "json: {json}");
        // CRITICAL: never the private key, never the signature.
        assert!(
            !json.contains(secret_private_key),
            "private key leaked into audit row: {json}"
        );
        assert!(
            !json.contains(secret_signature),
            "signature bytes leaked into audit row: {json}"
        );
        assert!(
            !json.to_lowercase().contains("private key"),
            "private-key text leaked into audit row: {json}"
        );

        // Round-trips back through Deserialize the way the history view reads it.
        let parsed: AuditEntry = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(
            parsed.fingerprint.as_deref(),
            Some("SHA256:Nh0Me49Zh9fDwabc")
        );
        assert_eq!(parsed.wrap, "ssh:ssh.deploy");
        assert_eq!(parsed.callers.len(), 2);
        assert!(parsed.secrets.is_empty());
    }

    /// A scoped-agent row must record the scope, the ref, and the decision —
    /// and must never carry the resolved value, nor invent a caller chain a
    /// guest cannot have.
    #[test]
    fn agent_resolve_entry_carries_scope_and_ref_but_never_the_value() {
        let secret_value = "ghp_liveTokenValue_DEADBEEF";

        let entry =
            AuditEntry::agent_resolve("brain-nx-t5", "secret://op/Dev/gh/token", Decision::Approve);
        let json = serde_json::to_string(&entry).expect("serialize agent-resolve entry");

        assert!(
            json.contains("\"wrap\":\"agent:brain-nx-t5\""),
            "json: {json}"
        );
        assert!(
            json.contains("\"secrets\":[\"secret://op/Dev/gh/token\"]"),
            "json: {json}"
        );
        assert!(json.contains("\"decision\":\"approve\""), "json: {json}");
        // CRITICAL: the value never lands in the log.
        assert!(
            !json.contains(secret_value),
            "secret value leaked into audit row: {json}"
        );
        // No fabricated provenance: the scope IS the principal.
        assert!(json.contains("\"callers\":[]"), "json: {json}");

        let parsed: AuditEntry = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(parsed.wrap, "agent:brain-nx-t5");
        assert!(parsed.callers.is_empty());
        assert!(parsed.fingerprint.is_none());
    }

    /// The out-of-scope denial is a distinct decision string, so a reader
    /// can tell a guest probing for an undeclared ref from a user clicking
    /// Deny on one it was offered.
    #[test]
    fn agent_resolve_records_out_of_scope_denials_distinctly() {
        let entry = AuditEntry::agent_resolve(
            "brain-nx-t5",
            "secret://op/Prod/aws/key",
            Decision::DenyOutOfScope,
        );
        assert_eq!(entry.decision, "deny+out-of-scope");
        assert_ne!(entry.decision, Decision::Deny.as_str());
    }

    #[test]
    fn abandoned_entry_records_context_with_abandoned_decision() {
        // The daemon writes this when a wrap dies before the user decides.
        // It must carry the requesting process's cwd (not the daemon's),
        // the wrap + args + caller chain + secret NAMES, and the distinct
        // "abandoned" decision — and never a fingerprint (that's SSH-only).
        let callers = vec![
            AuditCaller {
                pid: 4242,
                name: "gh".to_owned(),
                command: "gh pr view 42".to_owned(),
            },
            AuditCaller {
                pid: 4000,
                name: "zsh".to_owned(),
                command: "-zsh".to_owned(),
            },
        ];
        let entry = AuditEntry::abandoned(
            "gh",
            &["pr".to_owned(), "view".to_owned(), "42".to_owned()],
            "/home/dev/project",
            &callers,
            &["GITHUB_TOKEN".to_owned()],
        );
        assert_eq!(entry.decision, "abandoned");
        assert_eq!(entry.wrap, "gh");
        assert_eq!(entry.args, vec!["pr", "view", "42"]);
        assert_eq!(entry.cwd, "/home/dev/project");
        assert_eq!(entry.secrets, vec!["GITHUB_TOKEN"]);
        assert_eq!(entry.callers.len(), 2);
        assert_eq!(entry.callers[0].pid, 4242);
        assert!(entry.fingerprint.is_none());

        // Round-trips through the same Deserialize the history view uses.
        let json = serde_json::to_string(&entry).expect("serialize abandoned entry");
        let parsed: AuditEntry = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(parsed.decision, "abandoned");
        assert_eq!(parsed.wrap, "gh");
    }

    #[test]
    fn read_history_round_trips_entries_and_skips_corrupt_lines() {
        // Mix two valid JSON lines, a blank line, and a garbage line — the
        // garbage must be silently ignored so one bad write never blanks
        // the daemon's history view.
        let log = "\
{\"ts_unix\":100,\"cwd\":\"/a\",\"wrap\":\"gh\",\"args\":[\"pr\",\"view\",\"42\"],\"callers\":[{\"pid\":111,\"name\":\"zsh\",\"command\":\"-zsh\"}],\"secrets\":[\"GITHUB_TOKEN\"],\"decision\":\"approve+remember\"}

not json at all
{\"ts_unix\":200,\"cwd\":\"/b\",\"wrap\":\"aws\",\"args\":[],\"callers\":[{\"pid\":222,\"name\":\"npm\",\"command\":\"npm test\"}],\"secrets\":[\"AWS_KEY\"],\"decision\":\"deny\"}
";
        let f = write_log(log);
        let entries = read_path(&f.path().to_path_buf(), None);
        assert_eq!(entries.len(), 2, "two valid entries, garbage dropped");
        assert_eq!(entries[0].wrap, "gh");
        assert_eq!(entries[0].args, vec!["pr", "view", "42"]);
        assert_eq!(entries[0].callers[0].pid, 111);
        assert_eq!(entries[1].decision, "deny");
    }

    #[test]
    fn read_history_limit_keeps_newest() {
        // Tail-like behaviour: when capped, we keep the *latest* entries
        // (end of file), not the oldest. The UI cares about recency.
        let log = "\
{\"ts_unix\":1,\"cwd\":\"\",\"wrap\":\"a\",\"args\":[],\"callers\":[],\"secrets\":[],\"decision\":\"approve\"}
{\"ts_unix\":2,\"cwd\":\"\",\"wrap\":\"b\",\"args\":[],\"callers\":[],\"secrets\":[],\"decision\":\"approve\"}
{\"ts_unix\":3,\"cwd\":\"\",\"wrap\":\"c\",\"args\":[],\"callers\":[],\"secrets\":[],\"decision\":\"approve\"}
";
        let f = write_log(log);
        let entries = read_path(&f.path().to_path_buf(), Some(2));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].wrap, "b");
        assert_eq!(entries[1].wrap, "c");
    }
}
