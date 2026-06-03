//! Append-only audit log (§8, §11).
//!
//! Every grant decision is recorded as one JSON line: when, where, what command,
//! the caller chain, the secret **names** released, and the decision. Secret
//! **values never appear** here — only names, per the threat model (§11).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
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
    let path = audit_log_path()?;
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

/// `$XDG_STATE_HOME/secreq` (or `~/.local/state/secreq`) — the state directory.
pub fn state_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("secreq"));
        }
    }
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".local").join("state").join("secreq"))
}

pub fn audit_log_path() -> Result<PathBuf> {
    Ok(state_dir()?.join("audit.log"))
}

/// mtime of the audit log, or `None` if it doesn't exist yet. The daemon's
/// history view uses this to decide whether to re-read the file (cheap stat
/// vs. full reparse) between paints.
pub fn audit_log_mtime() -> Option<SystemTime> {
    let path = audit_log_path().ok()?;
    std::fs::metadata(path).ok()?.modified().ok()
}

/// Stream the audit log into memory, newest-last. Corrupt lines (anything
/// that doesn't parse as `AuditEntry`) are skipped silently — the audit
/// log spans daemon versions, and a single bad line shouldn't blank the
/// history view. Missing file returns an empty vec, not an error.
pub fn read_history(limit: Option<usize>) -> Result<Vec<AuditEntry>> {
    let path = audit_log_path()?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
