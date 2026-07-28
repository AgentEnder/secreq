//! Append-only audit log (§8, §11).
//!
//! Every grant decision is recorded as one JSON line: when, where, what command,
//! the caller chain, the secret **names** released, and the decision. Secret
//! **values never appear** here — only names, per the threat model (§11).

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::consent::Decision;
use crate::provenance::{Caller, CallerChain, SignAnchor, SignAnchorKind};

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
    /// The wrap that ran (the binary name registered in `config.toml`).
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
    /// Whether the walk that produced [`AuditEntry::callers`] stopped at its
    /// own ceiling with ancestry still above the outermost frame.
    ///
    /// **Three states, and the third is why this is an `Option`.** Storage is
    /// nearest-first, so the frames a walk gives up are the *outermost* ones —
    /// the ones that answer "where did this ultimately come from". A reader
    /// holding only `callers` cannot tell a chain that ended at its root from
    /// one abandoned at the walk's limit, and the audit view drew both the
    /// same way.
    ///
    /// - `Some(true)` — the walk stopped short; there is ancestry above that
    ///   nothing read.
    /// - `Some(false)` — the walk reached the top. The outermost frame really
    ///   is the origin.
    /// - `None` — **this row predates the field.** Not "not truncated": the
    ///   row was written by a `secreq` that never recorded the answer, so the
    ///   log does not know. The audit view renders that as its own third
    ///   state rather than as completeness, because a log that reports an
    ///   unknown as a fact is worse than one that admits the gap.
    ///
    /// `#[serde(default)]` is what produces that `None`, and every
    /// constructor in this module writes `Some(_)` — including
    /// [`AuditEntry::agent_resolve`], which has no chain at all. That is the
    /// invariant the third state rests on: **an absent field means an old
    /// row, and nothing else.**
    #[serde(default)]
    pub callers_truncated: Option<bool>,
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
    /// The process the sign grant bound to, on an SSH-agent sign row only.
    ///
    /// **This is the field that tells a forwarded sign from a local one**, and
    /// nothing else on the row can. Under `ssh -A` the anchor is the local
    /// `ssh` client — the socket peer — and the caller-chain walk deliberately
    /// starts at the peer's *parent*, so [`AuditEntry::callers`] on a forwarded
    /// sign looks exactly like the chain behind a local `git push`: shell,
    /// terminal, launchd. A remote host asking for a signature and the user
    /// asking for one were the same row.
    ///
    /// Recorded as the whole anchor rather than a `forwarded: bool` because
    /// "which host" is the question a reader actually has, and
    /// [`AuditSignAnchor::command`] is the only place the answer exists: the
    /// `ssh -A build-box` argv names it, and that process appears nowhere in
    /// `callers`.
    ///
    /// `None` means one of two things, told apart by `wrap`:
    ///
    /// - On a row whose `wrap` does **not** start with `ssh:`, there was no
    ///   sign and so no anchor — the same way `fingerprint` is absent there.
    /// - On an `ssh:` row, the row **predates this field**. The audit view
    ///   renders that as its own state rather than as "not forwarded", because
    ///   a log that reports an unknown as a fact is worse than one that admits
    ///   the gap. Every `ssh:` row this version writes carries the field; see
    ///   `every_sign_row_this_version_names_its_anchor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_anchor: Option<AuditSignAnchor>,
    /// The local process the daemon saw on `consent.sock` naming the scope, on
    /// a scoped-agent row only.
    ///
    /// **This is what tells a forged scoped-agent request from a genuine one**
    /// after the fact. The daemon cannot distinguish them live and does not
    /// try — both arrive as one `ClientMsg::Ask` on the same socket — so the
    /// prompt states what it does know: which process spoke. A genuine request
    /// names the `secreq agent open` the user started, at the path they
    /// installed it to; a forger names itself, in its own executable. That
    /// evidence reached the screen and stopped there, so a forgery was visible
    /// for as long as the prompt was up and anonymous forever after.
    ///
    /// **Not the principal, and it must never become one.** The host-declared
    /// scope stays the gating identity, the grant anchor and this row's `wrap`,
    /// per the provenance section of
    /// `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md`. This is a
    /// fact about a *host* socket — `consent.sock`, per-user, `0600`, never
    /// forwarded — and says nothing whatever about the guest, which is in
    /// another kernel behind whatever tunnel the scoped socket runs over.
    ///
    /// `None` means one of two things, told apart by `wrap`:
    ///
    /// - On a row whose `wrap` does **not** start with `agent:`, no scope was
    ///   declared, so nothing named one.
    /// - On an `agent:` row, the row **predates this field**. Distinct from
    ///   [`ScopeDeclarant::NotRead`], which is a row this version wrote about a
    ///   release that never reached the daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_by: Option<ScopeDeclarant>,
    /// The caller chain a **guest reported about itself** on a scoped-agent
    /// row, already rendered for display (`"node → pnpm → postinstall"`);
    /// `None` on every other row, and on guest rows that claimed nothing.
    ///
    /// The field name carries the caveat because a log outlives the context
    /// it was written in: this is a **claim**, not a fact. It is deliberately
    /// *not* merged into [`AuditEntry::callers`], which stays empty on these
    /// rows — `callers` means "the host walked the process tree and saw
    /// this", and the whole point of the scoped-agent design is that no such
    /// walk is possible behind a guest. Filing a guest's story under the
    /// field reserved for kernel-sourced provenance would launder it into
    /// evidence, and `rules.rs` matches on `callers`.
    ///
    /// It is recorded because it is useful when the guest is honest and
    /// interesting when it is not — a claimed chain that disagrees with what
    /// a sandbox should be running is a signal worth having — and it is safe
    /// to record precisely because nothing downstream reads it back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unverified_guest_chain: Option<String>,
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
    /// Absolute path to the executable; see [`crate::daemon::proto::Caller`].
    /// `#[serde(default)]` so rows written before this decode as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
}

/// Everything the daemon still holds about an ask whose client died before
/// the user decided, for [`AuditEntry::abandoned`].
///
/// The awkward half of this struct is the point: `callers_truncated`,
/// `sign_anchor` and `declared_by` are each the last surviving copy of
/// something the daemon observed and the client can no longer be asked about.
/// A row that dropped one reads, months later, exactly like a row where the
/// answer was "no".
pub struct AbandonedAsk<'a> {
    pub wrap: &'a str,
    pub args: &'a [String],
    /// The **requesting** process's working directory, not the daemon's.
    pub cwd: &'a str,
    pub callers: &'a [AuditCaller],
    pub callers_truncated: bool,
    /// Secret **names** the ask would have released. Never values.
    pub secret_names: &'a [String],
    /// `Some` on a sign ask; see [`AuditEntry::sign_anchor`].
    pub sign_anchor: Option<AuditSignAnchor>,
    /// `Some` on a scoped-agent ask; see [`AuditEntry::declared_by`].
    pub declared_by: Option<ScopeDeclarant>,
}

/// What the host could say about the local process that named a scope, for
/// [`AuditEntry::declared_by`].
///
/// Three answers rather than an `Option<AuditLocalPeer>`, because "nobody
/// looked" and "we looked and it was gone" are different facts and a log that
/// spells them the same way is asserting one of them without checking.
///
/// It also crosses the daemon socket, on the reply to a scoped-agent ask
/// (`daemon::proto::DaemonMsg::Decision`). That is the log's vocabulary
/// travelling rather than a display type being persisted: the scoped agent is
/// a *client*, so it writes its own audit rows, and the only value in this
/// field is that the daemon — not the client describing itself — produced it.
/// A client writing its own pid here would make the row a claim; the point is
/// that it is the kernel's answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDeclarant {
    /// The kernel's answer: the process on the other end of `consent.sock`.
    Peer(AuditLocalPeer),
    /// The daemon looked and the process had already exited (between the
    /// `SO_PEERCRED` call and the lookup). Recorded rather than dropped,
    /// because a row that looks the same whether or not anything checked is
    /// the failure this field exists to fix.
    Gone,
    /// Nothing read a peer for this row: the release never reached the daemon.
    /// A ref the scope's own allowlist refused, or one served by the scope's
    /// cached grant, is decided inside the agent process — the row's
    /// `decision` (`deny+out-of-scope`, `approve+cached`) says which. The
    /// prompt that granted the cache entry has its own row, with its own
    /// declarant.
    NotRead,
}

/// A local process as the kernel described it, as an audit row records it.
///
/// Mirrors [`crate::daemon::proto::LocalPeer`] for the reason [`AuditCaller`]
/// mirrors a caller frame: one is drawn on a prompt for a few seconds, the
/// other is read out of a file months later, and the wire side is free to
/// gain display fields the log has no business keeping forever.
///
/// `name` and `command` are what the process chose for itself; `exe` is what
/// the kernel loaded. All three are kept because their value is being
/// adjacent: `secreq` beside `/tmp/.build-cache/postinstall` is a
/// contradiction nobody has to go looking for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLocalPeer {
    pub pid: u32,
    pub name: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
}

/// The process an SSH sign grant bound to, as an audit row records it.
///
/// Mirrors the runtime [`crate::provenance::SignAnchor`] minus its
/// `start_time`: that half of the identity exists to stop a recycled pid
/// inheriting a live grant, and a grant no longer exists by the time anyone
/// reads this row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSignAnchor {
    /// `"session"` or `"forwarded_ssh"` — why the grant bound where it did,
    /// and the whole reason this struct is on the row.
    pub kind: SignAnchorKind,
    pub pid: u32,
    /// The anchor's sanitized `comm`.
    pub name: String,
    /// The anchor's command line, carried only for a forwarded anchor — the
    /// one frame [`AuditEntry::callers`] does not contain. `ssh -A build-box`
    /// names the host that could have been asking; without it the row says a
    /// forwarded sign happened and cannot say to where.
    ///
    /// Absent on a session anchor, whose argv the caller tree already draws.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

impl AuditSignAnchor {
    pub fn from_runtime(anchor: &SignAnchor) -> AuditSignAnchor {
        AuditSignAnchor {
            kind: anchor.kind,
            pid: anchor.identity.pid,
            name: anchor.name.clone(),
            command: match anchor.kind {
                SignAnchorKind::ForwardedSsh => Some(anchor.command.clone()),
                SignAnchorKind::Session => None,
            },
        }
    }

    /// Did this sign go out through an agent forwarded to another host?
    pub fn forwarded(&self) -> bool {
        self.kind == SignAnchorKind::ForwardedSsh
    }
}

impl AuditCaller {
    pub fn from_runtime(caller: &Caller) -> AuditCaller {
        AuditCaller {
            pid: caller.pid,
            name: caller.name.clone(),
            command: caller.command.clone(),
            exe: caller.exe.clone(),
        }
    }
}

impl AuditEntry {
    /// Assemble an entry from the pieces a `run` already has. Rule
    /// linkage is attached via [`AuditEntry::with_rule_id`] when the
    /// decision came from an auto-rule.
    ///
    /// Takes the whole [`CallerChain`] rather than its frames: the audit view
    /// draws this chain, so "how far the walk got" has to survive the write
    /// alongside what it got.
    pub fn new(
        wrap: &str,
        args: &[String],
        chain: &CallerChain,
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
            callers: chain.frames.iter().map(AuditCaller::from_runtime).collect(),
            callers_truncated: Some(chain.truncated),
            secrets: secret_names.to_vec(),
            decision: decision.as_str().to_owned(),
            rule_id: None,
            fingerprint: None,
            // Not a sign, so there is no anchor — absent for the same reason
            // `fingerprint` is.
            sign_anchor: None,
            // No scope was declared, so nothing named one.
            declared_by: None,
            // Local wraps have a real, kernel-sourced `callers`; there is no
            // guest to be claiming anything.
            unverified_guest_chain: None,
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
    ///
    /// `cwd` is the *socket peer's* working directory, read by the daemon via
    /// [`crate::provenance::cwd_for_pid`], because a sign request has no wrap
    /// client to self-report one the way [`AuditEntry::new`] does. Empty when
    /// it couldn't be read — the row records what was observed, not a guess.
    ///
    /// `anchor` is the frame the grant bound to, and it travels with the chain
    /// rather than being derivable from it: under agent forwarding the anchor
    /// is the socket peer, which the walk starts *above*, so no amount of
    /// reading `chain` afterwards recovers it. It is the difference between a
    /// signature the user asked for and one a remote host asked for — see
    /// [`AuditEntry::sign_anchor`].
    pub fn ssh_sign(
        key_id: &str,
        fingerprint: &str,
        chain: &CallerChain,
        anchor: &SignAnchor,
        cwd: &str,
        decision: Decision,
    ) -> AuditEntry {
        AuditEntry {
            ts_unix: now_unix(),
            cwd: cwd.to_owned(),
            wrap: format!("ssh:{key_id}"),
            args: Vec::new(),
            callers: chain.frames.iter().map(AuditCaller::from_runtime).collect(),
            callers_truncated: Some(chain.truncated),
            secrets: Vec::new(),
            decision: decision.as_str().to_owned(),
            rule_id: None,
            fingerprint: Some(fingerprint.to_owned()),
            sign_anchor: Some(AuditSignAnchor::from_runtime(anchor)),
            declared_by: None,
            unverified_guest_chain: None,
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
    /// `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md`).
    ///
    /// `guest_chain` is whatever the guest *claimed* about itself, already
    /// rendered for display, or `None`. It lands in
    /// [`AuditEntry::unverified_guest_chain`] — never in `callers`. The two
    /// fields are kept apart on purpose: one is what the host saw, the other
    /// is what the guest said, and a log that blurs them is worse than a log
    /// that omits the claim entirely.
    ///
    /// `declared_by` is the third kind of thing on this row and the only one
    /// the *daemon* asserted: which local process was on `consent.sock` when
    /// the prompt went up. It is passed in rather than derived here for the
    /// reason the field exists at all — a process describing itself is a
    /// claim, and this row is supposed to carry the kernel's answer, which
    /// only the daemon has. See [`AuditEntry::declared_by`].
    pub fn agent_resolve(
        scope: &str,
        reference: &str,
        decision: Decision,
        guest_chain: Option<&str>,
        declared_by: ScopeDeclarant,
    ) -> AuditEntry {
        AuditEntry {
            ts_unix: now_unix(),
            // A guest has no host cwd.
            cwd: String::new(),
            wrap: format!("agent:{scope}"),
            args: Vec::new(),
            callers: Vec::new(),
            // `Some(false)`, structurally, the same answer
            // `Ask::callers_truncated` gives a guest ask: there was no walk to
            // stop short, so nothing is missing from the empty chain above.
            // Writing it rather than leaving the field off is what keeps an
            // *absent* field meaning exactly one thing — a row written before
            // the field existed.
            callers_truncated: Some(false),
            secrets: vec![reference.to_owned()],
            decision: decision.as_str().to_owned(),
            rule_id: None,
            fingerprint: None,
            // Nothing was signed, so there is no anchor.
            sign_anchor: None,
            declared_by: Some(declared_by),
            unverified_guest_chain: guest_chain.map(str::to_owned),
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
    ///
    /// `callers_truncated` travels next to `callers` because it is the same
    /// fact about the same chain: the ask carried both from the daemon's own
    /// walk of the socket peer, and splitting them here is how a row ends up
    /// claiming an ancestry it only has part of.
    ///
    /// `sign_anchor` and `declared_by` are `Some` on exactly the rows a live
    /// [`AuditEntry::ssh_sign`] / [`AuditEntry::agent_resolve`] would have
    /// filled them on. An abandoned sign carries an `ssh:` wrap and an
    /// abandoned guest request an `agent:` one, and a reader must not have to
    /// know that "abandoned" is the one kind of row where an absent field
    /// means something other than an old log.
    ///
    /// Takes [`AbandonedAsk`] rather than eight positional arguments: half of
    /// them are the daemon's last copy of a fact nobody else still holds, and
    /// at that width a swapped pair is a silent mis-attribution rather than a
    /// type error.
    pub fn abandoned(ask: AbandonedAsk<'_>) -> AuditEntry {
        AuditEntry {
            ts_unix: now_unix(),
            cwd: ask.cwd.to_owned(),
            wrap: ask.wrap.to_owned(),
            args: ask.args.to_vec(),
            callers: ask.callers.to_vec(),
            callers_truncated: Some(ask.callers_truncated),
            secrets: ask.secret_names.to_vec(),
            decision: Decision::Abandoned.as_str().to_owned(),
            rule_id: None,
            fingerprint: None,
            sign_anchor: ask.sign_anchor,
            declared_by: ask.declared_by,
            unverified_guest_chain: None,
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
        crate::paths::ensure_private_dir(parent)
            .with_context(|| format!("failed to create state dir {}", parent.display()))?;
    }
    let line = serde_json::to_string(entry).context("failed to serialize audit entry")?;
    // Owner-only: the row holds no value, but it does hold every wrapped
    // command's argv, cwd, caller chain and secret names.
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(crate::paths::PRIVATE_FILE_MODE)
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
        .map_or(0, |d| d.as_secs())
}

/// Run `f` with `$XDG_STATE_HOME` pointed at a fresh tempdir, so any audit
/// append during `f` lands there instead of the user's real state dir, and
/// [`read_history`] inside `f` reads it back. Restores the previous value
/// afterwards.
///
/// Serialized on [`crate::paths::env_lock`]: `$SECREQ_HOME` is
/// process-global, so two of these running at once (e.g. a `state` test and
/// a `server` test in the same binary) would otherwise clobber each other's
/// target dir. The lock lives in `paths` rather than here because setting
/// the var is only half the hazard — tests that merely *read* a path under
/// it (the wasm-store listings in `daemon::state`) have to take the same
/// lock, or this function moves the root out from under them mid-test.
#[cfg(test)]
pub(crate) fn with_temp_log<R>(f: impl FnOnce() -> R) -> R {
    let _guard = crate::paths::env_lock();
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
        let chain = CallerChain {
            frames: vec![
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
            ],
            truncated: false,
        };
        // A made-up PEM + signature blob that must NOT appear in the row.
        let secret_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----DEADBEEF";
        let secret_signature = "c2lnbmF0dXJlLWJ5dGVz";

        let entry = AuditEntry::ssh_sign(
            "ssh.deploy",
            "SHA256:Nh0Me49Zh9fDwabc",
            &chain,
            &test_anchor(SignAnchorKind::Session, 4000, "-zsh"),
            "/home/dev/repos/acme",
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

        let entry = AuditEntry::agent_resolve(
            "brain-nx-t5",
            "secret://op/Dev/gh/token",
            Decision::Approve,
            None,
            ScopeDeclarant::NotRead,
        );
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
            None,
            ScopeDeclarant::NotRead,
        );
        assert_eq!(entry.decision, "deny+out-of-scope");
        assert_ne!(entry.decision, Decision::Deny.as_str());
    }

    /// A guest's claimed chain is recorded, but **only** in the field named
    /// for what it is. `callers` stays empty: that field means "the host
    /// walked the process tree and saw this", and `rules.rs` matches on it.
    /// A guest's story filed there would be laundered into evidence.
    #[test]
    fn agent_resolve_files_a_guest_chain_as_unverified_never_as_callers() {
        let entry = AuditEntry::agent_resolve(
            "brain-nx-t5",
            "secret://op/Dev/gh/token",
            Decision::Approve,
            Some("node → pnpm → postinstall"),
            ScopeDeclarant::NotRead,
        );

        assert_eq!(
            entry.unverified_guest_chain.as_deref(),
            Some("node → pnpm → postinstall")
        );
        assert!(
            entry.callers.is_empty(),
            "a guest's claim must never land in the kernel-sourced caller chain"
        );

        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(
            json.contains("\"unverified_guest_chain\":\"node → pnpm → postinstall\""),
            "the field name must carry the caveat into the log: {json}"
        );
        assert!(json.contains("\"callers\":[]"), "json: {json}");
    }

    /// A guest that claimed nothing writes no chain field at all — better an
    /// absent field than an empty one that reads as "nothing was asking".
    #[test]
    fn agent_resolve_omits_the_chain_field_when_the_guest_claimed_nothing() {
        let entry = AuditEntry::agent_resolve(
            "brain-nx-t5",
            "secret://op/Dev/gh/token",
            Decision::Approve,
            None,
            ScopeDeclarant::NotRead,
        );
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(!json.contains("unverified_guest_chain"), "json: {json}");
    }

    /// Rows written before this field existed must still deserialize — the
    /// audit log is append-only and the UI streams the whole history back.
    #[test]
    fn rows_without_a_guest_chain_field_still_deserialize() {
        let json = r#"{"ts_unix":1,"cwd":"","wrap":"agent:s","args":[],"callers":[],
                       "secrets":["secret://op/a/b"],"decision":"approve"}"#;
        let parsed: AuditEntry = serde_json::from_str(json).expect("older rows must parse");
        assert!(parsed.unverified_guest_chain.is_none());
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
                exe: None,
            },
            AuditCaller {
                pid: 4000,
                name: "zsh".to_owned(),
                command: "-zsh".to_owned(),
                exe: None,
            },
        ];
        let entry = AuditEntry::abandoned(AbandonedAsk {
            wrap: "gh",
            args: &["pr".to_owned(), "view".to_owned(), "42".to_owned()],
            cwd: "/home/dev/project",
            callers: &callers,
            callers_truncated: false,
            secret_names: &["GITHUB_TOKEN".to_owned()],
            sign_anchor: None,
            declared_by: None,
        });
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

    /// A session anchor for tests that only need the shape.
    fn test_anchor(kind: SignAnchorKind, pid: u32, command: &str) -> SignAnchor {
        SignAnchor {
            identity: crate::provenance::ProcessIdentity { pid, start_time: 1 },
            name: "ssh".to_owned(),
            command: command.to_owned(),
            kind,
        }
    }

    /// The finding: a sign that went out through a forwarded agent and one the
    /// user drove themselves produced identical rows. The anchor is what
    /// separates them, and the forwarded case has to name the host — its `ssh`
    /// client is the socket peer, which the caller walk starts above, so it
    /// appears nowhere in `callers`.
    #[test]
    fn a_forwarded_sign_names_the_ssh_client_the_caller_chain_cannot() {
        let chain = CallerChain {
            frames: vec![Caller {
                pid: 7926,
                name: "zsh".to_owned(),
                command: "-zsh".to_owned(),
                exe: None,
                start_time: 1,
            }],
            truncated: false,
        };
        let forwarded = AuditEntry::ssh_sign(
            "ssh.deploy",
            "SHA256:x",
            &chain,
            &test_anchor(SignAnchorKind::ForwardedSsh, 9310, "ssh -A build-box"),
            "/w",
            Decision::Approve,
        );
        let anchor = forwarded.sign_anchor.as_ref().expect("anchor recorded");
        assert!(anchor.forwarded(), "{anchor:?}");
        assert_eq!(anchor.pid, 9310);
        assert_eq!(
            anchor.command.as_deref(),
            Some("ssh -A build-box"),
            "the host the agent was handed to is the answer a reader wants, \
             and this row is the only place it exists"
        );
        assert!(
            !forwarded.callers.iter().any(|c| c.pid == 9310),
            "the forwarding client is the socket peer; the chain starts above it"
        );

        let local = AuditEntry::ssh_sign(
            "ssh.deploy",
            "SHA256:x",
            &chain,
            &test_anchor(SignAnchorKind::Session, 7926, "-zsh"),
            "/w",
            Decision::Approve,
        );
        let anchor = local.sign_anchor.as_ref().expect("anchor recorded");
        assert!(!anchor.forwarded(), "{anchor:?}");
        assert_eq!(
            anchor.command, None,
            "a session anchor's argv is already on its row in the caller tree"
        );
    }

    /// The on-disk vocabulary, asserted on the serialized line rather than the
    /// struct: `jq 'select(.sign_anchor.kind == "forwarded_ssh")'` is the
    /// query this whole field exists to make answerable.
    #[test]
    fn a_forwarded_sign_is_greppable_in_the_written_line() {
        let chain = CallerChain {
            frames: Vec::new(),
            truncated: false,
        };
        let entry = AuditEntry::ssh_sign(
            "ssh.deploy",
            "SHA256:x",
            &chain,
            &test_anchor(SignAnchorKind::ForwardedSsh, 9310, "ssh -A build-box"),
            "/w",
            Decision::Approve,
        );
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(json.contains("\"kind\":\"forwarded_ssh\""), "json: {json}");
        assert!(json.contains("ssh -A build-box"), "json: {json}");

        let parsed: AuditEntry = serde_json::from_str(&json).expect("round-trip");
        assert!(parsed.sign_anchor.expect("anchor").forwarded());
    }

    /// An `ssh:` row from before the field reads back as **unknown**, not as
    /// "local". Rendering silence as a definite negative is the over-claim this
    /// field exists to remove, and on the audit view it would mislead worst:
    /// that surface is what someone uses to reconstruct what happened.
    #[test]
    fn an_ssh_row_written_before_the_field_reads_back_as_unknown_not_as_local() {
        let json = r#"{"ts_unix":1,"cwd":"/w","wrap":"ssh:ssh.deploy","args":[],
                       "callers":[{"pid":9,"name":"zsh","command":"-zsh"}],
                       "callers_truncated":false,"secrets":[],
                       "decision":"approve","fingerprint":"SHA256:x"}"#;
        let parsed: AuditEntry = serde_json::from_str(json).expect("older rows must parse");
        assert_eq!(parsed.sign_anchor, None);
        assert!(
            parsed.wrap.starts_with("ssh:"),
            "the wrap prefix is what says the absent field is a gap rather than \
             an inapplicable field"
        );
    }

    fn impostor() -> AuditLocalPeer {
        AuditLocalPeer {
            pid: 82702,
            // The `comm` a forger picks is the convincing half. The exe below
            // is the one it did not get to choose.
            name: "secreq".to_owned(),
            command: "secreq agent open brain-nx-t5".to_owned(),
            exe: Some("/tmp/.build-cache/postinstall".to_owned()),
        }
    }

    /// The finding: a forged scoped-agent request and a genuine one wrote the
    /// same row. The prompt renders the difference live and the log did not,
    /// so a forgery was visible only for as long as the window was up.
    #[test]
    fn a_forged_scoped_agent_row_names_the_process_that_named_the_scope() {
        let entry = AuditEntry::agent_resolve(
            "brain-nx-t5",
            "secret://op/Dev/gh/token",
            Decision::Approve,
            None,
            ScopeDeclarant::Peer(impostor()),
        );
        let ScopeDeclarant::Peer(peer) = entry.declared_by.as_ref().expect("declarant recorded")
        else {
            panic!("expected a peer");
        };
        assert_eq!(peer.pid, 82702);
        assert_eq!(
            peer.exe.as_deref(),
            Some("/tmp/.build-cache/postinstall"),
            "the executable is the half the process did not choose, and the \
             whole reason the row is worth reading"
        );
        assert!(
            entry.callers.is_empty(),
            "the peer is not provenance and must not be filed as a caller chain"
        );
        assert_eq!(
            entry.wrap, "agent:brain-nx-t5",
            "the scope stays the principal and the row's label"
        );

        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(
            json.contains("/tmp/.build-cache/postinstall"),
            "json: {json}"
        );
        assert!(json.contains("\"callers\":[]"), "json: {json}");
    }

    /// Two facts that are not the same fact. A release the scope's allowlist
    /// refused, or one its cached grant served, never reached the daemon —
    /// nothing read a peer. That is not the same as a daemon looking and
    /// finding the process gone, and a log that spells them alike asserts one
    /// of them without checking.
    #[test]
    fn nothing_looked_and_the_peer_was_gone_are_recorded_differently() {
        let not_read = AuditEntry::agent_resolve(
            "brain-nx-t5",
            "secret://op/Prod/aws/key",
            Decision::DenyOutOfScope,
            None,
            ScopeDeclarant::NotRead,
        );
        let gone = AuditEntry::agent_resolve(
            "brain-nx-t5",
            "secret://op/Dev/gh/token",
            Decision::Approve,
            None,
            ScopeDeclarant::Gone,
        );
        assert_eq!(not_read.declared_by, Some(ScopeDeclarant::NotRead));
        assert_eq!(gone.declared_by, Some(ScopeDeclarant::Gone));
        assert_ne!(not_read.declared_by, gone.declared_by);

        let json = serde_json::to_string(&not_read).expect("serialize");
        assert!(
            json.contains("\"declared_by\":\"not_read\""),
            "json: {json}"
        );
        let json = serde_json::to_string(&gone).expect("serialize");
        assert!(json.contains("\"declared_by\":\"gone\""), "json: {json}");
    }

    /// An `agent:` row from before the field reads back as **absent**, which
    /// the audit view renders as its own state. Absent is not `NotRead`: one
    /// is "this version never wrote it down", the other is "this version
    /// wrote down that nothing looked".
    #[test]
    fn an_agent_row_written_before_the_field_is_absent_not_not_read() {
        let json = r#"{"ts_unix":1,"cwd":"","wrap":"agent:brain-nx-t5","args":[],
                       "callers":[],"callers_truncated":false,
                       "secrets":["secret://op/a/b"],"decision":"approve"}"#;
        let parsed: AuditEntry = serde_json::from_str(json).expect("older rows must parse");
        assert_eq!(parsed.declared_by, None);
        assert_ne!(parsed.declared_by, Some(ScopeDeclarant::NotRead));
    }

    /// The invariant that makes an absent field readable: every row this
    /// version writes with an `agent:` wrap answers the question, so absence
    /// on such a row means an old log and nothing else.
    #[test]
    fn every_scoped_agent_row_this_version_writes_answers_who_named_the_scope() {
        let agent_rows = [
            AuditEntry::agent_resolve(
                "brain-nx-t5",
                "secret://op/a/b",
                Decision::Approve,
                None,
                ScopeDeclarant::Peer(impostor()),
            ),
            AuditEntry::abandoned(AbandonedAsk {
                wrap: "agent:brain-nx-t5",
                args: &[],
                cwd: "",
                callers: &[],
                callers_truncated: false,
                secret_names: &[],
                sign_anchor: None,
                declared_by: Some(ScopeDeclarant::Gone),
            }),
        ];
        for row in &agent_rows {
            assert!(
                row.wrap.starts_with("agent:"),
                "this test is only meaningful for scoped-agent rows: {row:?}"
            );
            assert!(
                row.declared_by.is_some(),
                "constructor left the declarant absent on an agent: row, which a \
                 reader takes to mean 'written by an older secreq': {row:?}"
            );
        }

        // The two that declare no scope leave it off, which is what keeps the
        // field out of every wrap and sign row in the log.
        let chain = CallerChain {
            frames: Vec::new(),
            truncated: false,
        };
        assert!(AuditEntry::new("gh", &[], &chain, &[], Decision::Approve)
            .declared_by
            .is_none());
        assert!(AuditEntry::ssh_sign(
            "ssh.deploy",
            "SHA256:x",
            &chain,
            &test_anchor(SignAnchorKind::Session, 1, "-zsh"),
            "/w",
            Decision::Approve
        )
        .declared_by
        .is_none());
    }

    /// The invariant the audit view's unknown state rests on: every row this
    /// version writes with an `ssh:` wrap names its anchor, so an absent one on
    /// such a row means an old log and nothing else. The two constructors that
    /// can produce an `ssh:` row are [`AuditEntry::ssh_sign`] and
    /// [`AuditEntry::abandoned`] (a sign whose requester gave up is still an
    /// `ssh:` row); the other two cannot, and say so with `None`.
    #[test]
    fn every_sign_row_this_version_names_its_anchor() {
        let chain = CallerChain {
            frames: Vec::new(),
            truncated: false,
        };
        let anchor = test_anchor(SignAnchorKind::Session, 7926, "-zsh");
        let sign_rows = [
            AuditEntry::ssh_sign(
                "ssh.deploy",
                "SHA256:x",
                &chain,
                &anchor,
                "/w",
                Decision::Approve,
            ),
            AuditEntry::abandoned(AbandonedAsk {
                wrap: "ssh:ssh.deploy",
                args: &[],
                cwd: "/w",
                callers: &[],
                callers_truncated: false,
                secret_names: &[],
                sign_anchor: Some(AuditSignAnchor::from_runtime(&anchor)),
                declared_by: None,
            }),
        ];
        for row in &sign_rows {
            assert!(
                row.wrap.starts_with("ssh:"),
                "this test is only meaningful for sign rows: {row:?}"
            );
            assert!(
                row.sign_anchor.is_some(),
                "constructor left the anchor absent on an ssh: row, which a \
                 reader takes to mean 'written by an older secreq': {row:?}"
            );
        }

        // The two that cannot sign leave it off, which is what keeps the field
        // out of every wrap row in the log.
        assert!(AuditEntry::new("gh", &[], &chain, &[], Decision::Approve)
            .sign_anchor
            .is_none());
        assert!(AuditEntry::agent_resolve(
            "scope",
            "secret://op/a/b",
            Decision::Approve,
            None,
            ScopeDeclarant::NotRead
        )
        .sign_anchor
        .is_none());
    }

    /// The invariant the audit view's third state rests on: **every**
    /// constructor writes the field, so an absent one means an old row and
    /// nothing else. If a future constructor forgets it, this fails here
    /// rather than by silently labelling fresh rows "may be more above".
    #[test]
    fn every_row_this_version_writes_carries_a_truncation_answer() {
        let chain = CallerChain {
            frames: vec![Caller {
                pid: 1,
                name: "zsh".to_owned(),
                command: "-zsh".to_owned(),
                exe: None,
                start_time: 1,
            }],
            truncated: true,
        };
        let anchor = test_anchor(SignAnchorKind::Session, 7926, "-zsh");
        let rows = [
            AuditEntry::new("gh", &[], &chain, &[], Decision::Approve),
            AuditEntry::ssh_sign(
                "ssh.deploy",
                "SHA256:x",
                &chain,
                &anchor,
                "/w",
                Decision::Approve,
            ),
            AuditEntry::agent_resolve(
                "scope",
                "secret://op/a/b",
                Decision::Approve,
                None,
                ScopeDeclarant::NotRead,
            ),
            AuditEntry::abandoned(AbandonedAsk {
                wrap: "gh",
                args: &[],
                cwd: "/w",
                callers: &[],
                callers_truncated: true,
                secret_names: &[],
                sign_anchor: None,
                declared_by: None,
            }),
        ];
        for row in &rows {
            assert!(
                row.callers_truncated.is_some(),
                "constructor left the field absent, which the reader takes to mean \
                 'written by an older secreq': {row:?}"
            );
            let json = serde_json::to_string(row).expect("serialize");
            assert!(json.contains("\"callers_truncated\":"), "json: {json}");
        }
    }

    /// The walk's own answer has to survive the write — both ways round.
    #[test]
    fn a_clipped_walk_is_recorded_as_clipped_and_a_whole_one_as_whole() {
        let frames = vec![Caller {
            pid: 1,
            name: "zsh".to_owned(),
            command: "-zsh".to_owned(),
            exe: None,
            start_time: 1,
        }];
        let clipped = CallerChain {
            frames: frames.clone(),
            truncated: true,
        };
        let whole = CallerChain {
            frames,
            truncated: false,
        };
        assert_eq!(
            AuditEntry::new("gh", &[], &clipped, &[], Decision::Approve).callers_truncated,
            Some(true)
        );
        assert_eq!(
            AuditEntry::new("gh", &[], &whole, &[], Decision::Approve).callers_truncated,
            Some(false)
        );
        assert_eq!(
            AuditEntry::ssh_sign(
                "k",
                "SHA256:x",
                &clipped,
                &test_anchor(SignAnchorKind::Session, 1, "-zsh"),
                "/w",
                Decision::Approve
            )
            .callers_truncated,
            Some(true)
        );
    }

    /// A row written before the field existed reads back as `None` — **not**
    /// as `Some(false)`. The distinction is the whole point: the log does not
    /// know whether that chain was the whole ancestry, and a reader must not
    /// be shown a walk's stopping point dressed as an origin.
    #[test]
    fn a_row_written_before_the_field_reads_back_as_unknown_not_as_whole() {
        let json = r#"{"ts_unix":1,"cwd":"/w","wrap":"gh","args":[],
                       "callers":[{"pid":9,"name":"zsh","command":"-zsh"}],
                       "secrets":["GITHUB_TOKEN"],"decision":"approve"}"#;
        let parsed: AuditEntry = serde_json::from_str(json).expect("older rows must parse");
        assert_eq!(parsed.callers_truncated, None);
        assert_ne!(parsed.callers_truncated, Some(false));
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
