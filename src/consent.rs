//! Consent data types.
//!
//! The user-facing prompt has moved into [`crate::daemon`]; this module now
//! owns:
//! - [`Decision`] — the serializable enum that crosses the daemon socket
//!   and lands in the audit log.
//! - [`ApprovalEntry`] — the in-memory remembered-approval record the
//!   daemon keys on `(wrap, ppid, parent_start_time)`. Never persisted:
//!   approvals live for the daemon process's lifetime only, so a daemon
//!   restart (`secreq daemon stop`) is the way to clear them. This is the
//!   security property we want — a remembered approval can't outlive the
//!   user's awareness of what they approved.

use serde::{Deserialize, Serialize};

/// The user's decision on a consent request.
///
/// Serializable so it crosses the daemon socket (`daemon::proto`) and lands
/// in the audit log. Only the **decision** crosses the wire — never the
/// secret value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Release the secrets for this run only. Not cached.
    Approve,
    /// Release and remember `(wrap, ppid, parent_start_time)` in the
    /// daemon's in-memory approvals cache. Subsequent asks from the same
    /// parent skip the prompt for as long as the daemon (and that parent
    /// process) lives.
    ApproveRemember,
    /// Released without prompting the user — the daemon's approvals
    /// cache had a matching `(wrap, scope)` entry from a prior
    /// `ApproveRemember`. The user never saw a window for this ask;
    /// it's distinguished from `Approve` so the audit log can show
    /// "the user wasn't asked again" vs. "the user was asked and
    /// said yes."
    ApproveCached,
    /// Released by a matching auto-approve rule from
    /// [`crate::rules`]. Unlike `ApproveRemember` / `ApproveCached`,
    /// the authorization is **persisted** — it survives daemon
    /// restarts via the rules file. Audit rows for this variant
    /// carry the firing rule's id so the user can trace which rule
    /// fired.
    ApproveAuto,
    /// SSH-sign only: approve this sign **and** remember a session grant
    /// for *this key* on the current anchor for the session TTL (see
    /// [`SshGrant`]). Subsequent signs of the same key from the same
    /// session skip the prompt until the grant expires.
    ApproveSshSession,
    /// SSH-sign only: approve this sign **and** remember a session grant
    /// for *all keys* on the current anchor for the session TTL — "stop
    /// asking me about any of my keys in this session for a while."
    ApproveSshSessionAll,
    /// Do not release; the run is aborted.
    Deny,
    /// Denied by a matching auto-deny rule. The wrap client surfaces
    /// the rule's configured `deny_message` (if any) to stderr before
    /// exiting 1.
    DenyAuto,
    /// Scoped-agent only: the guest asked for a `secret://` ref outside
    /// the allowlist its socket was opened with, so it was refused
    /// **without a prompt** (see [`crate::scoped_agent`]). Distinct from
    /// `Deny` for the same reason `ApproveCached` is distinct from
    /// `Approve` — it records that *the user was never asked*. That
    /// distinction is what lets someone reading the log tell "I refused
    /// this" from "a guest probed for something it was never offered",
    /// which is the signal a compromised sandbox would generate.
    DenyOutOfScope,
    /// The requesting process (the wrap, or an ancestor that took it
    /// down with it) exited before the user decided — the ask was
    /// abandoned, not answered. No secret is released and nothing is
    /// remembered. There is no live wrap client to write the audit row
    /// in this case, so the **daemon** records it directly (the second
    /// documented exception to "the daemon never writes audit rows",
    /// alongside SSH signs — see `CLAUDE.md`).
    Abandoned,
}

impl Decision {
    pub fn approved(self) -> bool {
        matches!(
            self,
            Decision::Approve
                | Decision::ApproveRemember
                | Decision::ApproveCached
                | Decision::ApproveAuto
                | Decision::ApproveSshSession
                | Decision::ApproveSshSessionAll
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Approve => "approve",
            Decision::ApproveRemember => "approve+remember",
            Decision::ApproveCached => "approve+cached",
            Decision::ApproveAuto => "approve+auto",
            Decision::ApproveSshSession => "approve+ssh-session",
            Decision::ApproveSshSessionAll => "approve+ssh-session-all",
            Decision::Deny => "deny",
            Decision::DenyAuto => "deny+auto",
            Decision::DenyOutOfScope => "deny+out-of-scope",
            Decision::Abandoned => "abandoned",
        }
    }
}

// ── Approval cache: scoped to the daemon process's lifetime ───────────────
//
// Each entry binds (wrap_name, ppid, parent_start_time). Re-invocations
// from the *same* parent skip the prompt; any other parent (npm postinstall,
// IDE integration, a fresh shell) prompts. There is **no TTL** and **no
// disk persistence** — the cache lives inside the daemon's memory and is
// gone when the daemon exits, by design:
//
//   - Survival across pid recycling is guaranteed by the `start_time`
//     part of the key, not by a timer.
//   - Restarting the daemon (`secreq daemon stop`, then any wrap re-spawns
//     it) is the canonical way for a user to revoke previously-granted
//     "approve all"s. A user who can't remember what they approved can
//     always reset cheaply.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalEntry {
    pub wrap: String,
    pub ppid: u32,
    pub parent_start_time: u64,
}

// ── SSH sign session grants: a deliberate TTL divergence ──────────────────
//
// [`SshGrant`] is the SSH-agent analogue of [`ApprovalEntry`], but it
// carries two things the wrap cache above intentionally does **not**: a
// wall-clock `expires_at` (Unix seconds), and a key *scope* that can be a
// single identity or a wildcard over all of them.
//
// Why a TTL? The wrap cache binds `(wrap, ppid, parent_start_time)` and
// relies on the parent process's lifetime as the natural expiry: a `gh`
// wrap's parent shell dies, its pid/start_time stop matching, and the
// approval is effectively dead. There's a concrete, user-observable event
// (the parent exits) that ends the grant, so a timer would be redundant.
//
// An SSH agent anchor is different. The anchor is the long-lived
// shell / IDE / git session that drives `ssh` — it can stay alive for
// *hours* (a developer's editor open all day). Binding a SIGN grant to the
// anchor's lifetime alone would mean one approval at 9am authorizes every
// signature until the editor closes at 6pm. That's too loose for a signing
// key, so grants are additionally time-bounded: the grant survives only
// `now < expires_at`, after which the next sign re-prompts even though the
// same anchor is still alive. (The re-prompt costs no biometric — the
// resolved key is cached like any other secret — but it re-confirms intent.)
//
// Why a wildcard scope? The consent prompt offers both "approve this key
// for the session" and "approve *all* keys for the session"; the latter is
// a single grant with [`SshGrantScope::AllKeys`].
//
// This is the *only* place in the codebase that puts a clock on an
// in-memory approval; it's scoped to SSH signing on purpose and should not
// be generalized back onto the wrap cache.

/// The key scope of an [`SshGrant`]: a single identity, or every identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshGrantScope {
    /// Grant covers exactly this `key_id`.
    OneKey(String),
    /// Grant covers every configured key (the "approve all keys" choice).
    AllKeys,
}

/// The anchor a grant is scoped to — the `(pid, start_time)` of the
/// long-lived session (shell / IDE / git) that drives the signing. A grant
/// only matches signs whose anchor is this exact session, so it can't leak
/// to an unrelated process that happens to reuse a recycled pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshAnchor {
    pub pid: u32,
    pub start_time: u64,
}

/// Remembered SSH sign session grant. Unlike [`ApprovalEntry`] (the wrap
/// cache, which has no TTL), this carries a wall-clock `expires_at` (Unix
/// seconds) and a [`SshGrantScope`]. See the module-level note above for the
/// rationale behind both divergences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshGrant {
    pub scope: SshGrantScope,
    pub anchor: SshAnchor,
    /// Unix seconds after which this grant no longer matches.
    pub expires_at: u64,
}

impl SshGrant {
    /// True iff the scope covers `key_id`, the anchor is this exact session,
    /// **and** the grant has not yet expired (`now < expires_at`). `now` is
    /// passed in (Unix seconds) so callers control the clock — the lookup in
    /// `state.rs` reads `SystemTime::now()`, while tests pass explicit values.
    pub fn matches(&self, key_id: &str, pid: u32, start: u64, now: u64) -> bool {
        let key_ok = match &self.scope {
            SshGrantScope::OneKey(id) => id == key_id,
            SshGrantScope::AllKeys => true,
        };
        key_ok && self.anchor.pid == pid && self.anchor.start_time == start && now < self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_str() {
        assert_eq!(Decision::Approve.as_str(), "approve");
        assert_eq!(Decision::ApproveRemember.as_str(), "approve+remember");
        assert_eq!(Decision::ApproveCached.as_str(), "approve+cached");
        assert_eq!(Decision::ApproveAuto.as_str(), "approve+auto");
        assert_eq!(Decision::ApproveSshSession.as_str(), "approve+ssh-session");
        assert_eq!(
            Decision::ApproveSshSessionAll.as_str(),
            "approve+ssh-session-all"
        );
        assert_eq!(Decision::Deny.as_str(), "deny");
        assert_eq!(Decision::DenyAuto.as_str(), "deny+auto");
        assert_eq!(Decision::DenyOutOfScope.as_str(), "deny+out-of-scope");
        assert_eq!(Decision::Abandoned.as_str(), "abandoned");
    }

    #[test]
    fn ssh_grant_one_key_expires_and_scopes() {
        let grant = SshGrant {
            scope: SshGrantScope::OneKey("github".into()),
            anchor: SshAnchor {
                pid: 42,
                start_time: 1000,
            },
            expires_at: 5000,
        };
        assert!(grant.matches("github", 42, 1000, /*now=*/ 4999));
        assert!(!grant.matches("github", 42, 1000, /*now=*/ 5001)); // expired
        assert!(!grant.matches("other", 42, 1000, 4999)); // wrong key
        assert!(!grant.matches("github", 43, 1000, 4999)); // wrong anchor pid
        assert!(!grant.matches("github", 42, 1001, 4999)); // wrong anchor start
    }

    #[test]
    fn ssh_grant_all_keys_covers_any_identity() {
        let grant = SshGrant {
            scope: SshGrantScope::AllKeys,
            anchor: SshAnchor {
                pid: 42,
                start_time: 1000,
            },
            expires_at: 5000,
        };
        // Any key id matches while the anchor + TTL hold.
        assert!(grant.matches("github", 42, 1000, 4999));
        assert!(grant.matches("gitlab", 42, 1000, 4999));
        // But the anchor scoping and TTL still bind.
        assert!(!grant.matches("github", 99, 1000, 4999)); // wrong anchor
        assert!(!grant.matches("github", 42, 1000, 5001)); // expired
    }

    #[test]
    fn decision_approved() {
        assert!(Decision::Approve.approved());
        assert!(Decision::ApproveRemember.approved());
        assert!(Decision::ApproveCached.approved());
        assert!(Decision::ApproveAuto.approved());
        assert!(Decision::ApproveSshSession.approved());
        assert!(Decision::ApproveSshSessionAll.approved());
        assert!(!Decision::Deny.approved());
        assert!(!Decision::DenyAuto.approved());
        assert!(!Decision::DenyOutOfScope.approved());
        // Abandoned is a non-decision (the caller vanished before the user
        // chose); it must never read as an approval.
        assert!(!Decision::Abandoned.approved());
    }
}
