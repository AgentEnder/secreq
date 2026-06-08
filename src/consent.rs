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
    /// Do not release; the run is aborted.
    Deny,
    /// Denied by a matching auto-deny rule. The wrap client surfaces
    /// the rule's configured `deny_message` (if any) to stderr before
    /// exiting 1.
    DenyAuto,
}

impl Decision {
    pub fn approved(self) -> bool {
        matches!(
            self,
            Decision::Approve
                | Decision::ApproveRemember
                | Decision::ApproveCached
                | Decision::ApproveAuto
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Approve => "approve",
            Decision::ApproveRemember => "approve+remember",
            Decision::ApproveCached => "approve+cached",
            Decision::ApproveAuto => "approve+auto",
            Decision::Deny => "deny",
            Decision::DenyAuto => "deny+auto",
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

// ── SSH sign approval cache: a deliberate TTL divergence ──────────────────
//
// [`SshApprovalEntry`] is the SSH-agent analogue of [`ApprovalEntry`], but
// it carries a wall-clock `expires_at` (Unix seconds) that the wrap cache
// above intentionally does **not** have.
//
// Why diverge? The wrap cache binds `(wrap, ppid, parent_start_time)` and
// relies on the parent process's lifetime as the natural expiry: a `gh`
// wrap's parent shell dies, its pid/start_time stop matching, and the
// approval is effectively dead. There's a concrete, user-observable event
// (the parent exits) that ends the grant, so a timer would be redundant.
//
// An SSH agent anchor is different. The anchor is the long-lived
// shell / IDE / git session that drives `ssh` — it can stay alive for
// *hours* (a developer's editor open all day). Binding a SIGN approval to
// the anchor's lifetime alone would mean one biometric tap at 9am
// authorizes every signature until the editor closes at 6pm. That's too
// loose for a signing key, so SSH approvals are additionally time-bounded:
// the grant survives only `now < expires_at`, after which the next sign
// re-prompts even though the same anchor is still alive.
//
// This is the *only* place in the codebase that puts a clock on an
// in-memory approval; it's scoped to SSH signing on purpose and should not
// be generalized back onto the wrap cache.

/// Remembered SSH sign approval. Unlike [`ApprovalEntry`] (the wrap cache,
/// which has no TTL), this carries a wall-clock `expires_at` (Unix
/// seconds): an anchor (shell / IDE / git session) can live for hours, so a
/// SIGN approval is time-bounded rather than tied to the anchor's lifetime
/// alone. See the module-level note above for the rationale behind the
/// divergence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshApprovalEntry {
    pub key_id: String,
    pub anchor_pid: u32,
    pub anchor_start_time: u64,
    /// Unix seconds after which this approval no longer matches.
    pub expires_at: u64,
}

impl SshApprovalEntry {
    /// True iff the identity, anchor, and start-time all match **and** the
    /// approval has not yet expired (`now < expires_at`). `now` is passed
    /// in (Unix seconds) so callers control the clock — the lookup in
    /// `state.rs` reads `SystemTime::now()`, while tests pass explicit
    /// values.
    pub fn matches(&self, key_id: &str, pid: u32, start: u64, now: u64) -> bool {
        self.key_id == key_id
            && self.anchor_pid == pid
            && self.anchor_start_time == start
            && now < self.expires_at
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
        assert_eq!(Decision::Deny.as_str(), "deny");
        assert_eq!(Decision::DenyAuto.as_str(), "deny+auto");
    }

    #[test]
    fn ssh_approval_expires() {
        let entry = SshApprovalEntry {
            key_id: "github".into(),
            anchor_pid: 42,
            anchor_start_time: 1000,
            expires_at: 5000,
        };
        assert!(entry.matches("github", 42, 1000, /*now=*/ 4999));
        assert!(!entry.matches("github", 42, 1000, /*now=*/ 5001)); // expired
        assert!(!entry.matches("other", 42, 1000, 4999)); // wrong key
        assert!(!entry.matches("github", 43, 1000, 4999)); // wrong anchor
    }

    #[test]
    fn decision_approved() {
        assert!(Decision::Approve.approved());
        assert!(Decision::ApproveRemember.approved());
        assert!(Decision::ApproveCached.approved());
        assert!(Decision::ApproveAuto.approved());
        assert!(!Decision::Deny.approved());
        assert!(!Decision::DenyAuto.approved());
    }
}
