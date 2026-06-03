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
    fn decision_approved() {
        assert!(Decision::Approve.approved());
        assert!(Decision::ApproveRemember.approved());
        assert!(Decision::ApproveCached.approved());
        assert!(Decision::ApproveAuto.approved());
        assert!(!Decision::Deny.approved());
        assert!(!Decision::DenyAuto.approved());
    }
}
