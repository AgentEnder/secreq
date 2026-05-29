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
    /// Do not release; the run is aborted.
    Deny,
}

impl Decision {
    pub fn approved(self) -> bool {
        matches!(self, Decision::Approve | Decision::ApproveRemember)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Approve => "approve",
            Decision::ApproveRemember => "approve+remember",
            Decision::Deny => "deny",
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
        assert_eq!(Decision::Deny.as_str(), "deny");
    }

    #[test]
    fn decision_approved() {
        assert!(Decision::Approve.approved());
        assert!(Decision::ApproveRemember.approved());
        assert!(!Decision::Deny.approved());
    }
}
