//! Wire protocol between `secreq` clients and the consent daemon.
//!
//! One JSON object per line, both directions. The client opens the socket,
//! writes a [`ClientMsg`], reads a [`DaemonMsg`], closes. The daemon's reply
//! may arrive seconds later (waiting on the user) but no keep-alive is
//! needed — the socket stays open across the wait.
//!
//! ## What crosses this socket
//!
//! - **Metadata** (always): command, cwd, caller chain, env-var names,
//!   provider schemes, locators, provider invocation templates.
//! - **Resolved secret values** (on Approve): the daemon runs the
//!   providers itself and ships the values back to every waiter. This is
//!   the load-bearing reason the daemon exists — it collapses N parallel
//!   client-side `op read` invocations (and their biometric prompts) into
//!   exactly one.
//!
//! The trust boundary is the per-user `0600` socket. Any process running
//! as the user already has the same access the daemon does, so adding
//! resolved values to the wire doesn't expand the threat surface — it
//! consolidates work that would otherwise happen N times in N clients.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::consent::Decision;

/// One message from client → daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientMsg {
    /// "Decide whether this wrap can run, and if so resolve the secrets."
    /// The daemon either replies immediately from cache (with resolution
    /// done daemon-side) or queues the ask for the user's review.
    Ask(Ask),
    /// "Show the pending-requests window." Used by `secreq pending`.
    /// Returns [`DaemonMsg::Ok`] immediately. The window will auto-hide
    /// once the queue empties (after a short grace period).
    ShowWindow,
    /// "Show the window in viewer mode" — same as `ShowWindow` but the
    /// auto-hide is suppressed so the user can browse the audit log.
    /// Used by `secreq view`. Viewer mode clears on manual close.
    ShowViewer,
    /// "Are you alive?" Used by the auto-spawn poll loop. Replies with `Ok`.
    Ping,
    /// "Exit cleanly." Used by `secreq daemon stop` to forget the
    /// in-memory approvals cache (and free the singleton pidfile lock).
    /// Replies with `Ok` immediately; the actual exit happens on the
    /// next UI tick.
    Shutdown,
}

/// Everything the daemon needs to render the prompt **and** resolve the
/// secrets after the user approves. Carries no secret *values* — only
/// addresses (locators) and the templates needed to fetch them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ask {
    /// Argv of the command the wrap will exec.
    pub command: Vec<String>,
    /// Working directory of the requesting process.
    pub cwd: String,
    /// Parent-process chain, nearest-first.
    pub callers: Vec<Caller>,
    /// Secrets to be granted: name + reference + reason. The locator is
    /// not a value, so it's safe on the wire — and the daemon needs it to
    /// invoke the provider's `retrieve` template.
    pub secrets: Vec<SecretAsk>,
    /// The provider definitions the daemon needs to run resolution. Each
    /// `SecretAsk.provider` must be a key here. We send a *snapshot* per
    /// ask so the daemon doesn't have to re-read the user's config file
    /// (and so coalesced asks all agree on what to run).
    pub providers: HashMap<String, WireProvider>,
    /// Coalescing key: parallel asks with the same key fold into one queue
    /// entry. Today: `(wrap_name, ppid, parent_start_time)`.
    pub dedupe_key: DedupeKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DedupeKey {
    pub wrap: String,
    pub ppid: u32,
    pub parent_start_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Caller {
    pub pid: u32,
    pub name: String,
    pub command: String,
    /// Process start time as `sysinfo` reports it. The `(pid, start_time)`
    /// pair is what makes an ancestor cache hit pid-recycle-safe — a new
    /// process inheriting the same pid will have a different start_time,
    /// so it can't ride an old approval. Default 0 for any client that
    /// hasn't been updated yet; matching against 0 just falls through.
    #[serde(default)]
    pub start_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAsk {
    pub name: String,
    pub provider: String,
    pub locator: String,
    pub default: Option<String>,
    pub description: Option<String>,
    pub reason: Option<String>,
}

/// Wire-form provider definition. Mirrors [`crate::manifest::Provider`]
/// but with serde derives and only the fields the daemon needs to do
/// retrieval. We don't ship `store` capabilities — the daemon never
/// writes secrets, only reads them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireProvider {
    pub name: String,
    pub retrieve: Vec<String>,
    pub retrieve_batch: Option<WireBatchRetrieve>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireBatchRetrieve {
    pub command: Vec<String>,
    pub env_value_template: String,
}

/// One message from daemon → client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DaemonMsg {
    /// The decision plus, on approve, the resolved secret values keyed by
    /// env-var name. On `Deny`, `secrets` is empty.
    Decision {
        decision: Decision,
        secrets: HashMap<String, String>,
    },
    /// Generic acknowledgement (Ping / ShowWindow).
    Ok,
    /// Daemon-side error (resolution failed, etc.). Client should treat
    /// as a hard error, not a silent deny — the user approved and the
    /// fetch then failed, which is different from "user said no."
    Err { message: String },
}
