//! Link-only projection of pending asks.
//!
//! This is the type boundary for cleartext LAN serialization. It deliberately
//! does not embed `daemon::proto::Ask` or `WireSnapshot` in its serialized
//! shape: those desktop/daemon types also carry provider commands, cache
//! policy, internal dedupe anchors, rules and viewer state. Adding one of those
//! fields there must not make it cross `/events` automatically.

use serde::{Deserialize, Serialize};

use crate::daemon::proto::{Ask, AskSubject, RowStatus, WireQueueRow, WireSnapshot};
use crate::provenance::SignAnchorKind;

/// The complete JSON value allowed to cross `GET /events`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkSnapshot {
    pub queue: Vec<LinkQueueRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_error: Option<LinkError>,
}

impl From<&WireSnapshot> for LinkSnapshot {
    fn from(snapshot: &WireSnapshot) -> Self {
        Self {
            queue: snapshot.queue.iter().map(LinkQueueRow::from).collect(),
            link_error: snapshot.link_error.as_ref().map(|error| LinkError {
                message: error.message.clone(),
            }),
        }
    }
}

/// The already-redacted, displayable top-level failure. The request id is a
/// daemon correlation detail and is intentionally not sent because the link UI
/// only renders this message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkError {
    pub message: String,
}

/// One pending or resolving request visible to a linked browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkQueueRow {
    pub request_id: String,
    pub ask_hash_hex: String,
    pub representative: LinkAsk,
    pub status: RowStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolving_since: Option<u64>,
}

impl From<&WireQueueRow> for LinkQueueRow {
    fn from(row: &WireQueueRow) -> Self {
        Self {
            request_id: row.request_id.clone(),
            ask_hash_hex: row.ask_hash_hex.clone(),
            representative: LinkAsk::from(&row.representative),
            status: row.status,
            resolving_since: row.resolving_since,
        }
    }
}

/// Only the ask fields rendered by the link client or consumed by canonical
/// hash v1. The display-facing wrap name lives only on the two subject variants
/// whose v1 hash covers it; the daemon's dedupe key, process/session anchor and
/// subject digest stay daemon-local.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkAsk {
    pub command: Vec<String>,
    pub subject: LinkAskSubject,
}

impl From<&Ask> for LinkAsk {
    fn from(ask: &Ask) -> Self {
        let subject = match &ask.subject {
            AskSubject::Wrap(wrap) => LinkAskSubject::Wrap(LinkWrapSubject {
                wrap: ask.dedupe_key.wrap.clone(),
                cwd: wrap.cwd.clone(),
                callers: wrap.callers.iter().map(LinkCaller::from).collect(),
                callers_truncated: wrap.callers_truncated,
                secrets: wrap.secrets.iter().map(LinkSecretAsk::from).collect(),
                allow_remember: wrap.allow_remember,
            }),
            AskSubject::SshSign(ssh) => LinkAskSubject::SshSign(LinkSshSubject {
                wrap: ask.dedupe_key.wrap.clone(),
                cwd: ssh.cwd.clone(),
                callers: ssh.callers.iter().map(LinkCaller::from).collect(),
                callers_truncated: ssh.callers_truncated,
                info: LinkSshAskInfo {
                    key_id: ssh.info.key_id.clone(),
                    fingerprint: ssh.info.fingerprint.clone(),
                    reason: ssh.info.reason.clone(),
                    anchor: ssh.info.anchor.as_ref().map(|anchor| LinkSshAnchorInfo {
                        name: anchor.name.clone(),
                        pid: anchor.pid,
                        kind: anchor.kind,
                        command: anchor.command.clone(),
                    }),
                },
            }),
            AskSubject::ScopedAgent(agent) => LinkAskSubject::ScopedAgent(LinkAgentAskInfo {
                scope: agent.scope.clone(),
                reference: agent.reference.clone(),
                guest_chain: agent.guest_chain.clone(),
                declared_by: agent.declared_by.as_ref().map(|peer| LinkLocalPeer {
                    pid: peer.pid,
                    name: peer.name.clone(),
                    exe: peer.exe.clone(),
                }),
            }),
        };
        Self {
            command: ask.command.clone(),
            subject,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinkAskSubject {
    Wrap(LinkWrapSubject),
    SshSign(LinkSshSubject),
    ScopedAgent(LinkAgentAskInfo),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkWrapSubject {
    pub wrap: String,
    pub cwd: String,
    pub callers: Vec<LinkCaller>,
    pub callers_truncated: bool,
    pub secrets: Vec<LinkSecretAsk>,
    pub allow_remember: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkSshSubject {
    pub wrap: String,
    pub cwd: String,
    pub callers: Vec<LinkCaller>,
    pub callers_truncated: bool,
    pub info: LinkSshAskInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkAgentAskInfo {
    pub scope: String,
    pub reference: String,
    pub guest_chain: Option<String>,
    pub declared_by: Option<LinkLocalPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkCaller {
    pub pid: u32,
    pub name: String,
    pub command: String,
    pub exe: Option<String>,
}

impl From<&crate::daemon::proto::Caller> for LinkCaller {
    fn from(caller: &crate::daemon::proto::Caller) -> Self {
        Self {
            pid: caller.pid,
            name: caller.name.clone(),
            command: caller.command.clone(),
            exe: caller.exe.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkSecretAsk {
    pub name: String,
    pub provider: String,
    pub locator: String,
    pub description: Option<String>,
    pub reason: Option<String>,
    pub requested_by: Vec<String>,
    pub declared_as: Option<String>,
}

impl From<&crate::daemon::proto::SecretAsk> for LinkSecretAsk {
    fn from(secret: &crate::daemon::proto::SecretAsk) -> Self {
        Self {
            name: secret.name.clone(),
            provider: secret.provider.clone(),
            locator: secret.locator.clone(),
            description: secret.description.clone(),
            reason: secret.reason.clone(),
            requested_by: secret.requested_by.clone(),
            declared_as: secret.declared_as.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkSshAskInfo {
    pub key_id: String,
    pub fingerprint: String,
    pub reason: Option<String>,
    pub anchor: Option<LinkSshAnchorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkSshAnchorInfo {
    pub name: String,
    pub pid: u32,
    pub kind: SignAnchorKind,
    pub command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkLocalPeer {
    pub pid: u32,
    pub name: String,
    pub exe: Option<String>,
}

/// Internal event on a linked subscriber channel. Only `Snapshot` is ever
/// serialized; the exit marker controls the stream lifetime.
#[derive(Debug, Clone)]
pub(crate) enum LinkEvent {
    Snapshot(LinkSnapshot),
    ExitPlease,
}
