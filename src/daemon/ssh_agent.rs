//! SSH agent listener — a second daemon socket speaking the SSH agent
//! protocol (PROTOCOL.agent) at `~/.secreq/agent.sock`.
//!
//! This is separate from the control socket (`consent.sock`): SSH clients
//! (`ssh`, `git`, `ssh-add`) connect here when `SSH_AUTH_SOCK` points at
//! it. The wire format is the SSH agent protocol (see
//! [`super::ssh_proto`]), NOT the daemon's JSON control protocol.
//!
//! `REQUEST_IDENTITIES` answers with the configured public keys, parsed
//! once from the inline `public_key` strings in `wraps.json5` — **no
//! provider resolve, no consent.**
//!
//! `SIGN_REQUEST` is the gated path: derive the connecting peer pid from
//! socket peer-credentials, walk that pid's ancestry to an anchor, gate on
//! the SSH approval cache + (on a miss) interactive consent, then resolve
//! the private key fresh through the provider, sign in-process, zeroize the
//! key material, and return only the signature. The approval cache caches
//! the *decision* (skip the prompt), never the key material — every sign
//! resolves the key fresh and drops it.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use super::proto::{Ask, Caller, DedupeKey, SshAskInfo};
use super::ssh_proto::{self, AgentRequest};
use super::state::{SharedState, WaiterReply};
use crate::consent::{Decision, SshApprovalEntry};
use crate::manifest::Provider;
use crate::wraps::SshIdentity;

/// Upper bound on a single agent frame's payload length. Mirrors OpenSSH's
/// `AGENT_MAX_MSGLEN` (256 KiB) from `authfd.h`: the agent protocol never
/// carries a legitimate message this large, so a bigger length prefix is a
/// buggy/hostile client. We reject it before allocating so an untrusted
/// wire value can't drive an arbitrary allocation in the long-lived daemon.
const MAX_AGENT_MSG_LEN: usize = 256 * 1024;

/// Default lifetime of an SSH sign approval when the user chooses
/// "remember". An anchor (shell / IDE / git session) can live for hours, so
/// a SIGN approval is time-bounded rather than tied to the anchor's
/// lifetime alone. There is no per-identity TTL knob in `wraps.json5`
/// today, so this constant is the single source of truth.
const SSH_APPROVAL_TTL_SECS: u64 = 300;

/// One configured identity prepared for `REQUEST_IDENTITIES` *and* the
/// SIGN path. The public-key blob + comment answer the listing; the
/// `key_id`, `reference`, and `reason` are what the SIGN handler needs to
/// map a wire blob back to its config entry, scope the approval cache, and
/// resolve the private key.
///
/// Derived once, up front, from the inline `public_key` string so the
/// per-connection listing path never parses keys per-connection and never
/// touches a provider.
#[derive(Debug, Clone)]
pub struct PreparedIdentity {
    /// Raw SSH wire public-key blob — what `SSH_AGENT_IDENTITIES_ANSWER`
    /// carries and what a `SIGN_REQUEST`'s `key_blob` is matched against.
    pub blob: Vec<u8>,
    /// The public key's comment (shown by `ssh-add -l`).
    pub comment: String,
    /// The public key's SHA256 fingerprint string (e.g.
    /// `SHA256:Nh0Me49Zh9fDw/…`). Computed once here so the consent prompt
    /// can show the user a stable, recognizable key identifier without the
    /// SIGN handler re-parsing the key per request.
    pub fingerprint: String,
    /// The config identity name (`ssh.<key_id>`), used as the cache key and
    /// the audit/consent label.
    pub key_id: String,
    /// `secret://provider/locator` reference to the private key, resolved
    /// fresh at every SIGN and never cached.
    pub reference: crate::reference::Reference,
    /// `$reason` from the config, shown in the consent prompt.
    pub reason: Option<String>,
}

/// Everything the per-connection SIGN handler needs that isn't on the wire:
/// the prepared identities, the provider definitions used to resolve a
/// private key, and the shared daemon state (consent queue + approval
/// cache). `state` is `None` only for the listing-only test path; the
/// production daemon always supplies it.
#[derive(Clone)]
pub struct SignContext {
    pub identities: Arc<Vec<PreparedIdentity>>,
    pub providers: Arc<BTreeMap<String, Provider>>,
    pub state: Option<SharedState>,
}

/// Stable per-user agent socket path. Lives alongside the control socket
/// (`consent.sock`) in [`super::server::socket_dir`] so both sockets share
/// the same per-user runtime dir; SSH clients point `SSH_AUTH_SOCK` here.
pub fn default_agent_socket_path() -> Result<PathBuf> {
    Ok(super::server::socket_dir()?.join("agent.sock"))
}

/// Parse each identity's inline `public_key` string into its raw SSH wire
/// blob + comment, **once**, up front, carrying the key id / private-key
/// reference / reason alongside so the SIGN handler has the full identity.
///
/// An unparseable `public_key` is skipped with a daemon-log warning rather
/// than failing the whole agent — one malformed entry shouldn't hide every
/// other key from `ssh-add -l`.
pub fn prepare_identities(ssh: &BTreeMap<String, SshIdentity>) -> Vec<PreparedIdentity> {
    let mut prepared = Vec::with_capacity(ssh.len());
    for (name, identity) in ssh {
        match ssh_key::PublicKey::from_openssh(&identity.public_key) {
            Ok(public_key) => match public_key.to_bytes() {
                Ok(blob) => prepared.push(PreparedIdentity {
                    blob,
                    comment: public_key.comment().to_owned(),
                    fingerprint: public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                    key_id: name.clone(),
                    reference: identity.private_key.clone(),
                    reason: identity.reason.clone(),
                }),
                Err(err) => super::log::log_at(
                    "ssh-agent",
                    format_args!("identity {name:?}: cannot serialize public key blob: {err}"),
                ),
            },
            Err(err) => super::log::log_at(
                "ssh-agent",
                format_args!("identity {name:?}: malformed public_key, skipping: {err}"),
            ),
        }
    }
    prepared
}

/// Bind the agent socket (unlinking any stale file first), set `0600`
/// perms, and spawn the accept loop. Returns the bound listener so the
/// caller keeps it alive; the accept thread exits when the listener is
/// dropped. Returns `Ok(None)` when there are no configured identities —
/// no agent socket is created in that case.
pub fn start(
    socket_path: PathBuf,
    ssh: &BTreeMap<String, SshIdentity>,
    providers: BTreeMap<String, Provider>,
    state: SharedState,
) -> Result<Option<UnixListener>> {
    if ssh.is_empty() {
        return Ok(None);
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    // Clear a stale socket from a previously-crashed daemon. The pidfile
    // flock taken in `daemon::run` guarantees we're the only live daemon,
    // so this can't race a running one.
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind agent socket {}", socket_path.display()))?;
    let mut perms = std::fs::metadata(&socket_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&socket_path, perms)?;

    let identities = prepare_identities(ssh);
    super::log::log_at(
        "ssh-agent",
        format_args!(
            "listener bound at {} serving {} identit{}",
            socket_path.display(),
            identities.len(),
            if identities.len() == 1 { "y" } else { "ies" }
        ),
    );

    let ctx = SignContext {
        identities: Arc::new(identities),
        providers: Arc::new(providers),
        state: Some(state),
    };

    let listener_clone = listener.try_clone().context("clone agent listener")?;
    thread::Builder::new()
        .name("secreqd-ssh-agent".to_owned())
        .spawn(move || serve_on(listener_clone, ctx))
        .context("spawn ssh-agent accept thread")?;

    Ok(Some(listener))
}

/// Accept loop for the agent socket: one thread per connection.
///
/// This is the testable entry point — a test can bind a `UnixListener` on
/// a tempdir path and call `serve_on` directly with a synthetic
/// [`SignContext`], without spawning the whole daemon.
pub fn serve_on(listener: UnixListener, ctx: SignContext) {
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(_) => break, // Listener closed or unrecoverable accept error.
        };
        let ctx = ctx.clone();
        thread::Builder::new()
            .name("secreqd-ssh-conn".to_owned())
            .spawn(move || {
                if let Err(err) = handle_connection(stream, &ctx) {
                    super::log::log_at("ssh-agent", format_args!("connection error: {err:#}"));
                }
            })
            .ok();
    }
}

/// Read framed agent requests off `stream` until the peer hangs up,
/// answering each in turn. SSH clients keep the socket open and pipeline
/// requests (e.g. `ssh-add -l` then a sign), so we loop rather than
/// handling a single message.
fn handle_connection(mut stream: UnixStream, ctx: &SignContext) -> Result<()> {
    // The connecting peer's pid is read once per connection. The SSH client
    // keeps the socket open across a listing + a sign, so the peer is stable
    // for the connection's lifetime.
    let peer_pid = super::peercred::peer_pid(&stream);
    while let Some(frame) = read_frame(&mut stream)? {
        let reply = match ssh_proto::parse_request(&frame) {
            Ok(request) => handle_request(request, ctx, peer_pid),
            // A malformed frame is the client's fault, not ours. Answer
            // FAILURE so a confused client gets a defined response rather
            // than a dropped connection.
            Err(err) => {
                super::log::log_at(
                    "ssh-agent",
                    format_args!("malformed request frame: {err:#}"),
                );
                ssh_proto::encode_failure()
            }
        };
        stream.write_all(&reply).context("write agent reply")?;
    }
    Ok(())
}

/// Map one parsed request to its reply bytes.
///
/// `REQUEST_IDENTITIES` lists the prepared public keys with no resolve and
/// no consent. `SIGN_REQUEST` runs the gated sign flow. Unsupported types
/// answer `SSH_AGENT_FAILURE`.
fn handle_request(request: AgentRequest, ctx: &SignContext, peer_pid: Option<u32>) -> Vec<u8> {
    match request {
        AgentRequest::RequestIdentities => {
            super::log::log_at(
                "ssh-agent",
                format_args!(
                    "← REQUEST_IDENTITIES; answering {} key(s)",
                    ctx.identities.len()
                ),
            );
            let listing: Vec<(&[u8], &str)> = ctx
                .identities
                .iter()
                .map(|id| (id.blob.as_slice(), id.comment.as_str()))
                .collect();
            ssh_proto::encode_identities_answer(&listing)
        }
        AgentRequest::Sign {
            key_blob,
            data,
            flags,
        } => handle_sign(ctx, peer_pid, &key_blob, &data, flags),
        AgentRequest::Unsupported(msg_type) => {
            super::log::log_at(
                "ssh-agent",
                format_args!("← unsupported message type {msg_type}; answering FAILURE"),
            );
            ssh_proto::encode_failure()
        }
    }
}

/// The gated SIGN flow: peer → provenance → consent → resolve → sign.
///
/// Fail-closed at every uncertainty: if we can't determine the peer pid,
/// can't anchor the caller chain, don't recognize the key, can't reach the
/// consent machinery, the user denies, or the resolve/sign fails, we answer
/// `SSH_AGENT_FAILURE` and release nothing.
fn handle_sign(
    ctx: &SignContext,
    peer_pid: Option<u32>,
    key_blob: &[u8],
    data: &[u8],
    flags: u32,
) -> Vec<u8> {
    // 1. Map the requested key blob to a configured identity. Unknown keys
    //    fail closed (the client asked us to sign with a key we don't hold).
    let Some(identity) = ctx.identities.iter().find(|id| id.blob == key_blob) else {
        super::log::log_at(
            "ssh-agent",
            format_args!("← SIGN_REQUEST for an unknown key blob; answering FAILURE"),
        );
        return ssh_proto::encode_failure();
    };

    // 2. Determine the connecting peer and its anchor. Either being
    //    unavailable means we can't attribute the request, so fail closed.
    let Some(peer_pid) = peer_pid else {
        super::log::log_at(
            "ssh-agent",
            format_args!(
                "← SIGN_REQUEST for {:?} but peer pid is unknown; answering FAILURE",
                identity.key_id
            ),
        );
        return ssh_proto::encode_failure();
    };
    let chain = crate::provenance::caller_chain_from_pid(peer_pid);
    let Some(anchor) = crate::provenance::select_anchor(&chain) else {
        super::log::log_at(
            "ssh-agent",
            format_args!(
                "← SIGN_REQUEST for {:?} (peer pid {peer_pid}) but no anchor in caller chain; answering FAILURE",
                identity.key_id
            ),
        );
        return ssh_proto::encode_failure();
    };
    let anchor_pid = anchor.pid;
    let anchor_start_time = anchor.start_time;

    // The production daemon always supplies state; the listing-only test
    // path doesn't. With no state there is no consent machinery, so fail
    // closed rather than signing unconditionally.
    let Some(state) = ctx.state.as_ref() else {
        super::log::log_at(
            "ssh-agent",
            format_args!("← SIGN_REQUEST but no consent state wired; answering FAILURE"),
        );
        return ssh_proto::encode_failure();
    };

    // 3. Decide whether to sign: approval-cache hit (skip the prompt) or
    //    interactive consent. The lock is held only for the cache check and
    //    the queue submission, never across the (blocking) consent wait.
    let decision = match decide_sign(state, identity, anchor_pid, anchor_start_time, &chain) {
        Some(d) if d.approved() => d,
        Some(_) => {
            // Task 12: audit deny.
            super::log::log_at(
                "ssh-agent",
                format_args!(
                    "← SIGN_REQUEST for {:?} denied; answering FAILURE",
                    identity.key_id
                ),
            );
            return ssh_proto::encode_failure();
        }
        None => {
            // Consent unavailable / the waiter channel dropped — fail closed.
            super::log::log_at(
                "ssh-agent",
                format_args!(
                    "← SIGN_REQUEST for {:?}: consent unavailable; answering FAILURE",
                    identity.key_id
                ),
            );
            return ssh_proto::encode_failure();
        }
    };

    // 4. On "remember", insert a TTL-bounded approval scoped to the anchor.
    if decision == Decision::ApproveRemember {
        let expires_at = now_unix_secs().saturating_add(SSH_APPROVAL_TTL_SECS);
        state
            .lock()
            .expect("state mutex")
            .remember_ssh_approval(SshApprovalEntry {
                key_id: identity.key_id.clone(),
                anchor_pid,
                anchor_start_time,
                expires_at,
            });
    }

    // 5. Resolve the private key FRESH, sign, and zeroize. The key material
    //    is never cached or held across requests.
    match resolve_and_sign(&ctx.providers, identity, data, flags) {
        Ok(sig_blob) => {
            // Task 12: audit approve (decision = `decision`).
            super::log::log_at(
                "ssh-agent",
                format_args!(
                    "← SIGN_REQUEST for {:?} ({}); signed {} byte challenge",
                    identity.key_id,
                    decision.as_str(),
                    data.len()
                ),
            );
            ssh_proto::encode_sign_response(&sig_blob)
        }
        Err(err) => {
            super::log::log_at(
                "ssh-agent",
                format_args!(
                    "← SIGN_REQUEST for {:?}: resolve/sign failed ({err:#}); answering FAILURE",
                    identity.key_id
                ),
            );
            ssh_proto::encode_failure()
        }
    }
}

/// Decide whether to sign for `identity` from `anchor`. Returns the approval
/// flavour (`ApproveCached` on a cache hit, or whatever the user chose) or
/// `Deny` on refusal; `None` means the consent machinery was unreachable
/// (caller fails closed).
///
/// **Lock discipline:** the state mutex is taken only for the cache check
/// and the queue submission. The blocking wait on the user's decision parks
/// on an `mpsc::Receiver` with **no lock held**, mirroring `server.rs`'s
/// `handle_ask` so the consent-window child can attach and render while the
/// prompt is up.
fn decide_sign(
    state: &SharedState,
    identity: &PreparedIdentity,
    anchor_pid: u32,
    anchor_start_time: u64,
    chain: &[crate::provenance::Caller],
) -> Option<Decision> {
    // Cache check — lock held only for the lookup. A cached approval needs no
    // UI, so this path is unaffected by whether a display is available; it
    // works headless.
    {
        let mut guard = state.lock().expect("state mutex");
        if guard.has_ssh_approval(&identity.key_id, anchor_pid, anchor_start_time) {
            // Task 12: audit cached.
            return Some(Decision::ApproveCached);
        }
    }

    // Cache miss → interactive consent is required, which needs a window to
    // render. Pass the real gui-availability bool into the miss handler so it
    // can fail closed in a headless environment instead of blocking forever.
    decide_sign_on_miss(
        state,
        identity,
        anchor_pid,
        anchor_start_time,
        chain,
        super::client::graphical_environment_available(),
    )
}

/// The consent-miss half of [`decide_sign`], split out so the headless
/// fail-closed guard can be unit-tested without racy process-global env
/// mutation: the test calls this with `gui_available = false` and asserts the
/// early `None` return happens **before** any `Ask` is submitted or any
/// blocking wait begins (see `consent_miss_without_gui_fails_closed`).
///
/// `gui_available` is the *only* new input; `decide_sign` always passes the
/// real [`super::client::graphical_environment_available`] result, so
/// production behaviour is unchanged for the display-present case.
fn decide_sign_on_miss(
    state: &SharedState,
    identity: &PreparedIdentity,
    anchor_pid: u32,
    anchor_start_time: u64,
    chain: &[crate::provenance::Caller],
    gui_available: bool,
) -> Option<Decision> {
    // No display → the consent window can never render, so `rx.recv()` below
    // would block indefinitely and hang `ssh`/`git`. Fail closed before we
    // touch state or enqueue anything. (A cached approval already returned
    // above, so headless cached signs still work.)
    if !gui_available {
        super::log::log_at(
            "ssh-agent",
            format_args!(
                "← SIGN_REQUEST for {:?}: consent needed but no graphical environment; failing closed",
                identity.key_id
            ),
        );
        return None;
    }

    // Miss → enqueue an Ask and park on the reply channel. Build the Ask so
    // the consent UI (Task 11) and the audit row (Task 12) have the
    // identity, the caller chain, and the anchor scope to render.
    let ask = sign_ask(identity, anchor_pid, anchor_start_time, chain);
    let (tx, rx) = mpsc::channel();
    {
        let mut guard = state.lock().expect("state mutex");
        guard.submit_ask(ask, tx);
    }
    // Raise the consent window so the user can decide. Best-effort: a
    // failure here just means the window doesn't pop, and the wait below
    // will block until the user acts through some other attached window or
    // the daemon shuts down.
    if let Err(err) = super::ensure_consent_window(state) {
        super::log::log_at(
            "ssh-agent",
            format_args!("ensure_consent_window (ssh sign) failed: {err:#}"),
        );
    }

    match rx.recv() {
        Ok(WaiterReply::Decision { decision, .. }) => Some(decision),
        // A resolve error on the wrap path can't happen here (the sign ask
        // carries no secrets for the daemon to resolve — we resolve the key
        // ourselves, fresh), but treat any Err as fail-closed.
        Ok(WaiterReply::Err { .. }) => None,
        Err(_) => None,
    }
}

/// Build the in-process consent [`Ask`] for an SSH sign. Carries **no
/// secrets** for the daemon to resolve — the SSH path resolves the private
/// key itself, fresh, after the decision (so the key is never cached in the
/// daemon's secret cache). The ask exists only to drive the consent prompt
/// and coalesce repeated signs from the same anchor into one queue entry.
fn sign_ask(
    identity: &PreparedIdentity,
    anchor_pid: u32,
    anchor_start_time: u64,
    chain: &[crate::provenance::Caller],
) -> Ask {
    let wrap = format!("ssh:{}", identity.key_id);
    Ask {
        command: vec![format!("ssh-sign {}", identity.key_id)],
        cwd: String::new(),
        callers: chain
            .iter()
            .map(|c| Caller {
                pid: c.pid,
                name: c.name.clone(),
                command: c.command.clone(),
                start_time: c.start_time,
            })
            .collect(),
        // No SecretAsk: the daemon resolves nothing for an SSH sign.
        secrets: Vec::new(),
        providers: std::collections::HashMap::new(),
        dedupe_key: DedupeKey {
            wrap,
            ppid: anchor_pid,
            parent_start_time: anchor_start_time,
        },
        // Mark this ask as an SSH sign so the consent window renders the
        // SSH variant (identity + fingerprint, no secret list) rather than
        // the wrap layout. Carries no secret material — only the display
        // identity and the public-key fingerprint.
        ssh: Some(SshAskInfo {
            key_id: identity.key_id.clone(),
            fingerprint: identity.fingerprint.clone(),
            reason: identity.reason.clone(),
        }),
    }
}

/// Resolve the identity's private-key reference fresh and sign `data`.
///
/// The PEM is held in a [`Zeroizing`] string and scrubbed when this
/// function returns; it is never written to the daemon's secret cache. The
/// resolved [`crate::secret::SecretValue`] is itself zeroizing-on-drop, so
/// the only copy that outlives the resolve is the `Zeroizing` PEM we sign
/// from and immediately drop.
fn resolve_and_sign(
    providers: &BTreeMap<String, Provider>,
    identity: &PreparedIdentity,
    data: &[u8],
    flags: u32,
) -> Result<Vec<u8>> {
    use crate::manifest::Manifest;
    use crate::resolve::{self, ResolutionPlan, SecretRequest, Source};

    let manifest = Manifest {
        groups: BTreeMap::new(),
        providers: providers.clone(),
    };
    let plan = ResolutionPlan {
        requests: vec![SecretRequest {
            name: identity.key_id.clone(),
            provider: identity.reference.provider.clone(),
            locator: identity.reference.locator.clone(),
            group: None,
            reason: identity.reason.clone(),
            description: None,
            default: None,
            source: Source::Eager,
        }],
    };

    let resolved = resolve::resolve_all(&manifest, &plan).with_context(|| {
        format!(
            "resolving private key for ssh identity {:?}",
            identity.key_id
        )
    })?;
    let secret = resolved
        .into_iter()
        .next()
        .with_context(|| format!("provider returned no value for {:?}", identity.key_id))?;

    // Copy the exposed PEM into a zeroizing buffer so it scrubs when this
    // scope ends, then sign from it. `secret` (also zeroizing) drops at the
    // end of the function. Neither copy is cached.
    let pem = Zeroizing::new(secret.value.expose().to_owned());
    crate::ssh_sign::sign(&pem, data, flags).context("signing the SSH challenge")
}

/// Current Unix time in whole seconds, for stamping `expires_at` on a
/// remembered SSH approval.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read one complete `[u32 length][payload]` agent frame off `stream`,
/// returning the **full** frame (length prefix included) so it can be
/// handed straight to [`ssh_proto::parse_request`]. Returns `Ok(None)` on
/// a clean EOF before any bytes of a new frame — the normal "client hung
/// up" signal.
fn read_frame(stream: &mut UnixStream) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match read_exact_or_eof(stream, &mut len_buf)? {
        ReadOutcome::Eof => return Ok(None),
        ReadOutcome::Filled => {}
    }
    let payload_len = u32::from_be_bytes(len_buf) as usize;
    // `payload_len` is untrusted wire input. Reject an over-cap length
    // before sizing or reading any body bytes so a buggy/hostile client
    // can't drive a huge allocation in the long-lived daemon.
    if payload_len > MAX_AGENT_MSG_LEN {
        return Err(anyhow::anyhow!(
            "agent frame payload length {payload_len} exceeds cap of {MAX_AGENT_MSG_LEN} bytes"
        ));
    }
    let mut frame = Vec::with_capacity(4 + payload_len);
    frame.extend_from_slice(&len_buf);
    frame.resize(4 + payload_len, 0);
    stream
        .read_exact(&mut frame[4..])
        .context("read agent frame payload")?;
    Ok(Some(frame))
}

enum ReadOutcome {
    Filled,
    Eof,
}

/// Like `read_exact`, but a clean EOF *before the first byte* is reported
/// as `Eof` rather than an error — that's the peer closing the socket
/// between frames, which is expected. An EOF *partway* through the buffer
/// is a truncated frame and still errors.
fn read_exact_or_eof(stream: &mut UnixStream, buf: &mut [u8]) -> Result<ReadOutcome> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(ReadOutcome::Eof);
                }
                return Err(anyhow::anyhow!(
                    "truncated agent frame: got {filled} of {} length-prefix bytes before EOF",
                    buf.len()
                ));
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context("read agent frame length prefix"),
        }
    }
    Ok(ReadOutcome::Filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::daemon::state::State;

    /// On a consent-cache miss with no graphical environment available,
    /// `decide_sign_on_miss` must fail closed (`None`) **without** enqueuing an
    /// Ask or reaching the blocking `rx.recv()`. This is the headless
    /// hang-prevention guard.
    ///
    /// The test exercises the guard rather than asserting a tautology: it
    /// passes a real empty [`State`] and checks two observable effects of the
    /// early return — (1) the returned decision is `None`, and (2) the queue is
    /// still empty afterward, proving no `submit_ask` ran. If the guard were
    /// missing, the call would push an Ask onto the queue and then park on
    /// `rx.recv()` with no sender ever replying, hanging this test forever — so
    /// a passing, non-hanging run is itself evidence the early return fired.
    #[test]
    fn consent_miss_without_gui_fails_closed() {
        let state: SharedState = Arc::new(Mutex::new(State::new()));
        let identity = PreparedIdentity {
            blob: vec![1, 2, 3],
            comment: "test key".to_owned(),
            fingerprint: "SHA256:testfingerprint".to_owned(),
            key_id: "ssh.test".to_owned(),
            reference: crate::reference::Reference {
                provider: "env".to_owned(),
                locator: "SSH_KEY".to_owned(),
            },
            reason: None,
        };
        let chain: Vec<crate::provenance::Caller> = Vec::new();

        let decision = decide_sign_on_miss(
            &state, &identity, /* anchor_pid */ 4242, /* anchor_start_time */ 1, &chain,
            /* gui_available */ false,
        );

        assert!(
            decision.is_none(),
            "headless consent miss must fail closed (None)"
        );
        assert!(
            state
                .lock()
                .expect("state mutex")
                .snapshot()
                .entries
                .is_empty(),
            "no Ask should be enqueued when failing closed without a GUI"
        );
    }

    /// An oversized length prefix must be rejected by the guard *before*
    /// `read_frame` tries to allocate or read a body that large. Writing
    /// just the 4-byte prefix is enough: without the guard, `read_frame`
    /// would size a buffer for the bogus length and then block in
    /// `read_exact` waiting for body bytes that never come.
    #[test]
    fn read_frame_rejects_oversized_length() {
        let (mut client, mut server) = UnixStream::pair().expect("create UnixStream pair");
        let oversized = (MAX_AGENT_MSG_LEN + 1) as u32;
        client
            .write_all(&oversized.to_be_bytes())
            .expect("write oversized length prefix");
        // Drop the client so any (incorrect) attempt to read a body sees EOF
        // rather than blocking forever; the guard should fire first anyway.
        drop(client);

        let result = read_frame(&mut server);
        let err = result.expect_err("expected Err for over-cap length");
        // The error must come from the size guard (which cites the cap),
        // not from an incidental truncated-body read after EOF — that
        // proves the guard fires before any body read/allocation.
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&MAX_AGENT_MSG_LEN.to_string()),
            "error should cite the cap, got: {msg}"
        );
    }

    /// A normal small frame still round-trips: the returned bytes are the
    /// full frame (length prefix included), byte-for-byte.
    #[test]
    fn read_frame_reads_small_frame() {
        let (mut client, mut server) = UnixStream::pair().expect("create UnixStream pair");
        let input = [0u8, 0, 0, 1, 11];
        client.write_all(&input).expect("write small frame");
        drop(client);

        let frame = read_frame(&mut server)
            .expect("read_frame ok")
            .expect("frame present");
        assert_eq!(frame, input);
    }
}
