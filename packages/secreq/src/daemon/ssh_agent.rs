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
//! the SSH session grants + (on a miss) interactive consent, then resolve
//! the private key through the shared encrypted secret cache, sign
//! in-process, and return only the signature. Two caches cooperate: a
//! *session grant* skips the prompt (scoped to an anchor with a TTL, one key
//! or all keys), and the *secret cache* holds the resolved key encrypted for
//! the daemon's lifetime so the provider's biometric runs at most once per
//! key — exactly like any other secret. `secreq daemon stop` resets both.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

use anyhow::{Context, Result};

use super::cache::{CacheKey, SecretCache};
use super::in_flight::InFlightMap;
use super::proto::{Ask, AskSubject, Caller, DedupeKey, SshAnchorInfo, SshAskInfo, SshSubject};
use super::ssh_proto::{self, AgentRequest};
use super::state::{SharedState, WaiterReply};
use crate::consent::{Decision, SshGrant, SshGrantScope};
use crate::manifest::Provider;
use crate::provenance::{SignAnchor, SignAnchorKind};
use crate::wraps::SshIdentity;

/// Upper bound on a single agent frame's payload length. Mirrors OpenSSH's
/// `AGENT_MAX_MSGLEN` (256 KiB) from `authfd.h`: the agent protocol never
/// carries a legitimate message this large, so a bigger length prefix is a
/// buggy/hostile client. We reject it before allocating so an untrusted
/// wire value can't drive an arbitrary allocation in the long-lived daemon.
const MAX_AGENT_MSG_LEN: usize = 256 * 1024;

/// Lifetime of an SSH sign **session grant** when the user chooses
/// "Approve 30m" / "Approve all keys 30m" (or hits Enter, the
/// approve-and-remember shortcut). An anchor (shell / IDE / git session) can
/// live for hours, so a grant is time-bounded rather than tied to the
/// anchor's lifetime alone. There is no per-identity TTL knob in
/// `wraps.json5` today, so this constant is the single source of truth — and
/// the "30m" in the button labels must track it.
const SSH_SESSION_GRANT_TTL_SECS: u64 = 1800;

/// One configured identity prepared for `REQUEST_IDENTITIES` *and* the
/// SIGN path. The public-key blob + comment answer the listing; the
/// `key_id`, `reference`, and `reason` are what the SIGN handler needs to
/// map a wire blob back to its config entry, scope the session grant, and
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
    /// through the shared encrypted cache on the first SIGN for this key.
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
        // A failed accept means the listener is closed or unrecoverably
        // broken; either way there is nothing left to serve.
        let Ok(stream) = incoming else { break };
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
    if super::peercred::peer_is_same_user(&stream) != Some(true) {
        super::log::log_at(
            "ssh-agent",
            format_args!("refused a connection from another user"),
        );
        return Ok(());
    }
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
    // The peer itself, which the chain walk deliberately starts above. It is
    // the local `ssh` client, and it is the only frame that can say whether
    // the agent is being forwarded to a remote host — see
    // `provenance::select_sign_anchor`.
    let peer = crate::provenance::describe_pid(peer_pid);
    // The peer's cwd stands in for the wrap client's self-reported `cwd`:
    // a sign request has no such field, so we read it off the connecting
    // process. Best-effort — an unreadable cwd renders as absent.
    let cwd = crate::provenance::cwd_for_pid(peer_pid).unwrap_or_default();
    let Some(anchor) = crate::provenance::select_sign_anchor(peer.as_ref(), &chain.frames) else {
        super::log::log_at(
            "ssh-agent",
            format_args!(
                "← SIGN_REQUEST for {:?} (peer pid {peer_pid}) but no anchor in caller chain; answering FAILURE",
                identity.key_id
            ),
        );
        return ssh_proto::encode_failure();
    };
    if anchor.kind == SignAnchorKind::ForwardedSsh {
        super::log::log_at(
            "ssh-agent",
            format_args!(
                "SIGN_REQUEST for {:?} arrived under agent forwarding; anchoring any grant on ssh pid {} rather than the shell",
                identity.key_id, anchor.identity.pid
            ),
        );
    }

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
    let decision = match decide_sign(state, identity, &anchor, &chain, &cwd, data) {
        Some(d) if d.approved() => d,
        Some(deny) => {
            audit_sign(identity, &chain, &cwd, deny);
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

    // 4. On a session grant, remember it scoped to the anchor with the
    //    session TTL. "Approve 30m" (and the Enter shortcut) grant this key;
    //    "Approve all keys 30m" grants every key on this anchor. Under agent
    //    forwarding that anchor is the `ssh` client, so the grant expires with
    //    the SSH session as well as with the clock.
    if let Some(scope) = grant_scope_for(decision, &identity.key_id) {
        let expires_at = now_unix_secs().saturating_add(SSH_SESSION_GRANT_TTL_SECS);
        state
            .lock()
            .expect("state mutex")
            .remember_ssh_grant(SshGrant {
                scope,
                anchor: anchor.identity,
                expires_at,
            });
    }

    // 5. Resolve the private key through the shared encrypted cache, sign, and
    //    zeroize. The first sign for a key invokes the provider (one
    //    biometric); subsequent signs ride the cache, like any other secret.
    let (cache, in_flight) = {
        let guard = state.lock().expect("state mutex");
        (guard.secret_cache_arc(), guard.in_flight_arc())
    };
    match resolve_and_sign(&cache, &in_flight, &ctx.providers, identity, data, flags) {
        Ok(sig_blob) => {
            // Audit the grant only once the sign actually succeeds — the row
            // carries the decision that authorized it (`ApproveCached` on a
            // cache hit, or whatever the user chose). The signature bytes are
            // never recorded; the row holds only the key id + fingerprint.
            audit_sign(identity, &chain, &cwd, decision);
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
    anchor: &SignAnchor,
    chain: &crate::provenance::CallerChain,
    cwd: &str,
    data: &[u8],
) -> Option<Decision> {
    // Grant check — lock held only for the lookup. A live session grant needs
    // no UI, so this path is unaffected by whether a display is available; it
    // works headless.
    {
        let mut guard = state.lock().expect("state mutex");
        if guard.has_ssh_grant(&identity.key_id, anchor.identity) {
            // The audit row for a grant hit is written at the sign outcome
            // (with `decision = ApproveCached`), alongside the approve/deny
            // rows — one audit-write site, fed the decision this returns.
            return Some(Decision::ApproveCached);
        }
    }

    // Auto-rules path — mirrors `server.rs::handle_ask`. A rule whose `wrap`
    // matches this identity's `ssh:<key_id>` fires here, so the sign is
    // auto-approved/denied without an interactive prompt. The SSH listener is
    // a separate socket from the wrap path (whose `handle_message` reloads on
    // every request), so reload hand-edits here too before evaluating. Lock is
    // held only for the reload + evaluation; we drop it before returning.
    {
        let ask = sign_ask(identity, anchor, chain, cwd, data);
        let mut guard = state.lock().expect("state mutex");
        guard.reload_rules_if_changed();
        if let Some(hit) = guard.evaluate_rules_for_ask(&ask) {
            return Some(match hit.decide {
                crate::rules::RuleDecision::Approve => Decision::ApproveAuto,
                crate::rules::RuleDecision::Deny => {
                    // Surface the auto-deny to any attached consent window,
                    // matching the wrap path's `handle_rule_hit` toast.
                    guard
                        .broadcast_auto_deny_toast(hit.rule_name.clone(), hit.deny_message.clone());
                    Decision::DenyAuto
                }
            });
        }
    }

    // Cache miss → interactive consent is required, which needs a window to
    // render. Pass the real gui-availability bool into the miss handler so it
    // can fail closed in a headless environment instead of blocking forever.
    decide_sign_on_miss(
        state,
        identity,
        anchor,
        chain,
        cwd,
        data,
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
    anchor: &SignAnchor,
    chain: &crate::provenance::CallerChain,
    cwd: &str,
    data: &[u8],
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
    // the consent UI and the audit row have the identity, the caller chain,
    // and the anchor scope to render.
    let ask = sign_ask(identity, anchor, chain, cwd, data);
    let key = ask.dedupe_key.clone();
    let (tx, rx) = mpsc::channel();
    // Keep the waiter id. The wrap path uses it to reap an ask whose client
    // vanished; this path used to throw it away, so an abandoned sign left
    // the entry in the queue forever — a card the user could not dismiss
    // except by deciding it, a parked thread, and no `abandoned` audit row.
    let waiter_id = {
        let mut guard = state.lock().expect("state mutex");
        let (_, waiter_id) = guard.submit_ask(ask, tx);
        waiter_id
    };
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
    // Also raise the always-on-top "N pending" badge — a sign request
    // can hang `git push` just as easily as a wrap, and the badge is the
    // safety net against a forgotten window. Idempotent.
    if let Err(err) = super::ensure_badge_window(state) {
        super::log::log_at(
            "ssh-agent",
            format_args!("ensure_badge_window (ssh sign) failed: {err:#}"),
        );
    }

    // Bounded, unlike the wrap path — which watches its socket for EOF and
    // reaps on hang-up. This thread is blocked on the channel, not on the
    // socket, so it cannot see the peer leave; the timeout is what stops an
    // abandoned sign from parking a thread and an undismissable card for the
    // daemon's lifetime. Generous enough that a user reading the prompt is
    // never the one who hits it: `ssh` itself gives up long before.
    match rx.recv_timeout(SIGN_DECISION_TIMEOUT) {
        Ok(WaiterReply::Decision { decision, .. }) => Some(decision),
        // A resolve error on the wrap path can't happen here (the sign ask
        // carries no secrets for the daemon to resolve — we resolve the key
        // ourselves, fresh), and a dropped sender means the daemon went down
        // under us. Neither is a decision, so both fail closed.
        Ok(WaiterReply::Err { .. }) | Err(mpsc::RecvTimeoutError::Disconnected) => None,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Withdraw exactly this waiter, which clears the card when it was
            // the last one and writes the `abandoned` audit row the wrap path
            // has always written. Fails closed: no decision, no signature.
            state
                .lock()
                .expect("state mutex")
                .withdraw_waiter(&key, waiter_id);
            super::log::log_at(
                "ssh-agent",
                format_args!(
                    "← SIGN_REQUEST for {:?} went undecided for {}s; withdrawing the ask and answering FAILURE",
                    identity.key_id,
                    SIGN_DECISION_TIMEOUT.as_secs()
                ),
            );
            None
        }
    }
}

/// How long a sign request waits for the user before it is withdrawn.
///
/// Not a policy on how fast someone must decide — `ssh` has given up well
/// before this — but a bound on how long an *abandoned* request can hold a
/// queue entry, a card and a thread.
const SIGN_DECISION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Map an approved [`Decision`] to the session-grant scope it should
/// remember, or `None` for a one-shot approval that grants nothing.
///
/// `ApproveSshSession` and the Enter-key `ApproveRemember` shortcut both
/// grant *this* key; `ApproveSshSessionAll` grants every key on the anchor.
/// `Approve` / `ApproveCached` / `ApproveAuto` (and any deny) return `None` —
/// a cached/auto/one-shot decision doesn't add a new grant.
fn grant_scope_for(decision: Decision, key_id: &str) -> Option<SshGrantScope> {
    match decision {
        Decision::ApproveSshSession | Decision::ApproveRemember => {
            Some(SshGrantScope::OneKey(key_id.to_owned()))
        }
        Decision::ApproveSshSessionAll => Some(SshGrantScope::AllKeys),
        _ => None,
    }
}

/// Build the in-process consent [`Ask`] for an SSH sign. Carries **no
/// secrets** for the daemon to resolve — the SSH path resolves (and caches)
/// the private key itself after the decision via [`resolve_and_sign`], rather
/// than handing a value back to a client. The ask exists only to drive the
/// consent prompt and coalesce repeated signs from the same anchor into one
/// queue entry.
fn sign_ask(
    identity: &PreparedIdentity,
    anchor: &SignAnchor,
    chain: &crate::provenance::CallerChain,
    cwd: &str,
    data: &[u8],
) -> Ask {
    let wrap = format!("ssh:{}", identity.key_id);
    Ask {
        command: vec![format!("ssh-sign {}", identity.key_id)],
        dedupe_key: DedupeKey {
            wrap,
            ppid: anchor.identity.pid,
            parent_start_time: anchor.identity.start_time,
            // What this ask authorizes is `data`, and `data` appears nowhere
            // else in the key. Without this, two signs for the same key from
            // the same anchor coalesce into one card and one Approve signs
            // both payloads — including one the user never saw.
            subject_digest: Some(crate::rules::sha256_hex(data)),
        },
        // The SSH-sign subject: the consent window renders the SSH variant
        // (identity + fingerprint, no secret list) because that is what this
        // ask *is*, not because a marker field is set. The variant carries no
        // secret material — only the display identity, the public-key
        // fingerprint, and the kernel-sourced chain behind the socket peer,
        // which is exactly what the scoped-agent path cannot have.
        subject: AskSubject::SshSign(SshSubject {
            cwd: cwd.to_owned(),
            // The chain and "is that all of it" travel together from the walk
            // to the prompt. Carried as one value rather than two arguments
            // because they are one fact: a suffix of an ancestry, plus the
            // only thing that distinguishes it from a whole one.
            callers_truncated: chain.truncated,
            callers: chain
                .frames
                .iter()
                .map(|c| Caller {
                    pid: c.pid,
                    name: c.name.clone(),
                    command: c.command.clone(),
                    start_time: c.start_time,
                    exe: c.exe.clone(),
                })
                .collect(),
            info: SshAskInfo {
                key_id: identity.key_id.clone(),
                fingerprint: identity.fingerprint.clone(),
                reason: identity.reason.clone(),
                // Built from the *same value* the grant keys on, not from a
                // second `select_anchor` pass over the chain. It used to be
                // re-derived, held honest by a `debug_assert` — which stopped
                // being possible the moment a forwarded anchor could be the
                // socket peer, a process the chain does not contain. One
                // value has no second answer to disagree with.
                anchor: Some(SshAnchorInfo {
                    name: anchor.name.clone(),
                    pid: anchor.identity.pid,
                    kind: anchor.kind,
                    // Only the forwarded case: a session anchor is a frame the
                    // ASKED BY tree already draws with its argv, and repeating
                    // it under the grant buttons would just be noise.
                    command: match anchor.kind {
                        SignAnchorKind::ForwardedSsh => Some(anchor.command.clone()),
                        SignAnchorKind::Session => None,
                    },
                }),
            },
        }),
    }
}

/// Resolve the identity's private-key reference through the shared encrypted
/// cache and sign `data`.
///
/// The key is cached under `CacheKey { wrap: "ssh:<key_id>", provider,
/// locator }` exactly like any other secret (encrypted at rest with a
/// per-entry key; see [`super::cache`]), so the provider — and its biometric
/// prompt — runs at most once per key per daemon lifetime instead of on
/// every sign. `secreq daemon stop` is the reset, same as for wrap secrets.
/// The returned PEM is a `Zeroizing` buffer that scrubs when this function
/// returns; only the encrypted ciphertext outlives the call.
fn resolve_and_sign(
    cache: &Arc<Mutex<SecretCache>>,
    in_flight: &Arc<InFlightMap>,
    providers: &BTreeMap<String, Provider>,
    identity: &PreparedIdentity,
    data: &[u8],
    flags: u32,
) -> Result<Vec<u8>> {
    let key = CacheKey {
        wrap: format!("ssh:{}", identity.key_id),
        provider: identity.reference.provider.clone(),
        locator: identity.reference.locator.clone(),
    };
    let pem = super::state::resolve_single_cached(
        cache,
        in_flight,
        key,
        &identity.key_id,
        identity.reason.as_deref(),
        providers,
    )
    .with_context(|| {
        format!(
            "resolving private key for ssh identity {:?}",
            identity.key_id
        )
    })?;
    crate::ssh_sign::sign(&pem, data, flags).context("signing the SSH challenge")
}

/// Write the audit row for one SSH-sign outcome.
///
/// This is the **one documented exception** to "the daemon never writes
/// audit rows" (see `CLAUDE.md`): there is no wrap client on the SSH path
/// to do it, so the daemon records the sign itself. The row carries the
/// identity key id, the public-key SHA256 fingerprint, the decision, and
/// the caller chain — and **never** the private key or the signature bytes
/// (see [`crate::audit::AuditEntry::ssh_sign`]).
///
/// An audit-write failure is non-fatal to the sign — we log it and move on,
/// mirroring the wrap client, which treats `audit::append` errors as
/// non-fatal (`commands/run.rs` ignores the `Result`). Failing a sign over an
/// audit-log write error would be a worse outcome than a missing row.
fn audit_sign(
    identity: &PreparedIdentity,
    chain: &crate::provenance::CallerChain,
    cwd: &str,
    decision: Decision,
) {
    let entry = crate::audit::AuditEntry::ssh_sign(
        &identity.key_id,
        &identity.fingerprint,
        chain,
        cwd,
        decision,
    );
    if let Err(err) = crate::audit::append(&entry) {
        super::log::log_at(
            "ssh-agent",
            format_args!(
                "failed to write audit row for ssh sign {:?}: {err:#}",
                identity.key_id
            ),
        );
    }
}

/// Current Unix time in whole seconds, for stamping `expires_at` on a
/// remembered SSH approval.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
        let chain = whole_chain(Vec::new());

        let decision = decide_sign_on_miss(
            &state,
            &identity,
            &test_anchor(4242, 1),
            &chain,
            /* cwd */ "/home/dev/repos/acme",
            /* data */ b"challenge",
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

    /// Build a `PreparedIdentity` for the given config name. Mirrors what
    /// `prepare_identities` produces: `key_id` is the config name, which
    /// `sign_ask` formats into the `ssh:<key_id>` wrap the rule matcher sees.
    fn test_identity(key_id: &str) -> PreparedIdentity {
        PreparedIdentity {
            blob: vec![1, 2, 3],
            comment: "test key".to_owned(),
            fingerprint: "SHA256:testfingerprint".to_owned(),
            key_id: key_id.to_owned(),
            reference: crate::reference::Reference {
                provider: "env".to_owned(),
                locator: "SSH_KEY".to_owned(),
            },
            reason: None,
        }
    }

    /// A session anchor for a fixture that only needs the identity half —
    /// the `(pid, start_time)` a grant keys on. Fixtures that care which
    /// frame was chosen build one through `select_sign_anchor` instead.
    fn test_anchor(pid: u32, start_time: u64) -> SignAnchor {
        SignAnchor {
            identity: crate::provenance::ProcessIdentity { pid, start_time },
            name: "zsh".to_owned(),
            command: "-zsh".to_owned(),
            kind: SignAnchorKind::Session,
        }
    }

    fn test_caller(pid: u32, name: &str, exe: Option<&str>) -> crate::provenance::Caller {
        crate::provenance::Caller {
            pid,
            name: name.to_owned(),
            command: name.to_owned(),
            exe: exe.map(std::borrow::ToOwned::to_owned),
            start_time: 1_700_000_000,
        }
    }

    /// An ancestry the walk saw all of — what these fixtures mean unless one
    /// says otherwise. The truncation half is exercised where it is decided
    /// (`provenance::walk`) and where it is read (`prompt_ui`).
    fn whole_chain(frames: Vec<crate::provenance::Caller>) -> crate::provenance::CallerChain {
        crate::provenance::CallerChain {
            frames,
            truncated: false,
        }
    }

    /// The prompt's "Approve for 30 min" buttons bind a grant to the anchor,
    /// not to the command in the header — so the ask has to say which session
    /// that is, or the user is approving something the prompt never named.
    #[test]
    fn sign_ask_names_the_session_the_grant_would_bind_to() {
        let chain = whole_chain(vec![
            test_caller(8120, "git", Some("/usr/bin/git")),
            test_caller(7926, "-zsh", Some("/bin/zsh")),
        ]);
        let anchor = crate::provenance::select_sign_anchor(None, &chain.frames).expect("anchor");
        let ask = sign_ask(
            &test_identity("github"),
            &anchor,
            &chain,
            "/home/dev/repos/acme",
            b"challenge",
        );

        let AskSubject::SshSign(ssh) = ask.subject else {
            panic!("sign_ask builds an SshSign subject");
        };
        let info = ssh.info.anchor.expect("anchor info");
        assert_eq!(info.pid, 7926, "the grant binds to the shell, not to git");
        assert_eq!(
            info.name, "-zsh",
            "the label must be the same string the ASKED BY tree renders"
        );
    }

    /// The named session must be the one the grant actually keys on. A label
    /// naming a different frame than `dedupe_key.ppid` would be a prompt that
    /// tells the truth about nothing.
    #[test]
    fn the_named_session_is_the_one_the_grant_keys_on() {
        // The attacker sits under the shell and calls itself `zsh`; the
        // anchor must resolve past it, and the label must follow.
        let chain = whole_chain(vec![
            test_caller(8120, "git", Some("/usr/bin/git")),
            test_caller(8000, "zsh", Some("/tmp/.hidden/payload")),
            test_caller(7926, "-zsh", Some("/bin/zsh")),
        ]);
        let anchor = crate::provenance::select_sign_anchor(None, &chain.frames).expect("anchor");
        let ask = sign_ask(
            &test_identity("github"),
            &anchor,
            &chain,
            "/home/dev/repos/acme",
            b"challenge",
        );

        let AskSubject::SshSign(ssh) = &ask.subject else {
            panic!("sign_ask builds an SshSign subject");
        };
        let info = ssh.info.anchor.as_ref().expect("anchor info");
        assert_eq!(info.pid, 7926);
        assert_eq!(
            info.pid, ask.dedupe_key.ppid,
            "the session the prompt names must be the session the grant keys on"
        );
    }

    /// Under agent forwarding the prompt has to name the `ssh` client, not
    /// the shell — and it has to carry that client's argv, because the caller
    /// chain starts *above* the socket peer and the tree therefore cannot
    /// draw the frame the grant is about.
    #[test]
    fn a_forwarded_sign_names_the_ssh_client_and_not_the_shell() {
        let mut ssh = test_caller(9200, "ssh", Some("/usr/bin/ssh"));
        ssh.command = "ssh -A build-box".to_owned();
        let peer = crate::provenance::PeerProcess {
            forwards_agent: crate::provenance::requests_agent_forwarding(&ssh.command),
            caller: ssh,
        };
        let chain = whole_chain(vec![test_caller(7926, "-zsh", Some("/bin/zsh"))]);
        let anchor =
            crate::provenance::select_sign_anchor(Some(&peer), &chain.frames).expect("anchor");
        let ask = sign_ask(
            &test_identity("github"),
            &anchor,
            &chain,
            "/home/dev/repos/acme",
            b"challenge",
        );

        let AskSubject::SshSign(ssh_subject) = &ask.subject else {
            panic!("sign_ask builds an SshSign subject");
        };
        let info = ssh_subject.info.anchor.as_ref().expect("anchor info");
        assert_eq!(info.kind, SignAnchorKind::ForwardedSsh);
        assert_eq!(
            info.pid, 9200,
            "the grant must bind to the ssh session, not to the terminal it was launched from"
        );
        assert_eq!(
            info.command.as_deref(),
            Some("ssh -A build-box"),
            "the prompt has to show a frame the caller tree cannot"
        );
        assert_eq!(
            info.pid, ask.dedupe_key.ppid,
            "the session the prompt names must be the session the grant keys on"
        );
    }

    /// The grant the forwarded anchor produces must not match a later sign
    /// from the shell. This is the property the finding is about: 30 minutes
    /// granted during an `ssh -A` push used to authorize everything under
    /// that terminal, including the remote host's own requests.
    #[test]
    fn a_forwarded_grant_does_not_cover_the_whole_terminal() {
        let mut ssh = test_caller(9200, "ssh", Some("/usr/bin/ssh"));
        ssh.command = "ssh -A build-box".to_owned();
        let shell = test_caller(7926, "-zsh", Some("/bin/zsh"));
        let peer = crate::provenance::PeerProcess {
            forwards_agent: crate::provenance::requests_agent_forwarding(&ssh.command),
            caller: ssh,
        };
        let chain = whole_chain(vec![shell.clone()]);
        let forwarded =
            crate::provenance::select_sign_anchor(Some(&peer), &chain.frames).expect("anchor");

        let state: SharedState = Arc::new(Mutex::new(State::new()));
        state
            .lock()
            .expect("state mutex")
            .remember_ssh_grant(SshGrant {
                scope: SshGrantScope::AllKeys,
                anchor: forwarded.identity,
                expires_at: u64::MAX,
            });

        let mut guard = state.lock().expect("state mutex");
        assert!(
            guard.has_ssh_grant("github", forwarded.identity),
            "the forwarded session keeps its own grant"
        );
        assert!(
            !guard.has_ssh_grant("github", shell.identity()),
            "a grant given for a forwarded session must not cover the shell"
        );
    }

    /// Build an `ssh:<wrap_key>` rule with the given decision. `trained_secrets`
    /// is empty (the guard is irrelevant for SSH — sign asks carry no secrets).
    fn ssh_rule(
        id: &str,
        wrap_key: &str,
        decide: crate::rules::RuleDecision,
    ) -> crate::rules::Rule {
        crate::rules::Rule {
            id: id.to_owned(),
            name: id.to_owned(),
            enabled: true,
            trained_secrets: Default::default(),
            created_at_unix: 0,
            body: crate::rules::RuleBody::Declarative {
                r#match: crate::rules::RuleMatch {
                    wrap: format!("ssh:{wrap_key}"),
                    argv: None,
                    ancestor: None,
                    cwd: None,
                },
                decide: decide.into(),
            },
        }
    }

    /// An auto-approve rule whose `wrap` matches the SSH identity
    /// (`ssh:<key_id>`) must fire on the sign path exactly as it does on the
    /// wrap path: `decide_sign` returns `ApproveAuto` **without** enqueuing an
    /// Ask or blocking on consent. Regression guard for the bug where the SSH
    /// sign path skipped rule evaluation entirely and always prompted, even
    /// with a matching rule saved from the suggested `ssh:<name>` template.
    #[test]
    fn auto_approve_rule_fires_for_ssh_sign() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        crate::rules::save_rules(
            &path,
            &[ssh_rule(
                "01",
                "github",
                crate::rules::RuleDecision::Approve,
            )],
        )
        .expect("save rules");
        let state: SharedState = Arc::new(Mutex::new(State::with_rules_path(path)));
        let identity = test_identity("github");
        let chain = whole_chain(Vec::new());

        let decision = decide_sign(
            &state,
            &identity,
            &test_anchor(4242, 1),
            &chain,
            /* cwd */ "/home/dev/repos/acme",
            /* data */ b"challenge",
        );

        assert_eq!(
            decision,
            Some(Decision::ApproveAuto),
            "a matching ssh:<key_id> approve rule must auto-approve the sign"
        );
        assert!(
            state
                .lock()
                .expect("state mutex")
                .snapshot()
                .entries
                .is_empty(),
            "auto-approved sign must not enqueue an Ask for interactive consent"
        );
    }

    /// A matching auto-deny rule must short-circuit to `DenyAuto` on the sign
    /// path without prompting — the mirror of the approve case.
    #[test]
    fn auto_deny_rule_fires_for_ssh_sign() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        crate::rules::save_rules(
            &path,
            &[ssh_rule("01", "github", crate::rules::RuleDecision::Deny)],
        )
        .expect("save rules");
        let state: SharedState = Arc::new(Mutex::new(State::with_rules_path(path)));
        let identity = test_identity("github");
        let chain = whole_chain(Vec::new());

        let decision = decide_sign(
            &state,
            &identity,
            &test_anchor(4242, 1),
            &chain,
            "/home/dev/repos/acme",
            b"challenge",
        );

        assert_eq!(decision, Some(Decision::DenyAuto));
        assert!(
            state
                .lock()
                .expect("state mutex")
                .snapshot()
                .entries
                .is_empty(),
            "auto-denied sign must not enqueue an Ask"
        );
    }

    /// `grant_scope_for` maps each approved decision to the grant it should
    /// remember: session→this key, session-all→all keys, Enter-key
    /// remember→this key, and one-shot/cached/auto/deny→no grant.
    #[test]
    fn grant_scope_for_maps_decisions() {
        assert_eq!(
            grant_scope_for(Decision::ApproveSshSession, "github"),
            Some(SshGrantScope::OneKey("github".to_owned()))
        );
        assert_eq!(
            grant_scope_for(Decision::ApproveRemember, "github"),
            Some(SshGrantScope::OneKey("github".to_owned()))
        );
        assert_eq!(
            grant_scope_for(Decision::ApproveSshSessionAll, "github"),
            Some(SshGrantScope::AllKeys)
        );
        // One-shot / cached / auto / deny add no grant.
        assert_eq!(grant_scope_for(Decision::Approve, "github"), None);
        assert_eq!(grant_scope_for(Decision::ApproveCached, "github"), None);
        assert_eq!(grant_scope_for(Decision::ApproveAuto, "github"), None);
        assert_eq!(grant_scope_for(Decision::Deny, "github"), None);
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

    /// The SIGN path reuses the wrap queue's coalescing, which folds asks
    /// with an equal dedupe key into one entry answered by one decision.
    /// That is sound when the key determines what is being authorized. For a
    /// sign it does not: the subject is the challenge blob, which is not in
    /// the key, not on the card, and nowhere the user can see. Two signs for
    /// the same key from the same anchor were one request as far as the
    /// queue and the UI were concerned, so one Approve signed both — one of
    /// them a payload the user never saw.
    #[test]
    fn two_signs_over_different_payloads_do_not_share_a_dedupe_key() {
        let identity = test_identity("github");
        let chain = whole_chain(Vec::new());

        let a = sign_ask(
            &identity,
            &test_anchor(4242, 1),
            &chain,
            "/repo",
            b"challenge-one",
        );
        let b = sign_ask(
            &identity,
            &test_anchor(4242, 1),
            &chain,
            "/repo",
            b"challenge-two",
        );

        assert_ne!(
            a.dedupe_key, b.dedupe_key,
            "distinct payloads must not coalesce onto one decision"
        );
        // Everything else still agrees — it is only the subject that differs.
        assert_eq!(a.dedupe_key.wrap, b.dedupe_key.wrap);
        assert_eq!(a.dedupe_key.ppid, b.dedupe_key.ppid);
    }

    /// A genuine retry of the same challenge should still coalesce, which is
    /// what coalescing is for.
    #[test]
    fn two_signs_over_the_same_payload_still_coalesce() {
        let identity = test_identity("github");
        let chain = whole_chain(Vec::new());

        let a = sign_ask(
            &identity,
            &test_anchor(4242, 1),
            &chain,
            "/repo",
            b"same-challenge",
        );
        let b = sign_ask(
            &identity,
            &test_anchor(4242, 1),
            &chain,
            "/repo",
            b"same-challenge",
        );

        assert_eq!(a.dedupe_key, b.dedupe_key);
    }

    /// Rules match on `wrap`, documented as `ssh:<key_id>`, so the
    /// discriminator must not live there.
    #[test]
    fn the_payload_digest_stays_out_of_the_rule_facing_wrap() {
        let identity = test_identity("github");
        let chain = whole_chain(Vec::new());
        let ask = sign_ask(
            &identity,
            &test_anchor(4242, 1),
            &chain,
            "/repo",
            b"challenge",
        );
        assert_eq!(ask.dedupe_key.wrap, format!("ssh:{}", identity.key_id));
    }
}
