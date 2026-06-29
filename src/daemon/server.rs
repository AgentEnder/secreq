//! Daemon socket server: bind, accept, handle one client per thread.
//!
//! Each connection is a single request/response over JSON lines. Long
//! requests (asks waiting on the user) park on a `mpsc::Receiver` until
//! the UI thread answers. The connection thread isn't a problem to keep
//! around — it's blocked on a channel, not on CPU.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use anyhow::{Context, Result};

use super::proto::{Ask, ClientMsg, DaemonMsg};
use super::state::{SharedState, WaiterReply};

/// Bind the daemon socket and start accepting connections.
///
/// Returns the bound listener so the caller can keep it alive. The accept
/// loop runs on a background thread that exits when the listener is
/// dropped (the OS errors the accept).
pub fn start(socket_path: PathBuf, state: SharedState) -> Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    // Clear a stale socket from a previous crashed daemon. We've already
    // taken the pidfile lock by the time we get here, so this can't race
    // with a live daemon.
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind daemon socket {}", socket_path.display()))?;
    let mut perms = std::fs::metadata(&socket_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&socket_path, perms)?;
    super::log::log_at(
        "server",
        format_args!("listener bound at {}", socket_path.display()),
    );

    let listener_clone = listener.try_clone()?;
    thread::Builder::new()
        .name("secreqd-accept".to_owned())
        .spawn(move || accept_loop(listener_clone, state))
        .context("spawn daemon accept thread")?;

    Ok(listener)
}

/// Bind and start the SSH agent listener when the loaded config declares
/// any `ssh` identities. Mirrors [`start`] (its own thread, returns the
/// bound listener for the caller to keep alive) but speaks the SSH agent
/// protocol on `agent.sock` rather than the JSON control protocol. Returns
/// `Ok(None)` when no identities are configured — no agent socket exists
/// in that case.
///
/// `providers` and `state` are threaded through to the SIGN handler: the
/// providers resolve the private key fresh at sign time; the shared state
/// drives the consent prompt + SSH approval cache.
pub fn start_ssh_agent(
    socket_path: PathBuf,
    ssh: &std::collections::BTreeMap<String, crate::wraps::SshIdentity>,
    providers: std::collections::BTreeMap<String, crate::manifest::Provider>,
    state: SharedState,
) -> Result<Option<UnixListener>> {
    super::ssh_agent::start(socket_path, ssh, providers, state)
}

fn accept_loop(listener: UnixListener, state: SharedState) {
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(_) => break, // Listener closed or unrecoverable accept error.
        };
        let state = state.clone();
        thread::Builder::new()
            .name("secreqd-conn".to_owned())
            .spawn(move || {
                if let Err(err) = handle_connection(stream, state) {
                    eprintln!("secreqd: connection error: {err:#}");
                }
            })
            .ok();
    }
}

fn handle_connection(stream: UnixStream, state: SharedState) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone().context("clone socket")?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        super::log::log_at("server", format_args!("client connected, sent nothing"));
        return Ok(());
    }
    let msg: ClientMsg = serde_json::from_str(line.trim()).context("malformed client message")?;

    // Branch: streaming consent-window attach vs one-shot request.
    if let ClientMsg::ConsentWindowAttach { pid } = msg {
        super::log::log_at(
            "server",
            format_args!("← ClientMsg::ConsentWindowAttach (pid={pid})"),
        );
        handle_consent_window_connection(reader, stream, state, pid)?;
        return Ok(());
    }

    // Branch: streaming pending-badge attach. Same push-stream shape as
    // the consent window but a leaner read loop (no decisions / rules —
    // only a click-to-raise nudge and detach).
    if let ClientMsg::BadgeWindowAttach { pid } = msg {
        super::log::log_at(
            "server",
            format_args!("← ClientMsg::BadgeWindowAttach (pid={pid})"),
        );
        handle_badge_window_connection(reader, stream, state)?;
        return Ok(());
    }

    // `Ask` blocks `handle_message` until the user decides, so the
    // spawn-the-consent-window step is done *inside* `handle_ask`
    // before it parks on the reply channel — see the comment there.
    // For the non-blocking show-the-window verbs, spawn after we've
    // replied so the client doesn't wait on `Command::spawn`.
    let needs_spawn = matches!(&msg, ClientMsg::ShowWindow | ClientMsg::ShowViewer);
    let reply = handle_message(msg, state.clone());
    let mut writer = stream;
    write_reply(&mut writer, &reply)?;
    if needs_spawn {
        if let Err(err) = super::ensure_consent_window(&state) {
            super::log::log_at(
                "server",
                format_args!("ensure_consent_window failed: {err:#}"),
            );
        }
    }
    Ok(())
}

/// Streaming connection. The child has just sent `ConsentWindowAttach`;
/// we register a writer thread that drains `DaemonMsg`s onto the socket
/// from an `mpsc::Receiver`, then loop reading further `ClientMsg`s
/// (decisions, detach) from the child. Connection drop or
/// `ConsentWindowDetach` both clean up the subscriber.
/// True for the I/O errors that mean "the peer hung up" rather than a
/// genuine daemon-side failure. A wrap process killed while its ask is
/// parked closes its socket; the eventual reply write then hits one of
/// these — expected, not an error to shout about.
fn is_client_disconnect(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}

/// Serialize `reply` and write it back over the one-shot connection.
///
/// A client that disappeared before we replied (its ask was killed while
/// parked) is the normal shutdown of a one-shot exchange, not a fault —
/// we swallow the broken-pipe quietly so it doesn't read as a daemon
/// error on stderr. Any other write failure still propagates.
fn write_reply(writer: &mut impl Write, reply: &DaemonMsg) -> Result<()> {
    let json = serde_json::to_string(reply).context("serialize reply")?;
    match writeln!(writer, "{json}") {
        Ok(()) => Ok(()),
        Err(err) if is_client_disconnect(&err) => {
            super::log::log_at(
                "server",
                format_args!("client gone before reply (killed while parked); dropping reply"),
            );
            Ok(())
        }
        Err(err) => Err(err).context("write reply"),
    }
}

fn handle_consent_window_connection(
    reader: BufReader<UnixStream>,
    socket: UnixStream,
    state: SharedState,
    pid: u32,
) -> Result<()> {
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel::<super::proto::DaemonMsg>();

    // Register subscriber + grab initial snapshot.
    let (subscriber_id, initial_snapshot) = state
        .lock()
        .expect("state mutex")
        .attach_consent_window(pid, tx.clone());

    // Send initial ConsentUpdate eagerly so the child can paint
    // before any state mutation arrives.
    let writer_socket = socket.try_clone().context("clone socket for writer")?;
    let writer_handle = thread::Builder::new()
        .name("consent-window-writer".to_owned())
        .spawn(move || {
            let mut writer = writer_socket;
            while let Ok(msg) = rx.recv() {
                let json = match serde_json::to_string(&msg) {
                    Ok(j) => j,
                    Err(err) => {
                        eprintln!("secreqd: serialize ConsentUpdate: {err}");
                        return;
                    }
                };
                if writeln!(writer, "{json}").is_err() {
                    return; // Socket closed.
                }
            }
        })
        .context("spawn consent-window writer thread")?;

    // Eager initial push (no state change yet, but the child needs a
    // snapshot to render its first frame).
    let _ = tx.send(super::proto::DaemonMsg::ConsentUpdate {
        snapshot: initial_snapshot,
    });

    // Read loop: handle decisions and detach.
    let mut reader = reader;
    let mut line = String::new();
    loop {
        line.clear();
        let n = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            super::log::log_at(
                "server",
                format_args!("consent-window socket closed by child"),
            );
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let msg: ClientMsg = match serde_json::from_str(trimmed) {
            Ok(m) => m,
            Err(err) => {
                super::log::log_at(
                    "server",
                    format_args!("consent-window: malformed msg: {err}; line=[{trimmed}]"),
                );
                continue;
            }
        };
        match msg {
            ClientMsg::ConsentDecision {
                key,
                decision,
                scope_pid,
                scope_start_time,
            } => {
                super::log::log_at(
                    "server",
                    format_args!(
                        "← ConsentDecision wrap={} decision={:?} scope=({scope_pid},{scope_start_time})",
                        key.wrap, decision
                    ),
                );
                let scope = super::state::ApprovalScope {
                    pid: scope_pid,
                    start_time: scope_start_time,
                };
                // `resolve` hands a clone of `state` to its off-thread
                // resolver so it can clear the "Resolving…" card when
                // the value lands; lock a separate handle to call it.
                let handle = state.clone();
                handle
                    .lock()
                    .expect("state mutex")
                    .resolve(&key, decision, scope, &state);
            }
            ClientMsg::ConsentWindowDetach => {
                super::log::log_at("server", format_args!("← ConsentWindowDetach"));
                break;
            }
            ClientMsg::ConsentWindowFocus { focused } => {
                super::log::log_at(
                    "server",
                    format_args!("← ConsentWindowFocus focused={focused}"),
                );
                state
                    .lock()
                    .expect("state mutex")
                    .set_consent_focused(subscriber_id, focused);
            }
            ClientMsg::ConsentWindowInteractive { interacting } => {
                super::log::log_at(
                    "server",
                    format_args!("← ConsentWindowInteractive interacting={interacting}"),
                );
                state
                    .lock()
                    .expect("state mutex")
                    .set_consent_interacting(subscriber_id, interacting);
            }
            // Rule mutations from the Rules tab. They arrive over the
            // streaming socket because that's the connection the
            // consent-window child already has open. Routed through
            // the same `State` mutators as the one-shot CLI path; the
            // UI doesn't wait for an ack — success shows up in the
            // next `ConsentUpdate` broadcast.
            ClientMsg::AddRule { .. }
            | ClientMsg::UpdateRule { .. }
            | ClientMsg::DeleteRule { .. }
            | ClientMsg::SetRuleEnabled { .. } => {
                apply_streaming_rule_msg(&state, msg);
            }
            other => {
                super::log::log_at(
                    "server",
                    format_args!(
                        "consent-window sent non-streaming message after attach: {other:?}"
                    ),
                );
            }
        }
    }

    // **Detach order matters.** We must remove the subscriber from
    // `state.consent_subscribers` BEFORE dropping our local tx — the
    // subscriber list holds a clone of the sender, and as long as it
    // sits there the writer thread's `Receiver::recv()` keeps
    // returning `Ok(...)`. Then we drop our tx, and only then is
    // there zero senders remaining, so `rx.recv()` returns `Err` and
    // the writer thread exits, which lets us `join` without
    // deadlocking. Without this exact ordering the streaming
    // connection thread hangs and the daemon thinks a stale
    // subscriber is still alive (the "every other view works" bug).
    state
        .lock()
        .expect("state mutex")
        .detach_consent_window(subscriber_id);
    drop(tx);
    let _ = writer_handle.join();

    // Two reasons a detach can happen:
    //
    //   1. **User-initiated**: clicked the close button, killed the
    //      process, etc. → run `hide_window()` to clear `viewer_mode`
    //      and `window_visible`. This is the existing behaviour.
    //   2. **Daemon-initiated restart**: we dropped the subscriber via
    //      `initiate_consent_restart()` so the next message that
    //      needs the UI spawns a fresh foreground process. Don't run
    //      `hide_window` — that would reset `viewer_mode` and the
    //      respawned child wouldn't enter viewer mode. Instead call
    //      `ensure_consent_window` to fire the spawn now.
    let restart_pending = state
        .lock()
        .expect("state mutex")
        .take_consent_restart_pending();
    if restart_pending {
        super::log::log_at(
            "server",
            format_args!("detach due to restart; ensuring fresh consent window"),
        );
        if let Err(err) = super::ensure_consent_window(&state) {
            super::log::log_at(
                "server",
                format_args!("restart-respawn ensure_consent_window failed: {err:#}"),
            );
        }
    } else {
        state.lock().expect("state mutex").hide_window();
    }
    Ok(())
}

/// Streaming connection for a pending-badge child. Mirrors
/// [`handle_consent_window_connection`]'s writer-thread + read-loop
/// shape (and its exact detach-ordering contract), but the badge's read
/// loop only handles two messages: `RaiseConsentRequested` (the user
/// clicked the pill → bring the consent window forward) and
/// `BadgeWindowDetach`. The badge gets the same `ConsentUpdate` stream
/// as the consent window — it just renders the `Awaiting` count.
fn handle_badge_window_connection(
    reader: BufReader<UnixStream>,
    socket: UnixStream,
    state: SharedState,
) -> Result<()> {
    let (tx, rx) = mpsc::channel::<DaemonMsg>();

    let (subscriber_id, initial_snapshot) = state
        .lock()
        .expect("state mutex")
        .attach_badge_window(tx.clone());

    let writer_socket = socket
        .try_clone()
        .context("clone socket for badge writer")?;
    let writer_handle = thread::Builder::new()
        .name("pending-badge-writer".to_owned())
        .spawn(move || {
            let mut writer = writer_socket;
            while let Ok(msg) = rx.recv() {
                let json = match serde_json::to_string(&msg) {
                    Ok(j) => j,
                    Err(err) => {
                        eprintln!("secreqd: serialize badge update: {err}");
                        return;
                    }
                };
                if writeln!(writer, "{json}").is_err() {
                    return; // Socket closed.
                }
            }
        })
        .context("spawn pending-badge writer thread")?;

    // Eager initial push so the badge can paint its first frame.
    let _ = tx.send(DaemonMsg::ConsentUpdate {
        snapshot: initial_snapshot,
    });

    let mut reader = reader;
    let mut line = String::new();
    loop {
        line.clear();
        let n = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            super::log::log_at(
                "server",
                format_args!("pending-badge socket closed by child"),
            );
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let msg: ClientMsg = match serde_json::from_str(trimmed) {
            Ok(m) => m,
            Err(err) => {
                super::log::log_at(
                    "server",
                    format_args!("pending-badge: malformed msg: {err}; line=[{trimmed}]"),
                );
                continue;
            }
        };
        match msg {
            ClientMsg::RaiseConsentRequested => {
                super::log::log_at(
                    "server",
                    format_args!("← RaiseConsentRequested (badge click)"),
                );
                // Same raise path as `ShowWindow`: show the window and,
                // unless a live consent child is already in front, kill
                // and respawn it so the fresh process gets foreground
                // intent (the macOS App-Nap workaround). Then ensure a
                // child exists at all.
                {
                    let mut guard = state.lock().expect("state mutex");
                    guard.show_window();
                    if !guard.any_consent_focused() {
                        guard.initiate_consent_restart();
                    }
                    guard.touch();
                }
                if let Err(err) = super::ensure_consent_window(&state) {
                    super::log::log_at(
                        "server",
                        format_args!("badge-raise ensure_consent_window failed: {err:#}"),
                    );
                }
            }
            ClientMsg::BadgeWindowDetach => {
                super::log::log_at("server", format_args!("← BadgeWindowDetach"));
                break;
            }
            other => {
                super::log::log_at(
                    "server",
                    format_args!("pending-badge sent unexpected message: {other:?}"),
                );
            }
        }
    }

    // Same detach-order contract as the consent window: remove the
    // subscriber before dropping our local tx so the writer thread's
    // `rx.recv()` returns `Err` and we can join without deadlocking.
    state
        .lock()
        .expect("state mutex")
        .detach_badge_window(subscriber_id);
    drop(tx);
    let _ = writer_handle.join();
    Ok(())
}

fn handle_message(msg: ClientMsg, state: SharedState) -> DaemonMsg {
    let tag = match &msg {
        ClientMsg::Ping => "Ping",
        ClientMsg::Hello { .. } => "Hello",
        ClientMsg::ShowWindow => "ShowWindow",
        ClientMsg::ShowViewer => "ShowViewer",
        ClientMsg::Ask(_) => "Ask",
        ClientMsg::Shutdown => "Shutdown",
        ClientMsg::ConsentWindowAttach { .. } => "ConsentWindowAttach",
        ClientMsg::ConsentDecision { .. } => "ConsentDecision",
        ClientMsg::ConsentWindowDetach => "ConsentWindowDetach",
        ClientMsg::ConsentWindowFocus { .. } => "ConsentWindowFocus",
        ClientMsg::ConsentWindowInteractive { .. } => "ConsentWindowInteractive",
        ClientMsg::BadgeWindowAttach { .. } => "BadgeWindowAttach",
        ClientMsg::BadgeWindowDetach => "BadgeWindowDetach",
        ClientMsg::RaiseConsentRequested => "RaiseConsentRequested",
        ClientMsg::ListRules => "ListRules",
        ClientMsg::AddRule { .. } => "AddRule",
        ClientMsg::UpdateRule { .. } => "UpdateRule",
        ClientMsg::DeleteRule { .. } => "DeleteRule",
        ClientMsg::SetRuleEnabled { .. } => "SetRuleEnabled",
    };
    super::log::log_at("server", format_args!("← ClientMsg::{tag}"));
    // Pick up any external hand-edits to the auto-rules file before
    // processing this request. Cheap mtime check; reloads in place
    // (no daemon restart, no in-flight error). See
    // `State::reload_rules_if_changed`.
    state.lock().expect("state mutex").reload_rules_if_changed();
    let reply = match msg {
        ClientMsg::Ping => {
            state.lock().expect("state mutex").touch();
            DaemonMsg::Ok
        }
        ClientMsg::Hello { build_id } => {
            // Version handshake. If the CLI is a different build than us,
            // log it (the CLI drives the actual restart) and don't touch
            // the idle clock — a stale daemon being probed for replacement
            // shouldn't extend its own life.
            if build_id != crate::BUILD_ID {
                super::log::log_at(
                    "server",
                    format_args!(
                        "Hello from CLI build {build_id}; daemon is {} — CLI will restart us",
                        crate::BUILD_ID
                    ),
                );
            }
            DaemonMsg::Hello {
                build_id: crate::BUILD_ID.to_owned(),
            }
        }
        ClientMsg::ShowWindow => {
            let mut guard = state.lock().expect("state mutex");
            guard.show_window();
            // Kill any existing child so the post-detach spawn yields
            // a fresh, foreground-focused process. macOS suspends
            // backgrounded-occluded apps' run loops; the only reliable
            // way to "raise" the consent UI is to launch a new
            // process that gets foreground intent at launch.
            //
            // Skip the restart if a live child reports itself focused —
            // it's already in front, so all we'd accomplish is closing
            // and re-opening it for no reason. The streaming snapshot
            // pushed by `show_window()` updates whatever state the
            // existing window needs to display.
            if !guard.any_consent_focused() {
                guard.initiate_consent_restart();
            }
            guard.touch();
            DaemonMsg::WindowOpened {
                child_pid: guard.consent_child_pid(),
            }
        }
        ClientMsg::ShowViewer => {
            let mut guard = state.lock().expect("state mutex");
            guard.enter_viewer_mode();
            if !guard.any_consent_focused() {
                guard.initiate_consent_restart();
            }
            guard.touch();
            DaemonMsg::WindowOpened {
                child_pid: guard.consent_child_pid(),
            }
        }
        ClientMsg::Ask(ask) => handle_ask(ask, state),
        ClientMsg::Shutdown => {
            state.lock().expect("state mutex").request_shutdown();
            DaemonMsg::Ok
        }
        // The streaming consent-window messages must arrive on the
        // streaming connection path (`handle_consent_window_connection`,
        // added below). Seeing them on the one-shot path means the
        // child connected without `ConsentWindowAttach` first; reply
        // with an error so the child doesn't deadlock.
        ClientMsg::ConsentWindowAttach { .. }
        | ClientMsg::ConsentDecision { .. }
        | ClientMsg::ConsentWindowDetach
        | ClientMsg::ConsentWindowFocus { .. }
        | ClientMsg::ConsentWindowInteractive { .. }
        | ClientMsg::BadgeWindowAttach { .. }
        | ClientMsg::BadgeWindowDetach
        | ClientMsg::RaiseConsentRequested => DaemonMsg::Err {
            message: "streaming consent/badge message arrived on one-shot path; \
                      child must send its Attach message first"
                .to_owned(),
        },
        ClientMsg::ListRules => {
            let guard = state.lock().expect("state mutex");
            DaemonMsg::RulesList {
                rules: guard.rules_snapshot(),
            }
        }
        ClientMsg::AddRule { rule } => {
            let mut guard = state.lock().expect("state mutex");
            match guard.add_rule(rule) {
                Ok(()) => DaemonMsg::Ok,
                Err(err) => DaemonMsg::Err {
                    message: format!("{err:#}"),
                },
            }
        }
        ClientMsg::UpdateRule { rule } => {
            let mut guard = state.lock().expect("state mutex");
            match guard.update_rule(rule) {
                Ok(()) => DaemonMsg::Ok,
                Err(err) => DaemonMsg::Err {
                    message: format!("{err:#}"),
                },
            }
        }
        ClientMsg::DeleteRule { id } => {
            let mut guard = state.lock().expect("state mutex");
            match guard.delete_rule(&id) {
                Ok(()) => DaemonMsg::Ok,
                Err(err) => DaemonMsg::Err {
                    message: format!("{err:#}"),
                },
            }
        }
        ClientMsg::SetRuleEnabled { id, enabled } => {
            let mut guard = state.lock().expect("state mutex");
            match guard.set_rule_enabled(&id, enabled) {
                Ok(()) => DaemonMsg::Ok,
                Err(err) => DaemonMsg::Err {
                    message: format!("{err:#}"),
                },
            }
        }
    };
    let reply_tag = match &reply {
        DaemonMsg::Ok => "Ok",
        DaemonMsg::Hello { .. } => "Hello",
        DaemonMsg::WindowOpened { child_pid } => match child_pid {
            Some(_) => "WindowOpened(existing)",
            None => "WindowOpened(spawning)",
        },
        DaemonMsg::Decision { decision, .. } => match decision {
            crate::consent::Decision::Approve => "Decision::Approve",
            crate::consent::Decision::ApproveRemember => "Decision::ApproveRemember",
            crate::consent::Decision::ApproveCached => "Decision::ApproveCached",
            crate::consent::Decision::ApproveAuto => "Decision::ApproveAuto",
            // SSH-only decisions; they ride the in-process sign waiter, not
            // this wrap socket reply, but Decision is shared so list them.
            crate::consent::Decision::ApproveSshSession => "Decision::ApproveSshSession",
            crate::consent::Decision::ApproveSshSessionAll => "Decision::ApproveSshSessionAll",
            crate::consent::Decision::Deny => "Decision::Deny",
            crate::consent::Decision::DenyAuto => "Decision::DenyAuto",
        },
        DaemonMsg::Err { .. } => "Err",
        DaemonMsg::ConsentUpdate { .. } => "ConsentUpdate",
        DaemonMsg::ConsentExitPlease => "ConsentExitPlease",
        DaemonMsg::RulesList { .. } => "RulesList",
        DaemonMsg::AutoDenyToast { .. } => "AutoDenyToast",
    };
    super::log::log_at("server", format_args!("→ DaemonMsg::{reply_tag}"));
    reply
}

fn handle_ask(ask: Ask, state: SharedState) -> DaemonMsg {
    // Fast-path: parent-keyed approval cache hit. Take the lock briefly
    // to check authorization, then *release it* before resolving — the
    // provider call (and any biometric prompt) must not hold the state
    // mutex, or the consent-window child couldn't attach to show the
    // "Resolving…" card. We don't enqueue: there's no decision to make.
    {
        let guard = state.lock().expect("state mutex");
        if guard.has_cached_approval(&ask) {
            let cache = guard.secret_cache_arc();
            let in_flight = guard.in_flight_arc();
            drop(guard);
            let reply = resolve_approved_with_pending(
                &ask,
                crate::consent::Decision::ApproveCached,
                cache,
                in_flight,
                &state,
            );
            return waiter_reply_to_daemon_msg(reply);
        }
    }
    // Auto-rules path. The mtime-based reload already ran in
    // `handle_message`, so `state.rules` reflects any hand-edits made
    // since the daemon started. If a rule fires, the ask never enters
    // the queue. ApproveAuto resolves synchronously on this thread
    // (we'd otherwise be blocking on the user's click anyway, so
    // blocking on a provider invocation is equivalent from the
    // socket's POV). DenyAuto replies immediately.
    {
        let guard = state.lock().expect("state mutex");
        if let Some(hit) = guard.evaluate_rules_for_ask(&ask) {
            let cache = guard.secret_cache_arc();
            let in_flight = guard.in_flight_arc();
            drop(guard);
            return handle_rule_hit(ask, hit, cache, in_flight, state);
        }
    }
    // Slow path: enqueue and park on the reply channel.
    let (tx, rx) = mpsc::channel();
    let is_new = {
        let mut guard = state.lock().expect("state mutex");
        let result = guard.submit_ask(ask, tx);
        // Restart only on genuinely new entries. A coalesced ask is
        // joining an existing queue row that the current UI is already
        // displaying; killing the window mid-decision to "re-show"
        // the same card would be worse UX (and would drop the user's
        // in-progress choice). Only the first fresh entry per dedupe
        // key warrants a foreground raise.
        matches!(result, super::state::SubmitResult::NewEntry)
    };
    if is_new {
        let mut guard = state.lock().expect("state mutex");
        // Restart-to-raise was added to drag a backgrounded consent
        // window forward on macOS — newly-spawned processes get
        // foreground intent at launch, which is the only way around
        // suspended run loops on occluded apps. But when the window
        // is already on screen AND focused, the restart is purely
        // disruptive: it kills the user's current tab/scroll state
        // and replays a fresh window over the top. Skip it then —
        // `submit_ask` has already broadcast the snapshot, and the
        // existing focused window will paint the new ask in place.
        if !guard.any_consent_focused() {
            guard.initiate_consent_restart();
        }
    }
    // Spawn the consent-window child **before** blocking on the
    // reply channel. Without this, the daemon enqueues the ask,
    // parks here, and never gets a chance to launch the UI that
    // would let the user decide — the wrap process hangs forever
    // waiting for a decision from a window that never opens.
    if let Err(err) = super::ensure_consent_window(&state) {
        super::log::log_at(
            "server",
            format_args!("ensure_consent_window failed: {err:#}"),
        );
    }
    // Raise the always-on-top "N pending" badge too, so a backgrounded
    // or dismissed consent window can't leave this ask forgotten with
    // the wrap process hung. Idempotent — a no-op if a badge is already
    // up. The badge persists until the queue drains.
    if let Err(err) = super::ensure_badge_window(&state) {
        super::log::log_at(
            "server",
            format_args!("ensure_badge_window failed: {err:#}"),
        );
    }
    match rx.recv() {
        Ok(reply) => waiter_reply_to_daemon_msg(reply),
        Err(_) => DaemonMsg::Decision {
            decision: crate::consent::Decision::Deny,
            secrets: std::collections::HashMap::new(),
            rule_id: None,
            rule_name: None,
            deny_message: None,
        },
    }
}

/// Apply a rule-mutation ClientMsg to State. Used by the streaming
/// connection handler when the consent-window child sends an
/// AddRule/UpdateRule/DeleteRule/SetRuleEnabled. Errors are logged
/// rather than returned to the caller — the UI doesn't currently
/// surface them, and silently leaving the form open without
/// persisting would be a worse user experience than a daemon-log
/// entry the operator can grep.
///
/// `pub(super)` to make the path unit-testable; in production it's
/// only called from `handle_consent_window_connection`. Panics on
/// non-rule variants because the call site is the only legal one
/// and dispatches its own branches above.
pub(super) fn apply_streaming_rule_msg(state: &SharedState, msg: ClientMsg) {
    let result = match msg {
        ClientMsg::AddRule { rule } => state
            .lock()
            .expect("state mutex")
            .add_rule(rule)
            .map(|_| "AddRule"),
        ClientMsg::UpdateRule { rule } => state
            .lock()
            .expect("state mutex")
            .update_rule(rule)
            .map(|_| "UpdateRule"),
        ClientMsg::DeleteRule { id } => state
            .lock()
            .expect("state mutex")
            .delete_rule(&id)
            .map(|_| "DeleteRule"),
        ClientMsg::SetRuleEnabled { id, enabled } => state
            .lock()
            .expect("state mutex")
            .set_rule_enabled(&id, enabled)
            .map(|_| "SetRuleEnabled"),
        other => {
            panic!("apply_streaming_rule_msg called with non-rule variant: {other:?}");
        }
    };
    match result {
        Ok(tag) => super::log::log_at(
            "server",
            format_args!("consent-window {tag} applied successfully"),
        ),
        Err(err) => super::log::log_at(
            "server",
            format_args!("consent-window rule mutation failed: {err:#}"),
        ),
    }
}

/// Build the `DaemonMsg::Decision` for an auto-rule hit. For
/// `DenyAuto` the reply is immediate; for `ApproveAuto` we resolve
/// the secrets synchronously on the connection thread (see the
/// comment in `handle_ask` for why that's fine). On resolution
/// failure we return `DaemonMsg::Err` so the client surfaces a real
/// error rather than silently exiting 1 — same contract as the
/// existing user-approval path.
fn handle_rule_hit(
    ask: Ask,
    hit: crate::rules::RuleHit,
    cache: std::sync::Arc<std::sync::Mutex<super::cache::SecretCache>>,
    in_flight: std::sync::Arc<super::in_flight::InFlightMap>,
    state: SharedState,
) -> DaemonMsg {
    match hit.decide {
        crate::rules::RuleDecision::Deny => {
            // Fire-and-forget toast to any attached consent window.
            // Done before the reply so a wrap with no UI (terminal-
            // only) doesn't lose the signal — the broadcast is
            // independent of the reply socket.
            state
                .lock()
                .expect("state mutex")
                .broadcast_auto_deny_toast(hit.rule_name.clone(), hit.deny_message.clone());
            DaemonMsg::Decision {
                decision: crate::consent::Decision::DenyAuto,
                secrets: std::collections::HashMap::new(),
                rule_id: Some(hit.rule_id),
                rule_name: Some(hit.rule_name),
                deny_message: hit.deny_message,
            }
        }
        crate::rules::RuleDecision::Approve => {
            // The rule's match is the authorization; the cache keys on
            // `(wrap, provider, locator)` so any sibling auto-approved
            // ask reuses the resolved value without re-prompting the
            // provider. The `in_flight` map further coalesces concurrent
            // first-time asks (parallel `gh pr view` bursts) so the
            // provider is invoked exactly once per key even when N
            // siblings race the empty cache. On a cold cache this raises
            // the consent window with a "Resolving…" card so the
            // biometric prompt has its provenance on screen.
            let reply = resolve_approved_with_pending(
                &ask,
                crate::consent::Decision::ApproveAuto,
                cache,
                in_flight,
                &state,
            );
            match reply {
                WaiterReply::Decision { secrets, .. } => DaemonMsg::Decision {
                    decision: crate::consent::Decision::ApproveAuto,
                    secrets,
                    rule_id: Some(hit.rule_id),
                    rule_name: Some(hit.rule_name),
                    deny_message: None,
                },
                WaiterReply::Err { message } => DaemonMsg::Err { message },
            }
        }
    }
}

/// Resolve an already-authorized ask on the calling connection thread,
/// surfacing a "Resolving…" card while the work is in flight.
///
/// Used by the two no-prompt approval paths (approvals-cache hit and
/// auto-rule approve). When the secret cache is **cold** — a provider
/// call, and possibly a biometric prompt, is imminent — it raises the
/// consent window and shows the ask as resolving so the prompt keeps
/// its provenance on screen, then clears the card once the value lands.
/// The state lock is **not** held across `resolve_for_ask`, so the
/// consent-window child can attach and render while the prompt is up.
///
/// `decision` is the approval flavour to stamp on the reply
/// (`ApproveCached` or `ApproveAuto`) so the audit log distinguishes
/// the path.
fn resolve_approved_with_pending(
    ask: &Ask,
    decision: crate::consent::Decision,
    cache: std::sync::Arc<std::sync::Mutex<super::cache::SecretCache>>,
    in_flight: std::sync::Arc<super::in_flight::InFlightMap>,
    state: &SharedState,
) -> WaiterReply {
    let cold = !super::state::ask_fully_cached(ask, &cache);
    if cold {
        state
            .lock()
            .expect("state mutex")
            .begin_pending(ask.clone());
        if let Err(err) = super::ensure_consent_window(state) {
            super::log::log_at(
                "server",
                format_args!("ensure_consent_window (resolving card) failed: {err:#}"),
            );
        }
    }
    let reply = super::state::resolve_for_ask(ask, cache, in_flight).map_decision(|d| {
        if d == crate::consent::Decision::Approve {
            decision
        } else {
            d
        }
    });
    if cold {
        state
            .lock()
            .expect("state mutex")
            .end_pending(&ask.dedupe_key);
    }
    reply
}

fn waiter_reply_to_daemon_msg(reply: WaiterReply) -> DaemonMsg {
    match reply {
        WaiterReply::Decision { decision, secrets } => DaemonMsg::Decision {
            decision,
            secrets,
            // The user-decision path (manual click) never carries
            // rule attribution. Auto-decisions take a different path
            // and construct DaemonMsg::Decision directly with
            // `rule_id` / `rule_name` / `deny_message` populated.
            rule_id: None,
            rule_name: None,
            deny_message: None,
        },
        WaiterReply::Err { message } => DaemonMsg::Err { message },
    }
}

#[allow(dead_code)] // Surface for future use (e.g. test helpers).
/// Directory that holds the daemon's runtime files (`consent.sock` +
/// `daemon.pid`). Both the daemon and its clients derive the path the
/// same way; no env-var handshake needed.
///
/// **Why not `std::env::temp_dir()`?** On macOS, `temp_dir()` reads
/// `TMPDIR`, which is *per-launchd-domain*: a sandboxed launcher
/// (e.g. a GUI app started via launchd) sees a different `TMPDIR`
/// than a plain shell. Two daemons spawned from different domains
/// would land in different directories, each happily holding its own
/// pidfile flock — neither aware of the other, neither protecting
/// the singleton invariant. We hit exactly that.
///
/// Anchoring to `dirs::cache_dir()` (or `XDG_RUNTIME_DIR` when set)
/// gives us a stable per-user path that doesn't move with the
/// caller's env:
///   - Linux: `$XDG_RUNTIME_DIR/secreq` (preferred — tmpfs, cleaned on
///     logout) or `~/.cache/secreq`.
///   - macOS: `~/Library/Caches/secreq`.
///
/// Unix-socket files work fine in `cache_dir()`; the daemon unlinks
/// `consent.sock` on clean shutdown and `acquire_pidfile_lock`
/// guarantees `daemon.pid`'s flock is the singleton primitive
/// regardless of where on disk the file lives.
pub fn socket_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("secreq"));
        }
    }
    let cache = dirs::cache_dir()
        .context("could not determine per-user cache dir for daemon socket (no $HOME?)")?;
    Ok(cache.join("secreq"))
}

/// Stable per-user socket path. Both client and daemon derive it the same
/// way; no env-var handshake needed.
pub fn default_socket_path() -> Result<PathBuf> {
    Ok(socket_dir()?.join("consent.sock"))
}

/// Stable per-user SSH agent socket path (`agent.sock`), alongside the
/// control socket. Re-exported here so the daemon derives both socket
/// paths through `server::`.
pub fn default_agent_socket_path() -> Result<PathBuf> {
    super::ssh_agent::default_agent_socket_path()
}

#[allow(dead_code)]
pub fn pidfile_path() -> Result<PathBuf> {
    Ok(socket_dir()?.join("daemon.pid"))
}

#[allow(dead_code)]
pub fn pidfile_exists(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn deny_reply() -> DaemonMsg {
        DaemonMsg::Decision {
            decision: crate::consent::Decision::Deny,
            secrets: std::collections::HashMap::new(),
            rule_id: None,
            rule_name: None,
            deny_message: None,
        }
    }

    /// Regression: a wrap process killed while its ask is parked leaves a
    /// dead socket. When the user later decides, the daemon writes the
    /// reply to that dead socket. The write hitting `EPIPE` is *expected*
    /// — it must not surface as a `connection error: write reply: Broken
    /// pipe` on the daemon's stderr.
    #[test]
    fn reply_to_killed_client_is_not_an_error() {
        let (server_end, client_end) = UnixStream::pair().expect("socketpair");
        // The client (wrap process) is killed before reading the reply.
        drop(client_end);

        let mut writer = server_end;
        let reply = deny_reply();
        // The kernel may buffer the first write(s); keep writing until the
        // broken peer is observed. Every call must succeed (classified as a
        // benign client-gone), never propagate the EPIPE as an error.
        for _ in 0..10_000 {
            write_reply(&mut writer, &reply)
                .expect("writing to a killed client must not be a daemon error");
        }
    }

    #[test]
    fn hello_handshake_reports_the_daemons_own_build_id() {
        // The version handshake must echo *this* binary's BUILD_ID
        // regardless of what the CLI sent, so the CLI can compare and
        // decide whether to restart a stale daemon.
        use std::sync::{Arc, Mutex};
        let state: SharedState = Arc::new(Mutex::new(super::super::state::State::new()));
        let reply = handle_message(
            ClientMsg::Hello {
                build_id: "some-other-build +123".to_owned(),
            },
            state,
        );
        match reply {
            DaemonMsg::Hello { build_id } => assert_eq!(build_id, crate::BUILD_ID),
            other => panic!("expected Hello reply, got {other:?}"),
        }
    }

    #[test]
    fn peer_hangup_kinds_are_client_disconnects() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
        ] {
            assert!(is_client_disconnect(&io::Error::from(kind)), "{kind:?}");
        }
        // A real daemon-side failure must still propagate.
        assert!(!is_client_disconnect(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }

    /// Regression: rule mutations sent over the consent-window
    /// streaming socket must reach `State::add_rule` and be
    /// persisted to disk. Before this fix, they hit the `other`
    /// arm in `handle_consent_window_connection`'s dispatch and
    /// were silently ignored — UI Save clicks vanished without
    /// touching `auto-rules.json5`.
    #[test]
    fn streaming_add_rule_persists_to_disk() {
        use crate::rules::{Pattern, Rule, RuleDecision, RuleMatch};
        use std::collections::BTreeSet;
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        let state: SharedState = Arc::new(Mutex::new(super::super::state::State::with_rules_path(
            path.clone(),
        )));

        let rule = Rule {
            id: "abc123".to_owned(),
            name: "test rule".to_owned(),
            enabled: true,
            decide: RuleDecision::Approve,
            r#match: RuleMatch {
                wrap: "gh".to_owned(),
                argv: Some(Pattern::parse("gh api")),
                ancestor: None,
                cwd: None,
            },
            trained_secrets: BTreeSet::new(),
            deny_message: None,
            created_at_unix: 0,
        };

        apply_streaming_rule_msg(&state, ClientMsg::AddRule { rule: rule.clone() });

        // Disk: file exists and contains the rule.
        let loaded = crate::rules::load_rules(&path).expect("reload");
        assert_eq!(loaded.rules, vec![rule.clone()]);
        // In-memory: State sees it too.
        assert_eq!(state.lock().unwrap().rules_snapshot(), vec![rule]);
    }

    #[test]
    fn streaming_delete_and_toggle_round_trip_to_disk() {
        use crate::rules::{Rule, RuleDecision, RuleMatch};
        use std::collections::BTreeSet;
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auto-rules.json5");
        let state: SharedState = Arc::new(Mutex::new(super::super::state::State::with_rules_path(
            path.clone(),
        )));

        let rule = Rule {
            id: "to-delete".to_owned(),
            name: "to delete".to_owned(),
            enabled: true,
            decide: RuleDecision::Deny,
            r#match: RuleMatch {
                wrap: "gh".to_owned(),
                argv: None,
                ancestor: None,
                cwd: None,
            },
            trained_secrets: BTreeSet::new(),
            deny_message: Some("blocked".to_owned()),
            created_at_unix: 0,
        };
        apply_streaming_rule_msg(&state, ClientMsg::AddRule { rule });

        apply_streaming_rule_msg(
            &state,
            ClientMsg::SetRuleEnabled {
                id: "to-delete".to_owned(),
                enabled: false,
            },
        );
        assert!(!crate::rules::load_rules(&path).unwrap().rules[0].enabled);

        apply_streaming_rule_msg(
            &state,
            ClientMsg::DeleteRule {
                id: "to-delete".to_owned(),
            },
        );
        assert!(crate::rules::load_rules(&path).unwrap().rules.is_empty());
    }
}
