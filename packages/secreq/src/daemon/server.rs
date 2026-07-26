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

use super::proto::{Ask, ClientMsg, DaemonMsg, DedupeKey};
use super::state::{SharedState, WaiterId, WaiterReply};

/// Bind the daemon socket and start accepting connections.
///
/// Returns the bound listener so the caller can keep it alive. The accept
/// loop runs on a background thread that exits when the listener is
/// dropped (the OS errors the accept).
pub fn start(socket_path: PathBuf, state: SharedState) -> Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        crate::paths::ensure_private_dir(parent)
            .with_context(|| format!("create {}", parent.display()))?;
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
        // A failed accept means the listener is closed or unrecoverably
        // broken; either way there is nothing left to serve.
        let Ok(stream) = incoming else { break };
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
    // Before a byte is parsed. The socket mode should already have excluded
    // a foreign uid; this covers the window where it did not (see
    // `peercred::peer_is_same_user`).
    if super::peercred::peer_is_same_user(&stream) != Some(true) {
        super::log::log_at(
            "server",
            format_args!("refused a connection from another user"),
        );
        return Ok(());
    }
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

    // Branch: streaming manager-window attach — the persistent Rules +
    // Audit surface. Same push-stream shape; its read loop handles rule
    // mutations and detach.
    if let ClientMsg::ManagerWindowAttach { pid } = msg {
        super::log::log_at(
            "server",
            format_args!("← ClientMsg::ManagerWindowAttach (pid={pid})"),
        );
        handle_manager_window_connection(reader, stream, state, pid)?;
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

    // Branch: one-shot Ask. Handled here rather than through
    // `handle_message` because this thread must keep the raw socket to
    // watch for the client hanging up while the ask is parked — a wrap
    // killed before the user decides then gets its ask reaped instead of
    // orphaned in the queue. See `handle_ask_connection`.
    if let ClientMsg::Ask(ask) = msg {
        super::log::log_at("server", format_args!("← ClientMsg::Ask"));
        // Mirror `handle_message`'s pre-dispatch rules refresh so a
        // hand-edited rules file is honoured for this ask too.
        state.lock().expect("state mutex").reload_rules_if_changed();
        return handle_ask_connection(reader, stream, ask, state);
    }

    // For the non-blocking show-a-window verbs, spawn after we've
    // replied so the client doesn't wait on `Command::spawn`.
    // `ShowWindow` raises the prompt; `ShowViewer` opens the manager
    // on the Audit view.
    let spawn_prompt = matches!(&msg, ClientMsg::ShowWindow);
    let spawn_manager = matches!(&msg, ClientMsg::ShowViewer);
    let reply = handle_message(msg, state.clone());
    let mut writer = stream;
    write_reply(&mut writer, &reply)?;
    if spawn_prompt {
        if let Err(err) = super::ensure_consent_window(&state) {
            super::log::log_at(
                "server",
                format_args!("ensure_consent_window failed: {err:#}"),
            );
        }
    }
    if spawn_manager {
        if let Err(err) =
            super::ensure_manager_window(&state, Some(super::proto::ManagerFocus::Audit))
        {
            super::log::log_at(
                "server",
                format_args!("ensure_manager_window failed: {err:#}"),
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
        let Ok(n) = reader.read_line(&mut line) else {
            break;
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
            ClientMsg::OpenManager { focus } => {
                super::log::log_at(
                    "server",
                    format_args!("← OpenManager focus={focus:?} (prompt link)"),
                );
                if let Err(err) = super::ensure_manager_window(&state, Some(focus)) {
                    super::log::log_at(
                        "server",
                        format_args!("open-manager ensure_manager_window failed: {err:#}"),
                    );
                }
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

/// Streaming connection for a manager-window child. Mirrors
/// [`handle_consent_window_connection`]'s writer-thread + read-loop
/// shape (and its exact detach-ordering contract). The manager's read
/// loop handles rule mutations (its Rules view is the primary editor)
/// and detach-by-socket-drop; it never sends decisions, never reports
/// focus, and never receives `ConsentExitPlease` — it closes when the
/// user closes it or when the daemon process exits (socket drop).
fn handle_manager_window_connection(
    reader: BufReader<UnixStream>,
    socket: UnixStream,
    state: SharedState,
    pid: u32,
) -> Result<()> {
    let (tx, rx) = mpsc::channel::<DaemonMsg>();

    let (subscriber_id, initial_snapshot) = state
        .lock()
        .expect("state mutex")
        .attach_manager_window(pid, tx.clone());

    let writer_socket = socket
        .try_clone()
        .context("clone socket for manager writer")?;
    let writer_handle = thread::Builder::new()
        .name("manager-window-writer".to_owned())
        .spawn(move || {
            let mut writer = writer_socket;
            while let Ok(msg) = rx.recv() {
                let json = match serde_json::to_string(&msg) {
                    Ok(j) => j,
                    Err(err) => {
                        eprintln!("secreqd: serialize manager update: {err}");
                        return;
                    }
                };
                if writeln!(writer, "{json}").is_err() {
                    return; // Socket closed.
                }
            }
        })
        .context("spawn manager-window writer thread")?;

    // Eager initial push so the manager can paint its first frame.
    let _ = tx.send(DaemonMsg::ConsentUpdate {
        snapshot: initial_snapshot,
    });

    let mut reader = reader;
    let mut line = String::new();
    loop {
        line.clear();
        let Ok(n) = reader.read_line(&mut line) else {
            break;
        };
        if n == 0 {
            super::log::log_at(
                "server",
                format_args!("manager-window socket closed by child"),
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
                    format_args!("manager-window: malformed msg: {err}; line=[{trimmed}]"),
                );
                continue;
            }
        };
        match msg {
            ClientMsg::AddRule { .. }
            | ClientMsg::UpdateRule { .. }
            | ClientMsg::DeleteRule { .. }
            | ClientMsg::SetRuleEnabled { .. } => {
                apply_streaming_rule_msg(&state, msg);
            }
            other => {
                super::log::log_at(
                    "server",
                    format_args!("manager-window sent unexpected message: {other:?}"),
                );
            }
        }
    }

    // Same detach-order contract as the consent window: remove the
    // subscriber before dropping our local tx so the writer thread's
    // `rx.recv()` returns `Err` and we can join without deadlocking.
    // `detach_manager_window` also clears viewer mode when this was
    // the last manager.
    state
        .lock()
        .expect("state mutex")
        .detach_manager_window(subscriber_id);
    drop(tx);
    let _ = writer_handle.join();
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
        let Ok(n) = reader.read_line(&mut line) else {
            break;
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
        ClientMsg::ManagerWindowAttach { .. } => "ManagerWindowAttach",
        ClientMsg::OpenManager { .. } => "OpenManager",
        ClientMsg::BadgeWindowAttach { .. } => "BadgeWindowAttach",
        ClientMsg::BadgeWindowDetach => "BadgeWindowDetach",
        ClientMsg::RaiseConsentRequested => "RaiseConsentRequested",
        ClientMsg::ListRules => "ListRules",
        ClientMsg::AddRule { .. } => "AddRule",
        ClientMsg::AddWasmRule { .. } => "AddWasmRule",
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
            // `secreq view` opens the *manager* window on the Audit
            // view. No kill-and-respawn: the manager is a persistent
            // browsing surface, so an existing one is left alone and
            // its pid handed back for CLI-side activation. The spawn
            // (if needed) happens after the reply, in
            // `handle_connection`.
            let mut guard = state.lock().expect("state mutex");
            guard.enter_viewer_mode();
            guard.touch();
            DaemonMsg::WindowOpened {
                child_pid: guard.manager_child_pid(),
            }
        }
        // Ask is intercepted in `handle_connection` (it needs the raw
        // socket to watch for a hang-up), so it never reaches this
        // one-shot dispatch.
        ClientMsg::Ask(_) => {
            unreachable!("ClientMsg::Ask is handled by handle_ask_connection")
        }
        ClientMsg::Shutdown => {
            state.lock().expect("state mutex").request_shutdown();
            DaemonMsg::Ok
        }
        // The streaming window messages must arrive on the streaming
        // connection paths (`handle_consent_window_connection` /
        // `handle_manager_window_connection` / the badge handler).
        // Seeing them on the one-shot path means the child connected
        // without its Attach message first; reply with an error so the
        // child doesn't deadlock.
        ClientMsg::ConsentWindowAttach { .. }
        | ClientMsg::ConsentDecision { .. }
        | ClientMsg::ConsentWindowDetach
        | ClientMsg::ConsentWindowFocus { .. }
        | ClientMsg::ManagerWindowAttach { .. }
        | ClientMsg::OpenManager { .. }
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
                wasm_refusals: guard.wasm_refusals_snapshot(),
            }
        }
        // `secreq rules add-wasm`. The wire carries the module's
        // (absolute) path, not its bytes — same-user, same-machine, so
        // the daemon reads the file itself, then vets/copies/persists
        // in `State::add_wasm_rule`. A read failure here registers
        // nothing.
        ClientMsg::AddWasmRule {
            name,
            module_path,
            trained_secrets,
            allow_all_secrets,
        } => match read_wasm_module_bytes(&module_path) {
            Ok(bytes) => {
                let mut guard = state.lock().expect("state mutex");
                match guard.add_wasm_rule(&name, &bytes, trained_secrets, allow_all_secrets) {
                    Ok(rule) => DaemonMsg::RuleAdded {
                        rule: Box::new(rule),
                    },
                    Err(err) => DaemonMsg::Err {
                        message: format!("{err:#}"),
                    },
                }
            }
            Err(err) => DaemonMsg::Err {
                message: format!("{err:#}"),
            },
        },
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
            // Scoped-agent only: the user anchored a TTL'd grant to the
            // scope. It crosses this socket as a normal decision reply — the
            // *agent process* is the client that acts on it, remembering the
            // grant in its own `ScopeApprovals`. The daemon deliberately
            // remembers nothing here (`Ask::allow_remember` is false on these
            // asks); a guest has no host parent for the daemon's cache to key
            // on.
            crate::consent::Decision::ApproveAgentSession => "Decision::ApproveAgentSession",
            crate::consent::Decision::Deny => "Decision::Deny",
            crate::consent::Decision::DenyAuto => "Decision::DenyAuto",
            // Scoped-agent only, and never sent as a reply from here: an
            // out-of-scope ref is refused by `scoped_agent::handle_request`
            // before any ask reaches this daemon. Named because Decision is
            // shared.
            crate::consent::Decision::DenyOutOfScope => "Decision::DenyOutOfScope",
            // Never sent as a wrap reply — an abandoned ask has no live
            // client to receive it — but Decision is shared, so name it.
            crate::consent::Decision::Abandoned => "Decision::Abandoned",
        },
        DaemonMsg::Err { .. } => "Err",
        DaemonMsg::ConsentUpdate { .. } => "ConsentUpdate",
        DaemonMsg::ConsentExitPlease => "ConsentExitPlease",
        DaemonMsg::RulesList { .. } => "RulesList",
        DaemonMsg::RuleAdded { .. } => "RuleAdded",
        DaemonMsg::AutoDenyToast { .. } => "AutoDenyToast",
    };
    super::log::log_at("server", format_args!("→ DaemonMsg::{reply_tag}"));
    reply
}

/// Outcome of `handle_ask`. A fast path resolves synchronously (reply the
/// client now); otherwise the ask is enqueued and the caller parks a
/// reply-writer on `rx` while watching the socket for the client hanging
/// up (see `handle_ask_connection`).
enum AskDisposition {
    Resolved(DaemonMsg),
    Enqueued {
        key: DedupeKey,
        waiter_id: WaiterId,
        rx: mpsc::Receiver<WaiterReply>,
    },
}

fn handle_ask(ask: Ask, state: SharedState) -> AskDisposition {
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
            return AskDisposition::Resolved(waiter_reply_to_daemon_msg(reply));
        }
    }
    // Auto-rules path. The mtime-based reload already ran in
    // `handle_ask_connection`, so `state.rules` reflects any hand-edits
    // made since the daemon started. If a rule fires, the ask never enters
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
            return AskDisposition::Resolved(handle_rule_hit(ask, hit, cache, in_flight, state));
        }
    }
    // Nested-run fast path: a `run` invoked under an already-consented
    // run (it carries `nested_run`) whose every value is already cached
    // resolves silently — "a secret crosses the consent boundary once per
    // run session." Any uncached secret makes `nested_run_fully_cached`
    // false, so the ask falls through to the prompt below; and an
    // unnested run never sets the flag, so it always prompts. Checked
    // after the rules pass so a deny rule still wins over the skip.
    {
        let guard = state.lock().expect("state mutex");
        let cache = guard.secret_cache_arc();
        let in_flight = guard.in_flight_arc();
        // Checked under the lock: the answer depends on what this session was
        // consented for, which lives in `State`, not in the value cache.
        let may_skip = guard.nested_run_may_skip_window(&ask);
        drop(guard);
        if may_skip {
            let reply = resolve_approved_with_pending(
                &ask,
                crate::consent::Decision::ApproveCached,
                cache,
                in_flight,
                &state,
            );
            return AskDisposition::Resolved(waiter_reply_to_daemon_msg(reply));
        }
    }
    // Slow path: enqueue and hand the caller the channel + waiter id so it
    // can park a reply-writer while watching the socket for hang-up.
    let (tx, rx) = mpsc::channel();
    let key = ask.dedupe_key.clone();
    let (is_new, waiter_id) = {
        let mut guard = state.lock().expect("state mutex");
        let (result, waiter_id) = guard.submit_ask(ask, tx);
        // Restart only on genuinely new entries. A coalesced ask is
        // joining an existing queue row that the current UI is already
        // displaying; killing the window mid-decision to "re-show"
        // the same card would be worse UX (and would drop the user's
        // in-progress choice). Only the first fresh entry per dedupe
        // key warrants a foreground raise.
        (
            matches!(result, super::state::SubmitResult::NewEntry),
            waiter_id,
        )
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
    AskDisposition::Enqueued { key, waiter_id, rx }
}

/// Drive a one-shot Ask connection. Fast-path resolutions reply straight
/// back; a queued ask parks a reply-writer thread on the decision channel
/// while THIS thread watches the socket for the client hanging up. A wrap
/// killed before the user decides closes its socket — we notice the EOF and
/// withdraw the ask (reaping the card + writing an `abandoned` audit row)
/// instead of leaving it orphaned in the queue.
/// Replace the client-supplied provenance on `ask` with a chain the daemon
/// walks itself from the socket peer.
///
/// The client sends `callers`, `cwd` and a dedupe key describing who is
/// asking, and until now the daemon rendered all of it as fact. Any process
/// that can reach this socket can therefore name the user's own shell as its
/// parent, and the consent prompt will say so. The kernel already knows the
/// truth, and `SO_PEERCRED` / `LOCAL_PEERCRED` is how the SSH agent has
/// always got it (`ssh_agent.rs`); this brings the wrap path level with it.
///
/// Returns `Err` with a client-facing message when provenance cannot be
/// established. That is fail-closed by construction: the caller replies with
/// the error and never enqueues the ask, so no prompt is shown and nothing is
/// released.
///
/// **Scoped-agent asks are exempt, and must stay exempt.** Their peer is the
/// `secreq agent open` process, whose parent is whatever shell started the
/// sandbox — a host process that has nothing to do with the guest making the
/// request. Walking it would not be "the truth about the asker", it would be
/// a plausible-looking chain attached to the wrong principal, which is worse
/// than the empty one the prompt shows today. The host-declared scope is the
/// principal on that path (see `scoped_agent`).
fn adopt_peer_provenance(ask: &mut Ask, stream: &UnixStream) -> Result<()> {
    if ask.agent.is_some() {
        return Ok(());
    }

    let peer = super::peercred::peer_pid(stream)
        .context("could not read the peer's pid from the consent socket")?;
    let chain = crate::provenance::caller_chain_from_pid(peer);
    let parent = chain.first().context(
        "the requesting process has no visible parent; refusing to prompt for an ask \
         whose provenance cannot be established",
    )?;

    // The dedupe key's process half keys the approvals cache, so a forged one
    // is a cache-scope escape, not just a display lie. Re-derive it from the
    // same walk that produced the chain.
    //
    // A `run` ask is the exception: its `(ppid, parent_start_time)` is a
    // *session* identity — the outer run's pid plus a random nonce, shared
    // across the tree — not a process identity, and re-deriving it per
    // process would dissolve the session into one entry per nested run.
    // Nothing keys the approvals cache on it (`run` sets
    // `allow_remember: false`, so no `ApprovalEntry` under that wrap is ever
    // stored, and a lookup needs an entry to hit), and what a session may be
    // served without prompting is bounded separately by
    // `State::nested_run_may_skip_window`.
    if ask.dedupe_key.wrap != super::state::RUN_SESSION_WRAP {
        ask.dedupe_key.ppid = parent.pid;
        ask.dedupe_key.parent_start_time = parent.start_time;
    }

    ask.callers = chain
        .iter()
        .map(|c| super::proto::Caller {
            pid: c.pid,
            name: c.name.clone(),
            command: c.command.clone(),
            start_time: c.start_time,
        })
        .collect();
    // A cwd we cannot read is rendered as absent rather than guessed at, and
    // the client's claim is not a fallback — it is the thing being replaced.
    ask.cwd = crate::provenance::cwd_for_pid(peer).unwrap_or_default();

    Ok(())
}

fn handle_ask_connection(
    reader: BufReader<UnixStream>,
    stream: UnixStream,
    mut ask: Ask,
    state: SharedState,
) -> Result<()> {
    if let Err(err) = adopt_peer_provenance(&mut ask, &stream) {
        super::log::log_at("server", format_args!("← ClientMsg::Ask refused: {err:#}"));
        let mut writer = stream;
        return write_reply(
            &mut writer,
            &DaemonMsg::Err {
                message: format!("{err:#}"),
            },
        );
    }
    match handle_ask(ask, state.clone()) {
        AskDisposition::Resolved(reply) => {
            let mut writer = stream;
            write_reply(&mut writer, &reply)
        }
        AskDisposition::Enqueued { key, waiter_id, rx } => {
            park_ask_and_watch(reader, stream, state, key, waiter_id, rx)
        }
    }
}

/// Park a queued ask: a reply-writer thread delivers the user's decision
/// while this thread blocks reading the socket to detect a hang-up. On EOF
/// (or a disconnect error) the client is gone, so we withdraw the waiter.
fn park_ask_and_watch(
    mut reader: BufReader<UnixStream>,
    stream: UnixStream,
    state: SharedState,
    key: DedupeKey,
    waiter_id: WaiterId,
    rx: mpsc::Receiver<WaiterReply>,
) -> Result<()> {
    // Reply-writer: delivers the decision when the user acts. If the waiter
    // is withdrawn first (client already gone), its sender is dropped and
    // this `recv` returns `Err` — nothing to send, so the thread just exits.
    let reply_thread = thread::Builder::new()
        .name("secreqd-ask-reply".to_owned())
        .spawn(move || {
            let mut writer = stream;
            if let Ok(reply) = rx.recv() {
                let _ = write_reply(&mut writer, &waiter_reply_to_daemon_msg(reply));
            }
        })
        .context("spawn ask reply-writer thread")?;

    // Watch for the client hanging up. A wrap sends nothing after its Ask,
    // so this single `read_line` blocks until the connection ends: `Ok(0)`
    // is EOF and a disconnect error is the same signal — either way the
    // client is gone. Unexpected extra bytes (a wrap shouldn't speak again)
    // also end the watch; we don't loop because the protocol is one-shot.
    let mut buf = String::new();
    match reader.read_line(&mut buf) {
        Ok(0) => {}
        Ok(_) => super::log::log_at(
            "server",
            format_args!("unexpected bytes on parked ask socket; ending watch"),
        ),
        Err(ref err) if is_client_disconnect(err) => {}
        Err(err) => return Err(err).context("watch parked ask socket"),
    }

    // Connection closed. Withdraw our waiter — a no-op if the user already
    // resolved it (entry gone / moved to a resolving card). On a genuine
    // abandon this reaps the card and writes the `abandoned` audit row.
    state
        .lock()
        .expect("state mutex")
        .withdraw_waiter(&key, waiter_id);

    // The reply-writer has either already written the decision or unblocked
    // on the dropped sender; join so the socket outlives any pending write.
    let _ = reply_thread.join();
    Ok(())
}

/// Upper bound on a to-be-registered wasm module's size. Real rule
/// modules are KB-scale (the SDK fixtures compile to a few KB); the
/// generous cap only exists so a mistaken path from the client can't
/// balloon daemon memory before the sandbox vetting rejects the bytes
/// anyway.
const MAX_WASM_MODULE_BYTES: u64 = 16 * 1024 * 1024;

/// Read a to-be-registered module defensively. The path is
/// client-supplied (same user, so not a privilege boundary — but the
/// daemon must not wedge itself on a typo): it must be a regular file
/// — a FIFO would block this connection thread forever — and within
/// [`MAX_WASM_MODULE_BYTES`].
fn read_wasm_module_bytes(path: &str) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).with_context(|| format!("stat wasm module {path}"))?;
    if !meta.is_file() {
        anyhow::bail!("wasm module {path} is not a regular file");
    }
    if meta.len() > MAX_WASM_MODULE_BYTES {
        anyhow::bail!(
            "wasm module {path} is {} bytes, over the {MAX_WASM_MODULE_BYTES}-byte \
             registration cap — rule modules are expected to be KB-scale",
            meta.len()
        );
    }
    std::fs::read(path).with_context(|| format!("read wasm module {path}"))
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
            .map(|()| "AddRule"),
        ClientMsg::UpdateRule { rule } => state
            .lock()
            .expect("state mutex")
            .update_rule(rule)
            .map(|()| "UpdateRule"),
        ClientMsg::DeleteRule { id } => state
            .lock()
            .expect("state mutex")
            .delete_rule(&id)
            .map(|()| "DeleteRule"),
        ClientMsg::SetRuleEnabled { id, enabled } => state
            .lock()
            .expect("state mutex")
            .set_rule_enabled(&id, enabled)
            .map(|()| "SetRuleEnabled"),
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
    crate::paths::socket_dir()
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

/// Path to the daemon-spawn lock, alongside the pidfile. Clients `flock`
/// this before auto-spawning the daemon so a burst of wraps forks one
/// daemon instead of a thundering herd (see `client::connect_or_spawn`).
/// Distinct from the pidfile lock, which the daemon itself holds for its
/// lifetime — this one is held only briefly, by whichever client is
/// bringing the daemon up.
pub fn spawn_lock_path() -> Result<PathBuf> {
    Ok(socket_dir()?.join("daemon.spawn.lock"))
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

    /// The core of the feature: a wrap killed while its ask is parked
    /// closes its socket. `park_ask_and_watch` must notice the EOF, reap
    /// the ask from the queue (so its card leaves the requests view), and
    /// record an `abandoned` audit row — rather than leaving the ask
    /// orphaned until the daemon exits.
    #[test]
    fn parked_ask_is_withdrawn_when_the_client_hangs_up() {
        use std::sync::{Arc, Mutex};

        crate::audit::with_temp_log(|| {
            let state: SharedState = Arc::new(Mutex::new(super::super::state::State::new()));

            // Register a parked waiter, as the slow path does.
            let ask = Ask {
                command: vec!["gh".to_owned(), "pr".to_owned(), "view".to_owned()],
                cwd: "/work".to_owned(),
                callers: vec![],
                secrets: vec![],
                providers: std::collections::HashMap::new(),
                dedupe_key: DedupeKey {
                    wrap: "gh".to_owned(),
                    ppid: 4242,
                    parent_start_time: 7,
                    subject_digest: None,
                },
                ssh: None,
                agent: None,
                allow_remember: true,
                nested_run: false,
            };
            let (tx, rx) = mpsc::channel();
            let key = ask.dedupe_key.clone();
            let waiter_id = state.lock().unwrap().submit_ask(ask, tx).1;
            assert_eq!(
                state.lock().unwrap().snapshot().entries.len(),
                1,
                "ask is queued before the hang-up"
            );

            // The wrap process is killed before the user decides: its socket
            // end closes, so the watch read hits EOF immediately.
            let (server_end, client_end) = UnixStream::pair().expect("socketpair");
            drop(client_end);
            let reader = BufReader::new(server_end.try_clone().expect("clone socket"));
            park_ask_and_watch(reader, server_end, state.clone(), key, waiter_id, rx)
                .expect("watch returns cleanly on a client hang-up");

            // The card is reaped from the requests view...
            assert!(
                state.lock().unwrap().snapshot().entries.is_empty(),
                "the abandoned ask is removed from the queue"
            );
            // ...and exactly one `abandoned` row was written for it.
            let rows = crate::audit::read_history(None).expect("read audit log");
            assert_eq!(rows.len(), 1, "one abandoned row");
            assert_eq!(rows[0].decision, "abandoned");
            assert_eq!(rows[0].wrap, "gh");
            assert_eq!(rows[0].args, vec!["pr", "view"]);
        });
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
            decide: Some(RuleDecision::Approve),
            r#match: Some(RuleMatch {
                wrap: "gh".to_owned(),
                argv: Some(Pattern::parse("gh api")),
                ancestor: None,
                cwd: None,
            }),
            wasm: None,
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

    /// The one-shot `AddWasmRule` path end to end: the CLI ships a
    /// module *path*, the daemon reads + vets + stores + persists, and
    /// the follow-up `ListRules` reply carries the new rule with no
    /// refusals. Also the guard: an empty trained-secrets snapshot
    /// without the opt-in is refused with nothing registered.
    #[test]
    fn add_wasm_rule_over_ipc_registers_and_lists() {
        use std::sync::{Arc, Mutex};

        const APPROVE_IF: &[u8] = include_bytes!("../../tests/fixtures/wasm_rules/approve_if.wasm");

        // `rules_path` is a tempdir, but the *module store* is not: it
        // resolves from `$SECREQ_HOME` and is shared by every test in this
        // process. Registering without this lock lets a module land in the
        // store while `daemon::state`'s rollback tests are comparing that
        // directory before and after, failing them on a file they never
        // created.
        let _store = crate::paths::env_lock();

        let dir = tempfile::tempdir().expect("tempdir");
        let module_src = dir.path().join("uploaded.wasm");
        std::fs::write(&module_src, APPROVE_IF).expect("write module");
        let rules_path = dir.path().join("auto-rules.json5");
        let state: SharedState = Arc::new(Mutex::new(super::super::state::State::with_rules_path(
            rules_path,
        )));

        // Empty snapshot without the opt-in: refused, nothing listed.
        let reply = handle_message(
            ClientMsg::AddWasmRule {
                name: "greedy".to_owned(),
                module_path: module_src.to_string_lossy().into_owned(),
                trained_secrets: Default::default(),
                allow_all_secrets: false,
            },
            state.clone(),
        );
        match reply {
            DaemonMsg::Err { message } => {
                assert!(message.contains("trained-secrets"), "{message}");
            }
            other => panic!("expected Err, got {other:?}"),
        }

        // With a trained snapshot: registered, and visible via ListRules.
        let trained: std::collections::BTreeSet<String> =
            ["GITHUB_TOKEN".to_owned()].into_iter().collect();
        let reply = handle_message(
            ClientMsg::AddWasmRule {
                name: "cursor gh reads".to_owned(),
                module_path: module_src.to_string_lossy().into_owned(),
                trained_secrets: trained.clone(),
                allow_all_secrets: false,
            },
            state.clone(),
        );
        let rule = match reply {
            DaemonMsg::RuleAdded { rule } => *rule,
            other => panic!("expected RuleAdded, got {other:?}"),
        };
        assert_eq!(rule.trained_secrets, trained);
        assert_eq!(
            rule.wasm.as_ref().expect("wasm").sha256,
            crate::rules::sha256_hex(APPROVE_IF)
        );

        match handle_message(ClientMsg::ListRules, state.clone()) {
            DaemonMsg::RulesList {
                rules,
                wasm_refusals,
            } => {
                assert_eq!(rules, vec![rule.clone()]);
                assert!(wasm_refusals.is_empty(), "{wasm_refusals:?}");
            }
            other => panic!("expected RulesList, got {other:?}"),
        }

        // Clean up the shared-store module this test registered.
        state.lock().unwrap().delete_rule(&rule.id).expect("delete");
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
            decide: Some(RuleDecision::Deny),
            r#match: Some(RuleMatch {
                wrap: "gh".to_owned(),
                argv: None,
                ancestor: None,
                cwd: None,
            }),
            wasm: None,
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

    // ── Peer-derived provenance ───────────────────────────────────────

    /// Build an ask carrying a caller chain and dedupe identity that name a
    /// process which does not exist. This is what a forged ask looks like:
    /// well-formed, and describing an ancestry the sender never had.
    fn forged_ask(wrap: &str) -> Ask {
        Ask {
            command: vec!["gh".to_owned(), "api".to_owned()],
            cwd: "/somewhere/the/attacker/named".to_owned(),
            callers: vec![super::super::proto::Caller {
                pid: FORGED_PID,
                name: "zsh".to_owned(),
                command: "-zsh".to_owned(),
                start_time: 12345,
            }],
            secrets: Vec::new(),
            providers: std::collections::HashMap::new(),
            dedupe_key: DedupeKey {
                wrap: wrap.to_owned(),
                ppid: FORGED_PID,
                parent_start_time: 12345,
                subject_digest: None,
            },
            ssh: None,
            agent: None,
            allow_remember: true,
            nested_run: false,
        }
    }

    const FORGED_PID: u32 = 999_999;

    /// A connected pair whose peer is this test process, so the daemon-side
    /// walk resolves to our own real ancestry.
    fn connected_pair() -> (UnixStream, UnixStream) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("t.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let client = UnixStream::connect(&path).expect("connect");
        let (server_conn, _) = listener.accept().expect("accept");
        (server_conn, client)
    }

    /// The core of the fix: whatever the client claimed about its ancestry is
    /// discarded in favour of a chain the daemon walked from the socket peer.
    /// Without this, any process that can reach the socket can name the
    /// user's own shell as its parent and the prompt will say so.
    #[test]
    fn a_forged_caller_chain_is_replaced_by_the_peers_real_one() {
        let (server_conn, _client) = connected_pair();
        let mut ask = forged_ask("gh");

        adopt_peer_provenance(&mut ask, &server_conn).expect("provenance");

        assert!(
            !ask.callers.iter().any(|c| c.pid == FORGED_PID),
            "the forged frame survived into the chain: {:?}",
            ask.callers.iter().map(|c| c.pid).collect::<Vec<_>>()
        );
        assert!(
            !ask.callers.is_empty(),
            "the real chain should be populated"
        );
        assert_ne!(ask.cwd, "/somewhere/the/attacker/named");
    }

    /// The dedupe key's process half keys the approvals cache, so leaving it
    /// client-supplied would be a cache-scope escape and not merely a display
    /// lie: claim the shell's pid, ride the approval the user granted there.
    #[test]
    fn a_forged_dedupe_identity_is_re_derived_from_the_peer() {
        let (server_conn, _client) = connected_pair();
        let mut ask = forged_ask("gh");

        adopt_peer_provenance(&mut ask, &server_conn).expect("provenance");

        assert_ne!(ask.dedupe_key.ppid, FORGED_PID);
        assert_ne!(ask.dedupe_key.parent_start_time, 12345);
        // It agrees with the chain the daemon just walked, which is how the
        // client derives it too.
        assert_eq!(ask.dedupe_key.ppid, ask.callers[0].pid);
        assert_eq!(ask.dedupe_key.parent_start_time, ask.callers[0].start_time);
        // The wrap half is config, not provenance, and is left alone.
        assert_eq!(ask.dedupe_key.wrap, "gh");
    }

    /// A `run` ask's dedupe key is a *session* identity: the outer run's pid
    /// plus a random nonce, shared by every descendant so one consent covers
    /// the tree. Re-deriving it per-process would dissolve the session into
    /// one entry per nested run. Its caller chain is still corrected.
    #[test]
    fn a_run_session_dedupe_key_survives_but_its_chain_does_not() {
        let (server_conn, _client) = connected_pair();
        let mut ask = forged_ask(super::super::state::RUN_SESSION_WRAP);

        adopt_peer_provenance(&mut ask, &server_conn).expect("provenance");

        assert_eq!(
            ask.dedupe_key.ppid, FORGED_PID,
            "session identity preserved"
        );
        assert_eq!(ask.dedupe_key.parent_start_time, 12345);
        assert!(!ask.callers.iter().any(|c| c.pid == FORGED_PID));
    }

    /// A scoped-agent ask's peer is the `agent open` process, whose parent is
    /// a host shell with no relationship to the guest that made the request.
    /// Walking it would attach a plausible chain to the wrong principal —
    /// worse than the empty one the prompt deliberately shows.
    #[test]
    fn a_scoped_agent_ask_keeps_its_empty_chain() {
        let (server_conn, _client) = connected_pair();
        let mut ask = forged_ask("agent:sandbox:secret://op/a/b");
        ask.callers = Vec::new();
        ask.cwd = String::new();
        ask.agent = Some(super::super::proto::AgentAskInfo {
            scope: "sandbox".to_owned(),
            reference: "secret://op/a/b".to_owned(),
            guest_chain: None,
        });

        adopt_peer_provenance(&mut ask, &server_conn).expect("provenance");

        assert!(
            ask.callers.is_empty(),
            "a guest ask must not gain a host chain"
        );
        assert!(ask.cwd.is_empty());
        assert_eq!(ask.dedupe_key.ppid, FORGED_PID);
    }
}
