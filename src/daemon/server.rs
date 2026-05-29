//! Daemon socket server: bind, accept, handle one client per thread.
//!
//! Each connection is a single request/response over JSON lines. Long
//! requests (asks waiting on the user) park on a `mpsc::Receiver` until
//! the UI thread answers. The connection thread isn't a problem to keep
//! around — it's blocked on a channel, not on CPU.

use std::io::{BufRead, BufReader, Write};
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

    let listener_clone = listener.try_clone()?;
    thread::Builder::new()
        .name("secreqd-accept".to_owned())
        .spawn(move || accept_loop(listener_clone, state))
        .context("spawn daemon accept thread")?;

    Ok(listener)
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
        return Ok(()); // Client disconnected without sending — no-op.
    }
    let msg: ClientMsg = serde_json::from_str(line.trim()).context("malformed client message")?;
    let reply = handle_message(msg, state);
    let mut writer = stream;
    let json = serde_json::to_string(&reply).context("serialize reply")?;
    writeln!(writer, "{json}").context("write reply")?;
    Ok(())
}

fn handle_message(msg: ClientMsg, state: SharedState) -> DaemonMsg {
    match msg {
        ClientMsg::Ping => {
            state.lock().expect("state mutex").touch();
            DaemonMsg::Ok
        }
        ClientMsg::ShowWindow => {
            let mut guard = state.lock().expect("state mutex");
            guard.show_window();
            guard.touch();
            DaemonMsg::Ok
        }
        ClientMsg::ShowViewer => {
            let mut guard = state.lock().expect("state mutex");
            guard.enter_viewer_mode();
            guard.touch();
            DaemonMsg::Ok
        }
        ClientMsg::Ask(ask) => handle_ask(ask, state),
        ClientMsg::Shutdown => {
            // Flip the flag and ack immediately — the actual exit
            // happens on the next UI tick (which we nudge via repaint
            // from inside `request_shutdown`). Acking before exit means
            // the client gets a clean reply instead of a closed-socket
            // error.
            state.lock().expect("state mutex").request_shutdown();
            DaemonMsg::Ok
        }
    }
}

fn handle_ask(ask: Ask, state: SharedState) -> DaemonMsg {
    // Fast-path: parent-keyed approval cache hit. Take the lock briefly,
    // resolve (one provider invocation, the win we want even on cache
    // hits), release. We don't enqueue: the UI has nothing to show.
    {
        let guard = state.lock().expect("state mutex");
        if let Some(reply) = guard.try_cache_hit(&ask) {
            return waiter_reply_to_daemon_msg(reply);
        }
    }
    // Slow path: enqueue and park on the reply channel. This thread is
    // blocked on the channel, not the state mutex.
    let (tx, rx) = mpsc::channel();
    {
        let mut guard = state.lock().expect("state mutex");
        guard.submit_ask(ask, tx);
    }
    match rx.recv() {
        Ok(reply) => waiter_reply_to_daemon_msg(reply),
        // UI dropped the sender without answering (daemon shutting down?).
        // Fail closed.
        Err(_) => DaemonMsg::Decision {
            decision: crate::consent::Decision::Deny,
            secrets: std::collections::HashMap::new(),
        },
    }
}

fn waiter_reply_to_daemon_msg(reply: WaiterReply) -> DaemonMsg {
    match reply {
        WaiterReply::Decision { decision, secrets } => DaemonMsg::Decision { decision, secrets },
        WaiterReply::Err { message } => DaemonMsg::Err { message },
    }
}

#[allow(dead_code)] // Surface for future use (e.g. test helpers).
pub fn socket_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("secreq"));
        }
    }
    Ok(std::env::temp_dir().join(format!("secreq-{}", users_uid())))
}

#[allow(dead_code)]
fn users_uid() -> u32 {
    // SAFETY: getuid() is always safe.
    unsafe { libc::getuid() }
}

/// Stable per-user socket path. Both client and daemon derive it the same
/// way; no env-var handshake needed.
pub fn default_socket_path() -> Result<PathBuf> {
    Ok(socket_dir()?.join("consent.sock"))
}

#[allow(dead_code)]
pub fn pidfile_path() -> Result<PathBuf> {
    Ok(socket_dir()?.join("daemon.pid"))
}

#[allow(dead_code)]
pub fn pidfile_exists(path: &Path) -> bool {
    path.exists()
}
