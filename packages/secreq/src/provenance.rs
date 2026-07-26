//! Provenance: who is asking for these secrets (§8).
//!
//! Before releasing anything, `run` walks the parent process tree so the
//! consent prompt can show the caller chain — process name, pid, and the
//! command line that launched it. This is the "awareness" the design is built
//! around: you see *what is asking* before you allow.

use std::path::Path;

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

/// One process in the caller chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub pid: u32,
    pub name: String,
    /// Best-effort full command line (argv joined with spaces).
    pub command: String,
    /// Absolute path to the executable, if known.
    pub exe: Option<String>,
    /// Process start time as reported by `sysinfo` (seconds since the Unix
    /// epoch). Paired with `pid` it tiebreaks pid recycling: a new process
    /// that inherits a freed pid has a different `start_time`, so any cache
    /// or audit entry keyed on both reliably distinguishes them.
    pub start_time: u64,
}

/// Walk from this process's parent up toward the root, newest first. Our
/// own process is excluded (that's the *callers*, not us) — and so are
/// any other `secreq` processes in the chain, because they're our PTY
/// masters / inner shims, not "who's asking."
///
/// Two depth caps:
/// - `max_chain` is the limit on *useful* (non-self) entries returned.
///   The daemon's approval-cache walk and the consent UI both want to
///   see the user's monitoring app at the top, even when it sits behind
///   a deeply-recursive stack of self-frames.
/// - `max_walk` bounds the raw upward traversal so a pathological tree
///   can't spin forever. We let the walk go further than `max_chain`
///   because self-frames don't count toward it.
pub fn caller_chain() -> Vec<Caller> {
    caller_chain_with_limit(16, 256)
}

fn caller_chain_with_limit(max_chain: usize, max_walk: usize) -> Vec<Caller> {
    let sys = refreshed_system();
    let Ok(self_pid) = sysinfo::get_current_pid() else {
        return Vec::new();
    };
    let my_exe = std::env::current_exe().ok();

    // Start at our parent; the chain is the callers above us.
    let start = sys.process(self_pid).and_then(sysinfo::Process::parent);
    walk(&sys, start, my_exe.as_deref(), max_chain, max_walk)
}

/// Walk the ancestry of `seed_pid` (its parent and up), newest first,
/// excluding secreq self-frames. `seed_pid` itself is the requester and
/// is NOT included — we report who is *behind* it. Used by the SSH agent,
/// where the requester is the socket peer rather than our own parent.
pub fn caller_chain_from_pid(seed_pid: u32) -> Vec<Caller> {
    caller_chain_from_pid_with_limit(seed_pid, 16, 256)
}

fn caller_chain_from_pid_with_limit(
    seed_pid: u32,
    max_chain: usize,
    max_walk: usize,
) -> Vec<Caller> {
    let sys = refreshed_system();
    let my_exe = std::env::current_exe().ok();
    let seed = sysinfo::Pid::from_u32(seed_pid);
    // Start at the seed's parent so the seed itself (the requester) is
    // never included; we report who is behind it.
    let start = sys.process(seed).and_then(sysinfo::Process::parent);
    walk(&sys, start, my_exe.as_deref(), max_chain, max_walk)
}

const TRANSPORT_FRAMES: &[&str] = &["ssh", "scp", "sftp", "ssh-agent"];

/// Shell / session frame names a SIGN grant should anchor on. Login shells
/// are exec'd with a leading `-` (e.g. `-zsh`), which we strip before
/// matching.
const SESSION_FRAMES: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "tcsh",
    "csh",
    "nu",
    "pwsh",
    "powershell",
    "tmux",
    "tmux: server",
    "screen",
];

/// True if `name` is a long-lived shell / session frame (see
/// [`SESSION_FRAMES`]), accounting for the leading `-` on login shells.
fn is_session_frame(name: &str) -> bool {
    let base = name.strip_prefix('-').unwrap_or(name);
    SESSION_FRAMES.contains(&base)
}

/// Pick the long-lived ancestor a SIGN grant should be scoped to.
///
/// A `git push` over SSH spawns a fresh `ssh` **and** a fresh `git` for every
/// push, so anchoring on either gives a timed grant no reuse across pushes —
/// the user would be re-prompted every time. The stable context the user
/// actually drives is their shell (or terminal multiplexer), so we anchor on
/// the nearest session frame. Failing that (GUI/daemon-launched, no shell in
/// the chain) we fall back to the first non-transport frame, then to the last
/// frame if the whole chain is transport.
pub fn select_anchor(chain: &[Caller]) -> Option<&Caller> {
    chain
        .iter()
        .find(|c| is_session_frame(&c.name))
        .or_else(|| {
            chain
                .iter()
                .find(|c| !TRANSPORT_FRAMES.contains(&c.name.as_str()))
        })
        .or_else(|| chain.last())
}

/// The working directory of a single process, best-effort.
///
/// Used by the SSH-agent path, where the requester is a socket peer rather
/// than a wrapped exec: the wrap client reports its own `cwd` in the ask it
/// sends, but a sign request carries no such field, so the daemon reads it
/// off the peer instead. `ssh` inherits its cwd from whatever spawned it,
/// so for a `git push` this is the repository — the fact that distinguishes
/// a push you started from one a script started.
///
/// Deliberately refreshes **only** the target pid rather than reusing
/// [`refreshed_system`]: cwd is an extra per-process syscall, and the chain
/// walk refreshes every process on the machine. Scoping it to one pid keeps
/// that walk exactly as cheap as it was.
///
/// `None` when the process is gone or the platform won't tell us — a cwd we
/// can't read is rendered as absent, never guessed at.
pub fn cwd_for_pid(pid: u32) -> Option<String> {
    let target = sysinfo::Pid::from_u32(pid);
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing().with_cwd(UpdateKind::Always),
    );
    sys.process(target)
        .and_then(|p| p.cwd())
        .map(|p| p.display().to_string())
}

/// A `System` refreshed with the command line and executable path of every
/// process — the data the caller chain renders.
fn refreshed_system() -> System {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::Always)
            .with_exe(UpdateKind::Always),
    );
    sys
}

/// Walk upward from `start` (already the first ancestor to consider),
/// newest first, collecting non-self frames until `max_chain` useful
/// entries or `max_walk` raw steps. Shared by `caller_chain` and
/// `caller_chain_from_pid`.
fn walk(
    sys: &System,
    start: Option<sysinfo::Pid>,
    my_exe: Option<&Path>,
    max_chain: usize,
    max_walk: usize,
) -> Vec<Caller> {
    let mut chain = Vec::new();
    let mut current = start;
    let mut walked = 0usize;
    while let Some(pid) = current {
        if walked >= max_walk || chain.len() >= max_chain {
            break;
        }
        walked += 1;
        let Some(proc) = sys.process(pid) else { break };
        let caller = Caller {
            pid: pid.as_u32(),
            name: proc.name().to_string_lossy().into_owned(),
            command: join_cmd(proc.cmd()),
            exe: proc.exe().map(|p| p.display().to_string()),
            start_time: proc.start_time(),
        };
        // Skip self-frames *during the walk* — they don't count toward
        // `max_chain`. Crucial for deeply-recursive wraps where 15+
        // `secreq gh` PTY masters sit between the wrap and the real
        // ancestor we want to anchor approvals on.
        if !is_self_frame(&caller, my_exe) {
            chain.push(caller);
        }
        current = proc.parent();
    }
    chain
}

/// True if `caller` is a `secreq` process — our own machinery, not a
/// meaningful step in "who's asking." Matched two ways:
/// 1. Caller's `exe` resolves to the same path as our own `current_exe`.
/// 2. Caller's process name is exactly `secreq` (sysinfo's `exe()` can
///    miss for short-lived processes; the name match is a fallback).
fn is_self_frame(caller: &Caller, my_exe: Option<&Path>) -> bool {
    if let (Some(c_exe), Some(my)) = (caller.exe.as_deref().map(Path::new), my_exe) {
        if c_exe == my {
            return true;
        }
    }
    caller.name == "secreq"
}

fn join_cmd(cmd: &[std::ffi::OsString]) -> String {
    cmd.iter()
        .map(|s| s.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mk_caller(pid: u32, name: &str, exe: Option<&str>) -> Caller {
        Caller {
            pid,
            name: name.to_owned(),
            command: name.to_owned(),
            exe: exe.map(std::borrow::ToOwned::to_owned),
            start_time: 0,
        }
    }

    #[test]
    fn caller_chain_excludes_our_own_pid() {
        let chain = caller_chain();
        // Running under cargo/the test harness, there is always at least one
        // ancestor, and none of them is our own pid.
        let me = std::process::id();
        assert!(!chain.is_empty(), "expected at least one ancestor");
        assert!(chain.iter().all(|c| c.pid != me));
    }

    #[test]
    fn chain_from_pid_starts_above_the_given_pid_and_excludes_self_frames() {
        // Our own parent chain, requested explicitly, equals caller_chain().
        let me = std::process::id();
        let explicit = caller_chain_from_pid(me);
        let implicit = caller_chain();
        // Both anchor on our parent; neither contains our own pid.
        assert!(explicit.iter().all(|c| c.pid != me));
        assert_eq!(
            explicit.iter().map(|c| c.pid).collect::<Vec<_>>(),
            implicit.iter().map(|c| c.pid).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn anchor_skips_transport_and_per_command_frames_to_the_shell() {
        // `git push` over SSH spawns a fresh `git` AND a fresh `ssh` for
        // every push, so anchoring on either gives a timed grant no reuse
        // across pushes. The stable context is the shell, so the anchor must
        // land on `zsh`, not `git`.
        let chain = vec![
            mk_caller(10, "ssh", Some("/usr/bin/ssh")),
            mk_caller(11, "git", Some("/usr/bin/git")),
            mk_caller(12, "zsh", Some("/bin/zsh")),
        ];
        let anchor = select_anchor(&chain).unwrap();
        assert_eq!(anchor.name, "zsh");
        assert_eq!(anchor.pid, 12);
    }

    #[test]
    fn anchor_picks_nearest_shell_through_a_deep_chain() {
        // Real-world shape: a CLI tool runs `git push` from inside a login
        // shell. The anchor is the nearest shell (`-zsh`), which survives
        // across pushes, not the ephemeral `git`/`claude` frames.
        let chain = vec![
            mk_caller(10, "ssh", Some("/usr/bin/ssh")),
            mk_caller(11, "git", Some("/usr/bin/git")),
            mk_caller(12, "claude", Some("/usr/local/bin/claude")),
            mk_caller(13, "-zsh", Some("/bin/zsh")),
            mk_caller(14, "login", Some("/usr/bin/login")),
        ];
        let anchor = select_anchor(&chain).unwrap();
        assert_eq!(anchor.name, "-zsh"); // login-shell prefix still matches
        assert_eq!(anchor.pid, 13);
    }

    #[test]
    fn anchor_falls_back_to_first_non_transport_when_no_shell() {
        // GUI/daemon-launched with no shell in the chain: there's no stable
        // session to anchor on, so fall back to the first non-transport
        // frame (here `git`) rather than the transport peer.
        let chain = vec![
            mk_caller(10, "ssh", None),
            mk_caller(11, "scp", None),
            mk_caller(12, "git", Some("/usr/bin/git")),
        ];
        assert_eq!(select_anchor(&chain).unwrap().name, "git");
    }

    #[test]
    fn anchor_falls_through_to_last_when_all_transport() {
        let chain = vec![mk_caller(10, "ssh", None), mk_caller(11, "scp", None)];
        assert_eq!(select_anchor(&chain).unwrap().name, "scp");
    }

    #[test]
    fn anchor_is_none_for_empty_chain() {
        assert!(select_anchor(&[]).is_none());
    }

    #[test]
    fn is_self_frame_matches_by_exe_path() {
        let my = PathBuf::from("/usr/local/bin/secreq");
        let caller = mk_caller(100, "secreq", Some("/usr/local/bin/secreq"));
        assert!(is_self_frame(&caller, Some(&my)));

        let other = mk_caller(101, "gh", Some("/opt/homebrew/bin/gh"));
        assert!(!is_self_frame(&other, Some(&my)));
    }

    #[test]
    fn is_self_frame_falls_back_to_name_when_exe_is_missing() {
        // sysinfo's `exe()` returns None for some short-lived processes
        // on macOS. The name match is the safety net.
        let my = PathBuf::from("/usr/local/bin/secreq");
        let no_exe = mk_caller(100, "secreq", None);
        assert!(is_self_frame(&no_exe, Some(&my)));

        let other_no_exe = mk_caller(101, "node", None);
        assert!(!is_self_frame(&other_no_exe, Some(&my)));
    }

    #[test]
    fn is_self_frame_handles_missing_my_exe_gracefully() {
        // If we couldn't resolve our own exe, fall back to name match.
        let secreq = mk_caller(100, "secreq", Some("/some/path"));
        assert!(is_self_frame(&secreq, None));
        let other = mk_caller(101, "bash", Some("/bin/bash"));
        assert!(!is_self_frame(&other, None));
    }
}
