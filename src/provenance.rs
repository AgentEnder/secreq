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
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::Always)
            .with_exe(UpdateKind::Always),
    );

    let mut chain = Vec::new();
    let Ok(self_pid) = sysinfo::get_current_pid() else {
        return chain;
    };
    let my_exe = std::env::current_exe().ok();

    // Start at our parent; the chain is the callers above us.
    let mut current = sys.process(self_pid).and_then(|p| p.parent());
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
        if !is_self_frame(&caller, my_exe.as_deref()) {
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
            exe: exe.map(|s| s.to_owned()),
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
