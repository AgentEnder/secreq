//! Provenance: who is asking for these secrets (§8).
//!
//! Before releasing anything, `run` walks the parent process tree so the
//! consent prompt can show the caller chain — process name, pid, and the
//! command line that launched it. This is the "awareness" the design is built
//! around: you see *what is asking* before you allow.

use std::path::Path;

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

/// Longest a rendered process name or command line may be.
///
/// A command line is unbounded, and the consent prompt's caller tree lays each
/// one out in a scrolling body. An argv of a few thousand characters scrolls
/// the genuine frames and the `IN <cwd>` row out of the initial viewport,
/// which is a cheap way to make the prompt say less than it appears to.
const MAX_DISPLAY_CHARS: usize = 300;

/// True for a character that renders as nothing, or that reorders what
/// follows it.
///
/// `char::is_control` covers only Unicode category Cc. The bidi overrides and
/// isolates and the zero-width formatting characters are category Cf, and they
/// are the ones that make a rendered string differ from the string that was
/// read.
pub fn is_invisible_or_reordering(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200B}'..='\u{200F}'   // zero-width space/joiners, LRM, RLM
            | '\u{202A}'..='\u{202E}' // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{FEFF}'              // BOM / zero-width no-break space
        )
}

/// Make one process-supplied string safe to render and to match on.
///
/// A process picks its own `comm` and argv, and both are rendered in the
/// consent prompt — the surface whose entire job is telling the user
/// accurately who is asking. Two things a raw string can do there:
///
/// - **A newline becomes a row.** The caller tree lays each name out in its
///   own label, and a label given `"node\n└ zsh"` renders *two* rows of bold
///   text in the name column: the attacker's frame plus a fabricated ancestor
///   the user reads as real. Whitespace runs are collapsed to single spaces,
///   so a name occupies exactly one row.
/// - **A bidi override reverses what follows it.** Trojan-Source in a widget
///   the user is reading to make a security decision.
///
/// Sanitized here, at the walk, rather than at each render site: there are
/// several (the prompt tree, the audit view, the SSH title), and the audit log
/// keeps these strings for later reading too.
fn sanitize_display(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_DISPLAY_CHARS));
    let mut last_was_space = false;
    for c in raw.chars() {
        // Whitespace first, and deliberately before the invisible-character
        // filter: a newline is category Cc, so filtering it as "invisible"
        // would *delete* it and silently join the tokens it separated
        // (`"node\n└ zsh"` → `"node└ zsh"`). Turning it into a space keeps the
        // name to one row while still showing the reader two tokens.
        if c.is_whitespace() {
            if !last_was_space && !out.is_empty() {
                out.push(' ');
                last_was_space = true;
            }
            continue;
        }
        if is_invisible_or_reordering(c) {
            continue;
        }
        last_was_space = false;
        out.push(c);
        if out.chars().count() >= MAX_DISPLAY_CHARS {
            out.push('…');
            break;
        }
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

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

/// Limit on *useful* (non-self) entries a walk returns. The daemon's
/// approval-cache walk and the consent UI both want to see the user's
/// monitoring app at the top, even when it sits behind a deeply-recursive
/// stack of self-frames.
const MAX_CHAIN: usize = 16;

/// Bound on the raw upward traversal, so a pathological tree can't spin
/// forever. Deliberately further than [`MAX_CHAIN`], because self-frames
/// don't count toward that one.
const MAX_WALK: usize = 256;

/// An ancestry as far as the walk got, and whether that was all of it.
///
/// The two halves are separate facts and the second one is the security-
/// relevant one. `frames` is a *suffix* of the real ancestry — nearest-first
/// storage means the frames given up are the outermost, the ones that answer
/// "where did this ultimately come from". A consumer holding only `frames`
/// cannot tell a chain that ended at its root from one the walk abandoned at
/// [`MAX_CHAIN`], and the consent prompt spent both of those cases rendering
/// its topmost row as though it were the origin.
pub struct CallerChain {
    /// The frames the walk collected, nearest-first.
    pub frames: Vec<Caller>,
    /// True when the walk stopped at its own ceiling with an unread ancestor
    /// still above `frames`' last entry.
    ///
    /// False when the walk ran out of ancestry — reached a process with no
    /// parent — which is the only way to know the outermost frame really is
    /// the outermost one.
    pub truncated: bool,
}

/// Walk from this process's parent up toward the root, newest first. Our
/// own process is excluded (that's the *callers*, not us) — and so are
/// any other `secreq` processes in the chain, because they're our PTY
/// masters / inner shims, not "who's asking."
///
/// This is the **client** entry point. A client's chain never reaches the
/// consent prompt — the daemon throws it away and re-walks from the socket
/// peer (`daemon::server::adopt_peer_provenance`), because a client's account
/// of its own ancestry is a claim rather than a fact — but it *is* what the
/// client writes into its own **audit row**, and the audit view renders that
/// chain back months later. So the truncation bit travels with the frames
/// here for the same reason it does in [`caller_chain_from_pid`]: a suffix of
/// an ancestry and a whole one are drawn identically unless something says
/// which of the two this is.
pub fn caller_chain() -> CallerChain {
    caller_chain_with_limit(MAX_CHAIN, MAX_WALK)
}

fn caller_chain_with_limit(max_chain: usize, max_walk: usize) -> CallerChain {
    let sys = refreshed_system();
    let Ok(self_pid) = sysinfo::get_current_pid() else {
        return CallerChain {
            frames: Vec::new(),
            truncated: false,
        };
    };
    let my_exe = std::env::current_exe().ok();

    // Start at our parent; the chain is the callers above us.
    let start = sys.process(self_pid).and_then(sysinfo::Process::parent);
    walk(&sys, start, my_exe.as_deref(), max_chain, max_walk)
}

/// Walk the ancestry of `seed_pid` (its parent and up), newest first,
/// excluding secreq self-frames. `seed_pid` itself is the requester and
/// is NOT included — we report who is *behind* it. Used by the SSH agent
/// and by the daemon's peer-provenance adoption, where the requester is the
/// socket peer rather than our own parent.
pub fn caller_chain_from_pid(seed_pid: u32) -> CallerChain {
    caller_chain_from_pid_with_limit(seed_pid, MAX_CHAIN, MAX_WALK)
}

fn caller_chain_from_pid_with_limit(
    seed_pid: u32,
    max_chain: usize,
    max_walk: usize,
) -> CallerChain {
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

/// The identity to match a frame against, preferring the kernel's record.
///
/// The same trust split [`is_self_frame`] documents, applied to the other
/// predicate that reads a frame's identity. `exe`'s file name is what the
/// kernel loaded; `name` is `comm`, which the process chose. Fall back to
/// `name` only when the kernel won't tell us — for a short-lived process
/// sysinfo can't resolve, it is all there is.
///
/// Returned rather than compared here because both [`SESSION_FRAMES`] and
/// [`TRANSPORT_FRAMES`] have to ask the same question of the same string:
/// answering it two different ways is how one of them ends up trusting a
/// name the other doesn't.
fn frame_identity(caller: &Caller) -> &str {
    caller
        .exe
        .as_deref()
        .map(Path::new)
        .and_then(Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or(&caller.name)
}

/// True if `caller` is a long-lived shell / session frame (see
/// [`SESSION_FRAMES`]).
///
/// Matched on [`frame_identity`], not on `name`. This predicate picks the
/// process a 30-minute SSH grant binds to, so a process that could put
/// itself here by taking the name `zsh` would get the grant the user
/// believed they were giving their terminal — and keep it after the
/// terminal is gone.
///
/// Both spellings still have to match, which is why the name fallback is
/// consulted as well as stripped: login shells are exec'd with a leading `-`
/// (`-zsh`), and tmux's server sets `comm` to `tmux: server` while its `exe`
/// is a plain `tmux`.
fn is_session_frame(caller: &Caller) -> bool {
    let ident = frame_identity(caller);
    let base = ident.strip_prefix('-').unwrap_or(ident);
    SESSION_FRAMES.contains(&base)
}

/// True if `caller` is an SSH-family transport frame — ephemeral, per-command
/// plumbing rather than a session worth anchoring on.
///
/// Matched on [`frame_identity`] for the same reason as [`is_session_frame`],
/// and the reason cuts both ways: a process that names itself `ssh` must not
/// be able to skip itself out of the fallback anchor, and a real `ssh` must
/// not be able to rename itself into it.
fn is_transport_frame(caller: &Caller) -> bool {
    TRANSPORT_FRAMES.contains(&frame_identity(caller))
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
///
/// Both predicates read [`frame_identity`] rather than the self-reported
/// `name`. What this function returns is what a session grant is scoped to,
/// so a process able to nominate itself by renaming could collect the user's
/// 30-minute approval on its own behalf.
pub fn select_anchor(chain: &[Caller]) -> Option<&Caller> {
    chain
        .iter()
        .find(|c| is_session_frame(c))
        .or_else(|| chain.iter().find(|c| !is_transport_frame(c)))
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
///
/// Stopping at either ceiling sets [`CallerChain::truncated`], because in
/// both cases `current` is still a live pid we chose not to read. Running out
/// of ancestry does not: the loop condition fails, and a process with no
/// parent is genuinely the top.
///
/// A frame `sysinfo` cannot resolve mid-walk (`sys.process(pid)` returning
/// `None` — a process that exited between the refresh and here) also stops
/// the walk, and deliberately does *not* set the flag. That is a different
/// fact from "we declined to look further", and a race a reader can do
/// nothing about is not worth putting a permanent row on the prompt for.
fn walk(
    sys: &System,
    start: Option<sysinfo::Pid>,
    my_exe: Option<&Path>,
    max_chain: usize,
    max_walk: usize,
) -> CallerChain {
    let mut frames = Vec::new();
    let mut current = start;
    let mut walked = 0usize;
    while let Some(pid) = current {
        if walked >= max_walk || frames.len() >= max_chain {
            return CallerChain {
                frames,
                truncated: true,
            };
        }
        walked += 1;
        let Some(proc) = sys.process(pid) else { break };
        let caller = Caller {
            pid: pid.as_u32(),
            name: sanitize_display(&proc.name().to_string_lossy()),
            command: sanitize_display(&join_cmd(proc.cmd())),
            exe: proc.exe().map(|p| p.display().to_string()),
            start_time: proc.start_time(),
        };
        // Skip self-frames *during the walk* — they don't count toward
        // `max_chain`. Crucial for deeply-recursive wraps where 15+
        // `secreq gh` PTY masters sit between the wrap and the real
        // ancestor we want to anchor approvals on.
        if !is_self_frame(&caller, my_exe) {
            frames.push(caller);
        }
        current = proc.parent();
    }
    CallerChain {
        frames,
        truncated: false,
    }
}

/// True if `caller` is a `secreq` process — our own machinery, not a
/// meaningful step in "who's asking."
///
/// A self-frame is *dropped from the chain entirely*, so this predicate
/// decides who the consent prompt does not show. That makes it a security
/// boundary, and the two inputs are not equally trustworthy:
///
/// - `exe` is the kernel's record of what was loaded. When we know both
///   sides, it is authoritative and a **mismatch is a mismatch** — whatever
///   the process calls itself.
/// - `name` is `comm`, which a process controls: one `prctl(PR_SET_NAME)` on
///   Linux, or simply a binary named `secreq` on macOS. It is used *only*
///   when `exe` is unavailable (sysinfo can't resolve it for some
///   short-lived processes), because then it is all we have.
///
/// Consulting `name` after a failed `exe` comparison — rather than only in
/// its absence — would let any process erase itself from the prompt by taking
/// our name, leaving its own parent rendered as the immediate caller.
fn is_self_frame(caller: &Caller, my_exe: Option<&Path>) -> bool {
    match (caller.exe.as_deref().map(Path::new), my_exe) {
        (Some(caller_exe), Some(mine)) => caller_exe == mine,
        _ => caller.name == "secreq",
    }
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
        let chain = caller_chain().frames;
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
        let explicit = caller_chain_from_pid(me).frames;
        let implicit = caller_chain().frames;
        // Both anchor on our parent; neither contains our own pid.
        assert!(explicit.iter().all(|c| c.pid != me));
        assert_eq!(
            explicit.iter().map(|c| c.pid).collect::<Vec<_>>(),
            implicit.iter().map(|c| c.pid).collect::<Vec<_>>(),
        );
    }

    /// The fact the consent prompt could not previously state: a chain that
    /// stops at the walk's ceiling is a *suffix* of the ancestry, and the
    /// frame it ends on is not the origin. Without this bit the prompt draws
    /// that frame as its top row and the reader has no way to tell.
    #[test]
    fn a_chain_that_hit_the_ceiling_says_so() {
        let me = std::process::id();
        // Under any test runner there is at least a cargo process and a shell
        // above us, so a ceiling of one frame is guaranteed to be short.
        let clipped = caller_chain_from_pid_with_limit(me, 1, MAX_WALK);
        assert_eq!(clipped.frames.len(), 1);
        assert!(
            clipped.truncated,
            "a walk that stopped at its own limit must admit it"
        );
    }

    /// The mirror image, and the reason the bit is worth carrying: a walk
    /// that reached a process with no parent has seen the whole ancestry, and
    /// saying "there may be more above" there would be the prompt inventing a
    /// doubt of its own.
    #[test]
    fn a_chain_that_reached_the_top_does_not_claim_to_be_short() {
        // Ceilings far past anything a real process tree reaches, so the only
        // way out of the loop is running out of ancestors.
        let me = std::process::id();
        let full = caller_chain_from_pid_with_limit(me, 4096, 4096);
        assert!(
            !full.truncated,
            "walked {} frames to the root and still reported truncation",
            full.frames.len()
        );
    }

    /// The raw-step ceiling is the other way out of the loop, and it means the
    /// same thing to a reader: we stopped, something is still above.
    #[test]
    fn the_raw_walk_ceiling_counts_as_truncation_too() {
        let me = std::process::id();
        let clipped = caller_chain_from_pid_with_limit(me, MAX_CHAIN, 1);
        assert!(clipped.truncated);
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
    fn anchor_ignores_a_shell_name_a_process_picked_for_itself() {
        // The attacker sits between the shell and `git` and calls itself
        // `zsh`. Nearest-first selection would hand it the anchor, so the
        // user's "Approve for 30 min" would bind a signing grant to the
        // attacker's process instead of to their terminal. `exe` says what
        // was actually loaded, and it is not a shell.
        let chain = vec![
            mk_caller(10, "ssh", Some("/usr/bin/ssh")),
            mk_caller(11, "git", Some("/usr/bin/git")),
            mk_caller(12, "zsh", Some("/tmp/.hidden/payload")),
            mk_caller(13, "-zsh", Some("/bin/zsh")),
        ];
        let anchor = select_anchor(&chain).unwrap();
        assert_eq!(
            anchor.pid, 13,
            "anchor must be the real shell, not the liar"
        );
    }

    #[test]
    fn anchor_finds_a_shell_that_renamed_itself() {
        // The mirror image, and the reason the fix is a preference rather
        // than an extra condition: a real `/bin/bash` that set its own
        // `comm` to something else is still the session the user drives.
        let chain = vec![
            mk_caller(20, "git", Some("/usr/bin/git")),
            mk_caller(21, "my-terminal", Some("/bin/bash")),
        ];
        assert_eq!(select_anchor(&chain).unwrap().pid, 21);
    }

    #[test]
    fn transport_frames_are_recognized_by_exe_too() {
        // The transport skip is the other half of the same trust question.
        // A process that names itself `ssh` must not be able to skip itself
        // out of the fallback anchor, and a real `ssh` must not be able to
        // rename itself into it.
        let liar = vec![
            mk_caller(30, "ssh", Some("/tmp/.hidden/payload")),
            mk_caller(31, "git", Some("/usr/bin/git")),
        ];
        assert_eq!(
            select_anchor(&liar).unwrap().pid,
            30,
            "a non-ssh binary calling itself ssh is not a transport frame"
        );

        let hider = vec![
            mk_caller(40, "definitely-not-ssh", Some("/usr/bin/ssh")),
            mk_caller(41, "git", Some("/usr/bin/git")),
        ];
        assert_eq!(
            select_anchor(&hider).unwrap().pid,
            41,
            "a real ssh stays a transport frame whatever it calls itself"
        );
    }

    #[test]
    fn tmux_server_is_a_session_frame_by_either_spelling() {
        // tmux renames itself to `tmux: server`; its exe is plain `tmux`.
        // Both spellings have to keep working, because dropping either one
        // re-prompts every `git push` inside a multiplexer.
        let named = vec![
            mk_caller(50, "git", Some("/usr/bin/git")),
            mk_caller(51, "tmux: server", None),
        ];
        assert_eq!(select_anchor(&named).unwrap().pid, 51);

        let by_exe = vec![
            mk_caller(60, "git", Some("/usr/bin/git")),
            mk_caller(61, "tmux: server", Some("/opt/homebrew/bin/tmux")),
        ];
        assert_eq!(select_anchor(&by_exe).unwrap().pid, 61);
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

    /// `name` is `comm`, which the process itself controls. A caller whose
    /// `exe` is known and is *not* ours must stay in the chain no matter what
    /// it calls itself — otherwise anything could erase itself from the
    /// consent prompt by taking our name, and the prompt would render that
    /// process's parent as the immediate caller.
    #[test]
    fn a_foreign_exe_named_secreq_is_not_a_self_frame() {
        let my = PathBuf::from("/usr/local/bin/secreq");
        let impostor = mk_caller(999, "secreq", Some("/tmp/evil/payload"));
        assert!(!is_self_frame(&impostor, Some(&my)));
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

    /// The caller tree lays each name out in its own label, so a newline in a
    /// process name renders as an extra *row* — the attacker's frame plus a
    /// fabricated ancestor the user reads as real. A process picks its own
    /// `comm`, so this is a name it can simply choose.
    #[test]
    fn a_newline_in_a_process_name_cannot_become_a_second_row() {
        let forged = sanitize_display("node\n└ zsh");
        assert!(!forged.contains('\n'), "{forged:?}");
        assert_eq!(forged, "node └ zsh");
    }

    /// Trojan-Source in the widget the user is reading to make a security
    /// decision. `char::is_control` is category Cc only and misses these.
    #[test]
    fn bidi_and_zero_width_characters_are_stripped() {
        for bad in ['\u{202E}', '\u{200B}', '\u{2066}', '\u{FEFF}'] {
            let out = sanitize_display(&format!("gh{bad}api"));
            assert!(!out.contains(bad), "{bad:?} survived: {out:?}");
        }
    }

    /// An argv is unbounded, and the prompt's body scrolls: a long enough one
    /// pushes the genuine frames and the cwd row out of the initial viewport.
    #[test]
    fn an_overlong_command_is_truncated() {
        let out = sanitize_display(&"A".repeat(5_000));
        assert!(
            out.chars().count() <= MAX_DISPLAY_CHARS + 1,
            "{}",
            out.chars().count()
        );
        assert!(out.ends_with('…'));
    }

    /// Ordinary command lines must survive intact — this runs on every frame
    /// of every ask, and mangling them would make the prompt less accurate,
    /// not more.
    #[test]
    fn an_ordinary_command_line_is_unchanged() {
        assert_eq!(
            sanitize_display("/Applications/Cursor.app/Contents/MacOS/Cursor --psn_0_12345"),
            "/Applications/Cursor.app/Contents/MacOS/Cursor --psn_0_12345"
        );
        assert_eq!(sanitize_display("-zsh"), "-zsh");
        // Runs of whitespace collapse, which is what keeps a name to one row.
        assert_eq!(sanitize_display("gh   api"), "gh api");
    }
}
