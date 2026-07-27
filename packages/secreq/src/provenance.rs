//! Provenance: who is asking for these secrets (§8).
//!
//! Before releasing anything, `run` walks the parent process tree so the
//! consent prompt can show the caller chain — process name, pid, and the
//! command line that launched it. This is the "awareness" the design is built
//! around: you see *what is asking* before you allow.

use std::path::Path;

use serde::{Deserialize, Serialize};
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
/// This is asked of every string a *process* picks for itself and every string
/// a *guest* claims, at the only place either becomes something a human reads
/// to make a security decision. So the bar is not "looks odd" but "present in
/// the string and absent from its rendering".
///
/// ## Why this asks a library instead of listing code points
///
/// It used to be a hand-written list of five ranges, and two audits found it
/// short: first the bidi controls and zero-width characters (category Cf, which
/// `char::is_control` — exactly category Cc — does not cover), then `U+061C`
/// ARABIC LETTER MARK, `U+00AD` SOFT HYPHEN, `U+180E`, the interlinear
/// annotation characters and the whole tag block. Every one of those is Cf. The
/// list was never wrong about what it named; it was a person recalling which
/// code points are format characters, and that is a question the UCD answers
/// exactly. `unicode_general_category` answers it from generated tables, so a
/// code point Unicode classifies as Cf cannot be missing from this predicate
/// without the crate itself being wrong.
///
/// ## What is still named by hand, and why that part is stable
///
/// Cc and Cf leave a residue: the characters that are
/// `Default_Ignorable_Code_Point` — Unicode's own name for "a conforming
/// renderer shows nothing" — but fall in some other category. No crate in this
/// tree exposes that property, so those are enumerated below. They are not the
/// kind of list that drifts: each is a closed allocation Unicode does not extend
/// (the variation selectors fill their space, the tag block is a fixed,
/// deprecated block, the fillers and the Mongolian selectors are frozen), and
/// the reserved holes inside them are *permanently* reserved as ignorable,
/// which is why the plane-14 range is matched whole rather than by assignment.
///
/// Category Cn is deliberately *not* rejected wholesale. It would sweep the
/// reserved ignorables in, but it would also reject every code point assigned
/// after the table's Unicode 16 — turning a stale dependency into mangled
/// process names for real users.
pub fn is_invisible_or_reordering(c: char) -> bool {
    use unicode_general_category::{get_general_category, GeneralCategory};

    // Cc is the C0/C1 controls, Cf the format characters: the bidi overrides
    // and isolates, the zero-width space and joiners, the soft hyphen, the
    // interlinear annotation marks, the language tag.
    if matches!(
        get_general_category(c),
        GeneralCategory::Control | GeneralCategory::Format
    ) {
        return true;
    }

    matches!(c,
        '\u{034F}'                // combining grapheme joiner (Mn)
        | '\u{115F}'..='\u{1160}' // Hangul choseong/jungseong filler (Lo)
        | '\u{17B4}'..='\u{17B5}' // Khmer inherent vowels AQ/AA (Mn)
        | '\u{180B}'..='\u{180D}' // Mongolian free variation selectors 1-3 (Mn)
        | '\u{180F}'              // Mongolian free variation selector 4 (Mn)
        | '\u{2065}'              // reserved, permanently ignorable (Cn)
        | '\u{3164}'              // Hangul filler (Lo) — renders as blank width
        | '\u{FE00}'..='\u{FE0F}' // variation selectors 1-16 (Mn)
        | '\u{FFA0}'              // halfwidth Hangul filler (Lo)
        | '\u{FFF0}'..='\u{FFF8}' // reserved, permanently ignorable (Cn)
        // Plane 14 whole: the language tag and tag characters (Cf), the
        // variation selectors 17-256 (Mn), and the reserved holes between them
        // (Cn) — every code point in `E0000..=E0FFF` is default-ignorable. The
        // tag block is how "invisible instructions" are smuggled into a string
        // that reads as plain ASCII.
        | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Every class of character [`is_invisible_or_reordering`] must reject, named,
/// with one representative from each.
///
/// Shared by the provenance and `scoped_agent` test modules so the two sanitizers
/// are held to one table rather than to two lists that drift apart — which is
/// how `scoped_agent` came to have its own copy of the predicate in the first
/// place.
///
/// A hand-written range list has now been audited twice and been found short
/// both times. The table is the durable half of the fix: a class nobody thought
/// of is a *failing test naming it*, not a finding in the next audit.
#[cfg(test)]
pub(crate) const INVISIBLE_OR_REORDERING_CLASSES: &[(&str, char)] = &[
    ("C0 control (BEL)", '\u{0007}'),
    ("ANSI escape introducer", '\u{001B}'),
    ("C1 control (DCS)", '\u{0090}'),
    ("soft hyphen", '\u{00AD}'),
    ("combining grapheme joiner", '\u{034F}'),
    ("Arabic number sign", '\u{0600}'),
    ("Arabic letter mark (bidi)", '\u{061C}'),
    ("Hangul choseong filler", '\u{115F}'),
    ("Khmer vowel inherent AQ", '\u{17B4}'),
    ("Mongolian free variation selector one", '\u{180B}'),
    ("Mongolian vowel separator", '\u{180E}'),
    ("zero width space", '\u{200B}'),
    ("zero width joiner", '\u{200D}'),
    ("right-to-left mark", '\u{200F}'),
    ("right-to-left override (bidi)", '\u{202E}'),
    ("word joiner", '\u{2060}'),
    ("reserved default-ignorable (U+2065)", '\u{2065}'),
    ("left-to-right isolate (bidi)", '\u{2066}'),
    ("Hangul filler", '\u{3164}'),
    ("variation selector-1", '\u{FE00}'),
    ("variation selector-16", '\u{FE0F}'),
    ("byte order mark / zero width no-break space", '\u{FEFF}'),
    ("halfwidth Hangul filler", '\u{FFA0}'),
    ("reserved default-ignorable (U+FFF0)", '\u{FFF0}'),
    ("interlinear annotation anchor", '\u{FFF9}'),
    ("interlinear annotation terminator", '\u{FFFB}'),
    ("shorthand format letter overlap", '\u{1BCA0}'),
    ("musical symbol begin beam", '\u{1D173}'),
    ("tag block: reserved head", '\u{E0000}'),
    ("tag block: language tag", '\u{E0001}'),
    ("tag block: tag latin small letter a", '\u{E0061}'),
    ("tag block: cancel tag", '\u{E007F}'),
    ("variation selector-17", '\u{E0100}'),
    ("variation selector-256", '\u{E01EF}'),
];

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

/// Which process this is, in the only way that survives pid recycling.
///
/// A bare pid is not an identity: the kernel hands a freed one to whatever
/// starts next, and every cache in this codebase is keyed on "may this
/// process have that secret". Pairing the pid with the process's start time
/// closes that — a new process on a recycled pid started later, so it cannot
/// match an approval stored for the process that is gone.
///
/// It exists as a type because the pair used to be spelled five different
/// ways (`pid`/`start_time` in one struct, `ppid`/`parent_start_time` in the
/// next), which forced every comparison to be written out by hand:
///
/// ```ignore
/// e.wrap == wrap && e.ppid == scope.pid && e.parent_start_time == scope.start_time
/// ```
///
/// Dropping one conjunct there is a cache-scope escape, and nothing but
/// review stood between that line and a wrong one. `PartialEq` is derived, so
/// the comparison is `e.parent == parent` and there is no conjunct to drop.
/// `Copy` because it is two integers and threading it should never be a
/// borrow question. Serializable because the prompt window is a child
/// process: the scope a decision is remembered at crosses that socket, and it
/// should cross as one value rather than as two fields a reader has to pair
/// back up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// Start time as `sysinfo` reports it (seconds since the Unix epoch).
    pub start_time: u64,
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
    /// epoch). Paired with `pid` it tiebreaks pid recycling; read that pair
    /// through [`Caller::identity`] rather than field by field.
    pub start_time: u64,
}

impl Caller {
    /// This frame's [`ProcessIdentity`] — the one way to make the pair out of
    /// a frame, so a site that means "this process" cannot accidentally take
    /// the pid and leave the start time behind.
    pub fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            start_time: self.start_time,
        }
    }
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
///
/// **This is the fallback, not the whole rule.** When agent forwarding is in
/// play the shell is the wrong subject entirely — see [`select_sign_anchor`],
/// which is what the SSH path calls.
pub fn select_anchor(chain: &[Caller]) -> Option<&Caller> {
    chain
        .iter()
        .find(|c| is_session_frame(c))
        .or_else(|| chain.iter().find(|c| !is_transport_frame(c)))
        .or_else(|| chain.last())
}

// ── Agent forwarding ──────────────────────────────────────────────────────

/// Single-letter `ssh` options that take no value.
///
/// Needed to read a combined cluster (`-tA`) without mistaking an option's
/// *value* for a flag: `-i` takes a path, so `-iA` names a key file called
/// `A` and has nothing to do with agent forwarding. Lowercase `a` is in the
/// list because it is a real valueless flag — but it *disables* forwarding,
/// which is why the search below looks for `A` specifically.
const SSH_VALUELESS_FLAGS: &str = "46AaCfGgKMNnqsTtVvXxYy";

/// `ForwardAgent` values that mean "forwarding may happen".
///
/// `ask` is included on purpose: OpenSSH prompts and then forwards, so from
/// secreq's side that is still a session which may serve a remote's
/// signatures.
const FORWARD_AGENT_AFFIRMATIVE: &[&str] = &["yes", "true", "1", "ask"];

/// True when this command line asks `ssh` to forward the agent.
///
/// The one signal available from the daemon's position. A forwarded sign
/// arrives on `agent.sock` from the local `ssh` client exactly as a local
/// `git push`'s does — same peer, same protocol, same chain shape — so the
/// kernel cannot tell the two apart. What *can* be read is whether the `ssh`
/// process behind the socket asked for forwarding in the first place.
///
/// **What this cannot see**, and it matters:
///
/// - `ForwardAgent yes` in `~/.ssh/config` (including under `Host *`), or in
///   a file named by `-F`. None of that reaches argv, so a user who turns
///   forwarding on globally in config still gets a shell-anchored grant.
///   Reading their ssh_config is not on the table: it would mean
///   reimplementing `Match` / `Include` / token expansion to second-guess a
///   process that has already made its own decision.
/// - Whether forwarding was *used*. An `ssh -A` nobody signs through is
///   still detected; the grant simply binds to a narrower subject than it
///   used to.
///
/// Which is why argv is *read* rather than *trusted*. The two ways this can
/// be wrong are "a command line mentions forwarding when nothing is
/// forwarded" (the grant gets narrower — harmless) and "forwarding is on and
/// argv doesn't say" (the grant stays exactly as wide as it is today — no
/// worse than the bug this closes). Neither direction lets a caller *widen* a
/// grant by choosing what it says, which is the property that matters: `-A`
/// in a process's own argv can only cost that process reuse, never buy it
/// reach.
///
/// Takes the joined command line rather than an argv slice so a chain frame
/// (which only ever kept the joined form) and a freshly-read peer are asked
/// the same question by the same code. Splitting on `=` as well as whitespace
/// folds `-oForwardAgent=yes`, `-o ForwardAgent=yes` and
/// `-o "ForwardAgent yes"` into one shape.
pub fn requests_agent_forwarding(command: &str) -> bool {
    let mut tokens = command
        .split(|c: char| c.is_whitespace() || c == '=')
        .filter(|t| !t.is_empty())
        .peekable();
    while let Some(token) = tokens.next() {
        if token == "-A" {
            return true;
        }
        let option = token.strip_prefix("-o").unwrap_or(token);
        if option.eq_ignore_ascii_case("ForwardAgent") {
            if tokens.peek().is_some_and(|value| {
                FORWARD_AGENT_AFFIRMATIVE.contains(&value.to_ascii_lowercase().as_str())
            }) {
                return true;
            }
            continue;
        }
        if is_valueless_cluster_forwarding_the_agent(token) {
            return true;
        }
    }
    false
}

/// True for a bundle of valueless short flags containing `A` (`-tA`, `-4At`).
/// Anything with a value-taking flag ahead of the `A` is rejected, because
/// what follows such a flag is its argument rather than another flag.
fn is_valueless_cluster_forwarding_the_agent(token: &str) -> bool {
    let Some(flags) = token.strip_prefix('-') else {
        return false;
    };
    !flags.is_empty()
        && flags.contains('A')
        && flags.chars().all(|c| SSH_VALUELESS_FLAGS.contains(c))
}

/// One process the walk did not collect, read on its own.
///
/// A caller chain deliberately starts at its seed's *parent* — it answers
/// "who is behind this request" — which leaves the requester itself
/// undescribed. For a sign that requester is the local `ssh` client, and it
/// is the only frame that knows whether the agent is being forwarded, so the
/// SSH path reads it directly.
#[derive(Debug, Clone)]
pub struct PeerProcess {
    /// The peer described the way a chain frame is: sanitized name, capped
    /// command line, kernel-reported `exe`.
    pub caller: Caller,
    /// Whether this process's command line asks for agent forwarding.
    ///
    /// Computed from the **raw** argv, not from `caller.command`, which
    /// [`sanitize_display`] caps at [`MAX_DISPLAY_CHARS`] for the prompt's
    /// benefit. What a grant binds to must not depend on a display budget.
    pub forwards_agent: bool,
}

/// Read one process without walking its ancestry.
///
/// Refreshes only the target pid, for the same reason [`cwd_for_pid`] does:
/// the chain walk refreshes every process on the machine, and asking about
/// one more process should not cost a second sweep.
///
/// `None` when the process is gone or the platform will not say — every
/// caller treats that as "we could not establish this", never as a default.
pub fn describe_pid(pid: u32) -> Option<PeerProcess> {
    let target = sysinfo::Pid::from_u32(pid);
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::Always)
            .with_exe(UpdateKind::Always),
    );
    let proc = sys.process(target)?;
    let raw_command = join_cmd(proc.cmd());
    Some(PeerProcess {
        caller: Caller {
            pid,
            name: sanitize_display(&proc.name().to_string_lossy()),
            command: sanitize_display(&raw_command),
            exe: proc.exe().map(|p| p.display().to_string()),
            start_time: proc.start_time(),
        },
        forwards_agent: requests_agent_forwarding(&raw_command),
    })
}

/// Why a sign grant is bound to the frame it is bound to.
///
/// Serializable because it rides [`crate::daemon::proto::SshAnchorInfo`] to
/// the prompt: the two anchors mean different things to the person reading
/// the window, so the window has to say which one it is offering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignAnchorKind {
    /// The long-lived shell / multiplexer the signing hangs off — the
    /// ordinary case, and what [`select_anchor`] picks.
    #[default]
    Session,
    /// An `ssh` client that asked for agent forwarding. The grant binds to
    /// that client, so it dies with the SSH session rather than with the
    /// terminal the session was launched from.
    ForwardedSsh,
}

/// The frame a sign grant binds to, in the terms the prompt needs to name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignAnchor {
    /// What the grant keys on. A [`ProcessIdentity`], not a bare pid: a grant
    /// that survived pid recycling would be a 30-minute signing window handed
    /// to whatever started next.
    pub identity: ProcessIdentity,
    /// The frame's sanitized `comm`, as the prompt shows it.
    pub name: String,
    /// The frame's command line. Worth carrying only for a forwarding `ssh`
    /// client, which is the socket peer and therefore the one frame the
    /// `ASKED BY` tree does not draw — the prompt has nowhere else to say
    /// which host the agent was handed to.
    pub command: String,
    pub kind: SignAnchorKind,
}

impl SignAnchor {
    fn of(caller: &Caller, kind: SignAnchorKind) -> SignAnchor {
        SignAnchor {
            identity: caller.identity(),
            name: caller.name.clone(),
            command: caller.command.clone(),
            kind,
        }
    }
}

/// Pick the process a SIGN grant should bind to, given the socket peer and
/// the ancestry behind it.
///
/// [`select_anchor`] answers "which frame is the stable session", and for a
/// local `git push` that is right: the `ssh` and the `git` are per-push, the
/// shell is what the user drives. But it makes a grant a property of the
/// **terminal**, and `ssh -A` puts a second party inside that terminal. A
/// user who clicks "Approve for 30 min" during a push has, for the next half
/// hour, also authorized every signature the forwarded host cares to request
/// — silently, headlessly, on their own keys. Binding the grant to the `ssh`
/// client instead makes "30 minutes" mean "30 minutes, and no longer than
/// this SSH session", which is how the button already read.
///
/// ## Which `ssh` frame, when there is more than one
///
/// A jump host means nested `ssh` processes, so the rule has to say which.
/// **The innermost forwarding frame wins.** The search starts at the socket
/// peer and works outward, and the peer is by construction the innermost
/// `ssh` — it is the process that opened the agent connection, and the chain
/// deliberately starts above it.
///
/// The other reading — anchor on the outermost — is the one the next person
/// will assume, so: it is rejected because it produces a grant that outlives
/// the session which created the exposure. Close the inner hop and the outer
/// `ssh` is still alive, still carrying a live grant, for a session the user
/// watched end. Innermost is the tightest live bound available, and every
/// argument for narrowing the anchor at all is an argument for narrowing it
/// as far as the process tree allows.
///
/// A frame only counts as forwarding when it is *both* an SSH-family process
/// by [`frame_identity`] (the kernel's `exe`, not a name it chose) and asking
/// for forwarding on its command line. Neither half alone: a process that
/// renames itself `ssh` must not get to nominate its own anchor, and an `ssh`
/// doing ordinary work must not lose the shell anchor that keeps a push loop
/// from re-prompting.
pub fn select_sign_anchor(peer: Option<&PeerProcess>, chain: &[Caller]) -> Option<SignAnchor> {
    if let Some(peer) = peer {
        if peer.forwards_agent && is_transport_frame(&peer.caller) {
            return Some(SignAnchor::of(&peer.caller, SignAnchorKind::ForwardedSsh));
        }
    }
    // Then outward through the ancestry, still innermost-first. Reached when
    // the peer is an inner `ssh` doing its own work — a ProxyJump transport,
    // say — underneath a session that *is* forwarding.
    if let Some(frame) = chain
        .iter()
        .find(|c| is_transport_frame(c) && requests_agent_forwarding(&c.command))
    {
        return Some(SignAnchor::of(frame, SignAnchorKind::ForwardedSsh));
    }
    select_anchor(chain).map(|c| SignAnchor::of(c, SignAnchorKind::Session))
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

    // ── Agent forwarding ─────────────────────────────────────────────────

    fn mk_peer(pid: u32, name: &str, exe: Option<&str>, command: &str) -> PeerProcess {
        let mut caller = mk_caller(pid, name, exe);
        caller.command = command.to_owned();
        PeerProcess {
            forwards_agent: requests_agent_forwarding(command),
            caller,
        }
    }

    fn mk_frame(pid: u32, name: &str, exe: Option<&str>, command: &str) -> Caller {
        let mut caller = mk_caller(pid, name, exe);
        caller.command = command.to_owned();
        caller
    }

    /// The finding: `ssh -A` hands a remote host the user's agent, and a
    /// "30 min" grant anchored on the shell keeps signing for it long after
    /// the SSH session is the only thing that could still be using it. The
    /// grant has to bind to the session that created the exposure.
    #[test]
    fn a_forwarding_ssh_client_anchors_the_grant_on_itself() {
        let peer = mk_peer(9200, "ssh", Some("/usr/bin/ssh"), "ssh -A build-box");
        let chain = vec![mk_frame(7926, "-zsh", Some("/bin/zsh"), "-zsh")];
        let anchor = select_sign_anchor(Some(&peer), &chain).expect("anchor");
        assert_eq!(anchor.kind, SignAnchorKind::ForwardedSsh);
        assert_eq!(
            anchor.identity.pid, 9200,
            "the grant must die with the SSH session, not with the terminal"
        );
    }

    /// The reason the argv test is load-bearing rather than "peer is ssh →
    /// anchor on it": a local push spawns a fresh `ssh` per push, so anchoring
    /// there would re-prompt every time — and a prompt users learn to click
    /// through is worse than the grant.
    #[test]
    fn a_local_git_push_still_anchors_on_the_shell() {
        let peer = mk_peer(9200, "ssh", Some("/usr/bin/ssh"), "ssh git@github.com");
        let chain = vec![
            mk_frame(8120, "git", Some("/usr/bin/git"), "git push origin main"),
            mk_frame(7926, "-zsh", Some("/bin/zsh"), "-zsh"),
        ];
        let anchor = select_sign_anchor(Some(&peer), &chain).expect("anchor");
        assert_eq!(anchor.kind, SignAnchorKind::Session);
        assert_eq!(anchor.identity.pid, 7926);
    }

    /// A jump host is more than one `ssh` frame, and the rule has to say
    /// which. Innermost: a grant must not outlive the session that created
    /// the exposure, and the outer `ssh` is still alive when the inner one
    /// the user was watching ends.
    #[test]
    fn the_innermost_forwarding_ssh_frame_wins_over_an_outer_one() {
        // The peer is the inner hop and it forwards, so it never reaches the
        // chain search — but the outer one forwards too, and would have been
        // chosen by the outermost reading.
        let peer = mk_peer(9310, "ssh", Some("/usr/bin/ssh"), "ssh -A inner-box");
        let chain = vec![
            mk_frame(9200, "ssh", Some("/usr/bin/ssh"), "ssh -A jump-box"),
            mk_frame(7926, "-zsh", Some("/bin/zsh"), "-zsh"),
        ];
        let anchor = select_sign_anchor(Some(&peer), &chain).expect("anchor");
        assert_eq!(anchor.identity.pid, 9310, "innermost forwarding frame");
    }

    /// The peer is the innermost `ssh` but is doing its own work (a ProxyJump
    /// transport authenticating to the jump host). The session above it *is*
    /// forwarding, so the shell is still the wrong anchor.
    #[test]
    fn an_outer_forwarding_frame_is_found_when_the_peer_does_not_forward() {
        let peer = mk_peer(
            9310,
            "ssh",
            Some("/usr/bin/ssh"),
            "ssh -W target:22 jump-box",
        );
        let chain = vec![
            mk_frame(
                9200,
                "ssh",
                Some("/usr/bin/ssh"),
                "ssh -A -J jump-box target",
            ),
            mk_frame(7926, "-zsh", Some("/bin/zsh"), "-zsh"),
        ];
        let anchor = select_sign_anchor(Some(&peer), &chain).expect("anchor");
        assert_eq!(anchor.kind, SignAnchorKind::ForwardedSsh);
        assert_eq!(anchor.identity.pid, 9200);
    }

    /// The same trust split every other frame predicate makes. A process that
    /// renames itself `ssh` and puts `-A` in its own argv must not get to
    /// nominate its own anchor; `exe` says what was loaded.
    #[test]
    fn a_process_calling_itself_ssh_cannot_nominate_its_own_anchor() {
        let peer = mk_peer(
            9200,
            "ssh",
            Some("/tmp/.hidden/payload"),
            "ssh -A build-box",
        );
        let chain = vec![mk_frame(7926, "-zsh", Some("/bin/zsh"), "-zsh")];
        let anchor = select_sign_anchor(Some(&peer), &chain).expect("anchor");
        assert_eq!(anchor.kind, SignAnchorKind::Session);
        assert_eq!(anchor.identity.pid, 7926);
    }

    /// An `ssh -A` whose ancestry the daemon cannot read used to be refused
    /// outright (no anchor, `SSH_AGENT_FAILURE`). The peer is an anchor in
    /// its own right, so a forwarding session with no visible parent now has
    /// one — and it is the narrow one.
    #[test]
    fn a_forwarding_peer_anchors_even_with_no_visible_ancestry() {
        let peer = mk_peer(9200, "ssh", Some("/usr/bin/ssh"), "ssh -A build-box");
        let anchor = select_sign_anchor(Some(&peer), &[]).expect("anchor");
        assert_eq!(anchor.identity.pid, 9200);
    }

    /// Forwarding is spelled several ways on a command line and all of them
    /// hand the agent over. Reading only `-A` would leave the option form as
    /// an unguarded way to keep the wide grant.
    #[test]
    fn every_argv_spelling_of_forward_agent_is_recognized() {
        for command in [
            "ssh -A host",
            "ssh -tA host",
            "ssh -4At host",
            "ssh -oForwardAgent=yes host",
            "ssh -o ForwardAgent=yes host",
            "ssh -o ForwardAgent yes host",
            "ssh -o forwardagent=YES host",
            "ssh -o ForwardAgent=ask host",
        ] {
            assert!(requests_agent_forwarding(command), "{command}");
        }
    }

    /// The mirror image, and the reason the parser is not a substring search:
    /// a false positive costs the user a re-prompt on every push, which is
    /// how a consent surface gets trained out of being read.
    #[test]
    fn ordinary_ssh_command_lines_do_not_read_as_forwarding() {
        for command in [
            "ssh git@github.com",
            "ssh -a host",                 // lowercase: disables it
            "ssh -o ForwardAgent=no host", // explicitly off
            "ssh -o ForwardX11=yes host",  // a different forward
            "ssh -i /keys/A host",         // a key file named A
            "ssh -iA host",                // the same, bundled
            "ssh -W target:22 jump",       // ProxyJump transport
        ] {
            assert!(!requests_agent_forwarding(command), "{command}");
        }
    }

    /// `describe_pid` is what makes the peer readable at all — the chain walk
    /// starts *above* it, so without this the one frame that knows about
    /// forwarding is the one frame nothing describes.
    #[test]
    fn describe_pid_reads_the_process_the_chain_walk_skips() {
        let me = std::process::id();
        let peer = describe_pid(me).expect("our own process is readable");
        assert_eq!(peer.caller.pid, me);
        assert!(!peer.caller.name.is_empty());
        assert!(
            caller_chain_from_pid(me).frames.iter().all(|c| c.pid != me),
            "the walk excludes its seed, which is why describe_pid exists"
        );
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
    /// decision, plus every other way a character can be present in a string
    /// and absent from its rendering.
    ///
    /// One assertion per named class, so a gap reports itself by name.
    #[test]
    fn every_invisible_or_reordering_class_is_stripped() {
        for &(class, bad) in INVISIBLE_OR_REORDERING_CLASSES {
            assert!(
                is_invisible_or_reordering(bad),
                "{class} (U+{:04X}) is not recognised",
                bad as u32
            );
            let out = sanitize_display(&format!("gh{bad}api"));
            assert!(
                !out.contains(bad),
                "{class} (U+{:04X}) survived: {out:?}",
                bad as u32
            );
        }
    }

    /// The tag block spells ASCII in invisible characters — the "invisible
    /// instructions" trick — so a range check that looks right by eye is not
    /// evidence. This is a real payload: `U+E0001` then `sudo rm -rf /` in tag
    /// characters, then `U+E007F`.
    #[test]
    fn a_tag_block_payload_leaves_nothing_behind() {
        let payload: String = std::iter::once('\u{E0001}')
            .chain(
                "sudo rm -rf /"
                    .chars()
                    .map(|c| char::from_u32(0xE_0000 + c as u32).expect("a tag character")),
            )
            .chain(std::iter::once('\u{E007F}'))
            .collect();
        assert_eq!(payload.chars().count(), 15);

        let out = sanitize_display(&format!("node{payload}"));
        assert_eq!(out, "node", "the invisible instructions survived: {out:?}");
    }

    /// Ordinary text in scripts that are not Latin must survive intact. A
    /// category-driven predicate is only an improvement if it still says yes to
    /// the process names real people run.
    #[test]
    fn ordinary_non_latin_text_survives() {
        for good in ["中文命令", "команда", "コマンド", "café", "naïve", "מסוף"]
        {
            assert_eq!(sanitize_display(good), good);
        }
        // Decomposed: a base plus its combining acute. Both must survive.
        assert_eq!(sanitize_display("cafe\u{0301}"), "cafe\u{0301}");
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
