//! Terminal-state normalization for the interactive prompt flows.

use std::io::{IsTerminal, Write};

/// Soft-reset the terminal's input and rendering modes before prompting.
///
/// A full-screen app that crashed (or was killed) leaves the terminal
/// wedged in whatever modes it had switched on, and several of them break
/// cliclack prompts — the key reader (the `console` crate) only understands
/// plain CSI sequences, so any mode that changes what key presses put on
/// the wire makes selects go dead while single-byte Enter/Escape keep
/// working:
///
/// - DECCKM "application cursor keys": arrows arrive as SS3 `ESC O B`.
/// - The kitty keyboard protocol (left pushed): keys arrive as `CSI … u`.
/// - xterm's modifyOtherKeys: keys arrive as `CSI 27 ; … ~`.
/// - Mouse tracking: a stray scroll injects `CSI M …` bytes into the
///   prompt's input.
///
/// The reset is DECSTR (`CSI ! p`, the standards-track "fix the terminal
/// without clearing the screen") — which restores normal cursor keys,
/// numeric keypad, a visible cursor, and sane margins/SGR — followed by
/// explicit clears for what DECSTR predates or a partial implementation
/// may skip. Deliberately *not* touched: the alternate screen
/// (`?1049`) — leaving it is visible and could clobber a host app that
/// legitimately shelled out — and RIS (`ESC c`), which erases the screen
/// and scrollback.
///
/// Terminals ignore CSI sequences they don't recognize, so every line is a
/// safe no-op where unsupported. This cannot help when the terminal app
/// itself intercepts keys before they reach the pty; no byte sequence can.
///
/// Best-effort by design: written to stderr because that is where cliclack
/// renders, skipped when stderr is not a terminal (nobody to prompt,
/// nothing to fix), and a failed write must not abort the flow it precedes.
pub fn soft_reset() {
    let mut err = std::io::stderr();
    if !err.is_terminal() {
        return;
    }
    let _ = err.write_all(
        b"\x1b[!p\
          \x1b[?1l\
          \x1b>\
          \x1b(B\x0f\
          \x1b[=0;1u\
          \x1b[>4;0m\
          \x1b[?1000;1002;1003;1006;2004l",
    );
    let _ = err.flush();
}

/// Columns available inside a `cliclack::note` box, for the terminal we're
/// actually rendering into.
///
/// cliclack draws `│  ` down the left of a note and closes each row on the
/// right, so the usable width is the terminal minus that chrome. The cap
/// keeps prose readable on a very wide terminal — a 200-column window should
/// not produce 200-column sentences — and the floor keeps a pathologically
/// narrow one from wrapping to nothing.
fn note_width() -> usize {
    // cliclack renders to stderr; ask the same stream. `console` falls back to
    // 80 columns when there's no tty, which is exactly the right answer for a
    // piped or recorded run.
    let cols = console::Term::stderr().size().1 as usize;
    cols.min(90).saturating_sub(BOX_CHROME).max(20)
}

/// `│` + two spaces on the left, plus padding and the right border.
const BOX_CHROME: usize = 8;

/// Wrap prose so a `cliclack::note` built from it fits the terminal.
///
/// **Use this for any note text that interpolates a path.** cliclack sizes a
/// note's box to its longest line and neither wraps nor truncates, so one long
/// line doesn't overflow gracefully — it runs past the right edge, wraps in the
/// terminal instead, and every subsequent row's border lands on a line of its
/// own. The result is an unreadable box around the text that most wanted
/// reading. A `$HOME` long enough to trigger it is ordinary, so "it fits on my
/// machine" proves nothing.
///
/// Keep the note's *title* short and constant and put the variable-length
/// prose through here into the body; that way no user's directory layout can
/// size the box.
pub fn wrap_note_text(text: &str) -> String {
    let options = textwrap::Options::new(note_width())
        // Never split inside a token. A path broken across two lines is
        // unreadable, un-copyable, and — because the transcript harness
        // redacts the sandbox home by plain string replacement — invisible to
        // that redaction, which is how a `/tmp/…` sandbox path first leaked
        // into a published recording. Pass paths through
        // `daemon::ui::abbreviate_home` so they are short enough that this
        // rarely has to overflow at all.
        .break_words(false);
    textwrap::fill(text, options)
}

/// Wrap prose for a `cliclack::log::*` line (`▲  …`, `◆  …`).
///
/// These don't draw a box, so an over-long message doesn't corrupt any
/// borders — it just wraps wherever the terminal happens to run out, which
/// lands mid-word and, for a path, mid-path. Same reasons as
/// [`wrap_note_text`]: readable breaks, and a path that stays in one piece.
pub fn wrap_log_text(text: &str) -> String {
    let options = textwrap::Options::new(log_width()).break_words(false);
    textwrap::fill(text, options)
}

/// `▲` plus two spaces, with a column of slack so nothing lands flush against
/// the right edge.
const LOG_CHROME: usize = 5;

fn log_width() -> usize {
    let cols = console::Term::stderr().size().1 as usize;
    cols.min(90).saturating_sub(LOG_CHROME).max(20)
}
