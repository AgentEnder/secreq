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
