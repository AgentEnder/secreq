//! Transcript harness for secreq's interactive terminal flows.
//!
//! The docs recommend the interactive path — `secreq wrap gh` and let it ask
//! — but prose cannot show what a cliclack session looks like, and a
//! hand-typed code block showing what it *probably* looks like rots the
//! first time a prompt is reworded. So this target drives the **real
//! binary** on a **real pty** and records what a terminal would be
//! displaying, into `dev-docs/cli-transcripts/`. The docs site replays those
//! recordings via `::term{id=…}`, the same way `::shot{id=…}` publishes the
//! screenshot fixtures.
//!
//! All tests are `#[ignore]` so a normal `cargo test` run doesn't spawn
//! ptys. Regenerate the transcripts with:
//!
//! ```sh
//! cargo test --test cli_transcripts -- --ignored --nocapture --test-threads=1
//! ```
//!
//! ## What a recording contains
//!
//! Not a byte stream, and not a single final screen. A cliclack session is a
//! sequence of full-screen redraws with the user typing between them, so a
//! recording is a list of **steps** in the order they happened:
//!
//! - `frame` — the rendered screen after the TUI finished drawing. Redraws
//!   are already collapsed by the terminal emulator, so a frame is what a
//!   user's eye would see, not what the program wrote.
//! - `type` — text the user typed, with the cursor cell it was typed at, so
//!   the player can animate it character by character in the right place
//!   rather than cutting straight to the next frame.
//! - `key` — a bare keypress (Enter, arrows) that moved the session on.
//! - `gui` — the consent window rose (or fell) at this beat, and the
//!   screenshot fixture that shows it. Nothing the terminal can render: the
//!   whole point of the moment is that what happens next happens *off* the
//!   terminal, in a window the recording cannot photograph.
//!
//! Pacing is deliberately **not** recorded. Wall-clock here is an artifact
//! of harness sleeps and a fake provider that answers instantly; replaying
//! it would publish the harness's timing as if it were the product's. The
//! player paces frames and typing itself, and a fixture asks for a longer
//! beat explicitly with [`Recorder::hold`] where the real command genuinely
//! waits (a provider round-trip, a spinner).
//!
//! ## Why the fixtures look real
//!
//! A transcript is only worth publishing if it's the flow a reader will
//! actually get, so the sandbox is dressed to match: a fake `op` on `$PATH`
//! answering `op read`, so the built-in 1Password provider is the one being
//! exercised and "Locator resolves ✓" is a real check that really passed.
//! Nothing about the *flow* is stubbed — only the store behind it.
#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use common::pty::{PtyRun, COLS, ROWS};
use common::Sandbox;
use secreq::consent::Decision;
use secreq::daemon::proto::{ClientMsg, DaemonMsg};
use serde::Serialize;

/// Where the regenerated transcripts land. Relative to the package root,
/// which is `cargo test`'s CWD.
const OUT_DIR: &str = "../../dev-docs/cli-transcripts";

/// How long a fixture waits for a prompt to appear before giving up.
const STEP_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the screen must stop changing before a snapshot is taken. One
/// cliclack redraw is a single burst, so this only has to outlast a write.
const SETTLE: Duration = Duration::from_millis(120);

// ── The recording model ───────────────────────────────────────────────────

/// One styled run of characters on a line: the text, plus the attributes
/// every cell in it shares.
///
/// Emitting runs rather than per-cell data is what keeps a transcript
/// reviewable — a line of unstyled output is one run, not eighty cells.
///
/// The single-letter names are the wire format, not an abbreviation habit:
/// a frame is thousands of these, and `"foreground"` spelled out on every
/// one of them would multiply the size of a file that lives in git forever
/// and ships to secreq.dev. Every attribute is omitted when it carries no
/// information, so the common unstyled run is `{"t":"…"}` and nothing else.
#[derive(Serialize)]
struct Span {
    /// Foreground colour. See [`color_token`].
    #[serde(rename = "f", skip_serializing_if = "Option::is_none")]
    fg: Option<String>,
    /// Background colour, same encoding as [`Span::fg`]. Nothing recorded so
    /// far paints one — cliclack styles foregrounds — but a cell that does
    /// would be unreadable without it.
    #[serde(rename = "b", skip_serializing_if = "Option::is_none")]
    bg: Option<String>,
    /// The [`style_bits`] bitfield. Absent rather than `0` when unstyled.
    #[serde(rename = "s", skip_serializing_if = "is_unstyled")]
    style: u8,
    #[serde(rename = "t")]
    text: String,
}

fn is_unstyled(bits: &u8) -> bool {
    *bits == 0
}

/// One rendered row: the runs it is made of, left to right.
type Line = Vec<Span>;

/// One moment of a recorded session, in the order it happened.
///
/// The variants are the whole vocabulary the player understands; the
/// `kind` tag it dispatches on is the variant name, so the Rust enum and
/// the `Step` union in `docs-site/term-markup.ts` are the same declaration
/// written twice. A new kind of moment joins as one more variant here plus
/// one more member there, and nothing else in either file moves.
///
/// Making this an enum rather than a bag of optional fields is what makes
/// the impossible states impossible: there is no step that is a frame *and*
/// a keypress, and no `hold` on anything but a frame, so [`Recorder::hold`]
/// is a `match` instead of the runtime string check it used to be.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Step {
    /// The rendered screen after the TUI finished drawing.
    Frame {
        lines: Vec<Line>,
        /// Extra dwell the player adds to this frame, in ms. Absent on
        /// almost every frame; see [`Recorder::hold`].
        #[serde(skip_serializing_if = "Option::is_none")]
        hold: Option<u32>,
    },
    /// Text the user typed, and the cell it landed in.
    Type { text: String, row: u16, col: u16 },
    /// Text the user pasted, and the cell it landed in.
    ///
    /// Indistinguishable from [`Step::Type`] to the pty — a paste is bytes
    /// arriving quickly — so the distinction has to be recorded rather than
    /// inferred. It is worth recording because the two are different acts to
    /// a reader. Nobody types a secret reference: 1Password's "Copy Secret
    /// Reference" puts `op://Vault/Item/field` on the clipboard and you paste
    /// it, which is the flow [`provider::normalize_pasted_locator`] exists to
    /// accept. A recording that types the locator out character by character
    /// demonstrates a way of working the tool does not expect.
    Paste { text: String, row: u16, col: u16 },
    /// A bare keypress that moved the session on.
    Key { key: String },
    /// The consent window rose or fell here, and the screenshot fixture
    /// that shows it.
    ///
    /// The one step that describes something outside the terminal, which is
    /// exactly why it has to exist: a recording of a wrap blocking on
    /// consent is a recording of a terminal doing nothing, and the half of
    /// the story a reader needs is happening in a window the pty cannot
    /// see. The marker says "*this* is the beat, and *that* is the picture"
    /// and leaves the pairing to whoever is listening — the player raises an
    /// event and renders nothing itself, so a recording carrying markers
    /// still replays correctly on a page that has no window to show.
    ///
    /// `id` names a directory under `dev-docs/ui-screenshots/` and is
    /// carried on the hide as well as the show, so a listener never has to
    /// remember what it was showing. [`gui_ids_name_real_screenshot_fixtures`]
    /// checks every one of them against the fixtures on disk.
    Gui { action: GuiAction, id: String },
}

/// Which way a [`Step::Gui`] marker points.
#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum GuiAction {
    Show,
    Hide,
}

/// Style bits packed into a run's `s` field. The player maps each to a
/// class; keeping them a bitfield keeps an unstyled run's JSON to `{"t":…}`.
mod style_bits {
    pub const BOLD: u8 = 1;
    pub const DIM: u8 = 2;
    pub const ITALIC: u8 = 4;
    pub const UNDERLINE: u8 = 8;
    pub const INVERSE: u8 = 16;
}

/// A vt100 colour as the player wants it: `None` for the terminal default,
/// `"0".."15"` for a palette index (what cliclack uses), `"#rrggbb`" for a
/// true-colour cell.
///
/// Palette indices stay indices rather than being resolved to hex here: the
/// docs site renders in both light and dark, and "ANSI green" has to be a
/// different pixel value in each. Baking a colour in would pin it to one.
fn color_token(color: vt100::Color) -> Option<String> {
    match color {
        vt100::Color::Default => None,
        vt100::Color::Idx(i) => Some(i.to_string()),
        vt100::Color::Rgb(r, g, b) => Some(format!("#{r:02x}{g:02x}{b:02x}")),
    }
}

fn style_of(cell: &vt100::Cell) -> u8 {
    let mut bits = 0;
    if cell.bold() {
        bits |= style_bits::BOLD;
    }
    if cell.dim() {
        bits |= style_bits::DIM;
    }
    if cell.italic() {
        bits |= style_bits::ITALIC;
    }
    if cell.underline() {
        bits |= style_bits::UNDERLINE;
    }
    if cell.inverse() {
        bits |= style_bits::INVERSE;
    }
    bits
}

/// Render one screen into lines of styled runs.
///
/// Trailing blank cells and trailing blank lines are dropped: the pty is 40
/// rows tall so that nothing scrolls away, which would otherwise make every
/// frame a 40-row rectangle mostly full of nothing.
fn frame_lines(screen: &vt100::Screen) -> Vec<Line> {
    let mut lines: Vec<Line> = Vec::new();

    for row in 0..ROWS {
        let mut runs: Line = Vec::new();
        let mut text = String::new();
        let mut key: Option<(Option<String>, Option<String>, u8)> = None;

        for col in 0..COLS {
            let Some(cell) = screen.cell(row, col) else {
                continue;
            };
            // The second half of a wide glyph carries no content of its
            // own; emitting it would double the character.
            if cell.is_wide_continuation() {
                continue;
            }
            let contents = cell.contents();
            let glyph = if contents.is_empty() { " " } else { contents };
            let this = (
                color_token(cell.fgcolor()),
                color_token(cell.bgcolor()),
                style_of(cell),
            );

            match &key {
                Some(current) if *current == this => text.push_str(glyph),
                Some(current) => {
                    let (fg, bg, style) = current.clone();
                    runs.push(Span {
                        fg,
                        bg,
                        style,
                        text,
                    });
                    text = glyph.to_owned();
                    key = Some(this);
                }
                None => {
                    text = glyph.to_owned();
                    key = Some(this);
                }
            }
        }
        if let Some((fg, bg, style)) = key {
            runs.push(Span {
                fg,
                bg,
                style,
                text,
            });
        }

        // Trailing whitespace on a line is padding, not content.
        trim_trailing_blank_runs(&mut runs);
        lines.push(runs);
    }

    while lines.last().is_some_and(std::vec::Vec::is_empty) {
        lines.pop();
    }
    lines
}

fn trim_trailing_blank_runs(runs: &mut Line) {
    while let Some(last) = runs.last_mut() {
        let trimmed = last.text.trim_end().len();
        if trimmed == 0 {
            runs.pop();
        } else {
            last.text.truncate(trimmed);
            break;
        }
    }
}

/// Locate `needle` on the screen, as `(row, col)` of its first character.
///
/// Columns are counted in cells, not chars, so a wide glyph earlier on the
/// line doesn't shift the answer — the player positions its caret in `ch`
/// units against the same grid.
fn find_on_screen(screen: &vt100::Screen, needle: &str) -> Option<(u16, u16)> {
    for row in 0..ROWS {
        let mut text = String::new();
        let mut columns: Vec<u16> = Vec::new();
        for col in 0..COLS {
            let Some(cell) = screen.cell(row, col) else {
                continue;
            };
            if cell.is_wide_continuation() {
                continue;
            }
            let contents = cell.contents();
            let glyph = if contents.is_empty() { " " } else { contents };
            for _ in glyph.chars() {
                columns.push(col);
            }
            text.push_str(glyph);
        }
        if let Some(byte_idx) = text.find(needle) {
            let char_idx = text[..byte_idx].chars().count();
            return columns.get(char_idx).map(|col| (row, *col));
        }
    }
    None
}

/// The plain-text rendering of a frame, for the `.txt` companion file.
fn frame_text(lines: &[Line]) -> String {
    lines
        .iter()
        .map(|line| {
            line.iter()
                .map(|span| span.text.as_str())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Driving a session ─────────────────────────────────────────────────────

/// Records a live session as it is driven.
struct Recorder {
    run: PtyRun,
    steps: Vec<Step>,
}

impl Recorder {
    fn new(run: PtyRun) -> Self {
        Recorder {
            run,
            steps: Vec::new(),
        }
    }

    /// Photograph the screen as it now stands.
    fn snap(&mut self) -> &mut Self {
        self.run.wait_until_settled(SETTLE, STEP_TIMEOUT);
        let screen = self.run.screen();
        self.steps.push(Step::Frame {
            lines: frame_lines(&screen),
            hold: None,
        });
        self
    }

    /// Wait for `needle` to reach the screen, let the redraw finish, and
    /// photograph it.
    ///
    /// The needle is a real assertion, not a sleep in disguise: a fixture
    /// naming a prompt that no longer exists fails the regen instead of
    /// quietly recording a screen from somewhere else in the flow.
    fn expect(&mut self, needle: &str) -> &mut Self {
        self.run.wait_for_screen(needle, STEP_TIMEOUT);
        self.run.wait_until_settled(SETTLE, STEP_TIMEOUT);
        let screen = self.run.screen();
        assert!(
            screen.contents().contains(needle),
            "{needle:?} left the screen while it settled; screen was:\n{}",
            screen.contents()
        );
        self.steps.push(Step::Frame {
            lines: frame_lines(&screen),
            hold: None,
        });
        self
    }

    /// Photograph the first screen that shows `needle`, without waiting for
    /// it to settle.
    ///
    /// For the one thing [`Recorder::expect`] cannot photograph: a screen
    /// that is *never* going to stop changing. The wait indicator repaints
    /// its spinner every 100ms for as long as the wrap is blocked, so
    /// `wait_until_settled` would sit there until it timed out and failed a
    /// fixture whose subject is precisely that the terminal is still alive.
    ///
    /// The needle is still a real assertion — `wait_for_screen` returns only
    /// a screen that contains it, so a torn mid-repaint capture is retried
    /// rather than recorded.
    fn expect_transient(&mut self, needle: &str) -> &mut Self {
        let screen = self.run.wait_for_screen(needle, STEP_TIMEOUT);
        self.steps.push(Step::Frame {
            lines: frame_lines(&screen),
            hold: None,
        });
        self
    }

    /// Photograph the wait indicator once per glyph in `glyphs`, in the order
    /// the spinner paints them, with `tail` completing the line each of them
    /// leads.
    ///
    /// [`Recorder::expect_transient`] can photograph a screen that never
    /// settles, but one photograph of a spinner is a still — and a still is
    /// what the docs site would then play: a terminal frozen for the whole
    /// beat the consent window is up, so that the window's dismissal reads as
    /// the animation moving on rather than as the consequence of somebody
    /// approving. A wait has to *look* like a wait, which takes more than one
    /// frame of it.
    ///
    /// **The spacing is one spinner tick, and it is spelled as a glyph rather
    /// than as a 100ms sleep on purpose.** Timing the captures would leave
    /// the recorded bytes at the mercy of where each 20ms poll happened to
    /// land inside the indicator's 100ms window: a loaded machine would
    /// regenerate this fixture with a different braille glyph on some frame,
    /// and the diff would be noise nobody could act on. Naming the glyph pins
    /// the *content* instead. The indicator cycles for as long as the wrap is
    /// blocked, so every glyph comes back around; all load can change is how
    /// long a regen waited for one, and pacing is not what a recording
    /// records.
    fn expect_spinner(&mut self, glyphs: &[&str], tail: &str) -> &mut Self {
        for glyph in glyphs {
            // The whole line rather than the glyph alone: the needle is what
            // makes a torn mid-repaint capture get retried, and a lone glyph
            // would happily match a line that had only started to arrive.
            self.expect_transient(&format!("{glyph}{tail}"));
        }
        self
    }

    /// Block until the client's ask has actually reached `daemon`.
    ///
    /// Consulting the daemon beats sleeping: the next move is to photograph
    /// the wait indicator, which is only meaningful once the wrap is truly
    /// blocked, and a sleep long enough to be safe would still be a guess.
    ///
    /// A method on the recorder rather than on the stub so that the failure
    /// can show the screen. "No ask arrived" is almost always "the command
    /// died before it got that far" — a config it wouldn't parse, a binary
    /// it couldn't find — and the reason for that is on the terminal, which
    /// the stub cannot see.
    fn await_ask(&mut self, daemon: &StubDaemon) -> &mut Self {
        if daemon.asked.recv_timeout(STEP_TIMEOUT).is_err() {
            panic!(
                "the wrap never asked the daemon for consent; screen was:\n{}",
                self.run.screen().contents()
            );
        }
        self
    }

    /// Mark that the consent window is now up, and which screenshot fixture
    /// shows what the user is looking at.
    fn gui_show(&mut self, fixture: &str) -> &mut Self {
        self.steps.push(Step::Gui {
            action: GuiAction::Show,
            id: fixture.to_owned(),
        });
        self
    }

    /// Mark that the consent window is gone — the user decided, and the
    /// terminal is about to be the whole story again.
    fn gui_hide(&mut self, fixture: &str) -> &mut Self {
        self.steps.push(Step::Gui {
            action: GuiAction::Hide,
            id: fixture.to_owned(),
        });
        self
    }

    /// Move a cliclack select onto `label` and submit it.
    ///
    /// Arrow presses are driven by what the screen shows rather than a
    /// counted offset: the provider list is the built-in set, which differs
    /// by platform (there is no `keychain` on Linux), so "press Down twice"
    /// records a different choice depending on where it was regenerated.
    /// Each move is photographed, so the published animation shows the
    /// highlight travelling exactly as far as it really did.
    fn select_item(&mut self, label: &str) -> &mut Self {
        let active = format!("● {label}");
        for _ in 0..12 {
            self.run.wait_until_settled(SETTLE, STEP_TIMEOUT);
            if self.run.screen().contents().contains(&active) {
                return self.enter();
            }
            self.down();
            self.snap();
        }
        panic!(
            "never reached {label:?} in the select; screen was:\n{}",
            self.run.screen().contents()
        );
    }

    /// Ask the player to linger on the frame just recorded, for the beats
    /// where the real command is genuinely working (a provider round-trip).
    fn hold(&mut self, ms: u32) -> &mut Self {
        match self.steps.last_mut() {
            Some(Step::Frame { hold, .. }) => *hold = Some(ms),
            // Only a frame is something the player can linger *on*; a hold
            // on a keypress would be a beat with nothing on screen to hold.
            Some(_) => panic!("hold applies to a frame, and the last step recorded was not one"),
            None => panic!("hold needs a frame, and nothing has been recorded yet"),
        }
        self
    }

    /// Type text into the prompt on screen, then submit it.
    ///
    /// The position recorded is where the text *landed*, found by looking
    /// for the echo afterwards — not `cursor_position()` before sending.
    /// cliclack parks the cursor below its box while drawing, so the
    /// pre-send cursor is nowhere near the input line; animating there
    /// would type the answer into thin air under the prompt.
    ///
    /// No frame is recorded for the echo. The player reconstructs it by
    /// drawing the characters one at a time onto the frame that is already
    /// on screen, which is the whole point of recording typing separately.
    fn type_line(&mut self, text: &str) -> &mut Self {
        self.run.write_bytes(text.as_bytes());
        self.run.wait_until_settled(SETTLE, STEP_TIMEOUT);
        let echoed = self.run.screen();
        let (row, col) = find_on_screen(&echoed, text).unwrap_or_else(|| {
            panic!(
                "typed {text:?} never appeared on screen; screen was:\n{}",
                echoed.contents()
            )
        });
        self.steps.push(Step::Type {
            text: text.to_owned(),
            row,
            col,
        });
        self.enter()
    }

    /// Paste text into the prompt on screen, then submit it.
    ///
    /// The same write and the same echo-hunt as [`Recorder::type_line`]; a
    /// paste reaches a pty as bytes like anything else, and the only thing
    /// separating the two is which one the reader is meant to picture
    /// themselves doing. See [`Step::Paste`].
    fn paste_line(&mut self, text: &str) -> &mut Self {
        self.run.write_bytes(text.as_bytes());
        self.run.wait_until_settled(SETTLE, STEP_TIMEOUT);
        let echoed = self.run.screen();
        let (row, col) = find_on_screen(&echoed, text).unwrap_or_else(|| {
            panic!(
                "pasted {text:?} never appeared on screen; screen was:\n{}",
                echoed.contents()
            )
        });
        self.steps.push(Step::Paste {
            text: text.to_owned(),
            row,
            col,
        });
        self.enter()
    }

    fn enter(&mut self) -> &mut Self {
        self.steps.push(Step::Key {
            key: "Enter".to_owned(),
        });
        self.run.press_enter();
        self
    }

    /// Answer a cliclack confirm. `y`/`n` set the value *and* submit in one
    /// keystroke, so this deliberately does not follow with an Enter.
    fn answer(&mut self, yes: bool) -> &mut Self {
        let key = if yes { "y" } else { "n" };
        self.steps.push(Step::Key {
            key: key.to_owned(),
        });
        self.run.write_bytes(key.as_bytes());
        self
    }

    fn down(&mut self) -> &mut Self {
        self.steps.push(Step::Key {
            key: "Down".to_owned(),
        });
        self.run.press_arrow_down();
        self
    }

    /// Wait for the command to exit cleanly, photograph the final screen,
    /// and write the recording out.
    fn finish(self, transcript: Transcript) {
        self.finish_with_success(transcript, true);
    }

    /// Finish a recording whose command is expected to be refused.
    fn finish_denied(self, transcript: Transcript) {
        self.finish_with_success(transcript, false);
    }

    fn finish_with_success(mut self, transcript: Transcript, expect_success: bool) {
        let status = self.run.wait_exit(STEP_TIMEOUT);
        assert!(
            status.success() == expect_success,
            "`{}` exited with {status:?}; expected success={expect_success}; screen was:\n{}",
            transcript.command,
            self.run.screen().contents()
        );
        self.run.wait_until_settled(SETTLE, STEP_TIMEOUT);
        let screen = self.run.screen();
        self.steps.push(Step::Frame {
            lines: frame_lines(&screen),
            hold: None,
        });

        write_transcript(&transcript, &self.steps);
    }
}

/// Everything a recording says about itself.
struct Transcript {
    id: &'static str,
    /// Shown in the terminal's title bar. The command being demonstrated.
    command: &'static str,
    /// The figcaption the docs site publishes under the terminal. Written
    /// for a reader of the docs, exactly like a `Shot` caption.
    caption: &'static str,
}

impl Transcript {
    fn new(id: &'static str, command: &'static str, caption: &'static str) -> Self {
        Transcript {
            id,
            command,
            caption,
        }
    }
}

/// The recording as the docs site consumes it: the metadata a `Transcript`
/// carries, plus the steps, in one document.
#[derive(Serialize)]
struct TranscriptDoc<'a> {
    id: &'a str,
    command: &'a str,
    caption: &'a str,
    cols: u16,
    steps: &'a [Step],
}

/// Write `<id>.json` (what the site replays) and `<id>.txt` (the final
/// frame, so a reviewer can read the diff without decoding styled runs).
fn write_transcript(transcript: &Transcript, steps: &[Step]) {
    let out_dir = Path::new(OUT_DIR);
    std::fs::create_dir_all(out_dir).expect("create transcript dir");

    let doc = TranscriptDoc {
        id: transcript.id,
        command: transcript.command,
        caption: transcript.caption,
        cols: COLS,
        steps,
    };
    // Through `Value` deliberately, rather than straight to a string.
    // `serde_json::Map` is a `BTreeMap` here — nothing in the tree turns on
    // `preserve_order` — so the extra hop sorts every object's keys, which
    // is how these files have always been written and what makes their
    // diffs readable: a changed prompt shows as a changed prompt, never as
    // a field that moved because someone reordered a struct.
    //
    // It is also the only way to get that ordering at all. Serialising the
    // structs directly emits declaration order, and `#[serde(tag = "kind")]`
    // always writes the tag first, so a held frame would come out
    // `{"kind":…,"hold":…}` — sorted output puts `hold` first.
    let value = serde_json::to_value(&doc).expect("transcript is representable as json");
    let body = serde_json::to_string_pretty(&value).expect("serialize transcript");
    std::fs::write(
        out_dir.join(format!("{}.json", transcript.id)),
        format!("{body}\n"),
    )
    .expect("write transcript json");

    let final_frame = steps
        .iter()
        .rev()
        .find_map(|step| match step {
            Step::Frame { lines, .. } => Some(frame_text(lines)),
            _ => None,
        })
        .unwrap_or_default();
    std::fs::write(
        out_dir.join(format!("{}.txt", transcript.id)),
        format!("$ {}\n\n{final_frame}\n", transcript.command),
    )
    .expect("write transcript txt");

    println!("recorded {} ({} steps)", transcript.id, steps.len());
}

// ── Sandbox dressing ──────────────────────────────────────────────────────

/// Drop a fake `op` into the sandbox's `bin` dir and return that dir.
///
/// The built-in 1Password provider runs `op read op://{locator}`, so this is
/// all it takes for the recorded session to exercise the real provider path
/// — including the resolvability check that prints "Locator resolves ✓".
/// The value it returns is never displayed by any flow recorded here; the
/// check only asks whether the read succeeded.
fn install_fake_op(sb: &Sandbox) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let bin_dir = sb.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    let op = bin_dir.join("op");
    std::fs::write(
        &op,
        "#!/bin/sh\n\
         # Stand-in for the 1Password CLI: answers `op read op://…`.\n\
         [ \"$1\" = read ] || exit 1\n\
         printf '%s' 'example-secret-value'\n",
    )
    .expect("write fake op");
    std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).expect("chmod fake op");
    bin_dir
}

/// Drop a fake `gh` into the sandbox's `bin` dir.
///
/// The wrap-and-run path ends by exec'ing the real binary it gated, so a
/// recording of `gh` under secreq has to have a `gh` to hand — and a machine
/// with the GitHub CLI installed is not something a regen can assume. This
/// stands in for it: `find_real_binary` skips the shim dir and finds this,
/// so everything upstream of the exec (the consent round-trip, the
/// injection, the output masking) is the production path, and the only
/// invented thing is the listing at the end.
///
/// The listing is close to what `gh repo list` prints and not identical to
/// it. It is a stand-in for a tool, in the same sense as [`install_fake_op`]
/// — never quoted anywhere as GitHub's own output.
fn install_fake_gh(bin_dir: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let gh = bin_dir.join("gh");
    std::fs::write(
        &gh,
        "#!/bin/sh\n\
         # Stand-in for the GitHub CLI: answers `gh repo list`.\n\
         [ \"$1\" = repo ] || exit 1\n\
         echo 'Showing 3 of 3 repositories in @you'\n\
         echo\n\
         echo 'you/secreq      consent for secrets on your machine  public   1h'\n\
         echo 'you/dotfiles    shell, editor, and all the rest      private  3d'\n\
         echo 'you/notes       a wiki that is really just files     private  2w'\n",
    )
    .expect("write fake gh");
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).expect("chmod fake gh");
}

/// The home directory a recording actually runs in, and the one it
/// publishes as.
///
/// **These are the same length, and that is the entire point.** A recording
/// has to say something a reader recognises, but a substitution that
/// changes width breaks any layout the program computed before it: cliclack
/// draws its `note` box sized to the longest line, so shortening a path
/// afterwards leaves the box's right border stranded mid-air. Matched
/// widths make redaction invisible to layout — every box, every wrap, every
/// alignment lands exactly where it did in the real session.
///
/// `/tmp` rather than `$TMPDIR` because macOS hands out
/// `/var/folders/…/T/` there, which no fixed-width string can stand in for.
const RECORDING_HOME: &str = "/tmp/sqdoc";
const PUBLISHED_HOME: &str = "/Users/you";

/// The secreq root inside a recording's home — where `secreq init` would
/// put it, so nothing has to be overridden to make it look right.
fn recording_root() -> std::path::PathBuf {
    std::path::PathBuf::from(RECORDING_HOME).join(".secreq")
}

/// Where a recording's shims live: the default `init` picks.
fn shim_dir() -> std::path::PathBuf {
    recording_root().join("shims")
}

/// Where a recording's sockets live.
///
/// `<root>/run` is the documented fallback `paths::socket_dir` takes when
/// `$XDG_RUNTIME_DIR` is unset — which [`spawn_recording_env`] arranges, for
/// its own reasons, and which conveniently puts the consent socket inside
/// the recording home where a stub daemon can meet the client on it.
fn recording_socket_dir() -> std::path::PathBuf {
    recording_root().join("run")
}

/// A clean [`RECORDING_HOME`], wiped from any previous run.
///
/// Fixed rather than randomised so the width invariant above can hold. The
/// harness runs single-threaded (`--test-threads=1`, which the transcript
/// regen already requires), so two fixtures never share it.
fn reset_recording_home() {
    let home = std::path::Path::new(RECORDING_HOME);
    let _ = std::fs::remove_dir_all(home);
    std::fs::create_dir_all(shim_dir()).expect("create recording home");
    std::fs::create_dir_all(recording_socket_dir()).expect("create recording socket dir");
}

/// The screenshot fixture the `run-gh` recording points at while the
/// consent window is up. Named once so the marker and the guard below can
/// never disagree about it.
const CONSENT_FIXTURE: &str = "02-single-pending";

/// The wait indicator's line, minus the spinner glyph that leads it — the
/// part every frame of the animation has in common.
///
/// A copy of what `daemon::client::spinner_frame` formats, which is what
/// makes it an assertion: reword the indicator and this fixture stops
/// finding it, rather than recording whatever the terminal happens to say
/// during the wait.
const WAIT_LINE_TAIL: &str = " secreq: waiting for approval of `gh` — approve in the popup window";

/// The spinner glyphs the recording photographs, in the order the indicator
/// paints them — the head of the braille cycle in `daemon::client`.
///
/// Four because the docs site dwells on every frame it is handed, so the
/// length of the beat is now carried by the number of frames rather than by
/// a [`Recorder::hold`] on one of them. Four dwells already outlast the
/// single held frame they replace; a hold on top of them would leave the
/// consent window standing there for noticeably longer than it used to,
/// which is the opposite of the point. The point is that the terminal is
/// visibly alive while it waits.
const SPINNER_BEATS: [&str; 4] = ["⠋", "⠙", "⠹", "⠸"];

/// A recording environment for the wrap-and-run path: a `gh` wrap that
/// injects one secret, a `gh` to actually exec, and the wait indicator
/// turned on out loud.
///
/// `wait_indicator = true` is the default, so writing it changes nothing
/// about the run. It is here because the indicator *is* the subject — it is
/// the only thing the terminal has to say during the beat this recording
/// exists for — and a fixture whose subject depends on a default should say
/// which default it is depending on.
fn run_sandbox() -> (Sandbox, std::path::PathBuf) {
    let (sb, bin_dir) = recording_sandbox();
    install_fake_gh(&bin_dir);
    std::fs::write(
        recording_root().join("config.toml"),
        format!(
            r#"shim_dir = "{shim}"
wait_indicator = true

[wraps.gh]
reason = "GitHub API access"

[wraps.gh.env]
GITHUB_TOKEN = "secret://op/Personal/GitHub/credential"
"#,
            shim = shim_dir().display(),
        ),
    )
    .expect("seed recording config");
    (sb, bin_dir)
}

/// A recording environment dressed to look like a machine that has already
/// run `secreq init`: a shim dir where `init` puts it, and that shim dir on
/// `$PATH`.
///
/// The `$PATH` entry is not cosmetic. `wrap` ends by checking whether the
/// shim it just installed is actually reachable, and warns when it isn't —
/// correctly, since a scratch dir never is. Recording that warning would
/// publish a scary paragraph that no reader who ran `init` will ever see,
/// so the fixture satisfies the check instead of hiding its output.
fn wrap_sandbox() -> (Sandbox, std::path::PathBuf) {
    let (sb, bin_dir) = recording_sandbox();
    std::fs::write(
        recording_root().join("config.toml"),
        format!("shim_dir = {:?}\n", shim_dir().display().to_string()),
    )
    .expect("seed recording config");
    (sb, bin_dir)
}

/// A current-format config with one declaration ready for the interactive
/// wrap flow to inject under its own name.
fn declared_secret_wrap_sandbox() -> (Sandbox, std::path::PathBuf) {
    let (sb, bin_dir) = recording_sandbox();
    std::fs::write(
        recording_root().join("config.toml"),
        format!(
            r#"shim_dir = "{}"

[secrets.GITHUB_TOKEN]
ref = "secret://op/Personal/GitHub/credential"
"#,
            shim_dir().display()
        ),
    )
    .expect("seed recording config");
    (sb, bin_dir)
}

/// A fresh recording environment with no secreq config at all — a machine
/// that has installed the binary and nothing more.
fn recording_sandbox() -> (Sandbox, std::path::PathBuf) {
    let sb = Sandbox::new();
    reset_recording_home();
    let bin_dir = install_fake_op(&sb);
    (sb, bin_dir)
}

// ── A daemon that does nothing but wait ──────────────────────────────────

/// The value the stub daemon hands back for whatever it was asked to
/// resolve. Distinctive so that if output masking ever stopped working, the
/// leak would be unmistakable in the recorded frames rather than something a
/// reviewer had to recognise.
const STUB_TOKEN: &str = "gho_recordingStubToken_NOT_A_REAL_CREDENTIAL";

/// A stand-in consent daemon, listening on the recording home's consent
/// socket.
///
/// Every other fixture runs with no daemon at all, because every other
/// fixture records a *configuration* command that never asks for one. This
/// one records the moment a wrap blocks on consent, and there is no way to
/// record that beat without something on the far end of the socket to block
/// against.
///
/// It is a double for the daemon and for nothing else. The client under
/// recording is the real `secreq x`: it really dials the socket, really
/// speaks the framed protocol in `daemon::proto`, really paints its wait
/// indicator, and really exec's `gh` with what comes back. What the stub
/// replaces is the half of the transaction that needs a GPU, a window, and a
/// human — and, crucially, the *timing* of it, since a recording of a wait
/// needs the wait to be long enough to photograph and short enough to
/// finish.
///
/// The handshake is answered by **echoing the CLI's own build id** back at
/// it. `connect_or_spawn` restarts a daemon whose build differs from the
/// CLI's, so a stub that claimed any fixed id would be treated as stale and
/// killed. Echoing is also the honest answer: the stub is compiled from this
/// very tree, in the same `cargo` invocation as the binary it is answering.
struct StubDaemon {
    /// Fires when an ask lands. A real daemon raises its window here.
    asked: Receiver<()>,
    /// Releases the parked ask. A real daemon does this when the user
    /// clicks Approve.
    respond: Sender<()>,
}

impl StubDaemon {
    fn listening() -> StubDaemon {
        Self::with_decision(Decision::Approve, None)
    }

    fn denying(reason: &str) -> StubDaemon {
        Self::with_decision(Decision::Deny, Some(reason.to_owned()))
    }

    fn with_decision(decision: Decision, reason: Option<String>) -> StubDaemon {
        let socket = recording_socket_dir().join("consent.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind stub consent socket");

        let (ask_tx, asked) = std::sync::mpsc::channel();
        let (respond, respond_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || serve_stub(listener, ask_tx, respond_rx, decision, reason));
        StubDaemon { asked, respond }
    }

    /// Let the parked ask through, the way a click on a decision would.
    fn respond(&self) {
        self.respond.send(()).expect("stub daemon stopped serving");
    }
}

fn serve_stub(
    listener: UnixListener,
    asked: Sender<()>,
    respond: Receiver<()>,
    decision: Decision,
    reason: Option<String>,
) {
    // One connection at a time is enough: a single client takes three in
    // sequence (a liveness probe, the `Hello` handshake, then the ask), and
    // never two at once.
    for stream in listener.incoming().flatten() {
        let mut reader = BufReader::new(stream.try_clone().expect("clone stub connection"));
        let mut line = String::new();
        // The liveness probe connects and closes without writing. That is a
        // client behaving correctly, not an error.
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<ClientMsg>(line.trim()) else {
            continue;
        };
        let reply = match msg {
            ClientMsg::Hello { build_id } => DaemonMsg::Hello { build_id },
            ClientMsg::Ask(ask) => {
                asked.send(()).expect("recorder stopped listening");
                respond.recv().expect("recorder never answered the ask");
                DaemonMsg::Decision {
                    decision,
                    // Answer exactly what was asked for, rather than a
                    // hardcoded name: the reply then stays correct if the
                    // fixture's wrap ever declares a different variable.
                    secrets: if decision.approved() {
                        ask.secrets()
                            .iter()
                            .map(|secret| (secret.name.clone(), STUB_TOKEN.to_owned()))
                            .collect()
                    } else {
                        std::collections::HashMap::new()
                    },
                    rule_id: None,
                    rule_name: None,
                    reason: reason.clone(),
                    declared_by: None,
                    // A manual approve has no rule behind it, so nothing
                    // to attribute per secret.
                    approvers: std::collections::BTreeMap::new(),
                }
            }
            _ => DaemonMsg::Ok,
        };
        let mut writer = stream;
        let body = serde_json::to_string(&reply).expect("serialize stub reply");
        let _ = writeln!(writer, "{body}");
        let _ = writer.flush();
    }
}

/// Spawn a run inside [`RECORDING_HOME`] with the shim dir and the fake
/// `op` on `$PATH`, publishing as [`PUBLISHED_HOME`].
fn spawn_recording(sb: &Sandbox, bin_dir: &Path, args: &[&str]) -> PtyRun {
    spawn_recording_env(sb, bin_dir, args, &[])
}

/// [`spawn_recording`] with extra environment, for flows that need a
/// variable the sandbox deliberately strips.
///
/// The [`Sandbox`] still supplies the isolation set — the live sockets it
/// unsets, the no-daemon default, the legacy XDG probes. Only the two paths
/// a transcript actually *prints* are moved into the fixed-width home.
fn spawn_recording_env(
    sb: &Sandbox,
    bin_dir: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> PtyRun {
    let path = std::env::var("PATH").unwrap_or_default();
    let mut cmd = sb.cmd(args);
    cmd.env("HOME", RECORDING_HOME);
    cmd.env("SECREQ_HOME", recording_root());
    // `Sandbox` pins `$XDG_RUNTIME_DIR` into its tempdir so a test can't
    // bind sockets beside a developer's live daemon. Recordings *print*
    // that path — `ssh setup` writes it into an `IdentityAgent` line — and
    // no fixed-width string can stand in for a `/var/folders/…` tempdir.
    // Unsetting it takes the documented `<root>/run` fallback instead,
    // which is both what a reader on macOS gets and already inside the
    // recording home, so it redacts with everything else.
    cmd.env_remove("XDG_RUNTIME_DIR");
    cmd.env(
        "PATH",
        format!("{}:{}:{path}", shim_dir().display(), bin_dir.display()),
    );
    for (key, value) in env {
        cmd.env(key, value);
    }
    let mut run = PtyRun::spawn_with(cmd);
    run.redact(RECORDING_HOME, PUBLISHED_HOME);
    run
}

// ── Fixtures ──────────────────────────────────────────────────────────────

/// Not `#[ignore]`d: the width invariant is what keeps every recorded box
/// and every wrapped line honest, and it is one string edit away from being
/// broken silently. A normal `cargo test` should catch that, not a reviewer
/// squinting at a re-recorded transcript.
#[test]
fn recording_home_and_published_home_are_the_same_width() {
    assert_eq!(
        RECORDING_HOME.len(),
        PUBLISHED_HOME.len(),
        "redaction must not change text width — a shorter or longer \
         replacement moves every box border and line wrap that the CLI \
         laid out around the real path"
    );
}

/// Not `#[ignore]`d, for the same reason as the width invariant above: it
/// reads the *committed* recordings, so CI catches a leak without a pty.
///
/// [`PtyRun::redact`] is a plain string replacement over the rendered screen,
/// which means it only fires when the sandbox path survives layout in one
/// piece. It doesn't when a line wraps mid-path — and that is not
/// hypothetical: wrapping the `init` PATH note to fit an 80-column terminal
/// split `/tmp/sqdoc/.zshrc` across two lines and published the sandbox path
/// to secreq.dev, in a recording whose whole point was to look like a real
/// user's machine.
///
/// The fix was to keep paths unbroken (`term::wrap_note_text` sets
/// `break_words(false)`) and short (`abbreviate_home`), but the reason that
/// bug shipped is that nothing checked. Now something does.
/// Paths that must never reach a published recording.
///
/// `RECORDING_HOME` is the dressed sandbox every fixture runs in. The other two
/// are where the *real* tempdirs live — the fake `op` and `gh` binaries sit in
/// one, so a flow that ever printed a resolved binary path would leak a
/// developer's machine rather than the tidy home the recordings pretend to.
/// None of them appears in a committed recording today; they are here so that
/// stays true by test rather than by luck.
const SANDBOX_NEEDLES: &[&str] = &[RECORDING_HOME, "/var/folders/", "/tmp/.tmp"];

#[test]
fn recordings_leak_no_sandbox_paths() {
    let dir = std::path::Path::new(OUT_DIR);
    let mut leaked = Vec::new();

    // Every frame, from the JSON — not the `.txt`, which holds only the final
    // screen. The site replays all of them, so checking the last one meant
    // `wrap-gh`'s other nine frames were published unexamined: the guard was
    // reading the one screen a leak was least likely to be on.
    for entry in std::fs::read_dir(dir).expect("transcript dir must exist") {
        let path = entry.expect("readable dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("readable transcript");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("transcript is JSON");
        let steps = doc["steps"].as_array().cloned().unwrap_or_default();

        for (index, step) in steps.iter().enumerate() {
            let Some(lines) = step["lines"].as_array() else {
                continue;
            };
            for (lineno, spans) in lines.iter().enumerate() {
                // Spans are re-joined before matching: redaction is a literal
                // string replace, and a path split across two colour runs
                // would hide from a per-span search exactly the way one split
                // across two *rows* hid from the original bug.
                let line: String = spans
                    .as_array()
                    .map(|spans| {
                        spans
                            .iter()
                            .filter_map(|span| span["t"].as_str())
                            .collect::<String>()
                    })
                    .unwrap_or_default();
                for needle in SANDBOX_NEEDLES {
                    if line.contains(needle) {
                        leaked.push(format!(
                            "{} frame {index}, line {}: {line}",
                            path.display(),
                            lineno + 1
                        ));
                    }
                }
            }
        }
    }

    assert!(
        leaked.is_empty(),
        "\n{} line(s) still name a sandbox path ({SANDBOX_NEEDLES:?}) after \
         redaction:\n\n  {}\n\n\
         Redaction is a literal string replace, so this means the path did not \
         survive layout intact — almost certainly wrapped across two lines. \
         Shorten it for display (`daemon::ui::abbreviate_home`) or keep the \
         wrapper from breaking it, then re-record:\n  \
         cargo test --test cli_transcripts -- --ignored --nocapture --test-threads=1\n",
        leaked.len(),
        leaked.join("\n  "),
    );
}

/// Not `#[ignore]`d: the general form of the note-box bug, checked against the
/// committed recordings so CI catches it without a pty.
///
/// A cliclack box is sized to its longest line and neither wraps nor
/// truncates, so one over-wide line doesn't degrade — it runs off the right
/// edge, the terminal re-wraps it, and every following row's border lands on a
/// line of its own. That is what `init`'s PATH note did at 80 columns, around
/// the one thing `init` most wants read carefully. The recordings are pinned
/// to [`COLS`], so "did any line overflow" is answerable from the artifact.
///
/// Width here is display columns, not bytes: the box-drawing characters these
/// transcripts are full of are three bytes each, and `len()` would call every
/// correct box a violation.
#[test]
fn every_recorded_line_fits_the_pty_width() {
    fn display_width(line: &str) -> usize {
        // Nothing in these recordings is CJK or emoji; the wide-character case
        // is here so a future fixture with one doesn't quietly under-count.
        line.chars()
            .map(|c| if matches!(c, '\u{1100}'..='\u{115F}' | '\u{2E80}'..='\u{A4CF}' | '\u{AC00}'..='\u{D7A3}' | '\u{F900}'..='\u{FAFF}' | '\u{FF00}'..='\u{FF60}' | '\u{1F300}'..='\u{1FAFF}') { 2 } else { 1 })
            .sum()
    }

    let mut over = Vec::new();
    for entry in std::fs::read_dir(OUT_DIR).expect("transcript dir must exist") {
        let path = entry.expect("readable dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("txt") {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("readable transcript");
        for (lineno, line) in body.lines().enumerate() {
            let width = display_width(line);
            if width > COLS as usize {
                over.push(format!(
                    "{}:{} — {width} columns\n    {line}",
                    path.display(),
                    lineno + 1
                ));
            }
        }
    }

    assert!(
        over.is_empty(),
        "\n{} recorded line(s) exceed the {COLS}-column pty:\n\n  {}\n\n\
         A real terminal re-wraps these, which corrupts any box drawn around \
         them. Wrap the text before handing it to cliclack \
         (`term::wrap_note_text` / `term::wrap_log_text`) and shorten \
         interpolated paths (`daemon::ui::abbreviate_home`), then re-record:\n  \
         cargo test --test cli_transcripts -- --ignored --nocapture --test-threads=1\n",
        over.len(),
        over.join("\n  "),
    );
}

/// Not `#[ignore]`d: a `gui` marker is a promise that a screenshot exists,
/// and the two halves of that promise are kept in different directories by
/// different harnesses. Renaming a screenshot fixture is a perfectly
/// ordinary thing to do to `dev-docs/ui-screenshots/`, and without this it
/// would leave a recording pointing at nothing — a marker the player fires
/// happily, a listener that finds no image, and a blank space on secreq.dev
/// where the consent window was supposed to appear. Nothing would fail.
#[test]
fn gui_ids_name_real_screenshot_fixtures() {
    let mut missing = Vec::new();

    for entry in std::fs::read_dir(OUT_DIR).expect("transcript dir must exist") {
        let path = entry.expect("readable dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("readable transcript");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("transcript is json");
        for step in doc["steps"].as_array().into_iter().flatten() {
            if step["kind"] != "gui" {
                continue;
            }
            let id = step["id"]
                .as_str()
                .expect("a gui marker must name a screenshot fixture");
            if !Path::new(common::SCREENSHOT_DIR).join(id).is_dir() {
                missing.push(format!("{}: gui marker names {id:?}", path.display()));
            }
        }
    }

    // A marker's show and its hide name the same fixture, so an unresolved
    // id would otherwise be reported once per marker rather than once.
    missing.sort();
    missing.dedup();

    assert!(
        missing.is_empty(),
        "\n{} recorded gui marker(s) name a screenshot fixture that no longer \
         exists under {}:\n\n  {}\n\n\
         Either restore the fixture's directory or re-record the transcript \
         against the fixture that replaced it:\n  \
         cargo test --test cli_transcripts -- --ignored --nocapture --test-threads=1\n",
        missing.len(),
        common::SCREENSHOT_DIR,
        missing.join("\n  "),
    );
}

/// `secreq wrap gh` with no flags — the path the docs recommend and the one
/// nothing else demonstrates: pick what the wrap does, pick a provider, name
/// the env var, paste the locator, watch it get checked.
#[test]
#[ignore = "records a docs transcript; run with --ignored"]
fn wrap_interactive_inject_secrets() {
    let (sb, bin_dir) = wrap_sandbox();
    let mut rec = Recorder::new(spawn_recording(&sb, &bin_dir, &["wrap", "gh"]));

    rec.expect("What should this wrap do?").enter();
    rec.expect("Provider for the next env var")
        .select_item("op");
    rec.expect("Environment variable name")
        .type_line("GITHUB_TOKEN");
    // The native reference, pasted, because that is what "Copy Secret
    // Reference" puts on the clipboard and what `normalize_pasted_locator`
    // is written to peel. Recording the bare `Personal/GitHub/credential`
    // showed a reader hand-retyping the interesting part of a string they
    // already have, and quietly implied the `op://` form would be rejected.
    rec.expect("Locator")
        .paste_line("op://Personal/GitHub/credential");
    rec.expect("Locator resolves").hold(900);
    rec.expect("Add another env var?").enter();
    rec.expect("Reason (shown in consent prompt)")
        .type_line("GitHub API access");

    rec.finish(Transcript::new(
        "wrap-gh",
        "secreq wrap gh",
        "Authoring a wrap by answering questions. Every value is checked as \
         you go — the locator is resolved against your store before the wrap \
         is written, so a typo fails here rather than the first time you run \
         <code>gh</code>.",
    ));
}

/// Selecting a declaration offers the typo-proof form: inject it under the
/// declaration's own name without asking the user to type that name again.
#[test]
#[ignore = "records a docs transcript; run with --ignored"]
fn wrap_interactive_injects_a_declaration_under_its_own_name() {
    let (sb, bin_dir) = declared_secret_wrap_sandbox();
    let mut rec = Recorder::new(spawn_recording(&sb, &bin_dir, &["wrap", "gh"]));

    rec.expect("What should this wrap do?").enter();
    rec.expect("Use a declared or previously used secret?")
        .select_item("secret://GITHUB_TOKEN");
    rec.expect("Inject under the declaration's own name")
        .enter();
    rec.expect("Add another env var?").enter();
    rec.expect("Reason (shown in consent prompt)")
        .type_line("GitHub API access");

    rec.finish(Transcript::new(
        "wrap-declared-secret",
        "secreq wrap gh",
        "A declared secret can be injected under its own name without typing \
         the environment variable again. The resulting wrap records \
         <code>env_secrets = [\"GITHUB_TOKEN\"]</code>.",
    ));
}

/// `secreq init` — the first thing anyone runs, and the one flow whose
/// whole job is to ask permission before touching your dotfiles. The
/// transcript exists to show that: the exact block, in the exact file,
/// behind a prompt.
#[test]
#[ignore = "records a docs transcript; run with --ignored"]
fn init_first_time_setup() {
    let (sb, bin_dir) = recording_sandbox();
    // A machine that has not run `init` does not have the shim dir on
    // `$PATH` — that is the whole reason `init` has something to offer. The
    // shared dressing prepends it for the `wrap` fixtures, so this one
    // overrides `$PATH` back to a fresh machine's. Without this, `init`
    // takes its "on PATH, but via the wrong file" branch and records a
    // paragraph about `brew shellenv` shadowing that no new user ever sees.
    let fresh_path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // `Sandbox` strips `$SHELL` so a stray test can never edit a real
    // developer's rc files. This fixture *is* about that step, and its
    // `$HOME` is the recording home, so the block lands in a scratch
    // `.zshrc`.
    let mut rec = Recorder::new(spawn_recording_env(
        &sb,
        &bin_dir,
        &["init"],
        &[("SHELL", "/bin/zsh"), ("PATH", &fresh_path)],
    ));

    rec.expect("Where should secreq drop PATH shims?").enter();
    rec.expect("Append it?").answer(true);
    rec.expect("Also set up secreq as your SSH agent?")
        .answer(false);

    rec.finish(Transcript::new(
        "init",
        "secreq init",
        "First-time setup. Installing secreq changes nothing on your \
         <code>PATH</code> — <code>init</code> shows you the exact block it \
         wants to add and the exact file it would go in, then waits for an \
         answer.",
    ));
}

/// `secreq ssh setup` — the guided flow that points SSH clients at
/// secreq's agent socket. `ssh-agent.md` documents the config block by
/// hand and never mentions this command, which is the one a reader should
/// actually run.
///
/// An identity is seeded so the flow reaches its subject: with none
/// configured, step 1 detours into `ssh add` (key entry, provider
/// discovery) and the wiring — the point of the transcript — ends up
/// buried under it. `ssh add` deserves its own recording.
#[test]
#[ignore = "records a docs transcript; run with --ignored"]
fn ssh_setup_guided() {
    let (sb, bin_dir) = recording_sandbox();
    std::fs::write(
        recording_root().join("config.toml"),
        format!(
            r#"shim_dir = "{shim}"

[ssh.github]
reason = "git pushes to github"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample me@mac"
private_key = "secret://op/Private/gh-key/private key"
"#,
            shim = shim_dir().display(),
        ),
    )
    .expect("seed recording config");

    let mut rec = Recorder::new(spawn_recording(&sb, &bin_dir, &["ssh", "setup"]));

    rec.expect("Add another identity?").answer(false);
    rec.expect("Install the login service").answer(false);
    rec.expect("How should SSH find the secreq agent?").enter();
    rec.expect("it?").answer(true);
    rec.expect("Test that the agent can sign now?")
        .answer(false);

    rec.finish(Transcript::new(
        "ssh-setup",
        "secreq ssh setup",
        "Wiring SSH at secreq's agent socket. Like every other flow that \
         edits a file you own, it shows the block and the path first and \
         waits for an answer.",
    ));
}

/// `secreq wrap op` taking the gate-only branch: consent is still required,
/// but nothing is resolved or injected. The model for gating a tool that
/// holds its own credentials.
#[test]
#[ignore = "records a docs transcript; run with --ignored"]
fn wrap_interactive_gate_only() {
    let (sb, bin_dir) = wrap_sandbox();
    let mut rec = Recorder::new(spawn_recording(&sb, &bin_dir, &["wrap", "op"]));

    rec.expect("What should this wrap do?")
        .select_item("Gate only");
    rec.expect("Reason (shown in consent prompt)")
        .type_line("gate the 1Password CLI itself");

    rec.finish(Transcript::new(
        "wrap-gate-only",
        "secreq wrap op",
        "A gate-only wrap injects nothing — it just puts the consent prompt \
         in front of a command. Use it for tools that already hold their own \
         credentials.",
    ));
}

/// A wrapped command actually blocking on consent — the moment the whole
/// product is about, and the only recording here that is not a
/// configuration flow.
///
/// Every other fixture records secreq being *set up*. This one records the
/// day after: you type `gh repo list`, the shim `secreq wrap` installed
/// turns it into `secreq x gh`, and the command stops. What the terminal
/// shows for the length of that stop is one line — the wait indicator — and
/// what the *user* is looking at is a window this pty cannot photograph.
/// Hence the [`Step::Gui`] markers around the wait: the recording says which
/// screenshot fixture belongs to that beat, and whoever replays it can put
/// the two side by side.
///
/// That one line is recorded several times over rather than once and held.
/// The terminal has nothing to say during the wait, but it is not *dead* —
/// the spinner turns — and a recording that stops on a single frame plays
/// back as a terminal that has hung, with the consent window then vanishing
/// for no visible reason. Several beats of the spinner make the wait read as
/// a wait, and the dismissal as something a person did. See
/// [`Recorder::expect_spinner`].
///
/// The title is `gh repo list` because that is the command being
/// demonstrated — the shim is what makes typing it mean `secreq x gh repo
/// list`, and the shim is not the subject here. Recording the shim's own
/// `exec` would put an extra `/bin/sh` in the process chain and change
/// nothing a reader sees.
#[test]
#[ignore = "records a docs transcript; run with --ignored"]
fn run_gh_blocking_on_consent() {
    let (sb, bin_dir) = run_sandbox();
    // Bound before the client is spawned: `connect_or_spawn` probes the
    // socket first and would otherwise try to *start* a daemon.
    let daemon = StubDaemon::listening();
    let mut rec = Recorder::new(spawn_recording_env(
        &sb,
        &bin_dir,
        &["x", "gh", "repo", "list"],
        // The sandbox disables the daemon by default, which is right for
        // every other fixture and fatal for this one: a disabled daemon
        // fails closed on the spot, and there is no wait to record. Emptied
        // rather than removed because the only lever here layers extra
        // environment on — and the kill-switch is defined as *non-empty*
        // meaning off, so an empty value re-enables it exactly.
        &[(secreq::daemon::client::NO_DAEMON_ENV, "")],
    ));

    // Wait on the daemon rather than on the screen: the indicator is only
    // worth photographing once the ask has genuinely arrived and the wrap is
    // genuinely blocked on it.
    rec.await_ask(&daemon);
    rec.gui_show(CONSENT_FIXTURE);
    rec.expect_spinner(&SPINNER_BEATS, WAIT_LINE_TAIL);
    daemon.respond();
    rec.gui_hide(CONSENT_FIXTURE);

    rec.finish(Transcript::new(
        "run-gh",
        "gh repo list",
        "The day after setup. <code>gh</code> is a shim, so the command \
         stops and waits while secreq asks you — and the moment you approve, \
         the real <code>gh</code> runs with the token already in its \
         environment. Nothing was exported, and nothing stayed behind.",
    ));
}

#[test]
#[ignore = "records a docs transcript; run with --ignored"]
fn run_gh_denied_with_reason() {
    let (sb, bin_dir) = run_sandbox();
    let daemon = StubDaemon::denying("Wrong repository");
    let mut rec = Recorder::new(spawn_recording_env(
        &sb,
        &bin_dir,
        &["x", "gh", "repo", "delete", "acme/api"],
        &[(secreq::daemon::client::NO_DAEMON_ENV, "")],
    ));

    rec.await_ask(&daemon);
    rec.gui_show("51-pending-denial-reason");
    rec.expect_spinner(&SPINNER_BEATS, WAIT_LINE_TAIL);
    daemon.respond();
    rec.gui_hide("51-pending-denial-reason");

    rec.finish_denied(Transcript::new(
        "run-gh-denied",
        "gh repo delete acme/api",
        "A denial can explain itself. The reason returns to the wrap client, \
         appears in the terminal, and is recorded in the audit log.",
    ));
}
