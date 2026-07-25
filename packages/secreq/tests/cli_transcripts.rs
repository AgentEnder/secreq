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

use std::path::Path;
use std::time::Duration;

use common::pty::{PtyRun, COLS, ROWS};
use common::Sandbox;
use serde_json::{json, Value};

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
fn run_json(text: &str, fg: Option<String>, bg: Option<String>, style: u8) -> Value {
    let mut out = json!({ "t": text });
    let map = out.as_object_mut().expect("run is an object");
    if let Some(fg) = fg {
        map.insert("f".into(), json!(fg));
    }
    if let Some(bg) = bg {
        map.insert("b".into(), json!(bg));
    }
    if style != 0 {
        map.insert("s".into(), json!(style));
    }
    out
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
fn color_json(color: vt100::Color) -> Option<String> {
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
fn frame_lines(screen: &vt100::Screen) -> Vec<Value> {
    let mut lines: Vec<Value> = Vec::new();

    for row in 0..ROWS {
        let mut runs: Vec<Value> = Vec::new();
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
                color_json(cell.fgcolor()),
                color_json(cell.bgcolor()),
                style_of(cell),
            );

            match &key {
                Some(current) if *current == this => text.push_str(glyph),
                Some(current) => {
                    let (fg, bg, style) = current.clone();
                    runs.push(run_json(&text, fg, bg, style));
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
            runs.push(run_json(&text, fg, bg, style));
        }

        // Trailing whitespace on a line is padding, not content.
        trim_trailing_blank_runs(&mut runs);
        lines.push(json!(runs));
    }

    while lines
        .last()
        .and_then(|line| line.as_array())
        .is_some_and(|runs| runs.is_empty())
    {
        lines.pop();
    }
    lines
}

fn trim_trailing_blank_runs(runs: &mut Vec<Value>) {
    while let Some(last) = runs.last_mut() {
        let text = last["t"].as_str().unwrap_or("").trim_end().to_owned();
        if text.is_empty() {
            runs.pop();
        } else {
            last["t"] = json!(text);
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
fn frame_text(lines: &[Value]) -> String {
    lines
        .iter()
        .map(|line| {
            line.as_array()
                .map(|runs| {
                    runs.iter()
                        .filter_map(|run| run["t"].as_str())
                        .collect::<String>()
                })
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Driving a session ─────────────────────────────────────────────────────

/// Records a live session as it is driven.
struct Recorder {
    run: PtyRun,
    steps: Vec<Value>,
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
        self.steps.push(json!({
            "kind": "frame",
            "lines": frame_lines(&screen),
        }));
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
        self.steps.push(json!({
            "kind": "frame",
            "lines": frame_lines(&screen),
        }));
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
        let last = self.steps.last_mut().expect("hold needs a frame");
        assert_eq!(last["kind"], "frame", "hold applies to a frame");
        last["hold"] = json!(ms);
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
        self.steps.push(json!({
            "kind": "type",
            "text": text,
            "row": row,
            "col": col,
        }));
        self.enter()
    }

    fn enter(&mut self) -> &mut Self {
        self.steps.push(json!({ "kind": "key", "key": "Enter" }));
        self.run.press_enter();
        self
    }

    /// Answer a cliclack confirm. `y`/`n` set the value *and* submit in one
    /// keystroke, so this deliberately does not follow with an Enter.
    fn answer(&mut self, yes: bool) -> &mut Self {
        let key = if yes { "y" } else { "n" };
        self.steps.push(json!({ "kind": "key", "key": key }));
        self.run.write_bytes(key.as_bytes());
        self
    }

    fn down(&mut self) -> &mut Self {
        self.steps.push(json!({ "kind": "key", "key": "Down" }));
        self.run.press_arrow_down();
        self
    }

    /// Wait for the command to exit cleanly, photograph the final screen,
    /// and write the recording out.
    fn finish(mut self, transcript: Transcript) {
        let status = self.run.wait_exit(STEP_TIMEOUT);
        assert!(
            status.success(),
            "`{}` exited with {status:?}; screen was:\n{}",
            transcript.command,
            self.run.screen().contents()
        );
        self.run.wait_until_settled(SETTLE, STEP_TIMEOUT);
        let screen = self.run.screen();
        self.steps.push(json!({
            "kind": "frame",
            "lines": frame_lines(&screen),
        }));

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

/// Write `<id>.json` (what the site replays) and `<id>.txt` (the final
/// frame, so a reviewer can read the diff without decoding styled runs).
fn write_transcript(transcript: &Transcript, steps: &[Value]) {
    let out_dir = Path::new(OUT_DIR);
    std::fs::create_dir_all(out_dir).expect("create transcript dir");

    let doc = json!({
        "id": transcript.id,
        "command": transcript.command,
        "caption": transcript.caption,
        "cols": COLS,
        "steps": steps,
    });
    let body = serde_json::to_string_pretty(&doc).expect("serialize transcript");
    std::fs::write(
        out_dir.join(format!("{}.json", transcript.id)),
        format!("{body}\n"),
    )
    .expect("write transcript json");

    let final_frame = steps
        .iter()
        .rev()
        .find(|step| step["kind"] == "frame")
        .and_then(|step| step["lines"].as_array())
        .map(|lines| frame_text(lines))
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

/// A clean [`RECORDING_HOME`], wiped from any previous run.
///
/// Fixed rather than randomised so the width invariant above can hold. The
/// harness runs single-threaded (`--test-threads=1`, which the transcript
/// regen already requires), so two fixtures never share it.
fn reset_recording_home() {
    let home = std::path::Path::new(RECORDING_HOME);
    let _ = std::fs::remove_dir_all(home);
    std::fs::create_dir_all(shim_dir()).expect("create recording home");
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
        recording_root().join("wraps.json5"),
        format!("{{\n  $shim_dir: \"{}\",\n}}\n", shim_dir().display()),
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
    rec.expect("Locator")
        .type_line("Personal/GitHub/credential");
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
        recording_root().join("wraps.json5"),
        format!(
            r#"{{
  $shim_dir: "{shim}",
  ssh: {{
    github: {{
      $reason: "git pushes to github",
      public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample me@mac",
      private_key: "secret://op/Private/gh-key/private key",
    }},
  }},
}}
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
