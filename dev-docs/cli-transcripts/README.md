# CLI transcripts

Recorded sessions of secreq's **interactive terminal flows**, produced by
`packages/secreq/tests/cli_transcripts.rs` and published by the docs site
through the `::term{id=…}` markdown directive.

This directory is the CLI counterpart to `dev-docs/ui-screenshots/`: the
screenshot harness renders the real windows, this one drives the real
binary. Nothing in either is hand-authored, for the same reason: a
hand-typed transcript of what a prompt "probably says" starts rotting the
day someone rewords the prompt, and nobody notices until a reader follows
along and the screen doesn't match.

## Regenerating

```sh
cargo test --test cli_transcripts -- --ignored --nocapture --test-threads=1
```

`#[ignore]`-gated so a normal `cargo test` doesn't spawn ptys.
`--test-threads=1` is required: every fixture runs in the same fixed
recording home (see below).

## Files

Each fixture writes two files:

| File | What it is |
|---|---|
| `<id>.json` | The recording. Steps (`frame` / `type` / `key` / `gui`) with per-cell styling. This is what the docs site replays. |
| `<id>.txt` | The final frame as plain text. Not published; it exists so a reviewer can read a diff without decoding styled runs. |

Nothing describes a recording from outside it. Unlike a PNG, a recording
can describe itself, so each JSON carries its own command and caption and
the site's Vite plugin just indexes the directory. (The screenshots
reach the same end differently: a PNG cannot hold a caption, so each
fixture's `layout.json` holds it beside the renders.)

## Fixtures

| Id | Fixture function | What it shows |
|---|---|---|
| `init` | `init_first_time_setup` | First-time setup: choosing a shim dir, and the PATH block shown in full before it touches a dotfile. |
| `wrap-gh` | `wrap_interactive_inject_secrets` | `secreq wrap gh` with no flags: provider picker, env var name, locator, and the resolvability check that runs before the wrap is written. |
| `wrap-gate-only` | `wrap_interactive_gate_only` | The gate-only branch of `secreq wrap`: consent required, nothing injected. |
| `ssh-setup` | `ssh_setup_guided` | `secreq ssh setup` wiring SSH clients at the agent socket, showing the managed block and the file first. |
| `run-gh` | `run_gh_blocking_on_consent` | A wrapped `gh repo list` actually blocking on consent: the wait indicator while the window is up, then the real command running with the token injected. The only fixture here that is not a configuration flow, and the only one with `gui` markers. |
| `run-gh-denied` | `run_gh_denied_with_reason` | A wrapped destructive command denied with an optional explanation; the client prints the reason and does not run the command. |

## The `gui` marker, for the half that isn't in the terminal

A recording of a wrap blocking on consent is a recording of a terminal
doing almost nothing. The interesting half is a window the pty cannot
photograph, and one that `dev-docs/ui-screenshots/` has already
photographed properly, six ways, under a fixture id.

So the harness records a seam rather than a picture: a `gui` step
carrying `action` (`show` / `hide`) and the `id` of a screenshot fixture
directory. The player dispatches it as a `secreq-gui` event on the
`<secreq-terminal>` element and draws nothing itself, so a recording with
markers in it still replays correctly on a page with nowhere to put a
window: with no listener, a marker is just a beat.

`gui_ids_name_real_screenshot_fixtures` (not `#[ignore]`d) checks every
recorded id against the directories on disk. Renaming a screenshot
fixture is an ordinary thing to do, and without that check it would leave
a marker pointing at nothing: an event fired, no image found, and a blank
space on the docs site where the consent window should have been. Nothing
else would fail.

## A caption is published documentation

In `Transcript::new(id, command, caption)`, the third argument is the
figcaption that ships on the docs site wherever the recording appears, not a
test comment. Write it for someone *using* secreq; `<code>` and `<b>` are
the markup honoured. This table is the contributor-facing description of
the same recording.

## Three invariants to respect when adding a fixture

**No line may exceed the pty width.** `cliclack::note` sizes its box to
the longest line it is given and neither wraps nor truncates, so one
over-wide line doesn't degrade. It runs off the right edge, the terminal
re-wraps it, and every following row's border lands on a line of its own.
`log::warning` / `log::info` / `outro` don't wrap either; they break
mid-word. Put anything that interpolates a path through
`term::wrap_note_text` or `term::wrap_log_text`, keep a note's *title*
short and constant, and shorten paths with `daemon::ui::abbreviate_home`.
`every_recorded_line_fits_the_pty_width` enforces this against the
committed `.txt` files, in display columns rather than bytes, since the
box-drawing characters here are three bytes each.

**Redaction must not change text width.** Recordings run in a fixed home
(`/tmp/sqdoc`) and publish as another (`/Users/you`), chosen to be the
same length. Text a program merely *printed* reflows fine at any width,
but text it *positioned* does not: `cliclack::note` sizes its box to the
longest line, so a shorter substitution leaves the right border stranded
in mid-air. A non-ignored test enforces the widths match.

Redaction is a literal string replace, so it only fires when the sandbox
path survives layout in one piece, which it does not when a line wraps
mid-path. That is not hypothetical: wrapping `init`'s PATH note to fit 80
columns split `/tmp/sqdoc/.zshrc` across two lines and published the
sandbox path to the docs site. Both wrappers set `break_words(false)` for
this reason, and `recordings_leak_no_sandbox_paths` fails if
`RECORDING_HOME` ever survives into a committed `.txt` again.

**The sandbox is dressed, not stubbed.** A fake `op` on `$PATH` answers
`op read`, so the built-in 1Password provider really runs and
"Locator resolves ✓" is a check that really passed. The shim dir is
actually on `$PATH`, which is why `wrap`'s "this isn't on your PATH" warning
never fires. Satisfy a check rather than hiding its output:
if a warning appears in a recording, the fix is to make the condition
false, not to redact the text.

The one deliberate double is the **consent daemon** in `run-gh`, and it
is a double for the daemon and nothing else: the client under recording
really dials the socket, really speaks the protocol in
`src/daemon/proto.rs`, really paints its wait indicator, and really
exec's the command with what comes back. What a stub replaces is the half
that needs a GPU, a window and a human, plus the *timing* of it, since a
recorded wait has to be long enough to photograph and short enough to
finish. It parks the ask until the recorder has its frames, then approves.

## Adding a fixture

1. Write it in `cli_transcripts.rs` using `Recorder`: `expect()` waits for
   a prompt *and* photographs the screen, `type_line()` records typing
   with the cell it landed on, `select_item()` drives a picker by name
   rather than by counted arrow presses (the built-in provider list
   differs by platform). Use `expect_transient()` only for a screen that
   is never going to stop changing (a spinner), since it is the one that
   skips the settle wait, and `expect_spinner()` when the point is that
   the screen *keeps* changing: it photographs one frame per named glyph,
   so a wait plays back as a wait rather than as a still.
2. Regenerate, and **read the `.txt`**. It is the fastest way to catch a
   leaked path, a spurious warning, or a flow that took a branch you
   didn't intend.
3. Add a row to the table above.
4. Reference it from a doc with `::term{id=<id>}`. An id with no
   recording fails the docs build rather than publishing a hole.
