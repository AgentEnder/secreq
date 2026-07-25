# CLI transcripts

Recorded sessions of secreq's **interactive terminal flows**, produced by
`packages/secreq/tests/cli_transcripts.rs` and published by the docs site
through the `::term{id=…}` markdown directive.

This directory is the CLI counterpart to `dev-docs/ui-screenshots/`: the
screenshot harness renders the real windows, this one drives the real
binary. Nothing in either is hand-authored, for the same reason — a
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
| `<id>.json` | The recording. Steps (`frame` / `type` / `key`) with per-cell styling. This is what the docs site replays. |
| `<id>.txt` | The final frame as plain text. Not published — it exists so a reviewer can read a diff without decoding styled runs. |

There is no `manifest.json`. Unlike a PNG, a recording can describe
itself, so each JSON carries its own command and caption and the site's
Vite plugin simply indexes the directory.

## Fixtures

| Id | Fixture function | What it shows |
|---|---|---|
| `init` | `init_first_time_setup` | First-time setup: choosing a shim dir, and the PATH block shown in full before it touches a dotfile. |
| `wrap-gh` | `wrap_interactive_inject_secrets` | `secreq wrap gh` with no flags — provider picker, env var name, locator, and the resolvability check that runs before the wrap is written. |
| `wrap-gate-only` | `wrap_interactive_gate_only` | The gate-only branch of `secreq wrap`: consent required, nothing injected. |
| `ssh-setup` | `ssh_setup_guided` | `secreq ssh setup` wiring SSH clients at the agent socket, showing the managed block and the file first. |

## A caption is published documentation

`Transcript::new(id, command, caption)` — the third argument is the
figcaption that ships on secreq.dev wherever the recording appears, not a
test comment. Write it for someone *using* secreq; `<code>` and `<b>` are
the markup honoured. This table is the contributor-facing description of
the same recording.

## Two invariants worth knowing before you add a fixture

**Redaction must not change text width.** Recordings run in a fixed home
(`/tmp/sqdoc`) and publish as another (`/Users/you`) — deliberately the
same length. Text a program merely *printed* reflows fine at any width,
but text it *positioned* does not: `cliclack::note` sizes its box to the
longest line, so a shorter substitution leaves the right border stranded
in mid-air. A non-ignored test enforces the widths match.

**The sandbox is dressed, not stubbed.** A fake `op` on `$PATH` answers
`op read`, so the built-in 1Password provider is genuinely exercised and
"Locator resolves ✓" is a real check that really passed. The shim dir is
genuinely on `$PATH`, so `wrap`'s "this isn't on your PATH" warning
genuinely doesn't fire. Satisfy a check rather than hiding its output —
if a warning appears in a recording, the fix is to make the condition
false, not to redact the text.

## Adding a fixture

1. Write it in `cli_transcripts.rs` using `Recorder`: `expect()` waits for
   a prompt *and* photographs the screen, `type_line()` records typing
   with the cell it landed on, `select_item()` drives a picker by name
   rather than by counted arrow presses (the built-in provider list
   differs by platform).
2. Regenerate, and **read the `.txt`**. It is the fastest way to catch a
   leaked path, a spurious warning, or a flow that took a branch you
   didn't intend.
3. Add a row to the table above.
4. Reference it from a doc with `::term{id=<id>}`. An id with no
   recording fails the docs build rather than publishing a hole.
