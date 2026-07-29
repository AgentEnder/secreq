# Reference

## Verification map

Never settle a factual question by comparing two pages. Go to the file that
owns the answer. Each row below is a real defect that reached `docs/` and
survived review.

| Claim about…                        | Settled by                                              | Defect it produced                                                                          |
| ----------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Where a file lives                  | `packages/secreq/src/paths.rs`                          | Two pages put `audit.log` under `$XDG_STATE_HOME`; it is `~/.secreq/audit.log`.             |
| A command or flag existing          | `docs/cli-reference.md` (generated) or `src/cli.rs`     | `secreq import` / `secreq store` documented years after the verbs were removed.             |
| A capability being unused           | Who calls it in `src/`                                  | `providers.md` called `store` "not exposed via the CLI"; `run --prompt-unresolved` uses it. |
| Prebuilt binaries, release, signing | `.github/workflows/release.yml`                         | `platform-support.md` said none existed while `install.md` documented four.                 |
| Who writes an audit row             | `commands.rs`, `daemon/ssh_agent.rs`, `daemon/state.rs` | —                                                                                           |
| What a window actually shows        | The fixture PNG in `dev-docs/ui-screenshots/<id>/`      | Prose drifts from the UI; the render cannot.                                                |
| Architecture, rationale, history    | **brain**, `areas/secreq/**` — not this repo            | —                                                                                           |

Design docs live in brain. `brain read secreq`, `brain search "<topic>"`. If a
docs change alters something a brain doc describes, update it there; there is
no copy in the repo to fall out of sync.

## Guards that already exist

These run on an ordinary `cargo test`, so a docs change can fail the build.
Know which findings are already enforced (don't re-check by hand) and which
are not (why the audit script exists).

| Guard                                 | Enforces                                                                            |
| ------------------------------------- | ----------------------------------------------------------------------------------- |
| `tests/cli_drift.rs`                  | `docs/cli-reference.md` matches the clap tree; every visible command has a heading. |
| `tests/schema_drift.rs`               | The committed JSON Schemas match the Rust types.                                    |
| `tests/ui_screenshots.rs`             | Every fixture's layout matches its `layout.json` (CPU, no GPU).                     |
| `tests/screenshot_freshness.rs`       | No orphaned/undocumented fixture; every captioned one has a README row.             |
| `tests/cli_transcripts.rs`            | Recorded lines fit the pty width; no sandbox path leaked.                           |
| `tests/install_scripts.rs`            | The checkout install path stays reachable from getting-started.                     |
| `docs-site` build                     | Every `::shot` / `::term` / `::flow` id resolves. A bad id fails the build.         |
| `npx nx run docs-site:typecheck-docs` | Every `ts` fence in `wasm-rules.md` and the SDK README compiles.                    |

**Nothing guards prose accuracy, cross-page redundancy, or fixture coverage.**
That gap is this skill.

## Regenerating

```sh
cargo run --example gen-cli-reference > docs/cli-reference.md
cargo test --test cli_transcripts -- --ignored --nocapture --test-threads=1   # transcripts
SECREQ_BLESS_SHOTS=1 cargo test --test ui_screenshots -- --test-threads=1     # screenshots
SECREQ_BLESS_SHOTS=layout cargo test --test ui_screenshots -- --test-threads=1  # captions only
```

### Trap: do not blanket-regen screenshots for a docs change

A wgpu render is not byte-reproducible across GPUs and drivers, so re-rendering
untouched fixtures rewrites their PNGs with antialiasing noise — hundreds of
changed binaries hiding the one that matters. Render only the fixture you
added, by test name:

```sh
SECREQ_BLESS_SHOTS=1 cargo test --test ui_screenshots <fixture_fn> -- --test-threads=1
```

The layout guard already proves the others are unaffected; if it passes, they
are. Re-wording a caption needs no GPU at all — `SECREQ_BLESS_SHOTS=layout`
rewrites `layout.json`, which is what the site reads.

## Adding a fixture rather than describing one

When a page needs a picture that does not exist yet:

- **Screenshot** — add a fixture in `tests/ui_screenshots.rs`, render it,
  **open the PNG and look at it**, add a README row. `ManagerExtras` /
  `FixtureExtras` cover rules, refusals, toasts and window state; prefer adding
  a public method on the window state over reaching into private fields.
- **Transcript** — add to `tests/cli_transcripts.rs` and **read the generated
  `.txt`**. That file exists to catch a leaked tempdir path or a spurious
  warning before it ships.
- **`::flow`** — the expensive one. It needs `gui` markers recorded in the
  transcript _and_ an entry in `docs-site/flow-defs.ts` naming which control
  the reader pressed. Only recordings that block on consent can carry it.

A caption is published documentation, written for someone using secreq. The
README table is the contributor-facing description of the same image.

## Judgment calls the script cannot make

- **Repetition is sometimes correct.** A safety-critical fact (the audit log
  never holds values; `--sq-yes` skips consent) may be worth restating where a
  reader will act on it. Duplicated _explanation_ is the problem; a duplicated
  one-line warning usually is not.
- **A long page is not automatically a bloated one.** `cli-reference.md` is the
  longest file in the tree and every line is generated.
- **Prefer deleting to rewriting.** If a paragraph exists on the canonical page
  already, the edit is a link, not a paraphrase.
- **Don't invent scope.** A docs audit that starts renaming commands has
  stopped being a docs audit.
