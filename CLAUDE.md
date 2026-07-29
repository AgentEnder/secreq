# Project notes for Claude

Project-specific guidance for working in this repo. Layers on top of
the global `~/.claude/CLAUDE.md` (still authoritative for general
workflow). Conflicts here win because they're project-specific.

## UI changes always regenerate the screenshot fixtures

The egui consent UI is exercised by a screenshot harness at
`tests/ui_screenshots.rs`. Every fixture renders the **real**
`render_consent_panel` via `egui_kittest` + wgpu and writes a PNG to
`dev-docs/ui-screenshots/`.

**Whenever you change the UI** — adding a tab, changing a layout,
altering colors, adjusting the window's default size, introducing a
new visual primitive — you MUST:

1. **Add a new fixture** for any UI surface you introduced (a new tab,
   a new modal, a new transient banner). Don't rely on an existing
   fixture to incidentally exercise it. One fixture per visual state
   (empty / list / form / toast).
2. **Regenerate every screenshot.** Existing fixtures may also be
   affected (default size change, color tweaks, etc.). Every documented
   fixture renders across the **chrome matrix** — three OS flavors by
   two appearances — so one fixture produces six PNGs, written into that
   fixture's own folder as `<id>/<os>-<appearance>.png`. Don't add a
   fixture whose only distinction is its `OsFlavor`; the matrix already
   covers it.
3. **Inspect the resulting PNGs.** Verify the regen rendered what you
   intended — open at least one new fixture and one existing fixture
   to confirm the change landed and didn't regress anything else.
4. **Update `dev-docs/ui-screenshots/README.md`** to add a table row
   for any new fixture (file name, fixture function name, one-line
   "what it exercises").

Regenerate with:

```sh
npx nx run secreq:bless-screenshots
```

The target sets `SECREQ_BLESS_SHOTS=1` and passes `--test-threads=1`.
Rendering is behind that env var because it needs a GPU and rewrites
published assets; the thread pinning keeps `$SECREQ_HOME` mutation
serialised across fixtures. If you cannot render — no GPU, a headless
container, a driver that won't initialise — or your change moves layout
without changing pixels you mean to republish, re-bless only the
snapshots with `SECREQ_BLESS_SHOTS=layout`.

### CI enforces this — and it will catch a missing regen

**Forgetting the regen is a red build, not a silent mistake.** Every
fixture lays its window out on the CPU (a plain `egui::Context`, no
wgpu) and compares the shape stream — rects, circles, lines, and every
text run with its position, baseline, size, colour and underline —
against the `layout.json` committed in that fixture's folder. That runs
on an ordinary `cargo test`, so a padding constant, a colour token or a
reworded string fails by fixture name with the first shape that moved.
The regen command re-blesses those snapshots as it re-renders, so the
two halves cannot drift apart.

`tests/screenshot_freshness.rs` covers the bookkeeping on the same
ordinary `cargo test`:

- **Incomplete / orphaned** — a fixture's `layout.json` and the PNGs
  beside it must name each other exactly, and nothing else may sit in
  the folder, so a renamed fixture can't leave a dead file the docs site
  keeps publishing.
- **Unguarded** — every fixture folder must carry a `layout.json`, or
  the check above would pass by saying nothing.
- **Undocumented** — every _captioned_ fixture needs its README row.
  `Shot::exercise_only()` fixtures are exempt; a caption is the marker
  for "this one is published documentation".

None of this re-renders and compares pixels, and it never will. A wgpu
render isn't byte-reproducible across GPUs, so a Linux runner could never
match the macOS renders in git — comparing bytes would force a choice
between fixtures that are reviewable in a PR and fixtures that are
verified in CI. Layout has no such problem, which is why the guard
fingerprints the layout instead.

### Screenshots are compressed on write

`save_png` re-encodes through the `oxipng` crate (lossless, preset 4,
`strip safe`) before writing — measured ~70% off this corpus, which
matters because every one of these PNGs lives in git forever and is
published to the docs site. It runs in-process rather than shelling out to
the `oxipng` binary so the committed bytes never depend on what a
contributor happens to have installed. Don't add a lossy pass: these are
documentation screenshots of antialiased UI text.

### How to add a fixture

The harness's `render_fixture_with_extras` accepts a `FixtureExtras`
that covers the three things you usually want to set:

- **`rules`** — populate the Rules tab without going through the form.
- **`toast`** — render an `AutoDenyToastView` (the Pending-tab banner).
- **`window_state`** — a `FnOnce(&mut ConsentWindowState)` that runs
  before the first frame, used to focus a specific tab or open a rule
  form (via `ConsentWindowState::focus_rules_tab` /
  `open_new_rule_form` / `open_edit_rule_form`).

For Pending-tab fixtures you typically only need the `setup` closure
to call `submit(state, ...)`; for Audit-tab fixtures you write
synthetic entries via `audit_line` / `audit_line_traced` and the
helpers write them to the tempdir's `audit.log`.

If a new visual surface needs UI state that none of the existing
helpers cover, **prefer adding a public method to `ConsentWindowState`
over reaching into private state** — the harness is the canonical
user of those entry points, but they should read as legitimate
production APIs.

### A fixture's caption is published documentation

`Shot::new("id").caption("…")` on a fixture is not a test comment — it
is the figcaption that ships on the docs site wherever that screenshot
appears. The harness writes it into that fixture's
`dev-docs/ui-screenshots/<id>/layout.json`, alongside the window kind
and the layout snapshot, and the docs site renders it verbatim
(`<code>` and `<b>` are the only markup honoured). Write it for someone
_using_ secreq; the README table below is the contributor-facing
description of the same image.

No digest covers the caption, so re-wording one never fails the layout
guard — but it does have to reach `layout.json` to reach the site.
`SECREQ_BLESS_SHOTS=layout` is enough for that; no re-render needed.

A fixture with nothing to say to a reader takes a bare id
(`"99-resize-03".into()`) and ships without a caption; one that
exercises the UI rather than documenting it also takes
`Shot::exercise_only()`. The docs site keeps no screenshot list of its
own — it walks the fixture tree and reads each `layout.json` — so
**never** add a parallel list of screenshots, dimensions or captions
under `docs-site/`.

**`exercise_only` renders are not committed.** They render once (macOS
dark) into the gitignored `tmp/resize-screenshots/`, get no
`layout.json`, and skip the compression pass. They exist to
catch a layout panic, not to be read — persisting one would put a file in
git forever for a render whose only job was to not crash. They're still
on disk to _look_ at when a run does fail, and their CPU layout pass runs
on every `cargo test`, so the panic they guard against is now caught
without a GPU.

### Don't forget the README table

`dev-docs/ui-screenshots/README.md` documents what each file in the
directory shows. If a reviewer can't tell from your diff what the new
PNG demonstrates, they'll have to open the file and guess. The table
row is two lines of authorship cost; it's never wrong to write.

## Changing an interactive CLI flow regenerates the transcripts

The interactive terminal flows (`init`, `wrap`, `ssh setup`, the bare
`secreq` picker) are recorded by a second harness at
`tests/cli_transcripts.rs`, which drives the **real binary on a real
pty** and writes the rendered session to `dev-docs/cli-transcripts/`.
The docs replay those recordings via `::term{id=…}` — the CLI
counterpart to `::shot{id=…}`.

**Whenever you change a prompt** — rewording a question, adding a step,
reordering a select, changing what a flow prints at the end — you MUST:

1. **Regenerate.** A reworded prompt is also a _failed_ fixture: the
   `expect()` calls wait on prompt text, so a rename fails the regen
   rather than silently recording something else.
   ```sh
   npx nx run secreq:record-transcripts
   ```
2. **Read the regenerated `.txt`.** Each fixture writes `<id>.txt`
   alongside `<id>.json` for exactly this — it is where a leaked tempdir
   path, a spurious warning, or a wrong branch shows up.
3. **Add a fixture** for a genuinely new flow, and a row in
   `dev-docs/cli-transcripts/README.md`.

The README also documents the two invariants a new fixture has to
respect (width-preserving redaction, and dressing the sandbox rather
than hiding output). Read it before adding one.

### Never hand cliclack an unwrapped line

`cliclack::note` sizes its box to the longest line it is given and
neither wraps nor truncates, so an over-wide line does not degrade — it
runs past the right edge, the terminal re-wraps it, and every following
row's border lands on a line of its own. `log::warning` / `log::info` /
`outro` don't wrap either; they just break mid-word.

So, for any message that interpolates a path or runs past a sentence:

- Put it through **`term::wrap_note_text`** (note bodies) or
  **`term::wrap_log_text`** (log lines and outros).
- Keep the note's **title short and constant**. A title carrying a path
  is a box sized by the user's home directory.
- Shorten paths for display with **`daemon::ui::abbreviate_home`** —
  `~/.zshrc`, not `/Users/somebody-with-a-long-name/.zshrc`.

Both wrappers set `break_words(false)` deliberately. A path split across
two lines is unreadable _and_ invisible to the transcript harness's
redaction, which is a literal string replace — that is exactly how a
`/tmp/…` sandbox path once got published to the docs site.

Two non-`#[ignore]`d tests in `tests/cli_transcripts.rs` enforce this
against the committed recordings, so CI catches a regression without a
pty: `every_recorded_line_fits_the_pty_width` and
`recordings_leak_no_sandbox_paths`.

## The TypeScript in the docs is compiled, not just highlighted

`docs/wasm-rules.md` and `packages/secreq-rule/README.md` teach rule
authoring with code, and every identifier in those fences —
`ctx.joinedArgv`, `deny(reason)`, `DecisionKind.Approve` — is a promise
about the SDK's public surface. `docs-site/scripts/typecheck-docs.mts`
compiles them: each markdown file becomes one in-memory TypeScript
program where every `ts` fence is a source file and `secreq-rule`
resolves to `packages/secreq-rule/index.ts`. Diagnostics come back
addressed to the markdown line you would edit. Run it with:

```sh
npx nx run docs-site:typecheck-docs
```

CI runs it in the `web` job, so **renaming a field on `RuleCtx` or
changing `decide`'s signature fails the build until the guides agree.**

Fences are checked **by default** — a new snippet is guarded without
anyone opting in. Two options after the language tag adjust that:

- **`path=<file>`** names the fragment's file inside the program. Needed
  only when another fragment imports it (the spec fence reaches for
  `../rule`, so the rule fence is `path=assembly/rule.ts`) or when it
  must be a `.d.ts` — a signature with no body is not valid `.ts`.
- **`notypecheck`** opts a fence out. Reported at the end of each run,
  because a snippet nothing checks should be visible rather than
  discovered.

A fragment that imports nothing gets the SDK's surface imported for it,
which is what lets the doc state `decide`'s contract as a bare signature
without an import line above it as noise.

Two things this deliberately does not do. It does **not** run `asc`, so
it validates the fragments against the SDK's _typings_ only — rules are
AssemblyScript, and a snippet using a regex or a closure passes here and
still fails for a reader (`packages/secreq-rule/examples/` is compiled by
`asc` and covers that half). And it does **not** compare the doc's copy
of the npm-publish-guard rule against the example's real one; they are
allowed to differ, and only their types are held together.

The program runs with `skipLibCheck: false` on purpose. The signature
fence is materialized as a `.d.ts`, and `skipLibCheck` suppresses errors
in declaration files — turning it on makes the one fence that is purely a
claim about the SDK the one fence nothing checks.

## Every check is an Nx target, and the graph is load-bearing

Seven projects, and each one owns the targets whose sources it holds:

| Project           | Root                   | Owns (beyond `lint` / `format:check`)                                                       |
| ----------------- | ---------------------- | ------------------------------------------------------------------------------------------- |
| `secreq`          | `packages/secreq`      | `build` `check` `test`, `extract-docs-artifacts`, `bless-screenshots`, `record-transcripts` |
| `secreq-webfonts` | `packages/webfonts`    | `build` — the woff2 cuts — and `check`                                                      |
| `secreq-rule`     | `packages/secreq-rule` | the published SDK; `nx-release-publish`                                                     |
| `docs-site`       | `docs-site`            | `build` `dev` `preview` `deploy` `typecheck-docs`                                           |
| `docs`            | `docs`                 | `vale` `audit`                                                                              |
| `dev-docs`        | `dev-docs`             | nothing — it exists to be depended on                                                       |
| `workspace`       | `.`                    | only what no other project owns (see below)                                                 |

The Rust crates are registered by **`@monodon/rust`**, which runs
`cargo metadata` and creates a node per crate plus the crate-to-crate and
`cargo:` external edges. It infers **no** targets — those are hand-written in
each `project.json`. Adding a crate to the Cargo workspace therefore gets you
an Nx project for free, but not a single target.

**Project names come from Cargo**, so `packages/webfonts` is `secreq-webfonts`.
A `project.json` there naming itself `webfonts` would produce two projects at
one root.

### The edges are the point

```
docs ───────┬──> secreq          dev-docs ───┬──> secreq
            └──> docs-site                   └──> docs-site
secreq-rule ───> secreq, docs-site
secreq-webfonts ───> docs-site
```

Two of these are easy to get wrong:

- **`secreq` depends on `docs` and `dev-docs`.** Backwards-looking, but true:
  `schema_drift`, `cli_drift`, `screenshot_freshness` and `ui_screenshots` read
  those trees as fixtures, so a docs-only change really can turn `cargo test`
  red. CI affected-gates the Rust job, and this is what makes that sound.
  `secreq:test` also declares both trees as `{workspaceRoot}` inputs, which
  carries the same thing independently — **`nx affected` honours
  `{workspaceRoot}` inputs**, so a file owned by no project still marks every
  project that declares it. (`dist/install.sh` belongs to nothing and marks
  `docs-site` affected for exactly that reason.) The edge is the declarative
  half and the input is needed for the cache key regardless; keep both.
- **`docs-site` does NOT depend on `secreq`**, deliberately. It consumes only
  `secreq`'s _committed_ outputs. A direct edge would drag a full release build
  of an egui/wgpu app into the docs deploy through `^build` — the job that
  `deploy-docs.yml` keeps to a seconds-long webfonts compile.

### One CI job, and every project lints itself

`.github/workflows/ci.yml` is a single `checks` job over a two-OS matrix that
runs `nx affected -t lint,format:check,test,typecheck-docs,vale,audit`. There is
no job per tool: what runs is the graph's decision, so a job split would only be
a second place to maintain the same list.

Each project lints and formats its own tree — `lint` is clippy on the crates and
oxlint on the JS, `format:check` is `cargo fmt` and/or oxfmt. The two Rust
crates run **both** formatters, because they really do carry `.ts` fixtures and
`project.json` alongside the Rust.

The `workspace` root project covers exactly what no other project owns —
repo-root markdown and config, `.claude/`, `.github/`, `.vale/` — by excluding
the project directories rather than listing the leftovers:

```
oxfmt --check . '!docs-site/**' '!packages/**' '!docs/**'
```

Written that way so a **new top-level directory is covered automatically**;
enumerating the leftovers would silently miss it. The partition is exact — the
per-project counts plus the root's sum to the same total a whole-tree run sees,
and nothing is checked twice. If you add a project directly under the repo root,
add it to those exclusions.

Two traps:

- **`oxlint` exits 1 when a path holds no lintable file**, which is why `docs`
  and the Rust crates have no oxlint target — only oxfmt.
- **`nx affected` silently ignores `--projects`** (`--exclude` is honoured), so
  a filter cannot scope a job to a subset. With one job that no longer matters,
  but do not reintroduce a split expecting `--projects` to work.

There is no Nx Cloud here, so CI gets no remote cache — affected-based skipping
is the entire saving.

## The design docs live in brain, not in this repo

Architecture notes, the agent orientation guide, the release runbook,
the launch checklist, and every design/implementation plan live in
**brain**, under the `secreq` area — not under `dev-docs/`, which now
holds only the generated screenshot and transcript fixtures. Reach them
with:

```sh
brain read secreq                              # the area's doc registry
brain search "<what you're looking for>"       # semantic, docs + tasks
brain graph areas/secreq/architecture.md       # follow the edges
```

Source comments cite them as `brain: areas/secreq/design/<file>.md`;
that path is what `brain read` and `brain graph` take. **Read the
relevant design doc before changing a surface it covers**, and update it
there when the change lands — the repo has no copy to fall out of sync.

## Other project conventions

- The design plan for the auto-rules feature lives at
  `brain: areas/secreq/design/2026-06-02-auto-rules.md`. Changes that materially
  alter the trust model, the wire protocol, or the rule semantics
  should be reflected there before the code lands.
- JSON Schemas (`docs/wraps.schema.json`, `docs/auto-rules.schema.json`)
  and `docs/cli-reference.md` are all regenerated by one target,
  `nx run secreq:extract-docs-artifacts`. A test in `tests/schema_drift.rs`
  fails CI if either schema is stale, and `tests/cli_drift.rs` does the same
  for the CLI reference.

  Each generator writes to **stdout** and the target supplies the redirect —
  a bare `cargo run --example gen-schema` prints the schema and updates
  nothing.

  **A field's description is written at the field.** Both schemas are derived
  with `schemars` from the types that read those files — `RuleWire`,
  `RuleMatch` and `WasmRule` in `rules.rs`, `Wrap` and `SshIdentity` in
  `wraps.rs`, `Provider` and friends in `manifest.rs`. Every `///` on those
  fields is published verbatim as that property's `description`, so
  **changing what a matcher does means editing the doc comment above it**,
  and forgetting to is a failing `schema_drift`, not a silent lie on
  the docs site. Three descriptions contradicted the parser for a month each
  under the hand-written `json!` tree this replaced.

  `schemars` is optional and behind the `schema` feature, switched on for the
  test/example build by the self dev-dependency (the `harness` trick). A plain
  `cargo build` or `cargo install secreq` never compiles it — check with
  `cargo tree --package secreq -e normal`.

  What `schema.rs` still writes by hand is the file envelope (`wraps.json5`'s
  dynamic binary-name keys, the `$schema` pointer nothing reads) and the two
  constraints no field implies: declarative-XOR-wasm, and `retrieve`/`read`.
  Each sits next to the code that enforces it.

  `schema_drift` no longer only compares the generator to the file. It
  validates rules `secreq` actually writes against the committed schema, checks
  that the shapes the loader refuses are refused by the schema too, and feeds
  the wraps parser a config using every key the schema declares — that last one
  is what holds the hand-written `wraps.json5` parser to its `schemars(rename)`
  attributes. The round-trip suite in `rules.rs` is still the guard for the
  _bytes_ (exact serialized objects, written key order, a hand-authored JSON5
  file through load→save→load→save requiring byte-stable output).

## Tool versions come from `mise.toml`

Rust, Node and Vale are pinned in `mise.toml`, and CI installs the same
versions with `jdx/mise-action`. A local run and a green build therefore use
one toolchain.

```sh
mise install         # once, and after any change to mise.toml
```

`mise.toml` pins tools and nothing else. The two tasks it used to carry are
Nx targets now — `nx run docs:vale` and `nx run docs:audit` — because a task
in `mise.toml` is invisible to the graph: uncacheable, and unable to say
which projects it applies to.

Rust is pinned to an exact version rather than `stable`, so a lint added in a
new stable release can't turn an unrelated PR red. Bumping it is its own
commit.

`rustfmt` and `clippy` are named in `mise.toml`'s `components`, and have to
be. mise installs Rust through rustup, so your machine hands them over from
whatever your rustup default profile already had and nothing looks wrong; a
fresh runner takes the minimal profile and the `rustfmt` and `clippy` jobs
both fail with "not installed for the toolchain". Adding a tool to that file
is not the same as adding a component to it.

## Prose is linted

`.vale.ini` + `.vale/styles/Secreq/` lint `docs/`, the READMEs and
`CONTRIBUTING.md`. The `web` CI job runs it as `nx affected -t vale`.

**Only `error` fails the build**; warnings and suggestions are advisory, so a
rule can be tightened without turning open PRs red. Errors are reserved for
things that are simply wrong: AI-tell phrases (`BannedPhrases`), writing about
the document instead of the subject (`SelfReferential`), stale terminology
(`Terminology`), and non-sentence-case headings.

A finding in `docs/cli-reference.md` is real, but **fix it in the doc comments
in `packages/secreq/src/cli.rs`** — the markdown is regenerated.

The rationale behind the rules, and the wider de-slopping guidance, live in
`.claude/skills/docs-audit/` (`VOICE.md` in particular). Vale catches what a
regex can catch; the skill covers the rest.

## `docs/cli-reference.md` is generated from clap

**Never hand-edit it.** It is the exhaustive command list, walked out of
the clap tree by `examples/gen_cli_reference.rs`:

```sh
npx nx run secreq:extract-docs-artifacts   # this file and both schemas
```

`tests/cli_drift.rs` fails an ordinary `cargo test` when the committed file
and the CLI disagree, so **adding a subcommand or a flag is a docs change
whether or not you meant it to be**. That test exists because `secreq read`,
`daemon status`, `migrate restore`, `agent open` and `run
--prompt-unresolved` all shipped undocumented: coverage used to depend on
someone remembering.

Two consequences worth internalising:

- **A doc comment in `src/cli.rs` is published prose.** It reaches
  `--help` and the docs site from the same string, so a missing `///` on an
  arg renders as a `—` in a published table.
- **Indented examples in a doc comment need
  `#[command(verbatim_doc_comment)]`.** Without it clap rewraps the comment
  as prose, which folds a `\`-continued shell line onto its head and
  publishes a command that does not run.

The hand-written half is `docs/cli.md`, which carries the narrative (the
argv contract, `x` versus `run`) and deliberately **no flag tables** — the
`--sq-` table is the one exception, because those options are parsed by
hand and clap never sees them.

- The design plan for the remote secret agent (serving `secret://`
  refs to a guest VM over a scoped socket) lives at
  `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md`. Its provenance
  section is load-bearing: the scoped-agent path must **never** call
  `daemon/peercred.rs` or `provenance.rs`, because a guest has no host
  pid and a forwarded socket's peer is the tunnel (sshd), not the
  asker. The host-declared scope is the principal instead.
- The audit log is written by the **wrap client** (`commands/run.rs`)
  after the daemon's reply lands. The scoped agent
  (`scoped_agent/mod.rs`) is also a client, so it writes its own rows
  via `audit.rs::AuditEntry::agent_resolve` — that's the rule, not an
  exception to it. The daemon never writes audit
  rows itself — **with two exceptions:**
  1. **SSH-agent signs.** There is no wrap client on the SSH path
     (the daemon _is_ the agent), so the daemon records each sign
     outcome itself via `audit.rs::AuditEntry::ssh_sign` from
     `daemon/ssh_agent.rs::audit_sign` (`ssh:<key_id>` wrap, the
     public-key SHA256 fingerprint, the decision, and the caller
     chain — never the private key or the signature bytes).
  2. **Abandoned asks.** When a wrap (or an ancestor that took it
     down) exits before the user decides, its socket closes; the
     daemon reaps the parked ask and — since the client is gone and
     can't write its own row — records the `abandoned` outcome via
     `audit.rs::AuditEntry::abandoned` from
     `daemon/state.rs::withdraw_waiter` (one row per dead command,
     with the requesting process's `cwd` + caller chain + secret
     **names**, `decision = "abandoned"`). See `Decision::Abandoned`.
     Audit-write failures are non-fatal on all paths (logged, never
     failing the user's command / the sign / the reap).
     If you change the audit shape, update `audit.rs::AuditEntry::new`,
     the other `AuditEntry` constructors (`ssh_sign`, `abandoned`), and
     the screenshot fixture helpers that construct `AuditEntry` directly.
