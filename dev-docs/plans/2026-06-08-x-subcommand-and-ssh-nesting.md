# `secreq x <wrap>` + nested `secreq ssh …` — implementation plan

> **For Claude:** REQUIRED SUB-SKILL: superpowers:executing-plans.

**Goal:** Move wrap-and-run from the `allow_external_subcommands` catch-all
(`secreq gh …`) to an explicit `secreq x <wrap> …`, migrate existing shims,
and remove the catch-all — which frees the namespace so SSH can nest as
`secreq ssh setup` / `ssh add` / `ssh validate` without binary-name
collisions.

**Decisions (brainstormed):**
- Wrap execution: `secreq x <wrap> [args…]`. Remove `allow_external_subcommands`
  and the `External(Vec<String>)` variant. Bare `secreq <binary>` no longer
  runs a wrap (it's the collision source) — migrated shims cover it.
- Nest SSH: `secreq ssh setup` (was `ssh-setup`), `secreq ssh add` (was
  `ssh-add`), `secreq ssh validate` (was `ssh-test`, renamed test→validate).
- Migrate the user's existing shims (`claude-glm`, `gh`, `op`) to the new body.

---

## Task 1 — `secreq x <wrap>` + shim body + migration + drop catch-all

**Files:** `src/cli.rs`, `src/shim.rs`, `src/commands.rs`, `tests/cli.rs`,
`src/shim.rs` tests.

1. **`src/shim.rs`**: change `body()` from `exec secreq {wrap} "$@"` to
   `exec secreq x {wrap} "$@"`. Update the in-body comment lines that say
   `secreq wrap {wrap}` / `secreq unwrap {wrap}` only if they reference the
   run command (they reference wrap/unwrap, which are unchanged — leave).
   Update shim.rs unit tests that assert the body.
2. **`src/cli.rs`**: 
   - Remove `allow_external_subcommands = true` from `#[command(...)]` on `Cli`.
   - Remove the `External(Vec<String>)` variant.
   - Add a new variant:
     ```rust
     /// Run a wrapped binary through secreq: consent → inject secrets →
     /// exec the real binary with output masking. This is what the PATH
     /// shims call (`exec secreq x <wrap> "$@"`).
     X {
         /// The wrap (binary) name, e.g. `gh`.
         wrap: String,
         /// Arguments passed through to the wrapped binary.
         #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
         args: Vec<String>,
     },
     ```
   - In `run()`, replace the `Command::External(args)` arm with
     `Some(Command::X { wrap, args }) => commands::wrap_run(...)` — match the
     EXACT current `wrap_run` call/signature the External arm used (study it:
     it builds `WrapRunOpts` from `cli.raw`/`cli.yes`/`cli.no_remember` and
     passes the binary + args + config). The External arm passed
     `args[0]` as the binary and `args[1..]` as the rest; now `wrap` and
     `args` are already split.
3. **Migration** of existing shims (rewrite-on-rerun already exists in
   `shim::install`): add `pub fn reinstall_all(shim_dir: &Path, wrap_names:
   impl IntoIterator<Item = &str>) -> Result<Vec<PathBuf>>` that calls
   `install` for each (idempotent; rewrites stale bodies). Wire it into
   `secreq init` so init repairs/migrates all configured wraps' shims, and
   print a line when a shim's body changed. (Detect "changed" by comparing
   the pre-existing body to the new one before writing, or just report
   "ensured N shims".)
4. **Tests** (`tests/cli.rs`): update every test that invoked a wrap via the
   external path to use `x` (e.g. a wrap-run test now runs `secreq x <bin>`).
   Add `x_runs_the_wrap` / `bare_binary_is_no_longer_a_wrap` (a bare unknown
   subcommand now errors). Update `shim.rs` body tests to expect `secreq x`.
   Verify the recursion-guard path is unaffected (the `op` provider shim
   becomes `secreq x op`; `wrap_run` still passes through on `SECREQ_RESOLVING`).

**Commit:** `feat(cli): run wraps via `secreq x <wrap>` (frees the namespace)`

## Task 2 — Nest SSH into `secreq ssh setup/add/validate`

**Files:** `src/cli.rs`, `src/commands.rs` (cross-reference strings + the
`ssh_test`→validate rename if any user-facing text), `tests/cli.rs`, docs
touched in Task 3.

1. **`src/cli.rs`**: replace the flat `SshSetup`, `SshAdd`, `SshTest`
   variants with a nested group:
   ```rust
   /// Manage secreq's SSH agent: configure identities, wire clients, and
   /// verify signing.
   Ssh {
       #[command(subcommand)]
       action: SshAction,
   }
   ```
   and `#[derive(Subcommand)] enum SshAction { Setup { method, undo }, Add {
   name, public_key, private_key, reason, force }, Validate { name } }` —
   move the existing arg definitions verbatim. Update `run()` dispatch:
   `Some(Command::Ssh { action: SshAction::Setup { .. } }) => commands::ssh_setup(..)`,
   `…Add { .. } => commands::ssh_add(..)`, `…Validate { name } =>
   commands::ssh_test(name, config)`.
2. **Cross-references**: grep the codebase for user-facing strings
   `ssh-setup`, `ssh-add`, `ssh-test` (in `commands.rs` reminders/hints, e.g.
   "run `secreq ssh-setup`", "run `secreq ssh-add <name>`", the self-test
   "then `secreq ssh-test <name>`") and update to the nested forms
   (`secreq ssh setup`, `secreq ssh add`, `secreq ssh validate`). Keep the
   internal Rust fn names (`ssh_setup`, `ssh_add`, `ssh_test`) as-is to
   minimize churn — only the CLI surface and user-facing text change. (Rename
   the handler `ssh_test`→leave; its CLI name is now `validate`.)
3. **Tests** (`tests/cli.rs`): update `ssh-setup`/`ssh-add` invocations to
   `ssh setup` / `ssh add`; the scripted-path assertions stay. Add a smoke
   test that `secreq ssh --help` lists `setup`, `add`, `validate`.

**Commit:** `feat(cli): nest SSH commands under `secreq ssh setup/add/validate``

## Task 3 — docs + migrate the user's shims + final verify

1. **Docs**: update `docs/ssh-agent.md`, `docs/cli.md`, `docs/README.md`,
   `docs/getting-started.md`, `README.md`, and any `docs/*.md` that show
   `secreq <binary>` wrap usage or `secreq ssh-setup/ssh-add/ssh-test` — to
   `secreq x <binary>` and `secreq ssh setup/add/validate`. Update the
   `wraps.md`/overview examples and the shim explanation (`exec secreq x …`).
2. **Migrate the user's installed shims**: after building, re-install the
   three managed shims (`claude-glm`, `gh`, `op`) via the tool (e.g. `secreq
   init`'s reinstall step, or the `reinstall_all` path) so their bodies
   become `exec secreq x <name>`. Confirm by reading the files.
3. `cargo fmt`/`clippy -D warnings`/`cargo test` green; no UI change → no
   screenshots; no TODO/Task markers. Verify `secreq x gh --help`-style
   smoke and `secreq ssh validate --help`.

**Commit:** `docs: secreq x + nested ssh commands`
