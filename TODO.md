# secreq — Pivot complete

The pivot from project-level manifests to per-binary wraps has shipped.
What's left is incremental polish.

## Locked design (all implemented)

- **Wedge:** per-binary wrap × multi-provider × provenance-aware consent.
- **Cache key:** `(wrap_name, ppid, parent_start_time)`. Direct-parent
  scoped; pid-recycle safe via start_time. **No TTL**: the cache lifetime
  is the lifetime of the parent process — when it exits, the entry is
  unreachable. On every cache write, dead-parent entries are pruned via
  one sysinfo refresh. Use `--no-remember` on the command line for one-
  shot non-caching invocations.
- **Install:** PATH shim only (`<shim_dir>/<bin>` execs `secreq <bin>`).
  No shell aliases. Covers every `execvp` including `npm` postinstalls.
- **Shim dir:** chosen at `secreq init`; default `~/.secreq/shims` (a
  dedicated directory we own — no collision risk with other tools'
  managed bin dirs like asdf's or pip user-installs'). If the canonical
  shell config file lacks our sentinel block, `init` detects the shell
  and offers to append a sentinel-bracketed PATH export to: `.zshrc`
  (zsh — runs after `.zprofile` so we win over `brew shellenv`),
  `.bashrc` (bash), `conf.d/secreq.fish` (fish), or `.profile` (sh).
  Idempotent; on re-runs detects stale blocks in other files (e.g. a
  pre-fix `.zshenv` block) and surfaces them as a warning.
- **Mask default:** mask always; `--raw` opts out (`secreq --raw gh auth token`).
- **Unwrapped binaries:** if `secreq foo` invokes a binary with no wrap
  entry, pass through unchanged. Lets users blanket-shim and add wraps
  later.

## What shipped

- [x] `src/wraps.rs` — `WrapsConfig` / `Wrap` model + parser, `$shim_dir`
      / `$reason` / `$remember` / `env` fields, tilde expansion.
- [x] `src/shim.rs` — `install` / `remove` / `is_managed` with sentinel
      protection.
- [x] `src/path_setup.rs` — shell detection (zsh / bash / fish / sh /
      Unknown), `plan` (pure) + `apply` (idempotent write), sentinel
      block, per-shell caveats.
- [x] `consent.rs` — ppid+start_time-keyed cache:
      `wrap_remember_key`, `is_wrap_remembered`, `remember_wrap`.
- [x] `provenance.rs::Caller` — now carries `start_time`.
- [x] New `cli.rs` — admin verbs + `allow_external_subcommands`; global
      `--raw` / `--yes` / `--no-remember` / `--config`.
- [x] New `commands.rs` — `wrap_run` (with passthrough, IPC broker
      setup, masking opt-out); admin verbs `init` / `wrap` / `unwrap_cmd`
      / `wraps_list` / `check` / `doctor` / `edit_cmd`.
- [x] Removed `dotenv.rs`, old `run` / `request` / `store` / `import` /
      `list` commands, project-scope manifest discovery.
- [x] `src/schema.rs` — rewritten for the wraps shape; built-in alias
      `manifest_schema()` for back-compat with any external refs.
- [x] `docs/wraps.schema.json` — regenerated.
- [x] `tests/cli.rs` — rewritten against the new CLI. 10 integration tests
      covering wrap-and-run, `--raw`, passthrough, deny-without-tty,
      `wrap`/`unwrap`/`wraps`/`check`/`init`.
- [x] Docs: `wraps.md`, refreshed `cli.md` / `overview.md` /
      `architecture.md` / `providers.md` / `AGENTS.md` / `README.md`.

## Status

- **92 tests pass** (80 unit + 10 integration + 2 schema drift).
- **clippy clean** (`-D warnings`).
- **fmt clean**.
- **schema reproducible** (drift test passes).

## What's deliberately not done (and why)

- **No `secreq` verb to actually invoke a provider's `store`.** The model
  is currently retrieve-only at the CLI surface. The `store` capability
  remains on the provider type so user-written tooling can drive it (and
  for future verbs), but `secreq store` / `secreq import` are gone.
- **No project-scope config.** That's varlock's space. Coexistence, not
  competition.
- **The `init` interactive flow needs a real terminal.** The integration
  test for `init` tolerates either outcome (success or "no terminal"
  error) because cargo test doesn't have a tty. Smoke-test by running
  `secreq init` in a real shell.

## Possible follow-ups (un-prioritized)

- **`secreq uninit`** — reverse what `init` did: remove the
  sentinel-bracketed PATH block from the shell config.
- **`secreq unwrap --remove-from-shim-dir-only`** for accidentally
  installed-elsewhere shims.
- **A real interactive `secreq wrap` flow polish pass** — currently the
  prompts are functional but verbose for multi-env wraps.
- **`$shell_init` block support for non-`.zshenv` zsh users** — some
  people set PATH only in `.zshrc`; we'd want to detect that and adapt.
- **Hardware-backed local encryption for wraps.json5 itself** — varlock
  has Secure Enclave / TPM support for its overrides; we could mirror it
  for the wraps config if we ever store more than refs there.
