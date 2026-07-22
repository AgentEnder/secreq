# AGENTS.md — orientation for AI agents

`secreq` is a Rust CLI that wraps individual binaries (`gh`, `aws`,
`kubectl`, …) so each invocation gets its credentials injected from your
chosen store, with a provenance-aware consent prompt before any release
and output masking on stdout/stderr.

Read this first. The other docs go deeper.

## TL;DR

```sh
secreq init                                              # one-time setup
secreq wrap gh --env GITHUB_TOKEN=secret://op/Personal/GitHub/credential
gh repo list   # now: PATH shim → secreq → consent → resolve → real gh
```

1. `init` creates a config file and a PATH shim directory; optionally
   wires that directory into your shell's PATH via `.zshenv` / `.bashrc` /
   `conf.d/secreq.fish`.
2. `wrap` adds an entry to `~/.secreq/wraps.json5` and drops a
   shim at `<shim_dir>/<binary>` whose body is `exec secreq <binary> "$@"`.
3. Any `execvp` call to `<binary>` — from your shell, from npm postinstalls,
   from IDE subprocesses — resolves the shim, which calls into secreq.
4. secreq prompts (or hits the cache), resolves the env, masks the
   output, execs the real binary.

## Mental model in 60 seconds

| Concept | What it is |
|---|---|
| **Wrap** | Per-binary config: env vars to inject + reason. Top-level key in `wraps.json5`. There is no TTL — the approval cache lives in the daemon's memory only. |
| **Shim** | A 5-line POSIX script in `$shim_dir` that execs `secreq <wrap>`. Carries a sentinel comment so `unwrap` can safely delete it. |
| **Provider** | A scheme that knows how to fetch (and optionally store) a value. Built-ins: `op`, `keychain` (macOS), `lastpass`, `pass` (Unix). Override or add your own in the `providers` block. |
| **Reference** | `secret://<provider>/<locator>`. Used in `env` entries and inline in any inherited env var. |
| **Consent** | The daemon's egui prompt shows command, working dir, caller chain, env names + providers. Decisions: approve / approve+remember / deny. All asks (top-level and nested) flow over the per-user `0600` Unix-domain socket. |
| **Cache** | Approval keyed by `(wrap_name, ppid, parent_start_time)`. Direct parent only; pid-recycle safe via start_time. Lives in daemon memory only; `secreq daemon stop` clears it. |
| **Masking** | Streaming byte-exact multi-secret redactor on the child's stdout/stderr. Catches values split across chunks. |
| **`retrieve_batch`** | A provider's *batched-read* descriptor: one invocation resolves many secrets via synthetic env + parsed `KEY=VALUE` output. Op uses `op run -- printenv`, so N secrets share one biometric. |

## Module map — where each concept lives

| Looking for… | File | Key items |
|---|---|---|
| CLI entry / argv parsing | `src/cli.rs` | `Cli`, `Command`, `pub fn run() -> i32`, `allow_external_subcommands` |
| Subcommand implementations | `src/commands.rs` | `wrap_run`, `wrap`, `unwrap_cmd`, `wraps_list`, `init`, `check`, `doctor`, `edit_cmd` |
| Wraps config model + parsing | `src/wraps.rs` | `WrapsConfig`, `Wrap`, `default_config_path()` |
| Provider types + built-ins | `src/manifest.rs` | `Provider`, `StoreCapability`, `BatchRetrieve`, `FieldSpec`, `ValueMode`, `builtin_providers()` |
| `secret://` parser | `src/reference.rs` | `Reference::parse`, `looks_like_ref` |
| Provider invocation | `src/provider.rs` | `pub fn retrieve`, `retrieve_batch`, `store`, `validate` |
| Resolution + batching | `src/resolve.rs` | `build_plan`, `resolve_all` (groups by provider; auto-batches when ≥2 share a batch-capable one) |
| Output masking | `src/mask.rs` | `Masker::{new, push, finish}` |
| Caller-chain provenance | `src/provenance.rs` | `caller_chain()` — each `Caller` carries `(pid, name, command, exe, start_time)` |
| Consent enum + approval record | `src/consent.rs` | `Decision`, `ApprovalEntry` (in-memory only) |
| Consent daemon (queue, UI, socket) | `src/daemon/` | `mod.rs` (entry), `proto.rs` (wire types), `server.rs` (accept loop), `state.rs` (queue + approvals + cache), `ui.rs` (egui app + tabs), `client.rs` (auto-spawn) |
| Audit log (names only) | `src/audit.rs` | `AuditEntry`, `append`, `state_dir` |
| PTY / piped exec | `src/exec.rs` | `pub fn run` |
| PATH shim management | `src/shim.rs` | `install`, `remove`, `is_managed`, `SENTINEL` |
| Shell-config PATH setup | `src/path_setup.rs` | `detect_shell`, `path_includes`, `plan`, `apply`, `Shell` enum |
| JSON Schema source of truth | `src/schema.rs` | `wraps_schema()`, `manifest_schema()` (back-compat alias) |
| Secret value (zeroizing) | `src/secret.rs` | `SecretValue` |

## Common tasks

### Add a new admin subcommand

1. New variant on `Command` in `src/cli.rs` (with `#[command(...)]`).
2. New dispatch arm in `cli::run`.
3. Implement `pub fn <name>` in `src/commands.rs`.
4. Add integration tests in `tests/cli.rs`.

### Add a built-in provider

1. Insert a `Provider {…}` entry in `manifest::builtin_providers()`.
2. Gate with `#[cfg(target_os = "…")]` if platform-specific.
3. Update `builtin_providers_include_op_and_platform_stores` test.
4. Update [`docs/providers.md`](../docs/providers.md).

A built-in must be:

- **Non-interactive in the happy path.** Touch ID prompts are fine
  (the OS handles the modal); "type your master password" prompts are
  not, because the consent daemon's PTY-managed terminal can't show
  them.
- **Cross-platform** if possible — or `#[cfg]`-gated to the platforms
  where its CLI actually exists. Don't ship a built-in that fails on
  `secreq doctor` for half the user base.
- **Idempotent on store.** Re-storing the same `(fields, value)`
  should produce one entry, not duplicates. The keychain built-in
  uses `-U` (update if exists); `pass` uses `-f` (force overwrite).

### Add a wrap-config field

1. Add it to `Wrap` in `src/wraps.rs`.
2. Handle it in `parse_wrap`.
3. Update the JSON Schema (`src/schema.rs::wrap_schema()`).
4. Regenerate: `cargo run --example gen-schema > docs/wraps.schema.json`.
5. Add a parser unit test.
6. Document in `docs/wraps.md`.

### Change the consent prompt

Edit `src/daemon/ui.rs` — the egui app. `render_row` draws a single
queue entry; the bulk Approve all / Deny all buttons live in
`ConsentApp::update`. The window's visibility/idle/auto-hide logic lives
in the same file (search for `HIDE_GRACE_SECS` / `IDLE_EXIT_SECS`).

If you're changing the wire metadata the prompt can show, also update
`daemon::proto::Ask` (and the client builder in
`commands::obtain_wrap_consent`).

### Add an integration test

Put it in `tests/cli.rs`. Use the `bin()` helper for the binary path and
`tempfile::tempdir()` for sandboxing. Drive the tempdir through
`sandbox_env`, which pins `$SECREQ_HOME` (the config/audit/remember root)
into it — plus the legacy `$XDG_CONFIG_HOME` / `$XDG_STATE_HOME` probe and
`$HOME` backstop — so nothing pollutes the developer's home.

## Invariants you must not break

1. **Consent before fetch.** `resolve_wrap_env` must run only *after*
   `Decision::approved()`. Provider commands never run otherwise.
2. **No secret values in logs, prompts, audit, or the remember cache.**
   `SecretValue::Debug` redacts. The audit log records names only. The
   approvals cache is keyed by `(wrap, ppid, parent_start_time)` —
   identifiers, never values. The two boundaries values *do* cross are
   intentional and inside the per-user trust boundary: the `0600`
   daemon socket (daemon → client, on approve) and env-var injection
   into the wrapped child.
3. **Fail-closed at boundaries.** `SECREQ_NO_DAEMON` + no `--yes` ⇒ deny.
   No graphical env (no `$DISPLAY`/`$WAYLAND_DISPLAY` on Linux) + no
   `--yes` ⇒ deny. Required secret missing with no default ⇒ hard error
   before exec. Daemon unreachable / exits early ⇒ deny. The integration
   tests pin each.
4. **Cache scoped to the direct parent only.** `(wrap_name, ppid,
   parent_start_time)`. Postinstall hooks have a different ppid; pid
   recycling produces a different `start_time`. Both make the cache
   key change, both re-prompt.
5. **Schema drift is a build failure.** `tests/schema_drift.rs` fails if
   `docs/wraps.schema.json` falls out of sync with `schema::wraps_schema()`.
   Regenerate: `cargo run --example gen-schema > docs/wraps.schema.json`.
6. **The shim sentinel is load-bearing.** `shim::install` refuses to
   clobber a file at the target path that doesn't carry our sentinel;
   `shim::remove` refuses to delete one. Don't add a path that bypasses
   either check.
7. **`find_real_binary` must skip the shim dir.** Otherwise the shim
   recurses into itself. Test: `wrap_run_injects_env_and_masks_output…`
   pins this — if the skip is broken, the test deadlocks or fails.

## Quality gate before declaring done

```sh
cargo test                                                       # all
cargo clippy --all-targets -- -D warnings                        # zero warnings
cargo fmt --check                                                # formatted
cargo run --example gen-schema | diff -q - docs/wraps.schema.json  # no schema drift
```

## Testing patterns

- **Pure logic gets unit tests in the module** (`#[cfg(test)] mod tests`).
- **End-to-end behavior gets integration tests** in `tests/cli.rs` driving
  the built binary via `Command::new(env!("CARGO_BIN_EXE_secreq"))`.
- **Fake provider via `printf`/`sh`** for most integration tests — avoids
  triggering real Keychain / `op` invocations (which would prompt for
  biometrics).
- **Sandbox per test**: tempdir rooted with `SECREQ_HOME=…` (via
  `sandbox_env`, which also pins the legacy `XDG_CONFIG_HOME` / `XDG_STATE_HOME`
  probe and `HOME`) to keep state out of the developer's real home.
- **`env("SECREQ_NO_DAEMON", "1")`** in test commands — disables the
  consent daemon entirely so cargo test never pops a GUI window. Tests
  that *should* succeed pass `--yes`; tests that exercise the deny path
  rely on this env var making the daemon path return `Deny` immediately.

## What this project deliberately doesn't do

- No long-lived **secret** broker. The consent daemon never sees or
  caches secret values — it gates *access*, not data. Resolved values
  live in the client process for the duration of the wrapped child only.
- No interception of `.env` file reads at runtime. (And: no `.env`
  migration tool — that responsibility went to varlock with the pivot.)
- No project-level config; user-scope only. Project-level is varlock's
  territory.
- No cloud-secret-sync; no rotation; no drift detection.
- No competing with `op run` on 1Password-only flows; we delegate to
  `op read` and win on the multi-provider union + provenance-aware
  consent.

## Pointers

- High-level prose: [`docs/overview.md`](../docs/overview.md)
- CLI reference: [`docs/cli.md`](../docs/cli.md)
- Config authoring: [`docs/wraps.md`](../docs/wraps.md) (+ [`docs/wraps.schema.json`](../docs/wraps.schema.json))
- Providers in depth: [`docs/providers.md`](../docs/providers.md)
- Internals: [`architecture.md`](./architecture.md) (this directory)
- Original (pre-pivot) design: [`plans/2026-05-22-secrets-requestor-design.md`](./plans/2026-05-22-secrets-requestor-design.md)
- Top-level README: [`../README.md`](../README.md)
- Top-level TODO/progress: [`../TODO.md`](../TODO.md)
