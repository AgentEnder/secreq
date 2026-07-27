# Contributing to secreq

Thanks for your interest in `secreq`, a per-binary CLI wrapper that
injects credentials from your secret store of choice behind a
provenance-aware consent prompt. Because this is a **secrets tool**,
contributions are held to a slightly higher bar than usual: a bug here
can leak a credential or weaken a trust boundary. This document is the
short version of what that means in practice.

By participating you agree to abide by our
[Code of Conduct](./CODE_OF_CONDUCT.md).

> **Found a security issue?** Do **not** open a public issue or PR.
> Follow the private disclosure process in [SECURITY.md](./SECURITY.md).

## Toolchain

Rust, Node, and Vale versions live in `mise.toml`, and CI installs the same
ones. If you have [mise](https://mise.jdx.dev):

```sh
mise install         # once, and after mise.toml changes
mise run docs        # lint published prose with Vale
mise run docs-audit  # sweep the docs for redundancy and stale claims
```

Without mise, install those versions yourself; nothing else assumes it.

## Ways to contribute

- **Report a bug**: open an issue with a reproduction (see the bug
  template). Never paste real secret values, tokens, or `secret://`
  refs that point at live credentials.
- **Request a feature**: open an issue describing the problem first,
  then the proposed shape. `secreq` does _not_ do some things
  (project-scope config, cloud sync, rotation); check
  [`docs/overview.md`](./docs/overview.md) for the scope before
  proposing.
- **Send a patch**: small, focused PRs are easiest to review. For
  anything that touches the trust model, the wire protocol, or rule
  semantics, open an issue to align on the design first.

## Development setup

You need a recent stable Rust toolchain (`rustup` recommended) plus a
working `cargo`. Everything else is vendored through Cargo.

```sh
git clone <your-fork>
cd secreq
cargo build
```

## The dev loop

Run all four of these before you push. CI enforces every one:

```sh
cargo test                                                       # unit + integration + schema drift
cargo clippy --all-targets -- -D warnings                        # zero warnings; warnings fail CI
cargo fmt --check                                                # formatting (drop --check to fix)
cargo run --example gen-schema | diff -q - docs/wraps.schema.json  # no JSON-schema drift
```

Notes:

- **Tests never pop a GUI.** Integration tests set `SECREQ_NO_DAEMON=1`
  so the consent daemon window never opens. Tests that should succeed
  pass `--yes`; deny-path tests rely on the fail-closed default.
- **Schema drift is a build failure.** Both schemas are derived from the
  types that read those files, and every doc comment on those fields is
  published as that property's description, so renaming a field or
  rewording a `///` above one is a schema change. `tests/schema_drift.rs`
  fails until you regenerate:
  ```sh
  cargo run --example gen-schema > docs/wraps.schema.json
  cargo run --example gen-auto-rules-schema > docs/auto-rules.schema.json
  ```
- **UI changes must regenerate the screenshot fixtures.** If you change
  the egui consent window (a tab, a layout, colors, the default window
  size, a new visual surface), add a fixture and regenerate:
  ```sh
  cargo test --test ui_screenshots -- --ignored --nocapture --test-threads=1
  ```
  Then update the table in
  [`dev-docs/ui-screenshots/README.md`](./dev-docs/ui-screenshots/README.md).
  The screenshot tests are `#[ignore]`-gated (they need wgpu), so a
  normal `cargo test` won't run them, but CI does.

## Isolate every dev build from your real `~/.secreq`

This is the one trap that can brick a working setup, and it has actually
happened during a `cargo test`.

secreq keeps everything under one root (`$SECREQ_HOME`, else `~/.secreq`) and
applies pending **migrations** on every deliberate foreground command,
stamping the schema level it reached. Point a dev build at the same home as
your installed release and it goes wrong two ways. A newer dev build migrates
your live config and bumps the level, after which the release refuses to run
until you `secreq migrate restore <level>`. Worse, a test that pins
`$SECREQ_HOME` but leaves `$HOME` alone aims the migration's legacy probe at
your **real** `~/.config/secreq` and moves your live config into a tempdir
that is deleted moments later.

`$SECREQ_HOME` on its own is not enough: migrations resolve pre-migration
locations through frozen XDG logic, and the socket directory prefers
`$XDG_RUNTIME_DIR` over the root.

```sh
export SECREQ_HOME="$(mktemp -d)"
export XDG_RUNTIME_DIR="$SECREQ_HOME/run"   # sockets don't hang off SECREQ_HOME
mkdir -p "$XDG_RUNTIME_DIR"
export HOME="$SECREQ_HOME"                   # backstop: makes a forgotten pin harmless
export XDG_CONFIG_HOME="$SECREQ_HOME/config" # the migration's legacy probe
export XDG_STATE_HOME="$SECREQ_HOME/state"

cargo run -- doctor        # now safely sandboxed
```

Pinning `$HOME` is what makes a forgotten pin harmless rather than
destructive. The integration tests do this; see
`tests/ssh_agent.rs::isolate_paths`.

## Where things live

The mental model in one line: a shim on your `PATH` intercepts a wrapped
command, asks the consent daemon (which knows _who_ is asking, by walking
the caller chain), and only on approval fetches the secrets and execs the
real binary with them in its environment, masking them back out of its
output.

| Looking for…                       | File                |
| ---------------------------------- | ------------------- |
| CLI entry / argv parsing           | `src/cli.rs`        |
| Subcommand implementations         | `src/commands.rs`   |
| Wraps config model + parsing       | `src/wraps.rs`      |
| Provider types + built-ins         | `src/manifest.rs`   |
| `secret://` parser                 | `src/reference.rs`  |
| Provider invocation                | `src/provider.rs`   |
| Resolution + batching              | `src/resolve.rs`    |
| Output masking                     | `src/mask.rs`       |
| Caller-chain provenance            | `src/provenance.rs` |
| Consent enum + approval record     | `src/consent.rs`    |
| Consent daemon (queue, UI, socket) | `src/daemon/`       |
| Auto-rules evaluation              | `src/rules.rs`      |
| Audit log (names only)             | `src/audit.rs`      |
| PTY / piped exec                   | `src/exec.rs`       |
| PATH shim management               | `src/shim.rs`       |
| JSON Schema assembly (derived)     | `src/schema.rs`     |
| Secret value (zeroizing)           | `src/secret.rs`     |

### Invariants you must not break

1. **Consent before fetch.** Provider commands run only after
   `Decision::approved()`.
2. **No secret values in logs, prompts, the audit log, or the approvals
   cache.** `SecretValue`'s `Debug` redacts; the audit log records secret
   _names_. The only two boundaries values cross are the `0600` daemon
   socket and env-var injection into the wrapped child.
3. **Fail closed.** No daemon and no `--yes` ⇒ deny. No graphical
   environment and no `--yes` ⇒ deny. A required secret missing with no
   default ⇒ hard error before exec. Integration tests pin each.
4. **The approvals cache is scoped to the direct parent only:**
   `(wrap_name, ppid, parent_start_time)`. A postinstall hook has a
   different ppid; a recycled pid has a different start time. Both
   re-prompt.
5. **The published schema describes the parser.** `tests/schema_drift.rs`
   validates rules `secreq` writes against `docs/auto-rules.schema.json`,
   and feeds the wraps parser a config using every key
   `docs/wraps.schema.json` declares. Regenerate with
   `cargo run --example gen-schema > docs/wraps.schema.json`.
6. **The shim sentinel is load-bearing.** `shim::install` won't clobber a
   file that doesn't carry the sentinel; `shim::remove` won't delete one.
7. **`find_real_binary` must skip the shim dir**, or the shim recurses
   into itself.

If your change materially alters the trust model, the wire protocol, or
rule semantics, open an issue to align on the design **before** the code
lands. See [`CLAUDE.md`](./CLAUDE.md) for the conventions that go with
each of those surfaces.

## Authoring rules

Auto-rules let the daemon answer recurring asks without prompting.
There are two flavors, and the docs walk through each:

- **Declarative rules** (a match clause + a fixed approve/deny, created
  from the Rules view in `secreq view`): the default; prefer them
  whenever one can express the policy. Wire format and JSON Schema:
  [`docs/auto-rules.schema.json`](./docs/auto-rules.schema.json).
- **Programmable wasm rules** (a rule written as code, compiled to a
  sandboxed WebAssembly module): reach for these only when a match
  clause can't express the policy. Full authoring, testing, compiling,
  and `rules add-wasm` registration walkthrough:
  [`docs/wasm-rules.md`](./docs/wasm-rules.md).

To author a **wrap** itself (per-binary env injection, providers, cache
scope), see [`docs/wraps.md`](./docs/wraps.md) and point your editor at
[`docs/wraps.schema.json`](./docs/wraps.schema.json).

## Testing patterns

- **Pure logic** gets a unit test in the module (`#[cfg(test)] mod
tests`).
- **End-to-end behavior** gets an integration test in `tests/cli.rs`,
  driving the built binary via `env!("CARGO_BIN_EXE_secreq")`. Sandbox
  every test with a tempdir plus `XDG_CONFIG_HOME` and `XDG_STATE_HOME`
  pointed into it, so audit/remember state never touches your real home.
- Use a **fake provider** (`printf`/`sh`) rather than a real Keychain /
  `op` invocation, to avoid triggering biometric prompts in CI.

Every behavior change should come with a test. New fail-closed paths in
particular must be pinned by a test. That's how we keep the security
invariants honest.

## Submitting a change

1. Branch off `main` (never commit to `main` directly).
2. Keep the change focused: one logical change per PR.
3. Make the full dev loop green locally (tests, clippy, fmt, schema).
4. Fill in the PR template, including the security checklist.
5. Update docs alongside code: user-facing behavior → `docs/`;
   internals → the module comments and this file.

Commits and PRs should explain _why_, not just _what_. A reviewer of a
secrets tool needs to be able to reason about the security impact of a
change from its description alone.

## License

By contributing, you agree that your contributions are licensed under
the project's MIT License (the `license` field in
[`Cargo.toml`](./Cargo.toml)).
