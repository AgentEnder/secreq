# Contributing to secreq

Thanks for your interest in `secreq` — a per-binary CLI wrapper that
injects credentials from your secret store of choice behind a
provenance-aware consent prompt. Because this is a **secrets tool**,
contributions are held to a slightly higher bar than usual: a bug here
can leak a credential or weaken a trust boundary. This document is the
short version of what that means in practice.

By participating you agree to abide by our
[Code of Conduct](./CODE_OF_CONDUCT.md).

> **Found a security issue?** Do **not** open a public issue or PR.
> Follow the private disclosure process in [SECURITY.md](./SECURITY.md).

## Ways to contribute

- **Report a bug** — open an issue with a reproduction (see the bug
  template). Never paste real secret values, tokens, or `secret://`
  refs that point at live credentials.
- **Request a feature** — open an issue describing the problem first,
  then the proposed shape. `secreq` deliberately does *not* do some
  things (project-scope config, cloud sync, rotation — see
  [`dev-docs/AGENTS.md`](./dev-docs/AGENTS.md) → "What this project
  deliberately doesn't do"); check that list before proposing.
- **Send a patch** — small, focused PRs are easiest to review. For
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

Run all four of these before you push — CI enforces every one:

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
- **Schema drift is a build failure.** `tests/schema_drift.rs` fails if
  `docs/wraps.schema.json` or `docs/auto-rules.schema.json` fall out of
  sync with their generators. Regenerate with:
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
  normal `cargo test` won't run them — but CI does.

## Where things live

Start with the contributor docs in [`dev-docs/`](./dev-docs/):

- **[`dev-docs/AGENTS.md`](./dev-docs/AGENTS.md)** — the fastest
  orientation: the mental model in 60 seconds, a module map (which file
  owns which concept), common tasks, and the **invariants you must not
  break** (consent before fetch; no secret values in logs/prompts/audit;
  fail-closed at boundaries; cache scoped to the direct parent).
- **[`dev-docs/architecture.md`](./dev-docs/architecture.md)** — the
  data flow for `secreq <binary>`, consent-daemon threading, and the
  masking algorithm.
- **[`dev-docs/plans/`](./dev-docs/plans/)** — historical design docs.
  Context, not source of truth; the code and `AGENTS.md` win.

Design docs that are load-bearing for the trust model live under
`dev-docs/plans/` and are called out in [`CLAUDE.md`](./CLAUDE.md) — if
your change materially alters the trust model, wire protocol, or rule
semantics, update the relevant plan **before** the code lands.

## Authoring rules

Auto-rules let the daemon answer recurring asks without prompting.
There are two flavors, and the docs walk through each:

- **Declarative rules** (a match clause + a fixed approve/deny, created
  from the Rules tab in `secreq view`) — the default; prefer them
  whenever one can express the policy. Wire format and JSON Schema:
  [`docs/auto-rules.schema.json`](./docs/auto-rules.schema.json).
- **Programmable wasm rules** (a rule written as code, compiled to a
  sandboxed WebAssembly module) — reach for these only when a match
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
particular must be pinned by a test — that's how we keep the security
invariants honest.

## Submitting a change

1. Branch off `main` (never commit to `main` directly).
2. Keep the change focused — one logical change per PR.
3. Make the full dev loop green locally (tests, clippy, fmt, schema).
4. Fill in the PR template, including the security checklist.
5. Update docs alongside code: user-facing behavior → `docs/`;
   internals → `dev-docs/`.

Commits and PRs should explain *why*, not just *what*. A reviewer of a
secrets tool needs to be able to reason about the security impact of a
change from its description alone.

## License

By contributing, you agree that your contributions are licensed under
the project's MIT License (the `license` field in
[`Cargo.toml`](./Cargo.toml)).
