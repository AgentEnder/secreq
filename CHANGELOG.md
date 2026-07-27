# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are cut with [cargo-release](https://github.com/crate-ci/cargo-release)
(see `release.toml`). Pushing a `vX.Y.Z` tag runs
`.github/workflows/release.yml`, which cross-compiles, checksums, and publishes
the GitHub Release using the notes from the matching section below.

## [Unreleased]

### Added

- **Public distribution channels.** Install with `curl -fsSL
https://craigory.dev/secreq/install.sh | sh` (detects OS/arch, downloads the release
  binary, and verifies it against the signed `SHA256SUMS`), `brew install
AgentEnder/secreq/secreq`, or `cargo install secreq`. The release workflow
  now also generates the Homebrew formula from the real checksums, and
  cargo-release publishes the crate to crates.io. See [`docs/install.md`](docs/install.md).

## [0.1.0] - 2026-07-22

Initial release.

### Added

- **Per-binary wraps.** `secreq wrap <bin>` records how a binary's
  credentials are sourced (`--env NAME=secret://…`) and installs a PATH shim
  so every `execvp` of that binary — including `npm` postinstalls — routes
  through `secreq x`, resolves its `secret://` refs, and injects the values.
- **Multi-provider `secret://` references.** Resolve credentials from any
  store with a CLI — 1Password, macOS Keychain, `pass`, and more — behind a
  single reference syntax.
- **Provenance-aware consent daemon.** A long-lived daemon prompts (egui
  panel or terminal) before any secret is released, keyed on
  `(wrap_name, ppid, parent_start_time)`; approvals are remembered for the
  lifetime of the requesting parent process. Concurrent requests in one
  process tree union into a single prompt.
- **Auto-approval rules**, including sandboxed WASM rules authored with the
  `secreq-rule` AssemblyScript SDK, wired through the rule model, evaluator,
  and daemon.
- **`secreq run`** — `op run` for every store: resolve ambient `secret://`
  refs (and `--env-file` entries) then exec a command with values injected
  and masked.
- **Output masking** on the wrapped command's stdout/stderr, with `--raw`
  to opt out.
- **SSH agent** support: the daemon signs on the SSH path and records each
  outcome to the audit log.
- **Scoped remote secret agent** serving `secret://` refs to a guest VM over
  a scoped socket, with the host-declared scope as principal.
- **Audit log** of every resolve, sign, abandoned ask, and decision.
- **`SECREQ_BUILD_ID`** stamped at build time (`build.rs`); the CLI and
  daemon use it to detect and restart a stale daemon, and `secreq --version`
  reports it.
