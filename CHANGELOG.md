# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**This file is generated below the `[Unreleased]` line.**
[release-plz](https://release-plz.dev) writes each release section from the
conventional commits since the last tag, in a pull request that also bumps the
version. Merging that PR tags, and the tag runs
`.github/workflows/release.yml`: four targets cross-compiled, checksummed and
cosign-signed, the GitHub Release published, the Homebrew formula pushed to
the tap, and the crate published to crates.io. Nothing here is written by
hand — put the prose in the commit message.

## [Unreleased]

## [0.1.0] - 2026-07-27

Initial release.

### Added

- **Public distribution channels.** Install with `curl -fsSL
https://craigory.dev/secreq/install.sh | sh` (detects OS/arch, downloads the
  release binary, and verifies it against the signed `SHA256SUMS`),
  `brew install AgentEnder/secreq/secreq`, or `cargo install secreq`. The
  release workflow generates the Homebrew formula from the real checksums,
  pushes it to the tap, and publishes the crate to crates.io from CI over
  OIDC. See [`docs/install.md`](docs/install.md).

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
