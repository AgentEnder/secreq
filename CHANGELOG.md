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

## [0.2.0](https://github.com/AgentEnder/secreq/compare/v0.1.0...v0.2.0) - 2026-08-11

### Added

- *(link)* add CLI lifecycle and documentation ([#318](https://github.com/AgentEnder/secreq/pull/318))
- *(link)* sync signed remote decisions
- *(link)* add QR pairing enrollment flow
- *(link)* verify canonical signed decisions
- *(secrets)* declare a secret once, with a per-secret cache TTL ([#310](https://github.com/AgentEnder/secreq/pull/310))
- *(cli)* add `secreq rules new-wasm <dir>` ([#264](https://github.com/AgentEnder/secreq/pull/264))
- *(rules)* scaffold a buildable project, not a bare rule.ts ([#264](https://github.com/AgentEnder/secreq/pull/264))
- *(#265)* per-secret rule evaluation — approve iff every requested secret is blessed
- *(manifest)* derive serde on the provider model

### Fixed

- *(daemon)* reap window children instead of leaking zombies
- *(link)* verify asks and redact LAN snapshots ([#317](https://github.com/AgentEnder/secreq/pull/317))
- *(link)* harden live client and bundle checks ([#317](https://github.com/AgentEnder/secreq/pull/317))
- *(link)* sign decisions without Web Crypto ([#317](https://github.com/AgentEnder/secreq/pull/317))
- *(link)* harden enrollment boundaries
- *(link)* reconnect saturated event streams
- *(link)* bound SSE and nonce lifecycles
- *(migrate)* make private dirs umask-independent
- *(config)* stop writing a header for a table that only holds tables
- *(config)* un-garble the `--env` rejection, and cover it with a test ([#310](https://github.com/AgentEnder/secreq/pull/310))
- *(rules)* a scaffold's files took the umask's answer too ([#264](https://github.com/AgentEnder/secreq/pull/264))
- *(rules)* a scaffold under a hostile umask was unwritable ([#264](https://github.com/AgentEnder/secreq/pull/264))
- *(ci)* allow the one conversion that is only useless on Linux
- satisfy clippy on Linux, restore the publish guard, and correct the crate URLs

### Other

- review snapshot 1
- Merge #197: use the published SDK scaffold path
- Merge #298: rebuild project documentation
- Merge #314: add LAN listener and pairing transport
- Merge #312: persist device link registry
- Merge #425: add rule usage stats and SDK test helpers
- Merge #423: make rule mutations stale-safe
- Merge #418: validate wasm-declared subjects
- Merge #417: scope auto-rules by wrap
- Merge #416: add wrap env_secrets
- Merge #309: record denial reasons
- Merge #324: report and preserve background survivors
- Merge #373: make migration permissions umask-independent
- *(config)* write named edits, not a reconciled model
- Merge #21: move config to TOML, with an m0003 migration
- migrate the workspace to pnpm + Nx, and give every package a graph node
- *(manifest)* delete the secrets.json5 loader
- *(resolve)* delete the manifest-era plan builder
- *(rules)* describe the reload the daemon actually does
- *(cli)* give the daemon-death test the display it depends on

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
