//! `secreq` — a local-first CLI that resolves secrets from multiple providers
//! based on a declarative manifest, gates them behind a per-user consent
//! daemon, injects them as env vars, and runs a command inside a PTY that
//! masks any secret value that leaks to the child's output.
//!
//! Module map:
//! - [`manifest`]  — JSON5 config model: groups, providers, per-secret settings, merge.
//! - [`reference`] — `secret://<provider>/<locator>` parsing.
//! - [`secret`]    — zeroizing secret value type (never enters a GC heap).
//! - [`provider`]  — Tier-1 declarative read execution.
//! - [`resolve`]   — union resolution: eager set ∪ ambient env refs.
//! - [`mask`]      — sliding-window multi-secret output masking.
//! - [`provenance`]— walk the parent process tree for the consent prompt.
//! - [`consent`]   — `Decision` enum + persistent approvals cache I/O.
//! - [`daemon`]    — long-running consent daemon (socket + queue + egui UI).
//! - [`audit`]     — append-only JSONL audit log (names only, never values).
//! - [`exec`]      — PTY / piped child execution with masking + env injection.

/// Recursion-guard env var. Set on every subprocess `secreq` spawns to
/// *resolve* a secret (a provider's retrieve/batch command — see
/// [`provider`]). When a wrapped binary is itself a secret provider
/// (e.g. `op` is wrapped *and* used as a `secret://op/...` provider),
/// the retrieve command PATH-resolves to our own shim and re-enters
/// `secreq <binary>`. [`commands::wrap_run`] checks for this var and
/// passes straight through to the real binary instead of gating, so
/// resolving one wrap's secret doesn't pop a consent prompt for the
/// provider CLI. It is *not* a security boundary: any same-user process
/// could set it (or just invoke the real binary directly), which is the
/// same trust model as [`daemon::client::NO_DAEMON_ENV`].
pub const RESOLVING_ENV: &str = "SECREQ_RESOLVING";

pub mod audit;
pub mod cli;
pub mod commands;
pub mod consent;
pub mod daemon;
pub mod exec;
pub mod manifest;
pub mod mask;
pub mod path_setup;
pub mod provenance;
pub mod provider;
pub mod recommendations;
pub mod reference;
pub mod resolve;
pub mod rules;
pub mod schema;
pub mod secret;
pub mod shim;
pub mod ssh_setup;
pub mod ssh_sign;
pub mod wraps;
