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
pub mod reference;
pub mod resolve;
pub mod schema;
pub mod secret;
pub mod shim;
pub mod wraps;
