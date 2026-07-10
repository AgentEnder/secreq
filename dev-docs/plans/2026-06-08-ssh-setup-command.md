# SSH agent setup command — implementation plan

> **For Claude:** REQUIRED SUB-SKILL: superpowers:executing-plans.

**Goal:** A `secreq ssh-setup` command that wires SSH clients to secreq's
agent socket by modifying config files (with `--undo` to reverse), and have
`secreq init` offer the same. Two methods, user-selected: `~/.ssh/config`
`IdentityAgent`, or shell-rc `SSH_AUTH_SOCK`.

**Architecture:** New `src/ssh_setup.rs` mirroring `src/path_setup.rs`'s
pure `plan()`/`apply()` + sentinel-bracketed managed-block + `home`-injectable
design. A `Target` enum selects the method. The block is reversible
(`remove()`), idempotent, and shown to the user before writing.

**Tech stack:** Rust; reuse `path_setup::detect_shell`/shell-file choice
(refactor shared bits to avoid duplication); `ssh_agent::default_agent_socket_path()`
for the socket path; `cliclack` for the interactive flow.

**Design decisions (settled in brainstorming):**
- Command surface: BOTH a standalone `secreq ssh-setup` AND `init` calls into it.
- Target file: BOTH supported, user chooses (`--method ssh-config|shell-rc`,
  interactive prompt when omitted).
- `~/.ssh/config`: PREPEND the managed block (ssh uses the first obtained
  `IdentityAgent`); create `~/.ssh` `0700`, keep `~/.ssh/config` `0600`.
- Shell-rc: APPEND a managed `SSH_AUTH_SOCK` block (mirror `path_setup`).
- `--undo` removes the sentinel-bracketed block from the target file(s).
- Warn if `config.ssh` is empty (nothing to serve yet); remind about the
  `op`-export prerequisite.

---

## Task A — `src/ssh_setup.rs` module (pure, fully unit-tested)

**Files:** create `src/ssh_setup.rs`; `pub mod ssh_setup;` in `src/lib.rs`.
Reuse `path_setup::{detect_shell, Shell}`; if `shell_config_path`/`caveat_for`
are useful, make them `pub(crate)` in `path_setup` rather than duplicate.

- `pub enum Method { SshConfig, ShellRc }`.
- Sentinels (distinct from PATH ones):
  `# >>> secreq managed SSH agent (do not edit by hand) >>>` /
  `# <<< secreq managed SSH agent <<<`.
- `pub struct SshSetupPlan { method, config_file, block, already_configured, caveat }`
  (mirror `path_setup::Plan`).
- `pub fn plan(home: &Path, method: Method, shell: Shell, agent_sock: &Path) -> Result<SshSetupPlan>`:
  - SshConfig → file `~/.ssh/config`; block = `Host *\n    IdentityAgent "<sock>"`
    wrapped in sentinels; `already_configured` if file contains the begin sentinel.
  - ShellRc → reuse the shell→file mapping; block = `export SSH_AUTH_SOCK="<sock>"`
    (fish: `set -gx SSH_AUTH_SOCK <sock>`); caveat mirrors path_setup's shell caveats.
- `pub fn apply(plan: &SshSetupPlan) -> Result<bool>`:
  - Idempotent (sentinel present → `Ok(false)`).
  - SshConfig → ensure `~/.ssh` exists `0700`; PREPEND block above existing
    content; set file mode `0600`.
  - ShellRc → APPEND (reuse path_setup's append-with-leading-newline logic).
- `pub fn remove(home, method, shell) -> Result<bool>`: strip the
  sentinel-bracketed block (begin..=end inclusive, plus a trailing blank line)
  from the target file; `Ok(false)` if absent.
- Tests (TDD): ssh-config block content + prepend ordering + 0600; shell-rc
  append + fish variant; idempotent re-apply; remove round-trips (apply then
  remove yields original); already_configured detection; unknown-shell error
  for ShellRc.

**Commit:** `feat(ssh-setup): plan/apply/remove for IdentityAgent + SSH_AUTH_SOCK`

## Task B — `ssh-setup` subcommand + `init` integration

**Files:** `src/lib.rs`/`src/main.rs` (clap subcommand), `src/commands.rs`
(handler + init hook), `tests/cli.rs`.

- Clap: `secreq ssh-setup [--method ssh-config|shell-rc] [--undo]`.
- Handler `commands::ssh_setup(method: Option<Method>, undo: bool, config_path)`:
  - Resolve `agent_sock` via `ssh_agent::default_agent_socket_path()`.
  - Load config; if `config.ssh` empty, `cliclack::log::warning` (still allow setup).
  - If `--method` omitted, `cliclack::select` between the two methods.
  - `undo` → `remove()` and report; else `plan()` → show block via
    `cliclack::note` → confirm → `apply()`; print the `op`-export reminder and
    a "restart your shell / new ssh sessions pick this up" note.
- `init`: after PATH setup, offer SSH setup (a confirm prompt) that calls the
  same handler logic (extract a shared non-interactive core so both call it).
- Tests: `tests/cli.rs` drives `ssh-setup --method ssh-config` against a temp
  `$HOME`, asserts `~/.ssh/config` gets the block + mode `0600`; `--undo`
  removes it; `--method shell-rc` writes the rc block. Use the existing
  cli-test harness patterns (temp HOME/config).

**Commit:** `feat(cli): secreq ssh-setup command + init integration`

## Task C — docs + final verification

- Update `docs/ssh-agent.md` (replace the manual "add this to ~/.ssh/config"
  steps with `secreq ssh-setup`, keep the manual block as the fallback) and
  the `init` guidance text (point at the now-automatic flow).
- `cargo fmt`/`clippy -D warnings`/`cargo test` green. No UI change → no
  screenshot regen.
- **Commit:** `docs: document secreq ssh-setup`
