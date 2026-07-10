# Complete SSH onboarding — implementation plan

> **For Claude:** REQUIRED SUB-SKILL: superpowers:executing-plans.

**Goal:** Make SSH onboarding end-to-end: declare the identity in
`wraps.json5`, install the daemon as a login service so the agent socket
is always live, and wire SSH clients — orchestrated by `secreq ssh-setup`,
with each step also a standalone command.

**Decisions (brainstormed):**
- Identity step: BOTH provider-assisted (op discovery) and manual entry.
- Auto-start: AUTOMATE — `secreq daemon install [--undo]` writes + loads a
  per-user login service (launchd LaunchAgent / systemd --user unit).
- `ssh-setup` orchestrates all three steps; each is also standalone.

---

## Task 1 — Fix `write_config` to serialize the `ssh` block (DATA-LOSS BUGFIX)

`src/commands.rs::config_to_json_value` omits `config.ssh`, so writing the
config (via `secreq wrap`, `secreq ssh add`, etc.) silently drops SSH
identities. Fix first — it's a prerequisite for Task 3 and a shipped bug.

- TDD: in `commands.rs` tests (or wherever `write_config` is tested), add
  `write_config_preserves_ssh_block`: build a `WrapsConfig` with one `ssh`
  identity (+ a wrap + a provider), `write_config` to a temp file, re-read &
  parse, assert the `ssh` identity (key_id, public_key, private_key ref,
  reason) survives. Watch it fail.
- Extend `config_to_json_value` to emit an `ssh` object: for each
  `SshIdentity`, `{ $reason?, public_key, private_key: "<ref string>" }`.
  Reconstruct the `secret://provider/locator` string from the `Reference`
  (check `Reference`'s Display/round-trip; add one if missing).
- Keep the existing round-trip self-check; it now also covers `ssh`.
- **Commit:** `fix(config): persist the ssh block on write (was silently dropped)`

## Task 2 — `secreq daemon install` (login auto-start)

**Files:** create `src/autostart.rs`; `src/cli.rs` (`DaemonAction::Install { undo }`
or a new subcommand); `src/commands.rs` handler; tests.

- `pub enum Platform { Macos, Linux }`; detect via `cfg!`.
- Pure render fns (unit-testable):
  - macOS: `render_launchd_plist(exe: &Path, log_path: &Path) -> String` —
    `Label com.secreq.daemon`, `ProgramArguments = [<exe>, "daemon", "--fg"]`,
    `RunAtLoad true`, `KeepAlive true`, `StandardOutPath`/`StandardErrorPath`
    = daemon log, and **`EnvironmentVariables.PATH`** set to a sane default
    (`/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`) so the
    daemon can find `op`/provider binaries under launchd's minimal env.
  - Linux: `render_systemd_unit(exe, log_path) -> String` — `[Service]
    ExecStart=<exe> daemon --fg`, `Restart=on-failure`; `[Install]
    WantedBy=default.target`. (PATH inherited from the user systemd env;
    note in docs that `op` must be on it.)
- Paths: macOS `~/Library/LaunchAgents/com.secreq.daemon.plist`; Linux
  `~/.config/systemd/user/secreq.service`. `home`-injectable for tests.
- `plan(home, exe, log_path) -> Plan { service_file, contents, already_installed }`.
- `apply(plan)` writes the file (creating parent dirs). The LOADER step
  (`launchctl bootstrap gui/$UID <file>` / fallback `launchctl load -w`;
  `systemctl --user daemon-reload && systemctl --user enable --now secreq.service`)
  is a SEPARATE side-effecting fn `load_service(platform)` — keep it out of
  the pure path so tests cover render + write without touching the real
  service manager. `apply` returns enough for the handler to then call
  `load_service`.
- `remove(home, platform)` deletes the file; `unload_service(platform)`
  (`launchctl bootout` / `systemctl --user disable --now`) reverses the load.
- Handler `commands::daemon_install(undo: bool)`: resolve
  `std::env::current_exe()` and the daemon log path (reuse the existing
  log-path helper used by `secreq daemon log-path`); render → show the file
  + path via `cliclack::note` → confirm/`--yes` → write + load (or undo).
  Print where it wrote and how to check status.
- Tests: render contains the exe path + `daemon --fg` + KeepAlive/RunAtLoad
  (macOS) or `ExecStart`/`enable` semantics (Linux); `apply` writes the file;
  `remove` deletes it; idempotent `already_installed`. Do NOT invoke the real
  launchctl/systemctl in tests.
- **Commit:** `feat(daemon): secreq daemon install — login auto-start service`

## Task 3 — `secreq ssh add` (write an ssh identity)

**Files:** `src/cli.rs` (`SshAdd`/`ssh add` args), `src/commands.rs` handler;
tests. Mirror `commands::wrap` + `write_config` (now ssh-aware after Task 1).

- Args: `secreq ssh add <name> [--public-key <path-or-literal>]
  [--private-key secret://...] [--reason <text>]`. Missing pieces prompt
  interactively.
- Public key: if `--public-key` is a path to an existing file, read it; if it
  starts with `ssh-`/`ecdsa-`/`sk-`, treat as literal; else error. Validate it
  parses via `ssh_key::PublicKey::from_openssh`.
- Private key: parse `--private-key` via `Reference::parse`. If omitted:
  - **Provider-assisted (op):** if `op` is on PATH, offer to run
    `op item list --categories "SSH Key" --format json`, present the items
    (title + vault), let the user pick, then derive
    `private_key = secret://op/<vault>/<title>/private key` and, if
    `--public-key` was not given, fetch the public key via
    `op read "op://<vault>/<title>/public key"`. Best-effort; any failure →
    fall to manual.
  - **Manual:** prompt for the `secret://...` reference.
- Insert into `config.ssh` (error if name already exists unless `--force`),
  `write_config`. Print the op-export reminder.
- Tests (`tests/cli.rs`): `ssh add github --public-key <tmp .pub>
  --private-key secret://op/Private/GitHub/private\ key` writes a parseable
  `ssh` block; re-running errors on duplicate; the written config re-parses
  with the identity. (op-assisted path needs `op`; gate behind presence or
  skip — test the manual path deterministically.)
- **Commit:** `feat(cli): secreq ssh add — configure an SSH identity`

## Task 4 — `ssh-setup` orchestration

**Files:** `src/commands.rs` (extend `ssh_setup_core`); tests.

- Turn `ssh_setup_core` into a guided 3-step flow (each step skippable):
  1. **Identity:** if `config.ssh` empty → offer `ssh add` (call its core);
     else list configured identities and offer to add another or continue.
  2. **Auto-start:** if the login service isn't installed (check the service
     file path) → offer `daemon install`.
  3. **Client wiring:** the existing method-select + block write.
- Fix the misleading reminder at `commands.rs:415` ("it auto-starts") — it
  only truly auto-starts once the login service is installed; reword to point
  at step 2 / `secreq daemon install`.
- Keep `--method`/`--undo`/`--yes` working; in non-interactive (`--yes` +
  `--method`) mode, run client wiring only (don't force identity/service
  prompts) unless explicit flags request them. Document the behavior.
- Tests: an end-to-end-ish `ssh-setup --yes --method ssh-config` still writes
  the client block (the orchestration must not break the existing path).
- **Commit:** `feat(cli): ssh-setup orchestrates identity + autostart + wiring`

## Task 5 — docs + final verification

- `docs/ssh-agent.md`: document the full onboarding — `secreq ssh add`,
  `secreq daemon install`, and `secreq ssh-setup` running all three. Fix any
  "auto-starts" wording. Keep op-export / TTL / trust-model notes.
- `docs/cli.md`: add `ssh add` and `daemon install` entries.
- `cargo fmt`/`clippy -D warnings`/`cargo test` green. No UI change → no
  screenshot regen (confirm). No leftover TODO/Task-N markers.
- **Commit:** `docs: document full SSH onboarding (ssh add, daemon install)`
