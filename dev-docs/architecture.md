# Architecture

This page is for contributors — the module map, the data flow, the
load-bearing invariants. For *using* the tool, start with
[../docs/overview.md](../docs/overview.md) and
[../docs/cli.md](../docs/cli.md).

## Module map

```
src/
├── lib.rs           — public module list + session env-var constants
├── main.rs          — thin: calls cli::run(); maps Result to exit code
├── cli.rs           — clap definitions and dispatch; allow_external_subcommands
├── commands.rs      — every subcommand's implementation (admin + wrap_run)
├── wraps.rs         — wraps.json5 config model: WrapsConfig, Wrap, parser
├── manifest.rs      — Provider / StoreCapability / BatchRetrieve types + builtins
├── reference.rs     — secret://provider/locator parsing
├── secret.rs        — zeroizing SecretValue type
├── provider.rs      — provider execution (retrieve + retrieve_batch + store)
├── resolve.rs       — provider-grouped resolution with auto-batching
├── mask.rs          — streaming multi-secret output masker
├── provenance.rs    — parent-process tree via sysinfo (incl. start_time)
├── consent.rs       — Decision enum + ApprovalEntry record (in-memory only)
├── daemon/          — long-running consent daemon (socket + queue + egui UI)
│   ├── mod.rs       — entry point, pidfile-locked singleton, eframe::run_native
│   ├── proto.rs     — wire types (ClientMsg / DaemonMsg / Ask / DedupeKey)
│   ├── server.rs    — UnixListener accept loop; one thread per connection
│   ├── state.rs     — coalescing queue + in-memory approvals cache
│   ├── ui.rs        — egui app: hidden until queue is non-empty
│   ├── client.rs    — auto-spawn + connect; honors SECREQ_NO_DAEMON
│   └── log.rs        — persistent JSONL daemon log + 60s CPU/mem samples
├── audit.rs         — JSONL audit log (names only, never values)
├── exec.rs          — PTY + piped child execution with masking
├── shim.rs          — PATH shim install/remove (sentinel-protected)
├── path_setup.rs    — shell detection + PATH-config update for `init`
└── schema.rs        — JSON Schema for wraps.json5 (source of truth)
```

## Data flow for `secreq <BINARY> [args…]`

```
┌─ cli ────────────────────────────────────────────────────────────────────┐
│ parse argv. Anything not an admin verb is an external subcommand;        │
│ dispatch to commands::wrap_run                                            │
└────────────────────────┬─────────────────────────────────────────────────┘
                         ▼
┌─ commands::wrap_run ─────────────────────────────────────────────────────┐
│ 1. load config (built-in providers always overlaid)                      │
│ 2. lookup wrap by binary name                                             │
│      Some(wrap) → continue                                                │
│      None       → passthrough: exec the real binary with no injection    │
│ 3. caller_chain() via sysinfo (each Caller carries pid + start_time)     │
│ 4. consent — handed off to the daemon:                                    │
│      --yes              → return Approve, never contact the daemon       │
│      SECREQ_NO_DAEMON   → return Deny (test/automation override)         │
│      no graphical env   → return Deny (DISPLAY/WAYLAND on Linux)         │
│      otherwise:                                                           │
│        daemon::client::request_consent(Ask {                              │
│          command, cwd, callers, secrets,                                  │
│          dedupe_key: (wrap, ppid, parent_start_time),                    │
│        })                                                                 │
│        → auto-spawns the daemon if no socket is live, then blocks         │
│          on the reply.                                                   │
│ 5. append audit entry (names only)                                        │
│ 6. if denied → exit 1                                                     │
│ 7. resolve env: for each entry, retrieve via provider                     │
│      auto-batches when ≥2 entries share a batch-capable provider          │
│      (no-op for a gate-only wrap — empty env, nothing to resolve)         │
│ 8. find real binary: scan PATH skipping shim_dir (avoid recursion)       │
│ 9. exec::run with the real binary, args, env overrides, secrets list     │
│       PTY (interactive) or piped; output masked unless --raw              │
│ 10. propagate child exit code                                            │
└──────────────────────────────────────────────────────────────────────────┘
```

## Consent daemon

A long-running per-user process owns the consent queue, the approvals
cache, and the GUI. Started on-demand by the first client that finds no
live socket, exits after 2 hours of empty queue.

### Why a daemon

Without it, N parallel `secreq gh` invocations (a monitoring app firing
50 `gh api` calls at once) each independently check the cache, all miss,
and all prompt — the user sees 50 modal dialogs.

With it, all N connect to the same daemon, the daemon coalesces by
`(wrap, ppid, parent_start_time)` into a single queue entry showing
"×50", one click resolves every waiter.

### Process layout

```
┌─ secreqd process (singleton per user) ──────────────────────────────────┐
│                                                                         │
│  main thread        accept thread          connection threads (N)        │
│  ───────────        ─────────────          ─────────────────────         │
│  eframe::          UnixListener::          read ClientMsg                │
│    run_native →    incoming() →            handle_message →              │
│  ConsentApp           spawn per accept       cache hit  → DaemonMsg     │
│    .update()                                 cache miss → submit_ask,    │
│  reads state,                                            rx.recv()       │
│  draws queue,                                back DaemonMsg::Decision   │
│  resolves entries                                                       │
│                                                                         │
│         ─────── all share: Arc<Mutex<State>> ───────                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

The GUI event loop owns the main thread (macOS AppKit requires it; also
true on most platforms via winit). The accept loop runs on a side
thread; each connection thread parks on a `mpsc::Receiver` until the UI
resolves the corresponding queue entry.

### Singleton enforcement

`$XDG_RUNTIME_DIR/secreq/daemon.pid` is opened and locked with
`flock(LOCK_EX | LOCK_NB)`. A second daemon process sees the lock held
and exits 0 cleanly — the auto-spawning client simply connects to the
existing daemon.

### Socket path

`$XDG_RUNTIME_DIR/secreq/consent.sock` (mode 0600). Falls back to
`$TMPDIR/secreq-<uid>/consent.sock` when `$XDG_RUNTIME_DIR` is unset.

### Auto-spawn

`daemon::client::connect_or_spawn` first tries to connect optimistically;
on `ECONNREFUSED` / `ENOENT` it re-execs `secreq daemon` (via
`std::env::current_exe()`), polls for the socket with exponential
backoff up to 5 seconds, and *also* monitors the child process — if the
daemon exits before binding (e.g. eframe failed to init), the client
bails immediately with a useful error rather than waiting the full
timeout.

### Idle exit

The headless daemon main loop wakes once per second (`MAIN_LOOP_TICK`).
On each tick, if there's no attached consent window
(`consent_subscriber_count() == 0`) AND there's been no activity for the
idle timeout (`last_activity().elapsed() >= 2 hours`), it calls
`guard.request_shutdown()`. That flips an atomic shutdown flag, which the
main `while` loop observes and breaks out of, returning from `run`. The
socket file is cleaned up on drop. An attached consent window suppresses
the timeout entirely: while one is subscribed, every tick calls
`touch()` to reset the idle clock, so leaving the window open never
trips idle-exit.

### What crosses the daemon socket

- **Metadata** (always): command, cwd, caller chain, env-var names,
  provider schemes, locators, provider invocation templates.
- **Resolved secret values** (on Approve): the daemon runs the providers
  itself and ships values back to every waiter. This is the load-bearing
  reason the daemon resolves instead of just voting — it collapses N
  parallel client-side `op read` invocations (and the biometric prompts
  that come with them) into exactly one.

The trust boundary is the per-user `0600` socket. Any process running as
the user already has the same access the daemon does, so keeping
resolved values on the wire doesn't expand the threat surface — it
consolidates work that would otherwise happen N times in N clients.

### `SECREQ_NO_DAEMON` env var

Setting this to a non-empty value disables the client's daemon path
entirely — every consent request fails closed without contacting (or
spawning) a daemon. Used by tests and by automation that can't show a
GUI. `--yes` still works regardless.

## Load-bearing invariants

### Consent gates the fetch

`resolve_wrap_env` is called only after `decision.approved()`. Denying never
invokes a provider, no Touch ID prompt, no audit entry of a fetch we threw
away.

### Approval is direct-parent-scoped

Cache key is `(wrap_name, ppid, parent_start_time)`. Implications:

| Scenario | Outcome |
|---|---|
| Same shell, re-invocation | Cache hit. No prompt. |
| New terminal | Different ppid → prompt. |
| npm postinstall calls `gh` | Different ppid (npm, not your shell) → prompt. |
| Pid recycled into a new process | Different `start_time` → prompt. |

The `start_time` component is what makes the cache pid-recycle safe.
Without it, a recycled pid could grant approval to the new process.

### Parallel asks coalesce in the daemon

The dedupe key sent on every `Ask` matches the cache key. The daemon's
queue is `HashMap<DedupeKey, QueueEntry>`; a second ask with the same key
folds into the existing entry's waiter list rather than creating a new
row. Resolving the row replies to *every* waiter with one decision. This
is the load-bearing invariant that fixes the "monitoring app fires 50
parallel `gh api` calls" problem.

### Secret values stay inside the user's trust boundary

`SecretValue` wraps `zeroize::Zeroizing<String>`; on drop the memory is
scrubbed. Secrets are never:
- Logged.
- Printed via `Debug` (the impl shows `SecretValue(***)`).
- Stored in the remember cache (which is keyed by tuples of identifiers,
  not anything secret).
- Recorded in the audit log (names only).

Two places values cross a process boundary, both inside the per-user
trust boundary:
- **Daemon → client over the `0600` consent socket**, when the daemon
  ships resolved values back to a wrap that the user approved. This is
  what lets N parallel asks share one provider invocation.
- **Client → child via env-var injection**, when the wrapped command
  finally runs.

### `find_real_binary` skips the shim dir

Without this, our shim recurses: `secreq gh` finds `<shim_dir>/gh`, execs
it, which calls `secreq gh` again. The `skip` argument is mandatory; the
test `wrap_run_injects_env_and_masks_output…` exercises this.

### Resolution doesn't re-gate a wrapped provider CLI

If a binary is both **wrapped** *and* used as a `secret://` provider — the
canonical case is `op`, gated as a [gate-only wrap](#wraps-config) yet
named in `secret://op/...` references — then resolving another wrap's
secret would PATH-resolve `op` to our shim and pop a *second* consent
prompt (and, under `--yes`, hang on a prompt the caller never asked for).

`provider::{retrieve, retrieve_batch, store}` set `SECREQ_RESOLVING=1`
(`crate::RESOLVING_ENV`) on every subprocess they spawn. `wrap_run`
checks for it up front and passes straight through to the real binary —
no consent, no injection. The marker is scoped to secreq's own
resolution subprocess, so a wrapped *script* that calls `op` itself still
gates normally; only the internal `op read` secreq fires is skipped. It's
not a security boundary (any same-user process could set it, same model
as `SECREQ_NO_DAEMON`), just a recursion guard. Exercised by
`resolving_env_bypasses_the_gate_for_a_wrapped_provider`.

### Fail-closed at every boundary

| Boundary | Failure mode |
|---|---|
| Consent prompt unavailable (no tty + no `--yes`) | Deny. |
| Required env entry's provider fails with no default | Hard error before exec. |
| Consent IPC socket unreachable (nested run) | Deny — never falls back to a prompt the user can't see. |
| Provider retrieve returned non-zero exit | Apply default if present; else hard error. |
| Shim target file exists without our sentinel | `wrap` refuses to install; `unwrap` refuses to remove. |
| Shell-config edit (`init`) | Block is shown to the user; gated by y/N prompt; sentinel-bracketed so future re-runs are no-ops. |

## Masking algorithm

`mask::Masker` is a streaming byte-exact redactor.

- **Multi-secret.** Tries longest-first; overlapping matches prefer the
  longer secret.
- **Binary-safe.** Operates on bytes, never UTF-8-dependent.
- **Split-across-chunks.** A secret straddling two `push` calls is still
  caught — we hold back only the trailing bytes that could begin a secret
  in the next chunk. Latency is zero when nothing matches.
- **Re-entrant.** Each masker has its own state; nested-run masking
  composes (inner masks its values; outer's masker masks its own, never
  finds the inner's inside `********`).

## Consent ceremony

The client never renders the prompt itself. Every consent request
(except `--yes`, which bypasses entirely) is sent to the per-user
consent daemon over a Unix-domain socket; the daemon renders an egui
window listing pending requests and replies with a `Decision`. See the
["Consent daemon" section](#consent-daemon) above for the process and
threading details.

### Approvals cache

`ApproveRemember` stores an entry as `(wrap, ppid, parent_start_time)`
inside the daemon process's memory. There's no TTL and no disk backing:
the cache lifetime is bounded by both the parent process *and* the
daemon process. When the parent exits, the entry is unreachable (no new
process can share both the pid and the start_time); when the daemon
exits, every entry is gone.

`secreq daemon stop` is the supported way to clear the cache — it
sends a `Shutdown` message over the socket, the daemon exits, and the
next wrap invocation auto-spawns a fresh one with an empty list. Idle
exit (2 hours of empty queue + no activity) achieves the same thing
without user action.

The cache is **daemon-owned** at runtime. Clients never see it directly;
the only signal that an approval exists is the absence of a prompt on a
subsequent ask.

### `--yes` and `SECREQ_NO_DAEMON`

`--yes` bypasses the daemon entirely and returns `Decision::Approve`.
This is the supported path for scripted/CI use.

`SECREQ_NO_DAEMON=1` disables the daemon path without auto-approving:
consent fails closed. Used by tests and by automation that can't show a
GUI window.

On Linux/BSD, missing both `$DISPLAY` and `$WAYLAND_DISPLAY` is also
treated as fail-closed — there's no point spawning a daemon that will
crash on `winit` init.

## PTY vs piped exec

`exec::run` picks based on whether `stdin` *and* `stdout` are terminals:

| Both TTYs | Use PTY (`portable-pty`); enable raw mode on our stdin; forward `SIGWINCH`. Reader thread streams pty → mask → stdout. Writer thread streams stdin → pty. |
| Otherwise | Use `std::process::Command` with stdout+stderr piped; two mask-pumping threads, one per stream. |

Masking is the same in both paths — just the I/O plumbing differs.

## Wraps config

`WrapsConfig::parse` walks a `serde_json::Value` (produced by `json5::from_str`)
and builds a typed model:

```rust
WrapsConfig {
    shim_dir:  Option<PathBuf>,            // $shim_dir
    wraps:     BTreeMap<String, Wrap>,     // binary_name → Wrap
    providers: BTreeMap<String, Provider>, // user-declared (built-ins overlay at load time)
}
```

We parse to `Value` first (rather than deriving `Deserialize` on `WrapsConfig`)
because the on-disk shape has *dynamic keys*: arbitrary binary names + a
reserved `providers` key + `$`-prefixed metadata. A fixed `Deserialize`
target can't express "any key except these"; walking a `Value` and
validating field-by-field can, with much better error messages.

A `Wrap` with an empty `env` is a **gate-only wrap**: it routes the
binary through the consent daemon but injects nothing. The whole pipeline
above degrades to a no-op at the resolution steps (empty secrets list →
no provider invocation, no masking), so gate-only support lives entirely
at the input edges — the parser accepts empty `env`, the schema drops its
`required`/`minProperties` constraints, and the consent card renders a
"Gate only" marker instead of secret rows. `op` (1Password CLI) is the
motivating case: no secret to pass, but you still want a consent gate.

### Built-in providers

`manifest::builtin_providers()` returns a `BTreeMap` of providers shipped
with the binary. `WrapsConfig::merge_builtin_providers()` overlays them
under any user declarations. `#[cfg(target_os = "macos")]` / `#[cfg(unix)]`
gate platform-specific entries.

## JSON Schema

`src/schema.rs::wraps_schema()` is the source of truth.
`examples/gen_schema.rs` emits it to stdout.
`docs/wraps.schema.json` is the committed artifact, regenerated via:

```sh
cargo run --example gen-schema > docs/wraps.schema.json
```

The drift test `tests/schema_drift.rs` fails if the committed file
diverges. We don't use `schemars` derive because the Rust types are
post-parse representations (e.g. `ValueMode::Stdin` vs the JSON's
`"value": "stdin"`), and the JSON has dynamic keys we'd hand-write
`patternProperties` for either way.

## Where things live (cheat-sheet)

| Looking for… | File |
|---|---|
| The CLI entry point | `src/main.rs` → `src/cli.rs` |
| What `secreq <binary>` actually does | `src/commands.rs::wrap_run` |
| Wraps config + parser | `src/wraps.rs` |
| Provider types + built-ins | `src/manifest.rs` |
| Provider execution (retrieve / store / batch) | `src/provider.rs` |
| Resolution + batching | `src/resolve.rs::resolve_all` |
| Consent prompt rendering | `src/daemon/ui.rs` (egui, tabbed pages, audit summary lines) |
| Approval record (in-memory, ppid+start_time-keyed, no TTL, no disk) | `src/consent.rs` (`ApprovalEntry`); held in `src/daemon/state.rs::State::approvals` |
| Consent socket (single per-user 0600 socket; all asks, top-level and nested) | `src/daemon/server.rs`, `src/daemon/client.rs` |
| Output masking | `src/mask.rs::Masker` |
| PTY / piped exec | `src/exec.rs::run` |
| PATH shim management | `src/shim.rs` |
| Shell-rc PATH-update | `src/path_setup.rs` |
| JSON schema for the wraps config | `src/schema.rs` |
| End-to-end behavior tests | `tests/cli.rs` |
