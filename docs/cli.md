# CLI reference

`secreq` has admin subcommands (configuration) and two run verbs: `x`
(wrap-and-run, invoked when a PATH shim runs a wrapped binary) and `run`
(resolve ambient `secret://` refs for an arbitrary command). The
wrap-and-run path is what fires when a PATH shim invokes
`secreq x <WRAP> "$@"`.

```
secreq [GLOBAL OPTIONS] <ADMIN VERB> ...      # init, wrap, unwrap, wraps, check, doctor, edit, ssh
secreq [GLOBAL OPTIONS] x <WRAP> [ARGS...]    # wrap-and-run
secreq [GLOBAL OPTIONS] run [--env-file F]… -- <CMD> [ARGS...]   # resolve ambient refs
```

## Global options

| Flag | Effect |
|---|---|
| `--config <PATH>` | Use this config instead of `$XDG_CONFIG_HOME/secreq/wraps.json5`. |
| `--raw` | Disable output masking for the `x` / `run` paths. |
| `-y`, `--yes` | Auto-approve without prompting (resolves client-side, no daemon); intended for scripted/CI runs. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print version. |

To revoke a "remembered" approval, run `secreq daemon stop` — the cache
is in-memory, so a daemon restart clears it. There's no per-invocation
flag because the daemon design coalesces parallel asks; a one-shot
"don't remember this specific run" doesn't fit cleanly.

## Admin verbs

### `init`

```
secreq init [--shim-dir <PATH>]
```

First-time setup. Prompts for a shim directory (defaults to `~/.secreq/shims` — a dedicated dir nobody else manages, so there's no risk of collision with other tools' shims),
checks whether it's on `PATH`, and if not, offers to append a
sentinel-bracketed `export PATH=…` block to the appropriate shell config
(`~/.zshenv`, `~/.bashrc`, `~/.config/fish/conf.d/secreq.fish`, or
`~/.profile`).

Idempotent: re-running detects the sentinel and skips the append.

The PATH-config edit is shown to you in full and gated by a y/N prompt;
nothing touches your dotfiles without explicit confirmation.

`init` also offers to run the SSH-agent wiring step (see `ssh setup`)
once PATH is sorted.

### `ssh`

```
secreq ssh add <NAME> [--public-key <PATH-OR-LITERAL>] [--private-key secret://...] [--reason "..."] [--force]
secreq ssh setup [--method ssh-config|shell-rc] [--undo]
secreq ssh validate [<NAME>]
```

`secreq`'s SSH agent is managed through three nested subcommands:
`add` declares an identity, `setup` runs the guided wiring flow, and
`validate` proves the agent can sign. See [`ssh-agent.md`](./ssh-agent.md)
for the full onboarding.

#### `ssh add`

```
secreq ssh add <NAME> [--public-key <PATH-OR-LITERAL>] [--private-key secret://...] [--reason "..."] [--force]
```

Declares an SSH identity in `wraps.json5` under the `ssh` block so the
agent can serve it. The public key is stored inline (it isn't secret);
the private key is a `secret://provider/locator` reference resolved only
at sign time.

| Flag | Meaning |
|---|---|
| `--public-key <PATH-OR-LITERAL>` | A path to a `.pub` file (read and validated) or a literal `ssh-…`/`ecdsa-…`/`sk-…` line. Prompted for if omitted. |
| `--private-key secret://...` | The private-key reference, `secret://provider/locator`. Prompted for if omitted. |
| `--reason "..."` | Reason shown in the consent prompt when this identity signs. |
| `--force` | Overwrite an existing identity of the same name (otherwise a duplicate name errors). |

Pass both `--public-key` and `--private-key` for a fully non-interactive
run. Omit either and `secreq` resolves it interactively — including
1Password `op` discovery (pick an SSH-Key item; the private-key
reference, and the public key if you didn't supply one, are derived from
it) when `op` is on `PATH`, otherwise a manual prompt. You can also
hand-edit the `ssh` block directly. See [`ssh-agent.md`](./ssh-agent.md).

On the interactive path (not the fully non-interactive `--public-key` +
`--private-key` run), `ssh add` offers to run `ssh validate` for the new
identity once it's written, so you can confirm the agent can sign with it.

#### `ssh setup`

```
secreq ssh setup [--method ssh-config|shell-rc] [--undo]
```

A guided flow that walks the three SSH-onboarding steps: declare an
identity (`ssh add`), install the login service (`daemon install`), then
wire your SSH clients at secreq's agent socket by writing a
sentinel-bracketed managed block to a config file.

| Flag | Meaning |
|---|---|
| `--method ssh-config` | Prepend a `Host *` / `IdentityAgent` stanza to `~/.ssh/config` (scoped to SSH). |
| `--method shell-rc` | Append an `SSH_AUTH_SOCK` export to your shell rc (affects every SSH client in that shell). |
| `--undo` | Remove the managed block instead of writing it. |

Run it bare to be walked through all three steps interactively (each is
skippable). The scripted form `ssh setup --yes --method <method>` skips
the identity and auto-start prompts and runs **only** the client-wiring
step — the deterministic path for scripts. Omit `--method` to choose the
method interactively. Each block is shown to you in full and gated by a
confirm prompt (use `--yes` to skip it). Idempotent: re-running detects
the sentinel and skips the write. See [`ssh-agent.md`](./ssh-agent.md)
for the full onboarding, the two wiring methods, and the key-custody
tradeoff.

The guided (non-scripted) flow ends by offering to run `ssh validate` so
you can confirm the agent can actually sign before you walk away.

#### `ssh validate`

```
secreq ssh validate [<NAME>]
```

Proves the agent can sign. Connects to the agent socket, asks it to sign a
fixed test message with the configured key, and verifies the returned
signature against the key's public half — exercising the real
consent → resolve → sign path. With a `<NAME>` it tests that one identity;
with none, it tests every configured identity.

This performs a **real** signature, so it needs the daemon running and **may
prompt for consent** the first time (answer the prompt if the window
appears). Exit code 0 only if every tested identity signed and verified;
any failure (or no identities configured) returns non-zero. See
[`ssh-agent.md`](./ssh-agent.md).

### `wrap`

```
secreq wrap [--env NAME=secret://...] [--reason "..."] <BINARY>
```

Adds (or updates) a wrap entry in the config and installs a PATH shim at
`<shim_dir>/<BINARY>`.

| Flag | Meaning |
|---|---|
| `--env NAME=secret://provider/locator` | Repeatable. Each env var to inject. |
| `--reason "..."` | Reason shown in the consent prompt. |

If `--env` is not given, runs an interactive flow that prompts for each
env var, picks a provider from the available list, and asks for the
locator.

The shim file carries a sentinel comment so `unwrap` knows it's safe to
remove; if a file already exists at the target without our sentinel,
`wrap` refuses to clobber it.

> **There is no per-wrap cache TTL.** Approvals live in the daemon's
> memory for as long as the parent process that approved them is alive
> *and* the daemon hasn't been stopped. See "How approval is scoped" in
> [`wraps.md`](./wraps.md).

### `unwrap`

```
secreq unwrap <BINARY>
```

Removes the wrap's config entry and deletes the shim file (only if it's
ours — refuses to remove an unowned file at the target path).

### `wraps`

```
secreq wraps
```

Lists configured wraps with their reasons and the env-var names + provider
each one references. **Never prints values.**

### `check`

```
secreq check
```

Validates the config:
- Top-level structure is an object.
- Each `env` entry is a valid `secret://provider/locator` reference.
- Every referenced provider scheme exists (built-in or declared in
  `providers`).

Exit code 0 if clean; 1 if problems.

### `doctor`

```
secreq doctor
```

`check` plus: for every provider scheme that an `env` actually references,
confirms its retrieve CLI is on `PATH`. Providers declared but unused
aren't reported.

### `edit`

```
secreq edit
```

Opens the config file in `$EDITOR` (falls back to `vi`). The file is
created (empty object) if it doesn't exist yet.

### `daemon`

```
secreq daemon              # ensure a daemon is running, then tail its log
secreq daemon --fg         # run the daemon in the foreground in this process
secreq daemon stop [--force | -f]
secreq daemon log-path     # print the persistent log file path
secreq daemon install [--undo]   # install (or remove) the login service
```

Bare `secreq daemon` ensures a daemon is running in the background
(spawning a detached one if none is live), then **tails its persistent
log** (`<state_dir>/daemon.log`) until you Ctrl-C — handy for watching
the consent flow and the periodic CPU/memory samples live. It prints
the last 50 lines of existing log, then follows new ones.

`secreq daemon --fg` runs the daemon in the foreground in the current
process — the historical behavior, and the form a wrap auto-spawns
(detached) when it finds no live daemon. The daemon exits after 2
hours of empty queue. Singleton-per-user is enforced by an
fcntl-locked pidfile, so a second foreground daemon exits 0 silently.

`secreq daemon log-path` prints the absolute path of the persistent log
and exits without starting a daemon. The log is newline-delimited JSON
(one object per line: `ts_unix`, `t_mono_s`, `pid`, `level`, `tag`,
`msg`, plus `cpu_pct` / `rss_bytes` / `uptime_s` on `tag:"resource"`
sample lines) — pipe it through `jq` to filter.

`secreq daemon stop` tells a running daemon to exit cleanly. Since the
approvals cache lives in the daemon's memory only, this is also how
you clear any "approve all" decisions you made earlier — the next wrap
auto-spawns a fresh daemon with an empty cache. Exits 0 whether or not
a daemon was running.

`secreq daemon stop --force` SIGKILLs the daemon directly instead of
asking it to exit. Use when the daemon is unresponsive (wedged UI,
hung socket thread). Liveness is probed via the pidfile flock, not
just `kill(pid, 0)`, so a recycled pid can't be mistaken for a live
daemon. The force path also removes the pidfile and socket file,
which a SIGKILL'd process can't clean up itself.

`secreq daemon install` writes a per-user login service that runs
`secreq daemon --fg` at login and keeps it alive — a launchd
LaunchAgent at `~/Library/LaunchAgents/com.secreq.daemon.plist` on
macOS, a systemd `--user` unit at `~/.config/systemd/user/secreq.service`
on Linux. This is what keeps the SSH agent socket live for incoming
connections: wraps auto-spawn the daemon on demand, but nothing else
spawns it for an *incoming* SSH sign. It shows the service file before
writing (gated by a confirm prompt; `--yes` skips it), then loads it so
the daemon is running immediately. `--undo` unloads and removes the
service. See [`ssh-agent.md`](./ssh-agent.md) for the per-platform
details and the `op`-on-PATH caveat.

### `pending`

```
secreq pending
```

Open the consent daemon's window so you can review the queue and any
recent activity. Auto-spawns the daemon if it isn't running. The
window auto-hides ~2 seconds after the queue empties.

### `view`

```
secreq view
```

Open the daemon's window in **viewer mode** — pinned, so it stays
open after the queue empties. The window has two tabs:

- **Pending** — the consent tree, same as `secreq pending`.
- **Audit log** — recent grant decisions read from `audit.log`, newest
  first. Names only (the audit log never contains secret values).

`view` lands on the **Audit log** tab; switch via the tab bar to act
on queued requests. Clicking the window's close button exits viewer
mode and hides the window (the daemon keeps running). Auto-spawns the
daemon if it isn't running.

### `x`

```
secreq x <WRAP> [ARGS...]
```

The wrap-and-run verb. Most of the time you don't invoke this by hand —
your PATH shim does. The shim at `<shim_dir>/<WRAP>` is a 5-line POSIX
script that execs `secreq x <WRAP> "$@"`, so anything that does
`execvp("<WRAP>", …)` (interactive shells, `npm`, `make`, IDEs) routes
through us.

#### Flow

1. Load the config. Look up `<WRAP>` in `wraps`.
2. **If no wrap is configured**: pass through unchanged. Find the real
   `<WRAP>` on PATH (excluding our shim dir to avoid recursion) and exec
   it with no injection. This makes blanket-aliasing of binaries safe even
   before you've wrapped each one.
3. **If a wrap exists**:
   - Walk the parent process tree for the consent prompt.
   - Hand off to the consent daemon (auto-spawning it if no socket is
     live). The daemon checks its in-memory cache keyed on
     `(wrap_name, ppid, parent_start_time)`; a hit replies immediately,
     otherwise the daemon shows a native window listing pending
     requests. Parallel asks with the same key coalesce into one row.
   - On approve: resolve every `env` entry through its provider (with
     batching for providers that support `retrieve_batch`).
   - Build the child command: real binary path + forwarded args; child
     env layered with the resolved values.
   - Spawn in a PTY (or piped if non-tty), streaming output through a
     masking filter that redacts any resolved value (unless `--raw`).

#### Exit codes

| Code | Meaning |
|---|---|
| 0 | Child exited cleanly. |
| 1 | Consent denied, or provider resolution failed. |
| 2 | `secreq` invoked with no command. |
| child's | Otherwise the child's exit code propagates. |

### `run`

```
secreq run [--env-file PATH]… [--] <CMD> [ARGS...]
```

`op run`, but for every secret store. Where `x` injects a *declared* env
map for a *known binary* (a `wraps.json5` entry), `run` resolves
*ambient* `secret://provider/locator` references found in the
environment for an *arbitrary* command — no wrap entry required. The
references describe the secrets inline, so there's nothing to configure
first.

| Flag | Meaning |
|---|---|
| `--env-file <PATH>` | Repeatable. Load `NAME=value` lines and layer them **under** the inherited environment (inherited wins on conflict, matching `op run --env-file`). Values may be `secret://…` references or plaintext. The file holds **refs, not secrets**, so it's safe to commit. |

The global `--raw` (skip output masking) and `--yes` (auto-approve,
resolve client-side) apply. `--no-remember` is a no-op for `run` — it
already never persists approvals (see below).

#### Flow

1. Build the effective environment: the inherited env, with any
   `--env-file` entries layered **under** it.
2. Scan every variable whose **value** is a well-formed
   `secret://provider/locator` reference. Plain `NAME=value` entries pass
   through untouched. A value that starts with `secret://` but doesn't
   parse is a **hard error** before the command runs (it names the
   offending variable) — a literal `secret://…` never reaches the child.
3. **No references → fast path.** Exec `<CMD>` with the effective env
   directly: no daemon contact, no consent prompt.
4. Otherwise hand off to the consent daemon (the same path as `x`):
   consent prompt, rules engine, the in-memory value cache, and batched
   provider unlocks (one biometric per provider with ≥2 misses). Under
   `--yes` this resolves client-side instead, with no daemon.
5. On approve, substitute each reference with its resolved value and exec
   `<CMD>` in a PTY (or piped if non-tty), masking the resolved values on
   stdout/stderr unless `--raw`.

The consent window shows `secreq run` as what's asking, plus the actual
`<CMD> [args…]` and the caller chain. It never shows secret values.

#### Trust model

`run` presents a **fixed identity** (`run`) for every invocation, and it
**does not persist remembered approvals** — every `run` re-prompts for
consent. The re-prompt is cheap: because all `run` invocations share one
value-cache bucket, a reference that's already been resolved is served
from the cache with **no provider call and no biometric** — the prompt is
a single approve click, not an unlock. (A rule on the Rules tab can
auto-approve `run` for a given set of providers if you want to skip the
click entirely.)

Nested `run` is correct without any special handling: the outer `run`
has already replaced every reference in the child environment with a
plain value, so an inner `run` sees no `secret://` refs and just execs.

Concurrent `run` invocations in one process tree share **one** consent
prompt. The daemon unions their secret requests into a single card (each
secret annotated with the command that asked for it), you approve once,
and each command receives **only its own** secrets — never a sibling's.

#### Example

```sh
# A committable, refs-only .env (no plaintext secrets):
#   DATABASE_URL=secret://op/Work/Postgres/url
#   STRIPE_KEY=secret://keychain/stripe-live
secreq run --env-file .env -- ./deploy.sh
```

`./deploy.sh` runs with `DATABASE_URL` and `STRIPE_KEY` set to their
resolved values; both are redacted in anything the script prints.

#### Exit codes

Same as `x`: `0` on a clean child exit, `1` on denied consent or
resolution failure (including a malformed `secret://` value), `2` when no
command was given, otherwise the child's exit code.

### `resolve`

```
secreq resolve <REF>
secreq resolve --list
```

The **guest** side of the secret agent: ask the *host's* `secreq`, over the
socket named by `$SECREQ_SOCK`, for one secret this sandbox was declared
allowed to have. Nothing is stored in the guest — every use is asked for,
gated by consent on the host, and audited there. Full story:
[secret-agent.md](./secret-agent.md).

`$SECREQ_SOCK` is set for you inside a brain `--vm` sandbox. On a host, the
other end is `secreq agent open --scope <name> --allow <ref>… --sock <path>`,
forwarded in with `ssh -R`.

`<REF>` is a full `secret://provider/locator` or the bare
`provider/locator` shorthand.

**The value, and only the value, goes to stdout** — diagnostics, errors, and
denials all go to stderr, so the command substitutes cleanly:

```sh
export GH_TOKEN="$(secreq resolve secret://op/Dev/gh/token)"
```

The value is printed with a trailing newline (`op read`'s convention), which
`$(…)` strips. `--list` prints the scope's allowed ref **names**, one per
line, and never prompts — listing is free.

The global flags don't apply: the host owns every decision, so there is
nothing for `--yes`, `--no-remember`, or `--config` to act on.

#### Exit codes

| Code | Meaning |
|---|---|
| 0 | Released. The value is on stdout. |
| 3 | Denied by the host (you said no, a rule denied it, or the ref is outside this socket's declared scope). Reason on stderr, stdout empty. **A denial is final — don't retry it.** |
| 1 | Error: `$SECREQ_SOCK` unset, the agent unreachable, a malformed ref, or resolution failed on the host after approval. |

## Environment variables `secreq` reads or sets

| Variable | When |
|---|---|
| `SHELL` | `init` reads this to choose which shell config to edit. |
| `XDG_CONFIG_HOME` | Config discovery. Falls back to `~/.config`. |
| `XDG_STATE_HOME` | Audit log (`secreq/audit.log`) and the daemon's persistent log (`secreq/daemon.log`, see `secreq daemon log-path`) live here. Falls back to `~/.local/state`. The approvals cache is in-memory only — `secreq daemon stop` clears it. |
| `XDG_RUNTIME_DIR` | Consent daemon socket + pidfile. Falls back to `$TMPDIR/secreq-<uid>`. |
| `EDITOR` / `VISUAL` | Used by `secreq edit`. |
| `DISPLAY` / `WAYLAND_DISPLAY` | Linux/BSD: when neither is set, `secreq` fails closed instead of spawning a daemon that can't render. |
| `SECREQ_SOCK` | Read by `secreq resolve`: the scoped secret agent socket to ask, mirroring `SSH_AUTH_SOCK`. Set inside a brain `--vm` sandbox, where the host forwards its `secreq agent open` socket in. See [secret-agent.md](./secret-agent.md). |
| `SECREQ_NO_DAEMON` | Set to `1` to disable the daemon entirely — consent fails closed unless `--yes` is used. Intended for tests and headless automation. |
