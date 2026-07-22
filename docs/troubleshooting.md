# Troubleshooting & FAQ

The snags a first-week `secreq` user actually hits, and how to get
un-stuck. If you're just getting started, read
[getting-started.md](./getting-started.md) first; this page assumes you
have `secreq` installed and at least one wrap configured.

## Start here: self-diagnosis

Three commands answer most "why isn't this working?" questions:

```sh
secreq doctor        # config + PATH shadowing + provider CLIs on PATH
secreq daemon status # is the consent daemon running?
which gh             # does PATH resolve your wrap to secreq's shim?
```

`secreq doctor` is the big one. It runs `secreq check` (config
validity) and then prints two extra sections:

```
Wrap resolution (the first match on PATH):
  ✓ gh → /home/you/.secreq/shims/gh (shim)
  ✗ aws → /opt/homebrew/bin/aws (shadowed; expected the shim at /home/you/.secreq/shims/aws)

Provider CLIs (used by a wrap):
  ✓ op → op
  ✗ keychain → security (not found on PATH)
```

Every `✗` line is a concrete thing to fix, covered below.

If something is still going wrong after `doctor` is clean, the logs are
under `~/.secreq/` — see [Where the logs and audit live](#where-the-logs-and-audit-live).

---

## The consent window never appears

You run a wrapped command, no window pops up, and the command is denied
(`secreq: denied — <binary> not run`, exit 1) — or it just hangs, then
errors.

### No graphical session (Linux/BSD)

`secreq`'s consent prompt is a native window. On Linux/BSD, `secreq`
checks for a graphical session by looking at two environment variables:

- `$DISPLAY` (X11)
- `$WAYLAND_DISPLAY` (Wayland)

If **both** are empty or unset, `secreq` treats the session as headless
and **fails the consent request closed** — it deliberately does *not*
spawn a daemon that would just crash trying to open a window. The
wrapped command is denied and exits 1. (macOS always has a window server
in an interactive login, so this check only applies to Linux/BSD.)

This bites most often:

- **Over SSH without X/Wayland forwarding.** `ssh you@host` gives you no
  `$DISPLAY`. Reconnect with `ssh -X` (X11 forwarding) if you have a
  local X server, or use the headless bypass below.
- **In cron / CI / a systemd service / a bare TTY.** No display, by
  design.
- **In a terminal multiplexer that dropped the vars.** `echo "$DISPLAY
  $WAYLAND_DISPLAY"` — if that prints nothing inside `tmux`/`screen`,
  your multiplexer isn't inheriting them.

**The headless bypass.** For scripted / non-interactive runs, approve
without a prompt:

```sh
secreq x --sq-yes gh repo list     # through the shim / x path
secreq run --yes -- ./deploy.sh    # the run path
```

`--sq-yes` (and `--yes` for `run`) resolves secrets client-side and
skips the daemon entirely. It is the supported path for CI. Note that
`secreq read` has **no** `--yes` bypass — it prints a value, so it stays
daemon-gated on purpose.

### The daemon is running a stale build

The consent daemon is long-lived (it idle-exits after **2 hours** of an
empty queue). If you upgrade the `secreq` binary while an old daemon is
still running, the new CLI notices the build mismatch on connect and
**restarts** the stale daemon automatically — so this usually
self-heals. The one case it can't: a daemon old enough to predate the
build handshake. If a window still won't appear after an upgrade, force
it:

```sh
secreq daemon stop     # also clears every in-memory "Approve all"
```

The next wrap invocation spawns a fresh daemon on the current build.

### Everything is denied even with a display

If the consent request fails closed *with* a display present, check
whether the per-process kill-switch is set:

```sh
echo "$SECREQ_NO_DAEMON"
```

`SECREQ_NO_DAEMON` (any non-empty value) tells the client to neither
connect to nor spawn the daemon — every consent request fails closed and
you must use `--sq-yes` / `--yes` to proceed. It's meant for automation
that doesn't want a GUI; unset it for interactive use.

---

## Dev builds can corrupt your real `~/.secreq`

**This is the one trap that can brick a working setup. Read it before
you `cargo run` or `cargo test` a dev build of `secreq` against your
real home.**

`secreq` keeps everything under a single root: `$SECREQ_HOME` if set,
otherwise `~/.secreq`. On startup, every deliberate foreground command
runs any pending **migrations** — including a one-time migration that
moves the *legacy* layout (`~/.config/secreq/`, `~/.local/state/secreq/`)
into `~/.secreq/` and stamps a machine-local `~/.secreq/.migration-state`
with the schema level it reached.

The danger is running a **development build** — a checkout on a different
schema level than your installed release — against that same real home:

- A newer dev build migrates your live config and bumps
  `.migration-state`. Your installed **release** then reads that level as
  a *downgrade* and refuses to run every command until you
  `secreq migrate restore <level>`.
- Worse, a test that pins only `$SECREQ_HOME` but leaves `$HOME` /
  `$XDG_CONFIG_HOME` pointing at your real home makes the migration's
  legacy probe aim at your **real** `~/.config/secreq` and move your live
  config into a tempdir that's deleted moments later. This has actually
  corrupted a developer's config during a `cargo test` run.

**Isolate every dev build.** Point it at a throwaway root *and* pin the
legacy-probe and fallback vars, so nothing it does can reach your real
home:

```sh
export SECREQ_HOME="$(mktemp -d)"
export XDG_RUNTIME_DIR="$SECREQ_HOME/run"   # sockets don't hang off SECREQ_HOME
mkdir -p "$XDG_RUNTIME_DIR"
# For anything that touches migrations (tests, first run), also pin:
export HOME="$SECREQ_HOME"                   # backstop: makes a forgotten pin harmless
export XDG_CONFIG_HOME="$SECREQ_HOME/config" # the migration's legacy probe
export XDG_STATE_HOME="$SECREQ_HOME/state"

cargo run -- doctor        # now safely sandboxed
```

`$SECREQ_HOME` alone is **not** enough: migrations resolve the
*pre-migration* locations through the frozen XDG logic, and the socket
directory prefers `$XDG_RUNTIME_DIR` over the root. Pin `$HOME` too — it
is what makes a *forgotten* pin harmless rather than destructive. (The
project's own integration tests do exactly this; see
`tests/ssh_agent.rs::isolate_paths`.)

If a dev build already stamped a too-high level and your release now
refuses to start, recover with the snapshot it took:

```sh
secreq migrate restore <level>
```

---

## `gh --help` shows gh's help, not secreq's (and how to reach secreq's)

This is **intended**, and it's the whole point of the `x` argv contract:
the shim runs `exec secreq x gh "$@"`, and `secreq x` owns **no ordinary
flags**. Every argument after the wrap name — `--help`, `-y`,
`--config foo`, anything — is forwarded to the wrapped binary untouched.
So `gh --help` through the shim means **gh's** help. That's correct: you
don't want secreq silently eating a flag meant for `gh`.

To reach secreq's own options on the `x` path, use the reserved `--sq-`
prefix:

```sh
secreq x --sq-help              # secreq x's usage
secreq x --sq-raw gh auth token # a secreq flag; forwards the rest to gh
```

An unrecognized `--sq-*` token is a hard error (exit 2), not a silent
forward — the prefix is reserved so a typo can't hand a flag to the
wrong process. And secreq's *global* flags (`--raw`, `--yes`, …) don't
apply to `x`; putting one before the wrap name is rejected with a hint
to use the `--sq-` form instead.

**If you're on an older build where a leading `--help` printed secreq's
own help (or errored) instead of reaching the binary:** that was a real
bug — clap used to intercept leading tokens before the wrap name got
them. It's fixed by the "`x` owns no argv" rework. Update `secreq`, then
regenerate your shims so they call the current `x` path:

```sh
secreq unwrap gh && secreq wrap gh --env GITHUB_TOKEN=secret://...
# or `secreq daemon stop` and re-run to pick up the new binary
```

---

## `which gh` points at the wrong binary (shim / PATH ordering)

For a wrap to fire, the **first** thing `execvp("gh", …)` finds on
`$PATH` must be secreq's shim (`~/.secreq/shims/gh` by default). If
another directory earlier on `$PATH` has a `gh`, it shadows the shim and
the wrap never runs — no consent, no injection, just the bare binary.

Diagnose it:

```sh
secreq doctor    # the "Wrap resolution" section flags every shadowed wrap
which gh         # should print your shim dir, not /opt/homebrew/bin/gh etc.
echo "$PATH" | tr ':' '\n'   # is the shim dir before the shadowing dir?
```

`doctor` names the culprit directly (`✗ gh → /opt/homebrew/bin/gh
(shadowed; expected the shim at …)`). The fix is to make your shim dir
come **before** the shadowing entry on `$PATH`.

### The zsh + Homebrew ordering gotcha

The classic version of this: `brew shellenv` prepends
`/opt/homebrew/bin` to `$PATH`, and it does so *after* secreq's block if
the two land in the wrong startup files. On zsh, `secreq init` can write
its PATH block to `~/.zshenv`, but `.zshenv` runs **before** `.zprofile`
(where `brew shellenv` typically lives), so Homebrew's prepend wins and
shadows every shim.

If `doctor` shows Homebrew (or asdf, pyenv, any path-prepending tool)
shadowing your shims, move the secreq `export PATH=…` block so it runs
**after** the shadowing tool — for zsh that means putting it in
`~/.zshrc` (which runs after `.zprofile`), not `.zshenv`. Then restart
your shell and re-check with `which gh`.

---

## A provider CLI is missing or the store is locked

`secreq` never talks to your secret store directly — it shells out to
the provider's CLI (`op`, `security`, `pass`, `lpass`, …). Two distinct
failure modes:

### The provider CLI isn't installed / isn't on PATH

`secreq doctor`'s "Provider CLIs" section checks each provider a wrap
actually uses:

```
Provider CLIs (used by a wrap):
  ✗ op → op (not found on PATH)
```

At resolution time (not just in `doctor`), a missing CLI surfaces as:

```
secreq: error: provider `op`: failed to run `op`: <os error> (is it installed and on PATH?)
```

Install the provider's CLI and make sure it's on the `$PATH` that
`secreq` sees. See [providers.md](./providers.md) for each built-in's
CLI.

### The store is locked / you're not signed in

`secreq` can't tell "locked" apart from "no such secret" — both are just
a non-zero exit from the provider CLI. It passes the provider's own
stderr straight through. A locked 1Password, for example, shows up as
that CLI's authentication error embedded in a resolution failure:

```
secreq: error: secret `GITHUB_TOKEN` could not be resolved from `op` (exit status: 1: <op's "not signed in" message>) and has no default
```

The fix is whatever the provider's message says — usually to unlock or
sign in to the store *outside* secreq (`op signin`, unlock your
keychain, `gpg-agent` for `pass`, etc.). `secreq` never logs into your
store on your behalf. Once the store is unlocked, re-run the command.

---

## Where the logs and audit live

Everything lives under the `secreq` root — `$SECREQ_HOME` if set, else
`~/.secreq/`:

| File | What it is |
|---|---|
| `~/.secreq/audit.log` | Every grant/deny decision. **Names only, never values.** Written by the wrap client (and by the daemon for SSH signs / abandoned asks). |
| `~/.secreq/daemon.log` | The daemon's human-readable log (`[secreq +12.345s tag] msg`). Print its path with `secreq daemon log-path`. |
| `~/.secreq/daemon.jsonl` | The same daemon events as one JSON object per line, for machine parsing. |

The audit log is the first place to look for "did that command actually
get its secret, and when?" Browse it in the daemon window with:

```sh
secreq view      # opens the daemon's window in pinned viewer mode
```

Tail the daemon's own log to debug the daemon itself:

```sh
secreq daemon log-path     # prints ~/.secreq/daemon.log
secreq daemon              # follows the daemon log live
```

There is **no** `RUST_LOG` / `SECREQ_LOG` level knob — the daemon logs
its lifecycle unconditionally to the files above. When auto-spawned its
stderr is discarded; run `secreq daemon --fg` in a terminal to watch it
echo live. (`SECREQ_NO_WAIT_INDICATOR=1` silences only the wrap's
"waiting for approval" stderr spinner, not the logs.)

### Sockets and runtime files

The daemon's Unix sockets live in `$XDG_RUNTIME_DIR/secreq/` when that's
set (preferred — it's mode-0700 tmpfs), otherwise `~/.secreq/run/`:

- `consent.sock` — the consent-request socket.
- `agent.sock` — the SSH-agent socket (`SSH_AUTH_SOCK` points here).
- `daemon.pid`, `daemon.spawn.lock` — pidfile and spawn lock.

If sockets seem stale (e.g. after a crash), `secreq daemon stop` and let
the next invocation re-spawn cleanly.

---

## Still stuck?

- Re-run `secreq doctor` — it's the fastest triage.
- Check `~/.secreq/audit.log` and `~/.secreq/daemon.log`.
- For the command surface and every flag, see [cli.md](./cli.md).
- For the consent window's tabs and audit format, see
  [consent-window.md](./consent-window.md).
</content>
</invoke>
