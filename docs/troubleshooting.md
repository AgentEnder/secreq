# Troubleshooting

The snags a first-week `secreq` user actually hits. This assumes you have
`secreq` installed and at least one wrap configured — if not, start with
[getting-started](./getting-started.md).

## Start here

Three commands answer most "why isn't this working?" questions:

```sh
secreq doctor         # config + PATH shadowing + provider CLIs
secreq daemon status  # is the consent daemon running, and on which build?
which gh              # does PATH resolve your wrap to secreq's shim?
```

`doctor` is the big one. It runs `secreq check`, then prints two sections
where every `✗` is a concrete thing to fix:

```
Wrap resolution (the first match on PATH):
  ✓ gh → /home/you/.secreq/shims/gh (shim)
  ✗ aws → /opt/homebrew/bin/aws (shadowed; expected the shim at /home/you/.secreq/shims/aws)

Provider CLIs (used by a wrap):
  ✓ op → op
  ✗ keychain → security (not found on PATH)
```

## The consent window never appears

You run a wrapped command, no window appears, and the command is denied
(`secreq: denied — <binary> not run`, exit 1).

### No graphical session (Linux/BSD)

The prompt is a native window, so on Linux/BSD secreq checks `$DISPLAY` and
`$WAYLAND_DISPLAY`. If **both** are empty it treats the session as headless
and **fails closed** rather than spawning a daemon that would crash trying
to draw. (macOS always has a window server in an interactive login, so the
check doesn't apply there.)

This bites over SSH without forwarding, in cron/CI/systemd units and bare
TTYs, and in a multiplexer that dropped the variables — check with
`echo "$DISPLAY $WAYLAND_DISPLAY"` inside `tmux`.

For scripted runs, approve without a prompt:

```sh
secreq x --sq-yes gh repo list     # the x / shim path
secreq run --yes -- ./deploy.sh    # the run path
```

`secreq read` has **no** `--yes` bypass on purpose — it prints a value to
stdout, so it stays daemon-gated.

### The daemon is running a stale build

The daemon is long-lived. If you upgrade the binary while an old one is
running, the new CLI notices the build mismatch on connect and restarts it,
so this usually self-heals. `secreq daemon status` reports the running build
and flags the mismatch. If a window still won't appear:

```sh
secreq daemon stop     # also clears every in-memory approval
```

### Everything is denied even with a display

Check the kill-switch: `SECREQ_NO_DAEMON` (any non-empty value) tells the
client to neither connect to nor spawn the daemon, so every consent request
fails closed. It's meant for automation; unset it for interactive use.

## Dev builds can corrupt your real `~/.secreq`

**Read this before you `cargo run` or `cargo test` a dev build against your
real home.** It is the one trap that can brick a working setup.

secreq keeps everything under one root (`$SECREQ_HOME`, else `~/.secreq`),
and every deliberate foreground command applies any pending **migrations**,
stamping the schema level it reached. Running a development build at a
different schema level than your installed release against that same home
goes wrong two ways:

- A newer dev build migrates your live config and bumps the level. Your
  installed release then reads that as a *downgrade* and refuses to run
  anything until you `secreq migrate restore <level>`.
- Worse, a test that pins only `$SECREQ_HOME` but leaves `$HOME` pointing at
  your real home makes the migration's legacy probe aim at your **real**
  `~/.config/secreq` and move your live config into a tempdir that is
  deleted moments later. This has actually happened during a `cargo test`.

**Isolate every dev build.** `$SECREQ_HOME` alone is not enough: migrations
resolve the *pre-migration* locations through frozen XDG logic, and the
socket directory prefers `$XDG_RUNTIME_DIR` over the root.

```sh
export SECREQ_HOME="$(mktemp -d)"
export XDG_RUNTIME_DIR="$SECREQ_HOME/run"   # sockets don't hang off SECREQ_HOME
mkdir -p "$XDG_RUNTIME_DIR"
export HOME="$SECREQ_HOME"                   # backstop: makes a forgotten pin harmless
export XDG_CONFIG_HOME="$SECREQ_HOME/config" # the migration's legacy probe
export XDG_STATE_HOME="$SECREQ_HOME/state"

cargo run -- doctor        # now safely sandboxed
```

Pinning `$HOME` is what makes a *forgotten* pin harmless rather than
destructive. The project's own integration tests do exactly this — see
`tests/ssh_agent.rs::isolate_paths`.

## `which gh` points at the wrong binary

For a wrap to fire, the **first** thing `execvp("gh", …)` finds on `$PATH`
must be secreq's shim. If another directory earlier on `$PATH` has a `gh`, it
shadows the shim and the wrap never runs — no consent, no injection, just
the bare binary. `doctor` names the culprit directly:

```
✗ gh → /opt/homebrew/bin/gh (shadowed; expected the shim at …)
```

The fix is to make your shim dir come **before** the shadowing entry.

### The zsh + Homebrew ordering gotcha

`brew shellenv` prepends `/opt/homebrew/bin` to `$PATH`, and it does so
*after* secreq's block if the two land in the wrong startup files. On zsh,
`init` can write its block to `~/.zshenv` — but `.zshenv` runs **before**
`.zprofile`, where `brew shellenv` usually lives, so Homebrew's prepend wins
and shadows every shim.

If `doctor` shows Homebrew (or asdf, pyenv, any path-prepending tool)
shadowing your shims, move the secreq `export PATH=…` block so it runs
**after** that tool — for zsh, into `~/.zshrc` rather than `.zshenv`. Then
restart your shell and re-check `which gh`.

## `gh --help` shows gh's help, not secreq's

This is intended, and it's the whole point of the
[argv contract](./cli.md#the-argv-contract): `x` owns no ordinary flags, so
every argument after the wrap name reaches the wrapped binary untouched. To
reach secreq's own options there, use the reserved `--sq-` prefix
(`secreq x --sq-help`).

## A provider is missing or locked

secreq never talks to your store directly — it shells out to the provider's
CLI. Two distinct failures:

**The CLI isn't on PATH.** `doctor`'s "Provider CLIs" section checks each
provider a wrap actually uses. At resolution time it surfaces as:

```
secreq: error: provider `op`: failed to run `op`: <os error> (is it installed and on PATH?)
```

**The store is locked.** secreq can't tell "locked" from "no such secret";
both are just a non-zero exit from the provider CLI. So it passes the
provider's own stderr straight through:

```
secreq: error: secret `GITHUB_TOKEN` could not be resolved from `op` (exit status: 1: <op's "not signed in" message>) and has no default
```

The fix is whatever that message says, usually unlocking the store *outside*
secreq (`op signin`, unlocking your keychain, `gpg-agent` for `pass`).
secreq never signs into your store on your behalf.

## Where the logs live

Everything is under the root — `$SECREQ_HOME`, else `~/.secreq/`:

| File                     | What it is                                                                                            |
| ------------------------ | ------------------------------------------------------------------------------------------------------- |
| `~/.secreq/audit.log`    | Every decision. **Names only, never values.** See [the audit format](./consent-window.md#the-audit-log-file). |
| `~/.secreq/daemon.log`   | The daemon's human-readable log. Print its path with `secreq daemon log-path`.                        |
| `~/.secreq/daemon.jsonl` | The same events as one JSON object per line, for machine parsing.                                     |

The audit log answers "did that command actually get its secret, and when?"
— browse it with `secreq view`. To debug the daemon itself, `secreq daemon`
follows its log live.

There is **no** `RUST_LOG` knob; the daemon logs its lifecycle
unconditionally to the files above. When auto-spawned its stderr is
discarded, so run `secreq daemon --fg` in a terminal to watch it echo.

The daemon's sockets live in `$XDG_RUNTIME_DIR/secreq/` when that's set
(preferred — mode-0700 tmpfs), otherwise `~/.secreq/run/`: `consent.sock`,
`agent.sock` (where `SSH_AUTH_SOCK` points), plus the pidfile and spawn
lock. If they seem stale after a crash, `secreq daemon stop` and let the
next invocation respawn cleanly.
