# Getting started

A five-minute walkthrough from "I just installed `secreq`" to "my first
wrap is running with a secret from my store."

If you want the mental model first, read [`overview.md`](./overview.md).
If you want the full command reference, that's [`cli.md`](./cli.md).

## Prerequisites

- A secret store with a CLI on your `$PATH`. `secreq` ships with built-ins
  for [1Password (`op`)](https://developer.1password.com/docs/cli/),
  [macOS Keychain (`security`)](https://ss64.com/mac/security.html),
  [LastPass (`lpass`)](https://github.com/lastpass/lastpass-cli), and
  [`pass`](https://www.passwordstore.org/). You can also declare your
  own — see [providers.md](./providers.md).
- A login session for that store (e.g. `op signin`, or
  `pass init …`). `secreq` never logs into your store on your behalf.
- A graphical session if you're on Linux/BSD: `secreq`'s consent
  prompt is a native window. On macOS the WindowServer is always
  available; on Linux/BSD you need `$DISPLAY` or `$WAYLAND_DISPLAY`.
  Headless? Use the `--yes` flag on a per-invocation basis.

## 1. Install

```sh
cargo install --path .
# or build the release binary:
cargo build --release   # → target/release/secreq
```

Confirm:

```sh
secreq --version
```

## 2. First-time setup

```sh
secreq init
```

This:

1. Picks a **shim directory** — a dedicated `~/.secreq/shims` by default,
   so it doesn't collide with anything else (asdf, pip user-installs, …).
2. Checks whether that directory is on `$PATH`.
3. If it isn't, **offers** to append a sentinel-bracketed `export PATH=…`
   block to the right shell file:
   - `~/.zshenv` (zsh)
   - `~/.bashrc` (bash)
   - `~/.config/fish/conf.d/secreq.fish` (fish)
   - `~/.profile` (sh)

The block is shown to you in full, gated by a y/N prompt — nothing
touches your dotfiles without explicit confirmation. Re-running `init`
is a no-op once the sentinel is in place.

Restart your shell (or `source` the file) so the new `$PATH` takes
effect. Confirm:

```sh
echo $PATH | tr ':' '\n' | grep secreq    # should print your shim dir
```

## 3. Wrap your first binary

Pick a CLI you regularly hand a credential to via env var. Common
candidates: `gh`, `aws`, `kubectl`, `psql`, `terraform`. Let's say `gh`:

```sh
secreq wrap gh \
  --env GITHUB_TOKEN=secret://op/Personal/GitHub/credential \
  --reason "GitHub API access"
```

This:

- Adds an entry to `~/.config/secreq/wraps.json5`.
- Drops a 5-line POSIX shim at `<shim_dir>/gh` whose body is
  `exec secreq gh "$@"`.

Confirm:

```sh
secreq wraps             # lists configured wraps (names only)
secreq check             # validates the config
secreq doctor            # check + verifies provider CLIs are on PATH
which gh                 # should point at <shim_dir>/gh
```

The `secret://op/Personal/GitHub/credential` part is a **reference**.
`op` is the provider; `Personal/GitHub/credential` is the locator. The
provider knows how to turn the locator into a value (here:
`op read op://Personal/GitHub/credential`). See
[providers.md](./providers.md) for the full list of schemes and how to
add your own.

## 4. Run it

```sh
gh repo list
```

What happens (the first time):

1. Your shell finds `<shim_dir>/gh` first on `$PATH` and execs it.
2. The shim execs `secreq gh repo list`.
3. `secreq` looks up `gh` in your wraps config, sees the wrap entry,
   and auto-spawns the consent daemon (if it isn't running yet).
4. A small native window pops up showing what's about to happen:
   the command (`gh repo list`), the working directory, the parent
   process chain (so you can tell *what* asked for the secret), and the
   env vars + providers being released.
5. You click **Approve** (one shot) or **Approve all** (remember). On
   approve, the daemon runs `op read …` itself, ships the resolved
   value back to the `secreq` client, and the client execs the real
   `gh` with `GITHUB_TOKEN` in its env.
6. Any byte that matches the resolved value gets redacted from the
   wrapped `gh`'s stdout/stderr.

Run it again — if you clicked **Approve all**, the cache hits and
nothing prompts. The cache is keyed on `(wrap, ppid,
parent_start_time)` — see [wraps.md](./wraps.md) for what scope that
covers.

## 5. Things to know

- **The consent daemon stays alive** between invocations. It exits
  after 2 hours of empty queue, or when you run `secreq daemon
  stop`. Stopping it also clears every "Approve all" you've given (the
  approvals cache is in-memory only).
- **Pass-through is safe.** If you've blanket-aliased your shim dir
  before wrapping every binary, calling an unwrapped one (e.g. `git`)
  just execs the real one with no injection. Add wraps incrementally.
- **`secreq view`** opens the daemon's window in viewer mode (pinned)
  so you can browse the audit log of past grants. The audit log
  records names only, never values.
- **`--yes`** bypasses the consent daemon entirely and is the
  supported path for scripted/CI runs:

  ```sh
  secreq --yes gh repo list
  ```

- **`--raw`** disables output masking for the wrap-and-run path. Use
  it when you actually want the resolved value to reach stdout (e.g.
  `secreq --raw gh auth token | pbcopy`).

## What to read next

- [`cli.md`](./cli.md) — every subcommand and flag in detail.
- [`wraps.md`](./wraps.md) — authoring `wraps.json5` by hand, the
  consent cache scope, examples.
- [`providers.md`](./providers.md) — the provider model, built-ins,
  defining your own.
- [`overview.md`](./overview.md) — the design rationale and mental
  model.
