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
  own — see [providers](./providers.md).
- A login session for that store (e.g. `op signin`, or
  `pass init …`). `secreq` never logs into your store on your behalf.
- A graphical session if you're on Linux/BSD: `secreq`'s consent
  prompt is a native window. On macOS the WindowServer is always
  available; on Linux/BSD you need `$DISPLAY` or `$WAYLAND_DISPLAY`.
  Headless? Use the `--sq-yes` flag (`--yes` for `run`) on a
  per-invocation basis.

## 1. Install

Pick whichever channel fits your setup — they all install the same
binary, and none of them create any wraps or shims (that's `secreq
init`, step 2 below).

```sh
# macOS / Linux, one-liner (downloads + verifies the release binary):
curl -fsSL https://secreq.dev/install.sh | sh

# …or Homebrew:
brew install AgentEnder/secreq/secreq

# …or from crates.io, if you'd rather build from source:
cargo install secreq
```

**From a release tarball.** A downloaded
`secreq-<version>-<os>-<arch>.tar.gz` (produced by
`scripts/package-release.sh`) carries its own installer, so you skip
compilation entirely:

```sh
tar xzf secreq-*-*.tar.gz
cd secreq-*-*/
./install.sh              # installs the bundled binary, no Rust toolchain needed
```

**From a checkout.** One command from a fresh clone: it compiles the
release binary, installs it onto your PATH, and hands off to `secreq
init` for the shim-directory + PATH wiring.

```sh
bash scripts/install.sh
```

By default the binary lands in `~/.local/bin`; override with
`--bin-dir <dir>` (or `$SECREQ_BIN_DIR`). Pass `--no-init` to install the
binary only. If the script's stdin isn't a terminal (piped/CI), it installs
the binary and prints the `secreq init` command to run yourself. To drive
cargo against the checkout yourself instead:

```sh
cargo install --path packages/secreq
```

> ⚠ A dev/`cargo` build run against your real home can corrupt
> `~/.secreq` — see
> [docs/troubleshooting.md#dev-builds-can-corrupt-your-real-secreq](./troubleshooting.md#dev-builds-can-corrupt-your-real-secreq).

See [install](./install.md) for every channel and how to verify a download.
Confirm:

```sh
secreq --version
```

## 2. First-time setup

```sh
secreq init
```

::term{id=init}

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
candidates: `gh`, `aws`, `kubectl`, `psql`, `terraform`. Let's say `gh`.

Run `secreq wrap` with just the binary name and it asks for the rest:

```sh
secreq wrap gh
```

::term{id=wrap-gh}

This is the recommended path — not because typing is nicer, but because
the interactive flow **checks its work**. Choosing the provider from a
list means you can't misspell it, and the locator is resolved against
your store before the wrap is written, so a bad path fails while you're
still looking at it rather than the first time you run `gh`.

Everything it asked can also be passed up front, which is what you want
in a dotfiles script or a setup playbook:

```sh
secreq wrap gh \
  --env GITHUB_TOKEN=secret://op/Personal/GitHub/credential \
  --reason "GitHub API access"
```

Supplying `--env` skips the questions entirely — there's nothing left to
ask. Either way, the result is the same:

- Adds an entry to `~/.secreq/wraps.json5`.
- Drops a 5-line POSIX shim at `<shim_dir>/gh` whose body is
  `exec secreq x gh "$@"`.

### Wraps that inject nothing

Not every wrap carries a secret. A **gate-only** wrap injects nothing and
exists purely to put the consent prompt in front of a command — the model
for a tool that already holds its own credentials, like `op` itself:

::term{id=wrap-gate-only}

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
[providers](./providers.md) for the full list of schemes and how to
add your own.

## 4. Run it

```sh
gh repo list
```

::shot{id=02-single-pending}

What happens (the first time):

1. Your shell finds `<shim_dir>/gh` first on `$PATH` and execs it.
2. The shim execs `secreq x gh repo list`.
3. `secreq` looks up `gh` in your wraps config, sees the wrap entry,
   and auto-spawns the consent daemon (if it isn't running yet).
4. A small native window pops up showing what's about to happen:
   the command (`gh repo list`), the working directory, the parent
   process chain (so you can tell *what* asked for the secret), and the
   env vars + providers being released.
5. You press **Approve** (or <kbd>A</kbd>). The daemon runs `op read …`
   itself, ships the resolved value back to the `secreq` client, and
   the client execs the real `gh` with `GITHUB_TOKEN` in its env.
6. Any byte that matches the resolved value gets redacted from the
   wrapped `gh`'s stdout/stderr.

Run it again from the same shell and nothing prompts — approving also
remembers. The cache is keyed on `(wrap, ppid, parent_start_time)`, so
the approval belongs to *that shell*: a different terminal, an editor,
or an `npm` postinstall each get asked in their own right. See
[wraps](./wraps.md) for what that scope covers, and
[consent-window](./consent-window.md) for the window itself.

## 5. Things to know

- **The consent daemon stays alive** between invocations. It exits
  after 2 hours of empty queue, or when you run `secreq daemon
  stop`. Stopping it also clears every approval you've given (the
  approvals cache is in-memory only).
- **Pass-through is safe.** If you've blanket-aliased your shim dir
  before wrapping every binary, calling an unwrapped one (e.g. `git`)
  just execs the real one with no injection. Add wraps incrementally.
- **`secreq view`** opens the daemon's window in viewer mode (pinned)
  so you can browse the audit log of past grants. The audit log
  records names only, never values.
- **`--sq-yes`** bypasses the consent daemon entirely and is the
  supported path for scripted/CI runs:

  ```sh
  secreq x --sq-yes gh repo list
  ```

- **`--sq-raw`** disables output masking for the wrap-and-run path. Use
  it when you actually want the resolved value to reach stdout (e.g.
  `secreq x --sq-raw gh auth token | pbcopy`).

  The `--sq-` prefix is reserved for secreq: on the `x` path everything
  else in argv — `--help`, `-y`, whatever — forwards to the wrapped
  binary untouched, so `gh --help` through the shim means gh's help,
  not secreq's.

## SSH keys, too

`secreq` can also act as your **SSH agent**, gating each key signature on
the same consent ceremony. Add an `ssh` block to your config, point
`SSH_AUTH_SOCK` at secreq's agent socket (`secreq init` prints the path),
and `git push` prompts you with the caller chain before signing. See
[`ssh-agent.md`](./ssh-agent.md) — including the key-custody tradeoff vs.
1Password's sealed agent.

## Hit a snag?

- [`troubleshooting.md`](./troubleshooting.md) — the first-week traps and
  their fixes: the consent window never appears, a dev build corrupting
  your real `~/.secreq`, PATH shadowing, a locked provider, and where the
  logs and audit live.

## What to read next

- [`cli.md`](./cli.md) — every subcommand and flag in detail.
- [`wraps.md`](./wraps.md) — authoring `wraps.json5` by hand, the
  consent cache scope, examples.
- [`providers.md`](./providers.md) — the provider model, built-ins,
  defining your own.
- [`ssh-agent.md`](./ssh-agent.md) — the provenance-aware SSH agent.
- [`overview.md`](./overview.md) — the design rationale and mental
  model.
