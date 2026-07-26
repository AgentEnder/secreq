# Getting started

From "I just installed `secreq`" to "my first wrap is running with a secret
from my store."

## Before you start

- **A secret store with a CLI on your `$PATH`**: built-ins exist for
  [1Password (`op`)](https://developer.1password.com/docs/cli/),
  [macOS Keychain](https://ss64.com/mac/security.html),
  [LastPass](https://github.com/lastpass/lastpass-cli) and
  [`pass`](https://www.passwordstore.org/). You can declare your own; see
  [providers](./providers.md).
- **A login session for that store** (`op signin`, an unlocked keychain, a
  `gpg-agent` for `pass`). secreq never signs into your store for you.
- **A graphical session, on Linux/BSD**: the consent prompt is a native
  window, so it needs `$DISPLAY` or `$WAYLAND_DISPLAY`. macOS always has
  one. Headless machines use `--sq-yes`; see
  [platform-support](./platform-support.md#headless-use).

## 1. Install

```sh
curl -fsSL https://secreq.dev/install.sh | sh
```

Homebrew, `cargo install`, and verified release tarballs all work too.
[install](./install.md) covers every channel, and how to check a download's
signature. Confirm with `secreq --version`.

None of them create any wraps or shims. That's the next step.

## 2. First-time setup

```sh
secreq init
```

::term{id=init}

`init` picks a **shim directory** (`~/.secreq/shims` by default, a dedicated
one, so it can't collide with asdf, pip user-installs, or anything else),
checks whether it's on `$PATH`, and offers to append a
sentinel-bracketed `export PATH=…` block to the right shell file. The block
is shown to you in full and gated by a y/N prompt; nothing touches your
dotfiles unconfirmed. Re-running is a no-op.

Restart your shell so the new `$PATH` takes effect, then confirm:

```sh
echo $PATH | tr ':' '\n' | grep secreq    # should print your shim dir
```

## 3. Wrap your first binary

Pick a CLI you regularly hand a credential to by env var: `gh`, `aws`,
`kubectl`, `psql`, `terraform`. Run `wrap` with just the binary name and it
asks for the rest:

```sh
secreq wrap gh
```

::term{id=wrap-gh}

Prefer this path. The interactive flow **checks its work**: you pick the
provider from a list rather than spelling it, and the locator is resolved
against your store before the wrap is written. A bad path fails while you're still looking at
it, instead of the first time you run `gh`.

Everything it asks can be supplied up front, which is what you want in a
dotfiles script:

```sh
secreq wrap gh \
  --env GITHUB_TOKEN=secret://op/Personal/GitHub/credential \
  --reason "GitHub API access"
```

Either way you get an entry in `~/.secreq/wraps.json5` and a five-line shim
at `<shim_dir>/gh`. Confirm:

```sh
secreq doctor      # config valid, providers on PATH, no shim shadowed
which gh           # should point at <shim_dir>/gh
```

`secret://op/Personal/GitHub/credential` is a **reference**: `op` is the
provider, the rest is the locator, and the provider knows how to turn one
into a value. Values never appear in your config; only references do.

### Wraps that inject nothing

Not every wrap carries a secret. A **gate-only** wrap injects nothing and
exists purely to put the consent prompt in front of a command that already
holds its own credentials. `op` itself is the obvious case:

::term{id=wrap-gate-only}

## 4. Run it

::flow{term=run-gh}

The first time, that is: your shell finds the shim, the shim execs
`secreq x gh repo list`, secreq auto-spawns the consent daemon, and the
command **stops**, which is what the wait indicator means, while the daemon
puts up a window showing what's about to happen. You press Approve, the daemon
resolves the secret and hands it back, and the real `gh` runs with
`GITHUB_TOKEN` in its environment. Anything matching that value is redacted
from its output.

Run it again from the same shell and nothing prompts: approving also
remembers. The grant belongs to _that shell_: a different terminal, an
editor, or an `npm` postinstall each get asked in their own right. See
[how approval is scoped](./wraps.md#how-approval-is-scoped).

## 5. A few defaults

- **Unwrapped binaries pass straight through.** Calling one that has no
  wrap entry just execs the real thing. You can put the shim dir on `PATH`
  before you've wrapped everything.
- **`secreq view`** opens the manager window, holding your rules and your
  audit log. The audit log records names, never values.
- **`--sq-yes`** skips the daemon entirely and is the supported path for
  CI: `secreq x --sq-yes gh repo list`.
- **`--sq-raw`** disables masking when you actually want the value on
  stdout, e.g. `secreq x --sq-raw gh auth token | pbcopy`.

## SSH keys, too

`secreq` can act as your **SSH agent**, gating each key signature on the
same ceremony, so `git push` prompts you with the caller chain before
signing. See [ssh-agent](./ssh-agent.md), including the key-custody
tradeoff against 1Password's sealed agent.

## Next

- [cli guide](./cli.md): `x` versus `run`, and the argv contract.
- [wraps](./wraps.md): the config file in full.
- [troubleshooting](./troubleshooting.md): if something above didn't work.
