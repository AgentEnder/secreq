# Authoring `wraps.json5`

> **You may not need this page.** `secreq wrap <binary>` asks for everything
> a wrap needs and writes the entry for you. Unlike hand-editing, it
> resolves the locator against your store before saving, so a typo fails
> while you're still looking at it. Read this when you want to know what a
> field means, hand-edit something the prompts don't cover, or check a
> config into a dotfiles repo.

::term{id=wrap-gh}

The config lives at `~/.secreq/wraps.json5` (or `$SECREQ_HOME/wraps.json5`).
It's JSON5: comments, unquoted keys, trailing commas, single quotes. Point
your editor at [`wraps.schema.json`](./wraps.schema.json) for completion:

```json5
{
  $schema: './wraps.schema.json',
  $shim_dir: '~/.secreq/shims', // set by `secreq init`

  gh: {
    $reason: 'GitHub API access',
    env: {
      GITHUB_TOKEN: 'secret://op/Personal/GitHub Token/credential',
    },
  },

  aws: {
    $reason: 'AWS deployments',
    env: {
      AWS_ACCESS_KEY_ID: 'secret://op/Work/AWS/access_key_id',
      AWS_SECRET_ACCESS_KEY: 'secret://op/Work/AWS/secret_access_key',
    },
  },

  kubectl: {
    env: { KUBECONFIG: 'secret://keychain/work/kubeconfig' },
  },
}
```

Every top-level key that isn't `$`-prefixed is a **wrap**, named for the
binary. `$`-prefixed keys are settings.

## Settings

| Key               | Meaning                                                                                                                                                                                                        |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `$shim_dir`       | Where `secreq wrap` drops PATH shims. `~/` is expanded. Set by `secreq init`.                                                                                                                                  |
| `$wait_indicator` | Default `true`. Whether a blocked wrap prints a "waiting for approval" indicator to stderr: a spinner on a TTY, a timestamped line every 30s on a pipe. `SECREQ_NO_WAIT_INDICATOR` silences it per-invocation. |
| `$editor`         | Editor id (`code`, `cursor`, `zed`, `nvim`) the rule editor's "Open in editor" button defaults to. Written when you pick one in the manager's Rules view.                                                      |
| `$schema`         | Editor pointer; ignored at runtime.                                                                                                                                                                            |
| `providers`       | Provider definitions. Optional; see [providers](./providers.md).                                                                                                                                               |

Other `$`-prefixed keys are reserved. A per-wrap `$description` parses but
does nothing yet.

## Wraps

| Setting   | Type              | Meaning                                                                                                                                                     |
| --------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `$reason` | string            | Rationale shown in the consent prompt.                                                                                                                      |
| `env`     | object (optional) | Environment variables to inject. Each value is a full `secret://provider/locator` reference. Bare locators aren't accepted here. Omit for a gate-only wrap. |

A reference is `secret://<provider>/<locator>`: the provider is a scheme
name (built-in or declared in `providers`), and the locator is everything
after the first `/`. See [providers](./providers.md).

At the `Locator` prompt you can paste the store's own reference instead of
retyping the tail of it. 1Password's "Copy Secret Reference" gives you
`op://Vault/Item/field`, quoted or not, and `secreq wrap` strips the scheme,
the quotes and the whitespace, then tells you what it read.

### Already-satisfied env vars

An `env` entry whose variable is **already set** in the calling environment
to a non-empty value that isn't a `secret://…` marker, is skipped entirely. Nothing is resolved, and the child inherits what was already
there.

If every entry is satisfied this way the run needs no consent at all and
passes straight through, because secreq is releasing nothing. A partially
satisfied wrap prompts only for what's missing. This is what keeps wrapped
binaries cheap inside environments that pre-inject credentials: CI, a
shell where you exported the token yourself, a nested `secreq run`.

### Gate-only wraps

A wrap with no `env` is a **gate-only wrap**: invoking the binary still
requires consent, but nothing is resolved or injected. Use it for a tool
that manages its own credentials and has no secret for secreq to pass.
`op` is the canonical case:

```json5
op: {
  $reason: "1Password vault access",
}
```

::shot{id=21-gate-only-pending}

Now every `op read …` pauses for a prompt showing the full command, the
working directory and the caller tree, the "why am I getting this?"
context the tool's own prompt omits. The evidence well's secret row gives
way to a gate-only marker.

`secreq wrap op --reason "1Password vault access"` creates one directly, and
the interactive flow offers it as the second option on the first question:

::term{id=wrap-gate-only}

**Wrapping a provider CLI is safe.** If you gate `op` _and_ use it as a
`secret://op/...` provider, secreq won't double-prompt: it runs the provider
with an internal marker that makes the wrapped `op` pass straight through.
Only the `op` calls _you_ make are gated, never the ones secreq makes to
fetch a value for another wrap.

## How approval is scoped

When you approve a wrap invocation, the decision is cached against the
**direct parent process**, keyed on `(wrap, ppid, parent start time)`.

| Scenario                                                      | Outcome                          |
| ------------------------------------------------------------- | -------------------------------- |
| Run `gh` from your zsh, approve, run `gh` again from that zsh | Cache hit → no prompt.           |
| Open a new terminal and run `gh` there                        | Different ppid → prompt.         |
| An `npm` postinstall hook invokes `gh` through the shim       | Different ppid (`npm`) → prompt. |
| A pid is recycled after the original shell died               | Different start time → prompt.   |

Descendants of a process you already approved for ride the same grant.

The start-time component is what makes this pid-recycle safe: `(ppid,
start_time)` identifies exactly one process across its lifetime, so a new
process inheriting the number gets a fresh prompt.

**There is no TTL and no on-disk file.** Cache lifetime is bounded by two
natural boundaries: the parent process's lifetime, and the daemon's. When
the shell that approved a wrap exits, no process can share both its pid and
its start time, so the entry becomes unreachable. When the daemon exits
(`secreq daemon stop`, `--force`, or the two-hour idle timeout), the whole
cache goes with it. Nothing artificial expires entries in between, and a
daemon restart is always the clean reset.

Two kinds of request never remember: `secreq run`, whose
identity is fixed and would over-match, and SSH signatures, which have
their own clock-bounded [session grants](./ssh-agent.md).

## Editing the file

`secreq edit` opens it in `$EDITOR`; `secreq check` and `secreq doctor`
validate afterwards.

`secreq wrap` and `unwrap` edit the file for you but **don't preserve
hand-written comments** through a write. Prefer them for adding entries,
and `secreq edit` for surgical changes you want kept verbatim.
