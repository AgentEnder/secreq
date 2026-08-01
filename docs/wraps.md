# Authoring `config.toml`

> **You may not need this page.** `secreq wrap <binary>` asks for everything
> a wrap needs and writes the entry for you. Unlike hand-editing, it
> resolves the locator against your store before saving, so a typo fails
> while you're still looking at it. Read this when you want to know what a
> field means, hand-edit something the prompts don't cover, or check a
> config into a dotfiles repo.

::term{id=wrap-gh}

The config lives at `~/.secreq/config.toml` (or `$SECREQ_HOME/config.toml`).
It's TOML. The `#:schema` line points your editor at the published schema for
completion and inline validation:

```toml
#:schema ./wraps.schema.json
shim_dir = "~/.secreq/shims"   # set by `secreq init`

[secrets.GITHUB_TOKEN]
ref = "secret://op/Personal/GitHub Token/credential"

[wraps.gh]
reason = "GitHub API access"
env_secrets = ["GITHUB_TOKEN"]

[wraps.aws]
reason = "AWS deployments"
env.AWS_ACCESS_KEY_ID = "secret://op/Work/AWS/access_key_id"
env.AWS_SECRET_ACCESS_KEY = "secret://op/Work/AWS/secret_access_key"

[wraps.kubectl]
env.KUBECONFIG = "secret://keychain/work/kubeconfig"
```

Each entry under `[wraps.*]` is a **wrap**, named for the binary. Every
other top-level key is a setting this file declares, so a mistyped one is
an error rather than a wrap for a binary of that name.

## Settings

| Key              | Meaning                                                                                                                                                                                                        |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `shim_dir`       | Where `secreq wrap` drops PATH shims. `~/` is expanded. Set by `secreq init`.                                                                                                                                  |
| `wait_indicator` | Default `true`. Whether a blocked wrap prints a "waiting for approval" indicator to stderr: a spinner on a TTY, a timestamped line every 30s on a pipe. `SECREQ_NO_WAIT_INDICATOR` silences it per-invocation. |
| `editor`         | Editor id (`code`, `cursor`, `zed`, `nvim`) the rule editor's "Open in editor" button defaults to. Written when you pick one in the manager's Rules view.                                                      |
| `providers`      | Provider definitions. Optional; see [providers](./providers.md).                                                                                                                                               |
| `secrets`        | Secrets declared once under a name, with an optional per-secret cache `ttl`. See [declared secrets](#declared-secrets).                                                                                        |
| `ssh`            | SSH identities for the agent. Optional; see [ssh-agent](./ssh-agent.md).                                                                                                                                       |
| `wraps`          | The wraps themselves, keyed by binary name.                                                                                                                                                                    |

The schema pointer is the `#:schema` comment at the top of the file, not a
key. TOML has no `$schema` convention, and a comment cannot collide with a
setting.

## Wraps

| Setting       | Type              | Meaning                                                                                                                                                                                                                                    |
| ------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `reason`      | string            | Rationale shown in the consent prompt.                                                                                                                                                                                                     |
| `env_secrets` | array (optional)  | [Declared secret](#declared-secrets) names to inject under those same environment-variable names. Names must match `[A-Za-z_][A-Za-z0-9_]*`; references and provider locators aren't accepted.                                             |
| `env`         | object (optional) | Environment variables to inject. Each value is a `secret://provider/locator` reference or a `secret://<name>` naming a declared secret. Use this form for a different env name or an inline reference. Bare locators aren't accepted here. |

A reference is `secret://<provider>/<locator>`: the provider is a scheme
name (built-in or declared in `providers`), and the locator is everything
after the first `/`. See [providers](./providers.md).

A reference with **no** `/` after the scheme is a declared secret's name
instead. The slash is the whole rule, so `secret://op/Personal/GitHub/token`
and `secret://github_token` can never be read the same way.

At the `Locator` prompt you can paste the store's own reference instead of
retyping the tail of it. 1Password's "Copy Secret Reference" gives you
`op://Vault/Item/field`, quoted or not, and `secreq wrap` strips the scheme,
the quotes and the whitespace, then tells you what it read.

### Already-satisfied env vars

An `env_secrets` or `env` entry whose variable is **already set** in the
calling environment to a non-empty value that isn't a `secret://…` marker,
is skipped entirely. Nothing is resolved, and the child inherits what was
already there.

If every entry is satisfied this way the run needs no consent at all and
passes straight through, because secreq is releasing nothing. A partially
satisfied wrap prompts only for what's missing. This is what keeps wrapped
binaries cheap inside environments that pre-inject credentials: CI, a
shell where you exported the token yourself, a nested `secreq run`.

### Gate-only wraps

A wrap with neither `env_secrets` nor `env` is a **gate-only wrap**: invoking
the binary still requires consent, but nothing is resolved or injected. Use
it for a tool that manages its own credentials and has no secret for secreq
to pass. `op` is the canonical case:

```toml
[wraps.op]
reason = "1Password vault access"
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

## Declared secrets

A secret written inline in a wrap's `env` is a string, repeated in every
wrap that needs it. Declaring it under `secrets` gives it a name to reference
and a place for per-secret settings to live:

```toml
[secrets.GITHUB_TOKEN]
ref = "secret://op/Personal/GitHub Token/credential"
ttl = "15m"

[wraps.gh]
env_secrets = ["GITHUB_TOKEN"]

[wraps.hub]
env.GH_TOKEN = "secret://GITHUB_TOKEN"
```

| Setting | Type              | Meaning                                                                                                                           |
| ------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `ref`   | string            | The `secret://provider/locator` this name stands for. Always a provider reference — a declaration can't name another declaration. |
| `ttl`   | string (optional) | How long the daemon may serve this secret from its cache. A count and a unit: `30s`, `15m`, `2h`, `1d`.                           |

A name contains no `/`. Two names for one `ref` are fine as long as they
agree on the `ttl`; a file where they disagree fails to load, because one
reference is one cached value and so has one lifetime.

Changing a declaration's `ref` changes it for every wrap that references
the name, which is the point. `env_secrets` removes the repeated env key and
reference when the two names agree; `env` remains the explicit renaming form.
`secreq wrap gh --secret GITHUB_TOKEN` writes the first form. `secreq check`
reports an unknown declaration, a reference in `env_secrets`, or a name
claimed by both forms.

::term{id=wrap-declared-secret}

### How long a value stays cached

The daemon caches a resolved value so a second command doesn't pay for a
second provider call — on 1Password, a second biometric prompt. Without a
`ttl` that value lives as long as the daemon, which is the default and what
every secret does unless you say otherwise.

A `ttl` shortens it, for that secret only:

```toml
[secrets.prod_deploy_key]
ref = "secret://op/Work/Deploy/key"
ttl = "5m"
```

Five minutes after the value is fetched the daemon drops and scrubs it. The
next command that needs it re-runs the provider, biometric prompt included —
which is the trade you are making, and why this is per secret rather than a
global setting. Set it on the credential you want re-confirmed, not on
everything.

Two consequences worth knowing:

- **The approval is untouched.** A wrap you approved and told secreq to
  remember stays approved. Only the value expires; the prompt does not
  come back.
- **The `ttl` follows the reference, not the name.** A wrap that writes
  `secret://op/Work/Deploy/key` inline gets the same five minutes, because
  the daemon caches one value per reference.

A `ttl` is also the answer to a secret you rotate upstream: without one, the
old value is served until the daemon restarts.

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

**An approval has no TTL and no on-disk file.** Its lifetime is bounded by
two natural boundaries: the parent process's lifetime, and the daemon's.
When the shell that approved a wrap exits, no process can share both its pid
and its start time, so the entry becomes unreachable. When the daemon exits
(`secreq daemon stop`, `--force`, or the two-hour idle timeout), the whole
cache goes with it. Nothing artificial expires an approval in between, and a
daemon restart is always the clean reset.

A secret's [cache `ttl`](#how-long-a-value-stays-cached) is a different
thing and does not touch this: when a value expires, the next command
re-fetches it from the provider, but the approval it was released under
still stands, so no prompt opens.

Two kinds of request never remember: `secreq run`, whose
identity is fixed and would over-match, and SSH signatures, which have
their own clock-bounded [session grants](./ssh-agent.md).

## Editing the file

`secreq edit` opens it in `$EDITOR`; `secreq check` and `secreq doctor`
validate afterwards.

`secreq wrap` and `unwrap` edit the file for you but **don't preserve
hand-written comments** through a write. Prefer them for adding entries,
and `secreq edit` for surgical changes you want kept verbatim.
