# Overview

## What it is

`secreq` is a per-binary CLI wrapper. You wrap commands like `gh`, `aws`,
`kubectl`, or `psql` once. From then on every invocation of them, whether
interactive or scripted, goes through a consent prompt and gets its secrets
injected from your chosen store. Output is streamed through a
masking filter, so a secret that leaks to stdout is redacted on the way
past.

::shot{id=02-single-pending}

Think of it as **1Password Shell Plugins, but generic**: bring your own
store, or several, with provenance-aware consent before any release.

It also doubles as a [provenance-aware SSH agent](./ssh-agent.md). Point
your SSH clients at it and the same ceremony gates every signature, showing
who's asking before the key is used.

## What problem it solves

Everything else in the adjacent space is scoped to one store or one shape
of problem:

- **`op` / 1Password Shell Plugins**: 1Password only.
- **`aws-vault`**: AWS only.
- **`envchain`**: macOS Keychain only.
- **`gopass env`**: `pass` only.
- **`direnv`**: per-directory, not per-binary; no consent.
- **`varlock`**: solves the _project-level_ problem well (typed schemas,
  framework integrations). Different scope; we coexist rather than compete.

The empty square is **per-binary wrap × multi-provider × provenance-aware
consent**. Nobody else covers all three.

## Mental model

```
   ┌─ wraps.json5 (user-scope) ────────────────────────────────────────┐
   │  per-binary wraps: { gh, aws, kubectl, … }                        │
   │  each names env vars and `secret://provider/locator` references   │
   │  providers (built-ins + your overrides): op, keychain, pass, …    │
   └───────────────────────────────────────────────────────────────────┘
                  │
                  ▼  shell or script invokes `gh repo list`
   ┌─ PATH shim ───────────────────────────────────────────────────────┐
   │  ~/.secreq/shims/gh ⇒ exec '<abs path to secreq>' x 'gh' "$@"     │
   │  covers every execvp() — shells, npm postinstalls, IDEs           │
   └───────────────────────────────────────────────────────────────────┘
                  │
                  ▼
   ┌─ consent ─────────────────────────────────────────────────────────┐
   │  cache check: (wrap, ppid, parent start time)                     │
   │    hit  → release silently                                        │
   │    miss → prompt: command, cwd, caller chain, env names           │
   │  Approval is scoped to the direct parent — a postinstall hook     │
   │  re-prompts even if you just approved `gh` in your shell          │
   └───────────────────────────────────────────────────────────────────┘
                  │ approved
                  ▼
   ┌─ resolve + exec ──────────────────────────────────────────────────┐
   │  run each provider's retrieve template (batched where supported:  │
   │  one biometric for N secrets, not N)                              │
   │  exec the real binary with secrets in env, streaming its output   │
   │  through a masker that redacts every resolved value               │
   └───────────────────────────────────────────────────────────────────┘
```

## Vocabulary

| Term                 | Meaning                                                                                                                                           |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Wrap**             | A per-binary config entry: the env vars to inject, plus a reason. See [wraps](./wraps.md).                                                        |
| **Shim**             | A five-line POSIX script on your `PATH` that execs `secreq x <wrap>`, so every invocation of that binary routes through secreq.                   |
| **Provider**         | A scheme that knows how to fetch (and sometimes store) a value. Built-ins: `op`, `keychain`, `lastpass`, `pass`. See [providers](./providers.md). |
| **Reference**        | `secret://<provider>/<locator>`. The thing that crosses code boundaries; values never do.                                                         |
| **Consent ceremony** | The before-fetch prompt showing the caller chain and what is about to be released. See [consent-window](./consent-window.md).                     |
| **Gate-only wrap**   | A wrap with no secrets, existing purely to put consent in front of a tool that holds its own credentials.                                         |
| **Pass-through**     | `secreq x <bin>` for a binary with no wrap entry execs it unchanged, which is what makes blanket-shimming safe.                                   |
| **Rule**             | A saved decision that answers for you. Declarative, or [compiled from code](./wasm-rules.md).                                                     |

## What it is _not_

- **Not a secret storage backend.** It reads from stores you already have.
- **Not a long-lived secret broker.** The daemon gates access; it never
  persists secret values to disk, and its approvals cache is memory-only.
  Each run re-fetches from the provider. The daemon's job is to coalesce
  parallel asks, so a burst of N invocations costs one biometric instead of N.
- **Not a project-level config tool.** That's varlock's space.
- **Not a hardware-sealed SSH agent.** See the custody note below.

## Trust and threat model

- Approval is scoped to the direct parent. An approved `gh` in your zsh does
  not extend to `gh` spawned by an npm postinstall, and the key includes the
  parent's start time, so a recycled pid cannot inherit a grant.
- A token wrap injects the secret into the child's environment, where any
  **same-UID** process can read it (`/proc/<pid>/environ` on Linux; macOS has
  no `/proc`, so `ps -E` or `sysctl KERN_PROCARGS2`), as can root. Other users
  cannot, and neither can the world. So a same-UID adversary, say a script you
  were tricked into running, can lift a live token and use it outside secreq's
  consent and audit entirely. Rules and consent gate the wrap *invocation*,
  not the credential once it is injected. Masking, zeroizing and the audit log
  narrow this; an environment variable does not stop being readable. SSH
  sidesteps the whole problem, because the key never enters an environment and
  the agent signs over a socket. Tokens have no equivalent capability channel
  yet; a keyring front-end that gives them one is tracked work.
- SSH key custody is downgraded: the key is resolved into the daemon's
  memory to sign and then zeroized, where 1Password's sealed agent never
  releases it at all.
  [Details](./ssh-agent.md#trust-model-note-key-custody-is-downgraded).
- Sandbox granularity is downgraded: a guest VM has no host pid, so the
  declared scope is the principal rather than a verified process chain.
  [Details](./secret-agent.md#trust-model-note-granularity-is-downgraded).

## Next

Never run it before? [getting-started](./getting-started.md). Want the
command surface? [cli guide](./cli.md). Want to change secreq itself?
[`../CONTRIBUTING.md`](../CONTRIBUTING.md).
