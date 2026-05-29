# Overview

## What it is

`secreq` is a per-binary CLI wrapper. You wrap commands like `gh`, `aws`,
`kubectl`, `psql` once; from then on, every invocation of them
(interactive or scripted) goes through `secreq`'s consent prompt and gets
its secrets injected from your chosen store. Output is streamed through
a masking filter so any secret that leaks to stdout/stderr is redacted.

Think of it as **1Password Shell Plugins, but generic** — bring your own
store(s), with provenance-aware consent before any release.

## What problem it solves

Every other tool in the adjacent space:

- **`op` / 1Password Shell Plugins** — 1Password only.
- **`aws-vault`** — AWS only.
- **`envchain`** — macOS Keychain only.
- **`direnv`** — per-directory, not per-binary; no consent.
- **`gopass env`** — `pass` only.
- **`varlock`** — solves the *project-level* problem brilliantly (typed
  schemas, framework integrations, AI-safe schema sharing). Different
  scope from us.

The empty square `secreq` occupies: **per-binary wrap × multi-provider ×
provenance-aware consent**. Nobody else covers all three.

## Mental model

```
   ┌─ wraps.json5 (user-scope) ────────────────────────────────────────┐
   │  per-binary wraps: { gh, aws, kubectl, … }                         │
   │  each names env vars and `secret://provider/locator` references    │
   │                                                                    │
   │  providers (built-ins + your overrides): op, keychain, pass, …     │
   └───────────────────────────────────────────────────────────────────┘
                  │
                  ▼  shell or script invokes `gh repo list`
   ┌─ PATH shim ────────────────────────────────────────────────────────┐
   │  ~/.secreq/shims/gh ⇒ exec secreq gh "$@"                          │
   │  covers every execvp() — interactive shells, npm postinstalls,     │
   │  IDE integrations, anything that resolves `gh` via PATH            │
   └───────────────────────────────────────────────────────────────────┘
                  │
                  ▼
   ┌─ consent ──────────────────────────────────────────────────────────┐
   │  cache check: (wrap_name, ppid, parent_start_time)                  │
   │    hit  → approve silently                                          │
   │    miss → prompt: command, cwd, caller chain, env names + providers │
   │                                                                    │
   │  Decisions: approve / approve+remember / deny                       │
   │  Approval is scoped to the direct parent — postinstall hooks       │
   │  re-prompt even if you just approved `gh` from your shell           │
   └───────────────────────────────────────────────────────────────────┘
                  │ approved
                  ▼
   ┌─ provider invocation ─────────────────────────────────────────────┐
   │  for each env entry: run the provider's retrieve template          │
   │  (batched when N entries share a provider with retrieve_batch —    │
   │   one biometric for the whole set instead of N)                    │
   │  (may sub-prompt: Touch ID, op biometric)                          │
   └───────────────────────────────────────────────────────────────────┘
                  │
                  ▼
   ┌─ exec ─────────────────────────────────────────────────────────────┐
   │  find the real `gh` on PATH (skipping our shim dir to avoid recursion)
   │  spawn it with secrets in env                                       │
   │  stream stdout/stderr through a multi-secret masker that redacts   │
   │  any resolved value that appears in output (unless `--raw`)        │
   └───────────────────────────────────────────────────────────────────┘
```

## Key concepts

| Concept | One-line definition |
|---|---|
| **Wrap** | A per-binary config entry: env vars to inject + reason. Cache lifetime is the lesser of the parent process's lifetime and the daemon's lifetime (there's no clock-based TTL). |
| **Shim** | A 5-line POSIX script in your shim dir that execs `secreq <wrap>`. Placed on PATH so every invocation of the wrapped binary goes through us. |
| **Provider** | A scheme that knows how to fetch (and optionally store) a value. Built-ins: `op`, `keychain` (macOS), `lastpass`, `pass` (Unix). |
| **Reference** | `secret://<provider>/<locator>`. The thing that crosses code boundaries; values never do. |
| **Consent ceremony** | The before-fetch prompt showing the caller chain and what's about to be released. Approval is **direct-parent-scoped**. |
| **Cache key** | `(wrap_name, ppid, parent_start_time)`. Direct parent only; pid-recycle-safe. |
| **Masking** | A streaming, byte-exact redactor that scrubs any resolved value from the child's output. |
| **Pass-through** | `secreq <bin>` for a binary with no wrap entry just execs the binary unchanged. Lets you blanket-shim safely. |
| **`retrieve_batch`** | A provider's optional multi-resolve mode (`op run -- printenv` for `op`). N secrets, one biometric. |

## What it is *not*

- **Not a secret storage backend.** It reads from your existing stores.
- **Not a long-lived secret broker.** There *is* a consent daemon, but it
  only ever gates access — it never persists secret values to disk, and
  the approvals cache lives in its memory only (`secreq daemon stop`
  clears it; so does walking away for 30 minutes — the daemon idle-exits
  when nothing's in the queue). Each wrap run still re-fetches values
  from the underlying provider; the daemon coalesces parallel asks so a
  burst of N invocations triggers one biometric, not N.
- **Not a project-level config tool.** That's varlock's space, and varlock
  is good at it. We coexist; we don't compete.
- **Not a `.env` migrator.** The pre-pivot `import` command went away — if
  you have `.env` secrets you want to move into providers, do it manually
  (or wait for varlock's import path).

## Trust and threat model (short version)

- Approval is **direct-parent scoped**. An approved `gh` from your zsh
  doesn't extend to npm-spawned-`gh` from a postinstall hook — that's a
  different ppid and re-prompts.
- Once injected as env vars, secrets are visible to the child process and
  anything that can read `ps eww` / `/proc/<pid>/environ`. Accepted limit.
- Mitigations: PTY/piped output masking, zeroizing in-process memory,
  audit log of every grant (names only, never values), provenance-aware
  consent, pid-recycle-safe cache.
- See [`../dev-docs/architecture.md`](../dev-docs/architecture.md) for
  the technical details.

## Next step

If you've never run `secreq` before, start with
[`getting-started.md`](./getting-started.md) for a five-minute setup
walkthrough. Then [`cli.md`](./cli.md) is the full command reference
and [`wraps.md`](./wraps.md) covers authoring `wraps.json5` by hand.
If you want to *change* `secreq`, see
[`../dev-docs/`](../dev-docs/).
