# CLI guide

`secreq` has **admin verbs** that configure things (`init`, `wrap`, `ssh`,
`rules`, `daemon`, …) and **two run verbs** that actually release secrets:

```
secreq x    <WRAP> [ARGS...]        # a wrapped binary; what a PATH shim calls
secreq run  -- <CMD> [ARGS...]      # any command, resolving ambient secret:// refs
```

Everything each command accepts is in
[All commands](./cli-reference.md), generated from the CLI itself so it
can't drift from the binary you have. This page is the part that isn't a
flag list: why there are two run verbs, why `x` forwards every flag you
give it, and what each one does between your keystroke and the child
process.

## Wrap-and-run: `x`

`x` runs a binary you have wrapped. You rarely type it: `secreq wrap gh`
drops a five-line shim at `<shim_dir>/gh` whose body is
`exec '<path to secreq>' x 'gh' "$@"`, so anything that resolves `gh`
through `PATH` (your shell, `npm`, `make`, your IDE) routes through secreq
without knowing it. The shim names secreq by absolute path, so a `secreq`
that appears earlier on `PATH` later (direnv, asdf, `node_modules/.bin`)
cannot take its place.

### The argv contract

Because the shim forwards your argv wholesale, **`x` owns no ordinary
flags.** Every argument except the wrap name reaches the wrapped binary
untouched, so `gh --help` through the shim means gh's help, `gh -y` means
gh's `-y`. Anything else would mean secreq could silently eat a flag you
meant for the binary.

secreq's own options therefore use a reserved `--sq-` prefix, recognized
before or after the wrap name:

| Flag                 | Effect                                                                    |
| -------------------- | ------------------------------------------------------------------------- |
| `--sq-config <PATH>` | Use this config instead of `~/.secreq/config.toml`.                       |
| `--sq-raw`           | Disable output masking. Secrets are still injected.                       |
| `--sq-yes`           | Auto-approve without prompting; resolves client-side, no daemon.          |
| `--sq-no-remember`   | Don't read or write the remembered-approval cache.                        |
| `--sq-help`          | Print `x`'s help.                                                         |
| `--`                 | Stop `--sq-` recognition; everything after a literal `--` forwards as-is. |

These are the one part of the CLI that clap never sees. They're parsed by
hand, so that `<wrap> --help` can reach the binary. That is why they are
listed here rather than in the generated reference.

An unrecognized `--sq-*` argument is an error (exit 2), not a forward: the
prefix is reserved so a typo can't hand the flag to the wrong process. The
global options (`--raw`, `--yes`, …) don't compose with `x`; passing one
before the wrap name is rejected with a hint to use the `--sq-` form.

### What a run does

1. Look up `<WRAP>` in the config.
2. **No wrap configured → pass through.** Find the real binary on `PATH`
   (skipping the shim dir, so it can't recurse) and exec it with no
   injection. This is what makes it safe to shim a binary before you've
   decided what it needs.
3. **Drop `env_secrets` and `env` entries the environment already
   satisfies.** A variable already set to a non-empty, non-`secret://` value
   needs no injection; the child inherits it. If _every_ entry is satisfied,
   the run passes through with no prompt at all, because secreq is releasing
   nothing. Gate-only wraps have neither form, so they always gate.
4. Walk the parent process tree, then hand off to the consent daemon
   (auto-spawning it if no socket is live). A cache hit replies
   immediately; otherwise you get the [prompt](./consent-window.md).
   Parallel asks with the same key coalesce into one request.
5. On approve, resolve each entry through its provider, batched when a
   provider supports it, so N secrets cost one biometric.
6. Exec the real binary with the resolved values in its environment,
   streaming its output through a masker that redacts every resolved value
   (unless `--sq-raw`).

### Exit codes

| Code    | Meaning                                                   |
| ------- | --------------------------------------------------------- |
| 0       | Child exited cleanly.                                     |
| 1       | Consent denied, or provider resolution failed.            |
| 2       | Usage error: no wrap name, or an unknown `--sq-*` option. |
| child's | Otherwise the child's own exit code propagates.           |

## Ambient references: `run`

Where `x` injects a _declared_ env map for a _known binary_, `run` resolves
`secret://provider/locator` references it finds _in the environment_ for an
_arbitrary_ command. Nothing needs configuring first, because the
references describe the secrets inline:

```sh
# A committable, refs-only .env. No plaintext secrets:
#   DATABASE_URL=secret://op/Work/Postgres/url
#   STRIPE_KEY=secret://keychain/stripe-live
secreq run --env-file .env -- ./deploy.sh
```

`--env-file` entries layer **under** the inherited environment (inherited
wins on conflict, matching `op run --env-file`). A value that starts with
`secret://` but doesn't parse is a hard error _before_ the command runs, so
a literal `secret://…` never reaches the child. With no references at all,
`run` execs directly, with no daemon and no prompt.

### Why `run` always asks

`run` presents a **fixed identity** for every invocation, so a remembered
approval would over-match wildly: approving one `run` would approve every
later one from that shell. It therefore never persists approvals.

The re-prompt is cheap: all `run` invocations share one
value-cache bucket, so a reference that's already resolved is served
without a provider call and without a biometric. The prompt is one click,
not an unlock. A rule on the Rules view can remove even that.

Two consequences follow:

- **Nested `run` needs no special handling.** The outer run already
  replaced every reference with a plain value, so the inner one sees no
  refs and just execs.
- **Concurrent runs in one process tree share one prompt.** The daemon
  unions their requests into a single card, annotating each secret with the
  command that asked for it. You approve once, and each command receives
  **only its own** secrets, never a sibling's.

::shot{id=run-session-card}

Exit codes match `x`.

## Reading a value directly

`secreq read <REF>…` resolves references and prints them as a JSON object
keyed by each ref exactly as typed, so it pipes into `jq`. Every read goes
through the consent daemon, so it is prompted and audited. There is **no
`--yes` bypass**: the value lands on stdout, where masking cannot help you.

`secreq resolve` is a different thing that looks similar: it is the _guest_
half of a sandbox socket, asking a **host** secreq to release something.
See [secret-agent](./secret-agent.md).

## Bare `secreq`

With no subcommand and a terminal to prompt on, `secreq` presents an action
picker (open the manager, list wraps, manage rules, open pending requests,
set up the SSH agent, run first-time setup) and dispatches into the verb you
choose. The cursor starts on the manager, so `secreq` then
<kbd>Enter</kbd> opens the window.

Without a terminal (a shim, a pipe, CI) there is nothing to pick from, so a
bare invocation exits 2 with a usage hint instead.

## Revoking an approval

There is no per-invocation "forget this" flag. Approvals live in the
daemon's memory, so `secreq daemon stop` clears every one of them; the next
wrap auto-spawns a fresh daemon with an empty cache. How the scope is keyed,
and why it has no TTL, is in [wraps](./wraps.md#how-approval-is-scoped).

## Environment variables

| Variable                      | When                                                                                                                                           |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `SECREQ_HOME`                 | Root for everything secreq owns: config, `audit.log`, `daemon.log`, registered rule modules. Falls back to `~/.secreq`.                        |
| `SECREQ_SOCK`                 | Read by `secreq resolve`: the scoped agent socket to ask, mirroring `SSH_AUTH_SOCK`. See [secret-agent](./secret-agent.md).                    |
| `SECREQ_NO_DAEMON`            | Any non-empty value disables the daemon entirely; consent fails closed unless `--sq-yes` / `--yes` is used. For tests and headless automation. |
| `SECREQ_NO_WAIT_INDICATOR`    | Silences the "waiting for approval" indicator for one invocation, regardless of the `wait_indicator` config setting.                           |
| `XDG_RUNTIME_DIR`             | Preferred home for the daemon's sockets and pidfile; it is mode-0700 tmpfs. Falls back to `<root>/run`.                                        |
| `XDG_CONFIG_HOME`             | Legacy config location the first-run migration copies into the root. No longer used for discovery.                                             |
| `SHELL`                       | `init` reads this to choose which shell config to edit.                                                                                        |
| `EDITOR` / `VISUAL`           | Used by `secreq edit`.                                                                                                                         |
| `DISPLAY` / `WAYLAND_DISPLAY` | Linux/BSD: with neither set, secreq fails closed rather than spawning a daemon that can't render.                                              |

## Next

- [All commands](./cli-reference.md): every subcommand and flag.
- [wraps](./wraps.md): authoring `config.toml`, and how approval is scoped.
- [consent-window](./consent-window.md): the windows these verbs put up.
