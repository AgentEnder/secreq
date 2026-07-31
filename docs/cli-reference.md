<!-- GENERATED FILE. DO NOT EDIT.
     Source: packages/secreq/src/cli.rs (the clap tree).
     Regenerate: cargo run --example gen-cli-reference > docs/cli-reference.md
     Guarded by: packages/secreq/tests/cli_drift.rs -->

# All commands

Every command, subcommand, and flag `secreq` accepts, generated from the CLI definition itself.

This is the exhaustive list. For what the commands are *for* (the two run verbs, why `x` forwards every flag it is given, how approval is scoped) read the [CLI guide](./cli.md).

## Global options

These reach the admin verbs and `run`. They do **not** apply to `x`, whose argv belongs to the wrapped binary. See the [argv contract](./cli.md#the-argv-contract) for its `--sq-` equivalents.

| Flag | Meaning |
| --- | --- |
| `--config <PATH>` | Use a specific config file instead of `~/.secreq/config.toml`. For `x` use `--sq-config` |
| `--raw` | Skip output masking. The wrapped binary still runs with secrets in its env; only redaction of its stdout/stderr is disabled. Applies only to `run`, not admin verbs; for `x` use `--sq-raw` |
| `-y, --yes` | Auto-approve without prompting. Composes through nested runs. For `x` use `--sq-yes` |
| `--no-remember` | Don't read or write the remembered-approval cache. For `x` use `--sq-no-remember` |

`-h`/`--help` and `-V`/`--version` work everywhere.

## `secreq init`

```
secreq init [OPTIONS]
```

First-time setup: pick the shim dir and (optionally) wire it into PATH

| Flag | Meaning |
| --- | --- |
| `--shim-dir <PATH>` | Default shim dir to suggest (overrides `~/.secreq/shims`) |

## `secreq wrap`

```
secreq wrap [OPTIONS] <BINARY>
```

Add (or update) a wrap for a binary; installs the PATH shim

| Argument | Meaning |
| --- | --- |
| `<BINARY>` | The binary name to wrap, e.g. `gh` |

| Flag | Meaning |
| --- | --- |
| `--env <NAME=REF>…` | `--env NAME=secret://provider/locator`. Repeatable. If none given, runs the interactive flow |
| `--reason <REASON>` | Reason to show in the consent prompt |

## `secreq unwrap`

```
secreq unwrap <BINARY>
```

Remove a wrap (config entry + shim)

| Argument | Meaning |
| --- | --- |
| `<BINARY>` | The binary name |

## `secreq wraps`

```
secreq wraps
```

List configured wraps

## `secreq ssh`

```
secreq ssh <SUBCOMMAND>
```

Manage secreq's SSH agent: configure identities, wire SSH clients to the agent socket, and verify that signing works

### `secreq ssh setup`

```
secreq ssh setup [OPTIONS]
```

Wire SSH clients at secreq's agent socket by writing a managed block to `~/.ssh/config` (`IdentityAgent`) or your shell rc (`SSH_AUTH_SOCK`). Pick the method with `--method`, or get an interactive prompt when it's omitted. `--undo` strips the block back out

| Flag | Meaning |
| --- | --- |
| `--method <METHOD>` | Which file to wire: `ssh-config` (`~/.ssh/config` `IdentityAgent`) or `shell-rc` (`SSH_AUTH_SOCK` export). Omit to choose interactively |
| `--undo` | Remove the managed block instead of adding it |

### `secreq ssh add`

```
secreq ssh add [OPTIONS] <NAME>
```

Add (or overwrite) an SSH identity in `config.toml`. The agent serves this identity once the daemon is running. The public key is stored inline; the private key is a `secret://provider/locator` reference resolved only at sign time. Omit `--public-key`/`--private-key` to resolve them interactively (with 1Password `op` discovery when on PATH). Pass both for a fully non-interactive run

| Argument | Meaning |
| --- | --- |
| `<NAME>` | The identity name (the key under the `ssh` block), e.g. `github` |

| Flag | Meaning |
| --- | --- |
| `--public-key <PATH-OR-LITERAL>` | The OpenSSH public key: a path to a `.pub` file, or the literal `ssh-… / ecdsa-… / sk-…` line. Prompted for if omitted |
| `--private-key <secret://…>` | The private key reference, `secret://provider/locator`. Prompted for (with `op` discovery) if omitted |
| `--reason <REASON>` | Reason shown in the consent prompt when this identity signs |
| `--force` | Overwrite an existing identity of the same name |

### `secreq ssh validate`

```
secreq ssh validate [<NAME>]
```

Prove the agent can sign with a configured SSH identity. Connects to the agent socket, lists identities, then asks the agent to sign a fixed test message with the key and verifies the returned signature against its public half, exercising the real consent → resolve → sign path. With no `<name>`, validates every configured identity. Signing is a real sign, so it may prompt for consent (and a biometric). Exits 0 only if every validated identity verifies

| Argument | Meaning |
| --- | --- |
| `<NAME>` | The identity name to validate (the key under the `ssh` block). Omit to validate every configured identity |

## `secreq agent`

```
secreq agent <SUBCOMMAND>
```

Manage scoped secret agent sockets: the host-side end of serving `secret://` refs to a guest VM instead of copying tokens into it

### `secreq agent open`

```
secreq agent open [OPTIONS]
```

Open a scoped, ephemeral socket that resolves `secret://` refs for a guest, and serve it until interrupted.

The scope name and the allowlist are declared **here, by you, at open time**, and are immutable for the socket's life. A ref outside the allowlist is denied without a prompt (and audited), so a compromised guest can neither train you to click through nor enumerate your vault one prompt at a time. Every allowed request prompts for consent, showing the scope as the principal: a guest has no host process tree, so there is no caller chain to show.

The resolved socket path is printed to stdout on its own line, so the caller can read it back rather than reconstruct it.

Forward the socket into a VM the way `ssh -A` forwards an agent:

```sh
secreq agent open --scope my-vm --allow secret://op/Dev/gh/token \
  --sock "$HOME/.secreq/run/my-vm.sock" &
ssh -R /run/secreq.sock:"$HOME/.secreq/run/my-vm.sock" my-vm
```

| Flag | Meaning |
| --- | --- |
| `--scope <NAME>` | The scope name shown in the consent prompt as the principal, typically the sandbox / VM name |
| `--allow <secret://…>…` | A `secret://provider/locator` ref this socket may resolve. Repeatable; at least one is required. Matched exactly: there is no prefix or wildcard form, by design |
| `--sock <PATH>` | Where to bind the socket. Must not already exist. Defaults to `scope-<name>.sock` in secreq's socket dir (`$XDG_RUNTIME_DIR/secreq`, else `<$SECREQ_HOME>/run`), beside the consent and SSH-agent sockets. Pass this to bind elsewhere, e.g. at a path you are about to `ssh -R` into a guest. Pick a directory only you can write. The socket is owner-only from the moment it exists, but in a shared one like `/tmp` anyone can plant a file at the path first and break the bind. |

## `secreq check`

```
secreq check
```

Validate the config

## `secreq doctor`

```
secreq doctor
```

`check` plus confirm every used provider's CLI is installed

## `secreq edit`

```
secreq edit
```

Open the config in `$EDITOR`

## `secreq migrate`

```
secreq migrate <SUBCOMMAND>
```

Inspect and roll back config migrations.

secreq migrates its own config on first run after an upgrade, taking a snapshot beforehand. This is how you get back to one.

### `secreq migrate restore`

```
secreq migrate restore <LEVEL>
```

Restore the config snapshot taken before migration <LEVEL>.

Use this when a downgraded secreq refuses to run because your config was migrated by a newer build. Lossy: anything added since that snapshot is discarded. The diff is shown and confirmed first, and your current config is saved alongside the snapshots before anything is overwritten.

| Argument | Meaning |
| --- | --- |
| `<LEVEL>` | Migration level to go back to (the snapshot is the config as it stood *before* migration LEVEL+1 ran) |

## `secreq daemon`

```
secreq daemon [OPTIONS] <SUBCOMMAND>
```

Run or manage the consent daemon. Bare `secreq daemon` ensures a daemon is running in the background (spawning one if needed) and then tails its log until you Ctrl-C, which is handy for watching the consent flow live. Use `--fg` to run the daemon in the foreground in this process instead (the form auto-spawned by wraps). `secreq daemon stop` tells a running daemon to exit, which also clears every remembered approval (the cache is in-memory only by design). `secreq daemon status` reports whether one is running. `secreq daemon log-path` prints the log file path

| Flag | Meaning |
| --- | --- |
| `--fg` | Run the daemon in the foreground in this process instead of starting a background daemon and tailing its log |

### `secreq daemon stop`

```
secreq daemon stop [OPTIONS]
```

Stop the running daemon. Clears the in-memory approvals cache; the next wrap invocation auto-spawns a fresh daemon

| Flag | Meaning |
| --- | --- |
| `-f, --force` | Skip the graceful protocol and SIGKILL the daemon outright. Use when the daemon is unresponsive (wedged UI, hung socket thread). Also removes the pidfile + socket, which the killed process can no longer clean up itself |

### `secreq daemon status`

```
secreq daemon status
```

Report whether a daemon is running, without spawning one. Prints the pid, the running build (flagging a stale daemon whose build differs from this CLI's), and the socket + log paths. Exits 0 when a daemon is running and 3 when none is, so scripts can branch on it

### `secreq daemon log-path`

```
secreq daemon log-path
```

Print the path of the daemon's persistent log file and exit. Does not start a daemon

### `secreq daemon install`

```
secreq daemon install [OPTIONS]
```

Install a per-user login service that runs the daemon at login and keeps it alive (launchd LaunchAgent on macOS, systemd `--user` unit on Linux). This is what keeps the SSH agent socket live for incoming connections. `--undo` unloads and removes the service

| Flag | Meaning |
| --- | --- |
| `--undo` | Unload and remove the login service instead of installing it |

## `secreq pending`

```
secreq pending
```

Open the consent daemon's pending-requests window. Auto-spawns the daemon if it isn't running

## `secreq view`

```
secreq view
```

Also spelled `secreq ui`.

Open the manager window: the persistent surface holding your auto-rules and the audit log. Lands on Audit; a segmented control switches to Rules. It never holds a pending decision (that is the prompt window's job, `secreq pending`), so browsing history never blocks a waiting request. Auto-spawns the daemon if it isn't running

## `secreq rules`

```
secreq rules <SUBCOMMAND>
```

Manage auto-approve / auto-deny rules. Declarative rules are created from the manager window's Rules view (or by hand-editing the rules file); compiled wasm rule modules are registered here with `add-wasm`. The CLI surface covers the headless management path: list, inspect, enable/disable, delete, add-wasm

### `secreq rules list`

```
secreq rules list
```

One-line listing of every rule with its decide direction and enabled state. Default action for `secreq rules`

### `secreq rules stats`

```
secreq rules stats [OPTIONS]
```

Validate the installed ruleset and replay it over historical audit asks using the same evaluator and wasm host as live requests

| Flag | Meaning |
| --- | --- |
| `--since <DATE>` | Include rows at or after this UTC date (`YYYY-MM-DD`) or Unix timestamp |
| `--wrap <WRAP>` | Replay only rows for this exact wrap |
| `--top <TOP>` | Maximum prompt-shape rows in each ranked breakdown |
| `--audit <PATH>` | Read this audit file instead of `~/.secreq/audit.log` |
| `--json` | Emit the stable machine-readable report schema |
| `--verify` | Check eligible historical auto decisions for evaluator drift. Also exits non-zero for refused modules/patterns, invalid live scope, malformed audit records, or runtime wasm failures. Ordinary uncovered prompts are not failures |

### `secreq rules show`

```
secreq rules show <TARGET>
```

Show one rule in full (every match field, trained_secrets, deny_message, created_at). `target` matches by id, falling back to exact name

| Argument | Meaning |
| --- | --- |
| `<TARGET>` | The rule's id, or its exact name |

### `secreq rules enable`

```
secreq rules enable <TARGET>
```

Set `enabled = true` on a rule

| Argument | Meaning |
| --- | --- |
| `<TARGET>` | The rule's id, or its exact name |

### `secreq rules disable`

```
secreq rules disable <TARGET>
```

Set `enabled = false` on a rule. The rule stays in the file; re-enable later without re-typing

| Argument | Meaning |
| --- | --- |
| `<TARGET>` | The rule's id, or its exact name |

### `secreq rules rm`

```
secreq rules rm <TARGET>
```

Delete a rule by id or exact name. A wasm rule's stored module file goes with it

| Argument | Meaning |
| --- | --- |
| `<TARGET>` | The rule's id, or its exact name |

### `secreq rules new-wasm`

```
secreq rules new-wasm [OPTIONS] <DIR>
```

Scaffold a buildable wasm rule project into `<DIR>`: a `package.json` wired to the `secreq-rule` SDK, an `assembly/rule.ts` stub exporting `decide(ctx)`, an as-pect spec, and the test-runner config. `npm install && npm run build` produces the module `rules add-wasm` then registers

| Argument | Meaning |
| --- | --- |
| `<DIR>` | Directory to write the project into. Created if missing; an existing one must be empty |

| Flag | Meaning |
| --- | --- |
| `--name <NAME>` | npm package name for the project, also the suggested rule name. Folded to something npm accepts (lowercase, no spaces). Defaults to a slug of `<DIR>`'s last component |
| `--sdk <PATH>` | Path to the `secreq-rule` package (`packages/secreq-rule` in a secreq checkout), written into `package.json` as an absolute `file:` dependency. Auto-detected by walking up from this binary and the working directory; without one the manifest falls back to the registry, which does not carry the SDK yet |
| `--from <EXAMPLE>` | Seed `assembly/` from one of the SDK's worked examples (e.g. `npm-publish-guard`) instead of the empty stub |

### `secreq rules add-wasm`

```
secreq rules add-wasm [OPTIONS] <FILE>
```

Register a compiled wasm rule module (built with the `secreq-rule` SDK). The daemon vets the module in its sandbox, copies it into the canonical store under the secreq root, pins it by sha256, and persists the rule. A failed vetting registers nothing. The module decides approve/pass/deny per ask at evaluation time

| Argument | Meaning |
| --- | --- |
| `<FILE>` | Path to the compiled `.wasm` module |

| Flag | Meaning |
| --- | --- |
| `--name <NAME>` | Rule name shown in the UI and audit log. Defaults to the module's file stem |
| `--secret <NAME>…` | Env-var name the rule is allowed to decide (the trained-secrets guard). Repeatable. The rule never fires for an ask requesting any name outside this set |
| `--all-secrets` | Register with NO trained-secrets snapshot: the module will be consulted for every ask across every wrap. Dangerous; required explicitly when no --secret is given |

## `secreq x`

```
secreq x [--sq-OPTIONS] <WRAP> [ARGS...]
```

Run a wrapped binary through secreq: consent → inject secrets → exec the real binary with output masking. This is what the PATH shims call (`exec '<path to secreq>' x '<wrap>' "$@"` — the shim names secreq by absolute path so it cannot be hijacked by a `secreq` earlier on the caller's PATH). `x` owns no ordinary flags: everything after the wrap name is forwarded to the binary verbatim (so `<wrap> --help` reaches the binary, not secreq), and secreq's own options use the reserved `--sq-` prefix; `secreq x --sq-help` lists them. Parsed by hand in `run_x`, never by clap; this variant exists so `secreq --help` documents the verb

## `secreq run`

```
secreq run [OPTIONS] [<COMMAND>…]
```

`op run`, but for every secret store: resolve every `secret://provider/locator` reference found in the environment (the inherited environment plus any `--env-file`) through the consent daemon, then run the command with the resolved values injected and its output masked. Plain `NAME=value` entries pass through unchanged. Unlike `x`, no wrap entry is required: the references describe the secrets inline

| Argument | Meaning |
| --- | --- |
| `<COMMAND>…` | The command to run, followed by its arguments |

| Flag | Meaning |
| --- | --- |
| `--env-file <PATH>…` | Load `NAME=value` lines from this file, layered *under* the inherited environment (inherited wins on conflict). Values may be `secret://provider/locator` references or plaintext. Repeatable |
| `--prompt-unresolved` | For each `secret://` reference whose locator resolves to nothing, prompt for the value (masked, no echo) and write it, via the provider's `store` capability, to exactly where the locator points, so this and every later run resolves it normally. A reference whose provider is read-only (no `store` capability) fails with a clear error instead of being silently skipped. Without this flag an unresolved reference fails as before |

## `secreq read`

```
secreq read <REF>…
```

`op read`, but for every secret store: resolve one or more secret references and print their values as a JSON object. Each reference is `secret://provider/locator` or the bare `provider/locator` shorthand. Output is always a JSON object keyed by each ref exactly as typed, even for a single ref, so it pipes cleanly into `jq`. Resolution always goes through the consent daemon (every read is prompted and audited); there is no `--yes` bypass, by design

| Argument | Meaning |
| --- | --- |
| `<REF>…` | The references to resolve, e.g. `secret://op/Work/key` or `op/Work/key`. At least one is required |

## `secreq resolve`

```
secreq resolve [OPTIONS] [<REF>]
```

Ask the host's secreq for one secret, from inside a sandbox.

This is the guest end of a scoped agent socket (`secreq agent open` opens the host end). It dials the socket named by `$SECREQ_SOCK`, the same convention as `SSH_AUTH_SOCK`, so nothing is stored in the sandbox: each use is asked for, gated by consent on the host, and audited there. `$SECREQ_SOCK` is set for you inside a brain `--vm` sandbox.

The value goes to stdout and everything else to stderr, so it composes:

```sh
export GH_TOKEN="$(secreq resolve secret://op/Dev/gh/token)"
```

Exits 0 on a release, 3 when the host denies (reason on stderr, nothing on stdout), 1 on any error.

| Argument | Meaning |
| --- | --- |
| `<REF>` | The reference to resolve, e.g. `secret://op/Dev/gh/token` or the bare `op/Dev/gh/token`. It must be one the host declared with `--allow` when it opened this socket; anything else is denied without troubling the user for a decision |

| Flag | Meaning |
| --- | --- |
| `--list` | Print the ref names this socket may resolve, one per line, and exit. Free: listing never prompts and never releases a value |
