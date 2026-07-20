# secreq

> **1Password Shell Plugins, but generic.** Wrap the CLIs you use every
> day (`gh`, `aws`, `kubectl`, `psql`, …) so each invocation gets its
> credentials from your secret store of choice — 1Password, macOS
> Keychain, `pass`, anything with a CLI — with a provenance-aware
> consent prompt before any release, and output masking on
> stdout/stderr.

`secreq` is a **per-binary** wrap tool, scoped to your user account. For
*project-level* secrets management (typed `.env` schemas, framework
integrations, type-safe access) see [varlock](https://varlock.dev/) —
the two tools coexist; they solve different problems.

## Install

```sh
cargo install --path .
# or: cargo build --release  →  target/release/secreq
```

## Use

```sh
secreq init                                          # one-time setup
secreq wrap gh --env GITHUB_TOKEN=secret://op/Personal/GitHub/credential
secreq wrap aws \
  --env AWS_ACCESS_KEY_ID=secret://op/Work/AWS/access_key_id \
  --env AWS_SECRET_ACCESS_KEY=secret://op/Work/AWS/secret_access_key

gh repo list      # invokes secreq via PATH shim → consent → real gh
aws s3 ls         # same; one biometric for both keys (retrieve_batch)
```

For an *arbitrary* command (no wrap entry), `secreq run` is `op run` for
every store — it resolves `secret://` refs found in the environment (and
in any `--env-file`), then execs your command with the values injected
and masked:

```sh
# .env holds refs, not secrets — safe to commit:
#   DATABASE_URL=secret://op/Work/Postgres/url
#   STRIPE_KEY=secret://keychain/stripe-live
secreq run --env-file .env -- ./deploy.sh
```

Concurrent `secreq run` invocations in one process tree share a single
consent prompt: the daemon unions their secret requests into one card,
you approve once, and each command receives only its own secrets.

| Command | Purpose |
|---|---|
| `secreq init` | First-time setup: pick a shim dir and (optionally) wire it into PATH. |
| `secreq wrap <bin>` | Add a wrap entry + install the PATH shim. |
| `secreq unwrap <bin>` | Remove the wrap entry + delete the shim. |
| `secreq wraps` | List configured wraps (names only — no values). |
| `secreq check` / `doctor` | Validate config / verify provider CLIs. |
| `secreq edit` | Open the config in `$EDITOR`. |
| `secreq x <bin> [args…]` | Wrap-and-run path. The shim invokes this. |
| `secreq run [--env-file F]… -- <cmd>` | `op run`, but for every store: resolve ambient `secret://` refs, then exec `<cmd>`. |

Built-in providers: `op` (with `retrieve_batch` — one biometric per
multi-secret invocation), `keychain` (macOS), `lastpass`, `pass` (Unix).

## Why

- **Multi-provider, in one config.** Mix `op` + Keychain + `pass`
  freely. The 1Password Shell Plugin is 1Password-only; aws-vault is
  AWS-only; envchain is Keychain-only — `secreq` covers the union.
- **Provenance-aware consent.** Before any provider call, you see *what
  is asking* (the parent process chain), with the chance to deny. Cache
  is scoped to the **direct parent process** (`(wrap_name, ppid,
  parent_start_time)`) — an approval for `gh` from your shell doesn't
  extend to `npm` postinstall hooks. pid recycling can't sneak past it.
- **PATH shim, not shell alias.** Every `execvp("gh", …)` goes through
  us, including subprocesses of `npm` / `make` / `cargo` / IDE tooling.
  Aliases would miss those.
- **Multi-provider output masking.** Any value resolved through any
  provider gets redacted on the wrapped binary's stdout/stderr. `--sq-raw`
  opts out for `pbcopy`-style flows.
- **Provenance-aware SSH agent.** Point `SSH_AUTH_SOCK` at secreq and each
  key signature is gated by the same consent prompt — you see who's asking
  before `git push` signs. The private key is resolved from your provider,
  used in-process, and zeroized (a key-custody downgrade vs. 1Password's
  sealed agent — see [`docs/ssh-agent.md`](./docs/ssh-agent.md)).

## Documentation

End-user docs live in [`docs/`](./docs/):

| Reading | For |
|---|---|
| [`docs/getting-started.md`](./docs/getting-started.md) | First-time walkthrough: install → init → first wrap → first run |
| [`docs/overview.md`](./docs/overview.md) | What `secreq` is + mental model |
| [`docs/cli.md`](./docs/cli.md) | Every subcommand, every flag, the wrap-and-run flow |
| [`docs/wraps.md`](./docs/wraps.md) | Authoring `wraps.json5` |
| [`docs/providers.md`](./docs/providers.md) | Provider model + built-ins |
| [`docs/ssh-agent.md`](./docs/ssh-agent.md) | The provenance-aware SSH agent: config, setup, the key-custody tradeoff |
| [`docs/consent-window.md`](./docs/consent-window.md) | The daemon UI: pending tree, audit log, audit JSONL format |
| [`docs/wraps.schema.json`](./docs/wraps.schema.json) | JSON Schema (point your editor at it) |

Contributor docs (module map, internals, AI-agent primer, historical
design) live in [`dev-docs/`](./dev-docs/).

## Development

```sh
cargo test                                                       # unit + e2e
cargo clippy --all-targets -- -D warnings                        # zero warnings
cargo fmt                                                        # format
cargo run --example gen-schema > docs/wraps.schema.json          # regen JSON schema
```
