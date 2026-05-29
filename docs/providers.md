# Providers

A **provider** is a scheme that knows how to *retrieve* a secret value
(required) and *store* one (optional). Each provider is a declarative
description of CLI commands — there's no per-provider Rust code; everything
is templates.

## Capabilities

| Capability | Required? | Used by |
|---|---|---|
| `retrieve` | Yes | every wrap-and-run invocation; resolves each `env` entry |
| `store` | No | not exposed via the CLI in the current model — kept on the type so user-written tooling can drive it (and for forward-compat with future verbs) |
| `retrieve_batch` | No | `secreq <binary>` automatically, when a wrap's `env` references the same provider for ≥2 entries |

A provider with no `store` is *retrieve-only* — fine for read-only stores
like `op read` or `lpass show`. A provider with `retrieve_batch` declared
resolves many secrets in one invocation, which is the difference between
"one Touch ID prompt" and "N Touch ID prompts" for an `op`-backed wrap
with multiple env entries.

## Built-in providers

The following are baked into the binary; manifest-declared providers of the
same name override them.

| Scheme | Retrieve | Store | Batch | Available |
|---|---|---|---|---|
| `op` | `op read op://{locator}` | — (declare your own; 1Password items vary too much for a one-size template) | `op run --no-masking -- printenv` (single biometric for N refs) | all platforms |
| `keychain` | `security find-generic-password -w -s {locator}` | `security add-generic-password -U -s {service} -a {account}` (value via stdin) | — | macOS |
| `lastpass` | `lpass show --password {locator}` | — | — | Unix |
| `pass` | `pass show {locator}` | `pass insert -f -e {name}` (value via stdin) | — | Unix |

`secreq doctor` reports which of these have their CLIs installed on PATH.

## Defining your own

```json5
providers: {
  myvault: {
    retrieve: ["myvault", "get", "{locator}"],
    store: {
      command: ["myvault", "put", "{item}"],
      fields: {
        item: { required: true },
        tag:  { default: "v1" },
      },
      value: "stdin",        // recommended — keeps the value out of argv
      locator: "{item}",     // template for the retrieve-side locator
    },
    // Optional: a batched-retrieve path. Only declare this if your CLI has
    // a multi-resolve mode that resolves env-var references in one go.
    retrieve_batch: {
      command: ["myvault", "exec", "--", "printenv"],
      env_value: "myvault://{locator}",
    },
  },
}
```

### `retrieve`

An argv array. `{locator}` is substituted with the secret's locator before
the command runs. The command's **stdout** is the secret value (one
trailing newline stripped, matching the convention of `op read` and
`security find-generic-password`). Non-zero exit means "not found"; the
resolver applies the `default` if any, else errors.

### `store`

An object with four keys:

| Key | Meaning |
|---|---|
| `command` | Argv template. `{field}` placeholders are filled from caller-supplied `--field key=value` inputs. `{value}` (in argv mode) is the secret value. |
| `fields` | Schema for declared inputs (see below). |
| `value` | `"stdin"` (preferred) or any string template (typically `"{value}"`). |
| `locator` | Template that builds the **retrieve-locator** from the same field inputs so a subsequent `retrieve` finds the value just written. |

### `fields`

Each declared field is an object:

```json5
fields: {
  service: { required: true },
  account: { required: true },
  category: { default: "login" },     // implicit `optional: false`? no — see below
  tags:    { optional: true },        // sugar for required: false, no default
}
```

| Field property | Meaning |
|---|---|
| `required` | If true, the caller must supply this field (via `--field key=value`) OR it must have a `default`. |
| `optional` | Sugar for `required: false`. (Parity with the design doc.) |
| `default` | Value used when the caller doesn't supply this field. |

Fields the user supplies that aren't in the schema are **passed through**
verbatim — they're still substituted into the templates, so a custom
template can reference, e.g., `{key}` (which `secreq import` always
supplies as the env-var name being migrated).

### `value` — argv vs stdin

`"stdin"` (recommended): the value is piped on the child's stdin. Any
`{value}` placeholder in the argv stays unsubstituted (and should not be
present). Keeps the value out of argv where `ps eww` could see it.

`"{value}"` or anything else: the value replaces every `{value}`
substring in argv. Convenient, but exposes the secret to anyone who can
read the child's argv.

The built-in `keychain` and `pass` providers use stdin mode.

### `locator` template

After `store` runs, `secreq store` records a manifest entry
`NAME=secret://provider/<computed-locator>`, where `<computed-locator>` is
the `locator` template with the same field substitutions applied. Pick a
template such that `retrieve` against the computed locator returns the
value just written.

For example, keychain's built-in:
```json5
store: {
  command: ["security", "add-generic-password", "-U", "-s", "{service}", "-a", "{account}"],
  fields: { service: { required: true }, account: { required: true } },
  value: "stdin",
  locator: "{service}",
}
```
The retrieve template is `["security", "find-generic-password", "-w", "-s", "{locator}"]`. So storing with `service=myapp account=admin` writes via `security add-generic-password -s myapp -a admin`, and `retrieve` then runs `security find-generic-password -w -s myapp` — finding the value just written.

### `retrieve_batch` — many secrets in one invocation

Why this exists: each `op read op://…` call triggers a fresh biometric
prompt (no shared session across processes by default). For a run with 4
secrets that's 4 prompts — wretched UX. `op run -- printenv` resolves any
number of `op://` refs in one biometric session and emits them as env vars.
We generalize that pattern:

```json5
retrieve_batch: {
  command: ["op", "run", "--no-masking", "--", "printenv"],
  env_value: "op://{locator}",
}
```

**Protocol.** For each `(name, locator)` we want, the resolver sets the env
var `name` to `env_value` with `{locator}` substituted. Spawns `command`.
Parses its stdout as `KEY=VALUE` lines; lines whose key matches one of our
requested names yield the resolved value.

| Field | Meaning |
|---|---|
| `command` | argv to run. No placeholder substitution on the argv itself; the synthetic env is what the command sees. |
| `env_value` | Template for each synthetic env entry's *value* (`{locator}` is the only placeholder). The env-var **name** is the secret's own name. |

**When the resolver uses it.** Automatically, when **≥2 env entries in
one wrap share a provider** that declares `retrieve_batch`. A single
secret through batch buys nothing (and adds a wrapper process), so the
resolver falls through to per-secret `retrieve` for solo requests.

**Fallback.** If batching errors (CLI not installed, non-zero exit) or
returns *fewer* values than requested (multi-line values are the main way
this happens — see below), the resolver retries the missing secrets via
per-secret `retrieve` and emits a single `secreq: batch retrieve via …
failed; falling back to per-secret reads` line on stderr.

**Limitation: line-based output truncates multi-line values.** A PEM
certificate resolved through `op run -- printenv` would put literal
newlines in the output, breaking `KEY=VALUE` line parsing for that key
(the second line of the cert looks like a new entry that doesn't match a
requested name). The fallback path picks up these cases. If you're mixing
multi-line secrets with batchable ones on the same provider, the
multi-line ones cost an extra per-secret read.

**Disabling per-provider.** To opt out of the built-in op batch, redeclare
`op` in your manifest without `retrieve_batch`:

```json5
providers: {
  op: { retrieve: ["op", "read", "op://{locator}"] },
}
```

(Our provider merge replaces the whole provider entry by name — your
declaration shadows the built-in's fields wholesale.)

## Provider selection at runtime

| Where | How |
|---|---|
| Wrap `env` entry (`secret://op/foo`) | Embedded provider name. |
| `secreq wrap` interactive flow | Pick from `built-ins ∪ user-declared providers`. |

## Backward-compatible names

Early drafts of `secreq` used `read` and `write` for the
retrieve/store fields; the current parser accepts both `read`/`retrieve`
and `write`/`store` so older manifests keep working. Prefer the new
names in fresh files.

## Contributing a new built-in

If you want to land a new built-in provider in `secreq` itself, see
[`../dev-docs/architecture.md`](../dev-docs/architecture.md) for the
internals and edit `src/manifest.rs::builtin_providers()`. (Users who
just need a custom provider should declare it in their `wraps.json5`
`providers` block — no Rust changes needed.)

## Security notes

- **Sub-prompts** (Touch ID, `op` biometric, GPG passphrase) happen in the
  *invoking* process — `secreq` doesn't broker them. For nested runs, that
  means each layer's provider invocations sub-prompt in *that layer's*
  process, on the user's real terminal.
- **Stdin value delivery** is the default for built-ins because it keeps
  the secret out of argv. The argv mode is documented but should be avoided
  for new providers unless the underlying CLI has no stdin option.
- **`value: "stdin"` plus a `{value}` placeholder in argv is meaningless**
  — the placeholder stays as the literal `{value}` string. That's the
  signal that you've configured the wrong mode.
