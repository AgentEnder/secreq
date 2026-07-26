# Providers

A **provider** is a scheme that knows how to _retrieve_ a secret value
(required) and _store_ one (optional). Each is a declarative description of
CLI commands; there's no per-provider Rust code, only templates.

| Capability       | Required | Used by                                                                                |
| ---------------- | -------- | -------------------------------------------------------------------------------------- |
| `retrieve`       | Yes      | Every resolution: each `env` entry of a wrap, every ambient ref a `run` finds.         |
| `retrieve_batch` | No       | Automatically, when ≥2 entries in one wrap share a provider. N secrets, one biometric. |
| `store`          | No       | `secreq run --prompt-unresolved`, which writes a value to where the locator points.    |

A provider with no `store` is retrieve-only, which is fine for read-only
stores like `op read`. A `--prompt-unresolved` run against a read-only provider fails
with a clear error rather than silently skipping.

## Built-ins

Baked into the binary; a provider you declare with the same name overrides
it wholesale.

| Scheme     | Retrieve                                         | Store                                                                         | Batch                                                           | Available |
| ---------- | ------------------------------------------------ | ----------------------------------------------------------------------------- | --------------------------------------------------------------- | --------- |
| `op`       | `op read op://{locator}`                         | — (1Password items vary too much for one template; declare your own)          | `op run --no-masking -- printenv` (single biometric for N refs) | all       |
| `keychain` | `security find-generic-password -w -s {locator}` | `security add-generic-password -U -s {service} -a {account}` (value on stdin) | —                                                               | macOS     |
| `lastpass` | `lpass show --password {locator}`                | —                                                                             | —                                                               | Unix      |
| `pass`     | `pass show {locator}`                            | `pass insert -f -e {name}` (value on stdin)                                   | —                                                               | Unix      |

`secreq doctor` reports which of these have their CLIs installed.

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
      value: "stdin",        // keeps the value out of argv
      locator: "{item}",     // how to build the retrieve-side locator
    },
    retrieve_batch: {
      command: ["myvault", "exec", "--", "printenv"],
      env_value: "myvault://{locator}",
    },
  },
}
```

### `retrieve`

An argv array. `{locator}` is substituted before the command runs, and the
command's **stdout** is the value (one trailing newline stripped, matching
`op read` and `security find-generic-password`). A non-zero exit means "not
found": the resolver applies a `default` if one exists, else errors.

### `store`

| Key       | Meaning                                                                                                             |
| --------- | ------------------------------------------------------------------------------------------------------------------- |
| `command` | Argv template. `{field}` placeholders come from the declared fields; `{value}` is the secret, in argv mode.         |
| `fields`  | Schema for those inputs. Each is `{ required: true }`, `{ optional: true }`, or `{ default: "…" }`.                 |
| `value`   | `"stdin"` (preferred) or a template, typically `"{value}"`.                                                         |
| `locator` | Template building the **retrieve-locator** from the same fields, so a later `retrieve` finds what was just written. |

Fields the caller supplies that aren't in the schema are substituted
verbatim, so a custom template can reference its own placeholders.

**Prefer `value: "stdin"`.** It pipes the value on the child's stdin, keeping
it out of argv where `ps eww` could read it. Both built-ins that support
storing use it. Argv mode is documented but should be avoided unless the
underlying CLI has no stdin option. Combining `value: "stdin"` with a
`{value}` placeholder in argv is meaningless: the placeholder stays as the
literal string, which is the signal you've configured the wrong mode.

The `locator` template has to round-trip. keychain's built-in stores with
`-s {service} -a {account}` and sets `locator: "{service}"`, because its
retrieve template is `find-generic-password -w -s {locator}`, so storing
`service=myapp` writes something the retrieve side can find again.

### `retrieve_batch`: many secrets, one unlock

Each `op read` call triggers a fresh biometric prompt. For a wrap with four
secrets that's four prompts. `op run -- printenv` resolves any number of
refs in one session and emits them as env vars; this generalizes that
pattern.

```json5
retrieve_batch: {
  command: ["op", "run", "--no-masking", "--", "printenv"],
  env_value: "op://{locator}",
}
```

**How it works.** For each `(name, locator)` wanted, the resolver sets the
env var `name` to `env_value` with `{locator}` substituted, spawns
`command`, and parses stdout as `KEY=VALUE` lines. Keys matching a requested
name yield the value. There's no substitution on the argv itself; the
synthetic environment is what the command sees.

**When it fires.** Automatically, when ≥2 entries in one wrap share a
provider that declares it. A single secret through batch buys nothing and
adds a process, so solo requests fall through to per-secret `retrieve`.

**It falls back.** If batching errors or returns _fewer_ values than
requested, the resolver retries the missing ones per-secret and prints one
`batch retrieve … failed; falling back` line to stderr.

**Multi-line values are the main reason it returns fewer.** A PEM
certificate puts literal newlines in the output, so its second line looks
like a new `KEY=VALUE` entry that matches nothing. The fallback catches
these, at the cost of one extra read each.

To opt out of the built-in `op` batch, redeclare `op` without it. A
declaration replaces the whole built-in entry by name:

```json5
providers: {
  op: { retrieve: ["op", "read", "op://{locator}"] },
}
```

## Sub-prompts

Touch ID, the `op` biometric and GPG passphrases happen in the _invoking_
process; secreq doesn't broker them. For nested runs that means each
layer's provider invocations sub-prompt in that layer's process, on your
real terminal.

## Compatibility

Early drafts used `read` and `write` for the retrieve/store fields; the
parser still accepts both spellings. Prefer `retrieve`/`store` in new files.

## Contributing a built-in

To land a new built-in in secreq itself, see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md) and edit
`manifest.rs::builtin_providers()`. If you just need a custom provider for
yourself, declare it in your `wraps.json5`. No Rust changes needed.
