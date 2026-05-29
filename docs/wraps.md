# Authoring `wraps.json5`

The config lives at `$XDG_CONFIG_HOME/secreq/wraps.json5` (or
`~/.config/secreq/wraps.json5`). For schema-driven validation in your
editor, point it at [`./wraps.schema.json`](./wraps.schema.json):

```json5
{
  $schema: "./wraps.schema.json",
  // …
}
```

## Top-level shape

```json5
{
  $shim_dir: "~/.secreq/shims",       // set by `secreq init`

  gh: {
    $reason: "GitHub API access",
    env: {
      GITHUB_TOKEN: "secret://op/Personal/GitHub Token/credential",
    },
  },

  aws: {
    $reason: "AWS deployments",
    env: {
      AWS_ACCESS_KEY_ID:     "secret://op/Work/AWS/access_key_id",
      AWS_SECRET_ACCESS_KEY: "secret://op/Work/AWS/secret_access_key",
    },
  },

  // Optional: override a built-in provider or define a custom one.
  // providers: { … },
}
```

JSON5: comments, unquoted keys, trailing commas, single-quoted strings.

### Top-level keys

| Key | Meaning |
|---|---|
| `$shim_dir` | Where `secreq wrap` drops PATH shims. Tilde-expansion (`~/`) honored. Set by `secreq init`. |
| `$schema` | Editor pointer; ignored at runtime. |
| `providers` | Provider scheme definitions. Optional — see [providers.md](./providers.md). |
| Any other identifier | A **wrap** (binary name). |

## Wraps

A wrap declares how to invoke one specific binary. The top-level key is the
binary name; the value is an object:

```json5
gh: {
  $reason: "GitHub API access",          // shown in the consent prompt
  env: {                                  // env vars to inject
    GITHUB_TOKEN: "secret://op/Personal/GitHub Token/credential",
  },
}
```

### Per-wrap settings

| Setting | Type | Meaning |
|---|---|---|
| `$reason` | string | Rationale shown in the consent prompt for context. |
| `env` | object (required) | Environment variables to inject. Each value is a `secret://provider/locator` reference (full ref only — bare locators aren't supported here, unlike the old manifest model). |

`env` must be non-empty: a wrap with zero env vars has nothing to wrap.

There is **no TTL setting**. Cache lifetime is bounded by the lifetime
of your parent process *and* the daemon process (see "How approval is
scoped" below). To clear every remembered approval at once, run
`secreq daemon stop` — the daemon's in-memory cache goes with it.

### Reference syntax

```
secret://<provider>/<locator>
```

- `<provider>` matches a provider scheme name (built-in or in `providers`).
- `<locator>` is everything after the first `/`.

See [providers.md](./providers.md) for the built-in providers and how to add
your own.

## How approval is scoped (the cache)

When you approve a wrap invocation, the decision is cached against the
**direct parent process** — specifically `(wrap_name, ppid, parent_start_time)`.

| Scenario | Cache outcome |
|---|---|
| You run `gh` from your zsh, approve, then run `gh` again from the *same* zsh | Cache hit → no prompt. |
| You open a new terminal and run `gh` there | Different ppid → prompt. |
| A `npm` postinstall hook invokes `gh` via the shim | Different ppid (`npm`, not your shell) → prompt. |
| pid recycled into a new process after the original shell died | Different `start_time` → prompt. |

The `start_time` component is what makes the cache pid-recycle safe.
`(ppid, start_time)` together identify *exactly* one process across its
lifetime; a new process inheriting the recycled pid number has a different
`start_time` and gets a fresh prompt.

**Cache lifetime is bounded by two things:** the parent process's
lifetime and the daemon's lifetime. Whichever ends first ends the
entry. When the shell that approved a wrap exits, no new process can
share both its pid *and* its start_time, so the entry becomes
unreachable. When the daemon exits (`secreq daemon stop`, idle timeout,
or `--force`), the whole in-memory cache goes with it.

There is no clock-based TTL and no on-disk file: nothing artificial
expires the entries between those two natural boundaries, and a daemon
restart is always the clean reset path.

## Examples

### Minimal: wrap `gh`

```json5
{
  $shim_dir: "~/.secreq/shims",
  gh: {
    env: { GITHUB_TOKEN: "secret://op/Personal/GitHub Token/credential" },
  },
}
```

### Multi-provider, mixed local + cloud

```json5
{
  $shim_dir: "~/.secreq/shims",

  gh: {
    env: { GITHUB_TOKEN: "secret://op/Personal/GitHub Token/credential" },
  },

  aws: {
    $reason: "AWS deployments",
    env: {
      AWS_ACCESS_KEY_ID:     "secret://op/Work/AWS/access_key_id",
      AWS_SECRET_ACCESS_KEY: "secret://op/Work/AWS/secret_access_key",
    },
  },

  kubectl: {
    env: { KUBECONFIG: "secret://keychain/work/kubeconfig" },
  },

  psql: {
    $reason: "Prod DB — `secreq daemon stop` clears the cache if you want a fresh prompt",
    env: { PGPASSWORD: "secret://op/Work/Postgres/prod/password" },
  },
}
```

## Editing the file

`secreq edit` opens it in `$EDITOR` (falls back to `vi`). After editing,
`secreq check` and `secreq doctor` validate.

`secreq wrap` and `secreq unwrap` edit the file for you; they don't preserve
hand-written comments through a write, so prefer them for adding entries
and use `secreq edit` for surgical edits you want to keep verbatim.

## What `secreq` ignores

- Top-level keys starting with `$` other than `$shim_dir` are reserved
  metadata (e.g. `$schema`, future `$version`).
- Per-wrap `$description` is accepted and currently ignored at runtime
  (parity with future tooling).
- Comments, trailing commas, and JSON5 syntax sugar are accepted on read
  but not preserved through a write.
