# secreq — user documentation

`secreq` wraps the CLIs you use every day — `gh`, `aws`, `kubectl`,
`psql` — so they get their credentials from your secret store of choice
(1Password, macOS Keychain, `pass`, …) with a provenance-aware consent
prompt before any release. **Per-binary wrap × multi-provider ×
consent ceremony** — the wedge nobody else covers.

## Start here

| If you're… | Read |
|---|---|
| **New to `secreq`** | [getting-started.md](./getting-started.md) — five-minute walkthrough from install to first wrap. |
| **Looking for the design rationale** | [overview.md](./overview.md) — what it is, what problem it solves, the mental model. |
| **Looking up a command or flag** | [cli.md](./cli.md) — full reference. |
| **Authoring `wraps.json5`** | [wraps.md](./wraps.md) + [wraps.schema.json](./wraps.schema.json) (point your editor at the schema for validation). |
| **Picking or defining a provider** | [providers.md](./providers.md). |
| **Using `secreq` as your SSH agent** | [ssh-agent.md](./ssh-agent.md) — onboarding (`ssh-add`, `daemon install`, `ssh-setup`), config, the key-custody tradeoff. |
| **Understanding what the daemon window shows** | [consent-window.md](./consent-window.md) — pending tree, audit log, viewer mode. |

## Documentation map

- **[getting-started.md](./getting-started.md)** — concrete first-run
  walkthrough.
- **[overview.md](./overview.md)** — design rationale, mental model,
  what `secreq` is and isn't.
- **[cli.md](./cli.md)** — every subcommand + the wrap-and-run path.
- **[wraps.md](./wraps.md)** — authoring `wraps.json5` (per-binary
  wraps, settings, refs, how cache scope works).
- **[providers.md](./providers.md)** — the provider model
  (retrieve / store / retrieve_batch), the built-ins, defining your own.
- **[ssh-agent.md](./ssh-agent.md)** — the provenance-aware SSH agent:
  the three-step onboarding (`ssh-add` to declare an identity, `daemon
  install` for the login service, `ssh-setup` to wire clients), the `ssh`
  config block, the per-anchor TTL, and the key-custody downgrade vs.
  1Password's sealed agent.
- **[consent-window.md](./consent-window.md)** — the daemon UI: the
  pending tree, approve-all-at-an-ancestor semantics, the audit log
  tab, audit log JSONL format.
- **[wraps.schema.json](./wraps.schema.json)** — JSON Schema for
  `wraps.json5`. Generated; don't edit by hand.

## Contributing

If you're hacking on `secreq` itself, contributor-facing docs are in
[`../dev-docs/`](../dev-docs/) — module map, internals, AI-agent
orientation primer.
