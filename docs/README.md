# secreq user documentation

`secreq` wraps the CLIs you use every day (`gh`, `aws`, `kubectl`, `psql`)
so they get their credentials from your secret store of choice
(1Password, macOS Keychain, `pass`, …) with a provenance-aware consent
prompt before any release.

**Per-binary wrap × multi-provider × consent ceremony.** Nobody else covers
all three.

| Page                                      | What it covers                                                     |
| ----------------------------------------- | ------------------------------------------------------------------ |
| [install](./install.md)                   | Every install channel, and how to verify a download.               |
| [getting-started](./getting-started.md)   | Install to first wrap, in five minutes.                            |
| [overview](./overview.md)                 | What it is, what it isn't, and the threat model.                   |
| [cli guide](./cli.md)                     | Why there are two run verbs, and the argv contract.                |
| [all commands](./cli-reference.md)        | Every command and flag. Generated from the CLI itself.             |
| [wraps](./wraps.md)                       | Authoring `config.toml`. Also where approval scoping is explained. |
| [providers](./providers.md)               | The built-in providers, and how to declare your own.               |
| [consent-window](./consent-window.md)     | Both windows, and the audit log format.                            |
| [link](./link.md)                         | Pairing and LAN approval, including the plain-HTTP tradeoff.       |
| [ssh-agent](./ssh-agent.md)               | Serving your SSH keys, and the key-custody tradeoff.               |
| [secret-agent](./secret-agent.md)         | Getting secrets into a VM without copying them in.                 |
| [wasm-rules](./wasm-rules.md)             | Rules that need real logic: author, test, compile, register.       |
| [platform-support](./platform-support.md) | The OS and arch matrix, and per-OS prerequisites.                  |
| [troubleshooting](./troubleshooting.md)   | The first-week traps, and how to get unstuck.                      |

New here? Read [getting-started](./getting-started.md).

Two files are generated and should not be hand-edited:
[`cli-reference.md`](./cli-reference.md) comes from the CLI definition, and
[`wraps.schema.json`](./wraps.schema.json) from the Rust types. Point your
editor at the schema for completion while authoring `config.toml`.

## Contributing

Hacking on `secreq` itself? Start with
[`../CONTRIBUTING.md`](../CONTRIBUTING.md), which covers the dev loop, how to
author wraps and rules, and how to submit a change.

Participation is governed by our
[Code of Conduct](../CODE_OF_CONDUCT.md). Found a security issue? Please
disclose it **privately**; see [`../SECURITY.md`](../SECURITY.md).
