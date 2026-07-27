# secreq

A per-binary CLI wrapper that injects credentials from your secret store of
choice — 1Password Shell Plugins, but generic and multi-provider. `secreq run`
resolves the secrets a command needs at launch and hands them off without ever
writing them to disk.

This is the crate-level README that ships in the published `cargo install
secreq` tarball. For the full project overview — install channels, the wasm
rules SDK, architecture, and contributing — see the repository README and the
docs:

- Repository: <https://github.com/AgentEnder/secreq>
- Website & docs: <https://craigory.dev/secreq>

## Install

```sh
cargo install secreq
```

## License

MIT — see the `LICENSE` file at the repository root.
