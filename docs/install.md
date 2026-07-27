# Installing secreq

`secreq` is a single self-contained binary. Every channel below installs the
same executable, and none of them create wraps or shims. That is
[`secreq init`](#after-installing).

| Channel                                 | Best for                     | One-liner                                                 |
| --------------------------------------- | ---------------------------- | --------------------------------------------------------- |
| [curl \| sh](#curl--sh)                 | Quick install on macOS/Linux | `curl -fsSL https://craigory.dev/secreq/install.sh \| sh` |
| [Homebrew](#homebrew)                   | macOS / Linuxbrew users      | `brew install AgentEnder/secreq/secreq`                   |
| [`cargo install`](#cargo-install)       | Rust developers, any target  | `cargo install secreq`                                    |
| [Prebuilt binaries](#prebuilt-binaries) | Air-gapped, manual, CI       | download + verify a release tarball                       |

Prebuilt binaries ship for `{x86_64,aarch64}-unknown-linux-gnu` and
`{x86_64,aarch64}-apple-darwin`. On any other platform use
[`cargo install`](#cargo-install), which builds from source. See
[platform-support](./platform-support.md) for what "supported" means per OS.

## curl | sh

```sh
curl -fsSL https://craigory.dev/secreq/install.sh | sh
```

The installer detects your OS and architecture, downloads the matching
release tarball, **verifies its SHA-256 against the release's `SHA256SUMS`
manifest**, and drops `secreq` into `~/.local/bin`. It refuses to install a
binary it can't verify.

Read it before piping it to a shell; it's [`dist/install.sh`](../dist/install.sh).
Knobs, all optional:

| Env var              | Effect                                   | Default        |
| -------------------- | ---------------------------------------- | -------------- |
| `SECREQ_VERSION`     | Install a specific tag, e.g. `v0.1.0`    | latest release |
| `SECREQ_INSTALL_DIR` | Where to put the binary                  | `~/.local/bin` |
| `SECREQ_NO_VERIFY`   | Skip checksum verification (not advised) | off            |

```sh
curl -fsSL https://craigory.dev/secreq/install.sh | SECREQ_VERSION=v0.1.0 SECREQ_INSTALL_DIR=/usr/local/bin sh
```

If the install directory isn't on your `PATH`, the installer says so and
prints the `export PATH=…` line to add.

## Homebrew

```sh
brew install AgentEnder/secreq/secreq
```

Taps `AgentEnder/homebrew-secreq` and installs the formula, which pulls the
checksummed release binary for your architecture. Upgrades ride the normal
`brew upgrade secreq` path.

## cargo install

```sh
cargo install secreq
```

Builds from the [crates.io](https://crates.io/crates/secreq) release into
`~/.cargo/bin`. This is the portable path: it works on any target Rust
supports, including ones with no prebuilt binary. It needs a recent stable
toolchain and the platform GUI libraries the consent window links: on Linux
`libwayland`, `libxkbcommon` and the XCB dev packages; on macOS the native
frameworks need nothing extra.

## From a checkout

One command from a fresh clone compiles the release binary, installs it onto
your `PATH`, and hands off to `secreq init`:

```sh
bash scripts/install.sh
```

The binary lands in `~/.local/bin` by default; override with `--bin-dir <dir>`
or `$SECREQ_BIN_DIR`. Pass `--no-init` to install the binary only. If stdin
isn't a terminal (piped, CI) it installs the binary and prints the
`secreq init` command for you to run yourself. To drive cargo directly
instead: `cargo install --path packages/secreq`.

> ⚠ A dev build run against your real home can corrupt `~/.secreq`. See
> [dev builds](./troubleshooting.md#dev-builds-can-corrupt-your-real-secreq)
> before you `cargo run` or `cargo test`.

## Prebuilt binaries

Every [GitHub Release](https://github.com/AgentEnder/secreq/releases)
attaches a tarball per platform, a `SHA256SUMS` manifest, and a cosign
signature over that manifest.

```sh
VERSION=0.1.0
TARGET=aarch64-apple-darwin   # your platform triple
BASE=https://github.com/AgentEnder/secreq/releases/download/v$VERSION

curl -fsSLO "$BASE/secreq-$VERSION-$TARGET.tar.gz"
curl -fsSLO "$BASE/SHA256SUMS"

sha256sum -c SHA256SUMS 2>/dev/null | grep OK   # or: shasum -a 256 -c SHA256SUMS
tar xzf "secreq-$VERSION-$TARGET.tar.gz"
install "secreq-$VERSION-$TARGET/secreq" ~/.local/bin/secreq
```

A downloaded tarball also carries its own `install.sh`, if you'd rather not
place the binary by hand.

`SHA256SUMS` is signed with [cosign](https://github.com/sigstore/cosign)
keyless, so you can verify its provenance before trusting it:

```sh
cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

## After installing

Confirm the binary runs and reports its version and build id:

```sh
secreq --version
```

Then do the one-time setup, which creates the shim directory secreq routes
wrapped commands through:

```sh
secreq init
```

From there, [getting-started](./getting-started.md) walks you through your
first wrap.
