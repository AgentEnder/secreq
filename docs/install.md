# Installing secreq

`secreq` is a single self-contained binary. Pick whichever channel fits
your setup — all four install the same `secreq` executable; none of them
create any wraps or shims (that's `secreq init`, the [next step](#after-installing)).

| Channel | Best for | One-liner |
|---|---|---|
| [curl \| sh](#curl--sh) | Quick install on macOS/Linux | `curl -fsSL https://secreq.dev/install.sh \| sh` |
| [Homebrew](#homebrew) | macOS / Linuxbrew users | `brew install AgentEnder/secreq/secreq` |
| [`cargo install`](#cargo-install) | Rust developers | `cargo install secreq` |
| [Prebuilt binaries](#prebuilt-binaries) | Air-gapped / manual / CI | download + verify a release tarball |

secreq ships prebuilt binaries for four platforms:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

On any other platform, use [`cargo install`](#cargo-install), which builds
from source.

## curl | sh

```sh
curl -fsSL https://secreq.dev/install.sh | sh
```

The installer detects your OS and architecture, downloads the matching
release tarball, **verifies its SHA-256 against the release's `SHA256SUMS`
manifest**, and drops `secreq` into `~/.local/bin`. It refuses to install a
binary it can't verify.

Read it before you pipe it to a shell — it's
[`dist/install.sh`](../dist/install.sh) in this repo. Knobs (all optional):

| Env var | Effect | Default |
|---|---|---|
| `SECREQ_VERSION` | Install a specific tag, e.g. `v0.1.0` | latest release |
| `SECREQ_INSTALL_DIR` | Where to put the binary | `~/.local/bin` |
| `SECREQ_NO_VERIFY` | Skip checksum verification (not advised) | off |

```sh
# Pin a version and install system-wide:
curl -fsSL https://secreq.dev/install.sh | SECREQ_VERSION=v0.1.0 SECREQ_INSTALL_DIR=/usr/local/bin sh
```

If `~/.local/bin` isn't on your `PATH`, the installer tells you and prints the
`export PATH=…` line to add.

## Homebrew

```sh
brew install AgentEnder/secreq/secreq
```

That taps `AgentEnder/homebrew-secreq` and installs the formula, which pulls
the checksummed release binary for your architecture. Upgrades ride the normal
`brew upgrade` path:

```sh
brew upgrade secreq
```

## cargo install

```sh
cargo install secreq
```

Builds `secreq` from the [crates.io](https://crates.io/crates/secreq) release
and drops it in `~/.cargo/bin`. This is the portable path — it works on any
target Rust supports, including ones without a prebuilt binary. It needs a
recent stable Rust toolchain and the platform GUI libraries the consent window
links (`libwayland`, `libxkbcommon`, and the XCB dev packages on Linux; native
frameworks on macOS need nothing extra).

To build from a local checkout instead:

```sh
cargo install --path packages/secreq
# or: cargo build --release  →  target/release/secreq
```

## Prebuilt binaries

Every [GitHub Release](https://github.com/AgentEnder/secreq/releases) attaches a
tarball per platform, a `SHA256SUMS` manifest, and a cosign signature over that
manifest. To install manually:

```sh
VERSION=0.1.0
TARGET=aarch64-apple-darwin   # your platform triple (see the list above)
BASE=https://github.com/AgentEnder/secreq/releases/download/v$VERSION

curl -fsSLO "$BASE/secreq-$VERSION-$TARGET.tar.gz"
curl -fsSLO "$BASE/SHA256SUMS"

sha256sum -c SHA256SUMS 2>/dev/null | grep OK   # or: shasum -a 256 -c SHA256SUMS
tar xzf "secreq-$VERSION-$TARGET.tar.gz"
install "secreq-$VERSION-$TARGET/secreq" ~/.local/bin/secreq
```

`SHA256SUMS` is signed with [cosign](https://github.com/sigstore/cosign)
keyless. To verify the manifest's provenance before trusting it:

```sh
cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

## After installing

Confirm the binary runs and reports its version + build id:

```sh
secreq --version
```

Then do the one-time setup — this is what creates the shim directory secreq
routes wrapped commands through:

```sh
secreq init
```

From there, [getting-started](./getting-started.md) walks you through your
first wrap.
