# Releasing secreq

secreq ships through four channels, all cut from one tagged release:

- **GitHub Release** — prebuilt, checksummed, cosign-signed binaries.
- **crates.io** — `cargo install secreq` (published by cargo-release).
- **Homebrew** — the `AgentEnder/homebrew-secreq` tap.
- **curl | sh** — [`dist/install.sh`](../dist/install.sh) pulls the GitHub
  Release asset for the caller's platform.

The flow has two halves:

1. **Local (cargo-release):** bump the version, roll the CHANGELOG, publish the
   crate to crates.io, tag.
2. **CI (`.github/workflows/release.yml`):** on the pushed tag, cross-compile,
   verify the stamped build id, checksum, sign, generate the Homebrew formula,
   and publish the GitHub Release.

You only ever run the local half by hand; pushing the tag does the rest.

## Prerequisites

- [`cargo-release`](https://github.com/crate-ci/cargo-release):
  `cargo install cargo-release`.
- Push access to the repository (the tag push triggers the release workflow).
- A crates.io token with publish rights for `secreq`: `cargo login` (or export
  `CARGO_REGISTRY_TOKEN`). `release.toml` sets `publish = true`, so
  cargo-release runs `cargo publish` as part of the release — without a token
  the `--execute` run fails at that step.

## Cut a release

1. Make sure `main` is green and every user-facing change since the last
   release is recorded under `## [Unreleased]` in `CHANGELOG.md`. The
   `tests/changelog.rs` guard fails CI if the released version has no section.

2. From a clean `main`, pick the SemVer level and dry-run first:

   ```sh
   cargo release minor --dry-run     # patch | minor | major, or an explicit x.y.z
   ```

   This shows the version bump, the CHANGELOG rewrite (the `## [Unreleased]`
   heading is rolled into a dated `## [x.y.z] - YYYY-MM-DD` section, per the
   `pre-release-replacements` in `release.toml`), the release commit, and the
   `vX.Y.Z` tag it would create.

3. Execute it:

   ```sh
   cargo release minor --execute
   ```

   `release.toml` sets `push = false`, so this commits and tags locally but
   does **not** push — a release is never an accidental side effect of a
   routine `git push`. It **does** publish the crate to crates.io (this is the
   irreversible step; a crates.io version can never be re-published), so make
   sure the dry-run looked right first.

4. Push the release commit and its tag:

   ```sh
   git push --follow-tags
   ```

   The tag push triggers `Release`.

## What the workflow does

Triggered by any `v*` tag (`.github/workflows/release.yml`):

- **Builds** `secreq` on a **native runner per target** — cross-compiling the
  eframe/wgpu wayland+x11 stack is painful, and native builds also let each job
  run its own binary:
  - `x86_64-unknown-linux-gnu` (ubuntu-latest)
  - `aarch64-unknown-linux-gnu` (ubuntu-24.04-arm)
  - `x86_64-apple-darwin` (macos-13)
  - `aarch64-apple-darwin` (macos-14)
- **Verifies the build id.** `build.rs` stamps `SECREQ_BUILD_ID` from the
  tagged commit; each job runs `secreq --version` and asserts the output names
  that commit's short sha and carries no `-dirty` marker (a clean-tree tagged
  build). See `cli.rs::LONG_VERSION`.
- **Checksums** every tarball into a single `SHA256SUMS` manifest.
- **Signs** `SHA256SUMS` with **cosign keyless** (Sigstore/GitHub OIDC — no
  stored key). Verify with:

  ```sh
  cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
    --certificate-identity-regexp '.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    SHA256SUMS
  ```

- **Generates the Homebrew formula.** `dist/homebrew/gen-formula.sh` fills the
  per-arch `sha256` fields from the just-built `SHA256SUMS` and the result is
  uploaded as the `secreq.rb` release asset (see [Homebrew](#homebrew-tap)).
- **Publishes** the GitHub Release, using the notes extracted from the matching
  `CHANGELOG.md` section, with all `secreq-<version>-<target>.tar.gz` tarballs,
  the `SHA256SUMS` manifest, its signature/certificate, and `secreq.rb`
  attached.

Each tarball contains the `secreq` binary plus `README.md`, `LICENSE`, and
`CHANGELOG.md`.

## crates.io

cargo-release publishes `secreq` to crates.io during the local `--execute`
step (`publish = true` in `release.toml`). The publish metadata lives in
`Cargo.toml`'s `[package]` table — `description`, `keywords`, `categories`,
`repository`, `homepage`, `readme`, and an `exclude` list that keeps the
contributor docs, the AssemblyScript SDK, and test fixtures out of the
uploaded tarball. `tests/dist_channels.rs` guards the crates.io constraints
(≤5 keywords, ≤20 chars each, required fields present) so a bad manifest fails
CI instead of `cargo publish`.

## Homebrew tap

The formula is generated, never hand-edited. `dist/homebrew/gen-formula.sh`
is the source of truth; the committed `dist/homebrew/secreq.rb` is its output
with all-zero `sha256` sentinels (there are no real digests until the binaries
exist). `tests/dist_channels.rs` fails if the committed formula drifts from the
crate version or the release target matrix, so **after a version bump,
regenerate it**:

```sh
bash dist/homebrew/gen-formula.sh --version "$(cargo pkgid | sed 's/.*#//')" \
  > dist/homebrew/secreq.rb
```

At release time the workflow re-runs the generator with the real `SHA256SUMS`
and uploads the filled-in `secreq.rb` as a release asset. The tap repo
(`AgentEnder/homebrew-secreq`, which backs `brew install
AgentEnder/secreq/secreq`) tracks that asset — copy the released `secreq.rb`
into the tap's `Formula/secreq.rb`, or point the tap's updater at the release
asset URL.

## Re-running a release

If a publish step fails after some assets uploaded, re-run via
**Actions → Release → Run workflow** with the existing tag as input. The
publish job upserts the Release and re-uploads assets with `--clobber`.

## Verifying a downloaded artifact

```sh
tar xzf secreq-<version>-<target>.tar.gz
sha256sum -c SHA256SUMS            # or: shasum -a 256 -c SHA256SUMS
./secreq-<version>-<target>/secreq --version   # reports the build id
```
