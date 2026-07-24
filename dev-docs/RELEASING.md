# Releasing secreq

secreq ships as prebuilt, checksummed binaries attached to a GitHub Release.
The flow has two halves:

1. **Local (cargo-release):** bump the version, roll the CHANGELOG, tag.
2. **CI (`.github/workflows/release.yml`):** on the pushed tag, cross-compile,
   verify the stamped build id, checksum, sign, and publish the Release.

You only ever run the local half by hand; pushing the tag does the rest.

## Prerequisites

- [`cargo-release`](https://github.com/crate-ci/cargo-release):
  `cargo install cargo-release`.
- Push access to the repository (the tag push triggers the release workflow).

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
   routine `git push`.

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

- **Publishes** the GitHub Release, using the notes extracted from the matching
  `CHANGELOG.md` section, with all `secreq-<version>-<target>.tar.gz` tarballs,
  the `SHA256SUMS` manifest, and its signature/certificate attached.

Each tarball contains the `secreq` binary plus `README.md`, `LICENSE`, and
`CHANGELOG.md`.

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
