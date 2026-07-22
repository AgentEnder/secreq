#!/bin/sh
# secreq installer — download the right prebuilt binary for this machine from a
# GitHub Release, verify its checksum against the signed SHA256SUMS manifest,
# and drop `secreq` on your PATH.
#
#   curl -fsSL https://secreq.dev/install.sh | sh
#
# Knobs (all optional, via environment):
#   SECREQ_VERSION      tag to install, e.g. v0.1.0 (default: latest release)
#   SECREQ_INSTALL_DIR  where to put the binary   (default: ~/.local/bin)
#   SECREQ_REPO         GitHub owner/repo          (default: AgentEnder/secreq)
#   SECREQ_NO_VERIFY    set to 1 to skip checksum verification (not advised)
#
# This installs the *binary* only. secreq's per-command PATH shims are created
# later, per wrap, by `secreq init` / `secreq wrap` — the installer prints the
# next step rather than running that interactive, PATH-mutating setup for you.
#
# POSIX sh on purpose: it has to run under dash, busybox, and macOS's ancient
# /bin/sh, so no bashisms.
set -eu

REPO="${SECREQ_REPO:-AgentEnder/secreq}"
INSTALL_DIR="${SECREQ_INSTALL_DIR:-${HOME}/.local/bin}"
# Overridable so an on-prem mirror or a `file://` fixture can stand in for
# GitHub in tests and air-gapped installs.
BASE_URL="${SECREQ_BASE_URL:-https://github.com/${REPO}/releases}"
API_URL="${SECREQ_API_URL:-https://api.github.com/repos/${REPO}/releases}"

say() { printf '%s\n' "secreq-install: $*"; }
err() { printf '%s\n' "secreq-install: error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "required tool '$1' not found on PATH"; }

# One of curl or wget is enough; prefer curl.
if command -v curl >/dev/null 2>&1; then
    dl() { curl -fsSL "$1" -o "$2"; }
    dl_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    dl() { wget -qO "$2" "$1"; }
    dl_stdout() { wget -qO - "$1"; }
else
    err "need either curl or wget to download release assets"
fi

# Map `uname` output onto the release target triples produced by
# .github/workflows/release.yml. Keep these four in lockstep with that matrix
# (tests/dist_channels.rs guards the drift).
detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Linux)  os_part="unknown-linux-gnu" ;;
        Darwin) os_part="apple-darwin" ;;
        *) err "unsupported OS '$os' — secreq ships Linux and macOS binaries only (build from source: cargo install secreq)" ;;
    esac
    case "$arch" in
        x86_64 | amd64)          arch_part="x86_64" ;;
        arm64 | aarch64)         arch_part="aarch64" ;;
        *) err "unsupported architecture '$arch' — no prebuilt binary (build from source: cargo install secreq)" ;;
    esac
    printf '%s-%s' "$arch_part" "$os_part"
}

# Resolve the tag to install: honor a pinned SECREQ_VERSION, else ask the
# GitHub API for the latest release tag.
resolve_version() {
    if [ -n "${SECREQ_VERSION:-}" ]; then
        printf '%s' "$SECREQ_VERSION"
        return
    fi
    # Grep the tag_name out of the JSON; avoids a hard jq dependency.
    tag="$(dl_stdout "${API_URL}/latest" | sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$tag" ] || err "could not determine the latest release tag from ${API_URL}/latest (set SECREQ_VERSION to pin one)"
    printf '%s' "$tag"
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        err "need sha256sum or shasum to verify the download (set SECREQ_NO_VERIFY=1 to skip, not advised)"
    fi
}

main() {
    need uname
    need tar

    TARGET="$(detect_target)"
    VERSION="$(resolve_version)"
    # Accept both `0.1.0` and `v0.1.0` in SECREQ_VERSION; the asset name uses
    # the bare version, the download path uses the `v`-prefixed tag.
    TAG="$VERSION"
    case "$TAG" in v*) : ;; *) TAG="v$TAG" ;; esac
    VER="${TAG#v}"

    STAGE="secreq-${VER}-${TARGET}"
    TARBALL="${STAGE}.tar.gz"
    DL_BASE="${BASE_URL}/download/${TAG}"

    say "installing secreq ${TAG} (${TARGET}) into ${INSTALL_DIR}"

    TMP="$(mktemp -d "${TMPDIR:-/tmp}/secreq-install.XXXXXX")"
    trap 'rm -rf "$TMP"' EXIT INT TERM

    say "downloading ${TARBALL}"
    dl "${DL_BASE}/${TARBALL}" "${TMP}/${TARBALL}" \
        || err "download failed: ${DL_BASE}/${TARBALL} (is ${TAG} a published release for ${TARGET}?)"

    if [ "${SECREQ_NO_VERIFY:-0}" = "1" ]; then
        say "SECREQ_NO_VERIFY=1 — skipping checksum verification"
    else
        say "verifying checksum against SHA256SUMS"
        dl "${DL_BASE}/SHA256SUMS" "${TMP}/SHA256SUMS" \
            || err "could not fetch SHA256SUMS from ${DL_BASE} (set SECREQ_NO_VERIFY=1 to skip, not advised)"
        # SHA256SUMS lists every target as `<hash>  ./<stage>.tar.gz`; pull the
        # line for our tarball and compare against what we actually downloaded.
        want="$(sed -n "s|^\\([0-9a-f]\\{64\\}\\) .*${TARBALL}\$|\\1|p" "${TMP}/SHA256SUMS" | head -1)"
        [ -n "$want" ] || err "SHA256SUMS has no entry for ${TARBALL} — refusing to install an unverifiable binary"
        got="$(sha256_of "${TMP}/${TARBALL}")"
        [ "$want" = "$got" ] || err "checksum mismatch for ${TARBALL}: expected ${want}, got ${got}"
        say "checksum OK"
    fi

    say "unpacking"
    tar -xzf "${TMP}/${TARBALL}" -C "$TMP"
    [ -f "${TMP}/${STAGE}/secreq" ] || err "unpacked tarball has no ${STAGE}/secreq — asset layout changed?"

    mkdir -p "$INSTALL_DIR"
    # `install` isn't guaranteed on every minimal system; cp + chmod is.
    cp "${TMP}/${STAGE}/secreq" "${INSTALL_DIR}/secreq"
    chmod 0755 "${INSTALL_DIR}/secreq"

    say "installed ${INSTALL_DIR}/secreq"
    say "version: $("${INSTALL_DIR}/secreq" --version 2>/dev/null || echo '(could not run — see PATH note below)')"

    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) : ;;
        *) say "note: ${INSTALL_DIR} is not on your PATH — add it, e.g. export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
    esac

    printf '\n'
    say "next: run 'secreq init' to pick a shim directory and start wrapping commands."
}

main "$@"
