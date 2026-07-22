#!/usr/bin/env bash
#
# secreq — build a shareable release tarball for internal distribution.
#
# Compiles a release binary for the host platform and bundles it with
# `install.sh` and the getting-started docs into
# `dist/secreq-<version>-<os>-<arch>.tar.gz`. A teammate downloads the tarball,
# extracts it, and runs `./install.sh` — no Rust toolchain, no compilation.
#
# Cross-compilation is out of scope (it needs per-target linkers/SDKs): run
# this once on a macOS box and once on a Linux box to produce both artifacts.
#
# Usage:
#   scripts/package-release.sh [--out-dir DIR]
#
# Options:
#   --out-dir DIR   Where to write the tarball. Default: <repo>/dist.
#   -h, --help      Show this help.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$REPO_ROOT/dist"

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

usage() { sed -n '3,18p' "${BASH_SOURCE[0]}" | sed 's/^#\{1,\} \{0,1\}//;s/^#$//'; }

while [ $# -gt 0 ]; do
	case "$1" in
	--out-dir)   OUT_DIR="${2:?--out-dir needs a value}"; shift 2 ;;
	--out-dir=*) OUT_DIR="${1#*=}"; shift ;;
	-h|--help)   usage; exit 0 ;;
	*)           die "unknown argument: $1 (see --help)" ;;
	esac
done

command -v cargo >/dev/null 2>&1 || die "cargo not found on PATH — install Rust (https://rustup.rs)"

info "Building release binary…"
( cd "$REPO_ROOT" && cargo build --release )
BIN="$REPO_ROOT/target/release/secreq"
[ -x "$BIN" ] || die "expected release binary at $BIN"

# Version straight from the binary so the tarball name matches what installs.
VERSION="$("$BIN" --version | awk '{print $NF}')"
[ -n "$VERSION" ] || die "could not read version from $BIN --version"

# Normalise the host OS/arch into friendly tokens for the artifact name.
case "$(uname -s)" in
	Darwin) OS="macos" ;;
	Linux)  OS="linux" ;;
	*)      OS="$(uname -s | tr '[:upper:]' '[:lower:]')" ;;
esac
case "$(uname -m)" in
	arm64|aarch64)  ARCH="arm64" ;;
	x86_64|amd64)   ARCH="x86_64" ;;
	*)              ARCH="$(uname -m)" ;;
esac

NAME="secreq-${VERSION}-${OS}-${ARCH}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/$NAME"
mkdir -p "$PKG"

# Lay the binary next to install.sh so install.sh's "bundled sibling" mode
# picks it up and skips the build.
cp "$BIN" "$PKG/secreq"
chmod 0755 "$PKG/secreq"
cp "$SCRIPT_DIR/install.sh" "$PKG/install.sh"
chmod 0755 "$PKG/install.sh"
cp "$REPO_ROOT/README.md" "$PKG/README.md"
mkdir -p "$PKG/docs"
cp "$REPO_ROOT/docs/getting-started.md" "$PKG/docs/getting-started.md"

mkdir -p "$OUT_DIR"
TARBALL="$OUT_DIR/$NAME.tar.gz"
tar -czf "$TARBALL" -C "$STAGE" "$NAME"

info "Wrote $TARBALL"
info "Share it; the recipient runs:  tar xzf $NAME.tar.gz && cd $NAME && ./install.sh"
