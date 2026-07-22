#!/usr/bin/env bash
#
# secreq — one-command build + install.
#
# The internal stopgap for getting a coworker from `git clone` to a working
# `secreq` without hand-driving a raw cargo build. Two modes, auto-detected:
#
#   1. Source (default, run from a checkout): compiles `--release` and installs
#      the resulting binary onto PATH.
#   2. Prebuilt (run from an extracted release tarball): a `secreq` binary sits
#      next to this script, so we skip the build and install that binary.
#
# In both modes we then hand off to `secreq init`, which picks the shim
# directory and (with your y/N approval) wires it onto PATH. `init` needs a
# real terminal; when this script's stdin isn't a TTY (piped/CI) we skip it and
# print the one command to run yourself.
#
# Usage:
#   scripts/install.sh [--bin-dir DIR] [--prebuilt PATH] [--no-init]
#
# Options:
#   --bin-dir DIR    Where to install the `secreq` binary. Default: the first of
#                    $SECREQ_BIN_DIR or ~/.local/bin.
#   --prebuilt PATH  Install this already-built binary; skip the cargo build.
#                    (Same as $SECREQ_PREBUILT.)
#   --no-init        Install the binary only; don't run `secreq init`.
#   -h, --help       Show this help.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BIN_DIR="${SECREQ_BIN_DIR:-$HOME/.local/bin}"
PREBUILT="${SECREQ_PREBUILT:-}"
RUN_INIT=1

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }

usage() { sed -n '3,27p' "${BASH_SOURCE[0]}" | sed 's/^#\{1,\} \{0,1\}//;s/^#$//'; }

while [ $# -gt 0 ]; do
	case "$1" in
	--bin-dir)  BIN_DIR="${2:?--bin-dir needs a value}"; shift 2 ;;
	--bin-dir=*) BIN_DIR="${1#*=}"; shift ;;
	--prebuilt) PREBUILT="${2:?--prebuilt needs a value}"; shift 2 ;;
	--prebuilt=*) PREBUILT="${1#*=}"; shift ;;
	--no-init)  RUN_INIT=0; shift ;;
	-h|--help)  usage; exit 0 ;;
	*)          die "unknown argument: $1 (see --help)" ;;
	esac
done

# ---------------------------------------------------------------------------
# 1. Locate the binary to install: explicit --prebuilt, a bundled sibling
#    binary (tarball layout), or a fresh cargo build (source checkout).
# ---------------------------------------------------------------------------
SOURCE_BIN=""
if [ -n "$PREBUILT" ]; then
	[ -x "$PREBUILT" ] || die "--prebuilt $PREBUILT is not an executable file"
	SOURCE_BIN="$PREBUILT"
	info "Using prebuilt binary: $SOURCE_BIN"
elif [ -x "$SCRIPT_DIR/secreq" ]; then
	# Extracted release tarball: install.sh and the binary live side by side.
	SOURCE_BIN="$SCRIPT_DIR/secreq"
	info "Found bundled binary: $SOURCE_BIN"
elif [ -f "$SCRIPT_DIR/../Cargo.toml" ]; then
	REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
	command -v cargo >/dev/null 2>&1 || die "cargo not found on PATH — install Rust (https://rustup.rs) or run with a --prebuilt binary"
	info "Building release binary (cargo build --release)…"
	( cd "$REPO_ROOT" && cargo build --release )
	SOURCE_BIN="$REPO_ROOT/target/release/secreq"
	[ -x "$SOURCE_BIN" ] || die "build finished but $SOURCE_BIN is missing"
else
	die "no binary to install: not in a secreq checkout and no bundled/--prebuilt binary found"
fi

# ---------------------------------------------------------------------------
# 2. Install onto PATH.
# ---------------------------------------------------------------------------
mkdir -p "$BIN_DIR"
DEST="$BIN_DIR/secreq"
info "Installing → $DEST"
# cp then chmod rather than `install(1)`: BSD/macOS and GNU `install` differ on
# flags, but cp + chmod behave the same everywhere.
cp "$SOURCE_BIN" "$DEST"
chmod 0755 "$DEST"

# 3. Sanity-check the freshly installed binary actually runs.
VERSION="$("$DEST" --version 2>/dev/null || true)"
[ -n "$VERSION" ] || die "installed $DEST but \`$DEST --version\` failed to run"
info "Installed $VERSION"

# 4. Is the install dir on PATH? If not, `secreq` won't be found by name.
case ":$PATH:" in
	*":$BIN_DIR:"*) ON_PATH=1 ;;
	*)              ON_PATH=0 ;;
esac
if [ "$ON_PATH" -eq 0 ]; then
	warn "$BIN_DIR is not on your PATH. Add it, e.g.:"
	printf '    export PATH="%s:$PATH"\n' "$BIN_DIR" >&2
fi

# ---------------------------------------------------------------------------
# 5. First-time setup: shim dir + PATH wiring. `secreq init` is interactive
#    (needs a real terminal), so only run it when stdin is a TTY.
# ---------------------------------------------------------------------------
if [ "$RUN_INIT" -eq 0 ]; then
	info "Skipping \`secreq init\` (--no-init). Run it yourself to finish setup:"
	printf '    %s init\n' "$DEST"
elif [ -t 0 ]; then
	info "Running first-time setup (\`secreq init\`)…"
	"$DEST" init
else
	info "Binary installed. stdin isn't a terminal, so finish setup in your shell:"
	printf '    %s init\n' "$DEST"
fi

info "Done. \`secreq --version\` → $VERSION"
