#!/usr/bin/env bash
# Recompile the checked-in .wasm fixtures from their .ts sources.
#
# `cargo test` never runs this — the compiled .wasm files are committed so
# the Rust tests stay hermetic (no node/npm at test time). Re-run it (and
# commit the resulting .wasm) whenever a fixture .ts or the secreq-rule SDK
# changes. Requires node + npm; network only for the first `npm install`.
#
# The .wat fixtures in this directory are NOT compiled here — tests parse
# them directly via the `wat` crate.
set -euo pipefail
cd "$(dirname "$0")"

SDK=../../../../secreq-rule
(cd "$SDK" && npm install --no-fund --no-audit)

BUILD="$SDK/bin/build.js"
node "$BUILD" always_pass.ts -o always_pass.wasm
node "$BUILD" approve_if.ts -o approve_if.wasm
node "$BUILD" deny_echo.ts -o deny_echo.wasm
node "$BUILD" aborts.ts -o aborts.wasm
node "$BUILD" spins.ts -o spins.wasm
node "$BUILD" --raw bad_decision.ts -o bad_decision.wasm

echo "rebuilt $(ls -1 ./*.wasm | wc -l | tr -d ' ') wasm fixtures"
