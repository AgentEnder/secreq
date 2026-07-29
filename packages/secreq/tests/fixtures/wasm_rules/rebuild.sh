#!/usr/bin/env bash
# Recompile the checked-in .wasm fixtures from their .ts sources.
#
# `cargo test` never runs this — the compiled .wasm files are committed so
# the Rust tests stay hermetic (no node/pnpm at test time). Re-run it (and
# commit the resulting .wasm) whenever a fixture .ts or the secreq-rule SDK
# changes. Requires node + pnpm; network only for the first install.
#
# The .wat fixtures in this directory are NOT compiled here — tests parse
# them directly via the `wat` crate.
set -euo pipefail
cd "$(dirname "$0")"

ROOT=../../../../..
SDK="$ROOT/packages/secreq-rule"

# The SDK is a pnpm workspace member, so `asc` — which bin/build.js resolves
# out of the SDK's own devDependencies — is installed from the workspace root.
# An `npm install` in the SDK directory would fight pnpm for that node_modules
# and leave a package-lock.json behind.
(cd "$ROOT" && pnpm install --filter secreq-rule)

BUILD="$SDK/bin/build.js"
node "$BUILD" always_pass.ts -o always_pass.wasm
node "$BUILD" approve_if.ts -o approve_if.wasm
node "$BUILD" deny_echo.ts -o deny_echo.wasm
node "$BUILD" aborts.ts -o aborts.wasm
node "$BUILD" spins.ts -o spins.wasm
node "$BUILD" prompts.ts -o prompts.wasm
node "$BUILD" --raw bad_decision.ts -o bad_decision.wasm

echo "rebuilt $(ls -1 ./*.wasm | wc -l | tr -d ' ') wasm fixtures"
