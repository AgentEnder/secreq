// The wasm-level ABI glue between the secreq host and a rule module.
// Rule authors never touch this file — the `secreq-rule-build` wrapper
// generates an entry that wires the author's `decide(ctx)` through it.
//
// ABI (must stay in lock-step with `src/wasm_rules.rs` on the Rust side):
//   - export `alloc(len: i32) -> usize`: return a buffer the host writes
//     the UTF-8 ctx JSON into.
//   - export `decide(ptr: usize, len: i32) -> u64`: parse the ctx, run the
//     rule, return `(ptr << 32) | len` pointing at UTF-8 decision JSON.
//   - decision JSON: `"approve"` | `"pass"` | `{"deny": "reason"}`.
//
// Compiled with `--runtime stub` (bump allocator, no GC, nothing is ever
// freed), so buffers returned to the host stay valid until the instance is
// dropped — the host uses one instance per evaluation.

import { RuleCtx } from './ctx';
import { Decision, DecisionKind } from './decision';
import { parseRuleCtx, quoteJson } from './json';

/** Backing for the exported `alloc`: hand out raw heap bytes. */
export function allocBytes(len: i32): usize {
  return heap.alloc(len);
}

/** Decode the host-written UTF-8 ctx JSON and parse it into a `RuleCtx`. */
export function readCtx(ptr: usize, len: i32): RuleCtx {
  return parseRuleCtx(String.UTF8.decodeUnsafe(ptr, len));
}

/** Encode `d` as decision JSON in guest memory, packed as `(ptr<<32)|len`. */
export function encodeDecision(d: Decision): u64 {
  let json: string;
  if (d.kind == DecisionKind.Approve) {
    json = '"approve"';
  } else if (d.kind == DecisionKind.Pass) {
    json = '"pass"';
  } else {
    json = '{"deny":' + quoteJson(d.reason) + '}';
  }
  const buf = String.UTF8.encode(json);
  const ptr = changetype<usize>(buf);
  const len = buf.byteLength;
  return ((ptr as u64) << 32) | ((len as u64) & 0xffffffff);
}
