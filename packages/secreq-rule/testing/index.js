'use strict';

const fs = require('node:fs');

// Kept as decimal literals so the Rust publish guard can pin these values to
// the host ABI constants across the language boundary.
const MAX_GUEST_MEMORY_BYTES = 67108864;
const MAX_DECISION_BYTES = 65536;

function rejectUnknownKeys(value, allowed, label) {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length) {
    throw new TypeError(`${label} has unknown key(s): ${unknown.join(', ')}`);
  }
}

/** Normalize an author-friendly JS context to the host's real snake_case JSON. */
function contextJson(context) {
  if (!context || typeof context !== 'object' || Array.isArray(context)) {
    throw new TypeError('rule context must be an object');
  }
  rejectUnknownKeys(context, ['wrap', 'joinedArgv', 'callers', 'cwd', 'subjects'], 'rule context');
  return {
    wrap: context.wrap ?? '',
    joined_argv: context.joinedArgv ?? '',
    callers: (context.callers ?? []).map((caller) => {
      rejectUnknownKeys(caller, ['name', 'command', 'exe'], 'caller');
      const value = {
        name: caller.name ?? '',
        command: caller.command ?? '',
      };
      if (caller.exe) value.exe = caller.exe;
      return value;
    }),
    cwd: context.cwd ?? '',
    secrets: context.subjects ?? [],
  };
}

function moduleBytes(source) {
  if (typeof source === 'string' || source instanceof URL) return fs.readFileSync(source);
  if (source instanceof Uint8Array || source instanceof ArrayBuffer) return source;
  throw new TypeError('wasm source must be a path, URL, Uint8Array, or ArrayBuffer');
}

function compile(source) {
  const module = new WebAssembly.Module(moduleBytes(source));
  for (const imported of WebAssembly.Module.imports(module)) {
    if (imported.module !== 'env' || imported.name !== 'abort' || imported.kind !== 'function') {
      throw new Error(
        `rule imports ${imported.module}.${imported.name}; the host permits only env.abort`,
      );
    }
  }
  const exported = new Map(WebAssembly.Module.exports(module).map((value) => [value.name, value]));
  for (const [name, kind] of [
    ['memory', 'memory'],
    ['alloc', 'function'],
    ['decide', 'function'],
  ]) {
    if (exported.get(name)?.kind !== kind) {
      throw new Error(`rule does not export ${name} as a ${kind}`);
    }
  }
  return module;
}

function instantiate(module) {
  const instance = new WebAssembly.Instance(module, {
    env: {
      abort() {
        throw new Error('rule called abort()');
      },
    },
  });
  if (instance.exports.memory.buffer.byteLength > MAX_GUEST_MEMORY_BYTES) {
    throw new Error('rule memory exceeds the host 64 MiB limit');
  }
  return instance;
}

function decodeDecision(value) {
  if (value === 'approve' || value === 'pass') return value;
  if (value && typeof value === 'object') {
    if (typeof value.deny === 'string' && Object.keys(value).length === 1) {
      return { deny: value.deny };
    }
    if (typeof value.prompt === 'string' && Object.keys(value).length === 1) {
      return { prompt: value.prompt };
    }
  }
  throw new Error(`unrecognized decision JSON: ${JSON.stringify(value)}`);
}

function sameDecision(actual, expected) {
  if (actual === expected) return true;
  if (!actual || !expected || typeof actual !== 'object' || typeof expected !== 'object') {
    return false;
  }
  return actual.deny === expected.deny && actual.prompt === expected.prompt;
}

/** Compile once and return a runner that creates one fresh instance per case. */
function loadRule(source) {
  const module = compile(source);
  return {
    run(context) {
      const instance = instantiate(module);
      const { alloc, decide, memory } = instance.exports;
      const input = Buffer.from(JSON.stringify(contextJson(context)), 'utf8');
      let inputPointer;
      try {
        inputPointer = alloc(input.length);
      } catch (error) {
        throw new Error('rule alloc must have signature alloc(i32) -> i32', { cause: error });
      }
      if (!Number.isInteger(inputPointer) || inputPointer < 0) {
        throw new Error(`rule alloc returned invalid pointer ${inputPointer}`);
      }
      if (memory.buffer.byteLength > MAX_GUEST_MEMORY_BYTES) {
        throw new Error('rule memory grew beyond the host 64 MiB limit');
      }
      new Uint8Array(memory.buffer).set(input, inputPointer);
      let rawDecision;
      try {
        rawDecision = decide(inputPointer, input.length);
      } catch (error) {
        throw new Error(`rule decide failed: ${error.message}`, { cause: error });
      }
      if (typeof rawDecision !== 'bigint') {
        throw new Error('rule decide must have signature decide(i32, i32) -> i64');
      }
      const packed = BigInt.asUintN(64, rawDecision);
      const outputPointer = Number(packed >> 32n);
      const outputLength = Number(packed & 0xffffffffn);
      if (outputLength > MAX_DECISION_BYTES) {
        throw new Error(`rule returned oversized decision (${outputLength} bytes)`);
      }
      if (memory.buffer.byteLength > MAX_GUEST_MEMORY_BYTES) {
        throw new Error('rule memory grew beyond the host 64 MiB limit');
      }
      if (outputPointer + outputLength > memory.buffer.byteLength) {
        throw new Error('rule returned an out-of-bounds decision pointer');
      }
      const bytes = new Uint8Array(memory.buffer, outputPointer, outputLength);
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      let decoded;
      try {
        decoded = JSON.parse(text);
      } catch (error) {
        throw new Error(`rule returned malformed decision JSON ${JSON.stringify(text)}`, {
          cause: error,
        });
      }
      return decodeDecision(decoded);
    },
  };
}

function runRule(source, context) {
  return loadRule(source).run(context);
}

/** Run `{name, context, expected}` cases and report every failed row together. */
function runCases(source, cases) {
  const runner = loadRule(source);
  const failures = [];
  const results = [];
  for (let index = 0; index < cases.length; index++) {
    const testCase = cases[index];
    const label = testCase.name || `case ${index + 1}`;
    try {
      const actual = runner.run(testCase.context);
      results.push(actual);
      if (!sameDecision(actual, testCase.expected)) {
        failures.push(
          new Error(
            `${label}: expected ${JSON.stringify(testCase.expected)}, got ${JSON.stringify(actual)}`,
          ),
        );
      }
    } catch (error) {
      failures.push(new Error(`${label}: ${error.message}`, { cause: error }));
    }
  }
  if (failures.length) {
    throw new AggregateError(failures, `${failures.length} compiled-rule case(s) failed`);
  }
  return results;
}

/**
 * Node's built-in WebAssembly engine cannot meter fuel or constrain growth of
 * an exported memory during a call. The runner checks memory before and after
 * calls, and mirrors the host's fresh-instance, abort-only-import, 64 KiB
 * decision, packed-pointer ABI posture. Import names/kinds are checked, but
 * JavaScript's WebAssembly reflection does not expose import signatures.
 */
const sandboxPosture = Object.freeze({
  freshInstancePerCase: true,
  imports: ['env.abort'],
  maxMemoryBytes: MAX_GUEST_MEMORY_BYTES,
  maxDecisionBytes: MAX_DECISION_BYTES,
  fuelMetered: false,
  memoryConstrainedDuringCall: false,
  importSignaturesChecked: false,
});

module.exports = { contextJson, loadRule, runRule, runCases, sandboxPosture };
