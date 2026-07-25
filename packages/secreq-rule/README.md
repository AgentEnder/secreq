# secreq-rule

AssemblyScript helper for authoring **programmable secreq auto-rules**: you
write one function, compile it to a sandboxed WebAssembly module, and the
secreq daemon runs it before the consent prompt.

## Writing a rule

A rule is a single AssemblyScript file exporting `decide`:

```ts
import { RuleCtx, Decision, approve, pass, deny } from "secreq-rule";

export function decide(ctx: RuleCtx): Decision {
  if (ctx.wrap == "gh" && ctx.joinedArgv.startsWith("gh repo delete")) {
    return deny("repo deletes are never auto-approved");
  }
  if (ctx.wrap == "gh" && ctx.joinedArgv.startsWith("gh api --get ")) {
    return approve();
  }
  return pass(); // fall through to declarative rules / the prompt
}
```

`RuleCtx` mirrors the daemon's evaluation context (`EvalCtx` in
`src/rules.rs`): `wrap`, `joinedArgv`, `callers` (`{name, command}[]`,
nearest-first), `cwd`, and `secrets`.

## Compiling

```sh
npm install         # inside this package (pulls assemblyscript)
npx secreq-rule-build my-rule.ts -o my-rule.wasm
```

The build wrapper generates the wasm ABI entry around your `decide`,
compiles with AssemblyScript's `stub` runtime (no GC), and produces a core
wasm module whose only import is `env.abort`. Modules importing anything
else (WASI, clocks, fs, network) are rejected by the daemon at load time —
a rule can only inspect the ctx it is handed and return a decision.

## ABI (host ↔ module contract)

Kept in lock-step with `src/wasm_rules.rs`:

- module exports `memory`, `alloc(len: i32) -> usize`, and
  `decide(ptr: usize, len: i32) -> u64`;
- host JSON-encodes the ctx (UTF-8), copies it into `alloc(len)`, calls
  `decide`, and unpacks the returned `(ptr << 32) | len` to read UTF-8
  decision JSON: `"approve"`, `"pass"`, or `{"deny": "reason"}`.

You never deal with this directly — `secreq-rule-build` generates the glue.

## Publishing (maintainers)

The package ships AssemblyScript **source** (`assembly/*.ts`, the root
`index.ts`) plus the plain-JS build wrapper (`bin/build.js`) — there is no
compile step, so publishing is just:

```sh
cd packages/secreq-rule
npm publish            # runs from a clean checkout; needs npm auth
```

The `files` allowlist in `package.json` pins exactly what ships
(`assembly/`, `bin/`, `index.ts`, `asconfig.json`; npm always adds
`package.json` + `README.md`). `tests/sdk_publish.rs` guards that the
allowlist still covers everything `secreq-rule-build` reaches for at
consume time, so a new imported file can't silently drop out of the
tarball. Verify the tarball contents before publishing with
`npm pack --dry-run`.
