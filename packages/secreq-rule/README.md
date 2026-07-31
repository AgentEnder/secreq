# secreq-rule

AssemblyScript helper for authoring **programmable secreq auto-rules**: you
write one function, compile it to a sandboxed WebAssembly module, and the
secreq daemon runs it before the consent prompt.

## Writing a rule

A rule is a single AssemblyScript file exporting `decide`:

```ts path=assembly/rule.ts
import { RuleCtx, Decision, approve, pass, deny } from 'secreq-rule';

export function decide(ctx: RuleCtx): Decision {
  if (ctx.wrap == 'gh' && ctx.joinedArgv.startsWith('gh repo delete')) {
    return deny('repo deletes are never auto-approved');
  }
  if (ctx.wrap == 'gh' && ctx.joinedArgv.startsWith('gh api --get ')) {
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
  decision JSON: `"approve"`, `"pass"`, `{"prompt": "reason"}`, or
  `{"deny": "reason"}`.

You never deal with this directly — `secreq-rule-build` generates the glue.

## Testing

AssemblyScript specs import builders and assertions from the test-only entry
point, leaving the deployed rule dependent only on `secreq-rule`:

```ts path=assembly/__tests__/rule.spec.ts
import {
  assertDecision,
  caller,
  expectApprove,
  expectDeny,
  expectPass,
  ruleCtx,
} from 'secreq-rule/testing/assembly';
import { decide } from '../rule';

const shell = [caller('zsh', '-zsh', '/bin/zsh')];
assertDecision(
  decide(ruleCtx('gh', 'gh api --get /user', '/work', shell, ['GITHUB_TOKEN'])),
  expectApprove(),
);
assertDecision(decide(ruleCtx('npm', 'npm test')), expectPass());
assertDecision(
  decide(ruleCtx('gh', 'gh repo delete acme/app')),
  expectDeny('repo deletes are never auto-approved'),
);
```

For the built artifact, `secreq-rule/testing` loads `.wasm`, writes the host's
real snake_case context JSON, calls the packed pointer/length ABI, and compares
table rows with all four decision shapes:

```js
const { runCases } = require('secreq-rule/testing');

runCases('./rule.wasm', [
  {
    name: 'approve',
    context: { wrap: 'gh', joinedArgv: 'gh api --get /user' },
    expected: 'approve',
  },
  { name: 'pass', context: { wrap: 'npm', joinedArgv: 'npm test' }, expected: 'pass' },
  {
    name: 'deny',
    context: { wrap: 'gh', joinedArgv: 'gh repo delete x' },
    expected: { deny: 'blocked' },
  },
]);
```

The runner mirrors the host's abort-only imports, fresh instance per case,
64 MiB memory cap, and 64 KiB decision cap. Node WebAssembly cannot meter fuel;
the daemon and `secreq rules stats --verify` remain authoritative for runaway
modules.

## Publishing (maintainers)

The package ships AssemblyScript **source** (`assembly/*.ts`, the root
`index.ts`) plus the plain-JS build wrapper (`bin/build.js`) — there is no
compile step, so publishing is just:

```sh
cd packages/secreq-rule
npm publish            # runs from a clean checkout; needs npm auth
```

The `files` allowlist in `package.json` pins exactly what ships
(`assembly/`, `bin/`, the two `testing/` entry points, `index.ts`,
`asconfig.json`; npm always adds
`package.json` + `README.md`). `tests/sdk_publish.rs` guards that the
allowlist still covers everything `secreq-rule-build` reaches for at
consume time, so a new imported file can't silently drop out of the
tarball. Verify the tarball contents before publishing with
`npm pack --dry-run`.
