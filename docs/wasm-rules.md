# Programmable rules (WebAssembly)

Auto-rules let the daemon answer recurring asks without prompting.
Most rules are **declarative** — a match clause (wrap × argv pattern ×
ancestor × cwd) plus a fixed approve/deny — created from the Rules tab
in `secreq view`. When a policy doesn't fit a match clause ("approve
`npm publish`, but only from my canonical checkouts, and never when an
AI agent is driving"), you can write the rule as **code**: a single
function, compiled to a sandboxed WebAssembly module, evaluated by the
daemon before the consent prompt.

```ts
import { RuleCtx, Decision, approve, pass, deny } from "secreq-rule";

export function decide(ctx: RuleCtx): Decision {
  if (ctx.wrap == "gh" && ctx.joinedArgv.startsWith("gh repo delete")) {
    return deny("repo deletes are never auto-approved");
  }
  return pass(); // no opinion — fall through to the prompt
}
```

## When to reach for a wasm rule

Prefer a declarative rule whenever one can express the policy — it's
auditable at a glance in `rules show`, editable in the UI, and can't
have bugs. Reach for a wasm rule when the decision needs logic a match
clause can't express: combinations ("this argv *unless* that caller"),
negations, computed conditions on several ctx fields at once, or a
reason string built from the ask itself. Declarative and wasm rules
evaluate together in one pass and compete under the same precedence
(see below), so you can freely mix them — including keeping protective
declarative denies alongside a programmable approve.

## The security model, in plain language

A rule module is untrusted code that participates in security
decisions, so the daemon constrains it structurally rather than by
convention:

- **The sandbox has no I/O.** A module gets no filesystem, network,
  environment, clock, or randomness — the only import the daemon
  provides is AssemblyScript's `abort` (which cleanly fails the
  evaluation). A module that imports anything else (WASI included) is
  rejected at registration time, with an error naming the offending
  import. The only thing a rule can do is read the ctx it is handed
  and return a decision.
- **The ctx carries secret *names*, never values.** A rule sees what an
  ask would release (`secrets`) — env-var names, or `ssh:<key_id>` for a
  key signing; no secret value ever enters the sandbox.
- **Deny wins.** If any enabled rule — declarative or wasm — denies,
  the ask is denied, no matter what any approve says. A wasm rule that
  returns approve or deny is treated as maximally specific among
  approves (it made a programmatic decision about this exact ask);
  ties break on the lexically smallest rule id.
- **The trained-secrets guard runs before your code.** Every rule
  carries the set of secret names it was registered for. An ask
  requesting any name outside that set skips the rule entirely — the
  module never even sees the ask, let alone decides it. An SSH sign
  declares `ssh:<key_id>`, so a rule that gates key signings is scoped
  with `--secret ssh:github` like any other name.
- **Errors fail to the prompt, never to an approve.** A module that
  traps, aborts, runs out of fuel (there's a fixed instruction
  budget, so an infinite loop can't hang the daemon), exceeds the
  64 MiB memory cap, or returns malformed output simply doesn't match:
  the ask falls through to the interactive prompt, and the failure is
  logged loudly in the daemon log.
- **Modules are pinned by content hash.** Registration records the
  module's SHA-256, and the daemon re-verifies it every time it loads
  the rules. A module that changed on disk is refused — the rule can
  never fire — and the refusal is visible in `rules list`, `rules
  show`, and the UI.

Each evaluation runs in a fresh instance, so no state survives from
one ask to the next.

## What your rule sees and returns

Your rule is one exported function:

```ts
export function decide(ctx: RuleCtx): Decision;
```

`RuleCtx` (from the `secreq-rule` package) mirrors the daemon's
evaluation context:

| Field | Type | Meaning |
|---|---|---|
| `wrap` | `string` | The wrap being asked for (e.g. `gh`, `npm`). |
| `joinedArgv` | `string` | Joined argv of the wrapped command (e.g. `gh api --get /repos/x`). |
| `callers` | `Caller[]` | Caller chain, **nearest-first**. Each entry has `name` (short process name, e.g. `zsh`, `Cursor`) and `command` (full joined command line). |
| `cwd` | `string` | Working directory of the requesting process. |
| `secrets` | `string[]` | What the ask would release, by name — env-var names for a wrap run, or the single identity `ssh:<key_id>` for an SSH sign. Names only, never values. |

The decision is built with three constructors:

- `approve()` — auto-approve the ask without prompting.
- `pass()` — no opinion; this rule does not match. Other rules and the
  interactive prompt still apply.
- `deny(reason)` — auto-deny; `reason` is shown to the user (the wrap
  client prints it to stderr, the consent window shows a toast).

On the wire this is JSON with snake_case field names
(`joined_argv`, `secrets`, …) and decisions encoded as
`"approve"`, `"pass"`, or `{"deny": "reason"}` — but the SDK's build
tool generates all of that glue; you only write `decide`. The exact
ABI is documented in `sdk/secreq-rule/README.md` and
`src/wasm_rules.rs` if you want to author modules in another language.

## Write a rule

Rules are written in [AssemblyScript](https://www.assemblyscript.org)
— TypeScript syntax, compiled ahead-of-time to a tiny wasm module with
no embedded JS engine. Scaffold a package:

```sh
mkdir my-rule && cd my-rule
npm init -y
npm install --save-dev assemblyscript @as-pect/cli secreq-rule
mkdir -p assembly
```

Then write `assembly/rule.ts` exporting `decide(ctx)`. The worked
example at
[`sdk/secreq-rule/examples/npm-publish-guard/`](../sdk/secreq-rule/examples/npm-publish-guard/)
is a complete, runnable package for this policy: approve `npm publish`
from checkouts under `/home/me/oss/`, deny it when an agent session
appears anywhere in the caller chain, pass on everything else:

```ts
import { RuleCtx, Decision, approve, pass, deny } from "secreq-rule";

const PUBLISH_ROOT = "/home/me/oss/";

export function decide(ctx: RuleCtx): Decision {
  if (ctx.wrap != "npm") return pass();
  const argv = ctx.joinedArgv;
  if (argv != "npm publish" && !argv.startsWith("npm publish ")) {
    return pass();
  }
  for (let i = 0; i < ctx.callers.length; i++) {
    const c = ctx.callers[i];
    if (c.name.toLowerCase().includes("claude") ||
        c.command.toLowerCase().includes("claude")) {
      return deny("npm publish from an AI-agent session is never auto-approved " +
        "(caller: " + c.name + ")");
    }
  }
  if (ctx.cwd == "/home/me/oss" || ctx.cwd.startsWith(PUBLISH_ROOT)) {
    return approve();
  }
  return pass();
}
```

One AssemblyScript caveat worth knowing: it is a *subset* of
TypeScript. Stick to strings, arrays, and plain loops (as above) and
you won't notice; regexes, closures over `this`, and most of the
JavaScript standard library are not available.

## Test it

Because a rule is just a function of ctx → decision, it unit-tests
cleanly. The example uses [as-pect](https://github.com/as-pect/as-pect),
the AssemblyScript test runner — your spec is compiled to wasm and
exercises `decide` with contexts you construct:

```ts
// assembly/__tests__/rule.spec.ts
import { RuleCtx, Caller, DecisionKind } from "secreq-rule";
import { decide } from "../rule";

function ctx(wrap: string, joinedArgv: string, cwd: string): RuleCtx {
  const c = new RuleCtx();
  c.wrap = wrap;
  c.joinedArgv = joinedArgv;
  c.cwd = cwd;
  c.callers = [];
  c.secrets = ["NPM_TOKEN"];
  return c;
}

describe("npm-publish-guard", () => {
  it("approves a publish from inside the publish root", () => {
    const d = decide(ctx("npm", "npm publish", "/home/me/oss/my-lib"));
    expect(d.kind).toBe(DecisionKind.Approve);
  });

  it("passes on a publish from outside the publish root", () => {
    const d = decide(ctx("npm", "npm publish", "/tmp/scratch-clone"));
    expect(d.kind).toBe(DecisionKind.Pass);
  });
});
```

Run with `npx asp` (the example wires it to `npm test`; `npx asp
--init` scaffolds the config for a fresh package).

**secreq never runs your tests.** Testing happens entirely in your
package, before you compile; the daemon only ever loads the compiled
`.wasm` module. A rule with no tests will register just as happily —
the test suite is your safety net, not secreq's.

## Compile it

```sh
npx secreq-rule-build assembly/rule.ts -o rule.wasm
```

`secreq-rule-build` generates the ABI entry around your `decide`,
compiles with AssemblyScript's `stub` runtime (no GC), and produces a
core wasm module — typically 10–20 KB — whose only import is
`env.abort`. If you hand-implement the ABI instead of exporting
`decide(ctx)`, compile with `secreq-rule-build --raw`.

## Register it

Registration goes through the daemon, which vets the module in the
sandbox *before* anything is stored — a module that imports the wrong
things, misses an ABI export, or fails instantiation registers
nothing:

```sh
secreq rules add-wasm rule.wasm --name "npm publish guard" --secret NPM_TOKEN
```

```
registered wasm rule 'npm publish guard' (3f8a21c09b4d5e6f70a1b2c3)
module stored:  rules/3f8a21c09b4d5e6f70a1b2c3.wasm
sha256:         9c0e0f6c…
trained on:     NPM_TOKEN
```

- `--secret NAME` (repeatable) sets the **trained-secrets snapshot**:
  the only env vars the rule may decide. An ask requesting anything
  else skips the rule before your code runs.
- `--name` labels the rule in the UI and audit log (defaults to the
  module's file name, minus the `.wasm` extension).
- The module is **copied** into the canonical store
  (`~/.secreq/rules/<rule-id>.wasm`) and pinned by the sha256 of the
  vetted bytes. Your original file is no longer consulted; edits to it
  do nothing until you register a new build.

### `--all-secrets` and its blast radius

Omitting `--secret` entirely is refused:

```
no --secret given: a wasm rule with an empty trained-secrets snapshot
is consulted for EVERY ask across EVERY wrap, and an Approve from it
auto-approves secrets it was never trained on.
```

If you truly want an unscoped rule — say, a global deny policy — opt
in explicitly with `--all-secrets`. Understand what you're accepting:
the module will be consulted for every ask across every wrap, and an
`approve()` from it auto-releases secrets it has never seen. Scoped
rules with `--secret` are almost always what you want.

## Inspect, pause, delete

The standard rule verbs apply:

```sh
secreq rules                 # list — wasm rules show `wasm` in the decide column
secreq rules show <id|name>  # module path, pinned sha256, integrity status
secreq rules disable <id>    # pause without deleting; enable to resume
secreq rules rm <id>         # delete (also removes the stored module file)
```

A healthy wasm rule shows:

```
wasm module:    rules/3f8a21c09b4d5e6f70a1b2c3.wasm
wasm sha256:    9c0e0f6c…
wasm status:    ok (module loaded and hash-verified)
```

If the stored module has been deleted, replaced, or corrupted, the
rule is **refused** at load: `rules list` marks the row with
`[REFUSED: sha256 mismatch]` (or `module missing` / `module
rejected`), `rules show` prints the full reason, and the consent
window's Rules view badges the rule in red. A refused rule stays in
your ruleset but can never fire. Only that rule is refused — your
other rules, in particular protective declarative denies, keep
working; a tampered module must not be able to switch off the rest of
your policy.

## Update a rule's module

There is no in-place module update. To ship a new build:

```sh
secreq rules add-wasm rule.wasm --name "npm publish guard v2" --secret NPM_TOKEN
secreq rules rm "npm publish guard"       # then retire the old rule
```

(Registering first means the policy is never gone in between.)
Alternatively, stop the daemon (`secreq daemon stop`), hand-edit
`~/.secreq/auto-rules.json5` — replace the module file and update the
rule's `sha256` to `shasum -a 256 <new.wasm>` — and let the next ask
respawn the daemon. The daemon owns rule writes while it runs;
hand-edits belong to a stopped daemon.

## Operational notes

- **Integrity status reflects the daemon's last rules load.** The
  daemon verifies each module's sha256 when it loads the rules file
  (at startup, on any rules-file change, and on every rule mutation)
  and evaluates the *verified, in-memory* module from then on. A file
  swapped on disk after that load is therefore never executed: the
  running daemon keeps evaluating the bytes it verified, and the next
  load re-checks the hash and refuses the mismatch. Tampering fails
  closed — it can silence the one rule, loudly, but can't inject code
  into it.
- **Runtime failures are logged, not hidden.** A trap, abort, fuel
  exhaustion, or malformed decision shows up in the daemon log
  (`secreq daemon log-path`) as
  `WARN: wasm rule … errored evaluating wrap … — treating the rule as
  not matching; falling through to the prompt`. If a rule that used
  to fire silently stopped, look there first.
- **Auto-decisions are audited like any rule hit.** Fires appear in
  the audit log as `approve+auto` / `deny+auto` with the rule's id, so
  you can always trace which module decided.
- **Rule size is bounded.** Registration refuses modules over 16 MiB;
  real rules compile to a few KB.

## Trust-model note: why arbitrary code is acceptable here

The reason secreq can run user-authored code in its most
security-sensitive path is that the sandbox makes the module's
capabilities a property of construction: no imports means no
filesystem, network, clocks, or environment — not as policy, but
because the instantiation would fail. What remains is a pure function
from ask-context to decision, bounded in time (fuel) and space (memory
cap), pinned by hash, guarded by the trained-secrets snapshot, and
subordinate to deny-wins. The worst a hostile module can do is approve
asks within the secret set you explicitly trained it on — which is
exactly the authority you granted when you registered it.
