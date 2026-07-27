# Programmable rules (WebAssembly)

Auto-rules let the daemon answer recurring asks without prompting.
Most rules are **declarative**: a match clause (wrap × argv pattern ×
ancestor × cwd) plus a fixed approve/deny, created from the Rules view
in `secreq view`. When a policy doesn't fit a match clause ("approve
`npm publish`, but only from my canonical checkouts, and never when an
AI agent is driving"), you can write the rule as **code**: a single
function, compiled to a sandboxed WebAssembly module, evaluated by the
daemon before the consent prompt.

```ts
import { RuleCtx, Decision, approve, pass, deny } from 'secreq-rule';

export function decide(ctx: RuleCtx): Decision {
  if (ctx.wrap == 'gh' && ctx.joinedArgv.startsWith('gh repo delete')) {
    return deny('repo deletes are never auto-approved');
  }
  return pass(); // no opinion; fall through to the prompt
}
```

## When to reach for a wasm rule

Prefer a declarative rule whenever one can express the policy. It's
auditable at a glance in `rules show`, editable in the UI, and can't
have bugs. Reach for a wasm rule when the decision needs logic a match
clause can't express: combinations ("this argv _unless_ that caller"),
negations, computed conditions on several ctx fields at once, or a
reason string built from the ask itself. Declarative and wasm rules
evaluate together in one pass and compete under the same precedence
(see below), so you can freely mix them, including keeping protective
declarative denies alongside a programmable approve.

## The security model

A rule module is untrusted code that helps decide whether a secret is
released. The daemon constrains what it can do structurally, so the limits
hold whatever the module contains.

| Constraint                         | How it is enforced                                                                                                                                                       |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| No I/O of any kind                 | The only import a module may declare is AssemblyScript's `env.abort`. Anything else, WASI included, is refused at registration with an error naming the import.          |
| No secret values                   | The ctx carries names: env-var names, or `ssh:<key_id>` for a signing. No value enters the sandbox.                                                                      |
| Bounded time                       | A fixed fuel budget of 10⁸ instructions per call. An infinite loop stops in well under a second.                                                                         |
| Bounded memory                     | 64 MiB of guest memory, and 64 KiB for the decision it returns.                                                                                                          |
| No state between asks              | Every evaluation instantiates the module fresh.                                                                                                                          |
| Only the bytes you registered      | Registration records the module's SHA-256 and re-verifies it on every rules load. A file that changed is refused, and `rules list`, `rules show` and the manager say so. |
| Only the secrets you trained it on | Each rule carries the secret names it was registered with, checked before the module runs. An ask naming anything outside that set skips the rule entirely.              |

Two behaviors matter when you write one.

Decisions rank deny, then prompt, then approve. A deny from any enabled rule
denies the ask, whatever else approved. A `prompt()` from any enabled rule
sends it to the consent window, and no approve applies. Among approves, a wasm rule that returned a decision counts as
maximally specific (it made a programmatic decision about this exact ask),
and ties break on the lexically smallest rule id.

A failure never becomes an approve. A module that traps, aborts, exhausts
its fuel, exceeds a cap, or returns malformed output has no opinion to give,
and a rule that cannot be consulted may have been the one that would have
denied. So a failure suppresses any competing approve and sends the ask to
the consent prompt, which the daemon logs. The same applies to a module
refused at load time for a SHA-256 mismatch: tampering with one file must
not both disable a guard and leave the thing it guarded auto-approved.

The residual risk is the last row of that table: a hostile module can
approve asks for the secrets you trained it on, and nothing else.

## What your rule sees and returns

Your rule is one exported function:

```ts path=decide.d.ts
export function decide(ctx: RuleCtx): Decision;
```

`RuleCtx` (from the `secreq-rule` package) mirrors the daemon's
evaluation context:

| Field        | Type       | Meaning                                                                                                                                                                                                              |
| ------------ | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `wrap`       | `string`   | The wrap being asked for (e.g. `gh`, `npm`).                                                                                                                                                                         |
| `joinedArgv` | `string`   | Joined argv of the wrapped command (e.g. `gh api --get /repos/x`).                                                                                                                                                   |
| `callers`    | `Caller[]` | Caller chain, **nearest-first**. Each entry has `name` (`comm`), `command` (joined argv), and `exe` (absolute path, `''` when unknown). `name` and `command` are chosen by the process; `exe` is not. Gate on `exe`. |
| `cwd`        | `string`   | Working directory of the requesting process.                                                                                                                                                                         |
| `secrets`    | `string[]` | What the ask would release, by name: env-var names for a wrap run, or the single identity `ssh:<key_id>` for an SSH sign. Names only, never values.                                                                  |

The decision is built with four constructors:

- `approve()`: auto-approve the ask without prompting.
- `pass()`: no opinion; this rule does not match. Other rules and the
  interactive prompt still apply.
- `deny(reason)`: auto-deny. `reason` is shown to the user (the wrap
  client prints it to stderr, the consent window shows a toast).
- `prompt(reason)`: require the consent prompt. No rule may auto-approve
  this ask.

`prompt()` covers the case `pass()` cannot. Passing means "no opinion", so
another rule's approve still releases the ask silently. That is right when
your rule does not recognise the request, and wrong when it recognises it as
one a human should see. Reach for `prompt()` when a request is not
suspicious enough to refuse but too consequential to release unattended:

```ts
export function decide(ctx: RuleCtx): Decision {
  if (ctx.joinedArgv.startsWith('npm publish')) {
    return prompt('publishing to a registry');
  }
  return pass();
}
```

Write `reason` as the answer to "why am I being asked?".

On the wire this is JSON with snake_case field names (`joined_argv`,
`secrets`, …) and decisions encoded as `"approve"`, `"pass"`,
`{"deny": "reason"}` or `{"prompt": "reason"}`. The SDK's build tool
generates all of that glue; you only write `decide`. The exact ABI is in
`packages/secreq-rule/README.md` and `packages/secreq/src/wasm_rules.rs` if
you want to author modules in another language.

## Write a rule

### Scaffold from the rule editor (one click)

The fastest path is the Rules view in `secreq view`. The **"Write a
programmatic rule"** card at the top scaffolds a starter project on disk
(`$SECREQ_HOME/rule-drafts/<slug>/rule.ts` plus a README) and offers an
**"Open in editor"** split-button:

::shot{id=37-rules-scaffold-open-in-editor}

The primary action opens the scaffold in your preferred editor; the caret
picks from the editors detected on your machine, and your choice is
remembered as `$editor` in `wraps.json5` so the button defaults to it next
time.

::shot{id=38-rules-scaffold-editor-picker}

Land in your editor, edit `decide`, then compile and register (below).

### Scaffold by hand

Rules are written in [AssemblyScript](https://www.assemblyscript.org): TypeScript
syntax, compiled ahead-of-time to a tiny wasm module with no embedded JS
engine. Scaffold a package:

```sh
mkdir my-rule && cd my-rule
npm init -y
npm install --save-dev assemblyscript @as-pect/cli secreq-rule
mkdir -p assembly
```

Then write `assembly/rule.ts` exporting `decide(ctx)`. The worked
example at
[`packages/secreq-rule/examples/npm-publish-guard/`](../packages/secreq-rule/examples/npm-publish-guard/)
is a complete, runnable package for this policy: approve `npm publish`
from checkouts under `/home/me/oss/`, deny it when an agent session
appears anywhere in the caller chain, pass on everything else:

```ts path=assembly/rule.ts
import { RuleCtx, Decision, approve, pass, deny } from 'secreq-rule';

const PUBLISH_ROOT = '/home/me/oss/';

export function decide(ctx: RuleCtx): Decision {
  if (ctx.wrap != 'npm') return pass();
  const argv = ctx.joinedArgv;
  if (argv != 'npm publish' && !argv.startsWith('npm publish ')) {
    return pass();
  }
  for (let i = 0; i < ctx.callers.length; i++) {
    const c = ctx.callers[i];
    if (c.name.toLowerCase().includes('claude') || c.command.toLowerCase().includes('claude')) {
      return deny(
        'npm publish from an AI-agent session is never auto-approved ' + '(caller: ' + c.name + ')',
      );
    }
  }
  if (ctx.cwd == '/home/me/oss' || ctx.cwd.startsWith(PUBLISH_ROOT)) {
    return approve();
  }
  return pass();
}
```

One AssemblyScript caveat: it is a _subset_ of
TypeScript. Stick to strings, arrays, and plain loops (as above) and
you won't notice; regexes, closures over `this`, and most of the
JavaScript standard library are not available.

## Test it

Because a rule is just a function of ctx → decision, it unit-tests
cleanly. The example uses [as-pect](https://github.com/as-pect/as-pect),
the AssemblyScript test runner. Your spec is compiled to wasm and
exercises `decide` with contexts you construct:

```ts path=assembly/__tests__/rule.spec.ts
// assembly/__tests__/rule.spec.ts
import { RuleCtx, Caller, DecisionKind } from 'secreq-rule';
import { decide } from '../rule';

function ctx(wrap: string, joinedArgv: string, cwd: string): RuleCtx {
  const c = new RuleCtx();
  c.wrap = wrap;
  c.joinedArgv = joinedArgv;
  c.cwd = cwd;
  c.callers = [];
  c.secrets = ['NPM_TOKEN'];
  return c;
}

describe('npm-publish-guard', () => {
  it('approves a publish from inside the publish root', () => {
    const d = decide(ctx('npm', 'npm publish', '/home/me/oss/my-lib'));
    expect(d.kind).toBe(DecisionKind.Approve);
  });

  it('passes on a publish from outside the publish root', () => {
    const d = decide(ctx('npm', 'npm publish', '/tmp/scratch-clone'));
    expect(d.kind).toBe(DecisionKind.Pass);
  });
});
```

Run with `npx asp` (the example wires it to `npm test`; `npx asp
--init` scaffolds the config for a fresh package).

**secreq never runs your tests.** Testing happens entirely in your
package, before you compile; the daemon only ever loads the compiled
`.wasm` module. A rule with no tests will register just as happily; the
test suite is your safety net, not secreq's.

## Compile it

```sh
npx secreq-rule-build assembly/rule.ts -o rule.wasm
```

`secreq-rule-build` generates the ABI entry around your `decide`,
compiles with AssemblyScript's `stub` runtime (no GC), and produces a
core wasm module (typically 10–20 KB) whose only import is
`env.abort`. If you hand-implement the ABI instead of exporting
`decide(ctx)`, compile with `secreq-rule-build --raw`.

## Register it

Registration goes through the daemon, which vets the module in the
sandbox _before_ anything is stored. A module that imports the wrong
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

Omitting `--secret` entirely is refused, because an unscoped rule is
consulted for every ask across every wrap and an `approve()` from it
releases secrets it was never trained on. If you want that (a global deny
policy is the honest case), opt in with `--all-secrets`.

## Inspect, pause, delete

The standard rule verbs apply:

```sh
secreq rules                 # list; wasm rules show `wasm` in the decide column
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
rejected`), and `rules show` prints the full reason.

::shot{id=39-rules-wasm-refused}

A refused rule stays in your ruleset but can never fire. Only that rule
is refused. Your other rules keep working, protective denies included,
because a tampered module must not be able to switch off the rest of
your policy.

## Update a rule's module

There is no in-place module update. To ship a new build:

```sh
secreq rules add-wasm rule.wasm --name "npm publish guard v2" --secret NPM_TOKEN
secreq rules rm "npm publish guard"       # then retire the old rule
```

(Registering first means the policy is never gone in between.)
Alternatively, stop the daemon (`secreq daemon stop`), hand-edit
`~/.secreq/auto-rules.json5` (replace the module file and update the
rule's `sha256` to `shasum -a 256 <new.wasm>`), and let the next ask
respawn the daemon. The daemon owns rule writes while it runs;
hand-edits belong to a stopped daemon.

## Operational notes

- **Integrity status reflects the daemon's last rules load.** The
  daemon verifies each module's sha256 when it loads the rules file
  (at startup, on any rules-file change, and on every rule mutation)
  and evaluates the _verified, in-memory_ module from then on. A file
  swapped on disk after that load is therefore never executed: the
  running daemon keeps evaluating the bytes it verified, and the next
  load re-checks the hash and refuses the mismatch. Tampering fails
  closed: it can silence the one rule, loudly, but can't inject code
  into it.
- **Runtime failures are logged, not hidden.** A trap, abort, fuel
  exhaustion, or malformed decision shows up in the daemon log
  (`secreq daemon log-path`) as
  `WARN: wasm rule … errored evaluating wrap …; treating the rule as
not matching, falling through to the prompt`. If a rule that used
  to fire silently stopped, look there first.
- **Auto-decisions are audited like any rule hit.** Fires appear in
  the audit log as `approve+auto` / `deny+auto` with the rule's id, so
  you can always trace which module decided.
- **Rule size is bounded.** Registration refuses modules over 16 MiB;
  real rules compile to a few KB.
