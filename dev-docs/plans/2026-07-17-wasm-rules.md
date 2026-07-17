# Programmable (WebAssembly) Auto-Rules — Design

> Status: **Implemented** (phases A–D on `feat/wasm-rules`).
> Date: 2026-07-17
> Companion to: `2026-06-02-auto-rules.md` (the declarative engine this
> extends), `docs/wasm-rules.md` (the user guide).

## 1. One-line pitch

A rule can be a *program*: one user-authored function, compiled to a
sandboxed wasm module, evaluated by the daemon in the same pre-queue
pass as declarative rules — able to express policies a match clause
can't, without widening what a rule is able to *do*.

## 2. Motivating example

> *"Approve `npm publish`, but only from checkouts under `~/oss/`, and
> never when an AI-agent session appears anywhere in the caller
> chain."*

The declarative engine can express each clause alone but not the
combination (no negation, no cross-field logic, no computed deny
reason). The alternatives were to keep growing the match DSL clause by
clause — negations, boolean operators, string functions — or to admit
real code under a contract that keeps it decision-only. We chose the
latter; a DSL that grows toward expressiveness ends up as a worse
programming language with the same trust questions.

## 3. Trust model: the sandbox is the argument

Running user-authored code inside the consent daemon's most
security-sensitive path is acceptable for exactly one reason: the
module's capabilities are a **property of construction**, not of
review.

- **No WASI, no ambient imports.** The only host-provided import is
  AssemblyScript's `env.abort`, implemented as a trap. A module
  importing anything else fails `RuleModule::from_binary` with an
  error naming the import. No filesystem, network, env, clock, or
  randomness — not as policy but because instantiation fails.
- **Fuel-metered** (`FUEL_BUDGET = 10⁸` units ≈ instructions): an
  infinite loop is a clean error in well under a second. Fuel was
  chosen over epoch interruption because it is deterministic and needs
  no background ticker thread; the single-digit-percent slowdown is
  irrelevant at rule size.
- **Memory-capped** (64 MiB store limiter) and **decision-capped**
  (64 KiB returned JSON, checked before the read).
- **One fresh instance per evaluation** — no state across asks, and a
  trapped instance is simply dropped.
- **Registration-time vetting**: static import/export checks plus one
  throwaway smoke instantiation, so wrong `env.abort` signatures and
  oversized memory minimums fail while the user is still looking, not
  at the first ask.

What remains is a pure function from ask-context to decision. The ctx
carries secret **names**, never values. The worst a hostile module can
do is approve asks inside the trained-secrets set the user explicitly
registered it for — the authority the user granted, no more.

## 4. Why AssemblyScript + wasmtime (and not a JS engine)

Considered: embedding a JS engine (QuickJS/Boa) so rules are plain
JavaScript; or rules as external processes; or growing the DSL.

- An embedded JS engine means shipping and sandboxing an entire
  runtime; resource-limiting and capability-stripping it is *our*
  ongoing job. With core wasm, the isolation is the instruction set:
  wasmtime gives fuel, memory limits, and a closed import surface as
  first-class primitives.
- AssemblyScript compiles TypeScript-syntax source ahead-of-time to a
  **tiny, engine-free module** (the fixtures and the worked example
  compile to 10–20 KB) whose only import is `env.abort` under the
  `stub` runtime. Authors get a mainstream-looking language; the
  daemon gets a static artifact it can hash-pin.
- External processes would inherit the user's full ambient authority —
  precisely what the sandbox exists to remove.

The JSON marshalling cost (serialize ctx, parse decision) is paid once
per evaluation on a kilobyte-scale payload; irrelevant next to the
provider round-trips the rule may save.

## 5. The ABI (frozen)

Kept in lock-step between `src/wasm_rules.rs` and
`sdk/secreq-rule/assembly/abi.ts`. The module must export:

- `memory` — its linear memory;
- `alloc(len: i32) -> i32` — return a buffer the host writes into
  (stub-runtime bump allocator; nothing is freed; the host uses one
  instance per call so returned buffers stay valid);
- `decide(ptr: i32, len: i32) -> i64` — evaluate, return
  `(ptr << 32) | len` pointing at UTF-8 decision JSON.

Host flow: JSON-encode ctx (UTF-8) → `alloc` → write → `decide` →
unpack → read + parse.

Ctx JSON mirrors `rules::EvalCtx` with snake_case fields —
`{"wrap", "joined_argv", "callers": [{"name", "command"}] (nearest-
first), "cwd", "requested_secret_names"}` — and the decision JSON is
the serde encoding of `wasm_rules::Decision`: `"approve"` | `"pass"` |
`{"deny": "reason"}`. **Field names are the ABI**; renaming one breaks
every compiled rule. The guest parser skips unknown ctx fields, so the
host can *add* fields without recompiling existing rules.

The SDK hand-rolls its JSON (`assembly/json.ts`): the AS ecosystem's
JSON libraries assume a GC runtime, and the `stub` runtime is what
keeps modules import-free and tiny. The parser is shape-specific to
the ctx object; malformed input aborts, which the host maps to "rule
does not match".

## 6. Evaluation semantics

Wasm rules join the *same* single evaluation pass as declarative rules
(`rules::evaluate`), competing under the same precedence:

- The **trained-secrets guard runs before guest code**. A rule must
  not even see an ask outside its snapshot, let alone decide it.
- `Pass` ⇒ the rule does not match.
- A non-Pass wasm decision gets **maximal specificity**
  (`WASM_DECISION_SPECIFICITY = u32::MAX`): declarative specificity
  counts how many optional clauses constrain the match (0–3), and a
  module that programmatically chose approve/deny for this exact ask
  is as constrained as it gets. Ties break on the existing
  smallest-id rule.
- **Deny-wins dominates specificity entirely** — denies and approves
  compete in separate slots and deny is chosen first, so a bare
  declarative deny still beats a wasm approve (pinned by test against
  a future "one max-by-specificity pass" refactor).
- A **runtime error** (trap, abort, fuel exhaustion, OOB/oversized/
  malformed decision) means the rule does not match — **fail safe to
  the prompt, never to an auto-approve** — and is surfaced in
  `Evaluation::wasm_failures`, which the daemon WARN-logs per ask. A
  rule that silently stopped firing would be indistinguishable from
  one that decided to pass.

## 7. Storage, pinning, and the two-tier load-failure policy

A wasm rule is `wasm: {path, sha256}` XOR the declarative
`decide`+`match` (enforced by `Rule::validate_shape` at every load and
mutation; a wasm rule with `decide` or `deny_message` is rejected
loudly — those fields would be dead weight at best, misleading at
worst).

**Pinning.** `sha256` is recorded from the vetted bytes at
registration and **verified on every load**. Rules files are
hand-editable; the pin makes the module file non-editable-in-place by
construction.

**Two-tier failure granularity** in `load_rules` (deliberate):

- *File-level*: unparseable JSON5 or an invalid rule shape errors the
  whole load — the file was authored wrong, same class as a syntax
  error; the daemon's existing "warn + empty ruleset" contract
  applies.
- *Per-rule*: a wasm rule whose referenced **module** fails (missing
  file, sha256 mismatch, sandbox rejection) refuses just that rule.
  Rationale: a tampered module is a loud security event, but it must
  not knock out the user's *other* rules — in particular their
  protective declarative denies, which would otherwise stop firing
  exactly when something on disk is being tampered with.

**Refusal visibility.** Each refusal is retained as a typed
`WasmRefusal {rule_id, category, reason}` (categories:
`missing_module` / `sha256_mismatch` / `module_rejected`) and
surfaced everywhere the rule is: daemon-log WARN at load, a
`[REFUSED: …]` marker in `rules list`, the full reason in `rules
show`, and a red badge in the manager UI. The refused rule stays in
the ruleset, module-less, so it can never fire but never disappears
silently. Reasons name rules, paths, and hashes — never secret values.

**Store hygiene.** Registration is daemon-owned (`AddWasmRule` over
IPC, wrapped by `secreq rules add-wasm`): defensive read of the
client-supplied path (regular-file check so a FIFO can't wedge the
connection thread; 16 MiB cap), vet via `from_binary` *before*
touching disk, tmp-write + rename into the canonical store
(`rules/<rule-id>.wasm` under the secreq root, id validated against
path-escape), sha pinned from the vetted bytes, and full rollback —
in-memory state and the stored file — if persist fails. Deleting a
rule removes its canonically-stored module (a hand-registered module
at any other path is the user's file and is left alone).

## 8. The empty-snapshot opt-in

An empty `trained_secrets` set disables the guard entirely — the
module is consulted for every ask across every wrap, and an Approve
auto-releases secrets it has never seen. That is legitimate (a global
deny policy) but must be *chosen*: both doors that can create a wasm
rule — `rules add-wasm` (CLI-side check + daemon-side check) and the
raw `AddRule` IPC message — refuse an empty snapshot unless
`--all-secrets` / `allow_all_secrets` is passed explicitly, and the
CLI prints a blast-radius warning even then. Declarative rules keep
the historical "empty = guard off" hand-edit behavior; the opt-in is
new ceremony only where code decides.

## 9. The mtime-reload caveat

The daemon re-reads the rules file when its mtime changes (checked on
every client message; reload-in-place, no restart). Modules are
compiled at load and evaluated **from memory**, which yields the
operative integrity property: a module file swapped on disk after a
load is *never executed* — the running daemon keeps evaluating the
bytes it verified, and the next load (restart, rules-file change, or
any rule mutation) re-hashes and refuses the mismatch. The caveat is
the converse: swapping only the module file does not advance the
rules-file mtime, so the *refusal* also doesn't surface until the next
load. Fails closed, but not instantly loud. Accepted: closing it would
take per-evaluation re-hashing (cost with no integrity gain, since
evaluation doesn't re-read the file) or file watchers (platform
surface disproportionate to the window).

## 10. Deliberately rejected

- **Growing the declarative DSL** (negation, boolean ops) — see §2.
- **WASI (even "just" clocks/random)** — every import is capability
  surface to audit forever; a decision function needs none of it.
- **Epoch-based interruption** instead of fuel — needs a ticker
  thread; fuel is deterministic (§3).
- **secreq running user tests** — registration vets the *artifact*
  (imports, exports, instantiation), not the *logic*. Running
  user-supplied test suites inside secreq would mean executing more
  untrusted code to validate untrusted code, with no principled pass
  bar. Testing lives in the author's package (as-pect in the SDK
  example); the docs state this contract explicitly.
- **Letting wasm decisions seed the approvals cache / guest-influenced
  cache keys** — a guest that could shape a cache key could widen one
  approval into many. Wasm hits follow the exact `ApproveAuto` /
  `DenyAuto` path declarative hits use: every ask re-evaluates.
- **Trusting the client's hash at registration** — the daemon reads
  and hashes the bytes itself; the wire carries a path, not a digest.
- **Sanitizing rule ids into store filenames** — rejected, not
  mapped: aliasing two ids onto one file would let one rule overwrite
  another's module (same reasoning as scope-socket names in
  `paths.rs`).
- **In-place module update verb** — update = register new + remove
  old (or hand-edit with the daemon stopped). An in-place update door
  would need its own vet/pin/rollback path for marginal ergonomics.

## 11. SDK + toolchain notes

- `sdk/secreq-rule`: `RuleCtx`/`Caller`/`Decision` authoring types, the
  ABI glue (`abi.ts`), stub-runtime JSON (`json.ts`), and
  `secreq-rule-build` (wraps `asc`; generates the ABI entry around the
  author's `decide`; `--raw` compiles hand-implemented-ABI modules —
  used by the fixture rebuild).
- asc 0.28 resolves bare `import "secreq-rule"` to the package's root
  `index.ts` (it does not consult `ascMain`), so the package carries a
  root re-export. The generated entry must import the ABI glue through
  the *same* specifier the rule used (package vs relative) — asc types
  are nominal per module identity — so `secreq-rule-build` picks the
  specifier by resolving `secreq-rule` from the rule's directory.
- Compiled `.wasm` fixtures are checked in
  (`tests/fixtures/wasm_rules/`, rebuilt by `rebuild.sh`) so `cargo
  test` needs no node toolchain; hostile-shape fixtures are
  hand-written `.wat`, assembled at test time by the `wat` dev-dep.
- The worked example (`sdk/secreq-rule/examples/npm-publish-guard/`)
  is the user guide's running sample: rule + as-pect spec + checked-in
  `rule.wasm` (same convention as the fixtures; rebuild with `npm run
  build`).
