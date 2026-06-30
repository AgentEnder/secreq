# `secreq run` — Design

> Status: **Design complete.** Brainstormed 2026-06-29; ready for an
> implementation plan.
> Supersedes the `run` surface of the pre-pivot design
> (`2026-05-22-secrets-requestor-design.md` §6–§11), re-homed onto the
> current daemon architecture.

## 1. One-line pitch

**`op run`, but for every secret store you own** — scan the environment
for `secret://provider/locator` references, resolve them through the
consent daemon (with masking, caching, and batched provider unlocks),
and exec an arbitrary command with the resolved values injected.

This is the **ambient mirror of `secreq x`**: `x` resolves a *declared*
env map for a *known binary* (a `wraps.json5` entry); `run` resolves
*ambient* refs found in the inherited environment for *any* command.
Both share the same back end (`exec::run`, `reference.rs`, the daemon
resolution path).

## 2. Why bring it back

The original `run` was dropped at the per-binary-wrap pivot, with
project-level `.env` resolution handed to varlock. In practice varlock
doesn't deliver the `op run`-style UX we want: drop `secret://` refs in
your environment (or a committable, refs-only `.env`), run your command,
and have the values appear — gated by one consent ceremony and masked on
the way out. `run` is that path.

## 3. Goals / Non-goals

### Goals
- Resolve `secret://provider/locator` refs found in the **inherited
  environment** and in any **`--env-file`** (op-run parity).
- Route consent + resolution through the **existing daemon** — inheriting
  the consent window, the rules engine, coalescing, the in-memory value
  cache, and batched provider unlocks **for free**.
- Inject resolved values and exec the command through the **unchanged**
  `exec::run` engine (PTY/piped, output masking, signal/resize
  forwarding).
- Low prompt friction: the value cache removes already-known refs from
  the ask; batch resolution serves the rest with one unlock per provider.

### Non-goals (YAGNI — explicitly out)
- **No manifest / groups / `--only` / eager required-set.** Ambient refs
  only. (The original design's manifest stays retired — that's varlock's
  space.)
- **No `.env` *migration*** (`import`/`add`/write-capabilities). The new
  `dotenv` parser only *reads* `KEY=value` lines; it never writes or
  scrubs.
- **No new resolution, caching, or masking machinery.** `run` is a thin
  front end over machinery that already exists and is tested.
- **No `SECREQ_SESSION`/`SECREQ_DEPTH` nesting markers** — substitution
  makes nested `run` correct for free (§7).

## 4. CLI surface

```
secreq run [--env-file PATH]… [--] <cmd> [args…]
```

- `--env-file PATH` (repeatable): load `KEY=value` lines and layer them
  **under** the inherited environment (inherited wins, matching
  `op run --env-file`). The file holds **refs, not plaintext** and is
  safe to commit.
- Global flags already apply: `--raw` (skip output masking), `--yes`
  (auto-approve, resolve client-side for scripts/CI), `--config`,
  `--no-remember` (no-op for `run` — see §6).
- `<cmd> [args…]`: trailing var-arg, hyphen values allowed.

## 5. Data flow

```
secreq run [--env-file PATH]… -- <cmd> [args…]
  1. Effective env = inherited env, with --env-file entries layered
     UNDER it (inherited wins).
  2. Scan: every var whose VALUE is a well-formed secret:// reference
     (reference::Reference::parse) → the ref set {(name, provider, locator)}.
     A var whose value merely starts with secret:// but does NOT parse
     is a HARD ERROR before exec.
  3. Empty ref set → exec <cmd> with the effective env directly. No
     daemon contact, no consent (honest "nothing to resolve" fast path).
  4. Build an Ask:
        dedupe_key.wrap     = "run"            (fixed identity, §6)
        command             = [cmd, args…]     (shown in consent; never values)
        callers             = provenance::caller_chain()
        secrets             = [SecretAsk{name, provider, locator} per ref]
        providers           = wraps.json5 providers map (WireProvider)
        allow_remember      = false            (§6)
  5. Consent + resolve (same path as x):
        interactive → obtain_wrap_consent  (daemon: rules / coalesce /
                      consent window / cache-diff / batch-resolve)
        --yes       → resolve_wrap_env      (client-side)
        deny → exit 1
  6. Substitute: replace each ref var's value in the effective env with
     its resolved value → env_overrides. Masking set = resolved values
     (empty under --raw).
  7. exec::run(command, env_overrides, secrets_for_masking, cwd).
```

Only steps 1–3 and 6 are new code. Steps 4–5 and 7 are existing
machinery.

## 6. Identity, consent, and the trust model

`run` presents a **fixed identity**: `dedupe_key.wrap = "run"`, the same
for every invocation regardless of command.

- **Consent window.** The window's "what is asking" line shows
  `secreq run`, but the Ask also carries `command = [cmd, args…]`, so the
  panel still renders the actual command and the caller chain. Uniform
  rule bucket, informative prompt.
- **Rules engine.** Rules match the wrap name + trained secrets. A rule
  therefore targets *all* `run` invocations (e.g. "auto-approve `run`
  when it only wants `keychain` refs"), not a specific command — the
  intended consequence of a uniform identity.
- **Value cache.** Keyed `(wrap, provider, locator)`. Because every
  `run` shares `wrap = "run"`, they all share one cache bucket: a second
  `run` referencing an already-resolved `(provider, locator)` hits the
  cache with **no provider call / no biometric**. (A command-name
  identity would have fragmented this.)
- **Batched unlocks.** `resolve_all` groups the *misses* by provider and
  uses `retrieve_batch` when ≥2 share a provider — one `op run
  --no-masking -- printenv` for all `op://` misses, i.e. one biometric.
- **Audit.** `run` writes its own audit row client-side (the wrap-client
  path), `wrap = "run"`, recording command, caller chain, and secret
  **names** — never values.

### Remember is disabled for `run`

The approvals cache keys on `(wrap, ppid, parent_start_time)`. Under a
fixed identity, "approve & remember" for one `run` would let a *different*
later command in the same shell ride that approval — an undesired
widening. So **`run` disables remember entirely**:

- New `Ask.allow_remember: bool` (`#[serde(default = "…true")]`, so older
  peers decode as `true`; `false` only for `run`).
- **Enforcement is one condition, server-side.** The approvals cache is
  written at `state.rs:891` *only* when
  `decision == ApproveRemember && representative.ssh.is_none()`. We add
  `&& representative.allow_remember`. A `run` ask therefore **never
  persists an approval**, even if the user presses Enter (which sends
  `ApproveRemember`) — it degrades to a plain approve.
- **No consent-window surgery needed.** There is *no* visible "Approve &
  Remember" button — the wrap card shows only **Approve** / **Deny**
  (`ui.rs:3496`); remember rides the **Enter** key
  (`render_consent_panel:900`) and the **"Approve all ↵"** subtree button
  (`ui.rs:3359`). The server-side guard covers all of those paths at
  once. (Optional polish: drop the "↵"/"& remember" hint for a
  no-remember row — cosmetic, not load-bearing.)
- Every `run` re-prompts for consent. This is cheap: the value cache
  means a re-prompt is a single approve click, **not** an `op` unlock.

`--no-remember` on the CLI is thus a no-op for `run` (already the
default behavior).

## 7. Nested `run` is correct for free

`secreq run -- script` where `script` itself runs `secreq run -- thing`
works without session markers. After step 6, the outer `run` has already
replaced every `secret://` ref in the child env with a plain resolved
value. The inner `run` therefore scans an environment with **no
`secret://` refs remaining** → empty ref set → it just execs (step 3).
"A secret crosses the consent boundary once" falls out of substitution.
Output masking composes: the outer PTY masks the entire child subtree's
output, including the inner `run`'s.

## 8. New / changed code

| Item | Kind | Notes |
|---|---|---|
| `src/dotenv.rs` | **new, small** | `KEY=value` parser for `--env-file`. Comments (`#`), blank lines, `=`-in-value. **Read-only** — no scrub/migration. |
| `src/commands.rs::run` | **new** | Orchestrator mirroring `wrap_run`: scan → Ask → consent → substitute → `exec::run`. |
| `Ask.allow_remember: bool` | **new field** | Proto change, `serde` default `true`. `false` only for `run`. |
| `state.rs:891` approval-write guard | **change** | Add `&& representative.allow_remember` so a `run` ask never persists an approval. The single load-bearing enforcement point. |
| `src/cli.rs` `Run { env_file, command }` | **new subcommand** | Wires `--env-file` (repeatable) + trailing command; dispatches to `commands::run`. |

Reused unchanged: `exec::run`, `reference.rs`, `resolve.rs` /
`resolve_for_ask` (cache diff + batch), `provenance::caller_chain`,
`obtain_wrap_consent`, `resolve_wrap_env`, `audit`, `mask`, `secret`.

## 9. Edge cases

- **Malformed ref** (`secret://` prefix that doesn't `parse`): hard error
  before exec, naming the offending env var. Never pass a literal
  `secret://…` into the child.
- **Unknown provider** (scheme not in `wraps.json5` providers):
  `resolve_all` errors "unknown provider scheme"; surfaced before exec.
- **Recursion guard:** honor `RESOLVING_ENV` as `wrap_run` does — if
  `run` is invoked inside secreq's own resolution, skip scanning and just
  exec, so a provider CLI can't trigger a second consent.
- **`--yes`:** resolves client-side via `resolve_wrap_env` (no daemon, no
  coalescing — scripted runs), parallel to `x`.

## 10. Testing & docs obligations

**Unit / integration tests:**
- `dotenv` parser: comments, blanks, `=`-in-value, inherited-wins
  layering.
- Ambient scan: only `secret://` *values* become refs; everything else
  passes through untouched.
- Substitution + masking-set population.
- Empty-set fast path: no daemon contact.
- `--yes` client-side path.
- End-to-end `run` against a fake `sh -c` provider (the pattern in
  `state.rs` tests).
- `Ask` built by `run` carries `wrap = "run"`, `allow_remember = false`.

**Screenshot fixtures (CLAUDE.md):** a `run` ask renders through the
*existing* wrap card (command header + Approve/Deny), so it introduces no
new visual primitive. It is, however, a distinct scenario — a card whose
command is a free-form `cmd args…` and whose secrets came from ambient
env. Add one fixture to `tests/ui_screenshots.rs` rendering a `run` Ask
(`allow_remember = false`), regenerate every PNG, inspect a new + an
existing one, and add the README table row noting it exercises the `run`
consent path. The harness needs a way to build an `Ask` with
`allow_remember = false` (extend the existing `submit`/`FixtureExtras`
helper).

**Docs:** add `run` to the README command list and `docs/`; keep this
design doc current if the trust model / wire protocol shifts.
