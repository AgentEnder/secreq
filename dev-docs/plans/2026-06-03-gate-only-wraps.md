# Gate-only wraps

**Status:** implemented (2026-06-03)

## Motivation

`secreq` was built to *inject secrets* for a wrapped binary: a wrap
declares `env` entries, the daemon gates the invocation, resolves the
`secret://` references, and execs the binary with those env vars set.

Some tools need the **gate** but have no secret to inject. The 1Password
CLI (`op`) is the canonical case: `op read op://Vault/item/field`
manages its own auth (biometric / session token), so there's nothing for
`secreq` to pass. What's valuable is gating the command — pausing every
`op` invocation for a consent prompt that answers *"why am I getting this
request?"* with the full command, cwd, and caller process tree. `op`'s
own modal shows little of that context.

## Design

A **gate-only wrap** is a wrap with an empty `env` map. It routes the
binary through the consent daemon but resolves and injects nothing.

The key observation: the consent/daemon/audit/auto-rules machinery is
already secret-agnostic. The change surface is concentrated at the input
edges; the core pipeline degrades to a no-op when the secrets list is
empty.

### Decisions (from brainstorming)

- **Gate scope:** every invocation of the wrapped binary prompts (matches
  the existing per-binary model). Per-subcommand selectivity is left to
  auto-rules (argv patterns), which already exist.
- **Config shape:** `env` becomes optional. Omitting it (or `env: {}`)
  means gate-only. No new `$gate` flag.
- **CLI ergonomics:** absence of `--env` implies a gate. `secreq wrap op`
  with no `--env` and no terminal creates a gate-only wrap directly; in
  an interactive terminal it offers a "Gate only (no secrets)" choice.

### What changed

| Area | Change |
|---|---|
| `wraps.rs` | `env` key optional; dropped the empty-env `bail!`. Empty map is legal. |
| `schema.rs` | `wrap_schema`: dropped `required: ["env"]` and `env`'s `minProperties: 1`; updated descriptions. Regenerated `docs/wraps.schema.json`. |
| `commands.rs` | `wrap()`: three env-build paths (flags / interactive choice / no-terminal gate); dropped the empty-env bail; added `prompt::wrap_is_gate_only`; success summary notes "(gate-only …)". |
| `daemon/ui.rs` | Pending card renders a muted "Gate only — no secrets injected" marker (`render_card_gate_only`) when `secrets` is empty. |
| `tests/ui_screenshots.rs` | New fixture `21-gate-only-pending`. |
| `tests/cli.rs` | `wrap_with_no_env_creates_a_gate_only_wrap`, `gate_only_wrap_denies_without_terminal_or_yes`. |
| `wraps.rs` tests | `parses_a_gate_only_wrap_with_no_env`, `…with_empty_env` (replacing `rejects_empty_env`, whose expectation inverted). |
| docs | `docs/wraps.md` gate-only section; `dev-docs/architecture.md` notes; this plan. |

### Follow-up: the wrapped-provider recursion guard

Gating `op` exposes a recursion: `op` is commonly *also* a `secret://op/...`
provider. When secreq resolves another wrap's secret it runs the
provider's retrieve command — `Command::new("op")` — which PATH-resolves
to our shim and re-enters `secreq op`, popping a second consent prompt
(and hanging a `--yes` run on a prompt it never asked for).

Fix: `provider::{retrieve, retrieve_batch, store}` set
`SECREQ_RESOLVING=1` (`crate::RESOLVING_ENV`) on every subprocess they
spawn; `wrap_run` checks it up front and passes through to the real
binary (no consent, no injection).

- **Scope:** the marker rides only secreq's own resolution subprocess, so
  a wrapped *script* that calls `op` itself still gates. Only the internal
  `op read` secreq fires is skipped.
- **Security:** not a boundary. Any same-user process could set the var
  (or call the real binary directly, bypassing the shim) — identical to
  the existing `SECREQ_NO_DAEMON` model. It's a recursion guard, not an
  access control.
- **Tests:** `provider::tests::retrieve_sets_the_recursion_guard_env_on_the_child`
  (unit) and `resolving_env_bypasses_the_gate_for_a_wrapped_provider`
  (integration).

### What did NOT change (and why)

- **Daemon resolution** (`state.rs::resolve_for_ask`): an empty
  `ask.secrets` yields an empty `needs_resolve` and returns early with an
  empty value map — no provider invoked, no Touch ID.
- **Auto-rules**: the trained-secrets guard checks `requested ⊆ trained`.
  A gate-only ask requests `∅` (subset of anything) and a rule trained on
  it snapshots an empty `trained_secrets` set (guard disabled). So
  "approve `op read op://Work/*`, prompt otherwise" works with no new
  rule machinery.
- **Audit log**: `AuditEntry::new` already accepts an empty env-name list.
- **Wire protocol**: `Ask.secrets` is a `Vec`; the empty case needs no
  new field. The wrap-level `$reason` is not separately surfaced in the
  gate-only card — the command argv + caller chain carry the context.

## Out of scope (YAGNI)

- Per-subcommand argv gating inside a base wrap (auto-rules cover it).
- A `$gate: true` flag (empty `env` is unambiguous enough).
- Per-wrap "remember" overrides (decided per-prompt, as today).
