# secreq — per-secret rule evaluation

*Design captured 2026-07-23. Change rule evaluation from a whole-ask decision to a per-secret aggregation: run every rule that overlaps the ask, scope each wasm rule's `Approve` to the secrets it was trained on, and approve the ask only if **every** requested secret reached an approved state with no deny.*

## Problem — the trained-secrets gate is a workaround, not the model

Historically a wasm rule only ran when the ask's requested secrets were a **subset** of the rule's `trained_secrets` (`trained_secrets_allow`):

```rust
fn trained_secrets_allow(rule: &Rule, ctx: &EvalCtx) -> bool {
    rule.trained_secrets.is_empty()
        || ctx.requested_secret_names.iter()
            .all(|n| rule.trained_secrets.contains(*n))   // EVERY requested name ∈ trained set
}
```

That gate existed **because a wasm rule's `Approve` was scoped to the whole ask.** Since `Approve` meant "approve everything this ask requested," the only way to keep it safe was to refuse to run the rule unless the entire ask was already inside its competence — otherwise an `Approve` would auto-approve secrets the module was never trained on (the exact threat the `add-wasm` CLI warns about).

Consequences of the coarse granularity:
- A rule trained on `NPM_TOKEN` was **skipped entirely** for an ask requesting `{NPM_TOKEN, SSH_KEY}` — it couldn't contribute its knowledge about `NPM_TOKEN`.
- Multi-secret asks effectively needed a single rule that knew about *all* the secrets, defeating composition.

## Model — per-secret approval aggregation

Reframe a wasm rule's `Approve` from *"approve this ask"* to *"approve the secrets I'm responsible for"*:

> `approved_secrets(rule) = requested ∩ rule.trained_secrets`

Then a wasm rule **structurally cannot** approve a secret outside its trained set, regardless of what it returns — the safety property the subset-gate hacks around becomes impossible *by construction*, so the gate is no longer needed and every overlapping rule may run.

Aggregate decision:

> **The ask is approved iff every requested secret reached an approved state** — i.e. for each requested secret `S`, some responsible rule approved `S` — **and no rule denied.**

## Decided semantics (2026-07-23)

1. **Deny is a whole-ask veto (not per-secret).** A rule that sees a dangerous *combination* (e.g. `NPM_TOKEN` + `SSH_KEY` together) must be able to kill the entire ask. Rules still receive the full `ctx.requested_secret_names`, so they keep combination visibility. `Deny` beats `Approve`, evaluated after the per-secret AND. *(Carried as decided; revisit only if per-secret deny is wanted later.)*

2. **Declarative rules stay whole-ask-scoped for approval (chosen: option A).** A declarative rule's `Approve` covers **all** secrets in the ask it matched. Only **wasm** rules get the per-secret `requested ∩ trained` scoping. Rationale: declarative rules are *transparent* (the match clause is readable), so a whole-ask approval is deliberate, auditable user intent; wasm modules are *opaque*, which is why they earn the tighter scoping. **Bonus: declarative evaluation is unchanged — the entire refactor is localized to wasm-rule approval scoping + the aggregation step.** Smaller blast radius, trivial migration.

3. **Stricter coverage is intended (feature, not regression).** Every requested secret needs an approver or the ask falls through to prompt. One rule trained on `{A, B}` still covers both secrets of an ask requesting both — you don't need N rules, but every secret must be covered by *something*.

## Evaluation sketch

For an ask with `requested = {S1..Sn}`:

1. Gather candidate rules that **overlap** the ask (declarative: match clause matches; wasm: `trained ∩ requested ≠ ∅`, or empty-trained `--all-secrets` rules which overlap everything).
2. Run each candidate (wasm rules instantiated fresh, fuel-metered, as today).
3. **Deny short-circuit:** if any rule denies → whole ask denied (deny beats approve, most-specific wins among denies as today).
4. **Per-secret approval:** for each `Si`, `Si` is approved iff some candidate approves it —
   - wasm rule contributes approval for `Si` only if `Si ∈ rule.trained`;
   - declarative rule that matched contributes approval for **all** `Si` in the ask.
   Apply the existing specificity/precedence resolution *per secret*.
5. **Aggregate:** ask approved iff **all** `Si` approved; else fall through to prompt (`Pass` = no opinion, as today).

## Open items / decisions

- **Declarative rule secret-responsibility:** confirmed as "all secrets in the matched ask" (decision 2A). No `trained_secrets` scoping added to declarative rules.
- **Partial resolution (nice-to-have, not required):** if 2 of 3 secrets auto-approve, could we prompt for *only* the third? Depends on whether secreq's injection layer can grant an ask **partially** or whether an ask is atomic at the process boundary. If atomic → any uncovered secret means prompt-for-whole-ask. Verify before promising partial UX.
- **Conflict resolution reuse:** the existing deny-beats-approve + `WASM_DECISION_SPECIFICITY` / most-specific-approve logic is re-expressed to run *per secret* then AND, rather than once over the whole ask.
- **Cost:** every overlapping rule now runs (vs. the gate short-circuiting most), so more wasm instantiations per multi-secret ask. Rules are few and each eval is fuel-bounded, so expected negligible — but note it.
- **Audit/UX win captured:** per-secret decisions are more auditable — the audit log records *which rule blessed which secret* (per-secret approver attribution on `approve+auto` rows). Surfacing this in the manager UI Rules tab is a follow-up.

## Code touch-points

- `src/rules.rs` — `evaluate()`, restructured into per-secret approval aggregation; `trained_secrets_allow()` subset-gate replaced with per-secret intersection scoping (wasm) and a retained declarative-only subset guard.
- `src/rules.rs` — `Rule.trained_secrets`.
- `src/wasm_rules.rs` — the wasm ABI/eval (unchanged: modules still return a single `Decision`; only the host's *interpretation* of `Approve` changes).
- `src/audit.rs`, `src/daemon/proto.rs`, `src/daemon/client.rs`, `src/daemon/server.rs`, `src/commands.rs` — carry per-secret approver attribution (`RuleHit.approvals` → `DaemonMsg::Decision.approvers` → `ConsentOutcome.approvers` → `AuditEntry.approvers`).
- `src/daemon/ui.rs` — Rules tab per-secret provenance display: **deferred** (would require regenerating the wgpu screenshot fixtures).
