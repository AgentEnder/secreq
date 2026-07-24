# Rule-facing ask subjects: close the empty-`secrets` guard bypass

**Date:** 2026-07-23
**Status:** designed, not yet implemented

## Problem

An SSH sign ask reaches the auto-rules engine declaring **no requested
secrets**, and the trained-secrets guard treats that as "in scope for
everything".

```rust
// src/rules.rs
fn trained_secrets_allow(rule: &Rule, ctx: &EvalCtx) -> bool {
    rule.trained_secrets.is_empty()
        || ctx.requested_secret_names.iter().all(|n| rule.trained_secrets.contains(*n))
}
```

`.all()` over an empty iterator is vacuously `true`. `sign_ask`
(`src/daemon/ssh_agent.rs`) builds `secrets: Vec::new()` — deliberately,
since an SSH sign resolves nothing — and `evaluate_rules_for_ask`
(`src/daemon/state.rs`) maps that straight to an empty
`requested_secret_names`.

Consequence: **every registered rule is consulted for every SSH sign,
regardless of what it was trained on.** A rule registered
`--secret GITHUB_TOKEN` is handed SSH signing asks.

The three existing guard tests cover a widening ask, a subset ask, and an
empty *trained* set. None covers an empty *requested* set, so the
behaviour is emergent rather than intended — and it contradicts the
guard's stated purpose, which
`trained_secrets_guard_blocks_rule_when_ask_widens` describes as stopping
the user from "silently leak[ing] the new env var they never approved".

The user-visible symptom: an SSH rule can only be registered with
`--all-secrets`, because no `--secret` value can ever match an ask that
declares nothing.

## Non-goal: scoped-agent asks

`agent_ask` (`src/scoped_agent/mod.rs`) also builds `secrets:
Vec::new()`, but scoped-agent asks **never reach the rules engine** —
`evaluate_rules_for_ask` has exactly two call sites, `ssh_agent.rs` and
`server.rs`. There is no bypass to fix.

Wiring guest asks into auto-rules would grant a genuinely new capability,
and the current design appears to withhold it on purpose:
`AgentAskInfo`'s doc comment keeps the guest-claimed chain out of
`Ask::callers` "precisely so it cannot be mistaken for provenance:
`callers` is kernel-sourced and is what `rules.rs` matches on, and a
guest able to write there could name a process that fires an
auto-approve rule". A guest is the principal least suited to minting
silent approvals. Out of scope; decide separately if ever.

## Design

### 1. Rename the rule-facing field

`requested_secret_names` → `secrets`, for symmetry with `Ask.secrets` and
with the audit row's existing `secrets` field. Nothing is shipped and no
wasm rule is registered, so the old name is removed outright — no
compatibility shim.

| surface | before | after |
| --- | --- | --- |
| `EvalCtx` | `requested_secret_names: &[&str]` | `secrets: &[&str]` |
| ctx JSON (wire) | `"requested_secret_names"` | `"secrets"` |
| SDK (`ctx.ts`) | `requestedSecretNames` | `secrets` |

### 2. Derive the SSH subject at ctx-construction time

An SSH sign reports `["ssh:<key_id>"]` — the same identity string
`sign_ask` already builds for `dedupe_key.wrap`, so one spelling across
the ask, the audit row and the rule.

The subject is derived in `evaluate_rules_for_ask`, **not** pushed into
`Ask.secrets`. That field drives provider resolution (`SecretAsk` carries
`provider` + `locator`, and the daemon runs `retrieve` against it); a
synthetic entry would try to resolve a secret that does not exist.
`Ask.secrets` keeps meaning "secrets to inject"; `EvalCtx.secrets` means
"what this ask wants released".

```rust
// state.rs::evaluate_rules_for_ask
let requested: Vec<&str> = match &ask.ssh {
    Some(ssh) => vec![&ssh_subject],   // "ssh:<key_id>"
    None => ask.secrets.iter().map(|s| s.name.as_str()).collect(),
};
```

`sign_ask` itself is untouched.

**Rejected:** scoping to `SshAskInfo.fingerprint` instead of `key_id`.
More precise — a rotated key would fail closed rather than silently stay
authorized — but brittle. The fingerprint is already on the ask, so a
rule that wants to assert on it can do so in its own logic, which is the
more flexible place for it.

### 3. Guard logic is unchanged

No edit to `trained_secrets_allow`. Once `secrets` is populated,
`["ssh:github"]` is simply not a subset of `{GITHUB_TOKEN}` and the rule
stops being consulted. Containment starts holding uniformly.

Registration becomes:

```sh
secreq rules add-wasm ssh-github-guard.wasm --name "ssh github read-only" --secret ssh:github
```

`--all-secrets` stays — still the honest way to register a genuinely
cross-wrap rule, just no longer the only door for SSH.

`Rule.trained_secrets` and the `--secret` flag keep their names. They now
hold values like `ssh:github`, which is the same looseness being removed
from `EvalCtx`; carrying the rename through to them is a follow-up if
wanted.

## Implementation order

1. **RED** — add `trained_secrets_guard_blocks_ask_declaring_no_secrets`
   to `rules.rs`. Fails today.
2. **GREEN** — derive the SSH subject in `evaluate_rules_for_ask`.
3. **REFACTOR** — the rename, across `rules.rs`, `wasm_rules.rs`,
   `recommendations.rs`, `state.rs`, SDK `ctx.ts` / `json.ts` /
   `README.md`, `docs/wasm-rules.md`, and the SDK's
   `examples/npm-publish-guard` spec. Green throughout.
4. Update the three spec ctx-builders in `~/.secreq/rules-src`, rebuild,
   re-run its 44 specs.
5. Re-run the audit replay; verdict counts must be unchanged (284 of 412
   SSH asks approved, 0 mutating `gh api` calls approved).

## Verification

`cargo test`, `npm test` in the SDK example and in `rules-src`, then the
replay harness over `~/.secreq/audit.log`.

The replay matters specifically because a botched rename would leave
every rule seeing an empty `secrets` list and still compile cleanly — the
unit tests would not catch it, but the replay would.

## Note on `audit.log`

Not strictly JSONL: concurrent appends pack several records onto one line
(`…}{"ts_unix"…`), affecting ~1.5% of lines. `jq` reads it fine; a
per-line `JSON.parse` silently drops those rows. Any analysis tooling
must split on top-level brace depth and assert its record count against
`jq -c . audit.log | wc -l`.
