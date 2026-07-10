# Session Ask Aggregation — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Aggregate concurrent same-session `secreq run` asks into one live daemon consent card (union of secrets), approved once, with each waiter receiving only its own secrets.

**Architecture:** The root run mints a session token `"pid:nonce"` (already propagated tree-wide via `SECREQ_RUN_SESSION`). A nested run derives its daemon dedupe key from the token, so every descendant of one tree coalesces into one queue entry via the *existing* coalescing. We then generalize coalescing: union the secrets on merge, track each waiter's own requested secrets + source command, and on resolve send each waiter only its slice. The card renders the growing union with per-secret `← command` provenance.

**Tech Stack:** Rust, the daemon's `mpsc`-based queue/waiter model, `egui` consent card, `rand` (already a dep) for the nonce.

**Design doc:** `dev-docs/plans/2026-07-02-run-session-aggregation-design.md` — read first.

**Key existing code:**
- `src/commands.rs::run` — mints/propagates `SECREQ_RUN_SESSION`, builds the run `Ask`. Session detection at the top; `ask.nested_run` set before `request_consent`.
- `src/daemon/state.rs`: `QueueEntry` (37, `waiters: Vec<mpsc::Sender<WaiterReply>>`), `submit_ask` (824), `resolve` (873, resolves representative + broadcasts), `resolve_for_ask` (1346, cache+singleflight, returns name-keyed `WaiterReply`), `WaiterReply` (62).
- `src/daemon/proto.rs`: `Ask` (175), `SecretAsk` (251), `DedupeKey` (230).
- `src/daemon/ui.rs`: `render_card_secret` (3705).
- `src/lib.rs`: `RUN_SESSION_ENV` (const).

**Conventions:** `cargo fmt` + `cargo clippy --all-targets -- -D warnings` (zero warnings) + relevant tests before each commit. TDD: failing test first. Commit per task.

---

### Task 1: Session token `"pid:nonce"` + nested dedupe-key derivation

Make the session token carry a stable per-tree identity and have a nested run key its ask on it (so descendants coalesce).

**Files:**
- Modify: `src/commands.rs` (the `run` session block; add two helpers)
- Test: `src/commands.rs` (`#[cfg(test)]`)

**Step 1: Write the failing tests**

```rust
#[test]
fn session_token_round_trips_to_a_dedupe_key() {
    // "pid:nonce" → DedupeKey { wrap:"run", ppid:pid, parent_start_time:nonce }
    let key = session_dedupe_key("6042:12345678901234567890");
    assert_eq!(
        key,
        Some(proto::DedupeKey {
            wrap: "run".to_owned(),
            ppid: 6042,
            parent_start_time: 12345678901234567890,
        })
    );
    assert_eq!(session_dedupe_key("garbage"), None);
    assert_eq!(session_dedupe_key("6042"), None); // needs both halves
}

#[test]
fn minted_session_token_parses_back() {
    let token = mint_session_token();
    let key = session_dedupe_key(&token).expect("minted token must parse");
    assert_eq!(key.wrap, "run");
    assert_eq!(key.ppid, std::process::id());
}
```

**Step 2: Run to verify failure**

Run: `cargo test --lib commands::tests::session_token`
Expected: FAIL — helpers undefined.

**Step 3: Implement**

Add to `src/commands.rs`:

```rust
/// Mint a run-session token for a root run: `"<pid>:<nonce>"`. The pid
/// aids debugging; the random nonce guarantees two trees never collide
/// (and one tree always coalesces, since descendants inherit it verbatim).
fn mint_session_token() -> String {
    use rand::RngCore;
    let nonce = rand::thread_rng().next_u64();
    format!("{}:{}", std::process::id(), nonce)
}

/// Parse a session token into the dedupe key every descendant run of the
/// tree shares. `parent_start_time` holds the nonce — opaque to the
/// daemon, used only to group same-session asks into one queue entry.
fn session_dedupe_key(token: &str) -> Option<proto::DedupeKey> {
    let (pid, nonce) = token.split_once(':')?;
    Some(proto::DedupeKey {
        wrap: "run".to_owned(),
        ppid: pid.parse().ok()?,
        parent_start_time: nonce.parse().ok()?,
    })
}
```

Then in `run()`, change the session block so:
- `mint`/propagate uses `mint_session_token()` when not nested (was `std::process::id().to_string()`).
- When nested, after building the ask, override its dedupe key:
  ```rust
  ask.nested_run = nested;
  if let Some(key) = session_dedupe_key(&session) {
      ask.dedupe_key = key;
  }
  ```
  (Place right after the existing `ask.nested_run = nested;`.)

Note `session` is already `let session = std::env::var(RUN_SESSION_ENV).unwrap_or_else(|_| …)`; swap the fallback to `mint_session_token()`.

**Step 4: Run to verify pass**

Run: `cargo test --lib commands` && `cargo build`
Expected: PASS; existing run/marker tests still green.

**Step 5: Commit**

```bash
git add src/commands.rs
git commit -m "feat(run): session token carries a nonce; nested runs key on it"
```

---

### Task 2: Introduce `Waiter` (mechanical, behavior-preserving)

Change `QueueEntry.waiters` from bare senders to a struct that also holds each waiter's requested secrets and source command. Keep behavior identical for now (still broadcasts the representative's secrets).

**Files:**
- Modify: `src/daemon/state.rs` (`QueueEntry`, `submit_ask`, `resolve`, any waiter iteration)

**Step 1: Write the failing test**

```rust
#[test]
fn submit_ask_records_waiter_requested_and_command() {
    let mut state = State::new_for_test(); // use the real constructor the tests use
    let ask = ask_with_secret("run", &["run", "./worker"], "TOKEN");
    let (tx, _rx) = std::sync::mpsc::channel();
    state.submit_ask(ask.clone(), tx);
    let entry = state.queue_entry_for_test(&ask.dedupe_key).expect("entry");
    assert_eq!(entry.waiters.len(), 1);
    assert_eq!(entry.waiters[0].requested, ask.secrets);
    assert_eq!(entry.waiters[0].command, ask.command);
}
```

(Adapt `State::new_for_test` / add a small `queue_entry_for_test(&key)` accessor if none exists — match how existing state tests reach into the queue.)

**Step 2: Run → fail** (`.requested`/`.command` don't exist).

**Step 3: Implement**

```rust
/// One parked client on a queue entry: where to send its reply, the
/// secrets *it* asked for (so it receives only its own slice), and the
/// command it's running (for the card's per-secret provenance).
pub struct Waiter {
    pub sender: mpsc::Sender<WaiterReply>,
    pub requested: Vec<SecretAsk>,
    pub command: Vec<String>,
}
```

- `QueueEntry.waiters: Vec<Waiter>`.
- `waiter_count()` → `self.waiters.len()` (unchanged).
- `submit_ask`: push `Waiter { sender: waiter, requested: ask.secrets.clone(), command: ask.command.clone() }` (do this both on new-entry and coalesce paths).
- `resolve`: everywhere it iterates `entry.waiters` sending replies, iterate and send on `w.sender` (still the same reply to all — union == representative for now).

**Step 4: Run → pass.** `cargo test --lib daemon::state` and `cargo build` green (all existing coalescing tests still pass — behavior unchanged).

**Step 5: Commit**

```bash
git add src/daemon/state.rs
git commit -m "refactor(daemon): waiters carry their requested secrets + command"
```

---

### Task 3: Union secrets on coalesce

When a second ask joins an entry, merge its secrets into the representative's list (deduped by `(name, provider, locator)`), stamping each with the requesting command for provenance.

**Files:**
- Modify: `src/daemon/proto.rs` (`SecretAsk`: add provenance field)
- Modify: `src/daemon/state.rs` (`submit_ask` union logic)
- Test: `src/daemon/state.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn coalescing_unions_heterogeneous_secrets_with_provenance() {
    let mut state = State::new_for_test();
    let a = ask_with_secret_named("run", &["run", "./migrate"], "DB", "op", "pg");
    let b = ask_with_secret_named("run", &["run", "./worker"], "API", "op", "stripe");
    // Same dedupe key (same session) so they coalesce:
    let b = with_dedupe_key(b, a.dedupe_key.clone());
    let (tx1, _r1) = std::sync::mpsc::channel();
    let (tx2, _r2) = std::sync::mpsc::channel();
    state.submit_ask(a.clone(), tx1);
    state.submit_ask(b.clone(), tx2);
    let entry = state.queue_entry_for_test(&a.dedupe_key).unwrap();
    let names: Vec<&str> = entry.representative.secrets.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["DB", "API"], "union preserves both, in arrival order");
    // provenance stamped:
    assert!(entry.representative.secrets[0].requested_by.contains(&"./migrate".to_owned()));
    assert!(entry.representative.secrets[1].requested_by.contains(&"./worker".to_owned()));
}
```

(Add tiny helpers `ask_with_secret_named(wrap, argv, name, provider, locator)` and `with_dedupe_key(ask, key)` in the test module.)

**Step 2: Run → fail.**

**Step 3: Implement**

In `proto.rs`, add to `SecretAsk`:
```rust
    /// Commands that requested this secret (for the session card's
    /// `← command` provenance). Empty on the wire from the client; the
    /// daemon stamps it as asks merge. `#[serde(default)]`.
    #[serde(default)]
    pub requested_by: Vec<String>,
```
Update all `SecretAsk { … }` literals (client `build_ask`, tests, fixtures) with `requested_by: vec![]` — the compiler lists them.

In `submit_ask`:
- On **new entry**: stamp each representative secret's `requested_by` with `ask.command.join(" ")` (or the last argv element — pick a short label; the plan uses the full joined command, truncated in the UI).
- On **coalesce**: for each secret in the incoming `ask.secrets`, if an entry secret with the same `(name, provider, locator)` exists, append the incoming command to its `requested_by` (dedup); else push the secret (stamped with the incoming command) onto `representative.secrets`.

Extract a helper `fn merge_secret(rep: &mut Vec<SecretAsk>, incoming: &SecretAsk, command: &str)`.

**Step 4: Run → pass.** Confirm `x` tests unaffected (identical secrets → union == the one set; `requested_by` gains the command but nothing else changes).

**Step 5: Commit**

```bash
git add src/daemon/proto.rs src/daemon/state.rs
git commit -m "feat(daemon): union secrets across coalesced session asks with provenance"
```

---

### Task 4: Per-waiter subset resolution (the security core)

Resolve the union once, then reply to each waiter with *only* its own secrets — keyed by `(provider, locator)` so same-name-different-ref collisions across siblings stay correct.

**Files:**
- Modify: `src/daemon/state.rs` (`resolve_for_ask` → expose a `(provider,locator)`-keyed resolve; `resolve` per-waiter assembly)
- Test: `src/daemon/state.rs`

**Step 1: Write the failing tests**

```rust
#[test]
fn each_waiter_receives_only_its_own_secret() {
    // A wants DB (op/pg), B wants API (op/stripe); they coalesce.
    // On approve, A's reply has DB and NOT API; B's has API and NOT DB.
    // Drive submit_ask ×2 + resolve(Approve), read both rx.
    // (fake `sh -c` provider echoing resolved-<locator>, per state.rs tests ~2018)
    // assert a_reply.secrets.keys() == ["DB"], b_reply.secrets.keys() == ["API"]
}

#[test]
fn x_style_identical_asks_each_get_the_full_set() {
    // Two asks with the SAME secret set coalesce → both replies carry it.
    // Proves no regression for wrap coalescing.
}

#[test]
fn same_name_different_ref_across_siblings_stays_isolated() {
    // A: FOO=op/a, B: FOO=op/b (same name!). Each waiter's FOO must be its own.
}
```

**Step 2: Run → fail.**

**Step 3: Implement**

- Add a resolution that returns a `(provider, locator) → value` map for a set of `SecretAsk` (reuse the cache + singleflight from `resolve_for_ask`; the cache key is already `(wrap, provider, locator)`). Sketch:
  ```rust
  fn resolve_union(rep: &Ask, cache, in_flight)
      -> Result<HashMap<(String,String), String>, String>
  ```
  Iterate the union's distinct `(provider, locator)`, resolve each (cache-check → singleflight → provider), collect. Preserve the existing failure semantics per key.
- In `resolve`'s approved branch (the spawned worker), call `resolve_union` on `entry.representative`, then for **each waiter** build its reply:
  ```rust
  let mut secrets = HashMap::new();
  for s in &w.requested {
      if let Some(v) = union.get(&(s.provider.clone(), s.locator.clone())) {
          secrets.insert(s.name.clone(), v.clone());
      }
  }
  w.sender.send(WaiterReply::Decision { decision, secrets });
  ```
- **Partial failure:** if a `(provider, locator)` failed, a waiter needing it gets `WaiterReply::Err` (or a Decision missing that key → the client errors on the gap, matching `read`'s "approved but no value" guard). Prefer: a waiter whose full slice resolved gets `Decision`; a waiter missing any of its keys gets `Err{message}` for that key. Keep it per-waiter.

**Step 4: Run → pass.** All three tests + existing `daemon::state` suite green.

**Step 5: Commit**

```bash
git add src/daemon/state.rs
git commit -m "feat(daemon): resolve union once, reply each waiter its own slice"
```

---

### Task 5: Consent card — per-secret provenance + session framing

Show the growing union with each secret annotated by the command that requested it, and reframe the header/pill as a session.

**Files:**
- Modify: `src/daemon/ui.rs` (`render_card_secret` ~3705, and the card header/`×N waiting` context)
- Modify: `tests/ui_screenshots.rs` (new fixture)
- Create: `dev-docs/ui-screenshots/run-session-card.png`
- Modify: `dev-docs/ui-screenshots/README.md`

**Step 1: Render provenance**

In `render_card_secret`, when `!s.requested_by.is_empty()`, append a muted `← {joined}` (truncate to ~30 chars). Guard so a normal `x`/`run` secret with empty `requested_by` renders exactly as before (no regression to existing fixtures).

**Step 2: Session framing**

Where the wrap card header renders the command + `×N waiting` pill: when the representative is a `run` ask with `waiter_count > 1` (a merged session), the `×N waiting` pill already conveys the count. Optionally add a small "· session" tag next to the command. Keep it minimal — the per-secret provenance carries the meaning.

**Step 3: Add the fixture**

In `tests/ui_screenshots.rs`, add `run_session_card`: build one `run` Ask whose `secrets` is a union of 3 entries with distinct `requested_by` (`./migrate`, `./worker`, `./worker`) and a `waiter_count` of 3 (submit 3 asks, or construct the QueueRow directly per the harness pattern). Follow `run_consent_card`.

**Step 4: Regenerate + inspect**

Run: `cargo test --test ui_screenshots -- --ignored --nocapture --test-threads=1`
Open `dev-docs/ui-screenshots/run-session-card.png`: confirm 3 secrets each with `← command`, the `×3 waiting` pill, Approve all/Deny. Open one existing fixture to confirm no regression (empty `requested_by` renders unchanged). If only `07-audit-tab.png` also changed, revert it (known midnight flake).

**Step 5: README row + commit**

Add the table row. Then:
```bash
git add src/daemon/ui.rs tests/ui_screenshots.rs dev-docs/ui-screenshots/
git commit -m "feat(ui): session consent card with per-secret provenance"
```

---

### Task 6: Defense-in-depth client filter + docs + final verification

**Files:**
- Modify: `src/commands.rs::run` (filter resolved to own refs)
- Modify: `README.md` / `docs/cli.md` (a sentence on session aggregation)

**Step 1: Client filter**

In `run()`, after receiving `outcome.secrets`, keep only names present in `refs` before injecting — a second layer so a daemon bug can't inject a sibling's secret. Add a test asserting an extra key in the outcome is dropped (unit-test a small `filter_to_refs(outcome_secrets, &refs)` helper).

**Step 2: Docs**

Add a short note to the `run` docs: concurrent runs in one tree share one consent prompt (union), each command receives only its own secrets.

**Step 3: Full verification**

Run in order, expect all green:
- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `cargo test --test ui_screenshots -- --ignored --test-threads=1`

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(run): defense-in-depth client filter + docs for session aggregation"
```

---

## Done when

- Concurrent same-session `run` asks merge into one live daemon card (union of secrets, per-secret `← command` provenance, one Approve).
- Each waiter receives only its own secrets — verified by the isolation test, including same-name-different-ref siblings.
- `x` coalescing is unchanged (identical secrets → each waiter gets the full set), proven by a regression test.
- Session token `"pid:nonce"` groups a tree reliably regardless of subshell structure; top-level runs never aggregate.
- fmt + clippy + all tests green; new screenshot fixture + README row.
