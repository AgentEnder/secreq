# Pending-resolution UI (provenance for cold-cache biometric prompts)

Date: 2026-06-04

## Problems

1. **Daemon idle-exit too aggressive.** `IDLE_EXIT_SECS` was 30 min.
   When the daemon idle-exits it drops the in-memory encrypted secret
   cache, so the user is re-prompted for biometric sooner than they
   expect. Fixed by raising it to 2 h (`src/daemon/mod.rs`). No
   structural change; see that commit/diff.

2. **Cold-cache biometric prompts have no on-screen provenance.** A
   provider call (`op read` etc.) only fires on a *secret-cache miss*,
   inside `resolve_for_ask`. Three approval paths reach that miss
   without ever showing the consent window:
   - **Manual approve** (`State::resolve`): the queue card is removed
     *synchronously* before the off-thread resolve runs, so the card
     vanishes and the biometric prompt pops over an empty screen.
   - **Approvals-cache hit** (`handle_ask` fast path): resolves with no
     queue entry and — worse — *holds the state mutex across the
     provider call*, so the consent child can't even attach.
   - **Auto-rule approve** (`handle_rule_hit`): resolves on the
     connection thread with no UI.

   In all three, on a cold cache the user sees a Touch ID prompt with
   no diagram explaining *why* — "looks weird."

## Desired flows (from the issue)

```
ask -> not auto-approved -> ui -> approved -> [resolving] -> cleared
ask -> auto-approved -> if !cached -> [resolving] -> cleared
```

## Design: a `Resolving` request state

There was no per-request lifecycle state; a request was either *in the
queue* (rendered) or *gone*. We add a third state, **`Resolving`**, that
occupies the gap between *authorized* and *secret-cached*. While an ask
is resolving, its card stays on screen (same process-tree "approval
diagram") with a `Resolving…` pill in place of the Approve/Deny
buttons, so any biometric prompt has its provenance behind it.

### Wire / data model

- `proto.rs`: new `enum RowStatus { Awaiting (default), Resolving }`,
  `#[serde(default)]`. Add `status: RowStatus` to `WireQueueRow`.
- `state.rs`: add `status: RowStatus` to `QueueRow`. New private
  `struct PendingEntry { representative: Ask, since: Instant }` and a
  `pending: HashMap<DedupeKey, PendingEntry>` field on `State`.

### State lifecycle

- `begin_pending(&mut self, ask)` — insert (idempotent per dedupe key),
  `show_window()`, reset auto-hide clock, broadcast. Drives the card.
- `end_pending(&mut self, key)` — remove, refresh auto-hide, broadcast.
- `snapshot()` / `snapshot_for_wire()` merge `queue` rows (Awaiting) +
  `pending` rows (Resolving).
- `needs_consent_window()` and `refresh_queue_empty_since()` treat
  `pending` as "not empty" so the window appears/stays while resolving.
- New `pub(super) fn ask_fully_cached(ask, &cache) -> bool` — true iff
  every secret is already cached (so resolving fires no provider, hence
  no biometric, hence no need for a pending card). Vacuously true for a
  gate-only ask.

### Three call paths, one rule: *show pending iff approved && !cached*

- **Manual approve** — `State::resolve` gains a `&SharedState` param
  (its sole caller is `server.rs`). When the approved ask is cold, it
  moves the entry into `pending` instead of dropping it, then the
  off-thread worker clears it via the handle after resolution.
- **Approvals-cache hit** — `handle_ask` no longer calls the old
  `try_cache_hit` (which held the lock across resolution). It checks
  authorization (`has_cached_approval`), drops the lock, then routes
  through the shared `resolve_approved_with_pending` helper, stamping
  `ApproveCached`.
- **Auto-rule approve** — `handle_rule_hit`'s Approve arm routes
  through the same helper, stamping `ApproveAuto`.

`resolve_approved_with_pending(ask, decision, cache, in_flight, state)`
(server.rs): if cold, `begin_pending` + `ensure_consent_window`; run
`resolve_for_ask` *without the lock held*; if cold, `end_pending`.

### Rendering (`ui.rs`)

- `render_wrap_card_body`: branch on `row.status`. `Resolving` shows a
  `Resolving…` pill instead of Approve/Deny; the rest of the card
  (audit line, secret list / gate-only marker, cwd) renders unchanged.
- `render_node_header`: suppress the node-level "Approve all / Deny all"
  buttons when the whole subtree is `Resolving`.
- `collect_subtree_actions`: skip `Resolving` rows (defensive — a
  resolve on a non-queued key is already a no-op).
- `observe_pending` is intentionally left to include resolving rows:
  when the window is *raised* for an auto-approved resolve, pinning to
  the Pending tab is the desired behavior.

### Tests / fixtures

- Per `CLAUDE.md`: new screenshot fixture `23-pending-resolving`
  exercising a single resolving card; regenerate all fixtures; inspect;
  add the README table row.
- Update `child.rs` wire→`QueueRow` conversion and all `QueueRow`
  literals in `ui.rs` unit tests with the new `status` field.

## Out of scope

- No refcount on `pending` for concurrent sibling resolves: the card
  showing/clearing a touch early is harmless (the value is cached by
  the time the first finisher clears it).
- **Transient double-card (cosmetic, pre-existing race).** If an ask is
  approved *without* remembering and an identical dedupe key re-arrives
  during the seconds-long resolve window, `submit_ask` creates a fresh
  Awaiting card while the first is still a Resolving card — two cards,
  same key. This is correct-by-design (the second invocation genuinely
  needs its own consent, since nothing was remembered) and has no
  secret/correctness impact: each resolves independently and the
  in-flight singleflight still collapses the provider call. The same
  race already produced a second *queue* entry before this change; the
  Resolving card just makes it visible. Adversarial review (8 findings,
  0 confirmed) flagged and then dismissed it on these grounds.
