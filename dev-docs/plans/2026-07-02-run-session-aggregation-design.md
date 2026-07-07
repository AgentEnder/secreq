# Session Ask Aggregation for Nested `run` — Design

> Status: **Design complete.** Brainstormed 2026-07-02; ready for an
> implementation plan.
> Builds on the nested-run cache-skip
> (`2026-06-29-secreq-run-design.md` §7): the cache-skip handles the
> *sequential* case; this handles the *concurrent* case.

## 1. Problem

Sibling `secreq run` invocations under one run tree (e.g. a script that
launches several `secreq run -- …` in parallel) each open their own
consent prompt. When two siblings request the **same** secret, the user
is asked to approve the same data point more than once. And today's
coalescing can't help: `resolve()` broadcasts the *representative's*
secrets to every coalesced waiter — correct for `x` (identical secret
sets) but wrong for `run`, where siblings request different secrets.

## 2. Goal

One consent prompt per run tree's *concurrent* burst: the daemon
aggregates same-session run asks into a **single live card** whose secret
list is the **union**, the user approves once, and each waiter receives
**only its own** secrets. Duplicate requests for the same data point
collapse to one card entry and one provider call.

Non-goals (YAGNI): no inter-run IPC (the daemon is the aggregator); no
session grant covering future/unlisted secrets (approval covers the union
shown at click time); no artificial aggregation-window timer (merge into
the pending card as siblings arrive).

## 3. Decisions (from brainstorming)

- **Aggregator = the daemon, keyed by session.** Runs connect to the
  daemon as today; the `SECREQ_RUN_SESSION` token (already propagated
  tree-wide by the cache-skip work) groups the tree. No run↔run IPC.
- **Approval covers the union shown at approval time.** A *new, uncached*
  secret arriving after approval is handled by the existing rules
  (cached → nested skip; uncached → a fresh card that can itself
  aggregate). No open-ended session grant.
- **Per-secret provenance in the card.** Each secret is annotated with
  the command that requested it (`← ./worker`), because you're approving
  a batch spanning sibling commands.

## 4. How it composes with the cache-skip

| Case | Handled by |
|---|---|
| Later sibling rides a value a prior sibling cached (**sequential**) | nested cache-skip (`nested_run_fully_cached`) — never enters the queue |
| Concurrent siblings requesting secrets while a card is pending | **this feature** — session aggregation |

Order in `handle_ask`: cached-approval → rules → nested-cache-skip →
enqueue (**session coalescing happens here**). So a fully-cached nested
run skips entirely; only *uncached* nested runs reach aggregation.

## 5. Mechanic

```
Session token (minted by the root run) = "rootpid:nonce" — a stable,
unique per-tree identity, propagated via SECREQ_RUN_SESSION.

Client (commands::run):
  • Top-level run → normal dedupe_key (its own direct parent). Prompts
    alone; never aggregates.
  • Nested run    → dedupe_key = { wrap:"run", ppid:rootpid,
                    parent_start_time:nonce } parsed from the token.
    ⇒ every descendant of one tree yields the SAME dedupe_key, so the
      daemon's existing queue coalesces them into one entry — reliably,
      regardless of subshell structure (which the direct-parent key
      can't guarantee).

Daemon (generalize coalescing — the one real change):
  On coalesce:  UNION the incoming ask's secrets into the entry, and
                record the waiter WITH its own requested secrets +
                source command.
  On resolve:   resolve the UNION once (singleflight dedupes provider
                calls → one `op` unlock for the batch), then send each
                waiter back ONLY its requested (name→value) slice.
```

**Behavior-preserving for `x`:** every `gh` invocation requests the
identical set, so union = each waiter's set and each gets all of it —
today's result. Only heterogeneous `run` asks exercise the subset path.

Data-model change: `QueueEntry.waiters` grows from `Vec<Sender>` to
`Vec<Waiter>` where `Waiter = { sender, requested: Vec<SecretAsk>,
command: Vec<String> }`. The representative's secret list becomes the
live union (each entry remembers its source command for the card
annotation). No `QueueKey` enum, no strictly-required new wire field —
the dedupe key carries the session; each waiter's requested secrets come
from its own ask.

### Session token encoding

The root mints `ppid = std::process::id()`, `nonce = random u64`, token
= `"{ppid}:{nonce}"`. A nested run parses it back into the dedupe key.
`parent_start_time` holds the nonce (opaque to the daemon — used only for
grouping), which is why two trees never collide and one tree always
coalesces.

## 6. UI — the live-updating session card

Session asks coalesce into one queue entry → render as **one card** under
the representative's process node. `broadcast_consent_update` already
repaints on each merge, so the card grows live — no "re-show," an
in-place extend.

```
┌─ secreq run · session ───────────────  ×3 waiting ──┐
│  ↳ under deploy.sh (pid 6042)                        │
│   • DATABASE_URL   op        Work/PG/url    ← ./migrate
│   • STRIPE_KEY     keychain  stripe-live    ← ./worker
│   • REDIS_URL      op        Work/Redis/url ← ./worker
│                                    [Approve all] [Deny]│
└──────────────────────────────────────────────────────┘
```

Two additions over today's run card: **per-secret `← command`
provenance** (each union entry remembers its source `Ask.command`), and
**session framing** (the `×N waiting` pill now means "N sibling runs
merged"). One **Approve all** / **Deny** covers the union.

## 7. Security & edge cases

- **Per-waiter isolation (load-bearing).** A waiter receives *only* the
  secrets its own ask requested. Defense in depth: the daemon filters
  each reply to the waiter's `(name, provider, locator)` set, **and** the
  run client injects only env vars it has refs for. A bug here would leak
  a sibling's secret into the wrong child's env — the primary test target.
- **Partial failure.** If one union secret fails to resolve, only waiters
  needing *that* secret get the error; others still succeed (per-waiter
  result assembly, not all-or-nothing).
- **Name collision across siblings.** `FOO=secret://op/a` (A) and
  `FOO=secret://op/b` (B): two distinct union entries, both shown with
  provenance, each waiter gets its own. Same name + same ref collapses to
  one entry / one provider call.
- **Late sibling** (arrives after Approve, entry removed): forms a fresh
  ask; an in-flight secret makes it wait on the singleflight slot (no
  second prompt); a cached one is served by the nested cache-skip.
- **Deny** covers the whole session; every waiter exits 1.
- **Audit** granularity unchanged: each run writes its own client-side
  row for its own slice.

## 8. Testing

- **Daemon unit (security):** two coalescing asks with *different*
  secrets → union built; each waiter receives exactly its subset and
  **not** the other's.
- **Daemon unit (no regression):** `x` coalescing — identical secrets →
  each waiter gets all of them (today's behavior).
- **Daemon unit:** per-secret partial failure isolates to affected
  waiters.
- **Daemon unit:** the representative secret list equals the union after
  merges (drives the card).
- **Screenshot fixture:** the aggregated multi-command session card, with
  per-secret `← command` provenance and the `×N waiting` pill (+ README
  row).

## 9. New / changed code (preview)

| Item | Kind |
|---|---|
| `Ask` dedupe-key derivation in `commands::run` (nested → session-derived key) | change |
| Session token format `"pid:nonce"` (root mints; nested parses) | change |
| `QueueEntry.waiters: Vec<Waiter{sender, requested, command}>` | change |
| `submit_ask`: union secrets on coalesce; record per-waiter requested + command | change |
| `resolve()`: resolve union, reply per-waiter subset | change |
| Consent card: per-secret `← command` provenance + session framing | change (new visual state → fixture) |
