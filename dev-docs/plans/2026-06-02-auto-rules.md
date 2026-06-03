# Auto Approve/Deny Rules — Design & Implementation Plan

> Status: **Design complete; ready to execute.**
> Date: 2026-06-02
> Companion to: `2026-05-22-secrets-requestor-design.md`

## 1. One-line pitch

A persisted, user-managed ruleset that lets the daemon answer common asks
without prompting — keyed on **wrap × argv pattern × ancestor identity × cwd**
— with a hard "deny wins, rules survive across daemon restarts" semantics.

## 2. Motivating example

> *"Always approve requests to the `gh` wrap where the command being run
> matches `gh api --get /repos/*/pulls/*` and the process tree above it
> contains Cursor.app."*

Without rules, this user clicks Approve dozens of times a day for what's
effectively a single recurring scenario, or learns to use
`ApproveRemember` and accepts that anything else from the same parent
shell will *also* ride that approval. Rules give a third option that's
both more permissive (survives daemon restart) and more precise (matches
on what the request *is*, not just *who* made it).

## 3. Goals / Non-goals

### Goals
- **Persisted policy** that survives daemon restarts.
- **Pre-queue evaluation** — auto-approved asks never flash UI; auto-denied
  asks reply immediately with a configurable message.
- **Auditability** — every auto-decision is logged with the firing rule's
  ID; new `Decision` variants make the pill self-describing.
- **Safe-by-construction matching** — glob (no regex), deny-wins, snapshot
  of trained-on secret set so wrap edits don't silently auto-release new
  env vars.
- **Restart-on-change** — rule file mtime advancing triggers a clean
  daemon shutdown, matching the existing "restart is the revoke
  primitive" invariant from `src/consent.rs:11`.

### Non-goals (intentionally cut)
- **Per-secret partial release.** Wraps ask atomically. No real call site.
- **Regex patterns.** Glob covers every example; regex makes auditing
  harder for negligible gain.
- **Project-scope rules.** User-scope only, consistent with the rest of
  `secreq`.
- **Re-ordering UI.** Precedence is determined by rule *content*
  (deny-wins, then most-specific approve), not ordering.
- **Auto-rule that seeds the in-memory approvals cache.** Every ask
  re-evaluates rules; simpler, edits take effect immediately.

## 4. Trust model — explicit departure from existing invariant

`src/consent.rs:8-12` documents the project's hardest invariant:

> "approvals live for the daemon process's lifetime only, so a daemon
> restart is the way to clear them. This is the security property we
> want — a remembered approval can't outlive the user's awareness of
> what they approved."

Auto-rules deliberately break that invariant for a *different* class of
decision. The user's "awareness of what they approved" is enforced
differently for rules:

1. Rules are created from the UI (or via CLI) — never implicitly.
2. Editing the rule file by hand causes the daemon to restart on the
   next ask, which surfaces freshly via the audit log.
3. The audit log distinguishes rule-fired decisions from user clicks
   via new `Decision` variants (`ApproveAuto` / `DenyAuto`) and a
   `rule_id` field.
4. The "trained secret set" guard (§5) prevents a rule from quietly
   widening as the wrap's env block grows.

## 5. Data model

```rust
// src/rules.rs (new)

pub struct Rule {
    pub id: String,                        // UUID; stable across edits
    pub name: String,                      // user-facing label
    pub enabled: bool,
    pub decide: RuleDecision,              // Approve | Deny
    pub r#match: RuleMatch,
    pub trained_secrets: BTreeSet<String>, // env var names the rule was created against
    pub deny_message: Option<String>,      // only meaningful when decide == Deny
    pub created_at: OffsetDateTime,
}

pub enum RuleDecision { Approve, Deny }

pub struct RuleMatch {
    pub wrap: String,                       // required, exact
    pub argv: Option<Pattern>,              // glob; prefix if no wildcard
    pub ancestor: Option<Pattern>,          // substring against name/command/.app path of any caller
    pub cwd: Option<Pattern>,               // glob; prefix if no wildcard
}

pub enum Pattern {
    Literal(String),  // exact / prefix match
    Glob(glob::Pattern),
}
```

### Pattern semantics

- Argv is the **joined argv string** of the wrapped command
  (`Ask.command.join(" ")`).
- Ancestor is matched **as substring** against each `Caller`'s `name`
  and `command` fields in turn — first match wins. This makes
  `"Cursor.app"` work against a noisy `command` like
  `/Applications/Cursor.app/Contents/MacOS/Cursor --psn_0_12345`.
- Cwd is matched against `Ask.cwd`.
- A pattern with no wildcard characters (`*`, `?`, `[`) is treated as a
  literal — *prefix* for argv/cwd, *substring* for ancestor.

### Evaluation algorithm

```
fn evaluate(ruleset: &[Rule], ask: &Ask) -> Option<RuleHit> {
    let active = ruleset.iter().filter(|r| r.enabled);
    let candidates: Vec<&Rule> = active
        .filter(|r| r.match.wrap == ask.dedupe_key.wrap)
        .filter(|r| matches_optional(&r.match.argv,     joined_argv(ask)))
        .filter(|r| matches_ancestor(&r.match.ancestor, &ask.callers))
        .filter(|r| matches_optional(&r.match.cwd,      &ask.cwd))
        .filter(|r| trained_secrets_guard(&r.trained_secrets, &ask.secrets))
        .collect();

    // Deny wins.
    if let Some(r) = candidates.iter().find(|r| r.decide == RuleDecision::Deny) {
        return Some(RuleHit { rule_id: r.id.clone(), decide: r.decide, deny_message: r.deny_message.clone() });
    }
    // Most-specific approve wins; ties broken by rule id (stable).
    candidates
        .into_iter()
        .filter(|r| r.decide == RuleDecision::Approve)
        .max_by_key(|r| (specificity(&r.match), &r.id))
        .map(|r| RuleHit { rule_id: r.id.clone(), decide: r.decide, deny_message: None })
}

fn specificity(m: &RuleMatch) -> u32 {
    m.argv.is_some() as u32 + m.ancestor.is_some() as u32 + m.cwd.is_some() as u32
}

fn trained_secrets_guard(trained: &BTreeSet<String>, requested: &[SecretAsk]) -> bool {
    requested.iter().all(|s| trained.contains(&s.name))
}
```

## 6. Storage & file format

Path: `$XDG_CONFIG_HOME/secreq/auto-rules.json5` (defaults to
`~/.config/secreq/auto-rules.json5`).

```json5
{
  $schema: "https://…/auto-rules.schema.json",  // optional
  rules: [
    {
      id: "01J9X3K2…",
      name: "Cursor reads via gh",
      enabled: true,
      decide: "approve",
      match: {
        wrap: "gh",
        argv: "gh api --get /repos/*/pulls*",
        ancestor: "Cursor.app",
      },
      trained_secrets: ["GITHUB_TOKEN"],
      created_at: "2026-06-02T14:21:09Z",
    },
    {
      id: "01J9X4P1…",
      name: "Block gh destructive ops",
      enabled: true,
      decide: "deny",
      deny_message: "Destructive `gh` operations are policy-denied. Use `--force-prompt` to override.",
      match: {
        wrap: "gh",
        argv: "gh repo delete *",
      },
      trained_secrets: ["GITHUB_TOKEN"],
      created_at: "2026-06-02T14:23:55Z",
    },
  ],
}
```

### Malformed file behavior

- Daemon starts with **empty ruleset**.
- Writes `WARN: failed to load auto-rules.json5: <err> — continuing with no auto-rules` to stderr.
- No UI surface needed — the empty Rules tab + "0 rules loaded" is the visible signal.

### mtime check & restart on change

`State` gains:
```rust
ruleset_loaded_at: SystemTime,  // mtime read at startup
ruleset: Vec<Rule>,
```

Before each `evaluate_rules` call in the server:
1. `stat` the rules file path.
2. If `mtime > ruleset_loaded_at` (or file existence changed), call
   `State::request_shutdown()` — same path used by `ClientMsg::Shutdown`
   today. The current ask returns a daemon-restart error to the client
   (which will respawn the daemon and re-submit).
3. Next ask spawns a fresh daemon, which loads the new ruleset on
   startup.

This unifies "rule changed" with the existing
"in-memory-approvals-cleared" semantics — both happen on daemon
restart, both are user-visible via the daemon log.

## 7. Wire protocol additions

### `src/daemon/proto.rs`

```rust
pub enum ClientMsg {
    // existing variants…
    ListRules,
    AddRule { rule: WireRule },
    UpdateRule { id: String, rule: WireRule },
    DeleteRule { id: String },
    SetRuleEnabled { id: String, enabled: bool },
}

pub enum DaemonMsg {
    // existing variants…
    Decision {
        decision: Decision,
        secrets: HashMap<String, String>,
        rule_id: Option<String>,     // NEW
        deny_message: Option<String>, // NEW; only Some on DenyAuto with message
    },
    RulesList { rules: Vec<WireRule> },
    // ConsentUpdate snapshot grows: includes ruleset for the Rules tab
}

pub struct WireRule {
    // mirrors Rule but is the serde wire form
}
```

### `src/consent.rs::Decision`

```rust
pub enum Decision {
    Approve,
    ApproveRemember,
    ApproveCached,
    ApproveAuto,     // NEW
    Deny,
    DenyAuto,        // NEW
}

impl Decision {
    pub fn as_str(self) -> &'static str { /* + "approve+auto", "deny+auto" */ }
    pub fn approved(self) -> bool { /* + ApproveAuto */ }
}
```

## 8. Daemon-side flow

### `src/daemon/server.rs`

Insert one step in the `Ask` handler between `try_cache_hit` and
`submit_ask`:

```rust
let state = self.state.lock().unwrap();

// 1. existing in-memory approvals cache
if let Some(reply) = state.try_cache_hit(&ask) {
    return send_reply(reply);
}

// 2. NEW: auto-rule evaluation (also performs mtime restart check)
state.check_ruleset_freshness_or_request_restart()?;
if let Some(hit) = state.evaluate_rules(&ask) {
    drop(state); // resolution may shell out; do not hold mutex
    return handle_rule_hit(hit, &ask, /* … */);
}

// 3. existing: enqueue for user prompt
let waiter = state.submit_ask(ask.clone(), waiter_tx);
```

### `handle_rule_hit`

- **DenyAuto**: write audit row with `Decision::DenyAuto` and `rule_id`;
  reply `DaemonMsg::Decision { decision: DenyAuto, secrets: {}, rule_id, deny_message }`.
- **ApproveAuto**: spawn the existing
  `resolve_for_ask_at_scope(/* scope = direct parent */)` worker;
  on reply, rewrite `Decision::Approve` → `Decision::ApproveAuto` and
  attach `rule_id`. Audit row written by existing audit pipeline.

## 9. CLI client behavior on auto-deny

`src/commands.rs::wrap_run`: existing deny path exits 1 silently. New behavior:

- If `DaemonMsg::Decision` carries `decision == DenyAuto`:
  - print `eprintln!("secreq: denied by rule '{name}': {msg}")` if
    `deny_message` is `Some`, else `eprintln!("secreq: denied by rule '{name}'")`
  - exit 1 (unchanged)

Rule name lookup: include `rule_name` alongside `rule_id` in the reply
to avoid the client needing a round-trip. Cheap; one extra string.

## 10. Audit log changes

### `src/audit.rs`

- New record field `rule_id: Option<String>`.
- Existing `decision: Decision` serialization picks up the new variants
  via `Decision::as_str`.

### UI — audit row rendering

- New pill colors / labels: `[auto-approve]` (subtle green outline,
  distinct from `[approve]`), `[auto-deny]` (subtle red outline).
- When `rule_id` is present, append `— rule: 'Cursor reads via gh'`
  (resolved via the in-memory ruleset; falls back to the rule ID
  if the rule has since been deleted).

## 11. UI changes

### Window default size

`src/daemon/child.rs:92`: bump `with_inner_size([520.0, 480.0])` to
`[760.0, 560.0]`. Three tabs need more horizontal room; the rule form
needs vertical room.

### Tab layout

`Pending | Rules | Audit` (Rules in the middle so the destructive-ish
"Audit" stays rightmost as today).

### Rules tab

```
┌─ Rules ─────────────────────────────────────────────────┐
│ + New rule                                              │
│                                                         │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ [✓] [approve] Cursor reads via gh                ⋮  │ │
│ │     wrap: gh · argv: 'gh api --get /repos/*/pulls*' │ │
│ │     · ancestor: 'Cursor.app'                        │ │
│ │     trained: GITHUB_TOKEN                           │ │
│ ├─────────────────────────────────────────────────────┤ │
│ │ [✓] [deny] Block gh destructive ops              ⋮  │ │
│ │     wrap: gh · argv: 'gh repo delete *'             │ │
│ │     trained: GITHUB_TOKEN                           │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

Per-row `⋮` menu: Edit, Duplicate, Delete. Toggle enables/disables in place.

### Rule form (modal)

```
┌─ New rule / Edit rule ────────────────────────────┐
│ Name:        [ Cursor reads via gh           ]    │
│ Decide:      ( ) approve  (•) deny                │
│ Wrap:        [ gh                             ]   │
│ Argv match:  [ gh api --get /repos/*/pulls*  ]    │
│              hint: glob; blank = any              │
│ Ancestor:    [ Cursor.app                    ]    │
│              hint: substring; blank = any         │
│ Cwd match:   [                                ]   │
│              hint: glob; blank = any              │
│ Deny msg:    [ … shown only when decide=deny … ]  │
│ Trained on:  ⓘ GITHUB_TOKEN                       │
│                                                   │
│              [ Cancel ]  [ Save ]                 │
└───────────────────────────────────────────────────┘
```

### Audit-row → rule seeding

Each audit row gets a `⋮` menu with `Create rule from this ask…`.
Opens the rule form pre-populated with:
- `wrap` from the row's wrap
- `argv` (initially the row's argv verbatim; user trims)
- `ancestor` (first ancestor name)
- `cwd`
- `trained_secrets` from the row's requested secret set
- `decide` defaults to whatever the audit row decided (so seeding from
  a manual approve produces an `Approve` rule)

### Auto-deny toast

When a `DenyAuto` is broadcast, the consent window (if running) renders
a transient toast row at the top of the Pending tab for ~5s:

```
[auto-denied] gh repo delete me/x — rule: 'Block gh destructive ops'
              "Destructive gh operations are policy-denied."
```

If the consent window is **not** running at the time, no toast — the
terminal message and audit row are sufficient (we don't spawn a window
just for a deny notification).

## 12. CLI surface (headless rule management)

Optional but cheap, mirrors `wraps` / `wrap` / `unwrap`:

```
secreq rules                       # list (table)
secreq rules show <id|name>        # show one rule, full
secreq rules disable <id|name>     # set enabled=false
secreq rules enable <id|name>      # set enabled=true
secreq rules rm <id|name>          # delete
```

`secreq rules add` deferred — the form-driven UI is the primary path,
and a CLI `add` would need a flag for every field. Hand-editing the
JSON5 file remains supported.

## 13. Implementation order

Land in slices; each slice is independently shippable + reviewable.

1. **rules.rs core (no daemon wiring).**
   - Data model, parser (`parse_rules_file`), pattern matcher,
     evaluator. Unit tests cover: deny-wins, specificity-tie-break,
     trained-secret guard, glob vs literal-prefix, ancestor substring
     against noisy `.app` strings, missing file = empty ruleset, malformed
     file = empty + warn.
   - Decision enum additions, `Decision::as_str` / `approved`.

2. **Wire protocol + audit shape.**
   - New ClientMsg variants stubbed (handlers `Err("not implemented yet")`).
   - `Decision` extension propagated through proto.
   - Audit row gains `rule_id`.

3. **Daemon evaluation step.**
   - `State::load_rules_on_startup`, `State::check_ruleset_freshness_or_request_restart`,
     `State::evaluate_rules`.
   - Pre-queue step in server.
   - CLI client surfaces auto-deny message + exits 1.
   - **Test by hand-editing rules file and running wraps. No UI yet.**

4. **Rules tab UI.**
   - Window size bump.
   - New tab + list rendering + enable toggle + delete.
   - Rule form modal: create + edit.
   - Wire to AddRule / UpdateRule / DeleteRule / SetRuleEnabled.

5. **Audit row "create rule from this" + auto-deny toast.**

6. **Optional: CLI `secreq rules …` verbs.**

7. **Schema + drift test.**
   - `docs/auto-rules.schema.json` regenerated.
   - Existing `tests/schema_drift.rs` extended.

## 14. Test plan

### Unit (in `src/rules.rs`)
- Glob: `"gh api --get /repos/*/pulls*"` matches `"gh api --get /repos/me/x/pulls/3"`; rejects `"gh repo delete"`.
- Literal-prefix: `"gh api"` matches `"gh api --get ..."`; doesn't match `"gh repo ..."`.
- Ancestor substring against `Caller.command = "/Applications/Cursor.app/Contents/MacOS/Cursor"` with pattern `"Cursor.app"`.
- Deny-wins: approve + deny both match, evaluator returns deny.
- Specificity tie-break: two approves with equal specificity return the one whose id sorts first.
- Trained-secrets guard: ask requests `{A, B}`, rule trained on `{A}` — no hit.
- Disabled rule does not match.
- Wrap mismatch short-circuits before pattern evaluation.

### Integration (`tests/`)
- End-to-end with a fixture rules file: spawn wrap, observe auto-approve reply path (no UI launched).
- Auto-deny path: observe `secreq` exits 1 with the configured stderr message.
- mtime-change restart: write rules file mid-run, observe daemon shutdown on next ask.
- Malformed rules file: daemon starts, stderr warning emitted, no rules loaded.
- Schema drift test for `auto-rules.schema.json`.

### Manual smoke
- Create rule from audit row, verify next matching ask auto-approves.
- Toggle rule disabled, verify the same ask now prompts.
- Edit rule file by hand, verify daemon restart message and fresh load.
- Verify auto-deny toast in the consent window when one is open.
- Verify default window size shows all three tabs comfortably.

## 15. Open items deferred to later iterations

- ~~**Dry-run preview**~~ — landed inverted as the recommendation
  engine in §16: instead of scoring a proposed rule against history,
  cluster history and *suggest* rules.
- **Wildcard wrap matching** (e.g. rules that apply to all wraps).
  Out for v1 — too easy to footgun.
- **Per-rule cooldown / rate-limit** (auto-approve at most N times per
  M minutes). Out for v1.
- **Rule export / import** (share rules across machines). Out for v1.

## 16. Recommendation engine (post-v1)

### Pitch

The Rules tab grows a "Suggested rules" section above the existing
list. The engine clusters recent audit entries by
`(wrap, first_caller.name, decision_side)`, merges per-cluster argv
shapes into a single glob, and offers one card per cluster with a
"Review & save" affordance that funnels into the existing rule form.

The goal is to make the rules feature self-onboarding: a user who's
been clicking Approve for the same `gh api … /commits/*/statuses`
shape forty times this week shouldn't have to think *"I should write
a rule for this"* — the Rules tab proposes it for them.

### Trust model

Suggestions are **templates**, not rules. The save path is unchanged
— the user still lands in the rule form and clicks Save, which routes
through `AddRule` over IPC. §4's "rules are created from the UI, never
implicitly" invariant holds. Three additional guards:

1. **`*+auto` rows are excluded from clustering.** Auto-decisions are
   already covered by a rule; suggesting more from them would compound
   existing rules with redundant ones.
2. **Minimum cluster size** (`MIN_CLUSTER_SIZE = 3`). One- and two-off
   approvals are noise.
3. **Redundancy filter.** Before emitting a suggestion, we run the
   cluster's representative against the live ruleset via
   `rules::evaluate`. If an enabled rule already fires with the same
   side, the suggestion is dropped — guards the edge case where a
   user just authored a rule that retroactively covers prior history
   (those rows are plain `approve`/`deny`, not `*+auto`).

### Pattern aggregation

Implemented in [`crate::recommendations::merge_argv_samples`]. The
algorithm tokenises every sample on whitespace, walks the columns
left-to-right, and:

- Emits the literal when every sample agrees on a column.
- When a column disagrees, splits each sample on `/`. If the segment
  counts line up, emits a per-segment merge (`repos/*/*/commits/*/statuses`);
  otherwise emits a bare `*`. Glues a trailing `*` to whichever it
  emits and stops walking.
- After the loop, if lengths differed without ever diverging, appends
  a space-separated trailing `*`.

The "stop at the first divergent slot" rule encodes a heuristic:
once a token in the middle of the argv is volatile, trailing flags
almost always are too. Pinning them to whatever literal happened to
appear in the small sample would over-constrain the rule.

CWDs use a simpler literal-prefix LCP, collapsed to `None` at the
filesystem root since `/` matches every absolute path.

### Layering

- [`src/recommendations.rs`] is pure: it takes `&[AuditEntry]` and
  `&[Rule]` and returns `Vec<Suggestion>`. No daemon, no IPC, no I/O.
- The UI computes suggestions inline in `render_consent_panel`'s
  Rules-tab branch, filters out dismissed keys, and passes a slice
  down to a new `render_suggestions_section`.
- `RuleDraft::from_suggestion` mirrors the existing
  `RuleDraft::from_audit_entry` constructor so the rule form's save
  path is untouched.

### Dismissal

Session-scoped: `ConsentWindowState.dismissed_suggestions: HashSet<String>`,
keyed by `Suggestion::key` (`"{side}:{wrap}:{ancestor}"`). A fresh
consent-window process resurfaces them — matches the existing
"AuditCache is session-only" rhythm.

### Non-goals (for this iteration)

- **Persisted dismissals.** Add later if users ask. Storing them
  buys us "stays dismissed across window restarts" but introduces
  yet another XDG file to manage.
- **Per-suggestion `count` decay.** A cluster that fired 100×
  three weeks ago and 0× this week scores the same as one with
  10× this week — both fall inside the 30-day window. Worth doing
  if the surface gets cluttered in practice.
- **Wire-protocol changes.** The engine reads the audit log
  directly (the consent-window child already does for its history
  view), so no `ClientMsg`/`DaemonMsg` additions.
