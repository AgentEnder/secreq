# Project notes for Claude

Project-specific guidance for working in this repo. Layers on top of
the global `~/.claude/CLAUDE.md` (still authoritative for general
workflow). Conflicts here win because they're project-specific.

## UI changes always regenerate the screenshot fixtures

The egui consent UI is exercised by a screenshot harness at
`tests/ui_screenshots.rs`. Every fixture renders the **real**
`render_consent_panel` via `egui_kittest` + wgpu and writes a PNG to
`dev-docs/ui-screenshots/`.

**Whenever you change the UI** — adding a tab, changing a layout,
altering colors, adjusting the window's default size, introducing a
new visual primitive — you MUST:

1. **Add a new fixture** for any UI surface you introduced (a new tab,
   a new modal, a new transient banner). Don't rely on an existing
   fixture to incidentally exercise it. One fixture per visual state
   (empty / list / form / toast).
2. **Regenerate every screenshot.** Existing fixtures may also be
   affected (default size change, color tweaks, etc.). Every documented
   fixture renders across the **chrome matrix** — three OS flavors by
   two appearances — so one fixture produces six PNGs, named
   `<id>-<os>-<appearance>.png`. Don't add a fixture whose only
   distinction is its `OsFlavor`; the matrix already covers it.
3. **Inspect the resulting PNGs.** Verify the regen rendered what you
   intended — open at least one new fixture and one existing fixture
   to confirm the change landed and didn't regress anything else.
4. **Update `dev-docs/ui-screenshots/README.md`** to add a table row
   for any new fixture (file name, fixture function name, one-line
   "what it exercises").

Regenerate with:

```sh
cargo test --test ui_screenshots -- --ignored --nocapture --test-threads=1
```

The tests are `#[ignore]`-gated so a normal `cargo test` run isn't
slowed down by wgpu. `--test-threads=1` keeps `$XDG_STATE_HOME`
mutation serialised across fixtures.

### How to add a fixture

The harness's `render_fixture_with_extras` accepts a `FixtureExtras`
that covers the three things you usually want to set:

- **`rules`** — populate the Rules tab without going through the form.
- **`toast`** — render an `AutoDenyToastView` (the Pending-tab banner).
- **`window_state`** — a `FnOnce(&mut ConsentWindowState)` that runs
  before the first frame, used to focus a specific tab or open a rule
  form (via `ConsentWindowState::focus_rules_tab` /
  `open_new_rule_form` / `open_edit_rule_form`).

For Pending-tab fixtures you typically only need the `setup` closure
to call `submit(state, ...)`; for Audit-tab fixtures you write
synthetic entries via `audit_line` / `audit_line_traced` and the
helpers write them to the tempdir's `audit.log`.

If a new visual surface needs UI state that none of the existing
helpers cover, **prefer adding a public method to `ConsentWindowState`
over reaching into private state** — the harness is the canonical
user of those entry points, but they should read as legitimate
production APIs.

### A fixture's caption is published documentation

`Shot::new("id").caption("…")` on a fixture is not a test comment — it
is the figcaption that ships on secreq.dev wherever that screenshot
appears. The harness writes it into
`dev-docs/ui-screenshots/manifest.json`, and the docs site renders it
verbatim (`<code>` and `<b>` are the only markup honoured). Write it
for someone *using* secreq; the README table below is the
contributor-facing description of the same image.

A fixture with nothing to say to a reader takes a bare id
(`"99-resize-03".into()`) and ships without a caption; one that
exercises the UI rather than documenting it also takes
`Shot::exercise_only()` to opt out of the matrix. The docs site keeps
no screenshot list of its own — it reads the manifest — so **never**
add a parallel list of screenshots, dimensions or captions under
`docs-site/`.

### Don't forget the README table

`dev-docs/ui-screenshots/README.md` documents what each file in the
directory shows. If a reviewer can't tell from your diff what the new
PNG demonstrates, they'll have to open the file and guess. The table
row is two lines of authorship cost; it's never wrong to write.

## Other project conventions

- The design plan for the auto-rules feature lives at
  `dev-docs/plans/2026-06-02-auto-rules.md`. Changes that materially
  alter the trust model, the wire protocol, or the rule semantics
  should be reflected there before the code lands.
- JSON Schemas (`docs/wraps.schema.json`, `docs/auto-rules.schema.json`)
  are regenerated via `cargo run --example gen-schema` and
  `cargo run --example gen-auto-rules-schema`. A test in
  `tests/schema_drift.rs` fails CI if either is stale.
- The design plan for the remote secret agent (serving `secret://`
  refs to a guest VM over a scoped socket) lives at
  `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md`. Its provenance
  section is load-bearing: the scoped-agent path must **never** call
  `daemon/peercred.rs` or `provenance.rs`, because a guest has no host
  pid and a forwarded socket's peer is the tunnel (sshd), not the
  asker. The host-declared scope is the principal instead.
- The audit log is written by the **wrap client** (`commands.rs`)
  after the daemon's reply lands. The scoped agent
  (`scoped_agent/mod.rs`) is also a client, so it writes its own rows
  via `audit.rs::AuditEntry::agent_resolve` — that's the rule, not an
  exception to it. The daemon never writes audit
  rows itself — **with two exceptions:**
    1. **SSH-agent signs.** There is no wrap client on the SSH path
       (the daemon *is* the agent), so the daemon records each sign
       outcome itself via `audit.rs::AuditEntry::ssh_sign` from
       `daemon/ssh_agent.rs::audit_sign` (`ssh:<key_id>` wrap, the
       public-key SHA256 fingerprint, the decision, and the caller
       chain — never the private key or the signature bytes).
    2. **Abandoned asks.** When a wrap (or an ancestor that took it
       down) exits before the user decides, its socket closes; the
       daemon reaps the parked ask and — since the client is gone and
       can't write its own row — records the `abandoned` outcome via
       `audit.rs::AuditEntry::abandoned` from
       `daemon/state.rs::withdraw_waiter` (one row per dead command,
       with the requesting process's `cwd` + caller chain + secret
       **names**, `decision = "abandoned"`). See `Decision::Abandoned`.
  Audit-write failures are non-fatal on all paths (logged, never
  failing the user's command / the sign / the reap).
  If you change the audit shape, update `audit.rs::AuditEntry::new`,
  the other `AuditEntry` constructors (`ssh_sign`, `abandoned`), and
  the screenshot fixture helpers that construct `AuditEntry` directly.
