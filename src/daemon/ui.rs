//! egui-based consent UI.
//!
//! Hidden by default. The socket thread calls `State::show_window()` (and
//! `ctx.request_repaint()`) when a new ask arrives; this app reads
//! `window_visible` every frame and toggles the OS window via egui's
//! viewport command stream.
//!
//! ## Visual language
//!
//! The UI is a **process tree**, rendered as a single pane with classic
//! `pstree`-style connectors (`├──`, `└──`, `│`). Roots are the outermost
//! ancestors of any currently-pending ask; their descendants nest below;
//! the wraps the user is being asked about hang off the direct-parent
//! nodes as leaves.
//!
//! Every node in the tree carries `[Approve all]` / `[Deny all]`
//! buttons. Clicking at a given node applies the decision to every wrap
//! in its subtree, *and* writes the approval-cache entry at that node's
//! scope — so any future ask from any descendant of that node will hit
//! the cache without re-prompting. That's the load-bearing capability:
//! "Approve all from Superset.app" once and you never see Superset ask
//! again for the wraps it currently has queued, no matter how deep the
//! intermediate shells/scripts get.
//!
//! Per-leaf rows still have their own `[Approve]` / `[Deny]` buttons as
//! a one-shot escape hatch.
//!
//! ## Audit history
//!
//! Each wrap leaf is annotated with a one-line summary read from
//! `audit.log`: when the same wrap last ran from the same direct caller,
//! and how many grants vs. denies happened in the last 30 days. "First
//! request from this caller" for fresh combinations. A last-decision of
//! "deny" gets a warning tint so the user notices before approving.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;

use crate::audit::{self, AuditCaller, AuditEntry};
use crate::consent::Decision;
use crate::recommendations::{self, Suggestion, SuggestionDecision, SuggestionSort};
use crate::rules::{Pattern, Rule, RuleDecision, RuleMatch};

use super::proto::{Caller, DedupeKey, RowStatus, SecretAsk, SshAskInfo};
use super::state::{ApprovalScope, QueueRow, QueueSnapshot, SharedState};

/// How often the UI re-reads the audit log to refresh the per-wrap history
/// summaries. The log is append-only and small, so re-reading is cheap, but
/// we still skip the parse on every paint.
const AUDIT_REFRESH_SECS: u64 = 10;

/// The history window the summary line reports counts over. Past entries
/// outside this window are still present in the file (and still influence
/// "last decision"), but counts are bounded to a recent slice so the
/// summary stays meaningful.
const AUDIT_WINDOW_SECS: u64 = 30 * 24 * 3600;

/// Soft ceiling on parsed audit entries kept in memory. Realistic logs run
/// well under this; the cap exists so a pathologically large log can't
/// blow up the daemon's RSS.
const AUDIT_HISTORY_LIMIT: usize = 5_000;

// ── Palette ───────────────────────────────────────────────────────────────
//
// Cooled, slightly desaturated dark palette tuned to feel native on
// macOS Sonoma's translucent dark surfaces. Three background tiers
// (canvas → card → header) carry the visual depth; text moves through
// three readability tiers (primary → muted → footnote) so the eye
// always knows where the most important content lives.

/// Canvas background. The window's primary fill.
const COLOR_CANVAS: egui::Color32 = egui::Color32::from_rgb(14, 17, 22);
/// Slightly elevated surface — used for the title-bar chrome strip
/// and the hover state on cards.
const COLOR_CHROME: egui::Color32 = egui::Color32::from_rgb(20, 24, 30);
/// Card fill — the resting surface for wrap requests + audit entries.
/// One step lighter than `COLOR_CANVAS` so cards read as elevated
/// content without slamming the eye.
const COLOR_CARD: egui::Color32 = egui::Color32::from_rgb(24, 29, 36);
/// Subtle 1px stroke around cards. Same hue as the divider but
/// designed to wrap a shape rather than draw a line, so very low
/// alpha to keep cards feeling soft rather than boxed-in.
const COLOR_CARD_STROKE: egui::Color32 = egui::Color32::from_rgb(38, 45, 54);

/// Approve button — emerald, slightly cooler than the previous
/// brick-toned forest green. Reads as "go" without the cartoon
/// saturation of `#2E7D32`.
const COLOR_APPROVE_BG: egui::Color32 = egui::Color32::from_rgb(38, 158, 88);
const COLOR_APPROVE_BG_HOVER: egui::Color32 = egui::Color32::from_rgb(54, 178, 105);
/// Deny button — a more modern Stripe/Linear-style red. The previous
/// `#B03232` read as a warning banner; this reads as a confirmation
/// you actually want to make decisively.
const COLOR_DENY_BG: egui::Color32 = egui::Color32::from_rgb(224, 78, 95);
const COLOR_DENY_BG_HOVER: egui::Color32 = egui::Color32::from_rgb(238, 100, 116);
/// Accent — primary interactive blue. Used for active tab underlines,
/// caller names, the count badge.
const COLOR_ACCENT: egui::Color32 = egui::Color32::from_rgb(118, 169, 232);
/// Slightly desaturated accent for badges and pill backgrounds —
/// lighter than the foreground accent so it can sit behind text
/// without bleeding into it.
const COLOR_ACCENT_SOFT: egui::Color32 = egui::Color32::from_rgb(33, 50, 76);

/// Primary text — near-white with the slightest cool tint so it
/// matches the rest of the palette instead of looking too
/// fluorescent on a cool background.
const COLOR_TEXT: egui::Color32 = egui::Color32::from_rgb(235, 238, 244);
/// One-layer-down text for secondary labels: "from", "via", section
/// headers above lists, the tab bar's inactive label.
const COLOR_MUTED: egui::Color32 = egui::Color32::from_gray(150);
/// Two-layer-down text for tertiary metadata (`pid …`, `cwd …`,
/// timestamps, locators, the "↳" prefix in audit lines).
const COLOR_FOOTNOTE: egui::Color32 = egui::Color32::from_gray(120);

/// 1px hairline used between the title bar and the body. Matches
/// `COLOR_CARD_STROKE` for visual consistency.
const COLOR_DIVIDER: egui::Color32 = egui::Color32::from_rgb(38, 45, 54);

/// Outer window inset. Big enough to keep right-aligned buttons from
/// kissing the window edge and the title from sitting under the
/// macOS traffic-light row.
const WINDOW_INSET_X: i8 = 20;
const WINDOW_INSET_Y: i8 = 14;
/// Title-bar chrome height. Tuned to give the macOS traffic lights
/// enough clearance + room for the title row inside.
const TITLE_BAR_HEIGHT: f32 = 56.0;
/// Standard card corner radius. Used for wrap-leaf cards, audit
/// entries, decision pills, and the count badge so everything in the
/// app shares one corner language.
const CARD_CORNER_RADIUS: u8 = 8;
/// Horizontal indent step per tree depth level. Tuned to be tighter
/// than the macOS Finder default (32) but visible enough to read as
/// nesting; the left guide rail does the heavy lifting visually.
const INDENT_UNIT: f32 = 22.0;
/// Vertical gap between consecutive cards on the Pending tab.
const CARD_VERTICAL_GAP: f32 = 10.0;
/// Vertical gap between consecutive audit cards on the Audit tab.
const AUDIT_CARD_GAP: f32 = 8.0;
/// Reserved width of the right-hand verdict column in an audit card.
/// A *real* reservation now (the command label is measured to fit the
/// remaining space) rather than a budget subtraction. Clamped to a
/// fraction of the row on narrow windows so the verdict pill never
/// crowds the command off-screen.
const AUDIT_VERDICT_COL_WIDTH: f32 = 132.0;

/// One pending decision queued for after the render pass. Carries the
/// scope so a bulk-approve at an ancestor writes the approval entry at
/// that ancestor's `(pid, start_time)`, not the leaf's direct parent.
/// Public because the consent-window child process collects these and
/// ships them back to the daemon over the socket.
#[derive(Debug, Clone)]
pub struct PendingAction {
    pub key: DedupeKey,
    pub decision: Decision,
    pub scope: ApprovalScope,
}

/// How long the "a new ask just arrived" highlight takes to fade from
/// peak back to rest. Long enough to catch the eye after the badge
/// count ticks up, short enough not to linger while the user triages.
const PENDING_PULSE_SECS: f32 = 1.1;

/// State that lives across the lifetime of one consent-window
/// **session** (open → close), and persists into the next session.
/// The consent-window child process owns one of these; the
/// screenshot harness owns one too.
pub struct ConsentWindowState {
    /// Per-node collapsed state. Keyed on `(pid, start_time)` so it
    /// survives across queue churn for the same process.
    collapsed: HashMap<(u32, u64), bool>,
    /// Parsed view of `audit.log`. Refreshed when the file's mtime
    /// moves (or once every `AUDIT_REFRESH_SECS`).
    audit: AuditCache,
    /// Which page the UI is currently showing. Pending is the
    /// default because the window is most often shown in response
    /// to a fresh ask; `secreq view` rises the tab to Audit on entry.
    current_tab: Tab,
    /// Rising-edge tracker for viewer mode so we can switch the
    /// default tab to Audit exactly once when `secreq view` opens us.
    last_viewer_mode: bool,
    /// `Some` while the rule form modal is open (creating or
    /// editing); `None` while the list view is on the Rules tab.
    rules_draft: Option<RuleDraft>,
    /// Suggestion keys ([`Suggestion::key`]) the user has dismissed in
    /// this session. Session-scoped on purpose: a fresh consent-window
    /// process resurfaces them so a user who's never opened the
    /// Rules tab still sees what the engine thinks.
    dismissed_suggestions: HashSet<String>,
    /// How the Rules tab orders the suggestion cards. Flipped by the
    /// segmented toggle in the "Suggested rules" header; session-scoped
    /// like the dismissals above.
    suggestion_sort: SuggestionSort,
    /// How the Rules tab orders the saved-rule rows — by auto-fire count
    /// or recency. Flipped by the toggle in the rules-list header;
    /// session-scoped.
    rule_sort: RuleSort,
    /// Live query for the Audit tab's search bar. Empty string ⇒ no
    /// filter; otherwise we keep only entries whose wrap / args /
    /// caller names / secret names / decision contain it
    /// (case-insensitive substring). Session-scoped — fresh windows
    /// start with a clean slate.
    audit_search: String,
    /// Set the next time Cmd/Ctrl+F fires; consumed by
    /// `render_audit_page` to call `Response::request_focus()` on
    /// the search input and then reset to false. Carries the
    /// keypress's effect across the render boundary because focus
    /// only takes hold during the actual widget pass.
    audit_search_focus_pending: bool,
    /// Pending-queue dedupe keys observed on the previous frame. `None`
    /// until the first observation so a freshly-opened window — which
    /// already lands on Pending showing the initial asks — doesn't fire
    /// the new-ask highlight on its very first frame. Diffed every frame
    /// by [`observe_pending`] to spot genuinely-new asks.
    seen_pending: Option<HashSet<DedupeKey>>,
    /// Intensity (0.0 = rest, 1.0 = peak) of the "a new ask arrived"
    /// highlight on the title-bar count badge and the Pending tab. Set
    /// to 1.0 when a new ask lands while the window is focused; wound
    /// back to 0 over [`PENDING_PULSE_SECS`] by the child's frame loop.
    pending_pulse: f32,
}

impl ConsentWindowState {
    pub fn new() -> ConsentWindowState {
        ConsentWindowState {
            collapsed: HashMap::new(),
            audit: AuditCache::new(),
            current_tab: Tab::Pending,
            last_viewer_mode: false,
            rules_draft: None,
            dismissed_suggestions: HashSet::new(),
            suggestion_sort: SuggestionSort::default(),
            rule_sort: RuleSort::default(),
            audit_search: String::new(),
            audit_search_focus_pending: false,
            seen_pending: None,
            pending_pulse: 0.0,
        }
    }

    /// Reconcile the live pending queue against what we saw last frame
    /// and react to genuinely-new asks. Called once per frame, before
    /// the chrome is painted.
    ///
    /// - **Focused** — the user is looking at the window — flash the
    ///   count badge and the Pending tab instead of yanking them off
    ///   whatever tab they're on. Draws the eye without stealing context.
    /// - **Unfocused** — the window is backgrounded (or about to be
    ///   raised for this ask) — pin the active tab to Pending so the
    ///   surface they see when it comes forward is the fresh request,
    ///   not a stale Rules/Audit view.
    ///
    /// The first observation never fires: a freshly-spawned window is
    /// already on Pending, so its initial asks aren't "new".
    pub fn observe_pending(&mut self, snapshot: &QueueSnapshot, focused: bool) {
        let current: HashSet<DedupeKey> = snapshot.entries.iter().map(|r| r.key.clone()).collect();
        self.react_to_pending(current, focused);
    }

    /// Core of [`observe_pending`], split out so the new-ask reaction can
    /// be unit-tested without constructing a full [`QueueSnapshot`].
    fn react_to_pending(&mut self, current: HashSet<DedupeKey>, focused: bool) {
        let has_new = match &self.seen_pending {
            None => false,
            Some(prev) => current.iter().any(|k| !prev.contains(k)),
        };
        self.seen_pending = Some(current);
        if !has_new {
            return;
        }
        if focused {
            self.pending_pulse = 1.0;
        } else {
            self.current_tab = Tab::Pending;
        }
    }

    /// Advance the new-ask highlight toward rest by `dt` seconds. Returns
    /// `true` while the flash is still animating (so the caller keeps
    /// requesting repaints) and `false` once it has settled.
    pub fn decay_pending_pulse(&mut self, dt: f32) -> bool {
        if self.pending_pulse <= 0.0 {
            return false;
        }
        self.pending_pulse = (self.pending_pulse - dt / PENDING_PULSE_SECS).max(0.0);
        self.pending_pulse > 0.0
    }

    /// Pin the new-ask highlight intensity directly. Used by the
    /// screenshot harness to capture the peak-flash visual
    /// deterministically; production drives this through
    /// [`observe_pending`] + [`decay_pending_pulse`].
    pub fn set_pending_pulse(&mut self, intensity: f32) {
        self.pending_pulse = intensity.clamp(0.0, 1.0);
    }

    /// Switch to the Rules tab in list mode. Clears any open form so
    /// the caller doesn't inherit stale draft state from a previous
    /// session. Used by the screenshot harness and available to
    /// future entry points (e.g. a CLI verb that opens straight to
    /// the Rules tab).
    pub fn focus_rules_tab(&mut self) {
        self.current_tab = Tab::Rules;
        self.rules_draft = None;
    }

    /// Switch to the Audit tab. Distinct from viewer-mode (which
    /// rising-edge-pins the tab AND swaps the title-bar subtitle to
    /// "Audit timeline · pinned"): this method only flips the active
    /// tab, leaving the daemon's pending/viewer state alone. Used by
    /// the screenshot harness to land on Audit without the pinned
    /// framing, and available to future entry points that want the
    /// same.
    pub fn focus_audit_tab(&mut self) {
        self.current_tab = Tab::Audit;
    }

    /// `true` when the Pending tab is the active tab. The child reads
    /// this each frame to compute its "interacting" signal for the
    /// daemon (`focused && !on_pending_tab()`): the auto-hide gate
    /// suppresses hiding only when the user is busy on Rules / Audit,
    /// not when they're idling on the empty Pending tab.
    pub fn on_pending_tab(&self) -> bool {
        self.current_tab == Tab::Pending
    }

    /// Harness support: mark the viewer-mode rising edge (which lands a
    /// fresh `secreq view` window on the Audit tab) as already consumed,
    /// so a fixture can render the Pending tab inside a viewer-mode
    /// window — the state a user reaches by opening `secreq view` and
    /// then clicking Pending. Without this the first frame would jump
    /// the tab to Audit.
    pub fn mark_viewer_rising_edge_consumed(&mut self) {
        self.last_viewer_mode = true;
    }

    /// Pre-populate the Audit-tab search query. Used by the screenshot
    /// harness to capture the "search is filtering" visual state; the
    /// production keypress path mutates the field through the
    /// `TextEdit` widget directly.
    pub fn set_audit_search(&mut self, query: &str) {
        self.audit_search.clear();
        self.audit_search.push_str(query);
    }

    /// Set how the Rules tab orders its suggestion cards. Used by the
    /// screenshot harness to capture the "Recent" sort state; the
    /// production path mutates this through the header toggle.
    pub fn set_suggestion_sort(&mut self, sort: SuggestionSort) {
        self.suggestion_sort = sort;
    }

    /// Set how the Rules tab orders its saved-rule rows. Used by the
    /// screenshot harness to capture the "Recent" sort state; production
    /// mutates this through the rules-list header toggle.
    pub fn set_rule_sort(&mut self, sort: RuleSort) {
        self.rule_sort = sort;
    }

    /// Switch to the Rules tab and open a blank rule form. Equivalent
    /// to clicking "+ New rule" in the list view.
    pub fn open_new_rule_form(&mut self) {
        self.current_tab = Tab::Rules;
        self.rules_draft = Some(RuleDraft::fresh());
    }

    /// Switch to the Rules tab and open the edit form pre-filled
    /// from `rule`. Equivalent to clicking the per-row "Edit" button.
    pub fn open_edit_rule_form(&mut self, rule: &Rule) {
        self.current_tab = Tab::Rules;
        self.rules_draft = Some(RuleDraft::from_rule(rule));
    }
}

impl Default for ConsentWindowState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Pending,
    Rules,
    Audit,
}

/// Form-state for the rule create/edit modal. Holds raw strings so
/// the user can incrementally type into match-pattern fields without
/// the [`Pattern`] re-parser firing on every keystroke; on Save it
/// converts to a [`Rule`] and emits a [`RuleAction`].
///
/// `id == None` ⇒ creating; `id == Some` ⇒ editing an existing rule.
#[derive(Debug, Clone, Default)]
struct RuleDraft {
    id: Option<String>,
    name: String,
    enabled: bool,
    decide: RuleDecisionDraft,
    wrap: String,
    argv: String,
    ancestor: String,
    cwd: String,
    deny_message: String,
    /// Snapshot of the secret-set this rule was originally trained on.
    /// Seeded from the audit-row "create rule from this" affordance
    /// (slice 5); empty for blank-form creation, which disables the
    /// trained-secrets guard at evaluator time. UI displays this as
    /// a read-only chip with a tooltip explaining the guard.
    trained_secrets: std::collections::BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum RuleDecisionDraft {
    #[default]
    Approve,
    Deny,
}

impl From<RuleDecision> for RuleDecisionDraft {
    fn from(d: RuleDecision) -> Self {
        match d {
            RuleDecision::Approve => RuleDecisionDraft::Approve,
            RuleDecision::Deny => RuleDecisionDraft::Deny,
        }
    }
}

impl From<RuleDecisionDraft> for RuleDecision {
    fn from(d: RuleDecisionDraft) -> Self {
        match d {
            RuleDecisionDraft::Approve => RuleDecision::Approve,
            RuleDecisionDraft::Deny => RuleDecision::Deny,
        }
    }
}

impl RuleDraft {
    fn fresh() -> RuleDraft {
        RuleDraft {
            enabled: true,
            ..RuleDraft::default()
        }
    }

    /// Seed a draft from an audit row. Used by the "Create rule from
    /// this ask…" affordance on the Audit tab. Populates every match
    /// field that the audit row contains (wrap, joined argv, direct
    /// caller, cwd) and snapshots `entry.secrets` as `trained_secrets`
    /// so the safety guard kicks in by default.
    fn from_audit_entry(entry: &AuditEntry) -> RuleDraft {
        let argv = if entry.args.is_empty() {
            entry.wrap.clone()
        } else {
            format!("{} {}", entry.wrap, entry.args.join(" "))
        };
        // Fall back to a sensible name even if the user types nothing
        // — they can edit it before saving.
        let name = if entry.wrap.is_empty() {
            "auto-rule".to_owned()
        } else {
            format!("from {} ask", entry.wrap)
        };
        // Pre-fill `decide` to match what the audit row recorded. If
        // the past decision was an approve (any variant), seed an
        // approve rule; deny → deny. Auto-* variants seed the same
        // side as their non-auto counterpart.
        let decide = if entry.decision.starts_with("deny") {
            RuleDecisionDraft::Deny
        } else {
            RuleDecisionDraft::Approve
        };
        let ancestor = entry
            .callers
            .first()
            .map(|c| c.name.clone())
            .unwrap_or_default();
        let trained_secrets = entry.secrets.iter().cloned().collect();
        RuleDraft {
            id: None,
            name,
            enabled: true,
            decide,
            wrap: entry.wrap.clone(),
            argv,
            ancestor,
            cwd: entry.cwd.clone(),
            deny_message: String::new(),
            trained_secrets,
        }
    }

    /// Seed a draft from a recommendation-engine [`Suggestion`]. Used
    /// by the "Suggested rules" section's Review-and-save affordance.
    /// Differs from [`from_audit_entry`] in that the patterns are
    /// already pre-aggregated across a cluster — `argv`/`cwd` may
    /// already be globs, `trained_secrets` is a union across the
    /// cluster, and `decide` reflects the cluster's side rather than
    /// any single row's decision string.
    fn from_suggestion(s: &Suggestion) -> RuleDraft {
        let decide = match s.decide {
            SuggestionDecision::Approve => RuleDecisionDraft::Approve,
            SuggestionDecision::Deny => RuleDecisionDraft::Deny,
        };
        let name = format!("{} from {}", s.wrap, s.ancestor);
        RuleDraft {
            id: None,
            name,
            enabled: true,
            decide,
            wrap: s.wrap.clone(),
            argv: s.argv.clone().unwrap_or_default(),
            ancestor: s.ancestor.clone(),
            cwd: s.cwd.clone().unwrap_or_default(),
            deny_message: String::new(),
            trained_secrets: s.trained_secrets.clone(),
        }
    }

    fn from_rule(rule: &Rule) -> RuleDraft {
        RuleDraft {
            id: Some(rule.id.clone()),
            name: rule.name.clone(),
            enabled: rule.enabled,
            decide: rule.decide.into(),
            wrap: rule.r#match.wrap.clone(),
            argv: rule
                .r#match
                .argv
                .as_ref()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_default(),
            ancestor: rule
                .r#match
                .ancestor
                .as_ref()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_default(),
            cwd: rule
                .r#match
                .cwd
                .as_ref()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_default(),
            deny_message: rule.deny_message.clone().unwrap_or_default(),
            trained_secrets: rule.trained_secrets.clone(),
        }
    }

    /// Convert to a [`Rule`]. Returns `Err(reason)` if the draft is
    /// not savable; the UI surfaces the message inline so the user
    /// sees why Save is refusing.
    fn into_rule(self) -> Result<Rule, &'static str> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err("name is required");
        }
        let wrap = self.wrap.trim();
        if wrap.is_empty() {
            return Err("wrap is required");
        }
        let optional_pattern = |s: &str| -> Option<Pattern> {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                Some(Pattern::parse(s))
            }
        };
        let deny_message = if self.decide == RuleDecisionDraft::Deny {
            let m = self.deny_message.trim();
            if m.is_empty() {
                None
            } else {
                Some(m.to_owned())
            }
        } else {
            None
        };
        let id = self.id.unwrap_or_else(crate::rules::new_rule_id);
        let created_at = crate::rules::now_unix();
        Ok(Rule {
            id,
            name: name.to_owned(),
            enabled: self.enabled,
            decide: self.decide.into(),
            r#match: RuleMatch {
                wrap: wrap.to_owned(),
                argv: optional_pattern(&self.argv),
                ancestor: optional_pattern(&self.ancestor),
                cwd: optional_pattern(&self.cwd),
            },
            trained_secrets: self.trained_secrets,
            deny_message,
            created_at_unix: created_at,
        })
    }
}

/// One queued mutation against the rules file, emitted by the Rules
/// tab and consumed by the consent-window child process which ships
/// it over the socket as a `ClientMsg::Add/Update/Delete/SetRuleEnabled`.
/// Mirrors the [`PendingAction`] flow for consent decisions.
#[derive(Debug, Clone)]
pub enum RuleAction {
    Add(Rule),
    Update(Rule),
    Delete(String),
    SetEnabled { id: String, enabled: bool },
}

/// A live auto-deny toast for rendering at the top of the Pending
/// tab. Aging-out is the caller's responsibility — when the toast
/// has expired, pass `None` to the renderer.
#[derive(Debug, Clone)]
pub struct AutoDenyToastView {
    pub rule_name: String,
    pub deny_message: Option<String>,
}

/// Install fonts AND visuals — call once at startup, from both the
/// daemon and the screenshot harness, so the daemon and the
/// regenerated PNGs share one source of truth for the visual identity.
///
/// **Fonts.** egui's `FontDefinitions::default()` ships a Proportional
/// family of `[Ubuntu-Light, NotoEmoji-Regular, emoji-icon-font]`.
/// None of those cover the geometric shapes and arrows the UI leans
/// on (`⊙ ▾ ▸ ↳`). `Hack` (already bundled by egui's `default_fonts`
/// feature, derived from DejaVu Sans Mono) has wide coverage, so we
/// append it as a Proportional fallback.
///
/// **Visuals.** egui's stock dark theme is a workmanlike grey. We
/// replace its three background colours with our three-tier palette
/// (`COLOR_CANVAS` / `COLOR_CHROME` / `COLOR_CARD`), the text colour
/// with `COLOR_TEXT`, and bump the global corner radii so widgets
/// look part of one design system instead of a stock egui app.
pub fn install_style(ctx: &egui::Context) {
    // ── Fonts ────────────────────────────────────────────────────
    let mut fonts = egui::FontDefinitions::default();
    if let Some(proportional) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        if !proportional.iter().any(|name| name == "Hack") {
            proportional.push("Hack".to_owned());
        }
    }
    ctx.set_fonts(fonts);

    // ── Visuals ──────────────────────────────────────────────────
    ctx.global_style_mut(|style| {
        let v = &mut style.visuals;
        v.dark_mode = true;
        v.panel_fill = COLOR_CANVAS;
        v.window_fill = COLOR_CANVAS;
        v.extreme_bg_color = COLOR_CHROME;
        v.faint_bg_color = COLOR_CARD;
        v.override_text_color = Some(COLOR_TEXT);
        // Widget surface tones. egui uses these for buttons, tabs,
        // hovered labels, etc.; align them with our palette so
        // stock widgets we don't custom-paint still feel native.
        v.widgets.noninteractive.bg_fill = COLOR_CARD;
        v.widgets.noninteractive.weak_bg_fill = COLOR_CARD;
        v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, COLOR_CARD_STROKE);
        v.widgets.inactive.bg_fill = COLOR_CARD;
        v.widgets.inactive.weak_bg_fill = COLOR_CARD;
        v.widgets.hovered.bg_fill = COLOR_CHROME;
        v.widgets.hovered.weak_bg_fill = COLOR_CHROME;
        v.widgets.active.bg_fill = COLOR_ACCENT_SOFT;
        v.widgets.active.weak_bg_fill = COLOR_ACCENT_SOFT;
        // Unified corner radii across egui widgets. egui ships a
        // smaller default that ends up looking inconsistent next to
        // our hand-painted 8px cards.
        let r = egui::CornerRadius::same(6);
        v.widgets.noninteractive.corner_radius = r;
        v.widgets.inactive.corner_radius = r;
        v.widgets.hovered.corner_radius = r;
        v.widgets.active.corner_radius = r;
        // Selection chrome — used by text selection, accent fills.
        v.selection.bg_fill = COLOR_ACCENT_SOFT;
        v.selection.stroke = egui::Stroke::new(1.0, COLOR_ACCENT);
        // Loosen up some default spacing for a calmer rhythm.
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);
    });
}

/// Old name kept as a back-compat shim so callers from prior commits
/// still work if any exist; the real entry point is now `install_style`.
#[doc(hidden)]
pub fn install_fonts(ctx: &egui::Context) {
    install_style(ctx);
}

/// Alert background for the always-on-top pending badge. A deep,
/// saturated red so a "N pending" pill reads as "act on me" against an
/// arbitrary desktop — distinct from the consent window's calm dark
/// canvas, which the user has to be looking at to see at all.
const COLOR_BADGE_BG: egui::Color32 = egui::Color32::from_rgb(198, 52, 64);

/// Render the always-on-top pending-requests badge: a compact pill
/// reading "N pending" with a bright indicator dot. The background is
/// painted here (not left to the window/panel fill) so the screenshot
/// fixture renders the exact pixels the production badge window shows.
/// Returns the click response over the whole pill — the badge child
/// turns a click into a `RaiseConsentRequested`.
pub fn render_badge(ui: &mut egui::Ui, count: usize) -> egui::Response {
    let rect = ui.max_rect();
    // Clone so the painter doesn't hold a borrow across `allocate_rect`.
    let painter = ui.painter().clone();

    // Opaque fill of the whole (small, borderless) window.
    painter.rect_filled(rect, egui::CornerRadius::ZERO, COLOR_BADGE_BG);

    // Bright indicator dot, vertically centred, inset from the left.
    let dot_radius = 5.0;
    let dot_center = egui::pos2(rect.left() + 16.0, rect.center().y);
    painter.circle_filled(dot_center, dot_radius, COLOR_TEXT);

    // "N pending" — singular/plural so a single request doesn't read
    // "1 pendings".
    let label = if count == 1 {
        "1 pending".to_owned()
    } else {
        format!("{count} pending")
    };
    painter.text(
        egui::pos2(dot_center.x + dot_radius + 10.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(18.0),
        COLOR_TEXT,
    );

    ui.allocate_rect(rect, egui::Sense::click())
}

/// The badge window's clear colour, matching [`render_badge`]'s fill, so
/// any pixels the painter doesn't cover (sub-pixel edges, the frame
/// before the first paint) show the alert colour rather than flashing a
/// stale or black background. Shape matches `eframe::App::clear_color`'s
/// `[r, g, b, a]` gamma-normalised return.
pub fn badge_clear_color() -> [f32; 4] {
    COLOR_BADGE_BG.to_normalized_gamma_f32()
}

// ── Audit history cache ──────────────────────────────────────────────────
//
// The daemon never writes the audit log (clients do, post-decision in
// `commands.rs`), so the cache is a pure read. We poll on mtime to pick up
// entries from sibling client processes between paints — cheaper than a
// full reparse, and good enough since "history" is only consulted while
// the window is visible.

struct AuditCache {
    entries: Vec<AuditEntry>,
    last_load: Option<Instant>,
    last_mtime: Option<SystemTime>,
}

impl AuditCache {
    fn new() -> AuditCache {
        AuditCache {
            entries: Vec::new(),
            last_load: None,
            last_mtime: None,
        }
    }

    fn refresh_if_stale(&mut self) {
        let now = Instant::now();
        let due = self
            .last_load
            .map(|t| now.duration_since(t) >= Duration::from_secs(AUDIT_REFRESH_SECS))
            .unwrap_or(true);
        if !due {
            return;
        }
        let mtime = audit::audit_log_mtime();
        // mtime-unchanged → reuse parsed entries, just bump the poll clock.
        if self.last_load.is_some() && mtime == self.last_mtime {
            self.last_load = Some(now);
            return;
        }
        if let Ok(entries) = audit::read_history(Some(AUDIT_HISTORY_LIMIT)) {
            self.entries = entries;
        }
        self.last_load = Some(now);
        self.last_mtime = mtime;
    }

    fn summarize(&self, wrap: &str, caller_name: Option<&str>) -> WrapHistorySummary {
        summarize_history(&self.entries, wrap, caller_name, now_unix())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WrapHistorySummary {
    /// Decision string from the most recent matching audit entry, verbatim
    /// (one of "approve", "approve+remember", "approve+cached", "deny").
    last_decision: Option<String>,
    last_ts_unix: Option<u64>,
    /// Counts within the `AUDIT_WINDOW_SECS` window.
    approve_count: usize,
    deny_count: usize,
    total_count: usize,
}

impl WrapHistorySummary {
    fn is_empty(&self) -> bool {
        self.total_count == 0 && self.last_ts_unix.is_none()
    }
}

/// Pure summarizer split from `AuditCache` so it can be unit-tested without
/// touching the filesystem. Matches on `entry.wrap == wrap` and, when
/// `caller_name` is supplied, the direct (callers[0]) caller's name.
fn summarize_history(
    entries: &[AuditEntry],
    wrap: &str,
    caller_name: Option<&str>,
    now_unix: u64,
) -> WrapHistorySummary {
    let cutoff = now_unix.saturating_sub(AUDIT_WINDOW_SECS);
    let mut out = WrapHistorySummary::default();
    for e in entries {
        if e.wrap != wrap {
            continue;
        }
        if let Some(cn) = caller_name {
            let direct = e.callers.first().map(|c| c.name.as_str()).unwrap_or("");
            if direct != cn {
                continue;
            }
        }
        // "Last decision" is informative beyond the window — a deny from
        // 60 days ago is still worth surfacing — so update it first,
        // unconditionally.
        if out.last_ts_unix.is_none_or(|last| e.ts_unix >= last) {
            out.last_ts_unix = Some(e.ts_unix);
            out.last_decision = Some(e.decision.clone());
        }
        if e.ts_unix < cutoff {
            continue;
        }
        out.total_count += 1;
        match e.decision.as_str() {
            "approve" | "approve+remember" | "approve+cached" => out.approve_count += 1,
            "deny" => out.deny_count += 1,
            _ => {}
        }
    }
    out
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Render one frame of the consent UI into the given `Ui`.
///
/// Decisions the user makes (clicks, keyboard shortcuts) are appended
/// to `actions_out` for the caller to dispatch — the renderer
/// deliberately doesn't know how to deliver them. The consent-window
/// child process ships them over the socket as `ConsentDecision`
/// messages; the screenshot harness drops them on the floor.
#[allow(clippy::too_many_arguments)] // The panel renderer is the single entry point — bundling these into one struct would just push the unpacking work to every call site.
pub fn render_consent_panel(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    snapshot: &QueueSnapshot,
    viewer_mode: bool,
    rules: &[Rule],
    auto_deny_toast: Option<&AutoDenyToastView>,
    window_state: &mut ConsentWindowState,
    actions_out: &mut Vec<PendingAction>,
    rule_actions_out: &mut Vec<RuleAction>,
) {
    // Rising-edge tab switch for viewer mode (`secreq view` lands on
    // the Audit tab the first time, then leaves the tab alone).
    if viewer_mode && !window_state.last_viewer_mode {
        window_state.current_tab = Tab::Audit;
    }
    window_state.last_viewer_mode = viewer_mode;

    // React to a newly-arrived ask: flash the badge + Pending tab when
    // focused (don't yank the user's tab), or pin the active tab to
    // Pending when backgrounded so the raised window opens on the fresh
    // request. The decay back to rest happens in the child's frame loop.
    let focused = ctx.input(|i| i.focused);
    window_state.observe_pending(snapshot, focused);

    window_state.audit.refresh_if_stale();
    let tree = build_tree(snapshot);

    // ── Keyboard ─────────────────────────────────────────────────
    if window_state.current_tab == Tab::Pending {
        if let Some(&top_root) = tree.roots.first() {
            ctx.input(|i| {
                if i.key_pressed(egui::Key::Enter) {
                    collect_subtree_actions(
                        &tree,
                        top_root,
                        Decision::ApproveRemember,
                        actions_out,
                    );
                } else if i.key_pressed(egui::Key::Escape) {
                    collect_subtree_actions(&tree, top_root, Decision::Deny, actions_out);
                }
            });
        }
    }
    // Cmd/Ctrl+F from any tab — switch to Audit and focus the
    // search input. Mirrors the platform convention (Find) and
    // also serves as the discoverable entry point if the user
    // hasn't noticed the always-visible search bar yet.
    let find_pressed = ctx.input(|i| i.key_pressed(egui::Key::F) && i.modifiers.command);
    if find_pressed {
        window_state.current_tab = Tab::Audit;
        window_state.audit_search_focus_pending = true;
    }

    // ── Render ───────────────────────────────────────────────────
    ui.painter().rect_filled(ui.max_rect(), 0.0, COLOR_CANVAS);
    let body_inset = egui::Margin {
        left: WINDOW_INSET_X,
        right: WINDOW_INSET_X,
        top: WINDOW_INSET_Y,
        bottom: WINDOW_INSET_Y,
    };
    paint_title_bar(ui, &tree, viewer_mode, window_state.pending_pulse);
    let audit_len = window_state.audit.entries.len();
    let pending_pulse = window_state.pending_pulse;
    egui::Frame::NONE.inner_margin(body_inset).show(ui, |ui| {
        render_tab_bar(
            ui,
            &mut window_state.current_tab,
            &tree,
            audit_len,
            rules.len(),
            pending_pulse,
        );
        ui.add_space(14.0);
        match window_state.current_tab {
            Tab::Pending => {
                if let Some(toast) = auto_deny_toast {
                    render_auto_deny_toast(ui, toast);
                    ui.add_space(8.0);
                }
                render_pending_page(
                    ui,
                    &tree,
                    &mut window_state.collapsed,
                    actions_out,
                    &window_state.audit,
                    viewer_mode,
                );
            }
            Tab::Rules => {
                // Recompute on every Rules-tab paint. Cheap (one
                // linear pass over the capped audit cache) and keeps
                // the suggestions in lockstep with whatever new asks
                // landed since the last frame, without us having to
                // explicitly invalidate anything on rule edits.
                let now = now_unix();
                let all = recommendations::suggest(&window_state.audit.entries, rules, now);
                let mut visible: Vec<Suggestion> = all
                    .into_iter()
                    .filter(|s| !window_state.dismissed_suggestions.contains(&s.key))
                    .collect();
                // Re-order the filtered list per the user's toggle.
                // `suggest()` hands back a MostUsed default; this applies
                // MostRecent when selected (and is a cheap no-op-shaped
                // re-sort otherwise).
                window_state.suggestion_sort.sort(&mut visible);
                // Per-rule auto-fire stats from the same audit cache,
                // then order the rows per the user's rule-sort toggle.
                let usage = rule_usage_index(&window_state.audit.entries);
                let mut rule_rows: Vec<(&Rule, RuleUsage)> = rules
                    .iter()
                    .map(|r| (r, usage.get(&r.id).copied().unwrap_or_default()))
                    .collect();
                window_state.rule_sort.sort(&mut rule_rows);
                let mut rules_ui = RulesUi {
                    draft: &mut window_state.rules_draft,
                    dismissed: &mut window_state.dismissed_suggestions,
                    suggestion_sort: &mut window_state.suggestion_sort,
                    rule_sort: &mut window_state.rule_sort,
                };
                render_rules_page(ui, &rule_rows, &visible, &mut rules_ui, rule_actions_out)
            }
            Tab::Audit => render_audit_page(
                ctx,
                ui,
                &window_state.audit,
                &mut window_state.rules_draft,
                &mut window_state.current_tab,
                &mut window_state.audit_search,
                &mut window_state.audit_search_focus_pending,
            ),
        }
    });
}

// ── Process tree model ───────────────────────────────────────────────────

/// A node in the process tree we render. Owns the metadata we need to
/// draw and to dispatch actions; rendering walks `children` recursively.
#[derive(Debug, Clone)]
struct TreeNode {
    pid: u32,
    start_time: u64,
    /// Display info for this process. Pulled from the first `Caller` we
    /// saw at this position in any chain — they all agree on name/command.
    caller: Option<Caller>,
    children: Vec<usize>,
    /// Wraps where THIS node is the direct parent. Direct-parent rows
    /// hang as leaves off the bottommost ancestor we have info for.
    rows: Vec<QueueRow>,
    /// Oldest `first_seen` anywhere in the subtree. Drives root order.
    oldest_seen: Instant,
}

impl TreeNode {
    fn scope(&self) -> ApprovalScope {
        ApprovalScope {
            pid: self.pid,
            start_time: self.start_time,
        }
    }
}

#[derive(Debug)]
struct ProcessTree {
    nodes: Vec<TreeNode>,
    roots: Vec<usize>,
}

impl ProcessTree {
    fn total_leaf_rows(&self) -> usize {
        self.nodes.iter().map(|n| n.rows.len()).sum()
    }
}

fn build_tree(snapshot: &QueueSnapshot) -> ProcessTree {
    let mut tree = ProcessTree {
        nodes: Vec::new(),
        roots: Vec::new(),
    };

    for row in &snapshot.entries {
        // `callers` is nearest-first (direct parent at index 0). Walking
        // outermost → direct parent makes "drill down" the natural
        // direction for tree insertion.
        let chain: Vec<&Caller> = row.representative.callers.iter().rev().collect();
        if chain.is_empty() {
            // No ancestor info — orphan as a synthetic root keyed on the
            // dedupe_key's parent identity so it can still be approved.
            let key = (row.key.ppid, row.key.parent_start_time);
            let idx = ensure_root(&mut tree, key, None, row.first_seen);
            tree.nodes[idx].rows.push(row.clone());
            continue;
        }

        let root_caller = chain[0];
        let root_key = (root_caller.pid, root_caller.start_time);
        let root_idx = ensure_root(&mut tree, root_key, Some(root_caller), row.first_seen);
        update_oldest(&mut tree.nodes[root_idx], row.first_seen);

        let mut current = root_idx;
        for caller in chain.iter().skip(1) {
            let key = (caller.pid, caller.start_time);
            current = ensure_child(&mut tree, current, key, Some(*caller), row.first_seen);
            update_oldest(&mut tree.nodes[current], row.first_seen);
        }
        tree.nodes[current].rows.push(row.clone());
    }

    // Roots: oldest-first (matches the snapshot's own ordering).
    tree.roots.sort_by_key(|&i| tree.nodes[i].oldest_seen);
    // Children at every level: same ordering, so the visual tree is
    // stable across re-renders.
    for i in 0..tree.nodes.len() {
        let mut children = std::mem::take(&mut tree.nodes[i].children);
        children.sort_by_key(|&c| tree.nodes[c].oldest_seen);
        tree.nodes[i].children = children;
    }

    tree
}

fn ensure_root(
    tree: &mut ProcessTree,
    key: (u32, u64),
    caller: Option<&Caller>,
    seen: Instant,
) -> usize {
    if let Some(&idx) = tree.roots.iter().find(|&&i| tree.nodes[i].key() == key) {
        return idx;
    }
    let idx = tree.nodes.len();
    tree.nodes.push(TreeNode {
        pid: key.0,
        start_time: key.1,
        caller: caller.cloned(),
        children: Vec::new(),
        rows: Vec::new(),
        oldest_seen: seen,
    });
    tree.roots.push(idx);
    idx
}

fn ensure_child(
    tree: &mut ProcessTree,
    parent: usize,
    key: (u32, u64),
    caller: Option<&Caller>,
    seen: Instant,
) -> usize {
    if let Some(&idx) = tree.nodes[parent]
        .children
        .iter()
        .find(|&&i| tree.nodes[i].key() == key)
    {
        return idx;
    }
    let idx = tree.nodes.len();
    tree.nodes.push(TreeNode {
        pid: key.0,
        start_time: key.1,
        caller: caller.cloned(),
        children: Vec::new(),
        rows: Vec::new(),
        oldest_seen: seen,
    });
    tree.nodes[parent].children.push(idx);
    idx
}

fn update_oldest(node: &mut TreeNode, seen: Instant) {
    if seen < node.oldest_seen {
        node.oldest_seen = seen;
    }
}

impl TreeNode {
    fn key(&self) -> (u32, u64) {
        (self.pid, self.start_time)
    }
}

/// Walk a subtree and emit `PendingAction`s for every leaf row, all
/// scoped to the node we started at. Used by the bulk Approve/Deny
/// buttons and by the keyboard shortcuts.
fn collect_subtree_actions(
    tree: &ProcessTree,
    node_idx: usize,
    decision: Decision,
    out: &mut Vec<PendingAction>,
) {
    let scope = tree.nodes[node_idx].scope();
    walk_subtree(tree, node_idx, |row| {
        // Resolving rows are already authorized — a decision on them is
        // a no-op in `State::resolve` (the key isn't in the queue), but
        // skip them so a mixed "Approve all" only touches awaiting rows.
        if row.status == RowStatus::Resolving {
            return;
        }
        out.push(PendingAction {
            key: row.key.clone(),
            decision,
            scope,
        });
    });
}

/// True if a node's subtree contains rows and *all* of them are
/// resolving — used to drop the node-level Approve/Deny buttons, which
/// would otherwise offer a decision on something already authorized.
fn subtree_all_resolving(tree: &ProcessTree, node_idx: usize) -> bool {
    let mut any = false;
    let mut all = true;
    walk_subtree(tree, node_idx, |row| {
        any = true;
        if row.status != RowStatus::Resolving {
            all = false;
        }
    });
    any && all
}

fn walk_subtree<F: FnMut(&QueueRow)>(tree: &ProcessTree, node_idx: usize, mut f: F) {
    fn inner<F: FnMut(&QueueRow)>(tree: &ProcessTree, idx: usize, f: &mut F) {
        for row in &tree.nodes[idx].rows {
            f(row);
        }
        for &c in &tree.nodes[idx].children {
            inner(tree, c, f);
        }
    }
    inner(tree, node_idx, &mut f);
}

fn count_leaf_rows(tree: &ProcessTree, node_idx: usize) -> usize {
    let mut total = tree.nodes[node_idx].rows.len();
    for &c in &tree.nodes[node_idx].children {
        total += count_leaf_rows(tree, c);
    }
    total
}

// ── Rendering ─────────────────────────────────────────────────────────────

/// Paint the full-width title bar at the top of the window.
///
/// - Full-bleed `COLOR_CHROME` background strip, `TITLE_BAR_HEIGHT` tall.
/// - 30px app-icon badge on the left (drawn from primitives — a soft
///   accent rounded square with a stylised key glyph). Provides the
///   "branding" that lifts the chrome from "egui app" to "designed
///   product".
/// - Two-line title block: `secreq` as a bold 18pt wordmark,
///   `Consent requests` / `Audit timeline · pinned` as a 11pt
///   footnote subtitle.
/// - Right-aligned count badge — a rounded `COLOR_ACCENT_SOFT` pill
///   with a small accent dot + plain-English count. Hidden when the
///   queue is empty so the chrome reads calm in the no-news state.
fn paint_title_bar(ui: &mut egui::Ui, tree: &ProcessTree, viewer_mode: bool, pulse: f32) {
    let pending = tree.total_leaf_rows();
    let process_count = tree.roots.len();

    let available = ui.available_rect_before_wrap();
    let bar_rect = egui::Rect::from_min_size(
        available.min,
        egui::vec2(available.width(), TITLE_BAR_HEIGHT),
    );

    ui.painter().rect_filled(bar_rect, 0.0, COLOR_CHROME);
    let hairline_y = bar_rect.bottom() - 0.5;
    ui.painter().hline(
        bar_rect.x_range(),
        hairline_y,
        egui::Stroke::new(1.0, COLOR_DIVIDER),
    );

    // Defensive: when the window is dragged narrower than two title-bar
    // insets, the naive `bar_rect.right() - inset` calculation produces
    // `inner_rect.max.x < inner_rect.min.x`, which is an invalid
    // `Rect`. Passing that to `scope_builder` (or computing child
    // layouts from it) panics deep in egui. Clamp by collapsing
    // toward zero-width — the chrome strip still paints; the title
    // content just disappears off the right edge.
    let inset_x = (WINDOW_INSET_X as f32).min(bar_rect.width() * 0.5);
    let inner_left = bar_rect.left() + inset_x;
    let inner_right = (bar_rect.right() - inset_x).max(inner_left);
    let inner_rect = egui::Rect::from_min_max(
        egui::pos2(inner_left, bar_rect.top() + 10.0),
        egui::pos2(inner_right, bar_rect.bottom() - 8.0),
    );
    if inner_rect.width() < 1.0 {
        ui.allocate_rect(bar_rect, egui::Sense::hover());
        return;
    }
    ui.scope_builder(
        egui::UiBuilder::new()
            .max_rect(inner_rect)
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
        |ui| {
            paint_app_icon(ui, 30.0);
            ui.add_space(12.0);
            ui.vertical(|ui| {
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new("secreq")
                        .size(18.0)
                        .strong()
                        .color(COLOR_TEXT),
                );
                let subtitle = if viewer_mode {
                    "Audit timeline · pinned"
                } else {
                    "Consent requests"
                };
                ui.label(
                    egui::RichText::new(subtitle)
                        .size(11.0)
                        .color(COLOR_FOOTNOTE),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if pending > 0 {
                    paint_count_badge(ui, pending, process_count, pulse);
                }
            });
        },
    );

    ui.allocate_rect(bar_rect, egui::Sense::hover());
}

/// Draw the small app-logo badge — accent-soft rounded square with a
/// thin accent border and a stylised key shape inside. Built from
/// primitives so it scales cleanly across DPRs.
fn paint_app_icon(ui: &mut egui::Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let painter = ui.painter();
    let radius = egui::CornerRadius::same(7);
    painter.rect_filled(rect, radius, COLOR_ACCENT_SOFT);
    painter.rect_stroke(
        rect,
        radius,
        egui::Stroke::new(1.0, COLOR_ACCENT),
        egui::StrokeKind::Inside,
    );

    let inner = rect.shrink(7.0);
    let cx = inner.center().x;
    let head_r = inner.width() * 0.34;
    let head_center = egui::pos2(cx, inner.top() + head_r + 1.0);
    // Key bow: hollow circle, with an inner darker dot for depth.
    painter.circle_stroke(head_center, head_r, egui::Stroke::new(1.6, COLOR_ACCENT));
    painter.circle_filled(head_center, head_r - 3.0, COLOR_CHROME);
    // Key shaft.
    let shaft_top = head_center.y + head_r - 1.0;
    let shaft_half_w = 1.2;
    painter.rect_filled(
        egui::Rect::from_min_max(
            egui::pos2(cx - shaft_half_w, shaft_top),
            egui::pos2(cx + shaft_half_w, inner.bottom() - 1.0),
        ),
        egui::CornerRadius::same(1),
        COLOR_ACCENT,
    );
    // Key tooth.
    painter.rect_filled(
        egui::Rect::from_min_max(
            egui::pos2(cx + shaft_half_w, inner.bottom() - 4.5),
            egui::pos2(cx + shaft_half_w + 3.5, inner.bottom() - 2.0),
        ),
        egui::CornerRadius::same(1),
        COLOR_ACCENT,
    );
}

/// Paint a small magnifier glyph for the search bar — a hollow ring
/// with a short diagonal handle. Hand-painted because the bundled font
/// stack has no search glyph (and the UI avoids emoji), the same reason
/// the app logo and key are drawn from primitives.
fn paint_search_glyph(ui: &mut egui::Ui, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(15.0, 16.0), egui::Sense::hover());
    let painter = ui.painter();
    let lens_center = egui::pos2(rect.left() + 6.0, rect.center().y - 1.0);
    let lens_radius = 4.5;
    let stroke = egui::Stroke::new(1.5, color);
    painter.circle_stroke(lens_center, lens_radius, stroke);
    // Handle: a short segment off the lens at ~45°.
    let offset = lens_radius * std::f32::consts::FRAC_1_SQRT_2;
    let handle_start = lens_center + egui::vec2(offset, offset);
    let handle_end = handle_start + egui::vec2(3.5, 3.5);
    painter.line_segment([handle_start, handle_end], stroke);
}

/// Linear interpolate between two colours, component-wise on the
/// straight (un-premultiplied) channels. `t` is clamped to `0..=1`, and
/// `t == 0` returns `a` byte-for-byte — which is what keeps the resting
/// (`pulse == 0`) chrome pixel-identical to before the highlight existed.
fn lerp_color(a: egui::Color32, b: egui::Color32, t: f32) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    egui::Color32::from_rgba_unmultiplied(
        mix(a.r(), b.r()),
        mix(a.g(), b.g()),
        mix(a.b(), b.b()),
        mix(a.a(), b.a()),
    )
}

/// `pulse` (0.0 = rest, 1.0 = peak) flashes the badge when a new ask just
/// arrived: the soft pill fills to solid accent with near-white text, then
/// the child's frame loop decays it back to rest.
fn paint_count_badge(ui: &mut egui::Ui, pending: usize, process_count: usize, pulse: f32) {
    let label = if process_count > 1 {
        format!("{pending} pending · {process_count} apps")
    } else {
        format!("{pending} pending")
    };
    let fill = lerp_color(COLOR_ACCENT_SOFT, COLOR_ACCENT, pulse);
    let stroke = lerp_color(COLOR_ACCENT, COLOR_TEXT, pulse * 0.5);
    let text = lerp_color(COLOR_ACCENT, COLOR_TEXT, pulse);
    egui::Frame::new()
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(10, 5))
        .stroke(egui::Stroke::new(1.0, stroke))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("●").size(8.0).color(text));
                ui.label(egui::RichText::new(label).size(11.0).strong().color(text));
            });
        });
}

fn render_tab_bar(
    ui: &mut egui::Ui,
    current: &mut Tab,
    tree: &ProcessTree,
    audit_count: usize,
    rule_count: usize,
    pending_pulse: f32,
) {
    let pending = tree.total_leaf_rows();
    ui.horizontal(|ui| {
        let pending_label = if pending > 0 {
            format!("Pending  {pending}")
        } else {
            "Pending".to_owned()
        };
        render_tab(
            ui,
            &pending_label,
            *current == Tab::Pending,
            pending_pulse,
            || {
                *current = Tab::Pending;
            },
        );
        ui.add_space(6.0);
        let rules_label = if rule_count > 0 {
            format!("Rules  {rule_count}")
        } else {
            "Rules".to_owned()
        };
        render_tab(ui, &rules_label, *current == Tab::Rules, 0.0, || {
            *current = Tab::Rules;
        });
        ui.add_space(6.0);
        let audit_label = if audit_count > 0 {
            format!("Audit log  {audit_count}")
        } else {
            "Audit log".to_owned()
        };
        render_tab(ui, &audit_label, *current == Tab::Audit, 0.0, || {
            *current = Tab::Audit;
        });
    });
}

/// One underline-style tab. Active tab gets accent text + a 2px
/// accent underline; inactive tab uses muted text with no underline.
/// Both are clickable. Cheaper-looking than egui's stock
/// `selectable_label` pill, and reads as a proper top-of-page tab bar
/// rather than two adjacent buttons.
///
/// `highlight` (0.0 = none) flashes an *inactive* tab toward the active
/// look — used by the Pending tab when a new ask arrives while the user
/// is on another tab. At `0.0` the inactive colours are unchanged.
fn render_tab(
    ui: &mut egui::Ui,
    label: &str,
    active: bool,
    highlight: f32,
    mut on_click: impl FnMut(),
) {
    let (text_color, underline_color) = if active {
        (egui::Color32::from_gray(235), COLOR_ACCENT)
    } else {
        (
            lerp_color(COLOR_MUTED, COLOR_ACCENT, highlight),
            lerp_color(egui::Color32::TRANSPARENT, COLOR_ACCENT, highlight),
        )
    };
    let text = egui::RichText::new(label)
        .size(13.0)
        .color(text_color)
        .strong();
    let resp = ui.add(egui::Label::new(text).sense(egui::Sense::click()));
    // 2px underline 4px below the text baseline. We paint it ourselves
    // (rather than relying on egui's underline styling) so it can be
    // accent-coloured on active tabs only, and stays a constant 2px
    // even when egui's animation system would otherwise fade it.
    let underline_y = resp.rect.bottom() + 4.0;
    let stroke = egui::Stroke::new(2.0, underline_color);
    ui.painter().hline(resp.rect.x_range(), underline_y, stroke);
    if resp.clicked() {
        on_click();
    }
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
}

fn render_pending_page(
    ui: &mut egui::Ui,
    tree: &ProcessTree,
    collapsed: &mut HashMap<(u32, u64), bool>,
    actions: &mut Vec<PendingAction>,
    audit: &AuditCache,
    viewer_mode: bool,
) {
    if tree.roots.is_empty() {
        render_empty_state(ui, viewer_mode);
        return;
    }
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let last_root_idx = tree.roots.len().saturating_sub(1);
            for (i, &root_idx) in tree.roots.iter().enumerate() {
                // Each root is its own tree with no parent — start
                // with an empty `last_path`. The top root keeps the
                // keyboard-accelerator emphasis (no border anymore,
                // accent-coloured name instead).
                render_node(
                    ui,
                    tree,
                    root_idx,
                    i == 0,
                    0,
                    &[],
                    collapsed,
                    actions,
                    audit,
                );
                if i < last_root_idx {
                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(6.0);
                }
            }
        });
}

fn render_audit_page(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    audit: &AuditCache,
    rules_draft: &mut Option<RuleDraft>,
    current_tab: &mut Tab,
    search: &mut String,
    search_focus_pending: &mut bool,
) {
    if audit.entries.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(32.0);
            ui.label(
                egui::RichText::new("No audit entries yet.")
                    .size(16.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Every grant decision will land here once you make one.")
                    .color(COLOR_MUTED),
            );
        });
        return;
    }

    // Cap the render at 200 to mirror the previous behavior; do the
    // cap AFTER filtering so a user searching for an old wrap can
    // still find it in a long history.
    let total = audit.entries.len();
    let query = search.trim().to_owned();
    let filtered: Vec<&AuditEntry> = audit
        .entries
        .iter()
        .rev()
        .filter(|e| audit_entry_matches(e, &query))
        .take(200)
        .collect();

    render_audit_search_bar(ctx, ui, search, search_focus_pending, filtered.len(), total);
    ui.add_space(10.0);

    if filtered.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(28.0);
            ui.label(
                egui::RichText::new("No matching entries")
                    .size(15.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Try a different search, or clear it to see everything.")
                    .color(COLOR_MUTED),
            );
        });
        return;
    }

    let now = now_unix();
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // Newest first — that's what you want to scan in a console
            // session. Day-bucket headers give the eye an anchor while
            // scanning.
            let mut last_bucket: Option<String> = None;
            for entry in &filtered {
                let bucket = audit_day_bucket(entry.ts_unix, now);
                if last_bucket.as_deref() != Some(bucket.as_str()) {
                    if last_bucket.is_some() {
                        ui.add_space(6.0);
                    }
                    ui.label(
                        egui::RichText::new(&bucket)
                            .size(11.0)
                            .strong()
                            .color(COLOR_FOOTNOTE),
                    );
                    ui.add_space(4.0);
                    last_bucket = Some(bucket);
                }
                render_audit_entry(ui, entry, now, rules_draft, current_tab);
            }
        });
}

/// Search-bar row at the top of the Audit tab. Always visible (no
/// modal toggle). The whole row is wrapped in a card frame so it sits
/// in the same design language as the rule-form inputs and the entry
/// cards below it, rather than floating as a bare egui text box. The
/// input is frameless inside the card; the right edge carries a muted
/// match count and a faint shortcut-hint chip. Cmd/Ctrl+F focuses it.
fn render_audit_search_bar(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    search: &mut String,
    focus_pending: &mut bool,
    matches: usize,
    total: usize,
) {
    let shortcut_label = match ctx.os() {
        // Space between the glyph and the key: the ⌘ and F otherwise
        // kern almost on top of each other in the keycap chip.
        egui::os::OperatingSystem::Mac => "⌘ F",
        _ => "Ctrl+F",
    };
    let count_label = if search.trim().is_empty() {
        format!("{total} {}", if total == 1 { "entry" } else { "entries" })
    } else {
        format!("{matches} of {total}")
    };
    egui::Frame::new()
        .fill(COLOR_CARD)
        .stroke(egui::Stroke::new(1.0, COLOR_CARD_STROKE))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(12, 7))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                // A leading magnifier glyph reads as "search" without an
                // emoji; painted from primitives since the font stack
                // has no search glyph.
                paint_search_glyph(ui, COLOR_MUTED);
                ui.add_space(4.0);
                // The input flexes to fill the row; reserve room on the
                // right for the count + shortcut chip.
                let resp = ui.add(
                    egui::TextEdit::singleline(search)
                        .frame(egui::Frame::NONE)
                        .hint_text("Search wrap, args, ancestor, secret, decision…")
                        .desired_width(ui.available_width() - 150.0),
                );
                if *focus_pending {
                    resp.request_focus();
                    *focus_pending = false;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::Frame::new()
                        .fill(COLOR_CHROME)
                        .corner_radius(egui::CornerRadius::same(5))
                        .inner_margin(egui::Margin::symmetric(6, 2))
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new(shortcut_label)
                                    .color(COLOR_FOOTNOTE)
                                    .size(10.0),
                            );
                        });
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(count_label)
                            .color(COLOR_MUTED)
                            .size(11.0),
                    );
                });
            });
        });
}

/// Pure predicate: does `entry` match `query`? The query is split into
/// whitespace-separated terms; the entry matches when **every** term is
/// a case-insensitive substring of **some** field — the wrap name, any
/// argv token, each caller's `name`/`command`, any requested secret
/// name, or the decision string.
///
/// The per-term / any-field split is load-bearing: it lets `"gh auth"`
/// match a wrap named `gh` whose argv was `auth token`, where `"gh"`
/// hits the wrap and `"auth"` hits an arg even though no single field
/// holds the literal `"gh auth"`. AND across terms means each added
/// word narrows the result set, the behaviour a user expects from a
/// search box. An empty / whitespace-only query yields no terms, so the
/// all-terms predicate is vacuously true and matches everything.
fn audit_entry_matches(entry: &AuditEntry, query: &str) -> bool {
    let terms: Vec<String> = query
        .split_whitespace()
        .map(|t| t.to_ascii_lowercase())
        .collect();
    if terms.is_empty() {
        return true;
    }
    // Lowercase every searchable field once, then test each term
    // against the set — cheaper than re-lowercasing per term.
    let mut fields: Vec<String> = Vec::with_capacity(2 + entry.args.len() + entry.secrets.len());
    fields.push(entry.wrap.to_ascii_lowercase());
    fields.push(entry.decision.to_ascii_lowercase());
    fields.extend(entry.args.iter().map(|a| a.to_ascii_lowercase()));
    for caller in &entry.callers {
        fields.push(caller.name.to_ascii_lowercase());
        fields.push(caller.command.to_ascii_lowercase());
    }
    fields.extend(entry.secrets.iter().map(|s| s.to_ascii_lowercase()));

    terms
        .iter()
        .all(|term| fields.iter().any(|field| field.contains(term)))
}

// ── Rules tab ────────────────────────────────────────────────────────────
//
// Two modes: list (the default) and form (visible while
// `window_state.rules_draft` is `Some`). The form covers both Create
// and Edit; the `id` field of the draft discriminates which.

/// Mutable UI state the rules page threads into its sub-renderers.
/// Bundled so the render fns stay under the argument-count lint while
/// each field still maps 1:1 onto a `ConsentWindowState` slot.
struct RulesUi<'a> {
    draft: &'a mut Option<RuleDraft>,
    dismissed: &'a mut HashSet<String>,
    suggestion_sort: &'a mut SuggestionSort,
    rule_sort: &'a mut RuleSort,
}

fn render_rules_page(
    ui: &mut egui::Ui,
    rule_rows: &[(&Rule, RuleUsage)],
    suggestions: &[Suggestion],
    state: &mut RulesUi,
    actions_out: &mut Vec<RuleAction>,
) {
    if state.draft.is_some() {
        render_rule_form(ui, state.draft, actions_out);
        return;
    }
    render_rules_list(ui, rule_rows, suggestions, state, actions_out);
}

fn render_rules_list(
    ui: &mut egui::Ui,
    rule_rows: &[(&Rule, RuleUsage)],
    suggestions: &[Suggestion],
    state: &mut RulesUi,
    actions_out: &mut Vec<RuleAction>,
) {
    let has_suggestions = !suggestions.is_empty();
    let has_rules = !rule_rows.is_empty();

    ui.horizontal(|ui| {
        if ui.button("+ New rule").clicked() {
            *state.draft = Some(RuleDraft::fresh());
        }
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "Rules fire before the consent prompt. Deny rules win; \
                 most-specific approve wins ties.",
            )
            .color(COLOR_MUTED)
            .size(11.0),
        );
    });
    ui.add_space(12.0);

    if !has_suggestions && !has_rules {
        ui.vertical_centered(|ui| {
            ui.add_space(32.0);
            ui.label(
                egui::RichText::new("No rules yet.")
                    .size(16.0)
                    .strong()
                    .color(COLOR_TEXT),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Add a rule to auto-approve or auto-deny matching asks \
                     without prompting.",
                )
                .color(COLOR_MUTED),
            );
        });
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // Configured rules first, each under a labelled section
            // header (so the list isn't an unlabelled slab next to the
            // "Suggested rules" header below it). Suggestions follow —
            // they're proposals, secondary to rules the user has saved.
            if has_rules {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Your rules")
                            .size(12.0)
                            .strong()
                            .color(COLOR_MUTED),
                    );
                    // Sort toggle lives in the section header, mirroring
                    // the suggestions section's own toggle.
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.selectable_value(state.rule_sort, RuleSort::MostRecent, "Recent");
                        ui.selectable_value(state.rule_sort, RuleSort::MostUsed, "Most used");
                        ui.label(egui::RichText::new("Sort").size(11.0).color(COLOR_FOOTNOTE));
                    });
                });
                ui.add_space(8.0);
                let now = now_unix();
                for (rule, usage) in rule_rows {
                    render_rules_row(ui, rule, *usage, now, state.draft, actions_out);
                    ui.add_space(8.0);
                }
            }
            if has_suggestions {
                if has_rules {
                    ui.add_space(14.0);
                }
                render_suggestions_section(
                    ui,
                    suggestions,
                    state.draft,
                    state.dismissed,
                    state.suggestion_sort,
                );
            }
        });
}

/// "Suggested rules" header + one card per visible recommendation.
/// The cards funnel into the same rule form as `+ New rule` — clicking
/// "Review & save" opens the form pre-populated; "Dismiss" hides the
/// card for the rest of this consent-window session.
fn render_suggestions_section(
    ui: &mut egui::Ui,
    suggestions: &[Suggestion],
    draft: &mut Option<RuleDraft>,
    dismissed: &mut HashSet<String>,
    sort: &mut SuggestionSort,
) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("Suggested rules")
                .size(12.0)
                .strong()
                .color(COLOR_MUTED),
        );
        // Sort toggle, right-aligned on the header row. In a
        // right-to-left layout the first-added widget sits rightmost,
        // so add "Recent" first to land the pair as [Most used][Recent].
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.selectable_value(sort, SuggestionSort::MostRecent, "Recent");
            ui.selectable_value(sort, SuggestionSort::MostUsed, "Most used");
            ui.label(egui::RichText::new("Sort").size(11.0).color(COLOR_FOOTNOTE));
        });
    });
    ui.add_space(2.0);
    ui.label(
        egui::RichText::new(
            "Patterns we noticed in your recent decisions. Review one to seed a rule.",
        )
        .size(11.0)
        .color(COLOR_FOOTNOTE),
    );
    ui.add_space(8.0);
    for s in suggestions {
        render_suggestion_card(ui, s, draft, dismissed);
        ui.add_space(8.0);
    }
}

fn render_suggestion_card(
    ui: &mut egui::Ui,
    s: &Suggestion,
    draft: &mut Option<RuleDraft>,
    dismissed: &mut HashSet<String>,
) {
    egui::Frame::new()
        .fill(COLOR_CARD)
        .stroke(egui::Stroke::new(1.0, COLOR_ACCENT_SOFT))
        .inner_margin(egui::Margin::same(12))
        .corner_radius(egui::CornerRadius::same(8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (pill_fg, pill_bg, pill_text) = match s.decide {
                    SuggestionDecision::Approve => {
                        (COLOR_APPROVE_BG, COLOR_APPROVE_SOFT, "approve")
                    }
                    SuggestionDecision::Deny => (COLOR_DENY_BG, COLOR_DENY_SOFT, "deny"),
                };
                render_pill(ui, pill_text, pill_fg, pill_bg);
                ui.add_space(8.0);
                // Explicit COLOR_TEXT: `.strong()` alone resolves through
                // `visuals.strong_text_color()` (a widget stroke we don't
                // override), which renders off-palette against the dark
                // card. The rule rows set the colour for the same reason.
                ui.label(
                    egui::RichText::new(format!("{} from {}", s.wrap, s.ancestor))
                        .strong()
                        .color(COLOR_TEXT),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Dismiss").clicked() {
                        dismissed.insert(s.key.clone());
                    }
                    if ui.button("Review & save").clicked() {
                        *draft = Some(RuleDraft::from_suggestion(s));
                    }
                });
            });
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(suggestion_summary_line(s))
                    .color(COLOR_MUTED)
                    .size(11.0),
            );
            ui.label(
                egui::RichText::new(format!(
                    "{count} {asks} in the last 30 days · last seen {recency}",
                    count = s.count,
                    asks = if s.count == 1 { "ask" } else { "asks" },
                    recency = recency_label(s.last_ts_unix, now_unix()),
                ))
                .color(COLOR_FOOTNOTE)
                .size(10.0),
            );
        });
}

/// Recency phrase for an inline footnote — "today", "2 days ago",
/// "last week", etc. Reuses the audit tab's day-bucketing so every
/// surface agrees on how a timestamp reads, then lowercases the leading
/// word so it folds into an inline "last … {recency}" sentence. Shared
/// by the suggestion cards and the rule rows, both of which surface a
/// last-seen / last-fired key alongside a count.
fn recency_label(last_ts_unix: u64, now_unix: u64) -> String {
    let bucket = audit_day_bucket(last_ts_unix, now_unix);
    let mut chars = bucket.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
        None => bucket,
    }
}

/// Per-rule auto-fire tallies, aggregated from the audit cache. A rule
/// "fires" when it auto-approves or auto-denies an ask; the daemon
/// stamps each such audit row with the rule's id (`AuditEntry::rule_id`),
/// so counting rows by id gives the rule's usage. `last_ts_unix` is the
/// most recent fire, or `None` for a rule that has never fired (within
/// the audit cache's retained window).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RuleUsage {
    count: usize,
    last_ts_unix: Option<u64>,
}

/// One pass over the audit cache, bucketing fires by `rule_id`. Rules
/// that never fired simply won't appear in the map; the caller defaults
/// them to `RuleUsage::default()` (count 0, no last-fire).
fn rule_usage_index(entries: &[AuditEntry]) -> HashMap<String, RuleUsage> {
    let mut map: HashMap<String, RuleUsage> = HashMap::new();
    for e in entries {
        let Some(id) = &e.rule_id else {
            continue;
        };
        let u = map.entry(id.clone()).or_default();
        u.count += 1;
        if u.last_ts_unix.is_none_or(|last| e.ts_unix >= last) {
            u.last_ts_unix = Some(e.ts_unix);
        }
    }
    map
}

/// How the Rules tab orders its rows. Mirrors the suggestion sort but
/// keyed on each rule's [`RuleUsage`]. Default is `MostUsed`; rules that
/// have never fired (count 0, no last-fire) fall to the bottom under
/// either mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleSort {
    /// Most auto-fires first; most-recent fire breaks ties.
    #[default]
    MostUsed,
    /// Most-recently-fired first; higher count breaks ties.
    MostRecent,
}

impl RuleSort {
    /// Order `rows` (rule + its usage) in place. Stable and total: ties
    /// fall through to the other key, then to the rule name, then id.
    fn sort(self, rows: &mut [(&Rule, RuleUsage)]) {
        match self {
            RuleSort::MostUsed => rows.sort_by(|a, b| {
                b.1.count
                    .cmp(&a.1.count)
                    .then_with(|| b.1.last_ts_unix.cmp(&a.1.last_ts_unix))
                    .then_with(|| a.0.name.cmp(&b.0.name))
                    .then_with(|| a.0.id.cmp(&b.0.id))
            }),
            RuleSort::MostRecent => rows.sort_by(|a, b| {
                b.1.last_ts_unix
                    .cmp(&a.1.last_ts_unix)
                    .then_with(|| b.1.count.cmp(&a.1.count))
                    .then_with(|| a.0.name.cmp(&b.0.name))
                    .then_with(|| a.0.id.cmp(&b.0.id))
            }),
        }
    }
}

/// Footnote describing a rule's auto-fire history, e.g. "12 auto-fires ·
/// last fired today" or "No auto-fires yet" for a rule that's never
/// matched an ask.
fn rule_usage_line(usage: RuleUsage, now_unix: u64) -> String {
    match usage.last_ts_unix {
        Some(last) => format!(
            "{count} {fires} · last fired {recency}",
            count = usage.count,
            fires = if usage.count == 1 {
                "auto-fire"
            } else {
                "auto-fires"
            },
            recency = recency_label(last, now_unix),
        ),
        None => "No auto-fires yet".to_owned(),
    }
}

fn suggestion_summary_line(s: &Suggestion) -> String {
    let mut parts = vec![format!("wrap: {}", s.wrap)];
    if let Some(p) = &s.argv {
        parts.push(format!("argv: '{p}'"));
    }
    parts.push(format!("ancestor: '{}'", s.ancestor));
    if let Some(p) = &s.cwd {
        parts.push(format!("cwd: '{p}'"));
    }
    parts.join(" · ")
}

fn render_rules_row(
    ui: &mut egui::Ui,
    rule: &Rule,
    usage: RuleUsage,
    now_unix: u64,
    draft: &mut Option<RuleDraft>,
    actions_out: &mut Vec<RuleAction>,
) {
    egui::Frame::new()
        .fill(COLOR_CARD)
        .stroke(egui::Stroke::new(1.0, COLOR_CARD_STROKE))
        .inner_margin(egui::Margin::same(12))
        .corner_radius(egui::CornerRadius::same(8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                // Enable toggle — emits SetEnabled the moment it
                // changes so the daemon mirrors the bit immediately.
                let mut enabled = rule.enabled;
                if ui.checkbox(&mut enabled, "").changed() {
                    actions_out.push(RuleAction::SetEnabled {
                        id: rule.id.clone(),
                        enabled,
                    });
                }

                // Decide pill — green for approve, red for deny. A
                // disabled rule fades the pill to a neutral grey chip
                // so the live semantic colour is reserved for rules
                // that can actually fire.
                let (pill_fg, pill_bg, pill_text) = match rule.decide {
                    RuleDecision::Approve => (COLOR_APPROVE_BG, COLOR_APPROVE_SOFT, "approve"),
                    RuleDecision::Deny => (COLOR_DENY_BG, COLOR_DENY_SOFT, "deny"),
                };
                if rule.enabled {
                    render_pill(ui, pill_text, pill_fg, pill_bg);
                } else {
                    render_pill(ui, pill_text, COLOR_MUTED, COLOR_CHROME);
                }

                ui.add_space(8.0);
                let name_color = if rule.enabled {
                    COLOR_TEXT
                } else {
                    COLOR_MUTED
                };
                ui.label(egui::RichText::new(&rule.name).strong().color(name_color));
                if !rule.enabled {
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("disabled")
                            .size(10.5)
                            .color(COLOR_FOOTNOTE),
                    );
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Delete").clicked() {
                        actions_out.push(RuleAction::Delete(rule.id.clone()));
                    }
                    if ui.button("Edit").clicked() {
                        *draft = Some(RuleDraft::from_rule(rule));
                    }
                });
            });
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(rule_summary_line(rule))
                    .color(COLOR_MUTED)
                    .size(11.0),
            );
            // Auto-fire history. A rule that's actually firing gets the
            // brighter muted tone to reward the user's trust in it; a
            // never-fired rule stays in the dim footnote register.
            let usage_color = if usage.count > 0 {
                COLOR_MUTED
            } else {
                COLOR_FOOTNOTE
            };
            ui.label(
                egui::RichText::new(rule_usage_line(usage, now_unix))
                    .color(usage_color)
                    .size(10.0),
            );
            if !rule.trained_secrets.is_empty() {
                let trained = rule
                    .trained_secrets
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                ui.label(
                    egui::RichText::new(format!("trained: {trained}"))
                        .color(COLOR_FOOTNOTE)
                        .size(10.0),
                )
                .on_hover_text(
                    "This rule fires only for asks whose requested env-var set \
                     is a subset of the names listed here. Editing the wrap to add \
                     new env vars will quietly block the rule until you save it again \
                     with the updated set.",
                );
            }
        });
}

/// One-line summary of the rule's match clause for the list view.
/// Skips empty match fields; collapses to "wrap: gh" when nothing
/// else is constrained.
fn rule_summary_line(rule: &Rule) -> String {
    let mut parts = vec![format!("wrap: {}", rule.r#match.wrap)];
    if let Some(p) = &rule.r#match.argv {
        parts.push(format!("argv: '{}'", p.as_str()));
    }
    if let Some(p) = &rule.r#match.ancestor {
        parts.push(format!("ancestor: '{}'", p.as_str()));
    }
    if let Some(p) = &rule.r#match.cwd {
        parts.push(format!("cwd: '{}'", p.as_str()));
    }
    parts.join(" · ")
}

fn render_rule_form(
    ui: &mut egui::Ui,
    draft_slot: &mut Option<RuleDraft>,
    actions_out: &mut Vec<RuleAction>,
) {
    // Pull the draft out of the slot so we can mutate freely and put
    // it back at the end (or drop it on cancel/save). This avoids
    // double-mutable-borrow gymnastics on `*draft_slot`.
    let Some(mut draft) = draft_slot.take() else {
        return;
    };
    let editing = draft.id.is_some();
    let header_text = if editing { "Edit rule" } else { "New rule" };

    let mut save_clicked = false;
    let mut cancel_clicked = false;

    // ── Header: title + a live preview of the decide pill ──
    //
    // Stays pinned outside the scroll area so the user always
    // knows what rule they're editing.
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(header_text)
                .size(16.0)
                .strong()
                .color(COLOR_TEXT),
        );
        ui.add_space(8.0);
        let (pill_fg, pill_bg, pill_text) = match draft.decide {
            RuleDecisionDraft::Approve => (COLOR_APPROVE_BG, COLOR_APPROVE_SOFT, "approve"),
            RuleDecisionDraft::Deny => (COLOR_DENY_BG, COLOR_DENY_SOFT, "deny"),
        };
        render_pill(ui, pill_text, pill_fg, pill_bg);
    });
    ui.add_space(10.0);

    // ── Split the available area: scrollable body on top, pinned
    //    action bar at the bottom. Both regions render top-down
    //    (default layout); we manually reserve the bottom strip
    //    rather than relying on `bottom_up`, which would reverse the
    //    intra-row order of labels and inputs.
    //
    // Dry-run conversion every frame so Save's enabled state and
    // the banner reflect the current draft.
    let validation = draft.clone().into_rule();
    let action_bar_h = if validation.is_err() {
        // banner (~32) + spacing (8) + buttons (30) + padding
        86.0
    } else {
        // buttons (30) + padding
        46.0
    };
    let available_rect = ui.available_rect_before_wrap();
    let split_y = (available_rect.max.y - action_bar_h).max(available_rect.min.y);
    let body_rect = egui::Rect::from_min_max(
        available_rect.min,
        egui::pos2(available_rect.max.x, split_y),
    );
    let action_rect = egui::Rect::from_min_max(
        egui::pos2(available_rect.min.x, split_y),
        available_rect.max,
    );

    // Scrollable form body (top-down).
    ui.scope_builder(egui::UiBuilder::new().max_rect(body_rect), |ui| {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                render_rule_form_body(ui, &mut draft);
            });
    });

    // Action bar (top-down). Separator at the top, optional
    // validation banner, then Save / Cancel buttons.
    ui.scope_builder(egui::UiBuilder::new().max_rect(action_rect), |ui| {
        let sep_rect = egui::Rect::from_min_size(
            ui.cursor().left_top(),
            egui::vec2(ui.available_width(), 1.0),
        );
        ui.painter().rect_filled(sep_rect, 0.0, COLOR_DIVIDER);
        ui.add_space(10.0);
        if let Err(msg) = &validation {
            render_form_error_banner(ui, msg);
            ui.add_space(8.0);
        }
        ui.horizontal(|ui| {
            let save_enabled = validation.is_ok();
            let save_resp = render_primary_button(ui, "Save", save_enabled);
            if save_resp.clicked() && save_enabled {
                save_clicked = true;
            }
            ui.add_space(6.0);
            if render_secondary_button(ui, "Cancel").clicked() {
                cancel_clicked = true;
            }
        });
    });
    if cancel_clicked {
        // draft dropped — slot stays None, list view returns.
        return;
    }
    if save_clicked {
        match draft.clone().into_rule() {
            Ok(rule) => {
                if editing {
                    actions_out.push(RuleAction::Update(rule));
                } else {
                    actions_out.push(RuleAction::Add(rule));
                }
                return; // success → close form
            }
            Err(_) => {
                // Defense-in-depth: render_primary_button's gating
                // should have suppressed the click, but if it didn't,
                // we still refuse to ship an invalid rule.
                *draft_slot = Some(draft);
                return;
            }
        }
    }
    // Form still open; put the draft back.
    *draft_slot = Some(draft);
}

/// The scrollable middle of the rule form. Renders three section
/// cards: Basics (name + decide), Match (wrap + patterns), Outcome
/// (enabled + deny_message + trained-on chip). Kept as its own
/// function so the parent can compose it with a pinned action bar.
fn render_rule_form_body(ui: &mut egui::Ui, draft: &mut RuleDraft) {
    // ── Section 1: Basics ──────────────────────────────────
    render_form_section_card(ui, "Basics", |ui| {
        render_form_field(ui, "Name", None, |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut draft.name)
                    .hint_text("e.g. Cursor reads via gh")
                    .desired_width(f32::INFINITY),
            )
        });
        ui.add_space(8.0);
        render_form_field(
            ui,
            "Decide",
            Some(
                "Deny rules win over approves when both match. \
                 Among approves, the most-specific match fires.",
            ),
            |ui| render_decide_toggle(ui, &mut draft.decide),
        );
    });

    ui.add_space(10.0);

    // ── Section 2: When this rule fires ────────────────────
    render_form_section_card(ui, "When this rule fires", |ui| {
        render_form_field(
            ui,
            "Wrap",
            Some("Exact match against the wrap (binary) name."),
            |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut draft.wrap)
                        .hint_text("e.g. gh")
                        .font(egui::FontId::monospace(12.5))
                        .desired_width(f32::INFINITY),
                )
            },
        );
        ui.add_space(8.0);
        render_form_field(
            ui,
            "Argv pattern",
            Some(
                "Matched against the joined argv of the wrap. \
                 Glob (* ? [abc]) or literal-prefix. Blank = any.",
            ),
            |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut draft.argv)
                        .hint_text("e.g. gh api --get /repos/*/pulls*")
                        .font(egui::FontId::monospace(12.5))
                        .desired_width(f32::INFINITY),
                )
            },
        );
        ui.add_space(8.0);
        render_form_field(
            ui,
            "Ancestor",
            Some(
                "Substring (literal) or glob, matched against each caller's \
                 process name AND full command line. Hits if any ancestor matches.",
            ),
            |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut draft.ancestor)
                        .hint_text("e.g. Cursor.app")
                        .font(egui::FontId::monospace(12.5))
                        .desired_width(f32::INFINITY),
                )
            },
        );
        ui.add_space(8.0);
        render_form_field(
            ui,
            "Working directory",
            Some("Glob or literal-prefix, matched against the requesting cwd."),
            |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut draft.cwd)
                        .hint_text("e.g. ~/work/myproject/**")
                        .font(egui::FontId::monospace(12.5))
                        .desired_width(f32::INFINITY),
                )
            },
        );
    });

    ui.add_space(10.0);

    // ── Section 3: Outcome ────────────────────────────────
    render_form_section_card(ui, "Outcome", |ui| {
        ui.horizontal(|ui| {
            ui.checkbox(&mut draft.enabled, "");
            ui.label(
                egui::RichText::new(if draft.enabled {
                    "Enabled — rule will fire on matching asks."
                } else {
                    "Disabled — rule is saved but the evaluator skips it."
                })
                .color(if draft.enabled {
                    COLOR_TEXT
                } else {
                    COLOR_MUTED
                }),
            );
        });

        if draft.decide == RuleDecisionDraft::Deny {
            ui.add_space(10.0);
            render_form_field(
                ui,
                "Deny message",
                Some(
                    "Shown to the user on auto-deny — in the terminal \
                     via stderr and in the consent window as a toast.",
                ),
                |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut draft.deny_message)
                            .hint_text("e.g. Use the UI for destructive operations.")
                            .desired_rows(2)
                            .desired_width(f32::INFINITY),
                    )
                },
            );
        }

        if !draft.trained_secrets.is_empty() {
            ui.add_space(10.0);
            render_trained_secrets_chip(ui, &draft.trained_secrets);
        }
    });
}

/// One framed section in the rule form. Title sits at the top in a
/// small footnote-tier label so it doesn't compete with field labels;
/// the body lays out vertically below.
fn render_form_section_card<F: FnOnce(&mut egui::Ui)>(ui: &mut egui::Ui, title: &str, body: F) {
    egui::Frame::new()
        .fill(COLOR_CARD)
        .stroke(egui::Stroke::new(1.0, COLOR_CARD_STROKE))
        .corner_radius(egui::CornerRadius::same(CARD_CORNER_RADIUS))
        .inner_margin(egui::Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(title.to_uppercase())
                    .size(10.5)
                    .strong()
                    .color(COLOR_FOOTNOTE)
                    .extra_letter_spacing(0.6),
            );
            ui.add_space(8.0);
            body(ui);
        });
}

/// One labeled field: bold-ish label at top, body in the middle,
/// optional helper text below in footnote tier.
fn render_form_field<R, F: FnOnce(&mut egui::Ui) -> R>(
    ui: &mut egui::Ui,
    label: &str,
    helper: Option<&str>,
    body: F,
) -> R {
    ui.label(
        egui::RichText::new(label)
            .size(12.0)
            .strong()
            .color(COLOR_TEXT),
    );
    ui.add_space(3.0);
    let r = body(ui);
    if let Some(h) = helper {
        ui.add_space(3.0);
        ui.label(egui::RichText::new(h).color(COLOR_FOOTNOTE).size(10.5));
    }
    r
}

/// Segmented two-option toggle for the rule's decide direction. The
/// active option is filled with its semantic-soft colour
/// (`COLOR_ACCENT_SOFT` for approve, `COLOR_DENY_SOFT` for deny);
/// the inactive option is a muted chip. Clicking either switches the
/// draft. Reads as "this rule will approve / this rule will deny"
/// without needing to parse the bullet-radio convention.
fn render_decide_toggle(ui: &mut egui::Ui, decide: &mut RuleDecisionDraft) -> egui::Response {
    ui.horizontal(|ui| {
        let approve_resp = render_decide_segment(
            ui,
            "approve",
            *decide == RuleDecisionDraft::Approve,
            COLOR_ACCENT_SOFT,
            COLOR_ACCENT,
        );
        if approve_resp.clicked() {
            *decide = RuleDecisionDraft::Approve;
        }
        ui.add_space(6.0);
        let deny_resp = render_decide_segment(
            ui,
            "deny",
            *decide == RuleDecisionDraft::Deny,
            COLOR_DENY_SOFT,
            COLOR_DENY_HINT,
        );
        if deny_resp.clicked() {
            *decide = RuleDecisionDraft::Deny;
        }
    })
    .response
}

fn render_decide_segment(
    ui: &mut egui::Ui,
    label: &str,
    active: bool,
    active_fill: egui::Color32,
    active_stroke: egui::Color32,
) -> egui::Response {
    let (fill, stroke_color, text_color) = if active {
        (active_fill, active_stroke, egui::Color32::WHITE)
    } else {
        (COLOR_CHROME, COLOR_CARD_STROKE, COLOR_MUTED)
    };
    let frame = egui::Frame::new()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, stroke_color))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(14, 6));
    let inner = frame.show(ui, |ui| {
        ui.label(
            egui::RichText::new(label)
                .color(text_color)
                .strong()
                .size(12.5),
        );
    });
    let resp = inner.response.interact(egui::Sense::click());
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// Inline validation banner. Appears above the action bar when the
/// draft fails to convert into a [`Rule`]. Same accent treatment as
/// the auto-deny toast so the visual language is consistent.
fn render_form_error_banner(ui: &mut egui::Ui, msg: &str) {
    egui::Frame::new()
        .fill(COLOR_DENY_SOFT)
        .stroke(egui::Stroke::new(1.0, COLOR_DENY_HINT))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(12, 7))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("Can't save: {msg}"))
                    .color(COLOR_TEXT)
                    .size(11.5),
            );
        });
}

/// Primary action button — accent-filled, white text. Disabled state
/// dims the fill and renders the text in COLOR_MUTED. The caller is
/// responsible for ignoring `clicked()` when `enabled == false`; we
/// also use `interact` semantics so the click is "absorbed" visually
/// (no hover cursor) when disabled.
fn render_primary_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    let (fill, text_color) = if enabled {
        (COLOR_ACCENT, egui::Color32::WHITE)
    } else {
        (COLOR_ACCENT_SOFT, COLOR_MUTED)
    };
    let btn = egui::Button::new(
        egui::RichText::new(label)
            .color(text_color)
            .strong()
            .size(12.5),
    )
    .fill(fill)
    .min_size(egui::Vec2::new(96.0, 30.0));
    let resp = ui.add(btn);
    if enabled && resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// Secondary action button — chrome-tinted, muted text. Used for
/// Cancel and for any non-destructive secondary action that should
/// share visual weight class with `render_primary_button` but lose
/// the "primary CTA" emphasis.
fn render_secondary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(egui::RichText::new(label).color(COLOR_TEXT).size(12.5))
        .fill(COLOR_CHROME)
        .min_size(egui::Vec2::new(96.0, 30.0));
    let resp = ui.add(btn);
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// "Trained on: {names}" badge with a hover-tooltip explaining the
/// guard. Replaces the plain inline label so the safety property
/// reads as a deliberate piece of UI rather than a footnote.
fn render_trained_secrets_chip(ui: &mut egui::Ui, trained: &std::collections::BTreeSet<String>) {
    let names = trained.iter().cloned().collect::<Vec<_>>().join(", ");
    egui::Frame::new()
        .fill(COLOR_CHROME)
        .stroke(egui::Stroke::new(1.0, COLOR_CARD_STROKE))
        .corner_radius(egui::CornerRadius::same(5))
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("trained on")
                        .color(COLOR_FOOTNOTE)
                        .size(10.5)
                        .strong()
                        .extra_letter_spacing(0.4),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(names)
                        .color(COLOR_TEXT)
                        .size(11.5)
                        .family(egui::FontFamily::Monospace),
                );
            })
            .response
            .on_hover_text(
                "Rule fires only for asks whose secret-set is a subset of these names. \
                 Prevents accidental release of new env vars when the wrap is later edited.",
            );
        });
}

/// Render the transient banner that appears at the top of the
/// Pending tab when an auto-deny rule fires. Caller is responsible
/// for fading it out by passing `None` once it has expired.
fn render_auto_deny_toast(ui: &mut egui::Ui, toast: &AutoDenyToastView) {
    egui::Frame::new()
        .fill(COLOR_DENY_SOFT)
        .stroke(egui::Stroke::new(1.0, COLOR_DENY_HINT))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("auto-denied · rule: '{}'", toast.rule_name))
                    .size(12.0)
                    .strong(),
            );
            if let Some(msg) = &toast.deny_message {
                ui.add_space(2.0);
                ui.label(egui::RichText::new(msg).color(COLOR_MUTED).size(11.0));
            }
        });
}

/// Decision pill for the Rules tab (approve / deny status badge).
///
/// Shares the audit tab's verdict-pill recipe so the two surfaces
/// speak one visual language: a soft dark `bg` fill, a 1px `fg`
/// stroke, a leading `fg` dot, and the label in `fg`. Drawing the
/// text in the *semantic* colour (bright green / red) rather than
/// plain white is what makes the badge read as approve/deny at a
/// glance instead of a dim chip lost against the card.
fn render_pill(ui: &mut egui::Ui, label: &str, fg: egui::Color32, bg: egui::Color32) {
    egui::Frame::new()
        .fill(bg)
        .stroke(egui::Stroke::new(1.0, fg))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(7, 2))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 5.0;
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("\u{25cf}").size(7.0).color(fg));
                ui.label(egui::RichText::new(label).size(11.0).strong().color(fg));
            });
        });
}

fn render_audit_entry(
    ui: &mut egui::Ui,
    entry: &AuditEntry,
    now: u64,
    rules_draft: &mut Option<RuleDraft>,
    current_tab: &mut Tab,
) {
    egui::Frame::new()
        .fill(COLOR_CARD)
        .stroke(egui::Stroke::new(1.0, COLOR_CARD_STROKE))
        .corner_radius(egui::CornerRadius::same(CARD_CORNER_RADIUS))
        .inner_margin(egui::Margin::symmetric(14, 10))
        .show(ui, |ui| {
            render_audit_card_body(ui, entry, now);
            // "Create rule from this ask…" — small affordance at the
            // bottom of each audit card. We deliberately don't make
            // it a context-menu (would require right-click discovery)
            // or hover-only (would hide a not-obvious feature).
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let resp = ui.add(
                        egui::Label::new(
                            egui::RichText::new("Create rule from this ask…")
                                .color(COLOR_ACCENT)
                                .size(11.0),
                        )
                        .sense(egui::Sense::click()),
                    );
                    if resp.clicked() {
                        *rules_draft = Some(RuleDraft::from_audit_entry(entry));
                        *current_tab = Tab::Rules;
                    }
                    if resp.hovered() {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    }
                });
            });
        });
    // Gap painted *after* the frame (mirrors the Pending tab's
    // `add_space(CARD_VERTICAL_GAP)`), avoiding an i8 outer-margin cast.
    ui.add_space(AUDIT_CARD_GAP);
}

/// Three-tier audit card body:
///
/// 1. **Command** (mono bold, measured-width truncation) on the left,
///    a stable right-aligned verdict pill column on the right. The
///    optional "remembered" tag is a *separate* accent pill so it can
///    never widen the verdict pill or shove its leading dot — the core
///    fix for the jittering verdict column.
/// 2. **Secret names** (never values) on their own wrapped line.
/// 3. **Provenance footer** — `from <caller> · N more · .../cwd · ago`,
///    all footnote-tier, with the full caller chain + cwd in a hover
///    tooltip.
fn render_audit_card_body(ui: &mut egui::Ui, entry: &AuditEntry, now: u64) {
    let wrap = if entry.wrap.is_empty() {
        "(?)"
    } else {
        entry.wrap.as_str()
    };
    let verdict = AuditVerdict::from_decision(entry.decision.as_str());

    // ── Line 1: command (left) + verdict column (right) ──
    ui.horizontal(|ui| {
        let avail = ui.available_width();
        // Clamp the reservation on narrow windows (mirrors the
        // title-bar inset clamp) so the verdict never eats the row.
        let verdict_w = AUDIT_VERDICT_COL_WIDTH.min(avail * 0.45).max(0.0);
        let full = if entry.args.is_empty() {
            wrap.to_owned()
        } else {
            format!("{wrap} {}", entry.args.join(" "))
        };
        let cmd_font = egui::FontId::monospace(13.5);
        let body_w = (avail - verdict_w - 12.0).max(60.0);
        let shown = truncate_to_width(ui, &full, &cmd_font, body_w);
        let resp = ui.label(
            egui::RichText::new(&shown)
                .font(cmd_font)
                .strong()
                .color(COLOR_TEXT),
        );
        if shown != full {
            resp.on_hover_text(&full);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if let Some(tag) = verdict.tag {
                paint_pill(ui, tag, COLOR_ACCENT, COLOR_ACCENT_SOFT);
                ui.add_space(4.0);
            }
            paint_verdict_pill(ui, verdict);
        });
    });

    // ── Line 2: secret NAMES (never values) ──
    if !entry.secrets.is_empty() {
        ui.add_space(5.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            ui.label(
                egui::RichText::new("\u{25cf}")
                    .size(7.0)
                    .color(COLOR_ACCENT),
            );
            for name in &entry.secrets {
                ui.label(
                    egui::RichText::new(name)
                        .font(egui::FontId::monospace(11.5))
                        .color(COLOR_MUTED),
                );
            }
        });
    }

    // ── Line 3: process tree (the load-bearing provenance) ──
    //
    // The caller chain WITH each parent's argv is the whole reason an
    // audit log exists: it answers "what actually triggered this secret
    // release, and with what arguments". It stays fully visible — not
    // folded into a tooltip — even though that costs a few rows of card
    // height. `make ci-deploy` / `node ./scripts/import.js` is exactly
    // the line a reviewer scans for.
    if !entry.callers.is_empty() {
        ui.add_space(6.0);
        render_audit_caller_chain(ui, &entry.callers);
    }

    // ── Line 4: cwd + time footer ──
    let ago = humanize_duration(Duration::from_secs(now.saturating_sub(entry.ts_unix)));
    ui.add_space(5.0);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 5.0;
        if !entry.cwd.is_empty() {
            let cwd_resp = ui.label(
                egui::RichText::new(format!("in {}", short_cwd(&entry.cwd)))
                    .size(11.0)
                    .color(COLOR_FOOTNOTE),
            );
            cwd_resp.on_hover_text(&entry.cwd);
            ui.label(
                egui::RichText::new("\u{b7}")
                    .size(11.0)
                    .color(COLOR_FOOTNOTE),
            );
        }
        ui.label(
            egui::RichText::new(format!("{ago} ago"))
                .size(11.0)
                .color(COLOR_FOOTNOTE),
        );
    });
}

/// Normalized view of an audit decision string. Carries the verb, an
/// optional separate tag ("remembered"), and the fg/bg colours for the
/// verdict pill. Computing this once keeps the renderer free of inline
/// decision matching and lets the "remembered" tag ride on its own pill.
#[derive(Clone, Copy)]
struct AuditVerdict {
    label: &'static str,
    tag: Option<&'static str>,
    fg: egui::Color32,
    bg: egui::Color32,
}

impl AuditVerdict {
    fn from_decision(decision: &str) -> AuditVerdict {
        match decision {
            "deny" => AuditVerdict {
                label: "denied",
                tag: None,
                fg: COLOR_DENY_BG,
                bg: COLOR_DENY_SOFT,
            },
            "approve" => AuditVerdict {
                label: "approved",
                tag: None,
                fg: COLOR_APPROVE_BG,
                bg: COLOR_APPROVE_SOFT,
            },
            "approve+remember" => AuditVerdict {
                label: "approved",
                tag: Some("remembered"),
                fg: COLOR_APPROVE_BG,
                bg: COLOR_APPROVE_SOFT,
            },
            // The daemon's approvals cache short-circuited the prompt
            // — distinguished from "approve" so the audit log shows
            // "the user wasn't asked" vs. "the user said yes."
            "approve+cached" => AuditVerdict {
                label: "approved",
                tag: Some("cached"),
                fg: COLOR_APPROVE_BG,
                bg: COLOR_APPROVE_SOFT,
            },
            // An enabled auto-rule fired. Same colour as a hand-clicked
            // approve so the row scans the same at a glance; the "auto"
            // tag makes the provenance explicit on inspection.
            "approve+auto" => AuditVerdict {
                label: "approved",
                tag: Some("auto"),
                fg: COLOR_APPROVE_BG,
                bg: COLOR_APPROVE_SOFT,
            },
            "deny+auto" => AuditVerdict {
                label: "denied",
                tag: Some("auto"),
                fg: COLOR_DENY_BG,
                bg: COLOR_DENY_SOFT,
            },
            // Unknown decisions map to a static "seen" so `label`
            // stays `&'static` (no borrow of `decision`).
            _ => AuditVerdict {
                label: "seen",
                tag: None,
                fg: COLOR_MUTED,
                bg: COLOR_CHROME,
            },
        }
    }
}

/// Verdict pill: a soft-filled rounded chip with a leading status dot
/// and the verb. The "remembered" tag is deliberately NOT drawn here —
/// the caller paints it as a separate accent pill, so this pill keeps a
/// fixed shape and its dot never jitters between rows.
fn paint_verdict_pill(ui: &mut egui::Ui, v: AuditVerdict) -> egui::Response {
    egui::Frame::new()
        .fill(v.bg)
        .stroke(egui::Stroke::new(1.0, v.fg))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 5.0;
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("\u{25cf}").size(7.0).color(v.fg));
                ui.label(egui::RichText::new(v.label).size(11.0).strong().color(v.fg));
            });
        })
        .response
}

/// Truncate `text` to the widest prefix (plus an ellipsis) that fits
/// within `max_width`, measured against the *actual* galley width for
/// `font` rather than a char-count guess. Binary-searches the prefix
/// length so a 200-char argv collapses in a handful of layout calls.
fn truncate_to_width(ui: &egui::Ui, text: &str, font: &egui::FontId, max_width: f32) -> String {
    if max_width <= 1.0 {
        return String::new();
    }
    let measure = |s: &str| -> f32 {
        ui.ctx().fonts_mut(|f| {
            f.layout_no_wrap(s.to_owned(), font.clone(), COLOR_TEXT)
                .size()
                .x
        })
    };
    if measure(text) <= max_width {
        return text.to_owned();
    }
    let chars: Vec<char> = text.chars().collect();
    // Largest `n` such that `chars[..n] + "\u{2026}"` fits.
    let mut lo = 0usize;
    let mut hi = chars.len();
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let candidate: String = chars[..mid].iter().collect::<String>() + "\u{2026}";
        if measure(&candidate) <= max_width {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    if lo == 0 {
        return "\u{2026}".to_owned();
    }
    chars[..lo].iter().collect::<String>() + "\u{2026}"
}

/// Render an audit entry's caller chain as an indented process tree,
/// outermost-first (the way `pstree` prints). Each row carries the bare
/// process name, its pid, and — load-bearingly — the argv it was invoked
/// with when that adds information over the name (`make ci-deploy`,
/// `node ./scripts/import.js`). Depth is capped at `MAX_DEPTH` so a
/// pathological 16-deep wrapper stack can't dominate the card; the
/// overflow collapses to a single `… N more` row whose hover reveals the
/// rest. The command tail is width-truncated (tooltip on overflow) so a
/// long argv never pushes the card wider than the window.
fn render_audit_caller_chain(ui: &mut egui::Ui, callers: &[AuditCaller]) {
    const MAX_DEPTH: usize = 6;
    const INDENT_PX: f32 = 13.0;
    // Storage is nearest-first; reverse to outermost-first for display.
    let ordered: Vec<&AuditCaller> = callers.iter().rev().collect();
    let visible = ordered.len().min(MAX_DEPTH);
    let hidden = ordered.len().saturating_sub(visible);
    for (depth, c) in ordered.iter().take(visible).enumerate() {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 5.0;
            ui.add_space(depth as f32 * INDENT_PX);
            // `·` roots the tree; `└─` hangs every deeper level off its
            // parent so the eye walks the chain downward.
            let glyph = if depth == 0 {
                "\u{b7}"
            } else {
                "\u{2514}\u{2500}"
            };
            ui.label(
                egui::RichText::new(glyph)
                    .font(egui::FontId::monospace(11.0))
                    .color(COLOR_FOOTNOTE),
            );
            ui.label(
                egui::RichText::new(&c.name)
                    .font(egui::FontId::monospace(11.5))
                    .color(COLOR_TEXT),
            );
            ui.label(
                egui::RichText::new(format!("pid {}", c.pid))
                    .size(10.0)
                    .color(COLOR_FOOTNOTE),
            );
            if !c.command.is_empty() && c.command != c.name {
                let cmd_font = egui::FontId::monospace(11.0);
                let avail = (ui.available_width() - 4.0).max(40.0);
                let shown = truncate_to_width(ui, &c.command, &cmd_font, avail);
                let resp = ui.label(
                    egui::RichText::new(&shown)
                        .font(cmd_font)
                        .color(COLOR_MUTED),
                );
                if shown != c.command {
                    resp.on_hover_text(&c.command);
                }
            }
        });
    }
    if hidden > 0 {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 5.0;
            ui.add_space(visible as f32 * INDENT_PX);
            let summary = ordered
                .iter()
                .skip(visible)
                .map(|c| {
                    if !c.command.is_empty() && c.command != c.name {
                        format!("{} (pid {})  {}", c.name, c.pid, c.command)
                    } else {
                        format!("{} (pid {})", c.name, c.pid)
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            ui.label(
                egui::RichText::new(format!("\u{2514}\u{2500} \u{2026} {hidden} more"))
                    .font(egui::FontId::monospace(10.0))
                    .color(COLOR_FOOTNOTE),
            )
            .on_hover_text(summary);
        });
    }
}

/// Calendar-style day-bucket label for an audit timestamp, relative to
/// `now`. Buckets by day index (not raw age) so an entry from 11pm and
/// one from 1am the next morning land in different buckets the way a
/// human reads a calendar.
fn audit_day_bucket(ts_unix: u64, now: u64) -> String {
    const DAY: u64 = 24 * 3600;
    let today = now / DAY;
    let ts = ts_unix / DAY;
    if ts >= today {
        return "Today".to_owned();
    }
    if ts + 1 == today {
        return "Yesterday".to_owned();
    }
    let d = today - ts;
    if d < 7 {
        return format!("{d} days ago");
    }
    let w = d / 7;
    if w == 1 {
        "Last week".to_owned()
    } else {
        format!("{w} weeks ago")
    }
}

fn render_empty_state(ui: &mut egui::Ui, viewer_mode: bool) {
    ui.vertical_centered(|ui| {
        ui.add_space(40.0);
        paint_empty_state_badge(ui, 72.0);
        ui.add_space(16.0);
        ui.label(
            egui::RichText::new("All clear")
                .size(20.0)
                .strong()
                .color(COLOR_TEXT),
        );
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new("No pending consent requests.")
                .size(13.0)
                .color(COLOR_MUTED),
        );
        // The "will hide shortly" hint is only honest for a decision
        // window: viewer-mode windows (`secreq view`) are deliberately
        // opened to browse and never auto-hide, so promising otherwise
        // would be a lie. A decision window on this (empty Pending) tab
        // is not "interacting", so it genuinely does hide after the
        // grace period — see `daemon::mod::run`'s auto-hide gate.
        if !viewer_mode {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("This window will hide shortly")
                    .size(11.0)
                    .italics()
                    .color(COLOR_FOOTNOTE),
            );
        }
    });
}

/// Big drawn circular "all clear" badge: a soft accent-green ring with
/// a check mark stroked inside. Built from circles + a polyline so it
/// renders at any DPR and doesn't depend on font glyph coverage.
fn paint_empty_state_badge(ui: &mut egui::Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let painter = ui.painter();
    let center = rect.center();
    let radius = size * 0.5;
    // Outer soft ring fill (very low alpha to avoid loud).
    let ring_fill = egui::Color32::from_rgba_unmultiplied(38, 158, 88, 36);
    painter.circle_filled(center, radius, ring_fill);
    // Crisp 1.5px stroke ring in approve green.
    painter.circle_stroke(
        center,
        radius - 1.0,
        egui::Stroke::new(1.5, COLOR_APPROVE_BG),
    );
    // Check mark — three points (left-arm start, dip, right-arm end)
    // proportioned so the shape reads as a confident tick at this
    // size. Drawn as a connected stroked polyline.
    let arm_l = egui::pos2(center.x - radius * 0.36, center.y + radius * 0.02);
    let dip = egui::pos2(center.x - radius * 0.05, center.y + radius * 0.32);
    let arm_r = egui::pos2(center.x + radius * 0.42, center.y - radius * 0.26);
    painter.add(egui::Shape::line(
        vec![arm_l, dip, arm_r],
        egui::Stroke::new(4.0, COLOR_APPROVE_BG),
    ));
}

/// If `top_idx` is the start of a run of single-child, no-leaf, same-
/// display-name nodes, return the deepest node in the run plus the run
/// length. Otherwise returns `(top_idx, 1)`.
///
/// Why: deeply-recursive wraps (e.g. a `gh` invocation that internally
/// shells out to another `gh`) can stack 10+ identical rows in the
/// chain. Folding the run into a single row with a `× N` badge keeps
/// the UI legible and lets the user approve at the outermost scope
/// (which subsumes all the inner ones anyway).
fn fold_run(tree: &ProcessTree, top_idx: usize) -> (usize, usize) {
    let top_name = node_display_name(&tree.nodes[top_idx]);
    let mut current = top_idx;
    let mut count = 1;
    loop {
        let node = &tree.nodes[current];
        if !node.rows.is_empty() {
            break;
        }
        if node.children.len() != 1 {
            break;
        }
        let child_idx = node.children[0];
        if node_display_name(&tree.nodes[child_idx]) != top_name {
            break;
        }
        current = child_idx;
        count += 1;
    }
    (current, count)
}

fn node_display_name(node: &TreeNode) -> String {
    node.caller
        .as_ref()
        .map(|c| {
            if c.command.is_empty() {
                c.name.clone()
            } else {
                c.command.clone()
            }
        })
        .unwrap_or_else(|| format!("(process {})", node.pid))
}

// ── Tree connector glyphs ────────────────────────────────────────────────
//
// Tree visuals: depth-based indentation. The pre-card design used
// `pstree`-style ASCII connectors (`├──`, `└──`, `│  `) plumbed
// through a `last_path: &[bool]` argument. Cards replaced that
// scheme — nesting is communicated via card indentation alone — so
// the `last_path` parameter is now unused but still threaded through
// for back-compat in case the daemon ever wants the row-tree view
// again. The `tree_prefix` / `continuation_prefix` helpers and
// their tests went away with the redesign.

#[allow(clippy::too_many_arguments)]
fn render_node(
    ui: &mut egui::Ui,
    tree: &ProcessTree,
    node_idx: usize,
    is_top_root: bool,
    depth: usize,
    last_path: &[bool],
    collapsed: &mut HashMap<(u32, u64), bool>,
    actions: &mut Vec<PendingAction>,
    audit: &AuditCache,
) {
    // node_idx supplies the approval scope (outermost in any fold).
    // child_iter_idx supplies the children/rows to recurse into (the
    // deepest in the fold). When there's no run, they're the same.
    let (child_iter_idx, run_count) = fold_run(tree, node_idx);
    let key = tree.nodes[node_idx].key();
    let is_collapsed = *collapsed.get(&key).unwrap_or(&false);

    render_node_header(
        ui,
        tree,
        node_idx,
        child_iter_idx,
        run_count,
        is_top_root,
        depth,
        last_path,
        collapsed,
        actions,
    );
    if !is_collapsed {
        render_children_and_rows(
            ui,
            tree,
            child_iter_idx,
            depth + 1,
            last_path,
            collapsed,
            actions,
            audit,
        );
    }
}

/// `bottom_idx` is the bottom of any single-child same-name run starting
/// at `node_idx`. Used to decide whether to show the "▾/▸" disclosure
/// (based on whether the *bottom* has descendants) and what subtree to
/// recurse into.
#[allow(clippy::too_many_arguments)]
fn render_node_header(
    ui: &mut egui::Ui,
    tree: &ProcessTree,
    node_idx: usize,
    bottom_idx: usize,
    run_count: usize,
    is_top_root: bool,
    depth: usize,
    last_path: &[bool],
    collapsed: &mut HashMap<(u32, u64), bool>,
    actions: &mut Vec<PendingAction>,
) {
    let node = &tree.nodes[node_idx];
    let bottom = &tree.nodes[bottom_idx];
    let key = node.key();
    let is_collapsed = *collapsed.get(&key).unwrap_or(&false);
    let has_descendants = !bottom.children.is_empty() || !bottom.rows.is_empty();
    let descendant_count = count_leaf_rows(tree, bottom_idx);

    // Suppress the `last_path` arg — it's still passed by callers for
    // backwards compatibility but the new visual language uses
    // depth-based indentation and a left guide rail instead of
    // ASCII connectors.
    let _ = last_path;
    ui.horizontal(|ui| {
        ui.add_space(depth as f32 * INDENT_UNIT);

        // Disclosure chevron. Drawn from primitives — a right-pointing
        // triangle (collapsed) or down-pointing (expanded) — so it
        // looks like a native disclosure widget rather than a Unicode
        // glyph. Always reserves the same width so siblings align even
        // when one has no descendants.
        if has_descendants {
            let clicked = paint_disclosure_chevron(ui, !is_collapsed);
            if clicked {
                collapsed.insert(key, !is_collapsed);
            }
        } else {
            ui.add_space(14.0);
        }

        let display = node_display_name(node);
        let display_shown = truncate_for_display(&display, 56);
        // Process names get a slightly lighter weight than the wrap
        // commands inside — they're section headers, not the primary
        // content. The top root still gets accent colour to signal
        // "Enter/Esc act here".
        let mut name_text = egui::RichText::new(&display_shown)
            .font(egui::FontId::monospace(13.0))
            .strong()
            .color(COLOR_TEXT);
        if is_top_root && depth == 0 {
            name_text = name_text.color(COLOR_ACCENT);
        }
        let label_resp = ui.label(name_text);
        if display_shown.len() < display.len() {
            label_resp.on_hover_text(display);
        }
        ui.label(
            egui::RichText::new(format!("pid {}", node.pid))
                .size(11.0)
                .color(COLOR_FOOTNOTE),
        );
        if run_count > 1 {
            paint_pill(
                ui,
                &format!("×{run_count}"),
                COLOR_ACCENT,
                COLOR_ACCENT_SOFT,
            )
            .on_hover_text(format!(
                "Folded a chain of {run_count} processes with the same command, \
                 from pid {} (outermost) to pid {} (innermost). Approving here \
                 applies to all of them.",
                node.pid, bottom.pid
            ));
        }
        if is_collapsed && descendant_count > 0 {
            ui.label(
                egui::RichText::new(format!("· {descendant_count} hidden"))
                    .size(11.0)
                    .color(COLOR_FOOTNOTE),
            );
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // A node whose whole subtree is resolving has nothing to
            // decide — drop the Approve all / Deny all buttons so the
            // header reads as status, not a prompt.
            if subtree_all_resolving(tree, node_idx) {
                return;
            }
            let deny_label = if is_top_root && depth == 0 {
                "Deny all  Esc"
            } else {
                "Deny all"
            };
            if styled_button(ui, deny_label, ButtonRole::Deny).clicked() {
                collect_subtree_actions(tree, node_idx, Decision::Deny, actions);
            }
            ui.add_space(6.0);
            let approve_label = if is_top_root && depth == 0 {
                "Approve all  ↵"
            } else {
                "Approve all"
            };
            if styled_button(ui, approve_label, ButtonRole::Approve).clicked() {
                collect_subtree_actions(tree, node_idx, Decision::ApproveRemember, actions);
            }
        });
    });
}

#[allow(clippy::too_many_arguments)]
fn render_children_and_rows(
    ui: &mut egui::Ui,
    tree: &ProcessTree,
    node_idx: usize,
    depth: usize,
    parent_last_path: &[bool],
    collapsed: &mut HashMap<(u32, u64), bool>,
    actions: &mut Vec<PendingAction>,
    audit: &AuditCache,
) {
    let node = &tree.nodes[node_idx];
    let total = node.children.len() + node.rows.len();
    // Children first, wraps last — children are intermediate processes
    // (folders), wraps are the actual asks (leaves), so wraps anchoring
    // the bottom of the tree feels most natural to read.
    let mut i = 0;
    for &child in &node.children {
        let is_last = i + 1 == total;
        let mut next_path = parent_last_path.to_vec();
        next_path.push(is_last);
        ui.add_space(2.0);
        render_node(
            ui, tree, child, false, depth, &next_path, collapsed, actions, audit,
        );
        i += 1;
    }
    if !node.rows.is_empty() {
        let scope = node.scope();
        for row in &node.rows {
            let is_last = i + 1 == total;
            let mut next_path = parent_last_path.to_vec();
            next_path.push(is_last);
            ui.add_space(CARD_VERTICAL_GAP);
            render_wrap_leaf(ui, row, scope, depth, &next_path, actions, audit);
            i += 1;
        }
    }
}

/// Render one pending wrap request as a card.
///
/// Card layout (bg `COLOR_CARD`, 1px `COLOR_CARD_STROKE` border, 8px
/// rounded, 14×10 inner padding):
///
/// - **Top row.** Command in monospace bold (the load-bearing "what is
///   about to run"), optional waiter-count pill, then right-aligned
///   `<n>s ago` footnote and `Approve` / `Deny` action buttons.
/// - **Audit history.** Italic footnote-tier line summarising prior
///   decisions; tinted orange when the last decision was a deny.
/// - **Secret list.** One row per requested secret with a soft dot,
///   the env-var name in bold mono, provider in accent, locator in
///   footnote.
/// - **cwd line.** Smallest tier — visible at a glance for
///   provenance but never competes for the eye.
fn render_wrap_leaf(
    ui: &mut egui::Ui,
    row: &QueueRow,
    scope: ApprovalScope,
    depth: usize,
    _last_path: &[bool],
    actions: &mut Vec<PendingAction>,
    audit: &AuditCache,
) {
    let indent = (depth as f32 * INDENT_UNIT).min(120.0) as i8;
    egui::Frame::new()
        .fill(COLOR_CARD)
        .stroke(egui::Stroke::new(1.0, COLOR_CARD_STROKE))
        .corner_radius(egui::CornerRadius::same(CARD_CORNER_RADIUS))
        .inner_margin(egui::Margin::symmetric(14, 10))
        .outer_margin(egui::Margin {
            left: indent,
            right: 0,
            top: 0,
            bottom: 0,
        })
        .show(ui, |ui| {
            render_wrap_card_body(ui, row, scope, actions, audit);
        });
}

fn render_wrap_card_body(
    ui: &mut egui::Ui,
    row: &QueueRow,
    scope: ApprovalScope,
    actions: &mut Vec<PendingAction>,
    audit: &AuditCache,
) {
    // SSH sign asks render a distinct card — a key identity + fingerprint
    // instead of a wrap command + secret list. The approve/deny/remember
    // buttons and the provenance tree are identical; only the body differs.
    if let Some(ssh) = &row.representative.ssh {
        render_ssh_card_body(ui, row, ssh, scope, actions);
        return;
    }
    // ── Card header row: command + actions ──
    ui.horizontal(|ui| {
        let cmd = row.representative.command.join(" ");
        let truncated = truncate_for_display(&cmd, 50);
        let resp = ui.label(
            egui::RichText::new(&truncated)
                .font(egui::FontId::monospace(13.5))
                .strong()
                .color(COLOR_TEXT),
        );
        if truncated.len() < cmd.len() {
            resp.on_hover_text(cmd);
        }
        if row.waiter_count > 1 {
            paint_pill(
                ui,
                &format!("×{} waiting", row.waiter_count),
                COLOR_ACCENT,
                COLOR_ACCENT_SOFT,
            );
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            match row.status {
                RowStatus::Resolving => {
                    // Already authorized; the provider call (and any
                    // biometric prompt) is in flight. Read-only — no
                    // Approve/Deny — so the card is purely provenance
                    // for the prompt the user is being asked to satisfy.
                    paint_pill(ui, "Resolving…", COLOR_ACCENT, COLOR_ACCENT_SOFT);
                }
                RowStatus::Awaiting => {
                    if small_button(ui, "Deny", ButtonRole::Deny).clicked() {
                        actions.push(PendingAction {
                            key: row.key.clone(),
                            decision: Decision::Deny,
                            scope,
                        });
                    }
                    ui.add_space(4.0);
                    if small_button(ui, "Approve", ButtonRole::Approve).clicked() {
                        actions.push(PendingAction {
                            key: row.key.clone(),
                            decision: Decision::Approve,
                            scope,
                        });
                    }
                }
            }
            ui.add_space(10.0);
            ui.label(
                egui::RichText::new(format!(
                    "{} ago",
                    humanize_duration(row.first_seen.elapsed())
                ))
                .size(11.0)
                .color(COLOR_FOOTNOTE),
            );
        });
    });
    ui.add_space(4.0);

    // ── Audit history line ──
    let direct_caller = row.representative.callers.first().map(|c| c.name.as_str());
    let summary = audit.summarize(&row.key.wrap, direct_caller);
    let (text, color) = format_audit_line(&summary, now_unix());
    ui.label(egui::RichText::new(text).size(11.0).italics().color(color));

    // ── Secret list (or the gate-only marker when there's nothing to
    // inject — the prompt is purely a consent gate, e.g. for `op`) ──
    if !row.representative.secrets.is_empty() {
        ui.add_space(6.0);
        // Per-secret `← command` provenance only earns its space when the
        // card aggregates *more than one* command (a coalesced run session).
        // On a single-command card the header already names the command, so
        // repeating it on every secret is noise — suppress it there.
        let distinct_commands: std::collections::HashSet<&str> = row
            .representative
            .secrets
            .iter()
            .flat_map(|s| s.requested_by.iter())
            .map(String::as_str)
            .collect();
        let show_provenance = distinct_commands.len() > 1;
        for s in &row.representative.secrets {
            render_card_secret(ui, s, show_provenance);
        }
    } else {
        render_card_gate_only(ui);
    }

    // ── cwd line ──
    if !row.representative.cwd.is_empty() {
        ui.add_space(6.0);
        let cwd_shown = truncate_for_display(&row.representative.cwd, 70);
        let resp = ui.label(
            egui::RichText::new(format!("in  {cwd_shown}"))
                .size(10.0)
                .color(COLOR_FOOTNOTE),
        );
        if cwd_shown.len() < row.representative.cwd.len() {
            resp.on_hover_text(&row.representative.cwd);
        }
    }
}

/// Render the body of an SSH-sign consent card. Distinct from a wrap card:
/// the request is for a *key*, not a command, so we show
///
/// 1. an **"SSH key request"** label + the identity name (`ssh.<key_id>`)
///    in the header, with the same Approve / Deny / Resolving controls a
///    wrap card carries (so the decision semantics are identical);
/// 2. the key's **SHA256 fingerprint** in a monospace footnote (what
///    `ssh-add -l` prints — lets the user match it to a key they know);
/// 3. the configured **`$reason`**, if present, in the italic footnote tier;
/// 4. **no** "secrets to be injected" list and **no** "gate only" marker —
///    an SSH sign releases a signature, never an env var, so neither is
///    meaningful here.
///
/// The caller chain / provenance is rendered by the surrounding process
/// tree exactly as for a wrap, so it isn't repeated in the card body.
fn render_ssh_card_body(
    ui: &mut egui::Ui,
    row: &QueueRow,
    ssh: &SshAskInfo,
    scope: ApprovalScope,
    actions: &mut Vec<PendingAction>,
) {
    // ── Header row: "SSH key request" + identity, then actions ──
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("SSH key request")
                .font(egui::FontId::proportional(13.5))
                .strong()
                .color(COLOR_TEXT),
        );
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(&ssh.key_id)
                .font(egui::FontId::monospace(12.5))
                .color(COLOR_ACCENT),
        );
        if row.waiter_count > 1 {
            paint_pill(
                ui,
                &format!("×{} waiting", row.waiter_count),
                COLOR_ACCENT,
                COLOR_ACCENT_SOFT,
            );
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // A sign offers more than approve/deny: the user can grant a
            // session window so they're not re-prompted on every push. Those
            // buttons don't fit beside the identity label, so the header only
            // carries the "Signing…" pill (while resolving) and the age; the
            // action buttons render in a dedicated row below.
            if row.status == RowStatus::Resolving {
                paint_pill(ui, "Signing…", COLOR_ACCENT, COLOR_ACCENT_SOFT);
                ui.add_space(10.0);
            }
            ui.label(
                egui::RichText::new(format!(
                    "{} ago",
                    humanize_duration(row.first_seen.elapsed())
                ))
                .size(11.0)
                .color(COLOR_FOOTNOTE),
            );
        });
    });

    // ── Fingerprint row ──
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new("\u{25cf}")
                .size(7.0)
                .color(COLOR_ACCENT),
        );
        ui.label(
            egui::RichText::new("sign with")
                .size(11.0)
                .color(COLOR_MUTED),
        );
        let fp_shown = truncate_for_display(&ssh.fingerprint, 60);
        let resp = ui.label(
            egui::RichText::new(&fp_shown)
                .font(egui::FontId::monospace(11.5))
                .color(COLOR_TEXT),
        );
        if fp_shown.len() < ssh.fingerprint.len() {
            resp.on_hover_text(&ssh.fingerprint);
        }
    });

    // ── Reason (optional) ──
    if let Some(reason) = ssh.reason.as_deref().filter(|r| !r.is_empty()) {
        ui.horizontal(|ui| {
            ui.add_space(18.0);
            ui.label(
                egui::RichText::new(reason)
                    .size(11.0)
                    .italics()
                    .color(COLOR_FOOTNOTE),
            );
        });
    }

    // ── Action row ──
    // Only when awaiting a decision (a resolving sign is read-only; its
    // provider call is already in flight). Four choices: a one-shot approve,
    // two session grants ("this key" / "all keys" for the session TTL), and
    // deny. In a right-to-left layout the first-added button sits rightmost,
    // so adding Deny first then the approves yields the visual left-to-right
    // order: Approve once · Approve 30m · Approve all keys 30m · Deny.
    if row.status == RowStatus::Awaiting {
        ui.add_space(10.0);
        // The outer `horizontal` pins the row to a single button-height; a
        // bare `with_layout(right_to_left, Align::Center)` on the card body
        // would inherit the card's full available height and vertically
        // centre the buttons in a tall void.
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let mut push = |decision: Decision| {
                    actions.push(PendingAction {
                        key: row.key.clone(),
                        decision,
                        scope,
                    });
                };
                if small_button(ui, "Deny", ButtonRole::Deny).clicked() {
                    push(Decision::Deny);
                }
                ui.add_space(4.0);
                if small_button(ui, "Approve all keys 30m", ButtonRole::Approve).clicked() {
                    push(Decision::ApproveSshSessionAll);
                }
                ui.add_space(4.0);
                if small_button(ui, "Approve 30m", ButtonRole::Approve).clicked() {
                    push(Decision::ApproveSshSession);
                }
                ui.add_space(4.0);
                if small_button(ui, "Approve once", ButtonRole::Approve).clicked() {
                    push(Decision::Approve);
                }
            });
        });
    }
}

/// One secret-row inside a wrap card.
fn render_card_secret(ui: &mut egui::Ui, s: &SecretAsk, show_provenance: bool) {
    ui.horizontal(|ui| {
        ui.add_space(2.0);
        ui.label(egui::RichText::new("●").size(7.0).color(COLOR_ACCENT));
        ui.label(
            egui::RichText::new(&s.name)
                .font(egui::FontId::monospace(12.0))
                .strong()
                .color(COLOR_TEXT),
        );
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new(&s.provider)
                .font(egui::FontId::monospace(11.0))
                .color(COLOR_ACCENT),
        );
        if !s.locator.is_empty() {
            let loc_shown = truncate_for_display(&s.locator, 42);
            let resp = ui.label(
                egui::RichText::new(&loc_shown)
                    .font(egui::FontId::monospace(11.0))
                    .color(COLOR_FOOTNOTE),
            );
            if loc_shown.len() < s.locator.len() {
                resp.on_hover_text(&s.locator);
            }
        }
        // Session provenance: on a multi-command coalesced run session,
        // show which sibling command asked for this secret. Suppressed on
        // single-command cards (`show_provenance == false`) — the header
        // already names the command — and always empty for a plain wrap
        // (`x`) or SSH ask, so those render exactly as before, no arrow.
        if show_provenance && !s.requested_by.is_empty() {
            let joined = s
                .requested_by
                .iter()
                .map(|c| c.strip_prefix("run ").unwrap_or(c))
                .collect::<Vec<_>>()
                .join(", ");
            let label = truncate_for_display(&joined, 30);
            let resp = ui.label(
                egui::RichText::new(format!("← {label}"))
                    .font(egui::FontId::monospace(11.0))
                    .color(COLOR_MUTED),
            );
            if label.chars().count() < joined.chars().count() {
                resp.on_hover_text(&joined);
            }
        }
    });
    let why = s
        .description
        .as_deref()
        .or(s.reason.as_deref())
        .unwrap_or("");
    if !why.is_empty() {
        ui.horizontal(|ui| {
            ui.add_space(18.0);
            ui.label(
                egui::RichText::new(why)
                    .size(11.0)
                    .italics()
                    .color(COLOR_FOOTNOTE),
            );
        });
    }
}

/// Marker shown in place of the secret list for a *gate-only* wrap — one
/// with no secrets to inject. The request is a pure consent gate (e.g.
/// `op`), so we say so explicitly rather than render an empty gap the
/// user might read as "secrets failed to load".
fn render_card_gate_only(ui: &mut egui::Ui) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add_space(2.0);
        ui.label(egui::RichText::new("●").size(7.0).color(COLOR_MUTED));
        ui.label(
            egui::RichText::new("Gate only — no secrets injected")
                .size(11.5)
                .italics()
                .color(COLOR_MUTED),
        );
    });
}

/// One-line summary derived from `audit.log` history for this wrap +
/// caller. Empty history reads as "first request from this caller", a
/// reassuring counterpoint to wrap-rerun fatigue ("oh, I've approved
/// this 12 times before"). Color-coded only for the case worth a
/// second look: the last decision was a deny.
const COLOR_DENY_HINT: egui::Color32 = egui::Color32::from_rgb(220, 130, 110);

/// Soft fills behind the audit verdict pills — dim, desaturated
/// tints of the approve/deny semantics so the badge reads as a calm
/// status chip rather than a button. Cool-dark, macOS-native feel.
const COLOR_APPROVE_SOFT: egui::Color32 = egui::Color32::from_rgb(24, 48, 36);
const COLOR_DENY_SOFT: egui::Color32 = egui::Color32::from_rgb(54, 30, 34);

fn format_audit_line(summary: &WrapHistorySummary, now: u64) -> (String, egui::Color32) {
    if summary.is_empty() {
        return ("↳ first request from this caller".to_owned(), COLOR_MUTED);
    }
    let last_ts = summary.last_ts_unix.unwrap_or(now);
    let ago_secs = now.saturating_sub(last_ts);
    let ago = humanize_duration(Duration::from_secs(ago_secs));
    // Color only the deny case — approve/approve+remember is the
    // expected path and shouldn't draw the eye.
    let (verb, color) = match summary.last_decision.as_deref() {
        Some("deny") => ("denied", COLOR_DENY_HINT),
        Some("approve") | Some("approve+remember") | Some("approve+cached") => {
            ("approved", COLOR_MUTED)
        }
        _ => ("seen", COLOR_MUTED),
    };
    let counts = if summary.total_count > 0 {
        format!(
            " · {} grants / {} denies in 30d",
            summary.approve_count, summary.deny_count
        )
    } else {
        String::new()
    };
    (format!("↳ {verb} {ago} ago{counts}"), color)
}

// ── Drawn primitives ─────────────────────────────────────────────────────

/// Disclosure chevron — a small triangle, pointing right when
/// collapsed and down when expanded. Drawn from primitives because
/// the Unicode `▾` glyph reads as a font character (a bit awkward
/// inside a "real app" header row).
///
/// Returns whether the chevron was clicked this frame.
fn paint_disclosure_chevron(ui: &mut egui::Ui, expanded: bool) -> bool {
    let size = 14.0;
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::click());
    // Triangle, 8x8, centred. Right-pointing when collapsed, down-
    // pointing when expanded.
    let c = rect.center();
    let r = 4.0;
    let points = if expanded {
        vec![
            egui::pos2(c.x - r, c.y - r / 2.0),
            egui::pos2(c.x + r, c.y - r / 2.0),
            egui::pos2(c.x, c.y + r / 2.0 + 1.5),
        ]
    } else {
        vec![
            egui::pos2(c.x - r / 2.0, c.y - r),
            egui::pos2(c.x - r / 2.0, c.y + r),
            egui::pos2(c.x + r / 2.0 + 1.5, c.y),
        ]
    };
    let colour = if resp.hovered() {
        COLOR_TEXT
    } else {
        COLOR_MUTED
    };
    ui.painter().add(egui::Shape::convex_polygon(
        points,
        colour,
        egui::Stroke::NONE,
    ));
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp.clicked()
}

/// Small inline pill — a rounded rect with a tinted fill, a thin
/// stroke in the foreground accent colour, and a label. Used for
/// `× 15` fold badges, waiter counts, and decision badges.
fn paint_pill(
    ui: &mut egui::Ui,
    text: &str,
    fg: egui::Color32,
    bg: egui::Color32,
) -> egui::Response {
    egui::Frame::new()
        .fill(bg)
        .stroke(egui::Stroke::new(1.0, fg))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(7, 2))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).size(10.0).strong().color(fg));
        })
        .response
}

// ── Buttons ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum ButtonRole {
    Approve,
    Deny,
}

fn styled_button(ui: &mut egui::Ui, text: &str, role: ButtonRole) -> egui::Response {
    let (fill, hover, text_color) = button_colors(role);
    let button = egui::Button::new(egui::RichText::new(text).color(text_color))
        .fill(fill)
        .min_size(egui::Vec2::new(0.0, 26.0));
    let resp = ui.add(button);
    if resp.hovered() {
        paint_hover(ui, &resp, hover, text, text_color);
    }
    resp
}

fn small_button(ui: &mut egui::Ui, text: &str, role: ButtonRole) -> egui::Response {
    let (fill, hover, text_color) = button_colors(role);
    let button = egui::Button::new(egui::RichText::new(text).color(text_color).size(11.0))
        .fill(fill)
        .min_size(egui::Vec2::new(0.0, 20.0));
    let resp = ui.add(button);
    if resp.hovered() {
        paint_hover(ui, &resp, hover, text, text_color);
    }
    resp
}

fn button_colors(role: ButtonRole) -> (egui::Color32, egui::Color32, egui::Color32) {
    match role {
        ButtonRole::Approve => (
            COLOR_APPROVE_BG,
            COLOR_APPROVE_BG_HOVER,
            egui::Color32::WHITE,
        ),
        ButtonRole::Deny => (COLOR_DENY_BG, COLOR_DENY_BG_HOVER, egui::Color32::WHITE),
    }
}

fn paint_hover(
    ui: &mut egui::Ui,
    resp: &egui::Response,
    hover: egui::Color32,
    text: &str,
    text_color: egui::Color32,
) {
    let corner_radius = ui.visuals().widgets.hovered.corner_radius;
    ui.painter().rect_filled(resp.rect, corner_radius, hover);
    ui.painter().text(
        resp.rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        egui::FontId::default(),
        text_color,
    );
}

// ── Formatting helpers ────────────────────────────────────────────────────

fn humanize_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

/// Collapse a full working directory to a compact provenance hint:
/// the last path component prefixed with `.../`. The full cwd still
/// lives in the caller-chain tooltip, so this only needs to answer
/// "where did it run?" at a glance. A bare or root-level path is
/// returned unchanged.
fn short_cwd(cwd: &str) -> String {
    let trimmed = cwd.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((parent, last)) if !parent.is_empty() && !last.is_empty() => {
            format!(".../{last}")
        }
        _ => cwd.to_owned(),
    }
}

fn truncate_for_display(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[allow(dead_code)]
pub fn snapshot_for_test(state: &SharedState) -> QueueSnapshot {
    state.lock().expect("state mutex").snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditCaller;
    use crate::daemon::proto::Ask;
    use std::collections::HashMap;

    // ── audit_entry_matches ──────────────────────────────────────

    fn audit_entry_for_search(
        wrap: &str,
        args: &[&str],
        caller_name: &str,
        secrets: &[&str],
        decision: &str,
    ) -> AuditEntry {
        AuditEntry {
            ts_unix: 0,
            cwd: "/home/x".to_owned(),
            wrap: wrap.to_owned(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            callers: vec![AuditCaller {
                pid: 1,
                name: caller_name.to_owned(),
                command: caller_name.to_owned(),
            }],
            secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
            decision: decision.to_owned(),
            rule_id: None,
            fingerprint: None,
        }
    }

    #[test]
    fn search_empty_query_matches_every_entry() {
        let e = audit_entry_for_search("gh", &["api"], "zsh", &["GITHUB_TOKEN"], "approve");
        assert!(audit_entry_matches(&e, ""));
        // Trim is the caller's job; bare whitespace from `String::trim`
        // in `render_audit_page` arrives here as "" so we don't need
        // to handle " " specially.
    }

    #[test]
    fn search_matches_wrap_name_case_insensitively() {
        let e = audit_entry_for_search("gh", &[], "zsh", &[], "approve");
        assert!(audit_entry_matches(&e, "gh"));
        assert!(audit_entry_matches(&e, "GH"));
        assert!(audit_entry_matches(&e, "Gh"));
        assert!(!audit_entry_matches(&e, "aws"));
    }

    #[test]
    fn search_matches_any_arg() {
        let e = audit_entry_for_search(
            "gh",
            &["api", "--method", "GET", "repos/acme/web/issues"],
            "zsh",
            &[],
            "approve",
        );
        assert!(audit_entry_matches(&e, "acme/web"));
        assert!(audit_entry_matches(&e, "ISSUES"));
    }

    #[test]
    fn search_matches_caller_name_and_command() {
        let mut e = audit_entry_for_search("gh", &[], "zsh", &[], "approve");
        e.callers = vec![AuditCaller {
            pid: 2,
            name: "Cursor".to_owned(),
            command: "/Applications/Cursor.app/Contents/MacOS/Cursor".to_owned(),
        }];
        // Substring on the caller's bare name.
        assert!(audit_entry_matches(&e, "cursor"));
        // Substring on the caller's full command path.
        assert!(audit_entry_matches(&e, "Applications/Cursor.app"));
    }

    #[test]
    fn search_matches_secret_name() {
        let e = audit_entry_for_search("gh", &[], "zsh", &["GITHUB_TOKEN"], "approve");
        assert!(audit_entry_matches(&e, "GITHUB"));
        assert!(audit_entry_matches(&e, "token"));
    }

    #[test]
    fn search_matches_decision_string() {
        // "auto" is the load-bearing case — surfacing all auto-fired
        // decisions in one search saves the user filtering by hand.
        let e = audit_entry_for_search("gh", &[], "zsh", &[], "approve+auto");
        assert!(audit_entry_matches(&e, "auto"));
        assert!(audit_entry_matches(&e, "approve"));
        let denied = audit_entry_for_search("gh", &[], "zsh", &[], "deny");
        assert!(audit_entry_matches(&denied, "deny"));
        assert!(!audit_entry_matches(&e, "deny"));
    }

    #[test]
    fn search_misses_when_no_field_contains_query() {
        let e = audit_entry_for_search("gh", &["api"], "zsh", &["GITHUB_TOKEN"], "approve");
        assert!(!audit_entry_matches(&e, "kubernetes"));
    }

    #[test]
    fn search_terms_span_wrap_and_args() {
        // The reported bug: searching "gh auth" must surface a wrap
        // named `gh` whose argv was `auth token`. No single field holds
        // the literal "gh auth", so per-field substring matching missed
        // it. Multi-term search splits on whitespace and lets "gh" hit
        // the wrap while "auth" hits an arg.
        let e = audit_entry_for_search("gh", &["auth", "token"], "zsh", &[], "approve");
        assert!(audit_entry_matches(&e, "gh auth"));
        assert!(audit_entry_matches(&e, "auth token"));
        assert!(audit_entry_matches(&e, "gh token"));
        // Order-independent and case-insensitive.
        assert!(audit_entry_matches(&e, "TOKEN gh"));
    }

    #[test]
    fn search_requires_every_term_to_match() {
        // AND semantics: a stray term that matches nothing rejects the
        // whole entry, so each added word narrows the result set.
        let e = audit_entry_for_search("gh", &["auth", "token"], "zsh", &[], "approve");
        assert!(!audit_entry_matches(&e, "gh kubernetes"));
        assert!(!audit_entry_matches(&e, "auth nope"));
    }

    #[test]
    fn search_terms_match_across_different_field_kinds() {
        // Each term independently picks whichever field it likes —
        // caller name, secret, decision — not just one field per query.
        let e = audit_entry_for_search("gh", &["auth"], "Cursor", &["GITHUB_TOKEN"], "deny");
        assert!(audit_entry_matches(&e, "cursor deny"));
        assert!(audit_entry_matches(&e, "gh github_token"));
    }

    #[test]
    fn search_whitespace_only_query_matches_every_entry() {
        // `split_whitespace` yields no terms, so the all-terms-match
        // predicate is vacuously true — mirrors the empty-query case.
        let e = audit_entry_for_search("gh", &["api"], "zsh", &[], "approve");
        assert!(audit_entry_matches(&e, "   "));
    }

    fn mk_row(wrap: &str, ppid: u32, start: u64, secs_ago: u64, callers: Vec<Caller>) -> QueueRow {
        QueueRow {
            key: DedupeKey {
                wrap: wrap.to_owned(),
                ppid,
                parent_start_time: start,
            },
            representative: Ask {
                command: vec![wrap.to_owned()],
                cwd: String::new(),
                callers,
                secrets: vec![],
                providers: HashMap::new(),
                dedupe_key: DedupeKey {
                    wrap: wrap.to_owned(),
                    ppid,
                    parent_start_time: start,
                },
                ssh: None,
                allow_remember: true,
                nested_run: false,
            },
            waiter_count: 1,
            first_seen: Instant::now() - Duration::from_secs(secs_ago),
            status: RowStatus::Awaiting,
        }
    }

    fn caller(pid: u32, name: &str, start_time: u64) -> Caller {
        Caller {
            pid,
            name: name.to_owned(),
            command: name.to_owned(),
            start_time,
        }
    }

    // ── new-ask highlight (observe_pending / decay) ──────────────

    fn snap(rows: Vec<QueueRow>) -> QueueSnapshot {
        QueueSnapshot { entries: rows }
    }

    fn one_ask() -> QueueSnapshot {
        snap(vec![mk_row("gh", 1, 1, 1, vec![caller(1, "zsh", 1)])])
    }

    fn two_asks() -> QueueSnapshot {
        snap(vec![
            mk_row("gh", 1, 1, 1, vec![caller(1, "zsh", 1)]),
            mk_row("aws", 2, 2, 1, vec![caller(2, "zsh", 2)]),
        ])
    }

    #[test]
    fn first_pending_observation_does_not_flash() {
        // A freshly-opened window already shows Pending with its initial
        // asks — those aren't "new", so the very first frame is silent.
        let mut ws = ConsentWindowState::new();
        ws.observe_pending(&one_ask(), true);
        assert_eq!(ws.pending_pulse, 0.0);
        assert_eq!(ws.current_tab, Tab::Pending);
    }

    #[test]
    fn on_pending_tab_tracks_active_tab() {
        // Drives the child's "interacting" signal: true only off the
        // Pending tab. A fresh window starts on Pending.
        let mut ws = ConsentWindowState::new();
        assert!(ws.on_pending_tab());
        ws.focus_audit_tab();
        assert!(!ws.on_pending_tab());
        ws.focus_rules_tab();
        assert!(!ws.on_pending_tab());
    }

    #[test]
    fn new_ask_while_focused_flashes_without_switching_tab() {
        let mut ws = ConsentWindowState::new();
        ws.focus_audit_tab();
        ws.observe_pending(&one_ask(), true); // baseline
        assert_eq!(ws.pending_pulse, 0.0);

        ws.observe_pending(&two_asks(), true); // a genuinely-new ask
        assert_eq!(ws.pending_pulse, 1.0);
        assert_eq!(ws.current_tab, Tab::Audit); // not yanked away
    }

    #[test]
    fn new_ask_while_unfocused_switches_to_pending() {
        let mut ws = ConsentWindowState::new();
        ws.focus_audit_tab();
        ws.observe_pending(&one_ask(), false); // baseline
        ws.observe_pending(&two_asks(), false);
        assert_eq!(ws.current_tab, Tab::Pending);
        assert_eq!(ws.pending_pulse, 0.0); // no flash when unfocused
    }

    #[test]
    fn unchanged_pending_set_does_not_reflash() {
        let mut ws = ConsentWindowState::new();
        ws.observe_pending(&one_ask(), true);
        ws.observe_pending(&one_ask(), true);
        assert_eq!(ws.pending_pulse, 0.0);
    }

    #[test]
    fn decay_winds_the_pulse_down_to_zero() {
        let mut ws = ConsentWindowState::new();
        ws.set_pending_pulse(1.0);
        assert!(ws.decay_pending_pulse(PENDING_PULSE_SECS / 2.0));
        assert!(ws.pending_pulse > 0.0 && ws.pending_pulse < 1.0);
        // Overshoot the remaining time → clamps to 0 and reports settled.
        assert!(!ws.decay_pending_pulse(PENDING_PULSE_SECS));
        assert_eq!(ws.pending_pulse, 0.0);
        // Already at rest → no-op, still settled.
        assert!(!ws.decay_pending_pulse(0.1));
    }

    #[test]
    fn tree_groups_descendants_under_their_shared_ancestor() {
        // Two zsh shells (different pids) both descended from a single
        // Superset.app. Tree should have one root (Superset), with two
        // zsh children, each carrying its respective wrap leaf.
        let snapshot = QueueSnapshot {
            entries: vec![
                mk_row(
                    "gh",
                    7926,
                    100,
                    30,
                    vec![
                        caller(7926, "zsh-A", 1_000),
                        caller(2831, "Superset.app", 500),
                    ],
                ),
                mk_row(
                    "aws",
                    7927,
                    101,
                    20,
                    vec![
                        caller(7927, "zsh-B", 1_001),
                        caller(2831, "Superset.app", 500),
                    ],
                ),
            ],
        };
        let tree = build_tree(&snapshot);
        assert_eq!(tree.roots.len(), 1, "single shared root");
        let root_idx = tree.roots[0];
        assert_eq!(tree.nodes[root_idx].pid, 2831);
        assert_eq!(tree.nodes[root_idx].children.len(), 2);
        // Each zsh child has one leaf row.
        for &child in &tree.nodes[root_idx].children {
            assert_eq!(tree.nodes[child].rows.len(), 1);
            assert_eq!(tree.nodes[child].children.len(), 0);
        }
        assert_eq!(tree.total_leaf_rows(), 2);
    }

    #[test]
    fn tree_keeps_unrelated_processes_as_separate_roots() {
        let snapshot = QueueSnapshot {
            entries: vec![
                mk_row("gh", 7926, 100, 30, vec![caller(7926, "zsh", 1_000)]),
                mk_row("aws", 4001, 50, 10, vec![caller(4001, "npm", 800)]),
            ],
        };
        let tree = build_tree(&snapshot);
        assert_eq!(tree.roots.len(), 2);
    }

    #[test]
    fn collect_subtree_actions_uses_the_node_scope_for_every_leaf() {
        // Approving at the SHARED ancestor should write actions whose
        // `scope` is the ancestor's (pid, start_time) — that's the
        // load-bearing property: future descendants ride this approval.
        let snapshot = QueueSnapshot {
            entries: vec![
                mk_row(
                    "gh",
                    7926,
                    100,
                    30,
                    vec![
                        caller(7926, "zsh", 1_000),
                        caller(2831, "Superset.app", 500),
                    ],
                ),
                mk_row(
                    "aws",
                    7927,
                    101,
                    20,
                    vec![
                        caller(7927, "zsh", 1_001),
                        caller(2831, "Superset.app", 500),
                    ],
                ),
            ],
        };
        let tree = build_tree(&snapshot);
        let root = tree.roots[0];
        let mut actions = vec![];
        collect_subtree_actions(&tree, root, Decision::ApproveRemember, &mut actions);
        assert_eq!(actions.len(), 2);
        for a in &actions {
            assert_eq!(a.scope.pid, 2831);
            assert_eq!(a.scope.start_time, 500);
        }
    }

    #[test]
    fn collect_subtree_at_a_zsh_node_only_includes_its_own_subtree() {
        // Approving at one zsh shouldn't affect the other.
        let snapshot = QueueSnapshot {
            entries: vec![
                mk_row(
                    "gh",
                    7926,
                    100,
                    30,
                    vec![
                        caller(7926, "zsh-A", 1_000),
                        caller(2831, "Superset.app", 500),
                    ],
                ),
                mk_row(
                    "aws",
                    7927,
                    101,
                    20,
                    vec![
                        caller(7927, "zsh-B", 1_001),
                        caller(2831, "Superset.app", 500),
                    ],
                ),
            ],
        };
        let tree = build_tree(&snapshot);
        let root = tree.roots[0];
        // Find the zsh-A child of Superset.
        let zsh_a = tree.nodes[root]
            .children
            .iter()
            .copied()
            .find(|&i| tree.nodes[i].pid == 7926)
            .expect("zsh-A child");
        let mut actions = vec![];
        collect_subtree_actions(&tree, zsh_a, Decision::ApproveRemember, &mut actions);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key.wrap, "gh");
        assert_eq!(actions[0].scope.pid, 7926);
    }

    #[test]
    fn humanize_buckets_into_s_m_h() {
        assert_eq!(humanize_duration(Duration::from_secs(0)), "0s");
        assert_eq!(humanize_duration(Duration::from_secs(45)), "45s");
        assert_eq!(humanize_duration(Duration::from_secs(60)), "1m");
        assert_eq!(humanize_duration(Duration::from_secs(3600)), "1h");
    }

    #[test]
    fn recency_lowercases_the_leading_word() {
        const DAY: u64 = 24 * 3600;
        let now = 100 * DAY;
        // "Today" / "Yesterday" / "Last week" fold to lowercase so they
        // read inline after "last seen …"; the "N days ago" forms are
        // already lowercase and pass through unchanged.
        assert_eq!(recency_label(now, now), "today");
        assert_eq!(recency_label(now - DAY, now), "yesterday");
        assert_eq!(recency_label(now - 3 * DAY, now), "3 days ago");
        assert_eq!(recency_label(now - 8 * DAY, now), "last week");
        assert_eq!(recency_label(now - 21 * DAY, now), "3 weeks ago");
    }

    fn audit_with_rule(ts: u64, rule_id: Option<&str>) -> AuditEntry {
        AuditEntry {
            ts_unix: ts,
            cwd: String::new(),
            wrap: "gh".to_owned(),
            args: vec![],
            callers: vec![],
            secrets: vec![],
            decision: "approve+auto".to_owned(),
            rule_id: rule_id.map(str::to_owned),
            fingerprint: None,
        }
    }

    #[test]
    fn rule_usage_index_counts_fires_and_tracks_latest() {
        let entries = vec![
            audit_with_rule(100, Some("a")),
            audit_with_rule(300, Some("a")),
            audit_with_rule(200, Some("a")),
            audit_with_rule(150, Some("b")),
            // A manual decision (no rule fired) must not be counted.
            audit_with_rule(999, None),
        ];
        let idx = rule_usage_index(&entries);
        assert_eq!(idx.get("a").unwrap().count, 3);
        assert_eq!(idx.get("a").unwrap().last_ts_unix, Some(300));
        assert_eq!(idx.get("b").unwrap().count, 1);
        assert!(!idx.contains_key("c"), "never-fired rule absent from index");
    }

    fn rule_named(id: &str, name: &str) -> Rule {
        Rule {
            id: id.to_owned(),
            name: name.to_owned(),
            enabled: true,
            decide: RuleDecision::Approve,
            r#match: RuleMatch {
                wrap: "gh".to_owned(),
                argv: None,
                ancestor: None,
                cwd: None,
            },
            trained_secrets: std::collections::BTreeSet::new(),
            deny_message: None,
            created_at_unix: 0,
        }
    }

    #[test]
    fn rule_sort_orders_by_mode_with_never_fired_last() {
        // Alpha: high count, older. Bravo: low count, newer. Charlie: none.
        let used = rule_named("a", "Alpha");
        let recent = rule_named("b", "Bravo");
        let never = rule_named("c", "Charlie");
        let mut rows: Vec<(&Rule, RuleUsage)> = vec![
            (
                &used,
                RuleUsage {
                    count: 10,
                    last_ts_unix: Some(100),
                },
            ),
            (
                &recent,
                RuleUsage {
                    count: 2,
                    last_ts_unix: Some(500),
                },
            ),
            (&never, RuleUsage::default()),
        ];

        RuleSort::MostUsed.sort(&mut rows);
        assert_eq!(rows[0].0.id, "a", "highest count first");
        assert_eq!(rows[2].0.id, "c", "never-fired sorts last");

        RuleSort::MostRecent.sort(&mut rows);
        assert_eq!(rows[0].0.id, "b", "freshest fire first");
        assert_eq!(rows[2].0.id, "c", "never-fired still last");
    }

    #[test]
    fn rule_usage_line_reads_naturally() {
        const DAY: u64 = 24 * 3600;
        let now = 100 * DAY;
        assert_eq!(
            rule_usage_line(RuleUsage::default(), now),
            "No auto-fires yet"
        );
        assert_eq!(
            rule_usage_line(
                RuleUsage {
                    count: 1,
                    last_ts_unix: Some(now),
                },
                now
            ),
            "1 auto-fire · last fired today"
        );
        assert_eq!(
            rule_usage_line(
                RuleUsage {
                    count: 12,
                    last_ts_unix: Some(now - 2 * DAY),
                },
                now
            ),
            "12 auto-fires · last fired 2 days ago"
        );
    }

    #[test]
    fn truncate_keeps_short_strings_as_is_and_ellipsizes_long_ones() {
        assert_eq!(truncate_for_display("hi", 10), "hi");
        assert_eq!(truncate_for_display("1234567890", 5), "1234…");
        let s = "café-au-lait-très-longue";
        let t = truncate_for_display(s, 8);
        assert!(t.ends_with('…'));
        assert!(t.chars().count() == 8);
    }

    fn mk_audit(ts: u64, wrap: &str, caller: &str, decision: &str) -> AuditEntry {
        AuditEntry {
            ts_unix: ts,
            cwd: String::new(),
            wrap: wrap.to_owned(),
            args: vec![],
            callers: vec![AuditCaller {
                pid: 100,
                name: caller.to_owned(),
                command: caller.to_owned(),
            }],
            secrets: vec![],
            decision: decision.to_owned(),
            rule_id: None,
            fingerprint: None,
        }
    }

    #[test]
    fn summarize_returns_empty_when_no_match() {
        // Wrong wrap → no signal.
        let entries = vec![mk_audit(1000, "aws", "zsh", "approve")];
        let s = summarize_history(&entries, "gh", Some("zsh"), 2000);
        assert!(s.is_empty());
    }

    #[test]
    fn summarize_filters_by_direct_caller_when_provided() {
        // Two `gh` runs — one from zsh, one from npm. Asking about the
        // zsh caller should pick exactly the zsh entry.
        let entries = vec![
            mk_audit(1000, "gh", "zsh", "approve+remember"),
            mk_audit(1500, "gh", "npm", "deny"),
        ];
        let s = summarize_history(&entries, "gh", Some("zsh"), 2000);
        assert_eq!(s.total_count, 1);
        assert_eq!(s.approve_count, 1);
        assert_eq!(s.deny_count, 0);
        assert_eq!(s.last_decision.as_deref(), Some("approve+remember"));
        assert_eq!(s.last_ts_unix, Some(1000));
    }

    #[test]
    fn summarize_last_decision_survives_past_the_window() {
        // A deny 60 days ago is still informative even though it's
        // outside the 30d counting window — counts stay zero, but the
        // last-decision label still surfaces.
        let now = 100 * 24 * 3600;
        let sixty_days_ago = now - 60 * 24 * 3600;
        let entries = vec![mk_audit(sixty_days_ago, "gh", "zsh", "deny")];
        let s = summarize_history(&entries, "gh", Some("zsh"), now);
        assert_eq!(s.total_count, 0, "outside 30d window, not counted");
        assert_eq!(s.last_decision.as_deref(), Some("deny"));
    }

    #[test]
    fn summarize_aggregates_approves_and_denies_in_window() {
        let now = 10_000_000;
        let recent = now - 24 * 3600; // 1 day ago
        let entries = vec![
            mk_audit(recent, "gh", "zsh", "approve"),
            mk_audit(recent + 100, "gh", "zsh", "approve+remember"),
            mk_audit(recent + 200, "gh", "zsh", "deny"),
        ];
        let s = summarize_history(&entries, "gh", Some("zsh"), now);
        assert_eq!(s.total_count, 3);
        assert_eq!(s.approve_count, 2);
        assert_eq!(s.deny_count, 1);
        // Latest entry wins for last_decision.
        assert_eq!(s.last_decision.as_deref(), Some("deny"));
    }

    #[test]
    fn format_audit_line_handles_empty_and_populated_summaries() {
        let now = 1_000_000;
        let (empty_text, _) = format_audit_line(&WrapHistorySummary::default(), now);
        assert!(
            empty_text.contains("first request"),
            "{empty_text:?} should announce a fresh caller"
        );

        let s = WrapHistorySummary {
            last_decision: Some("approve+remember".into()),
            last_ts_unix: Some(now - 3600),
            approve_count: 5,
            deny_count: 1,
            total_count: 6,
        };
        let (text, _) = format_audit_line(&s, now);
        assert!(text.contains("approved"), "{text:?}");
        assert!(text.contains("5 grants / 1 denies"), "{text:?}");

        let denied = WrapHistorySummary {
            last_decision: Some("deny".into()),
            last_ts_unix: Some(now - 60),
            ..Default::default()
        };
        let (text, color) = format_audit_line(&denied, now);
        assert!(text.contains("denied"));
        assert_eq!(
            color, COLOR_DENY_HINT,
            "denied last must use the warn color"
        );
    }
}
