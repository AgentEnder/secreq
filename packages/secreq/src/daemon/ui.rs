//! Shared egui building blocks for the consent surfaces.
//!
//! The window-level renderers live elsewhere — the transient prompt in
//! [`super::prompt_ui`], the persistent Rules + Audit manager in
//! [`super::manager_ui`], the "N pending" pill in [`super::badge`].
//! This module owns what they share:
//!
//! - the style/font installer ([`install_style`]) that maps the
//!   [`super::theme`] tokens onto egui's stock widgets;
//! - the audit-log cache ([`AuditCache`]) plus the history summarizer
//!   the prompt's HISTORY row and the manager's Audit page both read;
//! - the Rules page (list, suggestions, rule form) and the Audit page,
//!   rendered inside the manager's chrome;
//! - small drawn primitives (app icon, pills, search glyph) and text
//!   helpers (width-measured truncation, durations).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
// Only the pinned clock uses these, and it exists only for the harness.
#[cfg(feature = "harness")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;

use crate::audit::{self, AuditCaller, AuditEntry};
use crate::consent::Decision;
use crate::recommendations::{Suggestion, SuggestionDecision, SuggestionSort};
use crate::rule_scaffold::{self, Editor};
use crate::rules::{
    Pattern, PatternField, Rule, RuleBody, RuleDecision, RuleMatch, StaticDecision,
};

use super::manager_ui::ManagerView;
use super::proto::DedupeKey;
use super::theme::{OsFlavor, Theme};
use crate::provenance::ProcessIdentity;

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
// All colors come from the semantic tokens in [`super::theme`]. Each
// render function resolves the current theme once near its top via
// `Theme::of(...)` — flavor from the compile target (or the harness
// override), light/dark from egui's resolved theme, which follows the
// OS under `ThemePreference::System`.

/// Reserved width of the right-hand verdict column in an audit row.
/// A *real* reservation (the command label is measured to fit the
/// remaining space) rather than a budget subtraction. Clamped to a
/// fraction of the row on narrow windows so the verdict indicator never
/// crowds the command off-screen.
const AUDIT_VERDICT_COL_WIDTH: f32 = 132.0;

/// One pending decision queued for after the render pass. Carries the
/// scope so the approval entry is written at the intended process. Public
/// because the prompt-window child process collects these and ships them
/// back to the daemon over the socket.
///
/// `scope` is `None` when the row's [`crate::daemon::proto::AskAnchor`]
/// names no process — a `run` session or a scoped agent's socket. The
/// prompt used to coerce those anchors into a [`ProcessIdentity`] and offer
/// it as the scope to remember at; a session nonce is not a start time, so
/// there is now no such value to offer.
#[derive(Debug, Clone)]
pub struct PendingAction {
    pub key: DedupeKey,
    pub decision: Decision,
    pub reason: Option<String>,
    pub scope: Option<ProcessIdentity>,
}

/// Form-state for the rule create/edit modal. Holds raw strings so the
/// user can incrementally type into match-pattern fields; on Save it
/// converts to a [`Rule`] and emits a [`RuleAction`].
///
/// The patterns are re-parsed every frame ([`RuleDraft::problems`]) so a
/// glob the loader would refuse cannot leave the form, but the field the
/// caret is in is exempt until the user asks to save — see
/// [`RuleDraft::problems`] for why.
///
/// `original == None` ⇒ creating; `original == Some` ⇒ editing the exact
/// version of an existing rule that seeded the form.
#[derive(Debug, Clone, Default)]
pub(crate) struct RuleDraft {
    id: Option<String>,
    original: Option<Rule>,
    name: String,
    enabled: bool,
    decide: RuleDecisionDraft,
    wrap: String,
    argv: String,
    ancestor: String,
    cwd: String,
    deny_message: String,
    /// Rule-level consultation scope. The current declarative editor does not
    /// expose this field, but it must preserve a hand-authored scope when an
    /// existing rule is edited.
    wraps: Option<std::collections::BTreeSet<String>>,
    /// Snapshot of the secret-set this rule was originally trained on.
    /// Seeded from the audit-row "create rule from this" affordance
    /// (slice 5); empty for blank-form creation, which disables the
    /// trained-secrets guard at evaluator time. UI displays this as
    /// a read-only chip with a tooltip explaining the guard.
    trained_secrets: std::collections::BTreeSet<String>,
    /// Set once a Save has been refused. From then on a broken pattern
    /// is reported wherever the caret is: the user has said they are
    /// finished typing, and a Save that neither saves nor explains
    /// itself is the silence this validation exists to remove.
    save_attempted: bool,
}

/// One reason the rule form will not save the draft.
#[derive(Debug, Clone, PartialEq)]
struct FormProblem {
    /// The match-pattern input it belongs to, when it belongs to one —
    /// which is what lets the form draw the message under that input as
    /// well as in the bottom banner.
    field: Option<PatternField>,
    /// One clause, for the banner, which is one line tall.
    summary: String,
    /// What the mistake costs, drawn under the field where there is
    /// room for it. `None` when the summary already says everything.
    detail: Option<String>,
}

impl FormProblem {
    /// A field the form has always required, whose whole story is its
    /// own summary.
    fn required(summary: &str) -> FormProblem {
        FormProblem {
            field: None,
            summary: summary.to_owned(),
            detail: None,
        }
    }
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
    pub(crate) fn fresh() -> RuleDraft {
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
        let argv = entry.joined_argv();
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
            original: None,
            name,
            enabled: true,
            decide,
            wrap: entry.wrap.clone(),
            argv,
            ancestor,
            cwd: entry.cwd.clone(),
            deny_message: entry.reason.clone().unwrap_or_default(),
            wraps: None,
            trained_secrets,
            save_attempted: false,
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
            original: None,
            name,
            enabled: true,
            decide,
            wrap: s.wrap.clone(),
            argv: s.argv.clone().unwrap_or_default(),
            ancestor: s.ancestor.clone(),
            cwd: s.cwd.clone().unwrap_or_default(),
            deny_message: s.deny_message.clone().unwrap_or_default(),
            wraps: None,
            trained_secrets: s.trained_secrets.clone(),
            save_attempted: false,
        }
    }

    /// Seed the form from an existing **declarative** rule. Wasm rules
    /// never reach this — the list hides their Edit button (the form
    /// only edits match clauses; saving one over a wasm rule would
    /// silently rewrite it as declarative) — so one seeds a blank form
    /// rather than a half-populated one.
    pub(crate) fn from_rule(rule: &Rule) -> RuleDraft {
        let pattern_str =
            |p: Option<&Pattern>| p.map(|p| p.as_str().to_owned()).unwrap_or_default();
        let RuleBody::Declarative { r#match, decide } = &rule.body else {
            return RuleDraft::fresh();
        };
        RuleDraft {
            id: Some(rule.id.clone()),
            original: Some(rule.clone()),
            name: rule.name.clone(),
            enabled: rule.enabled,
            decide: decide.decision().into(),
            wrap: r#match.wrap.clone(),
            argv: pattern_str(r#match.argv.as_ref()),
            ancestor: pattern_str(r#match.ancestor.as_ref()),
            cwd: pattern_str(r#match.cwd.as_ref()),
            deny_message: decide.deny_message().unwrap_or_default().to_owned(),
            wraps: rule.wraps.clone(),
            trained_secrets: rule.trained_secrets.clone(),
            save_attempted: false,
        }
    }

    /// Record that a Save was refused, so the next frame stops
    /// withholding the reason.
    fn note_refused_save(&mut self) {
        self.save_attempted = true;
    }

    /// Every reason the form will not save this draft, in the order the
    /// fields appear. Empty ⇒ Save is live.
    ///
    /// **Patterns are held to what the loader will accept.** A glob
    /// `glob::Pattern` refuses is refused here too, because
    /// [`crate::rules::pattern_refusals`] will refuse it the moment the
    /// rule is read back — saving it produces a rule that matches
    /// nothing and says so only in a badge the author has already
    /// navigated away from. The check is [`Pattern::invalid_reason`],
    /// the loader's own, so the two cannot come to disagree about what
    /// "broken" means.
    ///
    /// **Both decisions are refused, for different stated reasons.** A
    /// broken deny fails open and a broken approve fails closed, but
    /// neither is the rule its author meant to write, so the form
    /// blocks both and quotes
    /// [`crate::rules::refused_pattern_consequence`] to say which one
    /// you are holding.
    ///
    /// `focus` names the pattern input the caret is in, if any. A
    /// broken glob there is withheld: `[` is a legal thing to have
    /// typed so far, and a form that goes red between the `[` and the
    /// `]` teaches the user to type through its warnings. The exemption
    /// ends at the first refused Save (`save_attempted`), which is the
    /// point at which the user has claimed to be done.
    fn problems(&self, focus: Option<PatternField>) -> Vec<FormProblem> {
        let mut out = Vec::new();
        if self.name.trim().is_empty() {
            out.push(FormProblem::required("name is required"));
        }
        if self.wrap.trim().is_empty() {
            out.push(FormProblem::required("wrap is required"));
        }
        if let Some(wraps) = &self.wraps {
            let match_wrap = self.wrap.trim();
            if !match_wrap.is_empty() && !wraps.contains(match_wrap) {
                out.push(FormProblem::required(&format!(
                    "match wrap `{match_wrap}` is outside wrap scope [{}]",
                    wraps.iter().cloned().collect::<Vec<_>>().join(", ")
                )));
            }
        }
        let typing = if self.save_attempted { None } else { focus };
        for (field, raw) in [
            (PatternField::Argv, &self.argv),
            (PatternField::Ancestor, &self.ancestor),
            (PatternField::Cwd, &self.cwd),
        ] {
            if typing == Some(field) {
                continue;
            }
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let pattern = Pattern::parse(raw);
            let Some(err) = pattern.invalid_reason() else {
                continue;
            };
            out.push(FormProblem {
                field: Some(field),
                summary: format!("{} pattern is not a valid glob", field.as_str()),
                detail: Some(format!(
                    "{err} — {}",
                    crate::rules::refused_pattern_consequence(RuleDecision::from(self.decide))
                )),
            });
        }
        out
    }

    /// Convert to a [`Rule`]. Returns `Err(reason)` if the draft is
    /// not savable; the UI surfaces the message inline so the user
    /// sees why Save is refusing.
    ///
    /// Validates with no caret exemption — this is the only path from
    /// the form to a saved rule, so it is where "a user must not be
    /// able to save what the loader will refuse" is actually true,
    /// rather than merely likely.
    fn into_rule(self) -> Result<Rule, String> {
        if let Some(problem) = self.problems(None).into_iter().next() {
            return Err(problem.summary);
        }
        let name = self.name.trim();
        let wrap = self.wrap.trim();
        let optional_pattern = |s: &str| -> Option<Pattern> {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                Some(Pattern::parse(s))
            }
        };
        // The form keeps a message box either way (the toggle can flip
        // back), but only a deny has somewhere to show one — so the
        // approve branch simply has no field to put it in.
        let decide = match self.decide {
            RuleDecisionDraft::Approve => StaticDecision::Approve,
            RuleDecisionDraft::Deny => {
                let m = self.deny_message.trim();
                StaticDecision::Deny {
                    message: (!m.is_empty()).then(|| m.to_owned()),
                }
            }
        };
        let id = self.id.unwrap_or_else(crate::rules::new_rule_id);
        let created_at = crate::rules::now_unix();
        Ok(Rule {
            id,
            name: name.to_owned(),
            enabled: self.enabled,
            wraps: self.wraps,
            trained_secrets: self.trained_secrets,
            created_at_unix: created_at,
            // The form authors declarative rules only; wasm rules are
            // registered via the CLI.
            body: RuleBody::Declarative {
                r#match: RuleMatch {
                    wrap: wrap.to_owned(),
                    argv: optional_pattern(&self.argv),
                    ancestor: optional_pattern(&self.ancestor),
                    cwd: optional_pattern(&self.cwd),
                },
                decide,
            },
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
    Update {
        expected: Rule,
        replacement: Box<Rule>,
    },
    Delete {
        expected: Rule,
    },
    SetEnabled {
        expected: Rule,
        enabled: bool,
    },
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
/// **Visuals.** Every colour derives from the semantic tokens in
/// [`super::theme`], resolved per call so an OS light/dark flip (or a
/// harness flavor override) takes effect on the next frame. Corner
/// radii come from the flavor's metrics so stock widgets look part of
/// the same design system as the hand-painted surfaces.
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
    let th = Theme::of(ctx);
    ctx.global_style_mut(|style| {
        let v = &mut style.visuals;
        v.dark_mode = th.dark;
        v.panel_fill = th.panel;
        v.window_fill = th.panel;
        v.extreme_bg_color = th.well;
        v.faint_bg_color = th.raised;
        v.override_text_color = Some(th.fg);
        // Widget surface tones. egui uses these for buttons, tabs,
        // hovered labels, etc.; align them with our tokens so
        // stock widgets we don't custom-paint still feel native.
        v.widgets.noninteractive.bg_fill = th.well;
        v.widgets.noninteractive.weak_bg_fill = th.well;
        v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, th.rule);
        v.widgets.inactive.bg_fill = th.btn;
        v.widgets.inactive.weak_bg_fill = th.btn;
        v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, th.btn_border);
        v.widgets.hovered.bg_fill = th.raised;
        v.widgets.hovered.weak_bg_fill = th.raised;
        v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, th.btn_border);
        v.widgets.active.bg_fill = th.accent.gamma_multiply(0.35);
        v.widgets.active.weak_bg_fill = th.accent.gamma_multiply(0.35);
        // Unified corner radii across egui widgets, from the flavor's
        // button-radius metric so everything shares one corner language.
        let r = egui::CornerRadius::same(th.btn_radius);
        v.widgets.noninteractive.corner_radius = r;
        v.widgets.inactive.corner_radius = r;
        v.widgets.hovered.corner_radius = r;
        v.widgets.active.corner_radius = r;
        // Selection chrome — used by text selection, accent fills.
        v.selection.bg_fill = th.accent.gamma_multiply(0.35);
        v.selection.stroke = egui::Stroke::new(1.0, th.accent);
        // Loosen up some default spacing for a calmer rhythm.
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);
    });
}

/// Render the always-on-top pending-requests badge: a compact pill
/// reading "N pending" with an accent indicator dot. The background is
/// painted here (not left to the window/panel fill) so the screenshot
/// fixture renders the exact pixels the production badge window shows:
/// a `th.panel` surface with a 1px `th.rule` border, the count in
/// `th.accent_text`, and the "pending" label in `th.fg`.
/// Returns the click response over the whole pill — the badge child
/// turns a click into a `RaiseConsentRequested`.
pub fn render_badge(ui: &mut egui::Ui, count: usize) -> egui::Response {
    let th = Theme::of(ui.ctx());
    let rect = ui.max_rect();
    // Clone so the painter doesn't hold a borrow across `allocate_rect`.
    let painter = ui.painter().clone();

    // Opaque fill of the whole (small, borderless) window, with a
    // hairline border so the pill reads as a surface over any desktop.
    painter.rect_filled(rect, egui::CornerRadius::ZERO, th.panel);
    painter.rect_stroke(
        rect,
        egui::CornerRadius::ZERO,
        egui::Stroke::new(1.0, th.rule),
        egui::StrokeKind::Inside,
    );

    // Accent indicator dot, vertically centred, inset from the left.
    let dot_radius = 5.0;
    let dot_center = egui::pos2(rect.left() + 16.0, rect.center().y);
    painter.circle_filled(dot_center, dot_radius, th.accent);

    // Count in accent text, then the "pending" label in the body tier.
    let font = egui::FontId::proportional(18.0);
    let count_rect = painter.text(
        egui::pos2(dot_center.x + dot_radius + 10.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        count.to_string(),
        font.clone(),
        th.accent_text,
    );
    painter.text(
        egui::pos2(count_rect.right() + 6.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        "pending",
        font,
        th.fg,
    );

    ui.allocate_rect(rect, egui::Sense::click())
}

/// The badge window's clear colour, matching [`render_badge`]'s fill, so
/// any pixels the painter doesn't cover (sub-pixel edges, the frame
/// before the first paint) show the surface colour rather than flashing
/// a stale or black background. No `egui::Context` is available in
/// `eframe::App::clear_color`'s caller before the first frame, so this
/// resolves the host flavor's dark surface directly. Shape matches
/// `clear_color`'s `[r, g, b, a]` gamma-normalised return.
pub fn badge_clear_color() -> [f32; 4] {
    Theme::resolve(OsFlavor::current(), true)
        .panel
        .to_normalized_gamma_f32()
}

// ── Audit history cache ──────────────────────────────────────────────────
//
// The daemon never writes the audit log (clients do, post-decision in
// `commands/run.rs`), so the cache is a pure read. We poll on mtime to pick up
// entries from sibling client processes between paints — cheaper than a
// full reparse, and good enough since "history" is only consulted while
// the window is visible.

pub(crate) struct AuditCache {
    entries: Vec<AuditEntry>,
    last_load: Option<Instant>,
    last_mtime: Option<SystemTime>,
}

impl AuditCache {
    pub(crate) fn new() -> AuditCache {
        AuditCache {
            entries: Vec::new(),
            last_load: None,
            last_mtime: None,
        }
    }

    pub(crate) fn refresh_if_stale(&mut self) {
        let now = Instant::now();
        let due = self
            .last_load
            .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(AUDIT_REFRESH_SECS));
        if !due {
            return;
        }
        let mtime = audit::audit_log_mtime();
        // mtime-unchanged → reuse parsed entries, just bump the poll clock.
        if self.last_load.is_some() && mtime == self.last_mtime {
            self.last_load = Some(now);
            return;
        }
        match audit::read_history_with_summary(Some(AUDIT_HISTORY_LIMIT)) {
            Ok((entries, summary)) => {
                self.entries = entries;
                self.last_mtime = mtime;
                if summary.malformed > 0 {
                    super::log::log_at(
                        "ui",
                        format_args!(
                            "WARN: skipped {} malformed audit record(s) while refreshing history",
                            summary.malformed
                        ),
                    );
                }
            }
            Err(err) => {
                super::log::log_at(
                    "ui",
                    format_args!("WARN: could not refresh audit history: {err:#}"),
                );
            }
        }
        self.last_load = Some(now);
    }

    pub(crate) fn summarize(
        &self,
        wrap: &str,
        caller: Option<CallerIdentity<'_>>,
    ) -> WrapHistorySummary {
        summarize_history(&self.entries, wrap, caller, now_unix())
    }

    /// The parsed entries, newest last (file order). The manager's
    /// Rules view feeds these to the suggestion engine and the
    /// per-rule usage index.
    pub(crate) fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WrapHistorySummary {
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
    /// `pub(crate)` so `prompt_ui` can branch on it: the scoped-agent
    /// prompt substitutes its own empty-history wording, since the shared
    /// one names a "caller" that a guest ask doesn't have.
    pub(crate) fn is_empty(&self) -> bool {
        self.total_count == 0 && self.last_ts_unix.is_none()
    }
}

/// How the direct caller is identified when matching audit history.
///
/// The prompt's HISTORY row ("approved 12 times, last approve 2 minutes ago")
/// is the strongest "you have seen this and said yes" signal the UI offers,
/// and it used to be matched on `callers[0].name` — `comm`, which a process
/// sets on itself with one `prctl(PR_SET_NAME)` on Linux, or by being a file
/// called `zsh` on macOS. So `cp /bin/sh /tmp/zsh` inherited the victim's
/// entire approval record for the cost of a filename.
///
/// `exe` is the kernel's record of what was loaded and cannot be chosen by
/// the process it names, so it wins whenever both sides have one. The name is
/// the fallback, not a supplement: rows written before `exe` existed have
/// none, and dropping them would blank the history for every existing install.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CallerIdentity<'a> {
    pub name: &'a str,
    pub exe: Option<&'a str>,
}

impl CallerIdentity<'_> {
    /// Does `entry_caller` name the same caller?
    fn matches(self, entry_caller: Option<&crate::audit::AuditCaller>) -> bool {
        let Some(entry_caller) = entry_caller else {
            return false;
        };
        match (self.exe, entry_caller.exe.as_deref()) {
            // Both known: the path decides, and a mismatch is a mismatch
            // however the two processes chose to name themselves.
            (Some(want), Some(got)) => want == got,
            // Either side is missing a path — an older audit row, or a
            // process sysinfo could not resolve. Fall back to the name.
            _ => entry_caller.name == self.name,
        }
    }
}

/// Pure summarizer split from `AuditCache` so it can be unit-tested without
/// touching the filesystem. Matches on `entry.wrap == wrap` and, when
/// `caller` is supplied, the direct (callers[0]) caller's identity.
fn summarize_history(
    entries: &[AuditEntry],
    wrap: &str,
    caller: Option<CallerIdentity<'_>>,
    now_unix: u64,
) -> WrapHistorySummary {
    let cutoff = now_unix.saturating_sub(AUDIT_WINDOW_SECS);
    let mut out = WrapHistorySummary::default();
    for e in entries {
        if e.wrap != wrap {
            continue;
        }
        if let Some(want) = caller {
            if !want.matches(e.callers.first()) {
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
            "deny" | "deny+out-of-scope" => out.deny_count += 1,
            _ => {}
        }
    }
    out
}

/// A frozen wall clock, or `0` for "read the real one". See [`pin_clock`].
#[cfg(feature = "harness")]
static PINNED_CLOCK: AtomicU64 = AtomicU64::new(0);

/// Freeze the wall clock the audit and history surfaces read.
///
/// Those surfaces are relative-time views: the HISTORY row says "denied 5m
/// ago", the Audit page buckets rows by *calendar day* into Today / Yesterday
/// / N days ago. A window is therefore a function of **when** it was rendered
/// as much as of what it holds — a row six hours old reads "Today" at noon and
/// "Yesterday" at 3am. That is correct for a live window and wrong for a
/// captured one, where it means a fixture's PNGs and its layout snapshot
/// depend on the hour someone happened to regenerate them.
///
/// Pinning the clock makes a capture a function of its fixture data alone.
///
/// Behind the `harness` feature, which nothing but the test build enables, so
/// this does not exist in a shipped binary. That matters more than it looks:
/// the clock it freezes is the one `audit.rs` stamps onto every `AuditEntry`,
/// so an unguarded `pub fn` here is a public API for backdating the audit log.
/// "The harness is the only caller" was true and was enforced by nothing.
#[cfg(feature = "harness")]
pub fn pin_clock(ts_unix: u64) {
    PINNED_CLOCK.store(ts_unix, Ordering::Relaxed);
}

pub(crate) fn now_unix() -> u64 {
    // Without the `harness` feature there is no pinned clock to consult and no
    // branch here at all — a shipped binary reads the real one, always.
    #[cfg(feature = "harness")]
    {
        let pinned = PINNED_CLOCK.load(Ordering::Relaxed);
        if pinned != 0 {
            return pinned;
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ── Rendering ─────────────────────────────────────────────────────────────

/// Draw the app mark — the Gate Monogram: two brackets (the gate), one
/// accent dot (the secret); it passes through only with consent. No
/// tile, no border: the brackets ride the theme foreground directly on
/// the panel, so the mark reads as chrome, not as an app-store icon.
/// Master SVG: `dev-docs/brand/logo.svg` (viewBox 0 0 64 64; geometry
/// below mirrors it). The docs site's favicon and header mark are
/// derived from the same file — change the master, not one consumer.
pub(crate) fn paint_app_icon(ui: &mut egui::Ui, size: f32) {
    let th = Theme::of(ui.ctx());
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let painter = ui.painter();
    let s = size / 64.0;
    // Below ~20px, fatten the stroke and dot one step so the mark
    // survives (mirrors the SVG's 16px favicon variant).
    let (stroke_w, dot_r) = if size < 20.0 {
        (8.0 * s, 9.0 * s)
    } else {
        (7.0 * s, 7.0 * s)
    };
    let stroke = egui::Stroke::new(stroke_w.max(1.0), th.fg);

    let x = |v: f32| rect.left() + v * s;
    let y = |v: f32| rect.top() + v * s;
    // Left bracket: M23 10 H13 V54 H23. Verticals overshoot by half a
    // stroke width so the corners join square, like the SVG's
    // stroke-linecap="square".
    let half = stroke_w / 2.0;
    painter.line_segment(
        [egui::pos2(x(23.0), y(10.0)), egui::pos2(x(13.0), y(10.0))],
        stroke,
    );
    painter.line_segment(
        [
            egui::pos2(x(13.0), y(10.0) - half),
            egui::pos2(x(13.0), y(54.0) + half),
        ],
        stroke,
    );
    painter.line_segment(
        [egui::pos2(x(13.0), y(54.0)), egui::pos2(x(23.0), y(54.0))],
        stroke,
    );
    // Right bracket: M41 10 H51 V54 H41.
    painter.line_segment(
        [egui::pos2(x(41.0), y(10.0)), egui::pos2(x(51.0), y(10.0))],
        stroke,
    );
    painter.line_segment(
        [
            egui::pos2(x(51.0), y(10.0) - half),
            egui::pos2(x(51.0), y(54.0) + half),
        ],
        stroke,
    );
    painter.line_segment(
        [egui::pos2(x(51.0), y(54.0)), egui::pos2(x(41.0), y(54.0))],
        stroke,
    );
    // The secret.
    painter.circle_filled(rect.center(), dot_r, th.accent);
}

/// Paint a small magnifier glyph for the search field — a hollow ring
/// with a short diagonal handle. Hand-painted because the bundled font
/// stack has no search glyph (and the UI avoids emoji), the same reason
/// the app logo and key are drawn from primitives. Used by the manager
/// window's header search box.
pub(crate) fn paint_search_glyph(ui: &mut egui::Ui, color: egui::Color32) {
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

/// The Audit page body, rendered inside the manager window below its
/// header chrome. The search *input* lives in that header (bound to
/// `ManagerWindowState::audit_search`); this page receives the query
/// read-only and does the filtering, the day-bucketed timeline, and
/// the "Create rule from this ask…" hand-off into the Rules view.
pub(crate) fn render_audit_page(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    audit: &AuditCache,
    rules_draft: &mut Option<RuleDraft>,
    view: &mut ManagerView,
    search: &str,
    expanded_bursts: &mut std::collections::HashSet<String>,
) {
    let th = Theme::of(ctx);
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
                    .color(th.dim),
            );
        });
        return;
    }

    // Filter first, group second, cap third. The order is load-bearing:
    //
    // - Filtering before grouping is what makes a burst unable to hide a
    //   search hit; see [`audit_row_identity`] for the guarantee.
    // - Capping *groups* rather than rows is what makes the collapsing worth
    //   having. A cap on rows would let one flood of identical requests spend
    //   the whole budget and leave the reader looking at a single collapsed
    //   row above an empty page — the same "your history is buried" failure,
    //   wearing a count.
    let total = audit.entries.len();
    let query = search.trim().to_owned();
    let matched: Vec<&AuditEntry> = audit
        .entries
        .iter()
        .rev()
        .filter(|e| audit_entry_matches(e, &query))
        .collect();

    // Match count while a query is active — the header's search box is
    // pure input, so the "N of M" feedback renders with the results.
    // Counted in *entries*, not groups: a reader asking "how much of my log
    // is this" means rows, and a collapsed group already states its own size.
    if !query.is_empty() {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
            ui.label(
                egui::RichText::new(format!("{} of {total}", matched.len()))
                    .size(11.0)
                    .color(th.dim),
            );
        });
        ui.add_space(4.0);
    }

    if matched.is_empty() {
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
                    .color(th.dim),
            );
        });
        return;
    }

    let now = now_unix();
    let bursts = group_audit_bursts(&matched, now);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // Newest first — that's what you want to scan in a console
            // session. Day-bucket headers give the eye an anchor while
            // scanning; a 1px hairline separates consecutive entries
            // (flat rows, not bordered cards).
            let mut last_bucket: Option<&str> = None;
            let mut first = true;
            for burst in bursts.iter().take(AUDIT_MAX_BURSTS) {
                let new_bucket = last_bucket != Some(burst.bucket.as_str());
                if !first && !new_bucket {
                    audit_row_separator(ui, &th);
                }
                if new_bucket {
                    if last_bucket.is_some() {
                        ui.add_space(10.0);
                    }
                    ui.label(
                        egui::RichText::new(&burst.bucket)
                            .size(11.0)
                            .strong()
                            .color(th.faint),
                    );
                    ui.add_space(4.0);
                    last_bucket = Some(burst.bucket.as_str());
                }
                render_audit_burst(ui, burst, now, expanded_bursts, rules_draft, view);
                first = false;
            }
        });
}

/// 1px `th.rule` hairline between two flat audit rows.
fn audit_row_separator(ui: &mut egui::Ui, th: &Theme) {
    ui.add_space(7.0);
    let y = ui.cursor().min.y;
    ui.painter()
        .hline(ui.max_rect().x_range(), y, egui::Stroke::new(1.0, th.rule));
    ui.add_space(8.0);
}

/// How many bursts the timeline draws. Was 200 *rows*; it is 200 *groups*
/// because a cap on rows is spent by exactly the thing the grouping exists to
/// survive — a guest that can drive an unbounded run of identical asks fills
/// the budget with one repeated row and pushes the rest of the history off the
/// end. A collapsed burst costs one row, so the reader keeps 200 distinct
/// things to look at no matter how loud any one of them was.
///
/// An expanded burst can exceed this. That is one group, opened deliberately,
/// and refusing to draw what the user just asked to see would be the view
/// hiding the log again.
const AUDIT_MAX_BURSTS: usize = 200;

/// A maximal run of adjacent identical rows in the filtered timeline —
/// what the view collapses into one row plus a count.
///
/// **The log on disk is untouched.** Every row is still its own line in
/// `audit.log`, unique and unchanged; this type exists only between the
/// filter and the painter.
struct AuditBurst<'a> {
    /// The row a collapsed burst draws: the first of the run in the order the
    /// timeline is showing. Held as its own field rather than read back out of
    /// `rows`, so "a burst is never empty" is a fact about the type instead of
    /// an invariant every reader has to be trusted with.
    lead: &'a AuditEntry,
    /// Every row in the run, in timeline order, `lead` included. Length 1 is
    /// the ordinary case and renders exactly as it did before this existed.
    rows: Vec<&'a AuditEntry>,
    /// Seconds from the oldest member to the newest. `0` when the whole run
    /// landed inside one second, which is the shape a probing loop makes.
    ///
    /// Folded over every row rather than read off the run's two ends, so it
    /// stays true whatever order the list arrives in. A span is the number a
    /// reader sizes an incident with; it must not be able to read `0` because
    /// of a sort.
    span_secs: u64,
    /// The day-bucket header this run sits under. Part of the run's identity,
    /// so a burst can never straddle two headers and leave one of them
    /// claiming rows that are not under it.
    bucket: String,
    /// Stable key for the expansion set; see [`audit_burst_key`].
    key: String,
}

/// Everything the audit view draws about a request, minus the two things that
/// differ between two occurrences of the *same* request: **when** it happened,
/// and **which pids** the kernel happened to hand out. Two rows are "identical"
/// exactly when these strings are equal.
///
/// Excluding the pid is not a convenience. A shell loop gets a fresh pid every
/// iteration, and a run of asks from a guest carries no pid at all — so an
/// identity that read pids would collapse nothing on the case this feature
/// exists for. The cost is that a collapsed row shows one member's pids rather
/// than every member's, and the answer to that is the expansion: open the
/// group and each row is there with its own pids and its own timestamp.
///
/// **The search cannot lose a hit inside a burst.** `audit_entry_matches`
/// reads the wrap, the decision, the args, each caller's name and command, the
/// secret names, and the guest's claimed chain — a strict subset of the fields
/// below. So any two rows with the same identity are *search-equivalent*: no
/// query exists that matches one and not the other, and a group can never be
/// hiding a row the user is looking for. `identity_reads_every_field_the_search_reads`
/// is that invariant as a test, and it fails if a field is ever added to the
/// search without being added here.
///
/// Values are length-prefixed rather than delimited because a scoped-agent
/// guest supplies some of these strings verbatim (its claimed chain, the refs
/// it asks for), and a separator a guest can type is a boundary a guest can
/// move.
fn audit_row_identity(entry: &AuditEntry) -> String {
    let mut id = String::new();
    let mut push = |v: &str| {
        id.push_str(&v.len().to_string());
        id.push(':');
        id.push_str(v);
    };

    push(&entry.wrap);
    push(&entry.decision);
    push(entry.reason.as_deref().unwrap_or_default());
    push(&entry.cwd);
    push(entry.rule_id.as_deref().unwrap_or_default());
    push(entry.fingerprint.as_deref().unwrap_or_default());
    push(match entry.callers_truncated {
        Some(true) => "clipped",
        Some(false) => "complete",
        None => "unrecorded",
    });

    push(&entry.args.len().to_string());
    for arg in &entry.args {
        push(arg);
    }
    push(&entry.secrets.len().to_string());
    for secret in &entry.secrets {
        push(secret);
    }
    push(&entry.callers.len().to_string());
    for caller in &entry.callers {
        push(&caller.name);
        push(&caller.command);
        push(caller.exe.as_deref().unwrap_or_default());
    }

    match &entry.sign_anchor {
        Some(anchor) => {
            push("anchor");
            push(match anchor.kind {
                crate::provenance::SignAnchorKind::Session => "session",
                crate::provenance::SignAnchorKind::ForwardedSsh => "forwarded_ssh",
            });
            push(&anchor.name);
            push(anchor.command.as_deref().unwrap_or_default());
        }
        None => push("no-anchor"),
    }

    match &entry.declared_by {
        Some(crate::audit::ScopeDeclarant::Peer(peer)) => {
            push("declarant-peer");
            push(&peer.name);
            push(&peer.command);
            push(peer.exe.as_deref().unwrap_or_default());
        }
        Some(crate::audit::ScopeDeclarant::Gone) => push("declarant-gone"),
        Some(crate::audit::ScopeDeclarant::NotRead) => push("declarant-not-read"),
        None => push("no-declarant"),
    }

    push(entry.unverified_guest_chain.as_deref().unwrap_or_default());
    id
}

/// The expansion key for the burst `oldest` is the **oldest** member of.
///
/// Keyed on the oldest end because that is the end that does not move. A new
/// identical request joins at the newest end, so a key built from the newest
/// row would change every time the flood ticked — collapsing the group under
/// the user mid-read, on exactly the rows where they are most likely to be
/// reading. The oldest member only changes when rows age out of the cache.
pub(crate) fn audit_burst_key(oldest: &AuditEntry) -> String {
    burst_key_of(oldest.ts_unix, &audit_row_identity(oldest))
}

fn burst_key_of(oldest_ts: u64, identity: &str) -> String {
    format!("{oldest_ts}:{identity}")
}

/// Fold the filtered timeline into runs of adjacent identical rows.
///
/// **Adjacency, not a time window** — deliberately, and there is no tuning
/// constant here to get wrong. Three reasons:
///
/// - A row that is *not* identical breaks the run. That is the forensically
///   important half: a run of 47 refusals with one approval in the middle must
///   never render as 47 uninterrupted refusals, and a window would let it.
/// - A window would leave two identical rows three hours apart drawn as two
///   rows that look the same, making the reader compare timestamps to find
///   out they are not one event. Adjacency groups them and *states* the span,
///   which is more information rather than less.
/// - The failure mode is safe. Worst case adjacency groups nothing, and the
///   view is what it was before.
///
/// The list arrives newest-first and already filtered, so a query that hides
/// an interleaving row can merge two runs that were separate without it. That
/// is correct: the group is a property of the list on screen, and its header
/// counts what is on screen.
fn group_audit_bursts<'a>(rows: &[&'a AuditEntry], now: u64) -> Vec<AuditBurst<'a>> {
    let mut out: Vec<AuditBurst<'a>> = Vec::new();
    let mut open: Option<OpenBurst<'a>> = None;

    for row in rows {
        let identity = audit_row_identity(row);
        let bucket = audit_day_bucket(row.ts_unix, now);
        if let Some(acc) = &mut open {
            if acc.identity == identity && acc.bucket == bucket {
                acc.rows.push(row);
                continue;
            }
        }
        if let Some(acc) = open.take() {
            out.push(acc.close());
        }
        open = Some(OpenBurst {
            identity,
            bucket,
            lead: row,
            rows: vec![row],
        });
    }
    if let Some(acc) = open.take() {
        out.push(acc.close());
    }
    out
}

/// A run still being accumulated by [`group_audit_bursts`]. Separate from
/// [`AuditBurst`] because the finished type carries a span and a key that only
/// exist once the run is closed.
struct OpenBurst<'a> {
    identity: String,
    bucket: String,
    lead: &'a AuditEntry,
    rows: Vec<&'a AuditEntry>,
}

impl<'a> OpenBurst<'a> {
    fn close(self) -> AuditBurst<'a> {
        // `rows` always holds at least `lead`, so seeding the fold with it is
        // the run's own first answer rather than a stand-in: a one-row run
        // spans zero seconds because both its bounds are that row.
        let mut oldest_ts = self.lead.ts_unix;
        let mut newest_ts = self.lead.ts_unix;
        for row in &self.rows {
            oldest_ts = oldest_ts.min(row.ts_unix);
            newest_ts = newest_ts.max(row.ts_unix);
        }
        AuditBurst {
            key: burst_key_of(oldest_ts, &self.identity),
            span_secs: newest_ts.saturating_sub(oldest_ts),
            lead: self.lead,
            rows: self.rows,
            bucket: self.bucket,
        }
    }
}

/// Pure predicate: does `entry` match `query`? The query is split into
/// whitespace-separated terms; the entry matches when **every** term is
/// a case-insensitive substring of **some** field — the wrap name, any
/// argv token, each caller's `name`/`command`, any requested secret
/// name, the decision string, or a guest's claimed caller chain.
///
/// That last field is **attacker-chosen**: a guest writes it, so a guest
/// can put its row in the results for any term it likes. Searching it
/// anyway is right — a reviewer who has read a report and types
/// `postinstall` wants the rows where something *said* it was
/// postinstall at least as much as the ones secreq walked itself, and a
/// claim that is recorded and drawn but unfindable is worse than one
/// never recorded. What keeps the results honest is that the claim is
/// read here through [`guest_chain_claim`], the same accessor
/// [`render_audit_entry`] draws from: every row a claim can pull into
/// the results is a row that arrives carrying
/// [`GUEST_CHAIN_CAVEAT`] under `guest says`. A hit on a forgery cannot
/// render as a fact, because the two are the same code path.
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
        .map(str::to_ascii_lowercase)
        .collect();
    if terms.is_empty() {
        return true;
    }
    // Lowercase every searchable field once, then test each term
    // against the set — cheaper than re-lowercasing per term.
    let mut fields: Vec<String> = Vec::with_capacity(2 + entry.args.len() + entry.secrets.len());
    fields.push(entry.wrap.to_ascii_lowercase());
    fields.push(entry.decision.to_ascii_lowercase());
    if let Some(reason) = &entry.reason {
        fields.push(reason.to_ascii_lowercase());
    }
    fields.extend(entry.args.iter().map(|a| a.to_ascii_lowercase()));
    for caller in &entry.callers {
        fields.push(caller.name.to_ascii_lowercase());
        fields.push(caller.command.to_ascii_lowercase());
    }
    fields.extend(entry.secrets.iter().map(|s| s.to_ascii_lowercase()));
    if let Some(claim) = guest_chain_claim(entry) {
        fields.push(claim.to_ascii_lowercase());
    }

    terms
        .iter()
        .all(|term| fields.iter().any(|field| field.contains(term)))
}

// ── Rules page ───────────────────────────────────────────────────────────
//
// Two modes: list (the default) and form (visible while
// `rules_draft` is `Some`). The form covers both Create and Edit; the
// `id` field of the draft discriminates which.

// ── Programmatic-rule scaffold panel ───────────────────────────────────────
//
// The prominent "Write a programmatic rule" card at the top of the Rules
// list. It scaffolds a wasm-rule project on disk (via
// [`crate::rule_scaffold`]) and then offers a GitHub-style split-button
// that opens the scaffold in the user's editor — primary action runs the
// preferred editor, the caret picks a different detected one and makes it
// the new default (persisted to `editor`).

/// A transient status line shown under the scaffold panel after an
/// action. Info is the success path; Error surfaces a failed scaffold or
/// launch without tearing down the panel.
enum ScaffoldStatus {
    Info(String),
    Error(String),
}

/// Everything the scaffold panel remembers across frames. Session-scoped,
/// like the rest of [`super::manager_ui::ManagerWindowState`]. Detection
/// and the persisted preference are probed once, lazily, on first render
/// — the screenshot harness seeds them instead so it never touches the
/// host (see [`ScaffoldPanel::seed_for_test`]).
pub struct ScaffoldPanel {
    /// Editors detected on this machine, in catalog order. Empty after a
    /// probe that found none; `probed` distinguishes "not yet probed".
    editors: Vec<Editor>,
    /// The persisted preferred-editor id (`editor`), if set.
    preferred: Option<String>,
    /// Whether detection + preference-load has run. Guards the one-time
    /// host probe.
    probed: bool,
    /// The entry file scaffolded this session — enables the split-button.
    scaffolded: Option<PathBuf>,
    /// Whether the split-button's editor dropdown is expanded.
    dropdown_open: bool,
    /// Transient status line under the panel.
    status: Option<ScaffoldStatus>,
}

impl ScaffoldPanel {
    pub(crate) fn new() -> ScaffoldPanel {
        ScaffoldPanel {
            editors: Vec::new(),
            preferred: None,
            probed: false,
            scaffolded: None,
            dropdown_open: false,
            status: None,
        }
    }

    /// Run editor detection and load the persisted preference exactly
    /// once. A no-op after the first call — or if a fixture already
    /// seeded state, keeping the harness off the host.
    fn ensure_probed(&mut self) {
        if self.probed {
            return;
        }
        self.editors = rule_scaffold::detect_editors();
        self.preferred = rule_scaffold::preferred_editor();
        self.probed = true;
    }

    /// The editor the primary button targets: the persisted preference if
    /// it's still installed, else the first detected editor.
    fn primary(&self) -> Option<&Editor> {
        self.preferred
            .as_deref()
            .and_then(|id| self.editors.iter().find(|e| e.id == id))
            .or_else(|| self.editors.first())
    }

    /// Seed detected editors + preference without touching the host.
    /// Marks the panel probed so real detection never runs. Harness-only
    /// entry point (the production path probes lazily).
    pub fn seed_for_test(&mut self, editors: Vec<Editor>, preferred: Option<String>) {
        self.editors = editors;
        self.preferred = preferred;
        self.probed = true;
    }

    /// Pretend a scaffold happened at `entry`, so a fixture can render the
    /// post-scaffold state (the split-button appears).
    pub fn mark_scaffolded_for_test(&mut self, entry: PathBuf) {
        self.scaffolded = Some(entry);
    }

    /// Force the split-button's editor dropdown open, so a fixture can
    /// render the expanded menu.
    pub fn open_dropdown_for_test(&mut self) {
        self.dropdown_open = true;
    }
}

impl Default for ScaffoldPanel {
    fn default() -> Self {
        ScaffoldPanel::new()
    }
}

/// What the user did with the "Open in editor" split-button this frame.
enum SplitAction {
    /// Primary segment clicked — open in the currently-selected editor.
    Primary,
    /// A dropdown entry was picked — open in it and make it the default.
    Pick(String),
    /// Nothing this frame.
    None,
}

/// The prominent scaffold card. Lazily probes editors, renders the
/// pitch + "Scaffold a rule" button, and — once something is scaffolded
/// — the "Open in editor" split-button.
fn render_scaffold_panel(ui: &mut egui::Ui, panel: &mut ScaffoldPanel) {
    panel.ensure_probed();
    let th = Theme::of(ui.ctx());
    egui::Frame::new()
        .fill(th.well)
        .stroke(egui::Stroke::new(1.0, th.accent.gamma_multiply(0.55)))
        .inner_margin(egui::Margin::same(14))
        .corner_radius(egui::CornerRadius::same(th.well_radius))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                render_pill(ui, "programmatic", th.accent, soft_fill(th.accent));
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("Write a programmatic rule")
                        .strong()
                        .size(15.0)
                        .color(th.fg),
                );
            });
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "The primary way to author auto-approvals: a sandboxed \
                     decide(ctx) function with the full power of code. Scaffold \
                     a starter project and open it in your editor.",
                )
                .color(th.dim)
                .size(11.5),
            );
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                if render_primary_button(ui, "Scaffold a rule", true).clicked() {
                    match rule_scaffold::scaffold_new_rule() {
                        Ok(scaffold) => {
                            panel.status = Some(ScaffoldStatus::Info(format!(
                                "Scaffolded {}",
                                scaffold.dir.display()
                            )));
                            panel.scaffolded = Some(scaffold.entry);
                        }
                        Err(err) => {
                            panel.status =
                                Some(ScaffoldStatus::Error(format!("Scaffold failed: {err:#}")));
                        }
                    }
                }
                if panel.scaffolded.is_some() {
                    ui.add_space(8.0);
                    render_open_in_editor(ui, panel);
                }
            });

            if let Some(status) = &panel.status {
                ui.add_space(8.0);
                let (color, text) = match status {
                    ScaffoldStatus::Info(m) => (th.dim, m.as_str()),
                    ScaffoldStatus::Error(m) => (th.danger, m.as_str()),
                };
                ui.label(
                    egui::RichText::new(text)
                        .color(color)
                        .size(11.0)
                        .family(egui::FontFamily::Monospace),
                );
            }
        });
}

/// The "Open in editor" split-button plus the effect of clicking it:
/// launch the chosen editor on the scaffolded file, and (for a dropdown
/// pick) persist the choice as the new `editor` default.
fn render_open_in_editor(ui: &mut egui::Ui, panel: &mut ScaffoldPanel) {
    let th = Theme::of(ui.ctx());
    let Some(primary) = panel.primary().cloned() else {
        // Nothing installed — a dead button would be worse than a hint.
        ui.label(
            egui::RichText::new("No editor detected on PATH")
                .color(th.faint)
                .size(11.0),
        );
        return;
    };
    let path = panel.scaffolded.clone();
    let options = panel.editors.clone();
    let action = render_split_button(
        ui,
        &format!("Open in {}", primary.display),
        &options,
        &primary.id,
        &mut panel.dropdown_open,
    );

    // Resolve which editor to open (if any) and whether the pick should
    // stick, then do the one launch at the end — keeps the borrow of
    // `panel` simple (no closure over it).
    let to_open: Option<Editor> = match action {
        SplitAction::Primary => Some(primary),
        SplitAction::Pick(id) => {
            let picked = options.iter().find(|e| e.id == id).cloned();
            if picked.is_some() {
                // The pick sticks: update the in-memory preference so the
                // primary label updates immediately, and persist it.
                panel.preferred = Some(id.clone());
                if let Err(err) = rule_scaffold::save_preferred_editor(&id) {
                    panel.status = Some(ScaffoldStatus::Error(format!(
                        "couldn't save editor preference: {err:#}"
                    )));
                }
            }
            picked
        }
        SplitAction::None => None,
    };

    if let (Some(editor), Some(path)) = (to_open, path) {
        if let Err(err) = rule_scaffold::launch_editor(&editor, &path) {
            panel.status = Some(ScaffoldStatus::Error(format!("{err:#}")));
        }
    }
}

/// A GitHub-style split/dropdown button: an accent primary segment
/// (`primary_label`) fused to a caret segment that toggles a menu of
/// `options`. Returns what was clicked; `open` holds the menu's
/// expanded state across frames.
fn render_split_button(
    ui: &mut egui::Ui,
    primary_label: &str,
    options: &[Editor],
    selected_id: &str,
    open: &mut bool,
) -> SplitAction {
    let th = Theme::of(ui.ctx());
    let r = th.btn_radius;
    let mut action = SplitAction::None;

    ui.horizontal(|ui| {
        // Fuse the two segments: no gap between them.
        ui.spacing_mut().item_spacing.x = 1.0;

        // Primary segment — left corners rounded, right corners square.
        let primary = egui::Button::new(
            egui::RichText::new(primary_label)
                .color(egui::Color32::WHITE)
                .strong()
                .size(12.5),
        )
        .fill(th.accent)
        .corner_radius(egui::CornerRadius {
            nw: r,
            sw: r,
            ne: 0,
            se: 0,
        })
        .min_size(egui::Vec2::new(0.0, 30.0));
        let p = ui.add(primary);
        if p.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if p.clicked() {
            action = SplitAction::Primary;
            *open = false;
        }

        // Caret segment — right corners rounded, left corners square.
        let caret = egui::Button::new(
            egui::RichText::new("\u{25be}")
                .color(egui::Color32::WHITE)
                .size(12.5),
        )
        .fill(th.accent)
        .corner_radius(egui::CornerRadius {
            nw: 0,
            sw: 0,
            ne: r,
            se: r,
        })
        .min_size(egui::Vec2::new(26.0, 30.0));
        let c = ui.add(caret);
        if c.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        let caret_rect = c.rect;
        if c.clicked() {
            *open = !*open;
        }

        if *open {
            let area = egui::Area::new(ui.id().with("editor-dropdown"))
                .order(egui::Order::Foreground)
                .fixed_pos(egui::pos2(p.rect.left(), c.rect.bottom() + 4.0))
                .show(ui.ctx(), |ui| {
                    let mut picked: Option<String> = None;
                    egui::Frame::new()
                        .fill(th.raised)
                        .stroke(egui::Stroke::new(1.0, th.rule))
                        .corner_radius(egui::CornerRadius::same(6))
                        .inner_margin(egui::Margin::same(4))
                        .show(ui, |ui| {
                            ui.set_min_width(180.0);
                            for editor in options {
                                let is_sel = editor.id == selected_id;
                                let label = if is_sel {
                                    egui::RichText::new(format!("{}  \u{2713}", editor.display))
                                        .color(th.fg)
                                        .strong()
                                } else {
                                    egui::RichText::new(&editor.display).color(th.fg)
                                };
                                let resp = ui.add(
                                    egui::Label::new(label)
                                        .sense(egui::Sense::click())
                                        .selectable(false),
                                );
                                if resp.hovered() {
                                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                                }
                                if resp.clicked() {
                                    picked = Some(editor.id.clone());
                                }
                            }
                        });
                    picked
                });

            let picked = area.inner;
            let menu_rect = area.response.rect;
            if let Some(id) = picked {
                action = SplitAction::Pick(id);
                *open = false;
            } else if ui.input(|i| i.pointer.any_click()) {
                // A click that landed outside both the menu and the caret
                // dismisses it (the caret's own click already toggled).
                let in_menu = ui
                    .ctx()
                    .pointer_interact_pos()
                    .is_some_and(|pos| menu_rect.contains(pos) || caret_rect.contains(pos));
                if !in_menu {
                    *open = false;
                }
            }
        }
    });

    action
}

/// Mutable UI state the rules page threads into its sub-renderers.
/// Bundled so the render fns stay under the argument-count lint while
/// each field still maps 1:1 onto a `ManagerWindowState` slot.
pub(crate) struct RulesUi<'a> {
    pub(crate) draft: &'a mut Option<RuleDraft>,
    pub(crate) dismissed: &'a mut HashSet<String>,
    pub(crate) suggestion_sort: &'a mut SuggestionSort,
    pub(crate) rule_sort: &'a mut RuleSort,
    pub(crate) scaffold: &'a mut ScaffoldPanel,
}

pub(crate) fn render_rules_page(
    ui: &mut egui::Ui,
    rule_rows: &[(&Rule, RuleUsage)],
    refusals: &crate::rules::RuleRefusals,
    suggestions: &[Suggestion],
    state: &mut RulesUi,
    actions_out: &mut Vec<RuleAction>,
) {
    if state.draft.is_some() {
        render_rule_form(ui, state.draft, actions_out);
        return;
    }
    render_rules_list(ui, rule_rows, refusals, suggestions, state, actions_out);
}

fn render_rules_list(
    ui: &mut egui::Ui,
    rule_rows: &[(&Rule, RuleUsage)],
    refusals: &crate::rules::RuleRefusals,
    suggestions: &[Suggestion],
    state: &mut RulesUi,
    actions_out: &mut Vec<RuleAction>,
) {
    let th = Theme::of(ui.ctx());
    let has_suggestions = !suggestions.is_empty();
    let has_rules = !rule_rows.is_empty();

    // The programmatic-rule path leads — it's the primary way to author
    // auto-approvals — so its scaffold card sits above the declarative
    // "+ New rule" affordance.
    render_scaffold_panel(ui, state.scaffold);
    ui.add_space(12.0);

    ui.horizontal(|ui| {
        if ui.button("+ New rule").clicked() {
            *state.draft = Some(RuleDraft::fresh());
        }
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "Or add a simple declarative rule. Rules fire before the \
                 consent prompt. Deny rules win; most-specific approve wins ties.",
            )
            .color(th.dim)
            .size(11.0),
        );
    });
    ui.add_space(12.0);

    if !has_suggestions && !has_rules {
        ui.vertical_centered(|ui| {
            ui.add_space(24.0);
            ui.label(
                egui::RichText::new("No rules yet.")
                    .size(16.0)
                    .strong()
                    .color(th.fg),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Scaffold a programmatic rule above, or add a declarative \
                     rule to auto-approve or auto-deny matching asks.",
                )
                .color(th.dim),
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
                            .color(th.dim),
                    );
                    // Sort toggle lives in the section header, mirroring
                    // the suggestions section's own toggle.
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.selectable_value(state.rule_sort, RuleSort::MostRecent, "Recent");
                        ui.selectable_value(state.rule_sort, RuleSort::MostUsed, "Most used");
                        ui.label(egui::RichText::new("Sort").size(11.0).color(th.faint));
                    });
                });
                ui.add_space(8.0);
                let now = now_unix();
                for (rule, usage) in rule_rows {
                    let badges = refusals.for_rule(&rule.id);
                    render_rules_row(ui, rule, &badges, *usage, now, state.draft, actions_out);
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
    let th = Theme::of(ui.ctx());
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("Suggested rules")
                .size(12.0)
                .strong()
                .color(th.dim),
        );
        // Sort toggle, right-aligned on the header row. In a
        // right-to-left layout the first-added widget sits rightmost,
        // so add "Recent" first to land the pair as [Most used][Recent].
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.selectable_value(sort, SuggestionSort::MostRecent, "Recent");
            ui.selectable_value(sort, SuggestionSort::MostUsed, "Most used");
            ui.label(egui::RichText::new("Sort").size(11.0).color(th.faint));
        });
    });
    ui.add_space(2.0);
    ui.label(
        egui::RichText::new(
            "Patterns we noticed in your recent decisions. Review one to seed a rule.",
        )
        .size(11.0)
        .color(th.faint),
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
    let th = Theme::of(ui.ctx());
    egui::Frame::new()
        .fill(th.well)
        .stroke(egui::Stroke::new(1.0, th.well_border))
        .inner_margin(egui::Margin::same(12))
        .corner_radius(egui::CornerRadius::same(th.well_radius))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (pill_fg, pill_text) = match s.decide {
                    SuggestionDecision::Approve => (th.ok, "approve"),
                    SuggestionDecision::Deny => (th.danger, "deny"),
                };
                let pill_bg = soft_fill(pill_fg);
                render_pill(ui, pill_text, pill_fg, pill_bg);
                ui.add_space(8.0);
                // Explicit th.fg: `.strong()` alone resolves through
                // `visuals.strong_text_color()` (a widget stroke we don't
                // override), which renders off-palette against the dark
                // card. The rule rows set the colour for the same reason.
                ui.label(
                    egui::RichText::new(format!("{} from {}", s.wrap, s.ancestor))
                        .strong()
                        .color(th.fg),
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
                    .color(th.dim)
                    .size(11.0),
            );
            ui.label(
                egui::RichText::new(format!(
                    "{count} {asks} in the last 30 days · last seen {recency}",
                    count = s.count,
                    asks = if s.count == 1 { "ask" } else { "asks" },
                    recency = recency_label(s.last_ts_unix, now_unix()),
                ))
                .color(th.faint)
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
pub(crate) struct RuleUsage {
    count: usize,
    last_ts_unix: Option<u64>,
}

/// One pass over the audit cache, bucketing fires by `rule_id`. Rules
/// that never fired simply won't appear in the map; the caller defaults
/// them to `RuleUsage::default()` (count 0, no last-fire).
pub(crate) fn rule_usage_index(entries: &[AuditEntry]) -> HashMap<String, RuleUsage> {
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
    pub(crate) fn sort(self, rows: &mut [(&Rule, RuleUsage)]) {
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
    refusals: &[(String, &str)],
    usage: RuleUsage,
    now_unix: u64,
    draft: &mut Option<RuleDraft>,
    actions_out: &mut Vec<RuleAction>,
) {
    let th = Theme::of(ui.ctx());
    egui::Frame::new()
        .fill(th.well)
        .stroke(egui::Stroke::new(1.0, th.well_border))
        .inner_margin(egui::Margin::same(12))
        .corner_radius(egui::CornerRadius::same(th.well_radius))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                // Enable toggle — emits SetEnabled the moment it
                // changes so the daemon mirrors the bit immediately.
                let mut enabled = rule.enabled;
                if ui.checkbox(&mut enabled, "").changed() {
                    actions_out.push(RuleAction::SetEnabled {
                        expected: rule.clone(),
                        enabled,
                    });
                }

                // Decide pill — green for approve, red for deny; a
                // wasm rule has no static side (its module returns the
                // decision per ask) so it gets a neutral "wasm" chip. A
                // disabled rule fades the pill to a neutral grey chip
                // so the live semantic colour is reserved for rules
                // that can actually fire.
                let (pill_fg, pill_text) = match &rule.body {
                    RuleBody::Declarative {
                        decide: StaticDecision::Approve,
                        ..
                    } => (th.ok, "approve"),
                    RuleBody::Declarative {
                        decide: StaticDecision::Deny { .. },
                        ..
                    } => (th.danger, "deny"),
                    RuleBody::Wasm(_) => (th.dim, "wasm"),
                };
                let pill_bg = soft_fill(pill_fg);
                if rule.enabled {
                    render_pill(ui, pill_text, pill_fg, pill_bg);
                } else {
                    render_pill(ui, pill_text, th.dim, th.raised);
                }

                // Finding A, since generalised: a rule that cannot fire
                // as written — a wasm module refused at load (sha256
                // mismatch, missing file, sandbox rejection), or a match
                // pattern that is not a valid glob — is badged loudly
                // instead of being left to pose as a healthy rule. The
                // hover carries the full reason (rules, files, hashes and
                // the operator's own pattern text; never a secret value).
                if !refusals.is_empty() {
                    ui.add_space(4.0);
                    render_pill(ui, "refused", th.danger, soft_fill(th.danger));
                    for (label, reason) in refusals {
                        ui.label(egui::RichText::new(label).size(10.5).color(th.danger))
                            .on_hover_text(*reason);
                    }
                }

                ui.add_space(8.0);
                let name_color = if rule.enabled { th.fg } else { th.dim };
                ui.label(egui::RichText::new(&rule.name).strong().color(name_color));
                if !rule.enabled {
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("disabled").size(10.5).color(th.faint));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Delete").clicked() {
                        actions_out.push(RuleAction::Delete {
                            expected: rule.clone(),
                        });
                    }
                    // The form edits declarative match clauses only;
                    // offering it for a wasm rule would let a Save
                    // silently rewrite the rule as declarative. Wasm
                    // rules are re-registered via the CLI instead.
                    if !rule.is_wasm() && ui.button("Edit").clicked() {
                        *draft = Some(RuleDraft::from_rule(rule));
                    }
                });
            });
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(rule_summary_line(rule))
                    .color(th.dim)
                    .size(11.0),
            );
            // Auto-fire history. A rule that's actually firing gets the
            // brighter muted tone to reward the user's trust in it; a
            // never-fired rule stays in the dim footnote register.
            let usage_color = if usage.count > 0 { th.dim } else { th.faint };
            ui.label(
                egui::RichText::new(rule_usage_line(usage, now_unix))
                    .color(usage_color)
                    .size(10.0),
            );
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "scope: {}",
                        wrap_scope_label(rule.wraps.as_ref())
                    ))
                    .color(th.faint)
                    .size(10.0),
                )
                .on_hover_text(
                    "Consultation scope is read-only in this editor. The evaluator \
                     skips the rule unless the ask's wrap is listed here; re-register \
                     a wasm rule or hand-edit auto-rules.toml to change it.",
                );
                if !rule.trained_secrets.is_empty() {
                    ui.add_space(8.0);
                    let trained = rule
                        .trained_secrets
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ");
                    ui.label(
                        egui::RichText::new(format!("trained: {trained}"))
                            .color(th.faint)
                            .size(10.0),
                    )
                    .on_hover_text(
                        "Declarative approvals require the ask's requested env-var set \
                         to be a subset of these names. Wasm rules run when at least one \
                         requested name overlaps, and can approve only overlapping names.",
                    );
                }
            });
        });
}

fn wrap_scope_label(wraps: Option<&std::collections::BTreeSet<String>>) -> String {
    wraps.map_or_else(
        || "all".to_owned(),
        |wraps| wraps.iter().cloned().collect::<Vec<_>>().join(", "),
    )
}

/// One-line summary of the rule's match clause for the list view.
/// Skips empty match fields; collapses to "wrap: gh" when nothing
/// else is constrained. A wasm rule summarizes as its module path.
fn rule_summary_line(rule: &Rule) -> String {
    let scope = format!("scope: {}", wrap_scope_label(rule.wraps.as_ref()));
    let m = match &rule.body {
        RuleBody::Wasm(wasm) => return format!("{scope} · wasm: '{}'", wasm.path),
        RuleBody::Declarative { r#match, .. } => r#match,
    };
    let mut parts = vec![scope, format!("match wrap: {}", m.wrap)];
    if let Some(p) = &m.argv {
        parts.push(format!("argv: '{}'", p.as_str()));
    }
    if let Some(p) = &m.ancestor {
        parts.push(format!("ancestor: '{}'", p.as_str()));
    }
    if let Some(p) = &m.cwd {
        parts.push(format!("cwd: '{}'", p.as_str()));
    }
    parts.join(" · ")
}

fn render_rule_form(
    ui: &mut egui::Ui,
    draft_slot: &mut Option<RuleDraft>,
    actions_out: &mut Vec<RuleAction>,
) {
    let th = Theme::of(ui.ctx());
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
                .color(th.fg),
        );
        ui.add_space(8.0);
        let (pill_fg, pill_text) = match draft.decide {
            RuleDecisionDraft::Approve => (th.ok, "approve"),
            RuleDecisionDraft::Deny => (th.danger, "deny"),
        };
        render_pill(ui, pill_text, pill_fg, soft_fill(pill_fg));
    });
    ui.add_space(10.0);

    // ── Split the available area: scrollable body on top, pinned
    //    action bar at the bottom. Both regions render top-down
    //    (default layout); we manually reserve the bottom strip
    //    rather than relying on `bottom_up`, which would reverse the
    //    intra-row order of labels and inputs.
    //
    // Re-validate every frame so Save's enabled state, the banner and
    // the per-field messages all reflect the current draft. The caret's
    // position is read from egui's memory rather than from the inputs'
    // responses because the body's rect depends on whether the banner
    // shows, so validation has to happen before the inputs are laid out.
    let problems = draft.problems(focused_pattern_field(ui.ctx()));
    let action_bar_h = if !problems.is_empty() {
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
                render_rule_form_body(ui, &mut draft, &problems);
            });
    });

    // Action bar (top-down). Separator at the top, optional
    // validation banner, then Save / Cancel buttons.
    ui.scope_builder(egui::UiBuilder::new().max_rect(action_rect), |ui| {
        let sep_rect = egui::Rect::from_min_size(
            ui.cursor().left_top(),
            egui::vec2(ui.available_width(), 1.0),
        );
        ui.painter().rect_filled(sep_rect, 0.0, th.rule);
        ui.add_space(10.0);
        if let Some(problem) = problems.first() {
            render_form_error_banner(ui, &problem.summary);
            ui.add_space(8.0);
        }
        ui.horizontal(|ui| {
            let save_enabled = problems.is_empty();
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
        let expected = draft.original.clone();
        if let Ok(rule) = draft.clone().into_rule() {
            if editing {
                actions_out.push(RuleAction::Update {
                    expected: expected.expect("editing draft has its original rule"),
                    replacement: Box::new(rule),
                });
            } else {
                actions_out.push(RuleAction::Add(rule));
            }
            return; // success → close form
        } else {
            // Defense-in-depth: render_primary_button's gating should
            // have suppressed the click, but if it didn't — a glob
            // withheld because the caret was still in it is exactly
            // that case — we refuse to ship the rule and drop the
            // exemption, so the next frame says why.
            draft.note_refused_save();
            *draft_slot = Some(draft);
            return;
        }
    }
    // Form still open; put the draft back.
    *draft_slot = Some(draft);
}

/// The stable [`egui::Id`] of one match-pattern input. Explicit rather
/// than derived from the widget's position, because
/// [`focused_pattern_field`] has to ask which input holds the caret
/// before any of them have been added to the frame.
fn pattern_field_id(field: PatternField) -> egui::Id {
    egui::Id::new(("rule-form-pattern", field.as_str()))
}

/// Which match-pattern input holds the keyboard caret, if any. Focus
/// lives in egui's memory and survives across frames, so this answers
/// for the current frame before the inputs are laid out.
fn focused_pattern_field(ctx: &egui::Context) -> Option<PatternField> {
    let focused = ctx.memory(egui::Memory::focused)?;
    [
        PatternField::Argv,
        PatternField::Ancestor,
        PatternField::Cwd,
    ]
    .into_iter()
    .find(|field| pattern_field_id(*field) == focused)
}

/// The message under a match-pattern input whose glob will not compile.
///
/// The banner at the foot of the form says a rule cannot be saved; this
/// says which pattern and what it would have cost, next to the text the
/// user would have to change. That is the moment the mistake is free to
/// fix — after a save it costs a trip through the Rules list and a
/// badge nobody is looking at.
fn render_pattern_problem(ui: &mut egui::Ui, problem: Option<&FormProblem>) {
    let Some(problem) = problem else { return };
    let th = Theme::of(ui.ctx());
    ui.add_space(4.0);
    let text = match &problem.detail {
        Some(detail) => format!("\u{26a0} {detail}"),
        None => format!("\u{26a0} {}", problem.summary),
    };
    ui.label(egui::RichText::new(text).color(th.danger).size(10.5));
}

/// The scrollable middle of the rule form. Renders three section
/// cards: Basics (name + decide), Match (wrap + patterns), Outcome
/// (enabled + deny_message + read-only scope/training chips). Kept as its own
/// function so the parent can compose it with a pinned action bar.
fn render_rule_form_body(ui: &mut egui::Ui, draft: &mut RuleDraft, problems: &[FormProblem]) {
    let th = Theme::of(ui.ctx());
    let problem_for = |field: PatternField| problems.iter().find(|p| p.field == Some(field));
    let scope_problem = problems
        .iter()
        .find(|problem| problem.summary.contains("outside wrap scope"));
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
                let response = ui.add(
                    egui::TextEdit::singleline(&mut draft.wrap)
                        .hint_text("e.g. gh")
                        .font(egui::FontId::monospace(12.5))
                        .desired_width(f32::INFINITY),
                );
                render_pattern_problem(ui, scope_problem);
                response
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
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut draft.argv)
                        .id(pattern_field_id(PatternField::Argv))
                        .hint_text("e.g. gh api --get /repos/*/pulls*")
                        .font(egui::FontId::monospace(12.5))
                        .desired_width(f32::INFINITY),
                );
                render_pattern_problem(ui, problem_for(PatternField::Argv));
                resp
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
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut draft.ancestor)
                        .id(pattern_field_id(PatternField::Ancestor))
                        .hint_text("e.g. Cursor.app")
                        .font(egui::FontId::monospace(12.5))
                        .desired_width(f32::INFINITY),
                );
                render_pattern_problem(ui, problem_for(PatternField::Ancestor));
                resp
            },
        );
        ui.add_space(8.0);
        render_form_field(
            ui,
            "Working directory",
            Some("Glob or literal-prefix, matched against the requesting cwd."),
            |ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut draft.cwd)
                        .id(pattern_field_id(PatternField::Cwd))
                        .hint_text("e.g. ~/work/myproject/**")
                        .font(egui::FontId::monospace(12.5))
                        .desired_width(f32::INFINITY),
                );
                render_pattern_problem(ui, problem_for(PatternField::Cwd));
                resp
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
                .color(if draft.enabled { th.fg } else { th.dim }),
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
        if let Some(wraps) = &draft.wraps {
            ui.add_space(10.0);
            ui.label(
                egui::RichText::new(format!(
                    "consultation scope: {}",
                    wrap_scope_label(Some(wraps))
                ))
                .color(th.faint)
                .size(10.0),
            )
            .on_hover_text(
                "Read-only in this declarative editor. The match Wrap above must be \
                 one of these names or the rule can never be consulted.",
            );
        }
    });
}

/// One framed section in the rule form. Title sits at the top in a
/// small footnote-tier label so it doesn't compete with field labels;
/// the body lays out vertically below.
fn render_form_section_card<F: FnOnce(&mut egui::Ui)>(ui: &mut egui::Ui, title: &str, body: F) {
    let th = Theme::of(ui.ctx());
    egui::Frame::new()
        .fill(th.well)
        .stroke(egui::Stroke::new(1.0, th.well_border))
        .corner_radius(egui::CornerRadius::same(th.well_radius))
        .inner_margin(egui::Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(title.to_uppercase())
                    .size(10.5)
                    .strong()
                    .color(th.faint)
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
    let th = Theme::of(ui.ctx());
    ui.label(egui::RichText::new(label).size(12.0).strong().color(th.fg));
    ui.add_space(3.0);
    let r = body(ui);
    if let Some(h) = helper {
        ui.add_space(3.0);
        ui.label(egui::RichText::new(h).color(th.faint).size(10.5));
    }
    r
}

/// Segmented two-option toggle for the rule's decide direction. The
/// active option is filled with its semantic-soft colour (`th.raised`
/// for approve, a soft `th.danger` tint for deny); the inactive option
/// is a muted chip. Clicking either switches the draft. Reads as "this
/// rule will approve / this rule will deny" without needing to parse
/// the bullet-radio convention.
fn render_decide_toggle(ui: &mut egui::Ui, decide: &mut RuleDecisionDraft) -> egui::Response {
    let th = Theme::of(ui.ctx());
    ui.horizontal(|ui| {
        let approve_resp = render_decide_segment(
            ui,
            "approve",
            *decide == RuleDecisionDraft::Approve,
            th.raised,
            th.accent,
        );
        if approve_resp.clicked() {
            *decide = RuleDecisionDraft::Approve;
        }
        ui.add_space(6.0);
        let deny_resp = render_decide_segment(
            ui,
            "deny",
            *decide == RuleDecisionDraft::Deny,
            soft_fill(th.danger),
            th.danger,
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
    let th = Theme::of(ui.ctx());
    let (fill, stroke_color, text_color) = if active {
        (active_fill, active_stroke, th.fg)
    } else {
        (th.raised, th.well_border, th.dim)
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
    let th = Theme::of(ui.ctx());
    egui::Frame::new()
        .fill(soft_fill(th.danger))
        .stroke(egui::Stroke::new(1.0, th.danger))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(12, 7))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("Can't save: {msg}"))
                    .color(th.fg)
                    .size(11.5),
            );
        });
}

/// Primary action button — accent-filled, white text. Disabled state
/// dims the fill and renders the text in th.dim. The caller is
/// responsible for ignoring `clicked()` when `enabled == false`; we
/// also use `interact` semantics so the click is "absorbed" visually
/// (no hover cursor) when disabled.
fn render_primary_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    let th = Theme::of(ui.ctx());
    let (fill, text_color) = if enabled {
        (th.accent, egui::Color32::WHITE)
    } else {
        (th.raised, th.dim)
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
    let th = Theme::of(ui.ctx());
    let btn = egui::Button::new(egui::RichText::new(label).color(th.fg).size(12.5))
        .fill(th.raised)
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
    let th = Theme::of(ui.ctx());
    let names = trained.iter().cloned().collect::<Vec<_>>().join(", ");
    egui::Frame::new()
        .fill(th.raised)
        .stroke(egui::Stroke::new(1.0, th.well_border))
        .corner_radius(egui::CornerRadius::same(5))
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("trained on")
                        .color(th.faint)
                        .size(10.5)
                        .strong()
                        .extra_letter_spacing(0.4),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(names)
                        .color(th.fg)
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
pub(crate) fn render_auto_deny_toast(ui: &mut egui::Ui, toast: &AutoDenyToastView) {
    let th = Theme::of(ui.ctx());
    egui::Frame::new()
        .fill(soft_fill(th.danger))
        .stroke(egui::Stroke::new(1.0, th.danger))
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
                ui.label(egui::RichText::new(msg).color(th.dim).size(11.0));
            }
        });
}

/// Soft translucent tint of a semantic status colour (`th.ok` /
/// `th.danger`), used as the fill behind text drawn in the
/// full-strength colour. Replaces the old hardcoded `COLOR_*_SOFT`
/// constants so the tint tracks the flavor's own status tokens in both
/// light and dark.
pub(crate) fn soft_fill(color: egui::Color32) -> egui::Color32 {
    color.gamma_multiply(0.18)
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

/// What the burst header's hover says. Its job is to answer the question a
/// collapsed row raises — "what did you just stop showing me" — and the answer
/// has to lead with the fact that nothing was lost, because the reader's
/// alternative is to distrust the whole view.
const AUDIT_BURST_HOVER: &str =
    "Requests that differ only in when they ran and which pids were involved.\n\
     Every one of them is still its own line in audit.log; only this view\n\
     groups them, so one flood can't bury the rest of your history.\n\
     Click to show each.";

/// One burst: a header stating what is being folded, then either the newest
/// member standing in for the run, or every member of it.
///
/// A run of one is not a burst and draws no header — the overwhelming majority
/// of the timeline, unchanged.
fn render_audit_burst(
    ui: &mut egui::Ui,
    burst: &AuditBurst<'_>,
    now: u64,
    expanded: &mut std::collections::HashSet<String>,
    rules_draft: &mut Option<RuleDraft>,
    view: &mut ManagerView,
) {
    if burst.rows.len() == 1 {
        render_audit_entry(ui, burst.lead, now, rules_draft, view);
        return;
    }

    let th = Theme::of(ui.ctx());
    let is_open = expanded.contains(&burst.key);
    if render_burst_header(ui, &th, burst, is_open) {
        if is_open {
            expanded.remove(&burst.key);
        } else {
            expanded.insert(burst.key.clone());
        }
    }
    ui.add_space(5.0);

    if !is_open {
        // The newest member, verbatim. Its footer already says how long ago
        // *it* was, and the header above says how far back the run reaches —
        // between them, "47 attempts over 3 seconds, the last one 2m ago".
        render_audit_entry(ui, burst.lead, now, rules_draft, view);
        return;
    }

    // Indented, so the eye can see where the group ends: expanded members are
    // otherwise indistinguishable from the ungrouped rows below them, and a
    // header that says "6" above an unbounded list is not an improvement.
    // egui draws its own left rule down an indent, which is the same hairline
    // vocabulary the row separators already use.
    //
    // Bodies only — the group's one "Create rule…" hangs off the bottom, since
    // every member would build the same draft.
    ui.indent(("audit-burst", burst.key.as_str()), |ui| {
        let mut first = true;
        for row in &burst.rows {
            if !first {
                audit_row_separator(ui, &th);
            }
            render_audit_row_body(ui, row, now);
            first = false;
        }
    });
    render_create_rule_affordance(ui, burst.lead, rules_draft, view);
}

/// The clickable line above a collapsed or expanded burst. Returns whether it
/// was clicked.
///
/// One label rather than a styled run of them, because it is a hit target
/// first: a reader who wants the individual rows should not have to find the
/// clickable third of a sentence. It borrows the weight and colour of
/// "Create rule from this ask…" — the audit view's existing "this does
/// something" signal — so the affordance needs no separate learning.
fn render_burst_header(
    ui: &mut egui::Ui,
    th: &Theme,
    burst: &AuditBurst<'_>,
    is_open: bool,
) -> bool {
    let glyph = if is_open { "\u{25be}" } else { "\u{25b8}" };
    let count = burst.rows.len();
    let span = burst_span_text(burst.span_secs);
    let mut clicked = false;
    ui.horizontal(|ui| {
        let resp = ui.add(
            egui::Label::new(
                egui::RichText::new(format!("{glyph} {count} identical requests \u{b7} {span}"))
                    .size(11.0)
                    .color(th.accent_text),
            )
            .sense(egui::Sense::click()),
        );
        clicked = resp.clicked();
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        resp.on_hover_text(AUDIT_BURST_HOVER);
    });
    clicked
}

/// How far back a burst reaches, in the timeline's own vocabulary (the row
/// footers say `3s ago`, so a span says `over 3s`).
///
/// The span is the half of the header that a bare count cannot carry:
/// 47 attempts over 3s is a script hammering the socket, 47 over 3h is
/// something running on a timer, and a reader reconstructing an incident
/// needs to tell them apart without expanding the group.
fn burst_span_text(span_secs: u64) -> String {
    if span_secs == 0 {
        // Not "over 0s". Every row landed inside the same second, and saying
        // so is both shorter and the more alarming reading.
        return "within a second".to_owned();
    }
    format!("over {}", humanize_duration(Duration::from_secs(span_secs)))
}

/// One audit entry as a flat, hairline-separated row (the separator is
/// the page loop's job). No card frame — the timeline reads as a list,
/// not a stack of boxes.
fn render_audit_entry(
    ui: &mut egui::Ui,
    entry: &AuditEntry,
    now: u64,
    rules_draft: &mut Option<RuleDraft>,
    view: &mut ManagerView,
) {
    render_audit_row_body(ui, entry, now);
    render_create_rule_affordance(ui, entry, rules_draft, view);
}

/// "Create rule from this ask…" — small affordance at the bottom of each row.
/// We deliberately don't make it a context-menu (would require right-click
/// discovery) or hover-only (would hide a not-obvious feature).
///
/// Its own function because an expanded burst draws **one** of these for the
/// whole group rather than one per member: every row in a burst has the same
/// wrap, argv, decision and caller chain, so [`RuleDraft::from_audit_entry`]
/// would build the identical draft from any of them. Six copies of a control
/// that does one thing is six chances to wonder which one you want.
fn render_create_rule_affordance(
    ui: &mut egui::Ui,
    entry: &AuditEntry,
    rules_draft: &mut Option<RuleDraft>,
    view: &mut ManagerView,
) {
    let th = Theme::of(ui.ctx());
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let resp = ui.add(
                egui::Label::new(
                    egui::RichText::new("Create rule from this ask…")
                        .color(th.accent_text)
                        .size(11.0),
                )
                .sense(egui::Sense::click()),
            );
            if resp.clicked() {
                *rules_draft = Some(RuleDraft::from_audit_entry(entry));
                *view = ManagerView::Rules;
            }
            if resp.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
        });
    });
}

/// Three-tier audit row body:
///
/// 1. **Command** (mono bold, measured-width truncation) on the left,
///    a stable right-aligned verdict column on the right — a small
///    colored dot + colored verb, no background fill. The optional
///    "remembered"/"auto"/"cached" tag is a *separate* accent pill so
///    it can never shove the verdict's dot.
/// 2. **Secret names** (never values) on their own wrapped line.
/// 3. **Provenance footer** — `from <caller> · N more · .../cwd · ago`,
///    all footnote-tier, with the full caller chain + cwd in a hover
///    tooltip.
fn render_audit_row_body(ui: &mut egui::Ui, entry: &AuditEntry, now: u64) {
    let th = Theme::of(ui.ctx());
    let wrap = if entry.wrap.is_empty() {
        "(?)"
    } else {
        entry.wrap.as_str()
    };
    let verdict = AuditVerdict::from_decision(entry.decision.as_str(), &th);

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
                .color(th.fg),
        );
        if shown != full {
            resp.on_hover_text(&full);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            render_verdict_indicator(ui, verdict);
            if let Some(tag) = verdict.tag {
                ui.add_space(4.0);
                paint_pill(ui, tag, th.accent_text, th.raised);
            }
        });
    });

    // ── Line 2: secret NAMES (never values) ──
    if !entry.secrets.is_empty() {
        ui.add_space(5.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            ui.label(egui::RichText::new("\u{25cf}").size(7.0).color(th.accent));
            for name in &entry.secrets {
                ui.label(
                    egui::RichText::new(name)
                        .font(egui::FontId::monospace(11.5))
                        .color(th.dim),
                );
            }
        });
    }

    // ── Denial explanation, when one was supplied ──
    if let Some(reason) = &entry.reason {
        ui.add_space(5.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 5.0;
            ui.label(
                egui::RichText::new("reason")
                    .size(10.5)
                    .strong()
                    .color(th.faint),
            );
            ui.label(egui::RichText::new(reason).size(11.5).color(th.dim));
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
        render_audit_caller_chain(ui, &entry.callers, entry.callers_truncated);
    }

    // ── Who named the scope, on a guest row ──
    //
    // The counterpart to the caller tree above, on the one kind of row that
    // structurally cannot have one. It sits where the tree would, because it
    // answers the same question as far as the host can answer it at all.
    if let Some(row) = scope_declarant_row(entry) {
        ui.add_space(6.0);
        render_scope_declarant_row(ui, &th, &row);
    }

    // ── What the guest said about itself, on a row that carries a claim ──
    //
    // Below the declarant for the reason the prompt puts `GUEST SAYS` below
    // `SCOPE`: the reading order is "here's what we know, and here's what
    // we've merely been told", never the reverse.
    if let Some(chain) = guest_chain_claim(entry) {
        ui.add_space(6.0);
        render_guest_chain_row(ui, &th, chain);
    }

    // ── The forwarding marker, on a sign row that needs one ──
    //
    // Below the tree because that is where the frame it names belongs and
    // cannot go: the forwarding `ssh` is the socket peer, which the walk
    // starts above.
    if let Some((text, hover)) = forwarded_sign_marker(entry) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add(egui::Label::new(
                egui::RichText::new(text).size(11.0).color(th.danger),
            ))
            .on_hover_text(hover);
        });
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
                    .color(th.faint),
            );
            cwd_resp.on_hover_text(&entry.cwd);
            ui.label(egui::RichText::new("\u{b7}").size(11.0).color(th.faint));
        }
        ui.label(
            egui::RichText::new(format!("{ago} ago"))
                .size(11.0)
                .color(th.faint),
        );
    });
}

/// What a scoped-agent row says about the process that named its scope.
///
/// Either the peer itself, or one of the two things the log can say instead —
/// which are different and must not be spelled the same way.
enum ScopeDeclarantRow<'a> {
    /// The kernel's answer. `name` is what the process called itself, `exe`
    /// what was actually loaded, and the row keeps them adjacent for the
    /// reason the prompt does: `secreq` beside `/tmp/.build-cache/postinstall`
    /// is a contradiction nobody has to go looking for.
    Peer(&'a crate::audit::AuditLocalPeer),
    /// Something is wrong or unknown, said out loud in `th.danger`.
    Caveat(&'static str, &'static str),
}

/// What (if anything) to draw about who named this row's scope, for each state
/// [`crate::audit::AuditEntry::declared_by`] can be in.
///
/// - **A peer** — drawn always, including the ordinary genuine case. A line
///   that appears only when secreq is suspicious is a line that teaches a
///   reader nothing about what normal looks like, and "normal" here is the
///   whole comparison: an installed `secreq` at the path you installed it to.
/// - **`Gone`** — the daemon looked and the process had exited. Said, because
///   a row that reads the same whether or not anything checked is the failure
///   this field exists to fix.
/// - **`NotRead`** — nothing looked, because the release never reached the
///   daemon. Silent: the row's own `deny+out-of-scope` / `approve+cached`
///   verdict already says so, and a second line repeating it would compete
///   with the two above for a reader's attention.
/// - **Absent on an `agent:` row** — the row predates the field. Marked, for
///   the same reason an unrecorded truncation answer is: silence here would
///   read as "there was nothing to say".
/// - **Any non-`agent:` row** — no scope was declared, so nothing named one.
fn scope_declarant_row(entry: &AuditEntry) -> Option<ScopeDeclarantRow<'_>> {
    if !entry.wrap.starts_with("agent:") {
        return None;
    }
    match &entry.declared_by {
        Some(crate::audit::ScopeDeclarant::Peer(peer)) => Some(ScopeDeclarantRow::Peer(peer)),
        Some(crate::audit::ScopeDeclarant::Gone) => Some(ScopeDeclarantRow::Caveat(
            "\u{26a0} secreq could not read the process that named this scope",
            "The process on the consent socket had already exited when the daemon\n\
             looked it up, so nothing here identifies who put this scope name on\n\
             the wire.",
        )),
        Some(crate::audit::ScopeDeclarant::NotRead) => None,
        None => Some(ScopeDeclarantRow::Caveat(
            "\u{26a0} the process that named this scope was not recorded",
            "This row was written before secreq recorded which local process put\n\
             a scope name on the consent socket, so the log cannot say whether\n\
             this request came from an agent you started.",
        )),
    }
}

/// Draw [`scope_declarant_row`]'s answer, in the audit tree's own idiom.
fn render_scope_declarant_row(ui: &mut egui::Ui, th: &Theme, row: &ScopeDeclarantRow<'_>) {
    match row {
        ScopeDeclarantRow::Caveat(text, hover) => {
            ui.horizontal(|ui| {
                ui.add(egui::Label::new(
                    egui::RichText::new(*text).size(11.0).color(th.danger),
                ))
                .on_hover_text(*hover);
            });
        }
        ScopeDeclarantRow::Peer(peer) => {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 5.0;
                ui.label(
                    egui::RichText::new("\u{b7}")
                        .font(egui::FontId::monospace(11.0))
                        .color(th.faint),
                );
                ui.label(egui::RichText::new("named by").size(10.0).color(th.faint));
                ui.label(
                    egui::RichText::new(&peer.name)
                        .font(egui::FontId::monospace(11.5))
                        .color(th.fg),
                );
                ui.label(
                    egui::RichText::new(format!("pid {}", peer.pid))
                        .size(10.0)
                        .color(th.faint),
                );
                let exe = peer
                    .exe
                    .as_deref()
                    .map_or_else(|| "executable unknown".to_owned(), abbreviate_home);
                let font = egui::FontId::monospace(11.0);
                let avail = (ui.available_width() - 4.0).max(40.0);
                let shown = truncate_to_width(ui, &exe, &font, avail);
                let resp = ui.label(egui::RichText::new(&shown).font(font).color(th.fg));
                if shown != exe {
                    resp.on_hover_text(&exe);
                }
            })
            .response
            .on_hover_text(&peer.command);
        }
    }
}

use super::prompt_ui::GUEST_CHAIN_CAVEAT;

const GUEST_CHAIN_CAVEAT_HOVER: &str =
    "The sandbox volunteered this chain about itself. No host process was\n\
     walked to produce it and nothing checked it — a guest that wanted to\n\
     claim a different ancestry would say exactly this. It is recorded\n\
     because it is useful when the guest is honest and interesting when it\n\
     is not, never because it is evidence.";

/// The chain a guest claimed about itself on this row, if it claimed one.
///
/// Unlike [`scope_declarant_row`] and [`forwarded_sign_marker`], this needs no
/// `wrap`-prefix gate and draws no caveat for absence, because absence here has
/// only ever meant one thing: **the guest volunteered nothing**. The field
/// arrived with the guest-chain wire field itself, so no row exists that could
/// have carried a claim and does not — there was no version in which a guest
/// could report a chain and the log would drop it.
///
/// What the rendering must never do is let the claim pass for the caller tree
/// above it. `callers` is what the host walked; this is what the guest said,
/// and a log that draws them the same way has laundered the second into the
/// first. Hence [`GUEST_CHAIN_CAVEAT`], on its own line, never truncated.
fn guest_chain_claim(entry: &AuditEntry) -> Option<&str> {
    entry.unverified_guest_chain.as_deref()
}

/// Draw the guest's claim, then the caveat under it.
///
/// The chain truncates to the row's width and keeps the full text on hover;
/// the caveat does not truncate and is not on the same line as anything that
/// does. A warning a long enough chain can push out of view is not a warning,
/// which is the same rule `prompt_ui` states for the prompt's copy.
fn render_guest_chain_row(ui: &mut egui::Ui, th: &Theme, chain: &str) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 5.0;
        ui.label(
            egui::RichText::new("\u{b7}")
                .font(egui::FontId::monospace(11.0))
                .color(th.faint),
        );
        // "guest says", not "from" or "named by": the neighbouring lines earn
        // those verbs by being kernel-sourced, and reusing one here would
        // imply a check that never happened.
        ui.label(egui::RichText::new("guest says").size(10.0).color(th.faint));
        let font = egui::FontId::monospace(11.5);
        let avail = (ui.available_width() - 4.0).max(40.0);
        let shown = truncate_to_width(ui, chain, &font, avail);
        let resp = ui.label(egui::RichText::new(&shown).font(font).color(th.dim));
        if shown != chain {
            resp.on_hover_text(chain);
        }
    });
    ui.horizontal(|ui| {
        ui.add(egui::Label::new(
            egui::RichText::new(GUEST_CHAIN_CAVEAT)
                .size(11.0)
                .color(th.danger),
        ))
        .on_hover_text(GUEST_CHAIN_CAVEAT_HOVER);
    });
}

/// What (if anything) to say about agent forwarding under a sign row's caller
/// tree, for each state [`crate::audit::AuditEntry::sign_anchor`] can be in.
///
/// The row is drawn only when there is something a reader would otherwise get
/// wrong, which is the same rule the chain-completeness markers follow:
///
/// - **A forwarded anchor** — the sign arrived through an agent handed to
///   another host, and the `ssh -A <host>` argv is the only place on the row
///   that names it. The tree above shows the local shell either way, so
///   without this line the two cases are one row.
/// - **An `ssh:` row with no anchor recorded** — written before the log kept
///   this, so it cannot say. Drawn rather than left silent, because silence
///   here reads as "local", which is the claim nothing checked.
/// - **A session anchor** — the ordinary local sign. Nothing to say; the tree
///   already draws that frame with its argv.
/// - **Any non-sign row** — there was no sign, so the field never applied.
///
/// The `ssh:` prefix is what separates the middle two from the last: it is how
/// the row says the field is applicable, exactly as `fingerprint` is absent on
/// a wrap row without meaning "no fingerprint was computed".
fn forwarded_sign_marker(entry: &AuditEntry) -> Option<(String, &'static str)> {
    if !entry.wrap.starts_with("ssh:") {
        return None;
    }
    match &entry.sign_anchor {
        Some(anchor) if anchor.forwarded() => {
            let via = caller_args(&anchor.name, anchor.command.as_deref().unwrap_or_default());
            let named = if via.is_empty() {
                format!("{} pid {}", anchor.name, anchor.pid)
            } else {
                format!("{} {via} · pid {}", anchor.name, anchor.pid)
            };
            Some((
                format!("\u{26a0} signed through a forwarded agent \u{b7} {named}"),
                "The agent was forwarded to another host, so the request to sign\n\
                 came through that SSH session rather than from this machine.\n\
                 The client is the socket peer, which the caller tree starts above.",
            ))
        }
        Some(_) => None,
        None => Some((
            "\u{26a0} agent forwarding not recorded".to_owned(),
            "This row was written before secreq recorded whether a sign arrived\n\
             through a forwarded agent, so the log cannot say whether the request\n\
             came from this machine or from a host at the other end of an SSH\n\
             session.",
        )),
    }
}

/// Normalized view of an audit decision string. Carries the verb, an
/// optional separate tag ("remembered"), and the indicator colour.
/// Computing this once keeps the renderer free of inline decision
/// matching and lets the tag ride on its own pill.
#[derive(Clone, Copy)]
struct AuditVerdict {
    label: &'static str,
    tag: Option<&'static str>,
    color: egui::Color32,
}

impl AuditVerdict {
    fn from_decision(decision: &str, th: &Theme) -> AuditVerdict {
        match decision {
            "deny" => AuditVerdict {
                label: "denied",
                tag: None,
                color: th.danger,
            },
            "approve" => AuditVerdict {
                label: "approved",
                tag: None,
                color: th.ok,
            },
            "approve+remember" => AuditVerdict {
                label: "approved",
                tag: Some("remembered"),
                color: th.ok,
            },
            // The daemon's approvals cache short-circuited the prompt
            // — distinguished from "approve" so the audit log shows
            // "the user wasn't asked" vs. "the user said yes."
            "approve+cached" => AuditVerdict {
                label: "approved",
                tag: Some("cached"),
                color: th.ok,
            },
            // An enabled auto-rule fired. Same colour as a hand-clicked
            // approve so the row scans the same at a glance; the "auto"
            // tag makes the provenance explicit on inspection.
            "approve+auto" => AuditVerdict {
                label: "approved",
                tag: Some("auto"),
                color: th.ok,
            },
            "deny+auto" => AuditVerdict {
                label: "denied",
                tag: Some("auto"),
                color: th.danger,
            },
            // A guest asked a scoped agent socket for a ref outside its
            // host-declared allowlist, so it was refused without a prompt.
            // Danger-tinted like any deny, but tagged so it reads as "the
            // user was never asked" — a run of these rows is what a sandbox
            // probing for undeclared refs looks like.
            "deny+out-of-scope" => AuditVerdict {
                label: "denied",
                tag: Some("out of scope"),
                color: th.danger,
            },
            // The requesting process exited before the user decided — not
            // an approve, not a deny. Rendered muted so it reads as a
            // non-event at a glance, distinct from a real verdict.
            "abandoned" => AuditVerdict {
                label: "abandoned",
                tag: None,
                color: th.faint,
            },
            // The three TTL grants. Each authorises a *window* of silent
            // operation rather than the one request in front of the user,
            // which makes them the most consequential rows in the log — so
            // they carry the same weight as an approve and a tag naming the
            // scope of what was granted.
            //
            // These fell through to the `_` arm until 2026-07-26 and rendered
            // as a faint "seen": a thirty-minute signing grant read as the
            // least eventful row on the page. The catch-all is deliberately
            // muted, which is right for a decision verb we do not know and
            // exactly wrong for the three we do.
            // The SSH and agent single-subject grants share a tag: the row
            // already names the wrap (`ssh:<key_id>` versus `agent:<scope>`),
            // so repeating the kind in the pill would only crowd it.
            "approve+ssh-session" | "approve+agent-session" => AuditVerdict {
                label: "approved",
                tag: Some("session"),
                color: th.ok,
            },
            // Distinct from `session` because it grants every configured key
            // for the window, not just the one that was asked for — the row's
            // wrap names one key, so without this the pill would understate
            // what was actually authorised.
            "approve+ssh-session-all" => AuditVerdict {
                label: "approved",
                tag: Some("session · all keys"),
                color: th.ok,
            },
            // Unknown decisions map to a static "seen" so `label`
            // stays `&'static` (no borrow of `decision`).
            _ => AuditVerdict {
                label: "seen",
                tag: None,
                color: th.faint,
            },
        }
    }
}

/// Verdict indicator: a small colored dot + the verb in the same
/// semantic colour, no background fill — the flat-row counterpart of
/// the old verdict pill. The tag is deliberately NOT drawn here — the
/// caller paints it as a separate accent pill, so the indicator keeps a
/// fixed shape and its dot never jitters between rows.
fn render_verdict_indicator(ui: &mut egui::Ui, v: AuditVerdict) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 5.0;
        ui.label(egui::RichText::new("\u{25cf}").size(7.0).color(v.color));
        ui.label(
            egui::RichText::new(v.label)
                .size(11.0)
                .strong()
                .color(v.color),
        );
    });
}

/// Truncate `text` to the widest prefix (plus an ellipsis) that fits
/// within `max_width`, measured against the *actual* galley width for
/// `font` rather than a char-count guess. Binary-searches the prefix
/// length so a 200-char argv collapses in a handful of layout calls.
fn truncate_to_width(ui: &egui::Ui, text: &str, font: &egui::FontId, max_width: f32) -> String {
    let th = Theme::of(ui.ctx());
    if max_width <= 1.0 {
        return String::new();
    }
    let measure = |s: &str| -> f32 {
        ui.ctx()
            .fonts_mut(|f| f.layout_no_wrap(s.to_owned(), font.clone(), th.fg).size().x)
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
        // `take` rather than `chars[..mid]`: `mid <= hi <= chars.len()` holds,
        // but only by reading the loop's invariant. `take` cannot go out of
        // range at all, so the bound is structural instead of argued.
        let candidate: String = chars.iter().take(mid).collect::<String>() + "\u{2026}";
        if measure(&candidate) <= max_width {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    if lo == 0 {
        return "\u{2026}".to_owned();
    }
    chars.iter().take(lo).collect::<String>() + "\u{2026}"
}

/// The arguments a process was invoked with, with `argv[0]` removed.
///
/// `Caller::command` is the whole joined argv, and its first token is
/// the program itself — the same thing every caller row already prints
/// as the process name. Rendering both gives `gh  gh repo list` and
/// `zsh  zsh`, where the repetition crowds out the part that actually
/// carries information: the arguments.
///
/// The leading token is dropped only when it names the same program the
/// row is labelled with, bare (`gh`) or as a path (`/usr/bin/node`).
/// When it does **not** match, the full command line is kept: a process
/// whose `argv[0]` disagrees with its executable — a login shell's
/// `-zsh`, a busybox-style symlink alias, something deliberately
/// masquerading — is precisely what a consent prompt must not hide.
/// That branch also covers the case this can't parse, an `argv[0]`
/// containing spaces, so an unsplittable path degrades to showing
/// everything rather than to a wrong split.
pub(crate) fn caller_args<'a>(name: &str, command: &'a str) -> &'a str {
    let (head, rest) = match command.split_once(' ') {
        Some((head, rest)) => (head, rest.trim_start()),
        None => (command, ""),
    };
    if head.rsplit('/').next().unwrap_or(head) == name {
        rest
    } else {
        command
    }
}

/// Depth the audit view's process tree draws before collapsing the rest into
/// a `… N more` row. Mirrored by `prompt_ui::CALLER_TREE_MAX_DEPTH`: the two
/// surfaces show the same chain, and a reader who learns the elision in one
/// should not meet a different rule in the other.
pub(crate) const AUDIT_TREE_MAX_DEPTH: usize = 6;

/// Per-level indent of that tree.
const AUDIT_TREE_INDENT_PX: f32 = 13.0;

/// Render an audit entry's caller chain as an indented process tree,
/// outermost-first (the way `pstree` prints). Each row carries the bare
/// process name, its pid, and — load-bearingly — the argv it was invoked
/// with when that adds information over the name (`make ci-deploy`,
/// `node ./scripts/import.js`). Depth is capped at [`AUDIT_TREE_MAX_DEPTH`]
/// so a pathological 16-deep wrapper stack can't dominate the card; the
/// overflow collapses to a single `… N more` row whose hover reveals the
/// rest. The command tail is width-truncated (tooltip on overflow) so a
/// long argv never pushes the card wider than the window.
///
/// `truncated` is [`crate::audit::AuditEntry::callers_truncated`], and it
/// decides whether a row goes **above** the outermost frame. Without it this
/// tree drew the frame the walk happened to stop on exactly like a real
/// origin — the same over-claim the consent prompt made until it started
/// rendering `… more above`. The audit view is where that claim is read back
/// long after nobody can go and check.
fn render_audit_caller_chain(ui: &mut egui::Ui, callers: &[AuditCaller], truncated: Option<bool>) {
    let th = Theme::of(ui.ctx());
    // Storage is nearest-first; reverse to outermost-first for display.
    let ordered: Vec<&AuditCaller> = callers.iter().rev().collect();
    let visible = ordered.len().min(AUDIT_TREE_MAX_DEPTH);
    let hidden = ordered.len().saturating_sub(visible);
    let mut depth = 0usize;
    if let Some((text, hover)) = unwalked_row_text(truncated) {
        audit_elision_row(ui, &th, depth, text, hover.to_owned());
        depth += 1;
    }
    for c in ordered.iter().take(visible) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 5.0;
            ui.add_space(depth as f32 * AUDIT_TREE_INDENT_PX);
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
                    .color(th.faint),
            );
            ui.label(
                egui::RichText::new(&c.name)
                    .font(egui::FontId::monospace(11.5))
                    .color(th.fg),
            );
            ui.label(
                egui::RichText::new(format!("pid {}", c.pid))
                    .size(10.0)
                    .color(th.faint),
            );
            let args = caller_args(&c.name, &c.command);
            if !args.is_empty() {
                let cmd_font = egui::FontId::monospace(11.0);
                let avail = (ui.available_width() - 4.0).max(40.0);
                let shown = truncate_to_width(ui, args, &cmd_font, avail);
                let resp = ui.label(egui::RichText::new(&shown).font(cmd_font).color(th.dim));
                if shown != args {
                    resp.on_hover_text(args);
                }
            }
        });
        depth += 1;
    }
    if hidden > 0 {
        let summary = ordered
            .iter()
            .skip(visible)
            .map(|c| {
                let args = caller_args(&c.name, &c.command);
                if args.is_empty() {
                    format!("{} (pid {})", c.name, c.pid)
                } else {
                    format!("{} (pid {})  {}", c.name, c.pid, args)
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        audit_elision_row(ui, &th, depth, &format!("{hidden} more"), summary);
    }
}

/// What (if anything) to draw above the outermost frame, for each of the
/// three states [`crate::audit::AuditEntry::callers_truncated`] can be in.
///
/// The two rows say different things and must not be spelled the same way:
///
/// - **`Some(true)`** — the walk stopped at its own ceiling. There *is*
///   ancestry above and secreq declined to read it. Uncounted, for the reason
///   the prompt's row is: the walk stopped precisely so it would not have to
///   find out how much.
/// - **`None`** — the row was written before the log recorded this at all.
///   "May be" is the whole difference: nothing here knows whether anything is
///   missing, and rendering that silence as a complete chain would be the
///   audit view asserting something no writer ever checked. It fades from a
///   user's log on its own as old rows age out.
/// - **`Some(false)`** — the walk reached the top. Nothing to say.
fn unwalked_row_text(truncated: Option<bool>) -> Option<(&'static str, &'static str)> {
    match truncated {
        Some(true) => Some((
            "more above",
            "secreq stops walking the process tree after 16 frames.\n\
             Whatever launched this is further up and was not read.",
        )),
        None => Some((
            "may be more above",
            "This row was written before secreq recorded whether its walk\n\
             reached the top of the ancestry, so the log cannot say whether\n\
             anything is missing above.",
        )),
        Some(false) => None,
    }
}

/// One `…` row of the audit tree: the tree's own indent and glyph, then faint
/// text with an explanatory hover.
///
/// Shared by both elisions, mirroring `prompt_ui::elision_row` on the other
/// surface. They stand in for different things — frames this row holds and
/// hides, versus frames nothing ever read — but they are the same *kind* of
/// statement, "the tree is not showing you everything, here", and a reader who
/// learns one should not have to learn a second visual language for the other.
fn audit_elision_row(ui: &mut egui::Ui, th: &Theme, depth: usize, text: &str, hover: String) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 5.0;
        ui.add_space(depth as f32 * AUDIT_TREE_INDENT_PX);
        let glyph = if depth == 0 {
            "\u{b7}"
        } else {
            "\u{2514}\u{2500}"
        };
        ui.label(
            egui::RichText::new(format!("{glyph} \u{2026} {text}"))
                .font(egui::FontId::monospace(10.0))
                .color(th.faint),
        )
        .on_hover_text(hover);
    });
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

pub(crate) fn format_audit_line(
    summary: &WrapHistorySummary,
    now: u64,
    th: &Theme,
) -> (String, egui::Color32) {
    if summary.is_empty() {
        return ("↳ first request from this caller".to_owned(), th.dim);
    }
    let last_ts = summary.last_ts_unix.unwrap_or(now);
    let ago_secs = now.saturating_sub(last_ts);
    let ago = humanize_duration(Duration::from_secs(ago_secs));
    // Color only the deny case — approve/approve+remember is the
    // expected path and shouldn't draw the eye.
    let (verb, color) = match summary.last_decision.as_deref() {
        Some("deny") | Some("deny+out-of-scope") => ("denied", th.danger),
        Some("approve") | Some("approve+remember") | Some("approve+cached") => ("approved", th.dim),
        _ => ("seen", th.dim),
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

// ── Formatting helpers ────────────────────────────────────────────────────

pub(crate) fn humanize_duration(d: Duration) -> String {
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

/// Render a path with the user's home directory collapsed to `~`.
///
/// The prompt's `IN` row shows a full absolute cwd, and its leading
/// `/Users/<you>/` is the same on every ask — it carries nothing the
/// reader needs while pushing the part that does (the project) toward
/// truncation. Shells, file dialogs and the OS's own prompts all
/// abbreviate the same way, so `~` reads as itself rather than as a
/// literal directory named `~`.
pub(crate) fn abbreviate_home(path: &str) -> String {
    let home = dirs::home_dir().map(|h| h.display().to_string());
    abbreviate_home_within(path, home.as_deref())
}

/// The pure half of [`abbreviate_home`], with `$HOME` injected so it can
/// be tested without touching the environment.
///
/// The boundary rule itself lives in [`crate::paths::under_home`] — shared
/// with the shell-rc and `ssh_config` block builders, which need the same
/// "only on a path separator" test with a different token. This adds the
/// display-only case that `under_home` deliberately omits: the home
/// directory *itself* renders as a bare `~`.
fn abbreviate_home_within(path: &str, home: Option<&str>) -> String {
    let Some(home) = home.map(|h| h.trim_end_matches('/')) else {
        return path.to_owned();
    };
    if home.is_empty() {
        return path.to_owned();
    }
    if path == home {
        return "~".to_owned();
    }
    crate::paths::under_home(std::path::Path::new(path), std::path::Path::new(home), "~")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditCaller;

    // ── every decision the daemon can record is rendered ─────────

    /// `from_decision`'s `_` arm exists so `label` can stay `&'static` for a
    /// verb this build does not know. It is not a place for verbs we *do*
    /// know to land: until 2026-07-26 the three TTL grants fell through it,
    /// so a thirty-minute signing grant — the row authorising a window of
    /// silent operation, and so the most consequential kind in the log —
    /// rendered as a faint `seen`, the least eventful thing on the page.
    ///
    /// The match below is **exhaustive on purpose**: adding a `Decision`
    /// variant fails to compile here until someone decides how it reads in
    /// the audit view. That is the whole point of the test — the previous gap
    /// was silent because nothing forced the question.
    #[test]
    fn every_decision_variant_renders_as_more_than_seen() {
        use crate::consent::Decision;

        let all = [
            Decision::Approve,
            Decision::ApproveRemember,
            Decision::ApproveCached,
            Decision::ApproveAuto,
            Decision::ApproveSshSession,
            Decision::ApproveSshSessionAll,
            Decision::ApproveAgentSession,
            Decision::Deny,
            Decision::DenyAuto,
            Decision::DenyOutOfScope,
            Decision::Abandoned,
        ];

        // Exhaustiveness guard: this match names every variant, so a new one
        // is a compile error here, not a silent `seen` in the UI.
        for d in all {
            match d {
                Decision::Approve
                | Decision::ApproveRemember
                | Decision::ApproveCached
                | Decision::ApproveAuto
                | Decision::ApproveSshSession
                | Decision::ApproveSshSessionAll
                | Decision::ApproveAgentSession
                | Decision::Deny
                | Decision::DenyAuto
                | Decision::DenyOutOfScope
                | Decision::Abandoned => {}
            }
        }

        let th = Theme::resolve(OsFlavor::current(), true);
        for d in all {
            let v = AuditVerdict::from_decision(d.as_str(), &th);
            assert_ne!(
                v.label,
                "seen",
                "`{}` falls through to the unknown-verb arm",
                d.as_str()
            );
        }
    }

    /// An approve and a deny must not read the same at a glance, and a TTL
    /// grant must read as an approve rather than as its own muted thing.
    #[test]
    fn a_session_grant_reads_as_an_approval() {
        let th = Theme::resolve(OsFlavor::current(), true);
        let plain = AuditVerdict::from_decision("approve", &th);
        for granted in [
            "approve+ssh-session",
            "approve+ssh-session-all",
            "approve+agent-session",
        ] {
            let v = AuditVerdict::from_decision(granted, &th);
            assert_eq!(v.label, plain.label, "{granted} should read as approved");
            assert_eq!(
                v.color, plain.color,
                "{granted} should carry approve's colour"
            );
            assert!(v.tag.is_some(), "{granted} must say what was granted");
        }
    }

    // ── the rule form's glob validation ──────────────────────────

    fn draft_with(decide: RuleDecisionDraft, argv: &str) -> RuleDraft {
        RuleDraft {
            name: "a rule".to_owned(),
            wrap: "gh".to_owned(),
            decide,
            argv: argv.to_owned(),
            ..RuleDraft::fresh()
        }
    }

    /// The gap this closes: the loader refuses a glob it cannot compile, and
    /// the form — the path a user actually authors rules on — took the same
    /// text without a word and handed back a rule that does nothing. Being
    /// told at the moment you can still fix it for free is the whole point of
    /// refusing at all.
    #[test]
    fn a_glob_the_loader_would_refuse_cannot_be_saved_from_the_form() {
        let draft = draft_with(RuleDecisionDraft::Deny, "gh api /repos/*/actions/secrets*[");
        let err = draft
            .clone()
            .into_rule()
            .expect_err("a rule the loader will refuse must not leave the form");
        assert!(err.contains("argv"), "{err}");
        assert!(err.contains("glob"), "{err}");
        assert!(!draft.problems(None).is_empty());
    }

    /// One compile check, not two. The form asking `glob` a different question
    /// than `rules::pattern_refusals` does is how a rule ends up rejected in
    /// one place and accepted in the other, which is worse than either
    /// answer on its own.
    #[test]
    fn the_form_and_the_loader_agree_on_which_patterns_are_broken() {
        for pattern in [
            "gh api /repos/*/pulls*",
            "gh repo delete",
            "",
            "gh api /repos/*/actions/secrets*[",
            "gh [a-",
            "**/[",
        ] {
            let loader_refuses = Pattern::parse(pattern).is_invalid();
            let form_refuses = draft_with(RuleDecisionDraft::Approve, pattern)
                .problems(None)
                .iter()
                .any(|p| p.field == Some(PatternField::Argv));
            assert_eq!(
                loader_refuses, form_refuses,
                "form and loader disagree about `{pattern}`"
            );
        }
    }

    /// Both directions are refused — a rule secreq cannot evaluate is not the
    /// rule its author meant to write either way — but they do not cost the
    /// same thing, and the form says which one you are holding. The sentence
    /// is `rules::refused_pattern_consequence`'s, so the form and the Rules
    /// tab badge cannot come to describe the damage differently.
    #[test]
    fn a_broken_deny_and_a_broken_approve_are_refused_for_different_reasons() {
        let broken = "gh api /repos/*/actions/secrets*[";
        let deny = draft_with(RuleDecisionDraft::Deny, broken).problems(None);
        let approve = draft_with(RuleDecisionDraft::Approve, broken).problems(None);
        let (deny_detail, approve_detail) = (
            deny[0]
                .detail
                .clone()
                .expect("a refused deny says what it costs"),
            approve[0]
                .detail
                .clone()
                .expect("a refused approve says what it costs"),
        );
        assert_ne!(deny_detail, approve_detail);
        assert!(
            deny_detail.contains(crate::rules::refused_pattern_consequence(
                RuleDecision::Deny
            )),
            "{deny_detail}"
        );
        assert!(
            approve_detail.contains(crate::rules::refused_pattern_consequence(
                RuleDecision::Approve
            )),
            "{approve_detail}"
        );
        // The banner line stays one clause; the consequence goes under the
        // field, where there is room for it.
        assert!(
            deny[0].summary.len() < deny_detail.len(),
            "{}",
            deny[0].summary
        );
    }

    /// `[` is a legal thing to have typed so far. Flagging it before the `]`
    /// arrives turns a form that validates into a form that nags, and a
    /// warning a user has learned to type through is not a warning.
    #[test]
    fn the_field_the_caret_is_in_is_not_flagged_mid_glob() {
        let draft = draft_with(RuleDecisionDraft::Deny, "gh api /repos/[");
        assert!(
            draft.problems(Some(PatternField::Argv)).is_empty(),
            "the field being typed into is left alone"
        );
        assert!(
            !draft.problems(Some(PatternField::Cwd)).is_empty(),
            "a different field's caret withholds nothing"
        );
        assert!(
            !draft.problems(None).is_empty(),
            "and neither does no caret"
        );
    }

    /// Withholding it while the caret sits there must not survive the user
    /// saying they are done. A Save that neither saves nor explains itself is
    /// the silence this change exists to remove.
    #[test]
    fn asking_to_save_stops_withholding_the_error() {
        let mut draft = draft_with(RuleDecisionDraft::Deny, "gh api /repos/[");
        assert!(draft.problems(Some(PatternField::Argv)).is_empty());
        draft.note_refused_save();
        assert!(
            !draft.problems(Some(PatternField::Argv)).is_empty(),
            "after a refused save the reason shows wherever the caret is"
        );
    }

    /// A rule with two typos has two things wrong with it, named in field
    /// order — the same per-clause accounting `rules::pattern_refusals` does,
    /// so fixing one does not hide the other.
    #[test]
    fn every_broken_pattern_field_is_named_separately() {
        let draft = RuleDraft {
            ancestor: "Cursor[".to_owned(),
            cwd: "~/work/[".to_owned(),
            ..draft_with(RuleDecisionDraft::Approve, "gh *[")
        };
        let fields: Vec<Option<PatternField>> =
            draft.problems(None).iter().map(|p| p.field).collect();
        assert_eq!(
            fields,
            vec![
                Some(PatternField::Argv),
                Some(PatternField::Ancestor),
                Some(PatternField::Cwd)
            ]
        );
    }

    /// The pre-existing refusals still come first: an unnamed rule is a
    /// blocker whatever its patterns look like.
    #[test]
    fn a_missing_name_still_blocks_the_save() {
        let draft = RuleDraft {
            name: String::new(),
            ..draft_with(RuleDecisionDraft::Approve, "gh api *")
        };
        let problems = draft.problems(None);
        assert_eq!(problems[0].field, None);
        assert!(
            problems[0].summary.contains("name"),
            "{}",
            problems[0].summary
        );
        assert!(draft_with(RuleDecisionDraft::Approve, "gh api *")
            .problems(None)
            .is_empty());
    }

    // ── the audit tree's completeness marker ─────────────────────

    /// Three states in, three answers out — and the one that matters is the
    /// middle one. A row with no recorded answer must not render like a row
    /// that recorded "the walk reached the top", or the audit view goes back
    /// to claiming an origin nothing verified.
    #[test]
    fn an_unrecorded_walk_renders_as_neither_of_the_other_two() {
        let clipped = unwalked_row_text(Some(true)).expect("a clipped walk says so");
        let unknown = unwalked_row_text(None).expect("an unrecorded walk says so too");
        assert_eq!(clipped.0, "more above");
        assert_eq!(unknown.0, "may be more above");
        assert_ne!(
            clipped.0, unknown.0,
            "'we did not look further' and 'nobody wrote down whether we did' are \
             different claims and must not share a row"
        );
        assert_ne!(clipped.1, unknown.1, "and must not share a hover either");
        assert!(
            unwalked_row_text(Some(false)).is_none(),
            "a walk that reached the top has nothing to add above the outermost frame"
        );
    }

    // ── the sign row's forwarding marker ─────────────────────────

    fn sign_row(anchor: Option<crate::audit::AuditSignAnchor>) -> AuditEntry {
        let mut entry = mk_audit(1000, "ssh:github", "zsh", "approve");
        entry.fingerprint = Some("SHA256:x".to_owned());
        entry.sign_anchor = anchor;
        entry
    }

    fn anchor(kind: crate::provenance::SignAnchorKind) -> crate::audit::AuditSignAnchor {
        crate::audit::AuditSignAnchor {
            kind,
            pid: 9200,
            name: "ssh".to_owned(),
            command: matches!(kind, crate::provenance::SignAnchorKind::ForwardedSsh)
                .then(|| "ssh -A build-box".to_owned()),
        }
    }

    /// A forwarded sign has to say so **and** name the host: `ssh -A
    /// build-box` is the only thing on the row that identifies who could have
    /// been asking, and that process is not in the caller tree.
    #[test]
    fn a_forwarded_sign_row_names_the_host_the_agent_went_to() {
        let (text, _) = forwarded_sign_marker(&sign_row(Some(anchor(
            crate::provenance::SignAnchorKind::ForwardedSsh,
        ))))
        .expect("a forwarded sign says so");
        assert!(text.contains("forwarded agent"), "{text}");
        assert!(text.contains("-A build-box"), "{text}");
        assert!(text.contains("9200"), "{text}");
    }

    /// The three states an `ssh:` row can be in, and the one that would be a
    /// lie. An old row recorded nothing, so it must not render like a row that
    /// recorded "this was local" — that is the whole reason the field is an
    /// `Option` rather than a `bool`.
    #[test]
    fn an_ssh_row_with_no_recorded_anchor_renders_as_unknown_not_as_local() {
        let unknown = forwarded_sign_marker(&sign_row(None)).expect("an old row says so");
        assert!(unknown.0.contains("not recorded"), "{}", unknown.0);

        let forwarded = forwarded_sign_marker(&sign_row(Some(anchor(
            crate::provenance::SignAnchorKind::ForwardedSsh,
        ))))
        .expect("forwarded");
        assert_ne!(
            unknown.0, forwarded.0,
            "'nobody wrote it down' and 'it was forwarded' are different claims"
        );
        assert_ne!(unknown.1, forwarded.1, "and must not share a hover either");

        assert!(
            forwarded_sign_marker(&sign_row(Some(anchor(
                crate::provenance::SignAnchorKind::Session
            ))))
            .is_none(),
            "an ordinary local sign has nothing to add"
        );
    }

    /// A wrap row never had a sign, so an absent anchor there is not a gap —
    /// the same way an absent `fingerprint` on a wrap row is not one.
    #[test]
    fn a_row_that_never_signed_anything_gets_no_marker() {
        assert!(forwarded_sign_marker(&mk_audit(1000, "gh", "zsh", "approve")).is_none());
        assert!(
            forwarded_sign_marker(&mk_audit(1000, "agent:brain-nx-t5", "zsh", "approve")).is_none()
        );
    }

    // ── the guest row's "named by" line ──────────────────────────

    fn agent_row(declared: Option<crate::audit::ScopeDeclarant>) -> AuditEntry {
        let mut entry = mk_audit(1000, "agent:brain-nx-t5", "zsh", "approve");
        entry.callers.clear();
        entry.declared_by = declared;
        entry
    }

    /// The peer is drawn on an ordinary genuine row too. A line that appears
    /// only when secreq is suspicious teaches a reader nothing about what
    /// normal looks like, and "normal" is the entire comparison.
    #[test]
    fn a_guest_row_names_the_process_that_put_its_scope_on_the_wire() {
        let peer = crate::audit::AuditLocalPeer {
            pid: 82702,
            name: "secreq".to_owned(),
            command: "secreq agent open brain-nx-t5".to_owned(),
            exe: Some("/tmp/.build-cache/postinstall".to_owned()),
        };
        let entry = agent_row(Some(crate::audit::ScopeDeclarant::Peer(peer)));
        let row = scope_declarant_row(&entry).expect("a recorded peer is drawn");
        let ScopeDeclarantRow::Peer(drawn) = row else {
            panic!("expected the peer itself");
        };
        assert_eq!(drawn.pid, 82702);
        assert_eq!(drawn.exe.as_deref(), Some("/tmp/.build-cache/postinstall"));
    }

    /// Three ways a guest row can decline to name a process, and only two of
    /// them are worth a line. "Nobody looked" is already said by the row's own
    /// `deny+out-of-scope` / `approve+cached` verdict; the other two are not
    /// said anywhere else, and must not be spelled the same way.
    #[test]
    fn an_unrecorded_declarant_reads_as_neither_gone_nor_silent() {
        let unrecorded_row = agent_row(None);
        let gone_row = agent_row(Some(crate::audit::ScopeDeclarant::Gone));
        let unrecorded = scope_declarant_row(&unrecorded_row).expect("an old row says so");
        let gone = scope_declarant_row(&gone_row).expect("an unreadable peer says so");
        let (
            ScopeDeclarantRow::Caveat(unrecorded_text, unrecorded_hover),
            ScopeDeclarantRow::Caveat(gone_text, gone_hover),
        ) = (unrecorded, gone)
        else {
            panic!("both are caveats");
        };
        assert_ne!(
            unrecorded_text, gone_text,
            "'nobody wrote it down' and 'we looked and it had exited' are \
             different claims and must not share a row"
        );
        assert_ne!(unrecorded_hover, gone_hover, "nor a hover");

        let not_read_row = agent_row(Some(crate::audit::ScopeDeclarant::NotRead));
        assert!(
            scope_declarant_row(&not_read_row).is_none(),
            "a release the daemon was never asked about says so with its verdict"
        );
    }

    /// The gap this closes: the claim was written, documented and asserted,
    /// and the audit view drew nothing. A guest's story visible on the prompt
    /// and invisible in the log is the log quietly disagreeing with the UI
    /// about what happened.
    #[test]
    fn a_guest_row_draws_the_chain_the_guest_claimed() {
        let mut entry = agent_row(Some(crate::audit::ScopeDeclarant::NotRead));
        entry.unverified_guest_chain = Some("node → pnpm → postinstall".to_owned());
        assert_eq!(guest_chain_claim(&entry), Some("node → pnpm → postinstall"));
    }

    /// The claim never renders bare. It is the one thing on an audit row the
    /// host did not establish, and a log that draws a claim and a fact the
    /// same way has turned itself into a forgery surface. The string is the
    /// prompt's own, imported rather than copied, so the two surfaces cannot
    /// drift into saying the same thing two ways.
    #[test]
    fn the_guest_chain_carries_the_same_caveat_the_prompt_does() {
        assert!(
            GUEST_CHAIN_CAVEAT.contains("NOT verifiable"),
            "{GUEST_CHAIN_CAVEAT}"
        );
        assert!(
            GUEST_CHAIN_CAVEAT.contains("guest-reported"),
            "{GUEST_CHAIN_CAVEAT}"
        );
    }

    /// Absence means the guest volunteered nothing, and has never meant
    /// anything else — so unlike an unrecorded `declared_by`, it draws no
    /// caveat of its own.
    #[test]
    fn a_guest_row_with_no_claim_draws_nothing() {
        assert!(guest_chain_claim(&agent_row(None)).is_none());
        assert!(guest_chain_claim(&mk_audit(1000, "gh", "zsh", "approve")).is_none());
    }

    /// A row that declared no scope has nothing to name.
    #[test]
    fn a_row_with_no_scope_gets_no_named_by_line() {
        assert!(scope_declarant_row(&mk_audit(1000, "gh", "zsh", "approve")).is_none());
        assert!(scope_declarant_row(&mk_audit(1000, "ssh:github", "zsh", "approve")).is_none());
    }

    // ── abbreviate_home ──────────────────────────────────────────

    #[test]
    fn a_home_prefix_collapses_to_a_tilde() {
        assert_eq!(
            abbreviate_home_within("/Users/dev/repos/acme", Some("/Users/dev")),
            "~/repos/acme"
        );
        // The home directory itself, with and without a trailing slash.
        assert_eq!(
            abbreviate_home_within("/Users/dev", Some("/Users/dev")),
            "~"
        );
        assert_eq!(
            abbreviate_home_within("/Users/dev/x", Some("/Users/dev/")),
            "~/x"
        );
    }

    #[test]
    fn a_partial_match_is_left_alone() {
        // `/Users/youthful` merely starts with `/Users/you`; collapsing on
        // a non-boundary would rewrite it to a path that does not exist.
        assert_eq!(
            abbreviate_home_within("/Users/youthful/x", Some("/Users/you")),
            "/Users/youthful/x"
        );
        // Nothing to collapse against.
        assert_eq!(
            abbreviate_home_within("/opt/build", Some("/Users/dev")),
            "/opt/build"
        );
        assert_eq!(abbreviate_home_within("/opt/build", None), "/opt/build");
        assert_eq!(abbreviate_home_within("/opt/build", Some("")), "/opt/build");
    }

    // ── caller_args ──────────────────────────────────────────────

    #[test]
    fn argv0_is_dropped_when_it_just_repeats_the_process_name() {
        // The row already prints the name, so `gh  gh repo list` spends
        // its most legible column re-stating what the name said.
        assert_eq!(caller_args("gh", "gh repo list"), "repo list");
        // Nothing but argv[0] means there are no arguments to show.
        assert_eq!(caller_args("zsh", "zsh"), "");
        assert_eq!(caller_args("Superset.app", "Superset.app"), "");
        // argv[0] as an absolute path still names the same program.
        assert_eq!(
            caller_args("node", "/usr/bin/node ./scripts/import.js"),
            "./scripts/import.js"
        );
    }

    #[test]
    fn a_mismatched_argv0_is_kept_in_full() {
        // A login shell announces itself as `-zsh`; that divergence is
        // information, so the row shows the command line as it really is.
        assert_eq!(caller_args("zsh", "-zsh"), "-zsh");
        // Same for a process whose argv[0] claims to be something else —
        // exactly what a consent prompt must not quietly swallow.
        assert_eq!(caller_args("curl", "systemd --user"), "systemd --user");
        // An argv[0] with spaces can't be split reliably, so we show all
        // of it rather than guess at a boundary.
        let spaced = "/Applications/My App.app/Contents/MacOS/My App --flag";
        assert_eq!(caller_args("My App", spaced), spaced);
    }

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
            command: None,
            callers: vec![AuditCaller {
                pid: 1,
                name: caller_name.to_owned(),
                command: caller_name.to_owned(),
                exe: None,
            }],
            callers_truncated: Some(false),
            secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
            decision: decision.to_owned(),
            deciding_device: None,
            reason: None,
            rule_id: None,
            approvers: Default::default(),
            fingerprint: None,
            sign_anchor: None,
            declared_by: None,
            unverified_guest_chain: None,
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
            exe: None,
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
    fn search_matches_and_rule_draft_keeps_a_denial_reason() {
        let mut e = audit_entry_for_search("gh", &["repo", "delete"], "zsh", &[], "deny");
        e.reason = Some("wrong repository".to_owned());
        assert!(audit_entry_matches(&e, "repository"));

        let draft = RuleDraft::from_audit_entry(&e);
        assert_eq!(draft.deny_message, "wrong repository");
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

    /// The gap this closes: the claim is written to the log and drawn on the
    /// row, and the search box could not reach it. A reviewer filtering the
    /// log by `postinstall` — the single most likely thing to type after
    /// reading a report — got back every row secreq walked itself and none of
    /// the rows where something *said* it was postinstall. Recorded, drawn,
    /// and unfindable is a worse place to leave a claim than never recording
    /// it.
    #[test]
    fn search_finds_a_process_the_guest_only_claimed() {
        let mut e = audit_entry_for_search("agent:brain-nx-t5", &[], "", &[], "approve");
        e.callers.clear();
        e.unverified_guest_chain = Some("node → pnpm → postinstall".to_owned());
        assert!(audit_entry_matches(&e, "postinstall"));
        assert!(audit_entry_matches(&e, "POSTINSTALL"));
        // AND across terms still holds: the claim is one more field, not a
        // bypass.
        assert!(audit_entry_matches(&e, "postinstall approve"));
        assert!(!audit_entry_matches(&e, "postinstall kubernetes"));
    }

    /// A guest picks this string, so searching it is searching attacker-chosen
    /// text — a claim of `gh` puts the row in the results for `gh`. That is
    /// tolerable for exactly one reason: the row that comes back draws the
    /// claim under `guest says` with [`GUEST_CHAIN_CAVEAT`]. The search
    /// therefore reads the claim through [`guest_chain_claim`], the accessor
    /// the row renders from, so a hit cannot exist that the view would not
    /// disclaim.
    #[test]
    fn a_claim_is_searchable_only_through_the_accessor_that_disclaims_it() {
        let mut e = audit_entry_for_search("agent:brain-nx-t5", &[], "", &[], "approve");
        e.callers.clear();
        e.unverified_guest_chain = Some("gh".to_owned());
        assert!(audit_entry_matches(&e, "gh"));
        assert!(
            guest_chain_claim(&e).is_some(),
            "a row findable by its claim is a row that draws the caveat"
        );
        // And a row with nothing to disclaim contributes no field, rather
        // than an empty one that every query would match.
        let quiet = audit_entry_for_search("gh", &["api"], "zsh", &[], "approve");
        assert!(guest_chain_claim(&quiet).is_none());
        assert!(!audit_entry_matches(&quiet, "postinstall"));
    }

    #[test]
    fn search_whitespace_only_query_matches_every_entry() {
        // `split_whitespace` yields no terms, so the all-terms-match
        // predicate is vacuously true — mirrors the empty-query case.
        let e = audit_entry_for_search("gh", &["api"], "zsh", &[], "approve");
        assert!(audit_entry_matches(&e, "   "));
    }

    // ── burst collapsing ─────────────────────────────────────────
    //
    // A guest can drive an unbounded run of near-identical asks. The *log*
    // keeps every one; the view folds a run into one row and a count. These
    // pin what "identical" and "a run" mean, because both are answers the
    // feature is wrong without.

    /// A day well clear of any bucket boundary, so a test that moves a
    /// timestamp by seconds never accidentally crosses into "Yesterday".
    const BURST_NOW: u64 = 1_700_000_000 + 12 * 3600;

    fn burst_row(ts: u64, pid: u32) -> AuditEntry {
        let mut e = audit_entry_for_search(
            "agent:brain-nx-t5",
            &[],
            "node",
            &["secret://op/Prod/aws/root_key"],
            "deny+out-of-scope",
        );
        e.ts_unix = ts;
        e.callers[0].pid = pid;
        e
    }

    fn groups_of(rows: &[AuditEntry]) -> Vec<usize> {
        let refs: Vec<&AuditEntry> = rows.iter().collect();
        group_audit_bursts(&refs, BURST_NOW)
            .iter()
            .map(|b| b.rows.len())
            .collect()
    }

    /// The case the whole feature exists for. A different pid and a different
    /// second are exactly what two occurrences of one request differ by, so an
    /// identity that read either would collapse nothing on the only input
    /// anyone is worried about.
    #[test]
    fn rows_differing_only_in_time_and_pid_are_one_burst() {
        let rows = [
            burst_row(BURST_NOW - 15, 90210),
            burst_row(BURST_NOW - 16, 90204),
            burst_row(BURST_NOW - 17, 90199),
        ];
        assert_eq!(groups_of(&rows), vec![3]);
    }

    /// The forensically important half. 47 refusals with one approval in the
    /// middle must never render as 47 uninterrupted refusals — a run is
    /// *adjacent*, and anything else in it ends the run.
    #[test]
    fn an_interleaved_row_breaks_the_run() {
        let mut odd = burst_row(BURST_NOW - 16, 90204);
        odd.decision = "approve".to_owned();
        let rows = [
            burst_row(BURST_NOW - 15, 90210),
            odd,
            burst_row(BURST_NOW - 17, 90199),
        ];
        assert_eq!(groups_of(&rows), vec![1, 1, 1]);
    }

    /// A group is drawn under one day header, so it cannot contain rows that
    /// belong under another — the header would be counting rows that are not
    /// beneath it.
    #[test]
    fn a_burst_never_straddles_a_day_bucket() {
        const DAY: u64 = 24 * 3600;
        let rows = [
            burst_row(BURST_NOW, 1),
            // Same request, one day earlier: "Today" and "Yesterday".
            burst_row(BURST_NOW - DAY, 2),
        ];
        assert_eq!(groups_of(&rows), vec![1, 1]);
    }

    /// **The invariant that keeps a burst from hiding a search hit.**
    ///
    /// `audit_entry_matches` reads a strict subset of the fields
    /// [`audit_row_identity`] reads, so two rows in one burst are
    /// search-equivalent and no query can match one without matching the
    /// others. This asserts that subset relation the only way a test can:
    /// change each searched field in turn and require the group to break.
    ///
    /// It fails the day someone teaches the search a new field and forgets
    /// the identity — which is the day a group starts hiding a hit.
    #[test]
    fn identity_reads_every_field_the_search_reads() {
        /// A named edit to one field the search reads.
        type FieldEdit = (&'static str, fn(&mut AuditEntry));
        let mutators: [FieldEdit; 7] = [
            ("wrap", |e| e.wrap = "agent:other".to_owned()),
            ("decision", |e| e.decision = "approve".to_owned()),
            ("args", |e| e.args.push("--force".to_owned())),
            ("caller name", |e| e.callers[0].name = "pnpm".to_owned()),
            ("caller command", |e| {
                e.callers[0].command = "node ./probe.js".to_owned();
            }),
            ("secrets", |e| {
                e.secrets[0] = "secret://op/Prod/gh/token".to_owned();
            }),
            ("guest chain", |e| {
                e.unverified_guest_chain = Some("node \u{2192} postinstall".to_owned());
            }),
        ];
        for (field, mutate) in mutators {
            let mut changed = burst_row(BURST_NOW - 16, 90204);
            mutate(&mut changed);
            let rows = [burst_row(BURST_NOW - 15, 90210), changed];
            assert_eq!(
                groups_of(&rows),
                vec![1, 1],
                "a difference in {field} is searchable, so it must break the burst"
            );
        }
    }

    /// The count is only half the header. Someone reconstructing an incident
    /// has to tell 47 attempts over three seconds from 47 over three hours
    /// without opening the group.
    #[test]
    fn a_burst_reports_the_span_it_covers() {
        let rows = [burst_row(BURST_NOW - 15, 1), burst_row(BURST_NOW - 20, 2)];
        let refs: Vec<&AuditEntry> = rows.iter().collect();
        let bursts = group_audit_bursts(&refs, BURST_NOW);
        assert_eq!(bursts[0].span_secs, 5);
        assert_eq!(burst_span_text(bursts[0].span_secs), "over 5s");

        // Same run, handed over oldest-first. The span is a fact about the
        // rows, not about which end of the list they arrived from — read off
        // the two ends it would have collapsed to zero here.
        let rows = [burst_row(BURST_NOW - 20, 2), burst_row(BURST_NOW - 15, 1)];
        let refs: Vec<&AuditEntry> = rows.iter().collect();
        assert_eq!(group_audit_bursts(&refs, BURST_NOW)[0].span_secs, 5);

        assert_eq!(burst_span_text(3 * 3600), "over 3h");
        // Not "over 0s": a run inside one second is the shape a probing loop
        // makes, and saying so reads as the event it is.
        assert_eq!(burst_span_text(0), "within a second");
    }

    /// The expansion key is built off the **oldest** member, so a burst that
    /// is still growing keeps the key it was opened under. Keying on the
    /// newest row would collapse the group under the reader every time the
    /// flood ticked.
    #[test]
    fn a_growing_burst_keeps_its_expansion_key() {
        let rows = [burst_row(BURST_NOW - 15, 1), burst_row(BURST_NOW - 20, 2)];
        let refs: Vec<&AuditEntry> = rows.iter().collect();
        let before = group_audit_bursts(&refs, BURST_NOW)[0].key.clone();

        let grown = [
            burst_row(BURST_NOW - 2, 3),
            rows[0].clone(),
            rows[1].clone(),
        ];
        let refs: Vec<&AuditEntry> = grown.iter().collect();
        let after = group_audit_bursts(&refs, BURST_NOW)[0].key.clone();
        assert_eq!(before, after);
        // And it is the key the harness / a caller reaches for by naming the
        // oldest row, so the public entry point can't drift from the private
        // one.
        assert_eq!(after, audit_burst_key(&rows[1]));
    }

    /// A run of one is not a burst: no header, no count, and the row renders
    /// exactly as it did before any of this existed.
    #[test]
    fn an_ordinary_timeline_groups_nothing() {
        let mut later = burst_row(BURST_NOW - 15, 1);
        later.wrap = "gh".to_owned();
        let rows = [later, burst_row(BURST_NOW - 30, 2)];
        assert_eq!(groups_of(&rows), vec![1, 1]);
    }

    /// A guest supplies its own claimed chain and the refs it asks for, so it
    /// writes part of the identity string. Length-prefixing is what stops it
    /// moving a field boundary to make two different rows fold together.
    #[test]
    fn a_guest_cannot_forge_a_field_boundary_in_the_identity() {
        let mut a = burst_row(BURST_NOW - 15, 1);
        a.secrets = vec!["ab".to_owned(), "c".to_owned()];
        let mut b = burst_row(BURST_NOW - 16, 2);
        b.secrets = vec!["a".to_owned(), "bc".to_owned()];
        assert_ne!(audit_row_identity(&a), audit_row_identity(&b));
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
            command: None,
            callers: vec![],
            callers_truncated: Some(false),
            secrets: vec![],
            decision: "approve+auto".to_owned(),
            deciding_device: None,
            reason: None,
            rule_id: rule_id.map(str::to_owned),
            approvers: Default::default(),
            fingerprint: None,
            sign_anchor: None,
            declared_by: None,
            unverified_guest_chain: None,
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
            wraps: None,
            trained_secrets: std::collections::BTreeSet::new(),
            created_at_unix: 0,
            body: RuleBody::Declarative {
                r#match: RuleMatch {
                    wrap: "gh".to_owned(),
                    argv: None,
                    ancestor: None,
                    cwd: None,
                },
                decide: RuleDecision::Approve.into(),
            },
        }
    }

    #[test]
    fn declarative_editor_preserves_a_hand_authored_wrap_scope() {
        let mut rule = rule_named("01", "scoped");
        rule.wraps = Some(["gh".to_owned()].into_iter().collect());

        let edited = RuleDraft::from_rule(&rule)
            .into_rule()
            .expect("unchanged draft saves");

        assert_eq!(edited.wraps, rule.wraps);
    }

    #[test]
    fn declarative_editor_refuses_a_match_outside_its_read_only_wrap_scope() {
        let mut rule = rule_named("01", "scoped");
        rule.wraps = Some(["gh".to_owned()].into_iter().collect());
        let mut draft = RuleDraft::from_rule(&rule);
        draft.wrap = "aws".to_owned();

        let problems = draft.problems(None);
        assert!(
            problems
                .iter()
                .any(|problem| problem.summary.contains("outside wrap scope [gh]")),
            "{problems:?}"
        );
        assert!(
            draft.into_rule().is_err(),
            "the form must not save a rule whose consultation gate and match can never intersect"
        );
    }

    #[test]
    fn rule_summary_names_consultation_scope_separately_from_match_wrap() {
        let mut rule = rule_named("01", "scoped");
        rule.wraps = Some(["gh".to_owned()].into_iter().collect());

        let summary = rule_summary_line(&rule);
        assert!(summary.contains("scope: gh"), "{summary}");
        assert!(summary.contains("match wrap: gh"), "{summary}");
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

    fn mk_audit(ts: u64, wrap: &str, caller: &str, decision: &str) -> AuditEntry {
        AuditEntry {
            ts_unix: ts,
            cwd: String::new(),
            wrap: wrap.to_owned(),
            args: vec![],
            command: None,
            callers: vec![AuditCaller {
                pid: 100,
                name: caller.to_owned(),
                command: caller.to_owned(),
                exe: None,
            }],
            callers_truncated: Some(false),
            secrets: vec![],
            decision: decision.to_owned(),
            deciding_device: None,
            reason: None,
            rule_id: None,
            approvers: Default::default(),
            fingerprint: None,
            sign_anchor: None,
            declared_by: None,
            unverified_guest_chain: None,
        }
    }

    #[test]
    fn summarize_returns_empty_when_no_match() {
        // Wrong wrap → no signal.
        let entries = vec![mk_audit(1000, "aws", "zsh", "approve")];
        let s = summarize_history(
            &entries,
            "gh",
            Some(CallerIdentity {
                name: "zsh",
                exe: None,
            }),
            2000,
        );
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
        let s = summarize_history(
            &entries,
            "gh",
            Some(CallerIdentity {
                name: "zsh",
                exe: None,
            }),
            2000,
        );
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
        let s = summarize_history(
            &entries,
            "gh",
            Some(CallerIdentity {
                name: "zsh",
                exe: None,
            }),
            now,
        );
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
        let s = summarize_history(
            &entries,
            "gh",
            Some(CallerIdentity {
                name: "zsh",
                exe: None,
            }),
            now,
        );
        assert_eq!(s.total_count, 3);
        assert_eq!(s.approve_count, 2);
        assert_eq!(s.deny_count, 1);
        // Latest entry wins for last_decision.
        assert_eq!(s.last_decision.as_deref(), Some("deny"));
    }

    #[test]
    fn format_audit_line_handles_empty_and_populated_summaries() {
        let now = 1_000_000;
        let th = Theme::resolve(OsFlavor::MacOs, true);
        let (empty_text, _) = format_audit_line(&WrapHistorySummary::default(), now, &th);
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
        let (text, _) = format_audit_line(&s, now, &th);
        assert!(text.contains("approved"), "{text:?}");
        assert!(text.contains("5 grants / 1 denies"), "{text:?}");

        let denied = WrapHistorySummary {
            last_decision: Some("deny".into()),
            last_ts_unix: Some(now - 60),
            ..Default::default()
        };
        let (text, color) = format_audit_line(&denied, now, &th);
        assert!(text.contains("denied"));
        assert_eq!(color, th.danger, "denied last must use the danger token");
    }

    /// The prompt's HISTORY row is the strongest "you have seen this and said
    /// yes" signal the UI offers, and it used to match on the caller's *name*
    /// — `comm`, which a process sets on itself. `cp /bin/sh /tmp/zsh`
    /// inherited the victim's entire approval record for the cost of a
    /// filename.
    #[test]
    fn history_does_not_match_an_impostor_with_the_same_name() {
        let mut entry = mk_audit(1_000, "gh", "zsh", "approve");
        entry.callers[0].exe = Some("/bin/zsh".to_owned());
        let entries = vec![entry];

        // The real shell: same name, same path → its own history.
        let real = CallerIdentity {
            name: "zsh",
            exe: Some("/bin/zsh"),
        };
        assert_eq!(
            summarize_history(&entries, "gh", Some(real), 2_000).total_count,
            1
        );

        // The impostor: same name, different binary → no history at all.
        let impostor = CallerIdentity {
            name: "zsh",
            exe: Some("/tmp/zsh"),
        };
        assert_eq!(
            summarize_history(&entries, "gh", Some(impostor), 2_000).total_count,
            0,
            "a process merely named `zsh` must not inherit the real shell's record"
        );
    }

    /// Rows written before `exe` existed carry none. Dropping them would
    /// blank the history on every existing install, so the name remains the
    /// fallback when either side lacks a path.
    #[test]
    fn history_falls_back_to_the_name_for_rows_without_an_exe() {
        let entries = vec![mk_audit(1_000, "gh", "zsh", "approve")];
        let want = CallerIdentity {
            name: "zsh",
            exe: Some("/bin/zsh"),
        };
        assert_eq!(
            summarize_history(&entries, "gh", Some(want), 2_000).total_count,
            1
        );
    }
}
