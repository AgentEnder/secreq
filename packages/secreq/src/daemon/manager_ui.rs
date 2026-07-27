//! The manager window: the persistent Rules + Audit surface.
//!
//! The two-window split ("Native Sentinel") gives the transient consent
//! prompt (`prompt_ui`) exactly one job — decide the current ask — and
//! moves everything browsable here: the saved auto-rules (with the
//! suggestion engine's proposals) and the audit timeline. The manager is
//! a normal, non-always-on-top window the user opens deliberately
//! (`secreq view`, the prompt's "Open Manager…" link) and closes
//! themselves; none of the prompt's auto-hide or kill-and-respawn raise
//! machinery ever touches it.
//!
//! Chrome is flavor-structural like the prompt's footer: a macOS title
//! row with a centered segmented control, a Windows selector bar with an
//! accent underline, a GNOME headerbar with a view switcher. All colors
//! come from [`super::theme::Theme`] tokens.

use eframe::egui;

use crate::recommendations::{self, Suggestion};
use crate::rules::{Rule, RuleRefusals};

use super::theme::{OsFlavor, Theme};
use super::ui::{
    now_unix, paint_search_glyph, render_audit_page, render_rules_page, rule_usage_index,
    AuditCache, RuleAction, RuleDraft, RuleSort, RuleUsage, RulesUi, ScaffoldPanel,
};

pub use super::proto::ManagerFocus;

/// Which page the manager is showing. The UI-side mirror of the wire's
/// [`ManagerFocus`]; kept separate so the wire type stays a pure
/// address while this one can grow UI-only states later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerView {
    Rules,
    Audit,
}

impl From<ManagerFocus> for ManagerView {
    fn from(f: ManagerFocus) -> Self {
        match f {
            ManagerFocus::Rules => ManagerView::Rules,
            ManagerFocus::Audit => ManagerView::Audit,
        }
    }
}

/// The manager window's default viewport size, in logical points. Wide
/// enough for the audit timeline's caller chains without truncating
/// every argv; used by `child.rs` and the screenshot harness.
pub const MANAGER_DEFAULT_SIZE: [f32; 2] = [900.0, 600.0];

/// Body inset inside the manager window, below the header.
const INSET_X: i8 = 20;
const INSET_Y: i8 = 14;

/// Everything the manager window remembers across frames. The browsing
/// counterpart of `prompt_ui::PromptWindowState`; all session-scoped —
/// a fresh manager process starts clean.
pub struct ManagerWindowState {
    pub(crate) view: ManagerView,
    /// `Some` while the rule create/edit form is open on the Rules view.
    pub(crate) rules_draft: Option<RuleDraft>,
    /// The "Write a programmatic rule" scaffold card's state (detected
    /// editors, persisted preference, what's been scaffolded this session).
    pub(crate) scaffold: ScaffoldPanel,
    /// Suggestion keys the user dismissed this session.
    pub(crate) dismissed_suggestions: std::collections::HashSet<String>,
    /// Ordering of the suggestion cards.
    pub(crate) suggestion_sort: crate::recommendations::SuggestionSort,
    /// Ordering of the saved-rule rows.
    pub(crate) rule_sort: RuleSort,
    /// Live query for the Audit view (the header search box binds here
    /// while the Audit view is active).
    pub(crate) audit_search: String,
    /// Set when Cmd/Ctrl+F fires; consumed by the header to focus the
    /// search input on the next widget pass.
    pub(crate) audit_search_focus_pending: bool,
    /// Burst keys the user has opened on the Audit view — the timeline folds
    /// a run of identical rows into one, and this is which of those folds are
    /// showing their members. See `super::ui::audit_burst_key`.
    ///
    /// Session-scoped like everything else here: a fresh manager opens with
    /// every burst collapsed. Nothing about the log on disk is stored, or
    /// changed, by any of it.
    pub(crate) expanded_bursts: std::collections::HashSet<String>,
    /// Live name filter for the Rules view (the same header search box
    /// binds here while the Rules view is active).
    pub(crate) rules_filter: String,
    /// Parsed view of `audit.log` — drives both the Audit timeline and
    /// the Rules view's suggestions / usage footnotes.
    pub(crate) audit: AuditCache,
    /// Rising-edge tracker for viewer mode: `secreq view` sets the
    /// daemon's `viewer_mode`, and the first snapshot that carries it
    /// lands the manager on the Audit view exactly once.
    last_viewer_mode: bool,
}

impl ManagerWindowState {
    pub fn new() -> ManagerWindowState {
        ManagerWindowState {
            view: ManagerView::Rules,
            rules_draft: None,
            scaffold: ScaffoldPanel::new(),
            dismissed_suggestions: std::collections::HashSet::new(),
            suggestion_sort: crate::recommendations::SuggestionSort::default(),
            rule_sort: RuleSort::default(),
            audit_search: String::new(),
            audit_search_focus_pending: false,
            expanded_bursts: std::collections::HashSet::new(),
            rules_filter: String::new(),
            audit: AuditCache::new(),
            last_viewer_mode: false,
        }
    }

    /// A state that opens on `focus`. Used when the daemon spawned this
    /// manager with an explicit `--view` (the prompt's "Open Manager…"
    /// or `secreq view`'s Audit target).
    pub fn with_initial_view(focus: ManagerFocus) -> ManagerWindowState {
        let mut s = ManagerWindowState::new();
        s.view = focus.into();
        // An explicit view is stronger than the viewer-mode rising
        // edge — don't let the first snapshot yank it to Audit.
        s.last_viewer_mode = true;
        s
    }

    /// Switch to the Rules view in list mode (clearing any open form).
    /// Harness entry point; also what the audit page's "Create rule…"
    /// affordance effectively does (with a draft installed).
    pub fn focus_rules_view(&mut self) {
        self.view = ManagerView::Rules;
        self.rules_draft = None;
    }

    /// Switch to the Audit view.
    pub fn focus_audit_view(&mut self) {
        self.view = ManagerView::Audit;
    }

    /// Pre-populate the Audit view's search query (harness support; the
    /// production path types into the header's `TextEdit`).
    pub fn set_audit_search(&mut self, query: &str) {
        self.audit_search.clear();
        self.audit_search.push_str(query);
    }

    /// Open the burst whose **oldest** row is `oldest`, the way clicking its
    /// header does. The production path toggles this from the Audit view;
    /// this is the entry point for a caller that already knows which run it
    /// means (the screenshot harness builds the rows itself).
    ///
    /// Takes the oldest member rather than any member because that is what
    /// keys a burst — see `super::ui::audit_burst_key` for why that end.
    pub fn expand_audit_burst(&mut self, oldest: &crate::audit::AuditEntry) {
        self.expanded_bursts
            .insert(super::ui::audit_burst_key(oldest));
    }

    /// Set how the Rules view orders its suggestion cards.
    pub fn set_suggestion_sort(&mut self, sort: crate::recommendations::SuggestionSort) {
        self.suggestion_sort = sort;
    }

    /// Set how the Rules view orders its saved-rule rows.
    pub fn set_rule_sort(&mut self, sort: RuleSort) {
        self.rule_sort = sort;
    }

    /// Switch to the Rules view and open a blank rule form. Equivalent
    /// to clicking "+ New rule" in the list view.
    pub fn open_new_rule_form(&mut self) {
        self.view = ManagerView::Rules;
        self.rules_draft = Some(RuleDraft::fresh());
    }

    /// Switch to the Rules view and open the edit form pre-filled from
    /// `rule`. Equivalent to clicking the per-row "Edit" button.
    pub fn open_edit_rule_form(&mut self, rule: &Rule) {
        self.view = ManagerView::Rules;
        self.rules_draft = Some(RuleDraft::from_rule(rule));
    }

    /// Seed the scaffold card's detected editors + persisted preference
    /// without probing the host. Harness entry point so the screenshot
    /// fixtures render a fixed editor set regardless of what's installed
    /// on the regenerating machine.
    pub fn seed_scaffold_editors(
        &mut self,
        editors: Vec<crate::rule_scaffold::Editor>,
        preferred: Option<String>,
    ) {
        self.scaffold.seed_for_test(editors, preferred);
    }

    /// Put the scaffold card into its post-scaffold state (the split-
    /// button appears, targeting `entry`). Harness entry point.
    pub fn mark_scaffolded(&mut self, entry: std::path::PathBuf) {
        self.scaffold.mark_scaffolded_for_test(entry);
    }

    /// Force the "Open in editor" split-button's dropdown open. Harness
    /// entry point for the expanded-menu fixture.
    pub fn open_scaffold_dropdown(&mut self) {
        self.scaffold.open_dropdown_for_test();
    }
}

impl Default for ManagerWindowState {
    fn default() -> Self {
        Self::new()
    }
}

/// Render one frame of the manager window: flavor chrome up top, then
/// the Rules or Audit page. Rule mutations the user makes land in
/// `rule_actions_out` for the child process to ship to the daemon.
pub fn render_manager_panel(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    rules: &[Rule],
    refusals: &RuleRefusals,
    viewer_mode: bool,
    state: &mut ManagerWindowState,
    rule_actions_out: &mut Vec<RuleAction>,
) {
    let th = Theme::of(ctx);
    state.audit.refresh_if_stale();

    // Rising-edge view switch for viewer mode (`secreq view` lands on
    // the Audit view once, then leaves the view alone).
    if viewer_mode && !state.last_viewer_mode {
        state.view = ManagerView::Audit;
    }
    state.last_viewer_mode = viewer_mode;

    // Cmd/Ctrl+F — jump to the Audit view and focus its search box.
    let find_pressed = ctx.input(|i| i.key_pressed(egui::Key::F) && i.modifiers.command);
    if find_pressed {
        state.view = ManagerView::Audit;
        state.audit_search_focus_pending = true;
    }

    ui.painter().rect_filled(ui.max_rect(), 0.0, th.panel);

    render_header(ui, &th, state);

    let body_inset = egui::Margin {
        left: INSET_X,
        right: INSET_X,
        top: INSET_Y,
        bottom: INSET_Y,
    };
    egui::Frame::new()
        .inner_margin(body_inset)
        .show(ui, |ui| match state.view {
            ManagerView::Rules => {
                render_rules_body(ui, rules, refusals, state, rule_actions_out);
            }
            ManagerView::Audit => render_audit_page(
                ctx,
                ui,
                &state.audit,
                &mut state.rules_draft,
                &mut state.view,
                &state.audit_search,
                &mut state.expanded_bursts,
            ),
        });
}

/// The Rules view body: recompute suggestions + per-rule usage from the
/// audit cache each frame (cheap — one linear pass over a capped cache),
/// apply the header's name filter, then hand off to the shared
/// `render_rules_page`.
fn render_rules_body(
    ui: &mut egui::Ui,
    rules: &[Rule],
    refusals: &RuleRefusals,
    state: &mut ManagerWindowState,
    rule_actions_out: &mut Vec<RuleAction>,
) {
    let now = now_unix();
    let all = recommendations::suggest(state.audit.entries(), rules, now);
    let mut visible: Vec<Suggestion> = all
        .into_iter()
        .filter(|s| !state.dismissed_suggestions.contains(&s.key))
        .collect();
    state.suggestion_sort.sort(&mut visible);

    let filter = state.rules_filter.trim().to_ascii_lowercase();
    let usage = rule_usage_index(state.audit.entries());
    let mut rule_rows: Vec<(&Rule, RuleUsage)> = rules
        .iter()
        .filter(|r| filter.is_empty() || r.name.to_ascii_lowercase().contains(&filter))
        .map(|r| (r, usage.get(&r.id).copied().unwrap_or_default()))
        .collect();
    state.rule_sort.sort(&mut rule_rows);

    let mut rules_ui = RulesUi {
        draft: &mut state.rules_draft,
        dismissed: &mut state.dismissed_suggestions,
        suggestion_sort: &mut state.suggestion_sort,
        rule_sort: &mut state.rule_sort,
        scaffold: &mut state.scaffold,
    };
    render_rules_page(
        ui,
        &rule_rows,
        refusals,
        &visible,
        &mut rules_ui,
        rule_actions_out,
    );
}

// ── Header chrome ────────────────────────────────────────────────────────

/// Height of the header band, per flavor. Windows carries two stacked
/// rows (title + selector bar), the others one.
fn header_height(flavor: OsFlavor) -> f32 {
    match flavor {
        OsFlavor::Windows => 58.0,
        OsFlavor::MacOs | OsFlavor::Gnome => 46.0,
    }
}

fn render_header(ui: &mut egui::Ui, th: &Theme, state: &mut ManagerWindowState) {
    let avail = ui.available_rect_before_wrap();
    let bar = egui::Rect::from_min_size(
        avail.min,
        egui::vec2(avail.width(), header_height(th.flavor)),
    );

    // Band fill: GNOME gets its headerbar tone; the others sit on the
    // panel surface.
    let band_fill = match th.flavor {
        OsFlavor::Gnome => th.headerbar,
        _ => th.panel,
    };
    ui.painter().rect_filled(bar, 0.0, band_fill);

    match th.flavor {
        OsFlavor::MacOs => render_header_macos(ui, th, bar, state),
        OsFlavor::Windows => render_header_windows(ui, th, bar, state),
        OsFlavor::Gnome => render_header_gnome(ui, th, bar, state),
    }

    // 1px hairline under the header, all flavors.
    ui.painter().hline(
        bar.x_range(),
        bar.bottom() - 0.5,
        egui::Stroke::new(1.0, th.rule),
    );
    ui.allocate_rect(bar, egui::Sense::hover());
}

/// macOS: centered segmented control on the title row, search box
/// right-aligned.
fn render_header_macos(
    ui: &mut egui::Ui,
    th: &Theme,
    bar: egui::Rect,
    state: &mut ManagerWindowState,
) {
    let seg_size = egui::vec2(200.0, 26.0);
    let seg_rect = egui::Rect::from_center_size(bar.center(), seg_size);
    render_segmented_control(ui, th, seg_rect, state, SegmentStyle::MacThumb);

    let search_size = egui::vec2(210.0, 26.0);
    let search_rect = egui::Rect::from_min_size(
        egui::pos2(
            bar.right() - search_size.x - f32::from(INSET_X),
            bar.center().y - search_size.y / 2.0,
        ),
        search_size,
    );
    render_header_search(ui, th, search_rect, state);
}

/// Windows: slim title row, then a selector bar of flat text buttons
/// whose active item carries a 3px accent underline; search right.
fn render_header_windows(
    ui: &mut egui::Ui,
    th: &Theme,
    bar: egui::Rect,
    state: &mut ManagerWindowState,
) {
    let title_pos = egui::pos2(bar.left() + f32::from(INSET_X), bar.top() + 6.0);
    ui.painter().text(
        title_pos,
        egui::Align2::LEFT_TOP,
        "secreq Manager",
        egui::FontId::proportional(11.0),
        th.dim,
    );

    let row_top = bar.top() + 24.0;
    let mut x = bar.left() + f32::from(INSET_X);
    for (label, view) in [("Rules", ManagerView::Rules), ("Audit", ManagerView::Audit)] {
        let active = state.view == view;
        let font = egui::FontId::proportional(th.body_size);
        let text_w = ui
            .fonts_mut(|f| f.layout_no_wrap(label.to_owned(), font.clone(), th.fg))
            .size()
            .x;
        let w = text_w + 8.0;
        let rect = egui::Rect::from_min_size(egui::pos2(x, row_top), egui::vec2(w, 28.0));
        let resp = ui.interact(rect, ui.id().with(("mgr-tab", label)), egui::Sense::click());
        // "Semibold" approximated by painting the label twice with a
        // half-pixel offset — egui's bundled family has no bold cut.
        let color = if active { th.fg } else { th.dim };
        let pos = egui::pos2(rect.left() + 4.0, rect.center().y);
        ui.painter()
            .text(pos, egui::Align2::LEFT_CENTER, label, font.clone(), color);
        if active {
            ui.painter().text(
                pos + egui::vec2(0.3, 0.0),
                egui::Align2::LEFT_CENTER,
                label,
                font.clone(),
                color,
            );
        }
        if active {
            let underline = egui::Rect::from_min_size(
                egui::pos2(rect.left() + 2.0, rect.bottom() - 4.0),
                egui::vec2(rect.width() - 4.0, 3.0),
            );
            ui.painter()
                .rect_filled(underline, egui::CornerRadius::same(2), th.accent);
        }
        if resp.clicked() {
            state.view = view;
        }
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        x += w + 14.0;
    }

    let search_size = egui::vec2(210.0, 26.0);
    let search_rect = egui::Rect::from_min_size(
        egui::pos2(
            bar.right() - search_size.x - f32::from(INSET_X),
            row_top + (28.0 - search_size.y) / 2.0,
        ),
        search_size,
    );
    render_header_search(ui, th, search_rect, state);
}

/// GNOME: headerbar band with a centered view switcher (button-tone
/// track, panel-tone active thumb) and the search on the right. No fake
/// close buttons — window decoration is the compositor's job.
fn render_header_gnome(
    ui: &mut egui::Ui,
    th: &Theme,
    bar: egui::Rect,
    state: &mut ManagerWindowState,
) {
    let seg_size = egui::vec2(220.0, 28.0);
    let seg_rect = egui::Rect::from_center_size(bar.center(), seg_size);
    render_segmented_control(ui, th, seg_rect, state, SegmentStyle::GnomeThumb);

    let search_size = egui::vec2(200.0, 26.0);
    let search_rect = egui::Rect::from_min_size(
        egui::pos2(
            bar.right() - search_size.x - f32::from(INSET_X),
            bar.center().y - search_size.y / 2.0,
        ),
        search_size,
    );
    render_header_search(ui, th, search_rect, state);
}

/// Track/thumb tones for the two segmented-control flavors.
enum SegmentStyle {
    /// macOS: `th.well` track, `th.btn` active thumb.
    MacThumb,
    /// GNOME: `th.btn` track, `th.panel` active thumb.
    GnomeThumb,
}

/// A two-segment Rules|Audit control painted into `rect`. Active
/// segment gets a raised thumb + `th.fg` text; inactive is `th.dim` on
/// the bare track.
fn render_segmented_control(
    ui: &mut egui::Ui,
    th: &Theme,
    rect: egui::Rect,
    state: &mut ManagerWindowState,
    style: SegmentStyle,
) {
    let (track, thumb) = match style {
        SegmentStyle::MacThumb => (th.well, th.btn),
        SegmentStyle::GnomeThumb => (th.btn, th.panel),
    };
    let radius = th.btn_radius;
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(radius + 1), track);
    ui.painter().rect_stroke(
        rect,
        egui::CornerRadius::same(radius + 1),
        egui::Stroke::new(1.0, th.well_border),
        egui::StrokeKind::Inside,
    );

    let inner = rect.shrink(2.0);
    let half_w = inner.width() / 2.0;
    for (i, (label, view)) in [("Rules", ManagerView::Rules), ("Audit", ManagerView::Audit)]
        .into_iter()
        .enumerate()
    {
        let seg = egui::Rect::from_min_size(
            egui::pos2(inner.left() + i as f32 * half_w, inner.top()),
            egui::vec2(half_w, inner.height()),
        );
        let active = state.view == view;
        let resp = ui.interact(seg, ui.id().with(("mgr-seg", label)), egui::Sense::click());
        if active {
            ui.painter()
                .rect_filled(seg, egui::CornerRadius::same(radius), thumb);
            ui.painter().rect_stroke(
                seg,
                egui::CornerRadius::same(radius),
                egui::Stroke::new(1.0, th.rule),
                egui::StrokeKind::Inside,
            );
        }
        let color = if active { th.fg } else { th.dim };
        ui.painter().text(
            seg.center(),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(th.body_size - 0.5),
            color,
        );
        if resp.clicked() {
            state.view = view;
        }
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
    }
}

/// The header search field: a rounded `th.well` box with a `th.rule`
/// border. Binds to the audit search on the Audit view and to the rule
/// name filter on the Rules view. Consumes the Cmd/Ctrl+F focus request.
fn render_header_search(
    ui: &mut egui::Ui,
    th: &Theme,
    rect: egui::Rect,
    state: &mut ManagerWindowState,
) {
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(th.btn_radius + 2), th.well);
    ui.painter().rect_stroke(
        rect,
        egui::CornerRadius::same(th.btn_radius + 2),
        egui::Stroke::new(1.0, th.rule),
        egui::StrokeKind::Inside,
    );

    let inner = egui::Rect::from_min_max(
        egui::pos2(rect.left() + 8.0, rect.top()),
        egui::pos2(rect.right() - 6.0, rect.bottom()),
    );
    let (hint, is_audit) = match state.view {
        ManagerView::Rules => ("Filter rules…", false),
        ManagerView::Audit => ("Search audit…", true),
    };
    ui.scope_builder(
        egui::UiBuilder::new()
            .max_rect(inner)
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
        |ui| {
            paint_search_glyph(ui, th.dim);
            ui.add_space(2.0);
            let query = if is_audit {
                &mut state.audit_search
            } else {
                &mut state.rules_filter
            };
            let resp = ui.add(
                egui::TextEdit::singleline(query)
                    .frame(egui::Frame::NONE)
                    .hint_text(hint)
                    .font(egui::FontId::proportional(th.body_size - 0.5))
                    .desired_width(ui.available_width()),
            );
            if is_audit && state.audit_search_focus_pending {
                resp.request_focus();
                state.audit_search_focus_pending = false;
            }
        },
    );
}
