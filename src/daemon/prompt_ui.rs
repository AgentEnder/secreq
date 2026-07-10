//! The consent prompt window: one ask at a time.
//!
//! Ported from the approved "Native Sentinel" drafts
//! (`dev-docs/design-drafts/consent-ui/`). The prompt is a Focus Stack:
//! it renders the oldest pending ask big, like an OS security prompt,
//! with the queue reduced to a "N more waiting" line. Rules and the
//! audit log live in the separate manager window (`manager_ui`).
//!
//! Layout skeleton (all flavors): header (icon + summary + command),
//! an inset "evidence well" (secrets, caller tree with argv, cwd,
//! history), then a decision row whose shape is the OS idiom —
//! right-aligned pair on macOS, equal-width footer strip on Windows
//! (affirmative first), full-width response row on GNOME. Buttons
//! carry their hotkey as an underlined mnemonic character.

use std::time::Duration;

use eframe::egui;

use crate::consent::Decision;

use super::proto::SecretAsk;
use super::state::{ApprovalScope, QueueRow, QueueSnapshot};
use super::theme::{OsFlavor, Theme};
use super::ui::{
    format_audit_line, humanize_duration, paint_app_icon, render_auto_deny_toast, AuditCache,
    AutoDenyToastView, PendingAction,
};

/// Which manager view the prompt asks the daemon to open. A wire type
/// (the child forwards it as `ClientMsg::OpenManager`), so it lives in
/// [`super::proto`]; re-exported here for the renderer's callers.
pub use super::proto::ManagerFocus;

/// Everything the prompt window remembers across frames. Deliberately
/// small: the prompt is a transient surface, not a browsing one.
pub struct PromptWindowState {
    pub(crate) audit: AuditCache,
    /// Set when the secrets list is expanded past its collapsed cap.
    secrets_expanded: bool,
    /// The ask the expansion applies to; reset when the ask changes.
    expanded_for: Option<super::proto::DedupeKey>,
}

impl PromptWindowState {
    pub fn new() -> Self {
        PromptWindowState {
            audit: AuditCache::new(),
            secrets_expanded: false,
            expanded_for: None,
        }
    }
}

impl Default for PromptWindowState {
    fn default() -> Self {
        Self::new()
    }
}

/// Signals the child process acts on after the frame.
#[derive(Debug, Default)]
pub struct PromptOutput {
    /// The user clicked "Open Manager"; the child forwards this to the
    /// daemon, which spawns/raises the manager window.
    pub open_manager: Option<ManagerFocus>,
}

/// Secrets lists longer than this collapse into provider groups with a
/// scroll cap; at or below it, each secret gets its own labelled line.
const SECRETS_INLINE_MAX: usize = 5;
/// Max height of the collapsed many-secrets grid before it scrolls.
const SECRETS_SCROLL_MAX_HEIGHT: f32 = 150.0;

const INSET_X: i8 = 18;
const INSET_Y: i8 = 16;

pub fn render_prompt_panel(
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    snapshot: &QueueSnapshot,
    auto_deny_toast: Option<&AutoDenyToastView>,
    state: &mut PromptWindowState,
    actions_out: &mut Vec<PendingAction>,
) -> PromptOutput {
    let th = Theme::of(ctx);
    let mut out = PromptOutput::default();
    state.audit.refresh_if_stale();

    ui.painter().rect_filled(ui.max_rect(), 0.0, th.panel);

    // Current ask: the oldest awaiting row; failing that, the oldest
    // resolving row (kept on screen so a provider's biometric prompt
    // has its provenance visible).
    let current = current_row(snapshot);

    // Reset the many-secrets expansion when the displayed ask changes.
    if state.expanded_for.as_ref() != current.map(|r| &r.key) {
        state.secrets_expanded = false;
        state.expanded_for = current.map(|r| r.key.clone());
    }

    // Keyboard: mnemonics + platform keys, active only while the
    // current ask is awaiting a decision. The prompt has no text
    // inputs, so bare letter keys are safe to claim.
    if let Some(row) = current {
        if row.status == super::proto::RowStatus::Awaiting {
            let scope = row_scope(row);
            ctx.input(|i| {
                if i.modifiers.is_none()
                    && (i.key_pressed(egui::Key::A) || i.key_pressed(egui::Key::Enter))
                {
                    actions_out.push(PendingAction {
                        key: row.key.clone(),
                        decision: approve_decision(row),
                        scope,
                    });
                } else if i.modifiers.is_none()
                    && (i.key_pressed(egui::Key::D) || i.key_pressed(egui::Key::Escape))
                {
                    actions_out.push(PendingAction {
                        key: row.key.clone(),
                        decision: Decision::Deny,
                        scope,
                    });
                }
            });
        }
    }

    let inset = egui::Margin {
        left: INSET_X,
        right: INSET_X,
        top: INSET_Y,
        bottom: 0,
    };

    // Reserve the footer band; the body gets the rest and scrolls if
    // an ask outgrows it (deep ancestries, big secret sets) so the
    // decision row can never be pushed off-window.
    let footer_height = match th.flavor {
        OsFlavor::MacOs => 54.0,
        OsFlavor::Windows => 84.0,
        OsFlavor::Gnome => 70.0,
    };
    let body_height = (ui.available_height() - footer_height).max(0.0);
    let body_width = ui.available_width();

    ui.allocate_ui(egui::vec2(body_width, body_height), |ui| {
        ui.set_min_height(body_height);
        egui::ScrollArea::vertical()
            .id_salt("prompt-body")
            .max_height(body_height)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Frame::new().inner_margin(inset).show(ui, |ui| {
                    if let Some(toast) = auto_deny_toast {
                        render_auto_deny_toast(ui, toast);
                        ui.add_space(10.0);
                    }
                    match current {
                        None => render_empty_state(ui, &th, &mut out),
                        Some(row) => {
                            render_header(ui, &th, row);
                            ui.add_space(12.0);
                            render_evidence_well(ui, &th, row, state);
                            if row.representative.ssh.is_some()
                                && row.status == super::proto::RowStatus::Awaiting
                            {
                                ui.add_space(8.0);
                                render_ssh_session_grants(ui, &th, row, actions_out);
                            }
                        }
                    }
                });
            });
    });

    if current.is_some() || snapshot.entries.is_empty() {
        render_footer(ui, &th, current, snapshot, state, actions_out, &mut out);
    }

    out
}

/// Oldest awaiting row, else oldest resolving row.
fn current_row(snapshot: &QueueSnapshot) -> Option<&QueueRow> {
    snapshot
        .entries
        .iter()
        .filter(|r| r.status == super::proto::RowStatus::Awaiting)
        .min_by_key(|r| r.first_seen)
        .or_else(|| snapshot.entries.iter().min_by_key(|r| r.first_seen))
}

/// Approval scope for the current ask: its direct parent, which is what
/// the dedupe key already names. A remembered approval written there
/// covers subsequent asks from the same parent process.
fn row_scope(row: &QueueRow) -> ApprovalScope {
    ApprovalScope {
        pid: row.key.ppid,
        start_time: row.key.parent_start_time,
    }
}

/// What "Approve" means for this ask. SSH signs approve once; wrap asks
/// remember at the parent scope when the ask allows it (`secreq run`
/// forbids remembering — its fixed identity would over-match).
fn approve_decision(row: &QueueRow) -> Decision {
    if row.representative.ssh.is_some() {
        Decision::Approve
    } else if row.representative.allow_remember {
        Decision::ApproveRemember
    } else {
        Decision::Approve
    }
}

// ── Header ───────────────────────────────────────────────────────────────

fn render_header(ui: &mut egui::Ui, th: &Theme, row: &QueueRow) {
    let ask = &row.representative;
    ui.horizontal_top(|ui| {
        paint_app_icon(ui, 30.0);
        ui.add_space(10.0);
        ui.vertical(|ui| {
            ui.add(egui::Label::new(title_job(ui, th, row)).wrap());
            ui.add_space(2.0);
            let cmdline = ask.command.join(" ");
            let sub = if let Some(ssh) = &ask.ssh {
                ssh.reason.clone().unwrap_or_else(|| cmdline.clone())
            } else {
                cmdline.clone()
            };
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&sub)
                        .monospace()
                        .size(th.body_size - 1.0)
                        .color(th.dim),
                )
                .truncate(),
            );
        });
    });
}

/// "`gh` wants to use `GITHUB_TOKEN`" with the code spans in monospace.
fn title_job(ui: &egui::Ui, th: &Theme, row: &QueueRow) -> egui::text::LayoutJob {
    let ask = &row.representative;
    let mut job = egui::text::LayoutJob::default();
    let prop = egui::TextFormat {
        font_id: egui::FontId::proportional(th.body_size + 2.0),
        color: th.fg,
        line_height: Some(th.body_size + 8.0),
        ..Default::default()
    };
    let code = egui::TextFormat {
        font_id: egui::FontId::monospace(th.body_size + 1.0),
        color: th.fg,
        line_height: Some(th.body_size + 8.0),
        ..Default::default()
    };
    let _ = ui;
    if let Some(ssh) = &ask.ssh {
        let requester = ask
            .callers
            .first()
            .map(|c| c.name.as_str())
            .unwrap_or("ssh");
        job.append(requester, 0.0, code.clone());
        job.append(" wants to sign with ", 0.0, prop);
        job.append(&ssh.key_id, 0.0, code);
    } else {
        job.append(&row.key.wrap, 0.0, code.clone());
        if ask.secrets.len() == 1 {
            job.append(" wants to use ", 0.0, prop);
            job.append(&ask.secrets[0].name, 0.0, code);
        } else {
            job.append(" wants to use ", 0.0, prop);
            job.append(&format!("{} secrets", ask.secrets.len()), 0.0, code);
        }
    }
    job
}

// ── Evidence well ────────────────────────────────────────────────────────

fn well_frame(th: &Theme) -> egui::Frame {
    egui::Frame::new()
        .fill(th.well)
        .stroke(egui::Stroke::new(1.0, th.well_border))
        .corner_radius(th.well_radius)
        .inner_margin(egui::Margin::symmetric(12, 4))
}

fn render_evidence_well(
    ui: &mut egui::Ui,
    th: &Theme,
    row: &QueueRow,
    state: &mut PromptWindowState,
) {
    let ask = &row.representative;
    well_frame(th).show(ui, |ui| {
        ui.set_width(ui.available_width());
        if let Some(ssh) = &ask.ssh {
            well_row(ui, th, "SIGN WITH", |ui, th| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&ssh.fingerprint)
                            .monospace()
                            .size(th.body_size - 1.0)
                            .color(th.fg),
                    )
                    .truncate(),
                );
            });
            well_separator(ui, th);
        } else {
            well_row(ui, th, &secrets_label(ask.secrets.len()), |ui, th| {
                render_secrets(ui, th, &ask.secrets, state);
            });
            well_separator(ui, th);
        }

        well_row(ui, th, "ASKED BY", |ui, th| {
            render_caller_tree(ui, th, row);
        });
        well_separator(ui, th);

        well_row(ui, th, "IN", |ui, th| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&ask.cwd)
                        .monospace()
                        .size(th.body_size - 1.0)
                        .color(th.fg),
                )
                .truncate(),
            );
        });
        well_separator(ui, th);

        well_row(ui, th, "HISTORY", |ui, th| {
            let caller_name = ask.callers.first().map(|c| c.name.as_str());
            let summary = state.audit.summarize(&row.key.wrap, caller_name);
            let (line, color) = format_audit_line(&summary, super::ui::now_unix(), th);
            // The prompt's well already sets context; drop the audit
            // line's "↳ " prefix, which belongs to the old card layout.
            let line = line.trim_start_matches("↳ ").to_owned();
            ui.label(
                egui::RichText::new(line)
                    .size(th.body_size - 1.0)
                    .color(color),
            );
        });
    });
}

fn secrets_label(n: usize) -> String {
    if n == 1 {
        "SECRET".to_owned()
    } else {
        format!("SECRETS · {n}")
    }
}

fn well_row(ui: &mut egui::Ui, th: &Theme, label: &str, body: impl FnOnce(&mut egui::Ui, &Theme)) {
    ui.add_space(8.0);
    ui.label(
        egui::RichText::new(label)
            .size(th.body_size - 3.0)
            .strong()
            .color(th.faint),
    );
    ui.add_space(2.0);
    body(ui, th);
    ui.add_space(8.0);
}

fn well_separator(ui: &mut egui::Ui, th: &Theme) {
    let rect = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 1.0));
    ui.painter().hline(
        rect.x_range(),
        rect.top(),
        egui::Stroke::new(1.0, th.well_border),
    );
    ui.add_space(1.0);
}

/// Secrets: one labelled line each up to [`SECRETS_INLINE_MAX`]; past
/// that, grouped by locator prefix in a scroll-capped wrapped grid —
/// the `secreq run` 40-vars case.
fn render_secrets(
    ui: &mut egui::Ui,
    th: &Theme,
    secrets: &[SecretAsk],
    state: &mut PromptWindowState,
) {
    if secrets.len() <= SECRETS_INLINE_MAX {
        for s in secrets {
            ui.horizontal(|ui| {
                secret_name_label(ui, th, s);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&s.locator)
                            .monospace()
                            .size(th.body_size - 2.0)
                            .color(th.dim),
                    )
                    .truncate(),
                );
            });
        }
        return;
    }

    // Group by the locator's directory prefix. Largest group first —
    // the bulk grant is what the user is really deciding on — with the
    // prefix as a deterministic tiebreak.
    let mut group_map: std::collections::BTreeMap<String, Vec<&SecretAsk>> =
        std::collections::BTreeMap::new();
    for s in secrets {
        let prefix = match s.locator.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/*"),
            None => s.provider.clone(),
        };
        group_map.entry(prefix).or_default().push(s);
    }
    let mut groups: Vec<(String, Vec<&SecretAsk>)> = group_map.into_iter().collect();
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));

    let render_groups = |ui: &mut egui::Ui| {
        for (prefix, members) in &groups {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(prefix)
                        .monospace()
                        .size(th.body_size - 2.0)
                        .color(th.dim),
                );
                ui.label(
                    egui::RichText::new(members.len().to_string())
                        .size(th.body_size - 2.0)
                        .color(th.faint),
                );
            });
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(10.0, 2.0);
                for s in members {
                    secret_name_label(ui, th, s);
                }
            });
            ui.add_space(4.0);
        }
    };

    if state.secrets_expanded {
        render_groups(ui);
    } else {
        egui::ScrollArea::vertical()
            .max_height(SECRETS_SCROLL_MAX_HEIGHT)
            .auto_shrink([false, true])
            .show(ui, |ui| render_groups(ui));
    }
}

/// A secret's name, with its locator (and any per-secret provenance)
/// on hover.
fn secret_name_label(ui: &mut egui::Ui, th: &Theme, s: &SecretAsk) {
    let resp = ui.label(
        egui::RichText::new(&s.name)
            .monospace()
            .size(th.body_size - 1.0)
            .strong()
            .color(th.fg),
    );
    let mut hover = s.locator.clone();
    if !s.requested_by.is_empty() {
        hover.push_str("\nrequested by: ");
        hover.push_str(&s.requested_by.join(", "));
    }
    resp.on_hover_text(hover);
}

/// The ancestry, root-first, each process with its argv and pid; the
/// asking leaf is the ask's own command, set in the accent so the eye
/// lands on who is actually asking. Truncated argv shows the full
/// string on hover.
fn render_caller_tree(ui: &mut egui::Ui, th: &Theme, row: &QueueRow) {
    let ask = &row.representative;
    let mut depth = 0usize;
    for caller in ask.callers.iter().rev() {
        caller_row(
            ui,
            th,
            depth,
            &caller.name,
            &caller.command,
            Some(caller.pid),
            false,
        );
        depth += 1;
    }
    let leaf_argv = ask.command.join(" ");
    let leaf_name = ask
        .command
        .first()
        .map(|c| {
            c.rsplit('/')
                .next()
                .unwrap_or(c.as_str())
                .split_whitespace()
                .next()
                .unwrap_or(c.as_str())
                .to_owned()
        })
        .unwrap_or_else(|| row.key.wrap.clone());
    caller_row(ui, th, depth, &leaf_name, &leaf_argv, None, true);
}

fn caller_row(
    ui: &mut egui::Ui,
    th: &Theme,
    depth: usize,
    name: &str,
    argv: &str,
    pid: Option<u32>,
    leaf: bool,
) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        if depth > 0 {
            ui.add_space((depth as f32 - 1.0) * 14.0);
            ui.label(
                egui::RichText::new("└")
                    .monospace()
                    .size(th.body_size - 2.0)
                    .color(th.faint),
            );
        }
        let name_color = if leaf { th.accent_text } else { th.fg };
        ui.label(
            egui::RichText::new(name)
                .size(th.body_size - 1.0)
                .strong()
                .color(name_color),
        );
        // pid sits at the row's end; the argv label truncates into
        // whatever width remains, left-flush against the name.
        let pid_text = pid.map(|p| p.to_string()).unwrap_or_default();
        let pid_width = if pid_text.is_empty() { 0.0 } else { 44.0 };
        let argv_width = (ui.available_width() - pid_width).max(40.0);
        let row_height = ui.text_style_height(&egui::TextStyle::Body);
        ui.allocate_ui_with_layout(
            egui::vec2(argv_width, row_height),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_max_width(argv_width);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(argv)
                            .monospace()
                            .size(th.body_size - 2.0)
                            .color(th.dim),
                    )
                    .truncate(),
                );
            },
        );
        if !pid_text.is_empty() {
            ui.label(
                egui::RichText::new(pid_text)
                    .size(th.body_size - 2.0)
                    .color(th.faint),
            );
        }
    });
}

// ── SSH session grants ───────────────────────────────────────────────────

/// The two TTL'd session-grant actions, rendered as quiet secondary
/// buttons between the well and the footer. The footer's Approve stays
/// "this sign only".
fn render_ssh_session_grants(
    ui: &mut egui::Ui,
    th: &Theme,
    row: &QueueRow,
    actions_out: &mut Vec<PendingAction>,
) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("Session:")
                .size(th.body_size - 2.0)
                .color(th.faint),
        );
        let scope = row_scope(row);
        if quiet_button(ui, th, "Approve for 30 min").clicked() {
            actions_out.push(PendingAction {
                key: row.key.clone(),
                decision: Decision::ApproveSshSession,
                scope,
            });
        }
        if quiet_button(ui, th, "All keys for 30 min").clicked() {
            actions_out.push(PendingAction {
                key: row.key.clone(),
                decision: Decision::ApproveSshSessionAll,
                scope,
            });
        }
    });
}

fn quiet_button(ui: &mut egui::Ui, th: &Theme, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(
            egui::RichText::new(label)
                .size(th.body_size - 2.0)
                .color(th.dim),
        )
        .fill(egui::Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0, th.well_border))
        .corner_radius(th.btn_radius),
    )
}

// ── Empty state ──────────────────────────────────────────────────────────

fn render_empty_state(ui: &mut egui::Ui, th: &Theme, out: &mut PromptOutput) {
    let _ = out;
    ui.add_space(ui.available_height() * 0.30);
    ui.vertical_centered(|ui| {
        paint_app_icon(ui, 36.0);
        ui.add_space(10.0);
        ui.label(
            egui::RichText::new("No pending requests.")
                .size(th.body_size)
                .color(th.dim),
        );
    });
}

// ── Footer / decision surface ────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn render_footer(
    ui: &mut egui::Ui,
    th: &Theme,
    current: Option<&QueueRow>,
    snapshot: &QueueSnapshot,
    state: &mut PromptWindowState,
    actions_out: &mut Vec<PendingAction>,
    out: &mut PromptOutput,
) {
    let _ = state;
    let awaiting = current
        .map(|r| r.status == super::proto::RowStatus::Awaiting)
        .unwrap_or(false);
    let more_waiting = snapshot.entries.len().saturating_sub(1);

    // Full-bleed footer band.
    let band = egui::Rect::from_min_max(
        egui::pos2(ui.max_rect().left(), ui.cursor().min.y),
        ui.max_rect().right_bottom(),
    );
    if th.flavor == OsFlavor::Windows {
        ui.painter().rect_filled(band, 0.0, th.footer);
    }
    if matches!(th.flavor, OsFlavor::Windows | OsFlavor::Gnome) {
        ui.painter()
            .hline(band.x_range(), band.top(), egui::Stroke::new(1.0, th.rule));
    }

    let queue_label = |ui: &mut egui::Ui| {
        if more_waiting > 0 {
            let label = if more_waiting == 1 {
                "1 more waiting".to_owned()
            } else {
                format!("{more_waiting} more waiting")
            };
            ui.label(
                egui::RichText::new(label)
                    .size(th.body_size - 1.0)
                    .color(th.dim),
            );
        }
    };
    let manager_link = |ui: &mut egui::Ui, out: &mut PromptOutput| {
        let resp = ui.add(
            egui::Label::new(
                egui::RichText::new("Open Manager…")
                    .size(th.body_size - 1.0)
                    .color(th.accent_text),
            )
            .sense(egui::Sense::click()),
        );
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if resp.clicked() {
            out.open_manager = Some(ManagerFocus::Rules);
        }
    };
    let resolving_label = |ui: &mut egui::Ui, row: &QueueRow| {
        let text = if row.representative.ssh.is_some() {
            "Signing…"
        } else {
            "Resolving…"
        };
        ui.label(
            egui::RichText::new(text)
                .size(th.body_size)
                .color(th.accent_text),
        );
    };

    match th.flavor {
        OsFlavor::MacOs => {
            let margin = egui::Margin {
                left: INSET_X,
                right: INSET_X,
                top: 12,
                bottom: 12,
            };
            egui::Frame::new().inner_margin(margin).show(ui, |ui| {
                ui.horizontal(|ui| {
                    manager_link(ui, out);
                    ui.add_space(6.0);
                    queue_label(ui);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        match current {
                            Some(row) if awaiting => {
                                if mnemonic_button(ui, th, "Approve", 'A', true).clicked() {
                                    actions_out.push(PendingAction {
                                        key: row.key.clone(),
                                        decision: approve_decision(row),
                                        scope: row_scope(row),
                                    });
                                }
                                if mnemonic_button(ui, th, "Deny", 'D', false).clicked() {
                                    actions_out.push(PendingAction {
                                        key: row.key.clone(),
                                        decision: Decision::Deny,
                                        scope: row_scope(row),
                                    });
                                }
                            }
                            Some(row) => resolving_label(ui, row),
                            None => {}
                        }
                    });
                });
            });
        }
        OsFlavor::Windows => {
            // Meta line above the strip, then equal-width buttons,
            // affirmative first per the Windows convention.
            let margin = egui::Margin {
                left: 20,
                right: 20,
                top: 12,
                bottom: 14,
            };
            egui::Frame::new().inner_margin(margin).show(ui, |ui| {
                match current {
                    Some(row) if awaiting => {
                        ui.horizontal(|ui| {
                            let gap = 8.0;
                            let w = (ui.available_width() - gap) / 2.0;
                            ui.spacing_mut().item_spacing.x = gap;
                            if mnemonic_button_sized(ui, th, "Approve", 'A', true, w).clicked() {
                                actions_out.push(PendingAction {
                                    key: row.key.clone(),
                                    decision: approve_decision(row),
                                    scope: row_scope(row),
                                });
                            }
                            if mnemonic_button_sized(ui, th, "Deny", 'D', false, w).clicked() {
                                actions_out.push(PendingAction {
                                    key: row.key.clone(),
                                    decision: Decision::Deny,
                                    scope: row_scope(row),
                                });
                            }
                        });
                    }
                    Some(row) => {
                        ui.horizontal(|ui| {
                            resolving_label(ui, row);
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| queue_label(ui),
                            );
                        });
                    }
                    None => {}
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    manager_link(ui, out);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        queue_label(ui)
                    });
                });
            });
        }
        OsFlavor::Gnome => {
            // Meta line, then the full-width response row: two flat
            // segments split by a hairline; Approve carries the
            // suggested-action accent.
            ui.add_space(6.0);
            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    ui.add_space(ui.available_width() / 2.0 - 90.0);
                    manager_link(ui, out);
                    ui.add_space(6.0);
                    queue_label(ui);
                });
            });
            ui.add_space(6.0);
            match current {
                Some(row) if awaiting => {
                    let height = 34.0;
                    let full = egui::Rect::from_min_size(
                        egui::pos2(ui.max_rect().left(), ui.cursor().min.y),
                        egui::vec2(ui.max_rect().width(), height),
                    );
                    ui.painter()
                        .hline(full.x_range(), full.top(), egui::Stroke::new(1.0, th.rule));
                    let mid = full.center().x;
                    ui.painter().vline(
                        mid,
                        egui::Rangef::new(full.top(), full.bottom()),
                        egui::Stroke::new(1.0, th.rule),
                    );
                    let left =
                        egui::Rect::from_min_max(full.left_top(), egui::pos2(mid, full.bottom()));
                    let right =
                        egui::Rect::from_min_max(egui::pos2(mid, full.top()), full.right_bottom());
                    if gnome_response(ui, th, left, "Deny", 'D', false).clicked() {
                        actions_out.push(PendingAction {
                            key: row.key.clone(),
                            decision: Decision::Deny,
                            scope: row_scope(row),
                        });
                    }
                    if gnome_response(ui, th, right, "Approve", 'A', true).clicked() {
                        actions_out.push(PendingAction {
                            key: row.key.clone(),
                            decision: approve_decision(row),
                            scope: row_scope(row),
                        });
                    }
                    ui.advance_cursor_after_rect(full);
                }
                Some(row) => {
                    ui.vertical_centered(|ui| resolving_label(ui, row));
                }
                None => {}
            }
        }
    }
}

/// Button label with the mnemonic character underlined.
fn mnemonic_job(
    th: &Theme,
    label: &str,
    mnemonic: char,
    fg: egui::Color32,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let base = egui::TextFormat {
        font_id: egui::FontId::proportional(th.body_size),
        color: fg,
        ..Default::default()
    };
    let underlined = egui::TextFormat {
        underline: egui::Stroke::new(1.0, fg),
        ..base.clone()
    };
    match label.find(mnemonic) {
        Some(idx) => {
            let (before, rest) = label.split_at(idx);
            let mut chars = rest.chars();
            let m = chars.next().map(String::from).unwrap_or_default();
            let after: String = chars.collect();
            job.append(before, 0.0, base.clone());
            job.append(&m, 0.0, underlined);
            job.append(&after, 0.0, base);
        }
        None => job.append(label, 0.0, base),
    }
    job
}

fn mnemonic_button(
    ui: &mut egui::Ui,
    th: &Theme,
    label: &str,
    mnemonic: char,
    default: bool,
) -> egui::Response {
    let (fill, fg, stroke) = if default {
        (th.accent, th.accent_fg, egui::Stroke::new(1.0, th.accent))
    } else {
        (th.btn, th.btn_fg, egui::Stroke::new(1.0, th.btn_border))
    };
    ui.add(
        egui::Button::new(mnemonic_job(th, label, mnemonic, fg))
            .fill(fill)
            .stroke(stroke)
            .corner_radius(th.btn_radius)
            .min_size(egui::vec2(84.0, 26.0)),
    )
}

fn mnemonic_button_sized(
    ui: &mut egui::Ui,
    th: &Theme,
    label: &str,
    mnemonic: char,
    default: bool,
    width: f32,
) -> egui::Response {
    let (fill, fg, stroke) = if default {
        (th.accent, th.accent_fg, egui::Stroke::new(1.0, th.accent))
    } else {
        (th.btn, th.btn_fg, egui::Stroke::new(1.0, th.btn_border))
    };
    ui.add_sized(
        egui::vec2(width, 30.0),
        egui::Button::new(mnemonic_job(th, label, mnemonic, fg))
            .fill(fill)
            .stroke(stroke)
            .corner_radius(th.btn_radius),
    )
}

/// One flat GNOME response segment: no fill at rest, `raised` on
/// hover, bold label — accent-colored when it's the suggested action.
fn gnome_response(
    ui: &mut egui::Ui,
    th: &Theme,
    rect: egui::Rect,
    label: &str,
    mnemonic: char,
    suggested: bool,
) -> egui::Response {
    let resp = ui.interact(rect, ui.id().with(label), egui::Sense::click());
    if resp.hovered() {
        ui.painter().rect_filled(rect, 0.0, th.raised);
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    let fg = if suggested { th.accent_text } else { th.fg };
    let mut job = mnemonic_job(th, label, mnemonic, fg);
    job.sections.iter_mut().for_each(|s| {
        s.format.font_id = egui::FontId::proportional(th.body_size);
    });
    let galley = ui.fonts_mut(|f| f.layout_job(job));
    let pos = rect.center() - galley.size() / 2.0;
    ui.painter().galley(pos, galley, fg);
    resp
}

/// Kept for future use by the resize sweep fixture; the prompt's
/// minimum sensible size.
pub const PROMPT_DEFAULT_SIZE: [f32; 2] = [500.0, 470.0];

/// Small helper the child uses to time repaints for "Ns ago" labels.
pub fn age_label(age: Duration) -> String {
    humanize_duration(age)
}
