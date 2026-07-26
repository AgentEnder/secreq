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
    abbreviate_home, caller_args, format_audit_line, humanize_duration, paint_app_icon,
    render_auto_deny_toast, AuditCache, AutoDenyToastView, PendingAction,
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

    // Where the decision row sits is a question about the *window*, and
    // `ui.max_rect()` cannot answer it: it starts out truthful and then
    // grows to swallow anything that overflows it, so read after the
    // footer has drawn it reports 473 for a 470pt window. The viewport
    // rect is the only thing here that describes the window rather than
    // what got put in it. (`screen_rect()` is its deprecated spelling.)
    let full = ctx.content_rect();

    // An ask on screen gets a decision row; an empty queue gets the
    // manager hand-off. Neither is true while the last ask is resolving
    // out of a queue that still has entries, and then there is no footer
    // at all — so nothing is reserved for one.
    let show_footer = current.is_some() || snapshot.entries.is_empty();

    // How tall that row comes out is not knowable before it is laid out,
    // and egui cannot move what it has already laid out. So lay it out
    // twice: once into an invisible, disabled child `Ui` purely to read
    // a height off its `min_rect`, then again for real, anchored to the
    // bottom of the window. The measuring pass emits `Shape::Noop` for
    // every shape and its widgets can neither be hovered nor clicked, so
    // it costs one extra layout of half a dozen widgets and leaves no
    // other trace.
    //
    // Three hand-tuned per-OS constants stood here before, and each had
    // drifted from the arm it was meant to describe by a different
    // amount, because each was silently absorbing a different overshoot.
    // A number re-derived every frame from the very code that paints
    // cannot drift from it.
    let footer_height = if show_footer {
        measure_footer(ui, &th, current, snapshot, state, full)
    } else {
        0.0
    };

    // The body takes the remainder and scrolls when an ask outgrows it
    // (deep ancestries, big secret sets). Both halves are placed by
    // explicit rect rather than by the cursor, so an over-long body
    // cannot push the decision row off-window no matter what it holds.
    let split = (full.bottom() - footer_height).max(full.top());
    let body_rect = egui::Rect::from_min_max(full.min, egui::pos2(full.right(), split));
    let footer_rect = egui::Rect::from_min_max(egui::pos2(full.left(), split), full.max);

    ui.scope_builder(egui::UiBuilder::new().max_rect(body_rect), |ui| {
        // The two halves now abut exactly, so the scroll viewport has to
        // stop exactly where the decision row starts. `ScrollArea` pads
        // its own clip by `visuals.clip_rect_margin` (3pt, so an
        // antialiased edge at the boundary isn't shaved) and then
        // intersects with whatever clip it inherits — which is the hook
        // this uses. Without it a half-scrolled row's descenders paint a
        // 3pt sliver into the top of the footer band.
        ui.set_clip_rect(body_rect);
        egui::ScrollArea::vertical()
            .id_salt("prompt-body")
            .max_height(body_rect.height())
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
                            if row.representative.agent.is_some()
                                && row.status == super::proto::RowStatus::Awaiting
                            {
                                ui.add_space(8.0);
                                render_agent_session_grant(ui, &th, row, actions_out);
                            }
                        }
                    }
                });
            });
    });

    if show_footer {
        ui.scope_builder(egui::UiBuilder::new().max_rect(footer_rect), |ui| {
            render_footer(ui, &th, current, snapshot, state, actions_out, &mut out);
        });
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

/// "`gh` wants to use `GITHUB_TOKEN`" — one family throughout, with the
/// asking binary and the secret in `th.fg` and the connective words
/// dropped to `th.dim`.
///
/// The title used to switch families mid-sentence — proportional for
/// the prose, monospace for the code spans — which collided egui's
/// Light-weight proportional face with a Regular-weight monospace: a
/// ~100-unit weight step and a condensed-versus-wide texture change
/// inside a single line. Emphasis by colour within one family draws the
/// same distinction without the seam, and dimming the scaffolding
/// leaves the two things that actually matter — who is asking, and for
/// what — as the only bright text on the line.
fn title_job(ui: &egui::Ui, th: &Theme, row: &QueueRow) -> egui::text::LayoutJob {
    let ask = &row.representative;
    let mut job = egui::text::LayoutJob::default();
    // Hack's advance is ~0.6em against the old proportional face's
    // ~0.5em, so a mono-only title needs ~20% more width and the agent
    // branch (`sandbox <scope> wants <secret://…>`) wraps to two lines.
    // No title size that still reads as a title avoids that — fitting
    // it would take ~14px, under the body text on some flavors — so the
    // wrap is accepted and the title keeps its full weight.
    let span = |color| egui::TextFormat {
        font_id: egui::FontId::monospace(th.body_size + 2.0),
        color,
        line_height: Some(th.body_size + 8.0),
        ..Default::default()
    };
    let prose = span(th.dim);
    let subject = span(th.fg);
    let _ = ui;
    if let Some(agent) = &ask.agent {
        // "sandbox `brain-nx-t5` wants `secret://op/Dev/gh/token`". The
        // scope leads because it IS the principal here — there is no
        // process name to lead with, and inventing one would misrepresent
        // what we actually know (see `scoped_agent`'s module docs).
        job.append("sandbox ", 0.0, prose.clone());
        job.append(&agent.scope, 0.0, subject.clone());
        job.append(" wants ", 0.0, prose);
        job.append(&agent.reference, 0.0, subject);
    } else if let Some(ssh) = &ask.ssh {
        let requester = ask.callers.first().map_or("ssh", |c| c.name.as_str());
        job.append(requester, 0.0, subject.clone());
        job.append(" wants to sign with ", 0.0, prose);
        job.append(&ssh.key_id, 0.0, subject);
    } else {
        job.append(&row.key.wrap, 0.0, subject.clone());
        if ask.secrets.len() == 1 {
            job.append(" wants to use ", 0.0, prose);
            job.append(&ask.secrets[0].name, 0.0, subject);
        } else {
            job.append(" wants to use ", 0.0, prose);
            job.append(&format!("{} secrets", ask.secrets.len()), 0.0, subject);
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
        if let Some(agent) = &ask.agent {
            // A guest's request has a different evidence shape from every
            // local ask, and the well says so honestly:
            //
            // - SECRET is the ref itself (a guest asks by address; there's
            //   no env-var name on this path).
            // - ASKED BY gives way to SCOPE. We do NOT render a caller tree
            //   — not an empty one, not a placeholder one. There is no
            //   host-verifiable chain behind a guest (see `scoped_agent`),
            //   and a chain-shaped widget here would imply we checked
            //   something we did not.
            // - IN (cwd) is dropped for the same reason: the guest's cwd is
            //   in another kernel.
            well_row(ui, th, "SECRET", |ui, th| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&agent.reference)
                            .monospace()
                            .size(th.body_size - 1.0)
                            .color(th.fg),
                    )
                    .truncate(),
                );
            });
            well_separator(ui, th);

            well_row(ui, th, "SCOPE", |ui, th| {
                ui.vertical(|ui| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(&agent.scope)
                                .monospace()
                                .size(th.body_size - 1.0)
                                .color(th.fg),
                        )
                        .truncate(),
                    );
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(
                                "host-declared · the guest's callers are not visible",
                            )
                            .size(th.body_size - 2.0)
                            .color(th.dim),
                        )
                        .truncate(),
                    );
                });
            });
            well_separator(ui, th);

            // The guest's own story about itself, when it told one. Rendered
            // *below* SCOPE and visibly marked, so the reading order is
            // "here's what we know, and here's what we've merely been told" —
            // never the reverse.
            if let Some(chain) = &agent.guest_chain {
                render_guest_chain(ui, th, chain);
                well_separator(ui, th);
            }
        } else if let Some(ssh) = &ask.ssh {
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

        // ASKED BY / IN are host-process facts. A scoped-agent ask has
        // neither (its `agent` branch above rendered SCOPE in their place),
        // so they're skipped rather than rendered empty.
        if ask.agent.is_none() {
            well_row(ui, th, "ASKED BY", |ui, th| {
                render_caller_tree(ui, th, row);
            });
            well_separator(ui, th);

            // A cwd we don't have is omitted, not labelled blank. The SSH
            // path reads it off the socket peer and can come back empty
            // (process gone, platform won't say), and an `IN` header over
            // dead space reads as a rendering fault rather than as "we
            // could not determine this".
            if !ask.cwd.is_empty() {
                well_row(ui, th, "IN", |ui, th| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(abbreviate_home(&ask.cwd))
                                .monospace()
                                .size(th.body_size - 1.0)
                                .color(th.fg),
                        )
                        .truncate(),
                    );
                });
                well_separator(ui, th);
            }
        }

        well_row(ui, th, "HISTORY", |ui, th| {
            let caller = ask.callers.first().map(|c| super::ui::CallerIdentity {
                name: c.name.as_str(),
                exe: c.exe.as_deref(),
            });
            let summary = state.audit.summarize(history_wrap(row).as_ref(), caller);
            let (line, color) = if ask.agent.is_some() && summary.is_empty() {
                // The shared empty-history line says "first request from
                // this caller". There is no caller on this path — that's
                // the entire point of the scoped-agent design — so saying
                // so here would quietly contradict the SCOPE row directly
                // above it. The scope is what has (or hasn't) asked before.
                ("first request from this scope".to_owned(), th.dim)
            } else {
                format_audit_line(&summary, super::ui::now_unix(), th)
            };
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

/// The guest's self-reported caller chain, and the marker that says not to
/// believe it.
///
/// This row exists because the claim is genuinely useful — when the guest is
/// honest, it is exactly the context the user wants; when it is not, the
/// audit log has the lie on record. But it is the one thing in this prompt
/// the host did not establish, and a consent UI that renders a claim and a
/// fact identically has quietly turned itself into a forgery surface.
///
/// So the marker is not decoration:
///
/// - The label is `GUEST SAYS`, not `ASKED BY`. The local prompt's caller
///   tree earns `ASKED BY` by being kernel-sourced; reusing that widget here
///   would imply a check that never happened.
/// - The caveat renders in `th.danger` and is not truncatable away — a
///   warning that a long chain can push out of view is not a warning.
/// - The chain arrives pre-sanitized (see `scoped_agent::GuestChain`), so it
///   cannot paint its own second line claiming to be verified.
fn render_guest_chain(ui: &mut egui::Ui, th: &Theme, chain: &str) {
    well_row(ui, th, "GUEST SAYS", |ui, th| {
        ui.vertical(|ui| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(chain)
                        .monospace()
                        .size(th.body_size - 1.0)
                        .color(th.dim),
                )
                .wrap(),
            );
            ui.add(egui::Label::new(
                egui::RichText::new("⚠ guest-reported — NOT verifiable")
                    .size(th.body_size - 2.0)
                    .color(th.danger),
            ));
        });
    });
}

/// The scoped-agent TTL grant, rendered like the SSH one: a quiet secondary
/// action between the well and the footer, leaving the footer's Approve
/// meaning "this request only".
///
/// Two buttons for two different things, which is the honest split — "yes,
/// once" and "yes, and stop asking for a bit" are different amounts of trust
/// and the user should be able to say which they mean. Only this one anchors
/// a [`consent::AgentGrant`]; plain Approve anchors nothing.
///
/// The TTL is named on the button rather than buried in a tooltip: "Approve"
/// that silently means "approve for five minutes" is a consent UI lying by
/// omission.
fn render_agent_session_grant(
    ui: &mut egui::Ui,
    th: &Theme,
    row: &QueueRow,
    actions_out: &mut Vec<PendingAction>,
) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("Scope:")
                .size(th.body_size - 2.0)
                .color(th.faint),
        );
        if quiet_button(ui, th, "Approve for 5 min").clicked() {
            actions_out.push(PendingAction {
                key: row.key.clone(),
                decision: Decision::ApproveAgentSession,
                scope: row_scope(row),
            });
        }
    });
}

/// The wrap label this row's HISTORY should be summarized against.
///
/// Usually the dedupe key's wrap. Scoped-agent asks are the exception: their
/// dedupe key is `agent:<scope>:<ref>` (deliberately per-ref, so two refs
/// from one scope can't coalesce into a single prompt — see
/// `scoped_agent::agent_ask`), while their audit rows are written against
/// the coarser `agent:<scope>`. Summarizing on the dedupe key would find
/// nothing; this asks the question the user actually has — "what has this
/// sandbox asked for before?"
fn history_wrap(row: &QueueRow) -> std::borrow::Cow<'_, str> {
    match &row.representative.agent {
        Some(agent) => std::borrow::Cow::Owned(format!("agent:{}", agent.scope)),
        None => std::borrow::Cow::Borrowed(row.key.wrap.as_str()),
    }
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
            caller_args(&caller.name, &caller.command),
            Some(caller.pid),
            false,
        );
        depth += 1;
    }
    let leaf_argv = ask.command.join(" ");
    let leaf_name = ask.command.first().map_or_else(
        || row.key.wrap.clone(),
        |c| {
            c.rsplit('/')
                .next()
                .unwrap_or(c.as_str())
                .split_whitespace()
                .next()
                .unwrap_or(c.as_str())
                .to_owned()
        },
    );
    caller_row(
        ui,
        th,
        depth,
        &leaf_name,
        caller_args(&leaf_name, &leaf_argv),
        None,
        true,
    );
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

/// Width the session identity is laid out in, so a long process name
/// truncates instead of shoving the grant buttons off the row.
///
/// A fixed budget rather than "whatever is left" on purpose: the two things
/// sharing this row are attacker-influenced text and the controls that hand
/// out a 30-minute signing grant, and the controls are not allowed to move.
const SESSION_LABEL_WIDTH: f32 = 132.0;

/// The two TTL'd session-grant actions, rendered as quiet secondary
/// buttons between the well and the footer. The footer's Approve stays
/// "this sign only".
///
/// The row leads with **which session** — `zsh · 7926`. These buttons are
/// the only controls in the prompt whose effect outlives the request on
/// screen, and what they bind to is not the command in the header and not
/// the nearest caller: it is the shell or multiplexer that
/// `provenance::select_anchor` picked further up the chain. Every process
/// under that session signs freely for the next half hour, so a prompt that
/// offered the choice without naming its subject was asking the user to
/// approve something it had not shown them.
///
/// The pid is there to be matched by eye against the ASKED BY tree directly
/// above, which renders the same pid on that frame's row.
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
        if let Some(anchor) = row
            .representative
            .ssh
            .as_ref()
            .and_then(|s| s.anchor.as_ref())
        {
            let full = format!("{} · {}", anchor.name, anchor.pid);
            let row_height = ui.text_style_height(&egui::TextStyle::Body);
            let resp = ui
                .allocate_ui_with_layout(
                    egui::vec2(SESSION_LABEL_WIDTH, row_height),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.set_max_width(SESSION_LABEL_WIDTH);
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&full)
                                    .monospace()
                                    .size(th.body_size - 2.0)
                                    .color(th.fg),
                            )
                            .truncate(),
                        )
                    },
                )
                .inner;
            resp.on_hover_text(format!(
                "A 30-minute grant attaches to this process.\n{full}"
            ));
        }
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

// ── Optical centering ────────────────────────────────────────────────────

/// Advance width of `text` laid out in the proportional font at `size`.
/// The color is irrelevant to the measurement, so we hand the layouter a
/// placeholder rather than pulling a [`Theme`] in just to throw it away.
fn text_width(ui: &egui::Ui, text: &str, size: f32) -> f32 {
    ui.ctx().fonts_mut(|f| {
        f.layout_no_wrap(
            text.to_owned(),
            egui::FontId::proportional(size),
            egui::Color32::PLACEHOLDER,
        )
        .size()
        .x
    })
}

/// The width to *center* `text` on: its advance, with a trailing
/// ellipsis hanging off the right edge.
///
/// `…` is three low dots plus a generous sidebearing — it claims far
/// more advance than it puts ink on the screen. Center on the full
/// advance and the words land left of the axis by half the ellipsis,
/// which reads as a mis-aligned label rather than as centered text.
/// Letting it hang puts the words themselves on the axis, the way a
/// typesetter hangs trailing punctuation into the margin.
///
/// Only the *last* item in a row may hang: an ellipsis with more text
/// after it is interior ink, and measuring it with this rather than
/// [`text_width`] shoves the whole row off-axis by half an ellipsis.
fn centering_width(ui: &egui::Ui, text: &str, size: f32) -> f32 {
    text_width(ui, text.strip_suffix('\u{2026}').unwrap_or(text), size)
}

/// Leading space that puts `content_width` on the row's horizontal axis.
/// egui has no "center this row" layout — [`egui::Ui::vertical_centered`]
/// only centers lone widgets, and a `horizontal` nested inside it takes
/// the full width and lays out from the left — so centering a row of
/// widgets means measuring it and indenting by hand.
fn center_indent(ui: &egui::Ui, content_width: f32) -> f32 {
    ((ui.available_width() - content_width) / 2.0).max(0.0)
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

/// The prompt's hand-off into the manager window. Named because GNOME
/// measures it to center the meta line, and a measurement that drifts
/// from what's rendered is a silently-crooked row.
const MANAGER_LINK: &str = "Open Manager\u{2026}";

/// The read-only status word for an ask that's already been authorized
/// and is waiting on the provider: the SSH path is signing, everything
/// else is resolving.
fn resolving_text(row: &QueueRow) -> &'static str {
    if row.representative.ssh.is_some() {
        "Signing\u{2026}"
    } else {
        "Resolving\u{2026}"
    }
}

/// How tall the decision row will come out, by laying it out and looking.
///
/// This is a *sizing pass*, the same device [`egui::Area`] uses to place a
/// popup whose size it has never seen: the row is drawn into a child `Ui`
/// built [`egui::UiBuilder::invisible`], which turns every shape the arm
/// paints into a `Shape::Noop` and disables its widgets, so nothing lands
/// in the frame's output, nothing hovers and nothing can be clicked. What
/// survives is the one thing we came for — the `min_rect` the arm's
/// content grew to, margins included.
///
/// It is laid out against the whole window rather than a guess at the
/// band, because width is what the arm's content is actually sensitive to
/// (Windows splits the available width between two buttons, GNOME centers
/// its meta line in it) and an unconstrained height is what lets the
/// content report its natural one. The decisions and the manager hand-off
/// go to scratch buffers that are dropped on return: a disabled widget
/// cannot report a click, and this makes it impossible for one to be
/// counted twice even if that ever changed.
fn measure_footer(
    ui: &mut egui::Ui,
    th: &Theme,
    current: Option<&QueueRow>,
    snapshot: &QueueSnapshot,
    state: &mut PromptWindowState,
    full: egui::Rect,
) -> f32 {
    let mut scratch_actions = Vec::new();
    let mut scratch_out = PromptOutput::default();
    let mut probe = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("prompt-footer-measure")
            .max_rect(full)
            .invisible(),
    );
    render_footer(
        &mut probe,
        th,
        current,
        snapshot,
        state,
        &mut scratch_actions,
        &mut scratch_out,
    );
    probe.min_rect().height()
}

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
    let awaiting = current.is_some_and(|r| r.status == super::proto::RowStatus::Awaiting);
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

    // The meta line's two labels. GNOME centers them as a group, so the
    // text has to be measurable before it's rendered — hence the strings
    // live out here rather than inside the render closures.
    let meta_size = th.body_size - 1.0;
    let queue_text = (more_waiting > 0).then(|| {
        if more_waiting == 1 {
            "1 more waiting".to_owned()
        } else {
            format!("{more_waiting} more waiting")
        }
    });
    let queue_label = |ui: &mut egui::Ui| {
        if let Some(text) = &queue_text {
            ui.label(
                egui::RichText::new(text.as_str())
                    .size(meta_size)
                    .color(th.dim),
            );
        }
    };
    let manager_link = |ui: &mut egui::Ui, out: &mut PromptOutput| {
        let resp = ui.add(
            egui::Label::new(
                egui::RichText::new(MANAGER_LINK)
                    .size(meta_size)
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
        ui.label(
            egui::RichText::new(resolving_text(row))
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
                        queue_label(ui);
                    });
                });
            });
        }
        OsFlavor::Gnome => {
            // Meta line, then the full-width response row: two flat
            // segments split by a hairline; Approve carries the
            // suggested-action accent.
            //
            // The margin is load-bearing and it is why this arm has a
            // `Frame` at all. The response row is painted straight off the
            // cursor with nothing after it, so unlike its macOS and Windows
            // siblings it used to end at its own last pixel — the mnemonic
            // underline under `Approve` sat a point off the window's edge,
            // and what held it away was the reserved band being taller than
            // the row. The band is measured now, so the clearance has to be
            // the arm's own, the way the other two flavors already spell it.
            let margin = egui::Margin {
                left: 0,
                right: 0,
                top: 6,
                bottom: 12,
            };
            egui::Frame::new().inner_margin(margin).show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Explicit gap only: the default item spacing would sit
                    // on top of it and desync the row from its measurement.
                    const GAP: f32 = 6.0;
                    ui.spacing_mut().item_spacing.x = 0.0;
                    // Only whichever label lands last gets to hang its
                    // ellipsis; the link's dots are interior ink once the
                    // queue label follows them.
                    let content = match &queue_text {
                        Some(text) => {
                            text_width(ui, MANAGER_LINK, meta_size)
                                + GAP
                                + centering_width(ui, text, meta_size)
                        }
                        None => centering_width(ui, MANAGER_LINK, meta_size),
                    };
                    ui.add_space(center_indent(ui, content));
                    manager_link(ui, out);
                    if queue_text.is_some() {
                        ui.add_space(GAP);
                        queue_label(ui);
                    }
                });
                ui.add_space(6.0);
                match current {
                    Some(row) if awaiting => {
                        let height = 34.0;
                        let full = egui::Rect::from_min_size(
                            egui::pos2(ui.max_rect().left(), ui.cursor().min.y),
                            egui::vec2(ui.max_rect().width(), height),
                        );
                        ui.painter().hline(
                            full.x_range(),
                            full.top(),
                            egui::Stroke::new(1.0, th.rule),
                        );
                        let mid = full.center().x;
                        ui.painter().vline(
                            mid,
                            egui::Rangef::new(full.top(), full.bottom()),
                            egui::Stroke::new(1.0, th.rule),
                        );
                        let left = egui::Rect::from_min_max(
                            full.left_top(),
                            egui::pos2(mid, full.bottom()),
                        );
                        let right = egui::Rect::from_min_max(
                            egui::pos2(mid, full.top()),
                            full.right_bottom(),
                        );
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
                        ui.horizontal(|ui| {
                            let width = centering_width(ui, resolving_text(row), th.body_size);
                            ui.add_space(center_indent(ui, width));
                            resolving_label(ui, row);
                        });
                    }
                    None => {}
                }
            });
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
