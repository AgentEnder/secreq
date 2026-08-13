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

use std::time::{Duration, Instant};

use eframe::egui;

use crate::consent::Decision;

use super::proto::{AskSubject, Caller, LocalPeer, SecretAsk, SshAnchorInfo, SshAskInfo};
use super::state::{QueueRow, QueueSnapshot};
use super::theme::{OsFlavor, Theme};
use super::ui::{
    abbreviate_home, caller_args, format_audit_line, humanize_duration, paint_app_icon,
    render_auto_deny_toast, AuditCache, AutoDenyToastView, PendingAction,
};
use crate::provenance::{ProcessIdentity, SignAnchorKind};

/// Which manager view the prompt asks the daemon to open. A wire type
/// (the child forwards it as `ClientMsg::OpenManager`), so it lives in
/// [`super::proto`]; re-exported here for the renderer's callers.
pub use super::proto::ManagerFocus;

/// How long after the prompt gains focus before keyboard decisions are
/// honoured.
///
/// The window opens **without** taking focus (`with_active(false)` in
/// `child.rs`), so in the ordinary case keystrokes never reach it at all.
/// This delay covers the rest: the user ⌘-tabs to the prompt, or a window
/// manager hands it focus anyway, or the platform doesn't support opening
/// inactive (X11/Wayland). Half a second is enough for a person to notice
/// where their keys are now going, and long enough that the tail of a
/// keystroke burst already in flight lands harmlessly.
pub(crate) const KEYBOARD_ARM_DELAY: Duration = Duration::from_millis(500);

/// Everything the prompt window remembers across frames. Deliberately
/// small: the prompt is a transient surface, not a browsing one.
pub struct PromptWindowState {
    pub(crate) audit: AuditCache,
    /// Optional explanation attached to a denial of the currently displayed
    /// ask. Cleared when focus advances to another ask.
    denial_reason: String,
    /// Set when the secrets list is expanded past its collapsed cap.
    secrets_expanded: bool,
    /// The ask the expansion applies to; reset when the ask changes.
    expanded_for: Option<super::proto::DedupeKey>,
    /// When the window most recently gained focus; `None` while unfocused.
    /// Drives [`PromptWindowState::keyboard_armed`].
    focus_since: Option<Instant>,
    /// A click landed inside the window since it gained focus, so the
    /// keyboard is live regardless of the delay.
    armed_by_click: bool,
}

impl PromptWindowState {
    pub fn new() -> Self {
        PromptWindowState {
            audit: AuditCache::new(),
            denial_reason: String::new(),
            secrets_expanded: false,
            expanded_for: None,
            focus_since: None,
            armed_by_click: false,
        }
    }

    /// Pre-fill the optional denial reason. Primarily useful to the
    /// screenshot harness, but also a legitimate production state seam.
    pub fn set_denial_reason(&mut self, reason: impl Into<String>) {
        self.denial_reason = reason.into();
    }

    /// Record this frame's focus state. Gaining focus starts the arming
    /// delay; losing it disarms completely, so a blur-then-refocus starts
    /// the delay over rather than resuming a part-served one.
    ///
    /// Called by the window child, which owns the real OS window — not by
    /// the renderer. Keeping the clock and the focus read out of
    /// `render_prompt_panel` is what lets the screenshot harness draw a
    /// pinned armed or disarmed panel instead of racing a 500ms timer.
    pub fn note_focus(&mut self, focused: bool) {
        if focused {
            self.focus_since.get_or_insert_with(Instant::now);
        } else {
            self.focus_since = None;
            self.armed_by_click = false;
        }
    }

    /// Arm the keyboard immediately, on a click inside the window.
    ///
    /// A click is unambiguous intent in a way a keystroke is not: you
    /// cannot click this window by accident while typing into another one,
    /// so there is nothing to protect against and no reason to make a user
    /// who has clearly arrived here wait out the delay.
    pub fn arm_keyboard(&mut self) {
        self.armed_by_click = true;
    }

    /// Whether keyboard decisions are live this frame.
    pub fn keyboard_armed(&self) -> bool {
        self.armed_by_click
            || self
                .focus_since
                .is_some_and(|t| t.elapsed() >= KEYBOARD_ARM_DELAY)
    }

    /// How long until the delay expires, or `None` if the keyboard is
    /// already armed or the window is unfocused. The child schedules its
    /// repaint off this so the affordance flips on time.
    pub fn arming_remaining(&self) -> Option<Duration> {
        if self.armed_by_click {
            return None;
        }
        self.focus_since
            .map(|t| KEYBOARD_ARM_DELAY.saturating_sub(t.elapsed()))
            .filter(|d| !d.is_zero())
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
        if state.expanded_for.is_some() {
            state.denial_reason.clear();
        }
        state.expanded_for = current.map(|r| r.key.clone());
    }

    // Keyboard: approve takes the command modifier, deny does not.
    //
    // The asymmetry is the point. An accidental deny costs a re-run; an
    // accidental approve releases a live credential and writes an audit
    // row claiming the user meant it. Approve used to be bare `A` or bare
    // `Enter` — the letter and the keystroke most likely to already be in
    // flight when a window steals focus mid-sentence. Deny keeps its bare
    // keys because failing closed in a hurry is the behaviour we want.
    if let Some(row) = current {
        if row.status == super::proto::RowStatus::Awaiting && state.keyboard_armed() {
            let scope = row_scope(row);
            let no_text_input_focused = ctx.memory(|m| m.focused().is_none());
            ctx.input(|i| {
                if !no_text_input_focused {
                    return;
                }
                if i.modifiers.command_only() && i.key_pressed(egui::Key::Enter) {
                    actions_out.push(PendingAction {
                        key: row.key.clone(),
                        decision: approve_decision(row),
                        reason: None,
                        scope,
                    });
                } else if i.modifiers.is_none()
                    && (i.key_pressed(egui::Key::D) || i.key_pressed(egui::Key::Escape))
                {
                    actions_out.push(PendingAction {
                        key: row.key.clone(),
                        decision: Decision::Deny,
                        reason: denial_reason(state),
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

    // Where the decision band sits is a question about the *window*, and
    // `ui.max_rect()` cannot answer it: it starts out truthful and then
    // grows to swallow anything that overflows it, so read after the band
    // has drawn it reports a few points more than the window is tall. The
    // viewport rect is the only thing here that describes the window rather
    // than what got put in it. (`screen_rect()` is its deprecated spelling.)
    let full = ctx.content_rect();

    // An ask on screen gets a decision band; an empty queue gets the
    // manager hand-off. Neither is true while the last ask is resolving
    // out of a queue that still has entries, and then there is no band
    // at all — so nothing is reserved for one.
    let show_band = current.is_some() || snapshot.entries.is_empty();

    // How tall that band comes out is not knowable before it is laid out,
    // and egui cannot move what it has already laid out. So lay it out
    // twice: once into an invisible, disabled child `Ui` purely to read
    // a height off its `min_rect`, then again for real, anchored to the
    // bottom of the window. The measuring pass emits `Shape::Noop` for
    // every shape and its widgets can neither be hovered nor clicked, so
    // it costs one extra layout of a dozen widgets and leaves no other
    // trace.
    //
    // Three hand-tuned per-OS constants stood here before, and each had
    // drifted from the arm it was meant to describe by a different
    // amount, because each was silently absorbing a different overshoot.
    // A number re-derived every frame from the very code that paints
    // cannot drift from it.
    let band_height = if show_band {
        measure_decision_band(ui, &th, current, snapshot, state, full)
    } else {
        0.0
    };

    // The body takes the remainder and scrolls when an ask outgrows it
    // (deep ancestries, big secret sets). Both halves are placed by
    // explicit rect rather than by the cursor, so an over-long body
    // cannot push the decision band off-window no matter what it holds.
    let split = (full.bottom() - band_height).max(full.top());
    let body_rect = egui::Rect::from_min_max(full.min, egui::pos2(full.right(), split));
    let band_rect = egui::Rect::from_min_max(egui::pos2(full.left(), split), full.max);

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
                        }
                    }
                });
            });
    });

    if show_band {
        ui.scope_builder(egui::UiBuilder::new().max_rect(band_rect), |ui| {
            render_decision_band(ui, &th, current, snapshot, state, actions_out, &mut out);
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
/// the dedupe key's anchor already names. A remembered approval written
/// there covers subsequent asks from the same parent process.
///
/// `None` for a row anchored to a `run` session or a scoped agent's socket.
/// Those carry a pid beside a number that is not a start time — a random
/// nonce, a placeholder zero — and this function used to pack both into a
/// [`ProcessIdentity`] and send it to the daemon as the scope to remember
/// at. Nothing stored it, because those asks answer `allow_remember()` with
/// `false`; that was a flag in another file standing where a type belongs.
fn row_scope(row: &QueueRow) -> Option<ProcessIdentity> {
    row.key.anchor.process_identity()
}

/// What "Approve" means for this ask. A wrap ask remembers at the parent
/// scope when it allows it (`secreq run` forbids remembering — its fixed
/// identity would over-match). Everything else approves once: a sign and a
/// guest release both remember elsewhere, which is why `allow_remember()`
/// answers `false` for them and this needs no kind test of its own.
fn approve_decision(row: &QueueRow) -> Decision {
    if row.representative.allow_remember() {
        Decision::ApproveRemember
    } else {
        Decision::Approve
    }
}

fn denial_reason(state: &PromptWindowState) -> Option<String> {
    let reason = state.denial_reason.trim();
    (!reason.is_empty()).then(|| reason.to_owned())
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
            let cmdline = crate::rules::joined_argv(&ask.command);
            let sub = match &ask.subject {
                AskSubject::SshSign(s) => s.info.reason.clone().unwrap_or_else(|| cmdline.clone()),
                AskSubject::Wrap(_) | AskSubject::ScopedAgent(_) => cmdline.clone(),
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
    match &ask.subject {
        AskSubject::ScopedAgent(agent) => {
            // "sandbox `brain-nx-t5` wants `secret://op/Dev/gh/token`". The
            // scope leads because it IS the principal here — there is no
            // process name to lead with, and inventing one would misrepresent
            // what we actually know (see `scoped_agent`'s module docs).
            job.append("sandbox ", 0.0, prose.clone());
            job.append(&agent.scope, 0.0, subject.clone());
            job.append(" wants ", 0.0, prose);
            job.append(&agent.reference, 0.0, subject);
        }
        AskSubject::SshSign(ssh) => {
            let requester = ssh.callers.first().map_or("ssh", |c| c.name.as_str());
            job.append(requester, 0.0, subject.clone());
            job.append(" wants to sign with ", 0.0, prose);
            job.append(&ssh.info.key_id, 0.0, subject);
        }
        AskSubject::Wrap(wrap) => {
            job.append(&row.key.wrap, 0.0, subject.clone());
            job.append(" wants to use ", 0.0, prose);
            if let [only] = wrap.secrets.as_slice() {
                job.append(&only.name, 0.0, subject);
            } else {
                job.append(&format!("{} secrets", wrap.secrets.len()), 0.0, subject);
            }
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
        // A hairline belongs *between* two rows. Written after each row
        // instead, the well ends on a rule under nothing — and which row is
        // last differs by ask kind and by whether a cwd came back, so no
        // branch here can be the one that remembers to skip it.
        let mut rows = 0usize;
        let mut divide = |ui: &mut egui::Ui| {
            if rows > 0 {
                well_separator(ui, th);
            }
            rows += 1;
        };
        if let AskSubject::ScopedAgent(agent) = &ask.subject {
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
            divide(ui);
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

            divide(ui);
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
                    // This line used to read "host-declared · the guest's
                    // callers are not visible". It was the one thing on the
                    // prompt that vouched for the ask: the daemon never
                    // checked that any host declared this scope, because it
                    // cannot — a local process claiming the guest kind
                    // reaches it as the same message a real `agent open`
                    // does. It now names the process that said so instead.
                    render_scope_declarant(ui, th, agent.declared_by.as_ref());
                });
            });

            // The guest's own story about itself, when it told one. Rendered
            // *below* SCOPE and visibly marked, so the reading order is
            // "here's what we know, and here's what we've merely been told" —
            // never the reverse.
            if let Some(chain) = &agent.guest_chain {
                divide(ui);
                render_guest_chain(ui, th, chain);
            }
        } else if let AskSubject::SshSign(ssh) = &ask.subject {
            divide(ui);
            well_row(ui, th, "SIGN WITH", |ui, th| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&ssh.info.fingerprint)
                            .monospace()
                            .size(th.body_size - 1.0)
                            .color(th.fg),
                    )
                    .truncate(),
                );
            });
            if let Some(anchor) = forwarding_anchor(&ssh.info) {
                divide(ui);
                render_forwarded_by(ui, th, anchor);
            }
        } else {
            divide(ui);
            well_row(ui, th, &secrets_label(ask.secrets().len()), |ui, th| {
                render_secrets(ui, th, ask.secrets(), state);
            });
        }

        // ASKED BY / IN are host-process facts. A scoped-agent ask has
        // neither (its branch above rendered SCOPE in their place), so
        // they're skipped rather than rendered empty. That is now the
        // variant's shape talking: the subject has no field either row could
        // read from.
        if !matches!(ask.subject, AskSubject::ScopedAgent(_)) {
            divide(ui);
            well_row(ui, th, "ASKED BY", |ui, th| {
                render_caller_tree(ui, th, row);
            });

            // A cwd we don't have is omitted, not labelled blank. The SSH
            // path reads it off the socket peer and can come back empty
            // (process gone, platform won't say), and an `IN` header over
            // dead space reads as a rendering fault rather than as "we
            // could not determine this".
            if !ask.cwd().is_empty() {
                divide(ui);
                well_row(ui, th, "IN", |ui, th| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(abbreviate_home(ask.cwd()))
                                .monospace()
                                .size(th.body_size - 1.0)
                                .color(th.fg),
                        )
                        .truncate(),
                    );
                });
            }
        }
    });
}

/// What secreq's own audit log says about this caller — and the one row in
/// the prompt whose content the requester had no hand in.
///
/// It sits in the pinned band rather than in the evidence well, which is the
/// distinction the well now draws: **the well is what the caller is, the band
/// is what we know and what you can do about it.** Everything above the split
/// is attacker-influenced and free to grow; nothing above the split can push
/// this off the screen.
///
/// It used to be the well's last row, under a caller tree and an argv column
/// with no ceiling between them, so "denied 3 times before" was exactly the
/// line a deep enough ancestry scrolled away.
fn render_history_row(
    ui: &mut egui::Ui,
    th: &Theme,
    row: &QueueRow,
    state: &mut PromptWindowState,
) {
    // Its own inset block, in the evidence well's clothing. Left bare it read
    // as a line that had come adrift from the well above it; the frame says
    // the opposite and the truer thing — a second, smaller container, holding
    // what secreq knows rather than what it was told.
    well_frame(th).show(ui, |ui| {
        ui.set_width(ui.available_width());
        history_line(ui, th, row, state);
    });
}

fn history_line(ui: &mut egui::Ui, th: &Theme, row: &QueueRow, state: &mut PromptWindowState) {
    let ask = &row.representative;
    well_row(ui, th, "HISTORY", |ui, th| {
        let caller = ask.callers().first().map(|c| super::ui::CallerIdentity {
            name: c.name.as_str(),
            exe: c.exe.as_deref(),
        });
        let summary = state.audit.summarize(history_wrap(row).as_ref(), caller);
        let is_agent = matches!(ask.subject, AskSubject::ScopedAgent(_));
        let (line, color) = if is_agent && summary.is_empty() {
            // The shared empty-history line says "first request from this
            // caller". There is no caller on this path — that's the entire
            // point of the scoped-agent design — so saying so here would
            // quietly contradict the SCOPE row in the well. The scope is what
            // has (or hasn't) asked before.
            ("first request from this scope".to_owned(), th.dim)
        } else {
            format_audit_line(&summary, super::ui::now_unix(), th)
        };
        // The prompt already sets context; drop the audit line's "↳ " prefix,
        // which belongs to the old card layout.
        let line = line.trim_start_matches("↳ ").to_owned();
        ui.label(
            egui::RichText::new(line)
                .size(th.body_size - 1.0)
                .color(color),
        );
    });
}

/// This ask's anchor when — and only when — it is a forwarding `ssh` client.
///
/// One place answers "is forwarding in play", so the well row and the grant
/// row cannot end up disagreeing about whether to say so.
fn forwarding_anchor(info: &SshAskInfo) -> Option<&SshAnchorInfo> {
    info.anchor
        .as_ref()
        .filter(|a| a.kind == SignAnchorKind::ForwardedSsh)
}

/// The `ssh` client that handed this agent to a remote host.
///
/// The one frame the `ASKED BY` tree cannot draw. A sign arrives from the
/// local `ssh` client, and the caller chain deliberately starts at the socket
/// peer's *parent* — so under `ssh -A` the process that matters most to the
/// decision was, until this row, the only one the prompt never showed. The
/// tree said `zsh`, the header said `git`, and nothing on screen mentioned
/// the machine that could actually be asking.
///
/// The argv is here because it names the host. "A remote can sign with your
/// key" is abstract; `ssh -A build-box` is the sentence the user can act on.
/// It is requester-influenced text, so it lives in the scrolling well and is
/// truncated like any other argv — never in the pinned band, which is where
/// the grant buttons it describes are placed.
fn render_forwarded_by(ui: &mut egui::Ui, th: &Theme, anchor: &SshAnchorInfo) {
    well_row(ui, th, "FORWARDED BY", |ui, th| {
        ui.vertical(|ui| {
            let command = anchor.command.as_deref().unwrap_or_default();
            caller_row(
                ui,
                th,
                0,
                &anchor.name,
                // The same argv treatment the tree gives every other frame,
                // so `ssh -A build-box` under a name of `ssh` reads as
                // `ssh   -A build-box` rather than saying `ssh` twice.
                caller_args(&anchor.name, command),
                Some(anchor.pid),
                false,
            );
            ui.add(egui::Label::new(
                egui::RichText::new(
                    "\u{26a0} agent forwarding: the host at the other end can ask for signatures",
                )
                .size(th.body_size - 2.0)
                .color(th.danger),
            ));
        });
    });
}

/// The local process that put this scope name on the wire.
///
/// A guest ask legitimately has no `ASKED BY` row — there is no host process
/// behind the request, and a chain-shaped widget here would imply a check
/// that never happened. That absence was the last of the kind-forgery
/// problem: a local process could claim the guest kind and inherit it, so
/// declining to say who you are looked exactly like the design working as
/// intended.
///
/// This line is the difference. It is not the caller chain and not the
/// principal — the scope still gates, and no ancestry is walked — it is the
/// one thing the socket knows for certain: which process spoke. A genuine
/// request names a `secreq agent open` the user started, at the path they
/// installed. A forger names itself, in its own executable, and reads as a
/// process declining to be an agent rather than as a sandbox with no callers.
///
/// The daemon shows this instead of *refusing* an unrecognised peer, which
/// was the other option and the worse one: refusing is fail-closed, it breaks
/// a `cargo run` daemon talking to an installed `agent open`, and the escape
/// hatch it would need is a hole with a nicer name. Showing costs nothing and
/// leaves the judgement where the evidence is.
///
/// **It belongs to the `SCOPE` row rather than to a row of its own**, for two
/// reasons that agree. It reads as the sentence it is — "`brain-nx-t5`, named
/// by `secreq` at `/usr/local/bin/secreq`" — which binds the claim to its
/// claimant instead of leaving a reader to pair two labelled blocks. And it
/// costs the well no height: a separate row pushed `GUEST SAYS` and its "not
/// verifiable" marker clean out of the opening viewport on the taller
/// chromes, and a warning below the fold is not a warning.
///
/// The two identities sit side by side because that is where their value is.
/// `name` is `comm`, which the process chose, and a convincing forgery will
/// choose it convincingly; `exe` is what the kernel loaded. `secreq` beside
/// `/tmp/.build-cache/postinstall` is a contradiction nobody has to go
/// looking for. The peer's argv is deliberately absent — it restates the
/// scope, and it is the sender's to write.
fn render_scope_declarant(ui: &mut egui::Ui, th: &Theme, declared: Option<&LocalPeer>) {
    let Some(declared) = declared else {
        // The peer exited between `SO_PEERCRED` and the lookup. Said out
        // loud, because a prompt that looks identical whether or not it
        // checked is the failure this line exists to fix.
        ui.add(egui::Label::new(
            egui::RichText::new("\u{26a0} secreq could not read the process that named it")
                .size(th.body_size - 2.0)
                .color(th.danger),
        ));
        return;
    };
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.label(
            egui::RichText::new("named by")
                .size(th.body_size - 2.0)
                .color(th.faint),
        );
        ui.label(
            egui::RichText::new(&declared.name)
                .size(th.body_size - 2.0)
                .strong()
                .color(th.fg),
        );
        let pid_text = declared.pid.to_string();
        let exe_width = (ui.available_width() - 44.0).max(40.0);
        let row_height = ui.text_style_height(&egui::TextStyle::Body);
        ui.allocate_ui_with_layout(
            egui::vec2(exe_width, row_height),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_max_width(exe_width);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            declared
                                .exe
                                .as_deref()
                                .map_or_else(|| "executable unknown".to_owned(), abbreviate_home),
                        )
                        .monospace()
                        .size(th.body_size - 2.0)
                        // Full weight rather than the caller tree's dim argv
                        // colour: here the path is the evidence, not the
                        // annotation.
                        .color(th.fg),
                    )
                    .truncate(),
                );
            },
        );
        ui.label(
            egui::RichText::new(pid_text)
                .size(th.body_size - 2.0)
                .color(th.faint),
        );
    });
}

/// The caveat that rides every rendering of a guest-reported chain, here and
/// in the audit view (`ui::render_guest_chain_row`).
///
/// One string rather than one per surface, deliberately. The prompt and the
/// log are read by the same person about the same event, and two phrasings of
/// "do not believe this" invite the reading that they mean different things.
pub(crate) const GUEST_CHAIN_CAVEAT: &str = "\u{26a0} guest-reported — NOT verifiable";

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
                egui::RichText::new(GUEST_CHAIN_CAVEAT)
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
                reason: None,
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
    match &row.representative.subject {
        AskSubject::ScopedAgent(agent) => std::borrow::Cow::Owned(format!("agent:{}", agent.scope)),
        AskSubject::Wrap(_) | AskSubject::SshSign(_) => {
            std::borrow::Cow::Borrowed(row.key.wrap.as_str())
        }
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

/// How many ancestry frames the tree draws before it starts counting
/// instead. Matches the audit view's [`super::ui::AUDIT_TREE_MAX_DEPTH`],
/// deliberately: the two
/// surfaces show the same chain, and a reader who learns the `… N more` row
/// in one should not meet a different rule in the other.
const CALLER_TREE_MAX_DEPTH: usize = 6;

/// Split a chain into the frames the tree draws and the frames the
/// `… N more` row stands in for, both still in storage order
/// (nearest-first).
///
/// The elided frames come out of the **middle**. A consent prompt is read
/// from both ends — the outermost frame answers "where did this come from"
/// (your terminal, or a launch daemon you never started) and the leaf
/// answers "what is asking right now" — so those are the two the tree keeps
/// when it can't keep everything.
fn caller_tree_split(callers: &[Caller]) -> (&[Caller], &[Caller]) {
    let hidden_len = callers.len().saturating_sub(CALLER_TREE_MAX_DEPTH);
    let (hidden, shown) = callers.split_at(hidden_len);
    (shown, hidden)
}

/// One line per elided frame for the overflow row's hover, outermost-first
/// so the hover continues the tree's reading order rather than reversing it.
fn caller_overflow_summary(hidden: &[Caller]) -> String {
    hidden
        .iter()
        .rev()
        .map(|c| {
            let args = caller_args(&c.name, &c.command);
            if args.is_empty() {
                format!("{} (pid {})", c.name, c.pid)
            } else {
                format!("{} (pid {})  {}", c.name, c.pid, args)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The ancestry, root-first, each process with its argv and pid; the
/// asking leaf is the ask's own command, set in the accent so the eye
/// lands on who is actually asking. Truncated argv shows the full
/// string on hover.
///
/// A chain deeper than [`CALLER_TREE_MAX_DEPTH`] collapses its middle into a
/// single `… N more` row whose hover lists what it replaced — the same
/// indicator the audit view uses. Drawing every frame instead meant the
/// surface the decision is *made* on quietly claimed to be showing the whole
/// ancestry while `provenance::caller_chain` had already stopped walking at
/// 16, and the surface the decision is *reviewed* on was the only one that
/// said so.
///
/// Two different things can be missing, and the tree says both in the same
/// `…` idiom at the position each is missing *from*:
///
/// - Frames the **tree** gave up sit in the middle, between the outermost
///   frame and the leaf, and their count is known.
/// - Frames the **walk** never read sit above everything, and their count is
///   not — the walk stopped precisely so it would not have to find out. That
///   row goes at the top, because without it the outermost frame the walk
///   happened to stop on is drawn exactly like a real root, and a caller deep
///   enough inside its own ancestry gets to choose which process the user
///   reads as the origin.
fn render_caller_tree(ui: &mut egui::Ui, th: &Theme, row: &QueueRow) {
    let ask = &row.representative;
    let (shown, hidden) = caller_tree_split(ask.callers());
    let mut depth = 0usize;
    if ask.callers_truncated() {
        caller_unwalked_row(ui, th, depth);
        depth += 1;
    }
    for caller in shown.iter().rev() {
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
    if !hidden.is_empty() {
        caller_overflow_row(ui, th, depth, hidden);
        depth += 1;
    }
    let leaf_argv = crate::rules::joined_argv(&ask.command);
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

/// The `… N more` row standing in for the elided middle of the chain.
///
/// Rendered in `th.faint` at the tree's own indent so it reads as a gap in
/// the ancestry rather than as another process. The hover carries every
/// frame it replaced, which is what keeps this an honest summary instead of
/// a second way to hide something.
fn caller_overflow_row(ui: &mut egui::Ui, th: &Theme, depth: usize, hidden: &[Caller]) {
    elision_row(
        ui,
        th,
        depth,
        &format!("\u{2026} {} more", hidden.len()),
        &caller_overflow_summary(hidden),
    );
}

/// The row standing in for the ancestry above where the walk stopped.
///
/// Deliberately **uncounted**. Every other elision in this UI names a number
/// because it is standing in for frames it holds; this one is standing in for
/// frames nothing ever read, and printing a number here would be the prompt
/// asserting something it went out of its way not to learn. `… more above`
/// is the whole claim: there is ancestry past this row, and secreq did not
/// look at it.
///
/// It draws at depth 0, above the outermost frame, because that is where the
/// missing frames would have been — the reader's eye lands on it before the
/// row it would otherwise have read as the origin.
fn caller_unwalked_row(ui: &mut egui::Ui, th: &Theme, depth: usize) {
    elision_row(
        ui,
        th,
        depth,
        "\u{2026} more above",
        "secreq stops walking the process tree after 16 frames.\n\
         Whatever launched this is further up and was not read.",
    );
}

/// One `…` row of the caller tree: the tree's indent and elbow, then faint
/// text with an explanatory hover.
///
/// Shared by both elisions on purpose. They say different things, but they
/// are the same *kind* of statement — "the tree is not showing you
/// everything, here" — and a reader who learns one should not have to learn
/// a second visual language for the other.
fn elision_row(ui: &mut egui::Ui, th: &Theme, depth: usize, text: &str, hover: &str) {
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
        ui.label(
            egui::RichText::new(text)
                .size(th.body_size - 2.0)
                .color(th.faint),
        )
        .on_hover_text(hover.to_owned());
    });
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
///
/// "Fixed" has to mean a floor as well as a ceiling. A ceiling alone stops a
/// long name shoving the buttons right, but the box then *shrinks* to a short
/// one and drags them left — so which pixel "Approve for 30 min" occupies
/// still depended on a string the requester picked. See
/// `a_hostile_ask_cannot_move_a_decision_control`.
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
/// above, which renders the same pid on that frame's row — except under agent
/// forwarding, where the anchor is the socket peer and the tree starts above
/// it. That case says `Forwarded:` instead of `Session:` and the well's
/// `FORWARDED BY` row draws the frame, because a grant row naming a process
/// nothing else on screen mentions is the failure this row exists to avoid.
fn render_ssh_session_grants(
    ui: &mut egui::Ui,
    th: &Theme,
    row: &QueueRow,
    actions_out: &mut Vec<PendingAction>,
) {
    let anchor = match &row.representative.subject {
        AskSubject::SshSign(s) => s.info.anchor.as_ref(),
        AskSubject::Wrap(_) | AskSubject::ScopedAgent(_) => None,
    };
    let forwarded = anchor.is_some_and(|a| a.kind == SignAnchorKind::ForwardedSsh);
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(if forwarded { "Forwarded:" } else { "Session:" })
                .size(th.body_size - 2.0)
                // The label is the whole difference between "this grant dies
                // with your terminal" and "this grant is live for a machine
                // you are logged in to", so the forwarded spelling is not
                // allowed to read as quietly as the ordinary one.
                .color(if forwarded { th.danger } else { th.faint }),
        );
        if let Some(anchor) = anchor {
            let full = format!("{} · {}", anchor.name, anchor.pid);
            let row_height = ui.text_style_height(&egui::TextStyle::Body);
            let resp = ui
                .allocate_ui_with_layout(
                    egui::vec2(SESSION_LABEL_WIDTH, row_height),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.set_min_width(SESSION_LABEL_WIDTH);
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
            resp.on_hover_text(if forwarded {
                format!(
                    "This ssh client is forwarding your agent, so a 30-minute grant \
                     attaches to it and ends when the SSH session does.\n{full}"
                )
            } else {
                format!("A 30-minute grant attaches to this process.\n{full}")
            });
        }
        let scope = row_scope(row);
        if quiet_button(ui, th, "Approve for 30 min").clicked() {
            actions_out.push(PendingAction {
                key: row.key.clone(),
                decision: Decision::ApproveSshSession,
                reason: None,
                scope,
            });
        }
        if quiet_button(ui, th, "All keys for 30 min").clicked() {
            actions_out.push(PendingAction {
                key: row.key.clone(),
                decision: Decision::ApproveSshSessionAll,
                reason: None,
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
    match row.representative.subject {
        AskSubject::SshSign(_) => "Signing\u{2026}",
        AskSubject::Wrap(_) | AskSubject::ScopedAgent(_) => "Resolving\u{2026}",
    }
}

/// Everything the user needs in front of them to decide, in a band the
/// scrolling body cannot reach: what secreq's own log says about this caller,
/// any TTL'd grant the ask offers, and the decision row itself.
///
/// The split this band sits below is the prompt's security boundary, not a
/// layout preference. Above it is content the requester supplies — argv, a
/// process tree, a secret set, a cwd — all of it unbounded and all of it free
/// to scroll. Below it is what the user must read and what they act with, and
/// **nothing above the split can move anything below it**, because the two
/// are placed by explicit rect rather than by a shared cursor.
///
/// This is the same attack the argv cap in `provenance::sanitize_display`
/// answers, arriving through a different door: make the prompt say less than
/// it appears to by pushing the part that matters off-screen. Capping each
/// lever narrows it one lever at a time; a band the levers cannot reach ends
/// the shape.
#[allow(clippy::too_many_arguments)]
fn render_decision_band(
    ui: &mut egui::Ui,
    th: &Theme,
    current: Option<&QueueRow>,
    snapshot: &QueueSnapshot,
    state: &mut PromptWindowState,
    actions_out: &mut Vec<PendingAction>,
    out: &mut PromptOutput,
) {
    if let Some(row) = current {
        let margin = egui::Margin {
            left: INSET_X,
            right: INSET_X,
            top: 4,
            bottom: 0,
        };
        egui::Frame::new().inner_margin(margin).show(ui, |ui| {
            render_history_row(ui, th, row, state);
            // The two non-wrap kinds each offer a TTL grant above the
            // decision row; a wrap ask's "remember" lives in that row's
            // Approve instead.
            if row.status == super::proto::RowStatus::Awaiting {
                match &row.representative.subject {
                    AskSubject::SshSign(_) => {
                        render_ssh_session_grants(ui, th, row, actions_out);
                    }
                    AskSubject::ScopedAgent(_) => {
                        render_agent_session_grant(ui, th, row, actions_out);
                    }
                    AskSubject::Wrap(_) => {}
                }
                render_denial_reason_input(ui, th, state);
            }
        });
    }
    render_footer(ui, th, current, snapshot, state, actions_out, out);
}

/// How tall the decision band will come out, by laying it out and looking.
///
/// This is a *sizing pass*, the same device [`egui::Area`] uses to place a
/// popup whose size it has never seen: the band is drawn into a child `Ui`
/// built [`egui::UiBuilder::invisible`], which turns every shape it paints
/// into a `Shape::Noop` and disables its widgets, so nothing lands in the
/// frame's output, nothing hovers and nothing can be clicked. What survives
/// is the one thing we came for — the `min_rect` the content grew to, margins
/// included.
///
/// It is laid out against the whole window rather than a guess at the
/// band, because width is what the content is actually sensitive to
/// (Windows splits the available width between two buttons, GNOME centers
/// its meta line in it) and an unconstrained height is what lets the
/// content report its natural one. The decisions and the manager hand-off
/// go to scratch buffers that are dropped on return: a disabled widget
/// cannot report a click, and this makes it impossible for one to be
/// counted twice even if that ever changed.
fn measure_decision_band(
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
            .id_salt("prompt-band-measure")
            .max_rect(full)
            .invisible(),
    );
    render_decision_band(
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

/// Optional explanation attached to Deny. It is always present so a denial
/// with no explanation remains one click / one shortcut; typing is available
/// when the extra audit context is worth it.
fn render_denial_reason_input(ui: &mut egui::Ui, th: &Theme, state: &mut PromptWindowState) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("Reason (optional)")
                .size(th.body_size - 1.0)
                .color(th.dim),
        );
        ui.add(
            egui::TextEdit::singleline(&mut state.denial_reason)
                .hint_text("Why deny?")
                .desired_width(ui.available_width()),
        );
    });
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
    let awaiting = current.is_some_and(|r| r.status == super::proto::RowStatus::Awaiting);
    let more_waiting = snapshot.entries.len().saturating_sub(1);
    // Dims the key hints while a stray keystroke still can't decide.
    let armed = state.keyboard_armed();

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
                                if mnemonic_button(
                                    ui,
                                    th,
                                    "Approve",
                                    KeyHint::Chord(approve_chord(th.flavor)),
                                    true,
                                    armed,
                                )
                                .clicked()
                                {
                                    actions_out.push(PendingAction {
                                        key: row.key.clone(),
                                        decision: approve_decision(row),
                                        reason: None,
                                        scope: row_scope(row),
                                    });
                                }
                                if mnemonic_button(
                                    ui,
                                    th,
                                    "Deny",
                                    KeyHint::Mnemonic('D'),
                                    false,
                                    armed,
                                )
                                .clicked()
                                {
                                    actions_out.push(PendingAction {
                                        key: row.key.clone(),
                                        decision: Decision::Deny,
                                        reason: denial_reason(state),
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
                            if mnemonic_button_sized(
                                ui,
                                th,
                                "Approve",
                                KeyHint::Chord(approve_chord(th.flavor)),
                                true,
                                w,
                                armed,
                            )
                            .clicked()
                            {
                                actions_out.push(PendingAction {
                                    key: row.key.clone(),
                                    decision: approve_decision(row),
                                    reason: None,
                                    scope: row_scope(row),
                                });
                            }
                            if mnemonic_button_sized(
                                ui,
                                th,
                                "Deny",
                                KeyHint::Mnemonic('D'),
                                false,
                                w,
                                armed,
                            )
                            .clicked()
                            {
                                actions_out.push(PendingAction {
                                    key: row.key.clone(),
                                    decision: Decision::Deny,
                                    reason: denial_reason(state),
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
                        if gnome_response(
                            ui,
                            th,
                            left,
                            "Deny",
                            KeyHint::Mnemonic('D'),
                            false,
                            armed,
                        )
                        .clicked()
                        {
                            actions_out.push(PendingAction {
                                key: row.key.clone(),
                                decision: Decision::Deny,
                                reason: denial_reason(state),
                                scope: row_scope(row),
                            });
                        }
                        if gnome_response(
                            ui,
                            th,
                            right,
                            "Approve",
                            KeyHint::Chord(approve_chord(th.flavor)),
                            true,
                            armed,
                        )
                        .clicked()
                        {
                            actions_out.push(PendingAction {
                                key: row.key.clone(),
                                decision: approve_decision(row),
                                reason: None,
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

/// How a decision button spells its keyboard binding.
///
/// Deny still carries an underlined mnemonic because its binding is a
/// bare letter. Approve carries a written-out chord instead, because
/// `⌘↩` is not a character in the word "Approve" and pretending otherwise
/// is how the underlined `A` came to advertise a binding that no longer
/// existed.
enum KeyHint<'a> {
    /// Underline this character in the label.
    Mnemonic(char),
    /// Append this chord after the label.
    Chord(&'a str),
}

/// The chord that approves, spelled for the chrome being drawn.
///
/// Keyed off the rendered flavour rather than `cfg!(target_os)` so the
/// screenshot matrix — which draws all three chromes on one machine —
/// publishes each platform's real chord instead of the host's. At runtime
/// `OsFlavor` is itself derived from `cfg!`, so live windows agree with
/// what egui's `command_only()` actually matches.
fn approve_chord(flavor: OsFlavor) -> &'static str {
    match flavor {
        OsFlavor::MacOs => "⌘↩",
        OsFlavor::Windows | OsFlavor::Gnome => "Ctrl+↩",
    }
}

/// Dimming applied to a key hint when the keyboard is armed, and when it
/// is not. The hint is always quieter than the label it annotates; while
/// disarmed it recedes further, which is the whole of the disarmed
/// affordance. The button itself never dims — it stays clickable, and a
/// click is precisely what arms the keyboard.
/// Chosen by looking at the rendered fixtures, not by taste in the
/// abstract. An earlier 0.65/0.28 pair was a real 2.3× difference in the
/// layout snapshot and still indistinguishable on screen: the chord sits
/// in white on the saturated accent fill, where dropping alpha converges
/// toward the button colour instead of reading as faded. The armed state
/// is near-opaque now so the disarmed one has somewhere to fall from.
const HINT_ARMED: f32 = 0.92;
const HINT_DISARMED: f32 = 0.22;
/// Space between a button's label and its trailing chord.
const CHORD_GAP: f32 = 6.0;

/// Button label carrying its keyboard hint, dimmed per `armed`.
fn mnemonic_job(
    th: &Theme,
    label: &str,
    hint: KeyHint<'_>,
    fg: egui::Color32,
    armed: bool,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let base = egui::TextFormat {
        font_id: egui::FontId::proportional(th.body_size),
        color: fg,
        ..Default::default()
    };
    let hint_color = fg.gamma_multiply(if armed { HINT_ARMED } else { HINT_DISARMED });
    match hint {
        KeyHint::Mnemonic(mnemonic) => {
            let underlined = egui::TextFormat {
                underline: egui::Stroke::new(1.0, hint_color),
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
        }
        KeyHint::Chord(chord) => {
            job.append(label, 0.0, base.clone());
            job.append(
                chord,
                CHORD_GAP,
                egui::TextFormat {
                    color: hint_color,
                    ..base
                },
            );
        }
    }
    job
}

fn mnemonic_button(
    ui: &mut egui::Ui,
    th: &Theme,
    label: &str,
    hint: KeyHint<'_>,
    default: bool,
    armed: bool,
) -> egui::Response {
    let (fill, fg, stroke) = if default {
        (th.accent, th.accent_fg, egui::Stroke::new(1.0, th.accent))
    } else {
        (th.btn, th.btn_fg, egui::Stroke::new(1.0, th.btn_border))
    };
    ui.add(
        egui::Button::new(mnemonic_job(th, label, hint, fg, armed))
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
    hint: KeyHint<'_>,
    default: bool,
    width: f32,
    armed: bool,
) -> egui::Response {
    let (fill, fg, stroke) = if default {
        (th.accent, th.accent_fg, egui::Stroke::new(1.0, th.accent))
    } else {
        (th.btn, th.btn_fg, egui::Stroke::new(1.0, th.btn_border))
    };
    ui.add_sized(
        egui::vec2(width, 30.0),
        egui::Button::new(mnemonic_job(th, label, hint, fg, armed))
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
    hint: KeyHint<'_>,
    suggested: bool,
    armed: bool,
) -> egui::Response {
    let resp = ui.interact(rect, ui.id().with(label), egui::Sense::click());
    if resp.hovered() {
        ui.painter().rect_filled(rect, 0.0, th.raised);
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    let fg = if suggested { th.accent_text } else { th.fg };
    let mut job = mnemonic_job(th, label, hint, fg, armed);
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
///
/// The height grew with the pinned decision band. HISTORY used to be the
/// evidence well's last row and shared the body's scroll with it; now it sits
/// below the split in a block of its own, so a window of the old height
/// showed one fewer row of ancestry than it used to. Pinning what the user
/// decides with is meant to cost the requester's evidence nothing, and a
/// window that gives back exactly the height the band took is what makes that
/// true.
pub const PROMPT_DEFAULT_SIZE: [f32; 2] = [500.0, 510.0];

/// Small helper the child uses to time repaints for "Ns ago" labels.
pub fn age_label(age: Duration) -> String {
    humanize_duration(age)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(pid: u32, name: &str) -> Caller {
        Caller {
            pid,
            name: name.to_owned(),
            command: format!("{name} --run"),
            exe: None,
            start_time: 0,
        }
    }

    /// A chain that fits draws whole, with nothing standing in for anything.
    #[test]
    fn a_short_chain_hides_nothing() {
        let chain: Vec<Caller> = (0..4).map(|i| caller(100 + i, "sh")).collect();
        let (shown, hidden) = caller_tree_split(&chain);
        assert_eq!(shown.len(), 4);
        assert!(hidden.is_empty());
    }

    /// The case the prompt used to get wrong: `caller_chain` stops at 16
    /// frames, the prompt drew all 16 as if that were the whole story, and
    /// the audit view — the surface for *reviewing* a decision — was the
    /// only one that admitted to eliding anything.
    #[test]
    fn a_long_chain_keeps_the_root_and_the_leaf_and_counts_the_rest() {
        // Storage is nearest-first: pid 100 is the immediate caller,
        // pid 115 the outermost frame.
        let chain: Vec<Caller> = (0..16).map(|i| caller(100 + i, "node")).collect();
        let (shown, hidden) = caller_tree_split(&chain);

        assert_eq!(shown.len(), CALLER_TREE_MAX_DEPTH);
        assert_eq!(hidden.len(), 16 - CALLER_TREE_MAX_DEPTH);

        // The outermost frame survives — "where did this ultimately come
        // from" is half of what the tree is read for.
        assert_eq!(shown.last().expect("outermost").pid, 115);
        // The elided frames are the middle ones, and the frame nearest the
        // asking command is the *last* thing given up.
        assert_eq!(hidden.first().expect("nearest hidden").pid, 100);
        assert_eq!(hidden.last().expect("furthest hidden").pid, 109);
    }

    /// Exactly at the cap is not overflow; one past it is.
    #[test]
    fn the_indicator_appears_only_once_a_frame_is_actually_hidden() {
        let exact: Vec<Caller> = (0..CALLER_TREE_MAX_DEPTH as u32)
            .map(|i| caller(i, "sh"))
            .collect();
        assert!(caller_tree_split(&exact).1.is_empty());

        let over: Vec<Caller> = (0..CALLER_TREE_MAX_DEPTH as u32 + 1)
            .map(|i| caller(i, "sh"))
            .collect();
        assert_eq!(caller_tree_split(&over).1.len(), 1);
    }

    /// The hover has to carry what the row replaced, in the order the tree
    /// reads — outermost first, continuing downward toward the leaf.
    #[test]
    fn the_overflow_hover_lists_hidden_frames_outermost_first() {
        let chain: Vec<Caller> = vec![caller(100, "make"), caller(101, "bash")];
        let summary = caller_overflow_summary(&chain);
        let lines: Vec<&str> = summary.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("bash (pid 101)"), "got {:?}", lines[0]);
        assert!(lines[1].starts_with("make (pid 100)"), "got {:?}", lines[1]);
        assert!(lines[0].contains("--run"), "argv is the point of the hover");
    }

    /// A frame whose argv adds nothing over its name renders as just the
    /// name and pid, the same rule the visible rows follow.
    #[test]
    fn the_overflow_hover_omits_a_redundant_argv() {
        let mut c = caller(7, "zsh");
        c.command = "zsh".to_owned();
        assert_eq!(caller_overflow_summary(&[c]), "zsh (pid 7)");
    }

    // ── The viewport property ────────────────────────────────────────────
    //
    // *Nothing a caller controls may move a decision control out of the
    // initial viewport.*
    //
    // This is the A4 shape — "make the prompt say less than it appears to" —
    // and the caller chain is one lever for it among several. Capping the
    // chain narrows the lever; it does not close the shape, because the argv
    // column, the secret set and the cwd are all caller-influenced too. What
    // closes it is structural: the decision controls are laid out in a band
    // the scrolling body cannot reach.
    //
    // The tests below lay the real `render_prompt_panel` out on a plain
    // `egui::Context` at the production viewport size and compare a benign
    // ask against the most hostile one the wire admits. If the two agree on
    // where every control landed, no content between them moved anything.

    use super::super::proto::{
        Ask, AskAnchor, AskSubject, DedupeKey, RowStatus, SecretAsk, SshAnchorInfo, SshAskInfo,
        SshSubject, WrapSubject,
    };
    use super::super::state::{QueueRow, QueueSnapshot};

    /// Every string in the prompt that the user must be able to read *before*
    /// deciding: the two decisions, the two SSH grants, and the label over
    /// secreq's own record of what this caller did last time.
    const DECISION_CONTROLS: &[&str] = &[
        "Approve",
        "Deny",
        "Approve for 30 min",
        "All keys for 30 min",
        "HISTORY",
    ];

    fn ssh_row(callers: Vec<Caller>, truncated: bool, cwd: &str) -> QueueRow {
        let anchor = callers.last().map(|c| SshAnchorInfo {
            name: c.name.clone(),
            pid: c.pid,
            kind: SignAnchorKind::Session,
            command: None,
        });
        let key = DedupeKey {
            wrap: "ssh:github".to_owned(),
            anchor: AskAnchor::Process(ProcessIdentity {
                pid: callers.first().map_or(0, |c| c.pid),
                start_time: 0,
            }),
            subject_digest: None,
        };
        QueueRow {
            key: key.clone(),
            representative: Ask {
                command: vec!["ssh-sign github".to_owned()],
                dedupe_key: key,
                subject: AskSubject::SshSign(SshSubject {
                    cwd: cwd.to_owned(),
                    callers,
                    callers_truncated: truncated,
                    info: SshAskInfo {
                        key_id: "github".to_owned(),
                        fingerprint: "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM"
                            .to_owned(),
                        reason: Some("git pushes to github.com".to_owned()),
                        anchor,
                    },
                }),
            },
            waiter_count: 1,
            first_seen: std::time::Instant::now(),
            status: RowStatus::Awaiting,
        }
    }

    fn wrap_row(callers: Vec<Caller>, truncated: bool, secrets: Vec<SecretAsk>) -> QueueRow {
        let key = DedupeKey {
            wrap: "npm".to_owned(),
            anchor: AskAnchor::Process(ProcessIdentity {
                pid: callers.first().map_or(0, |c| c.pid),
                start_time: 0,
            }),
            subject_digest: None,
        };
        QueueRow {
            key: key.clone(),
            representative: Ask {
                command: vec!["npm".to_owned(), "publish".to_owned()],
                dedupe_key: key,
                subject: AskSubject::Wrap(WrapSubject {
                    cwd: "/home/dev/repos/acme".to_owned(),
                    callers,
                    callers_truncated: truncated,
                    secrets,
                    providers: std::collections::HashMap::new(),
                    allow_remember: true,
                    nested_run: false,
                    ignore_remembered: false,
                }),
            },
            waiter_count: 1,
            first_seen: std::time::Instant::now(),
            status: RowStatus::Awaiting,
        }
    }

    fn secret(name: &str) -> SecretAsk {
        SecretAsk {
            declared_as: None,
            ttl: crate::wraps::CacheTtl::default(),
            name: name.to_owned(),
            provider: "op".to_owned(),
            locator: format!("op://Dev/npm/{name}"),
            default: None,
            description: None,
            reason: None,
            requested_by: vec![],
        }
    }

    /// The scope the prompt offers is the value the daemon writes into the
    /// approvals cache. For a row anchored to a `run` session or a scoped
    /// agent's socket there is no honest one — the second number is a random
    /// nonce or a placeholder — and this function used to invent it anyway,
    /// packing both into a `ProcessIdentity` and shipping it over the socket.
    /// Nothing stored it, because those asks answer `allow_remember()` with
    /// `false`; a flag in the daemon was standing in for a type here.
    #[test]
    fn a_row_that_names_no_process_offers_no_scope() {
        let process_row = wrap_row(vec![caller(7926, "-zsh")], false, vec![]);
        assert_eq!(
            row_scope(&process_row),
            Some(ProcessIdentity {
                pid: 7926,
                start_time: 0,
            }),
            "a wrap row's parent is a real process and is the scope"
        );

        let mut session_row = process_row.clone();
        session_row.key.anchor = AskAnchor::RunSession {
            pid: 7926,
            nonce: 12_345_678_901_234_567_890,
        };
        assert_eq!(
            row_scope(&session_row),
            None,
            "a session nonce is not a start time, so there is no scope to send"
        );

        let mut agent_row = process_row;
        agent_row.key.anchor = AskAnchor::AgentSocket { pid: 4242 };
        assert_eq!(
            row_scope(&agent_row),
            None,
            "a guest's principal is its scope, and the socket pid is not a scope"
        );
    }

    /// The worst chain the wire admits: the walk's full 16 frames, each with
    /// an argv at `provenance::MAX_DISPLAY_CHARS`, and the walk itself
    /// reporting that it stopped short — so the tree draws both elisions on
    /// top of six full-width rows.
    fn hostile_chain() -> Vec<Caller> {
        (0..16)
            .map(|i| Caller {
                pid: 9000 + i,
                name: "n".repeat(40),
                command: format!("{} {}", "n".repeat(40), "A".repeat(300)),
                exe: None,
                start_time: 0,
            })
            .collect()
    }

    /// Lay the prompt out at the production viewport and return where every
    /// painted text run landed, keyed by its string.
    ///
    /// Keyed by text because that is the only stable name a widget has here:
    /// egui ids are positional and would change for the very reason this test
    /// exists. Every string in [`DECISION_CONTROLS`] is unique on the surface.
    fn control_positions(row: QueueRow) -> std::collections::BTreeMap<String, egui::Pos2> {
        let size = egui::vec2(PROMPT_DEFAULT_SIZE[0], PROMPT_DEFAULT_SIZE[1]);
        let ctx = egui::Context::default();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            ..Default::default()
        };
        let snapshot = QueueSnapshot { entries: vec![row] };
        let mut state = PromptWindowState::new();

        // Twice: egui settles container sizes on the pass after first sight,
        // and a one-shot capture records the unsettled frame. Same reason the
        // screenshot harness's layout capture runs two passes.
        let mut output = None;
        for _ in 0..2 {
            output = Some(ctx.run_ui(input.clone(), |ui| {
                let mut actions = Vec::new();
                let panel_ctx = ui.ctx().clone();
                render_prompt_panel(&panel_ctx, ui, &snapshot, None, &mut state, &mut actions);
            }));
        }

        let mut found = std::collections::BTreeMap::new();
        for clipped in &output.expect("two layout passes ran").shapes {
            collect_text(&clipped.shape, &mut found);
        }
        found
    }

    /// Find a decision control by label.
    ///
    /// Approve paints its keyboard chord into the same galley, so its text
    /// is `Approve⌘↩` on macOS and `ApproveCtrl+↩` elsewhere — an exact
    /// lookup would pass on one CI runner and fail on the other. A bare
    /// `starts_with` is not enough either: `Approve` prefixes
    /// `Approve for 30 min`, and the `BTreeMap` would hand back the grant
    /// button's position instead. So: exact match first, then the label
    /// followed by a chord and nothing else.
    fn control_pos(
        map: &std::collections::BTreeMap<String, egui::Pos2>,
        label: &str,
    ) -> Option<egui::Pos2> {
        if let Some(pos) = map.get(label) {
            return Some(*pos);
        }
        map.iter()
            .find(|(text, _)| {
                text.strip_prefix(label)
                    .is_some_and(|rest| rest.starts_with('⌘') || rest.starts_with("Ctrl"))
            })
            .map(|(_, pos)| *pos)
    }

    fn collect_text(shape: &egui::Shape, out: &mut std::collections::BTreeMap<String, egui::Pos2>) {
        match shape {
            egui::Shape::Text(text) => {
                out.insert(text.galley.text().to_owned(), text.pos);
            }
            egui::Shape::Vec(inner) => {
                for s in inner {
                    collect_text(s, out);
                }
            }
            _ => {}
        }
    }

    /// The property, stated directly: swap the most hostile ask the wire
    /// admits in for a benign one and every decision control stays exactly
    /// where it was.
    ///
    /// Before the decision band was pinned, a deep chain scrolled `HISTORY`
    /// and both grant buttons off the bottom of the prompt window — the
    /// `29-ssh-session-anchor` fixture had to give up its `IN` row to fit
    /// them, which is the bug demonstrating itself inside published
    /// documentation.
    #[test]
    fn a_hostile_ask_cannot_move_a_decision_control() {
        let benign = control_positions(ssh_row(
            vec![caller(7926, "zsh"), caller(8120, "git")],
            false,
            "/home/dev/repos/acme",
        ));
        let hostile = control_positions(ssh_row(hostile_chain(), true, "/home/dev/repos/acme"));

        for label in DECISION_CONTROLS {
            let (a, b) = (control_pos(&benign, label), control_pos(&hostile, label));
            assert!(a.is_some(), "benign prompt painted no {label:?}");
            assert_eq!(
                a, b,
                "{label:?} moved when the caller chain grew: {a:?} → {b:?}"
            );
        }
    }

    /// The same property from the other side: wherever the controls landed,
    /// they landed *on screen*. Equality alone would be satisfied by two
    /// prompts that both put Approve below the fold.
    #[test]
    fn every_decision_control_lands_inside_the_initial_viewport() {
        let hostile = control_positions(ssh_row(hostile_chain(), true, "/home/dev/repos/acme"));
        for label in DECISION_CONTROLS {
            let pos = control_pos(&hostile, label).unwrap_or_else(|| {
                panic!("the prompt painted no {label:?} at all");
            });
            assert!(
                pos.y >= 0.0 && pos.y < PROMPT_DEFAULT_SIZE[1],
                "{label:?} was painted at y={} in a {}pt window",
                pos.y,
                PROMPT_DEFAULT_SIZE[1],
            );
        }
    }

    /// The row the walk's ceiling is now allowed to draw. Without it the
    /// prompt's topmost frame is the frame the walk happened to stop on, drawn
    /// exactly like a real root — so a caller sixteen deep in its own ancestry
    /// picks which process the user reads as the origin.
    #[test]
    fn a_walk_that_stopped_short_says_so_above_the_outermost_frame() {
        let whole = control_positions(wrap_row(
            (0..16).map(|i| caller(9000 + i, "node")).collect(),
            false,
            vec![secret("NPM_TOKEN")],
        ));
        assert!(
            !whole.contains_key("\u{2026} more above"),
            "a chain the walk saw all of must not claim there is more"
        );

        let clipped = control_positions(wrap_row(
            (0..16).map(|i| caller(9000 + i, "node")).collect(),
            true,
            vec![secret("NPM_TOKEN")],
        ));
        let pos = clipped
            .get("\u{2026} more above")
            .expect("a truncated walk must say so");
        // Above every frame the tree drew: the missing ancestors would have
        // been outside the outermost one, and that is where the gap belongs.
        let topmost_frame = clipped.get("node").expect("the tree drew its frames").y;
        assert!(
            pos.y < topmost_frame,
            "the unwalked row landed at y={} but the tree starts at y={topmost_frame}",
            pos.y,
        );
    }

    /// A wrap ask has no grant buttons, so its whole decision surface is
    /// `HISTORY` plus the footer — and a big secret set is a second lever on
    /// the same body. Covered separately because the two ask kinds reserve
    /// different amounts of band and only one of them has grants to displace.
    #[test]
    fn a_wraps_secret_set_cannot_move_a_decision_control_either() {
        let benign = control_positions(wrap_row(
            vec![caller(7926, "zsh")],
            false,
            vec![secret("NPM_TOKEN")],
        ));
        let hostile = control_positions(wrap_row(
            hostile_chain(),
            true,
            (0..40).map(|i| secret(&format!("TOKEN_{i}"))).collect(),
        ));

        for label in ["Approve", "Deny", "HISTORY"] {
            assert_eq!(
                benign.get(label),
                hostile.get(label),
                "{label:?} moved when the ask grew"
            );
        }
    }
}
