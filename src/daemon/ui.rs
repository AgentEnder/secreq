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

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;

use crate::audit::{self, AuditEntry};
use crate::consent::Decision;

use super::proto::{Caller, DedupeKey, SecretAsk};
use super::state::{ApprovalScope, QueueRow, QueueSnapshot, SharedState};

/// How long the daemon stays alive with an empty queue before idle-exiting.
pub const IDLE_EXIT_SECS: u64 = 30 * 60;

/// How long after the queue empties before we hide the window.
const HIDE_GRACE_SECS: u64 = 2;

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

const COLOR_APPROVE_BG: egui::Color32 = egui::Color32::from_rgb(46, 125, 50);
const COLOR_APPROVE_BG_HOVER: egui::Color32 = egui::Color32::from_rgb(60, 145, 65);
const COLOR_DENY_BG: egui::Color32 = egui::Color32::from_rgb(176, 50, 50);
const COLOR_DENY_BG_HOVER: egui::Color32 = egui::Color32::from_rgb(196, 70, 70);
const COLOR_ACCENT: egui::Color32 = egui::Color32::from_rgb(120, 170, 230);
const COLOR_MUTED: egui::Color32 = egui::Color32::from_gray(140);

/// One pending decision queued for after the render pass. Carries the
/// scope so a bulk-approve at an ancestor writes the approval entry at
/// that ancestor's `(pid, start_time)`, not the leaf's direct parent.
#[derive(Debug, Clone)]
struct PendingAction {
    key: DedupeKey,
    decision: Decision,
    scope: ApprovalScope,
}

pub struct ConsentApp {
    state: SharedState,
    shutdown_flag: Arc<AtomicBool>,
    queue_emptied_at: Option<Instant>,
    last_window_visible: bool,
    /// Per-node collapsed state. Keyed on `(pid, start_time)` so it
    /// survives across queue churn for the same process.
    collapsed: HashMap<(u32, u64), bool>,
    /// Parsed view of `audit.log`. Refreshed when the file's mtime moves
    /// (or once every `AUDIT_REFRESH_SECS`), used to render the "last time
    /// this wrap ran from this caller" summary line under each leaf.
    audit: AuditCache,
    /// Which page the UI is currently showing. Pending is the default
    /// because the window is most often shown in response to a fresh
    /// ask; `secreq view` rises the tab to Audit on entry instead.
    current_tab: Tab,
    /// Rising-edge tracker for viewer mode so we can switch the
    /// default tab to Audit exactly once when `secreq view` opens us.
    last_viewer_mode: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Pending,
    Audit,
}

impl ConsentApp {
    pub fn new(state: SharedState, shutdown_flag: Arc<AtomicBool>) -> ConsentApp {
        ConsentApp {
            state,
            shutdown_flag,
            queue_emptied_at: None,
            last_window_visible: false,
            collapsed: HashMap::new(),
            audit: AuditCache::new(),
            current_tab: Tab::Pending,
            last_viewer_mode: false,
        }
    }
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
    /// (one of "approve", "approve+remember", "deny").
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
/// touching the filesystem. Matches on `command[0] == "wrap <wrap>"` and,
/// when `caller_name` is supplied, the direct (callers[0]) caller.
fn summarize_history(
    entries: &[AuditEntry],
    wrap: &str,
    caller_name: Option<&str>,
    now_unix: u64,
) -> WrapHistorySummary {
    let cutoff = now_unix.saturating_sub(AUDIT_WINDOW_SECS);
    let cmd_marker = format!("wrap {wrap}");
    let mut out = WrapHistorySummary::default();
    for e in entries {
        let cmd_matches = e.command.first().map(|c| c == &cmd_marker).unwrap_or(false);
        if !cmd_matches {
            continue;
        }
        if let Some(cn) = caller_name {
            let direct = e.callers.first().map(|s| s.as_str()).unwrap_or("");
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
            "approve" | "approve+remember" => out.approve_count += 1,
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

impl eframe::App for ConsentApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Snapshot under the mutex, release before drawing.
        let (snapshot, window_visible, last_activity, queue_empty, viewer_mode) = {
            let guard = self.state.lock().expect("state mutex");
            (
                guard.snapshot(),
                guard.window_visible(),
                guard.last_activity(),
                guard.queue_is_empty(),
                guard.viewer_mode(),
            )
        };
        // `secreq view` just opened us → switch to the Audit tab so the
        // user lands on the history they came to read. Other show paths
        // (auto-spawn on an ask, `secreq pending`) leave the tab alone.
        if viewer_mode && !self.last_viewer_mode {
            self.current_tab = Tab::Audit;
        }
        self.last_viewer_mode = viewer_mode;

        // External shutdown (`secreq daemon stop`): the socket thread
        // flips the flag inside State, the UI tick converts that to a
        // viewport close. Idle-exit uses the same path, just sets the
        // flag itself first.
        if self.shutdown_flag.load(Ordering::SeqCst) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        // The window's close button (or Cmd+W on macOS) sends a close
        // request through the windowing layer. We veto it and hide the
        // window instead — clicking the X shouldn't terminate the
        // daemon and forget every "approve all" the user gave. The
        // legitimate ways out remain `secreq daemon stop`, idle exit
        // after IDLE_EXIT_SECS, and SIGKILL.
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            let mut guard = self.state.lock().expect("state mutex");
            guard.hide_window();
            // Bump activity so the idle-exit timer doesn't fire right
            // after the user actively dismissed the window.
            guard.touch();
        }

        // Viewer mode pauses both the idle-exit and the empty-queue
        // auto-hide. The user explicitly pinned the window open — both
        // counters should stay frozen while they browse.
        if queue_empty
            && !viewer_mode
            && last_activity.elapsed() >= Duration::from_secs(IDLE_EXIT_SECS)
        {
            self.shutdown_flag.store(true, Ordering::SeqCst);
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        if queue_empty && !viewer_mode {
            let emptied_at = *self.queue_emptied_at.get_or_insert_with(Instant::now);
            if emptied_at.elapsed() >= Duration::from_secs(HIDE_GRACE_SECS) && window_visible {
                self.state.lock().expect("state mutex").hide_window();
            }
        } else {
            self.queue_emptied_at = None;
        }

        let visible_now = self.state.lock().expect("state mutex").window_visible();
        if visible_now != self.last_window_visible {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(visible_now));
            if visible_now {
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            }
            self.last_window_visible = visible_now;
        }

        ctx.request_repaint_after(Duration::from_millis(500));

        if !visible_now {
            return;
        }

        // History view is a window-visible-only cost; no point keeping it
        // warm while the daemon is hidden.
        self.audit.refresh_if_stale();

        let tree = build_tree(&snapshot);

        // ── Keyboard ─────────────────────────────────────────────────
        //
        // Enter approves the top root subtree (the broadest scope on
        // screen — exactly the "I trust this app" decision); Esc denies
        // the top root subtree. Scoped to the Pending tab so they don't
        // misfire while the user is reading audit history. No keyboard
        // path for per-leaf approve; that's mouse-only on purpose
        // because it's the granular escape hatch, not the default.
        let mut actions: Vec<PendingAction> = Vec::new();
        if self.current_tab == Tab::Pending {
            if let Some(&top_root) = tree.roots.first() {
                ctx.input(|i| {
                    if i.key_pressed(egui::Key::Enter) {
                        collect_subtree_actions(
                            &tree,
                            top_root,
                            Decision::ApproveRemember,
                            &mut actions,
                        );
                    } else if i.key_pressed(egui::Key::Escape) {
                        collect_subtree_actions(&tree, top_root, Decision::Deny, &mut actions);
                    }
                });
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            render_header(ui, &tree, viewer_mode);
            ui.add_space(6.0);
            render_tab_bar(ui, &mut self.current_tab, &tree, self.audit.entries.len());
            ui.add_space(6.0);
            ui.separator();
            ui.add_space(8.0);

            match self.current_tab {
                Tab::Pending => {
                    render_pending_page(ui, &tree, &mut self.collapsed, &mut actions, &self.audit)
                }
                Tab::Audit => render_audit_page(ui, &self.audit),
            }
        });

        // Apply actions after rendering. Approvals are in-memory only —
        // no disk write to schedule.
        if !actions.is_empty() {
            let mut guard = self.state.lock().expect("state mutex");
            for act in actions {
                guard.resolve(&act.key, act.decision, act.scope);
            }
        }
    }
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
        out.push(PendingAction {
            key: row.key.clone(),
            decision,
            scope,
        });
    });
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

fn render_header(ui: &mut egui::Ui, tree: &ProcessTree, viewer_mode: bool) {
    let pending = tree.total_leaf_rows();
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("secreq")
                .size(20.0)
                .strong()
                .color(COLOR_ACCENT),
        );
        let subtitle = if viewer_mode {
            "— viewer (pinned)"
        } else {
            "— consent requests"
        };
        ui.label(egui::RichText::new(subtitle).size(16.0).color(COLOR_MUTED));
        if pending > 0 {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = if tree.roots.len() > 1 {
                    format!("{pending} pending across {} processes", tree.roots.len())
                } else {
                    format!("{pending} pending")
                };
                ui.label(egui::RichText::new(label).size(13.0).color(COLOR_ACCENT));
            });
        }
    });
}

fn render_tab_bar(ui: &mut egui::Ui, current: &mut Tab, tree: &ProcessTree, audit_count: usize) {
    let pending = tree.total_leaf_rows();
    ui.horizontal(|ui| {
        // selectable_label gives us the "tab" look (highlighted when
        // selected, click to switch) without needing a separate widget.
        let pending_label = if pending > 0 {
            format!("Pending · {pending}")
        } else {
            "Pending".to_owned()
        };
        if ui
            .selectable_label(*current == Tab::Pending, pending_label)
            .clicked()
        {
            *current = Tab::Pending;
        }
        let audit_label = if audit_count > 0 {
            format!("Audit log · {audit_count}")
        } else {
            "Audit log".to_owned()
        };
        if ui
            .selectable_label(*current == Tab::Audit, audit_label)
            .clicked()
        {
            *current = Tab::Audit;
        }
    });
}

fn render_pending_page(
    ui: &mut egui::Ui,
    tree: &ProcessTree,
    collapsed: &mut HashMap<(u32, u64), bool>,
    actions: &mut Vec<PendingAction>,
    audit: &AuditCache,
) {
    if tree.roots.is_empty() {
        render_empty_state(ui);
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

fn render_audit_page(ui: &mut egui::Ui, audit: &AuditCache) {
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
    let now = now_unix();
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // Newest first — that's what you want to scan in a console
            // session. Cap the render to a couple hundred entries; the
            // cache itself already keeps a soft limit (5k).
            for (i, entry) in audit.entries.iter().rev().take(200).enumerate() {
                if i > 0 {
                    ui.add_space(2.0);
                    ui.separator();
                    ui.add_space(2.0);
                }
                render_audit_entry(ui, entry, now);
            }
        });
}

fn render_audit_entry(ui: &mut egui::Ui, entry: &AuditEntry, now: u64) {
    // `command[0]` is `"wrap <binary>"` per the audit-writer convention
    // in commands.rs; show just the binary part.
    let wrap = entry
        .command
        .first()
        .map(|s| s.strip_prefix("wrap ").unwrap_or(s.as_str()))
        .unwrap_or("(?)");
    let caller = entry.callers.first().map(String::as_str).unwrap_or("(?)");
    let ago_secs = now.saturating_sub(entry.ts_unix);
    let ago = humanize_duration(Duration::from_secs(ago_secs));
    let (verb, color) = match entry.decision.as_str() {
        "deny" => ("denied", COLOR_DENY_HINT),
        "approve" => ("approved", COLOR_APPROVE_BG),
        "approve+remember" => ("approved + remembered", COLOR_APPROVE_BG),
        other => (other, COLOR_MUTED),
    };
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(format!("{ago} ago"))
                .size(11.0)
                .color(COLOR_MUTED),
        );
        ui.label(egui::RichText::new("·").color(COLOR_MUTED));
        ui.label(
            egui::RichText::new(wrap)
                .font(egui::FontId::monospace(13.0))
                .strong(),
        );
        ui.label(egui::RichText::new("from").color(COLOR_MUTED));
        ui.label(
            egui::RichText::new(caller)
                .font(egui::FontId::monospace(12.0))
                .color(COLOR_ACCENT),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(verb).strong().color(color));
        });
    });
    if !entry.secrets.is_empty() {
        ui.horizontal(|ui| {
            ui.add_space(14.0);
            ui.label(egui::RichText::new("↳").color(COLOR_MUTED));
            let joined = entry.secrets.join(", ");
            let truncated = truncate_for_display(&joined, 80);
            let resp = ui.label(
                egui::RichText::new(&truncated)
                    .font(egui::FontId::monospace(11.0))
                    .color(COLOR_MUTED),
            );
            if truncated.len() < joined.len() {
                resp.on_hover_text(joined);
            }
        });
    }
    if !entry.cwd.is_empty() {
        ui.horizontal(|ui| {
            ui.add_space(14.0);
            let cwd_shown = truncate_for_display(&entry.cwd, 80);
            let resp = ui.label(
                egui::RichText::new(format!("cwd: {cwd_shown}"))
                    .size(10.0)
                    .color(COLOR_MUTED),
            );
            if cwd_shown.len() < entry.cwd.len() {
                resp.on_hover_text(&entry.cwd);
            }
        });
    }
}

fn render_empty_state(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(32.0);
        ui.label(egui::RichText::new("✓").size(48.0).color(COLOR_APPROVE_BG));
        ui.add_space(8.0);
        ui.label(egui::RichText::new("All clear").size(18.0).strong());
        ui.add_space(4.0);
        ui.label(egui::RichText::new("No pending consent requests.").color(COLOR_MUTED));
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new("This window will hide shortly.")
                .size(12.0)
                .italics()
                .color(COLOR_MUTED),
        );
    });
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
// We render the process tree as a single pane with classic `pstree`-style
// connectors (`├──`, `└──`, `│  `, `   `) instead of bare indentation.
// Each row computes its prefix from `last_path`: a slice of booleans where
// `last_path[i]` = "is the i-th descent step from the root the last
// child of its parent?". The vector grows by one each time we descend.
//
// Two helpers do the work:
//
// - [`tree_prefix`] produces the prefix used by a process node or a wrap
//   row — vertical bars for ancestors with more siblings below, plus a
//   `├──` or `└──` connector for this row.
// - [`continuation_prefix`] is what we use for annotations rendered
//   *under* a row (audit history, secret bullets, cwd) — same vertical
//   bars but no connector, so they sit visually inside the parent.

const PREFIX_UNIT: usize = 4; // characters per indentation step

fn tree_prefix(last_path: &[bool]) -> String {
    if last_path.is_empty() {
        return String::new();
    }
    let mut s = String::with_capacity(last_path.len() * PREFIX_UNIT);
    for &last in &last_path[..last_path.len() - 1] {
        s.push_str(if last { "    " } else { "│   " });
    }
    s.push_str(if *last_path.last().unwrap() {
        "└── "
    } else {
        "├── "
    });
    s
}

fn continuation_prefix(last_path: &[bool]) -> String {
    let mut s = String::with_capacity(last_path.len() * PREFIX_UNIT);
    for &last in last_path {
        s.push_str(if last { "    " } else { "│   " });
    }
    s
}

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

    ui.horizontal(|ui| {
        // Tree connector column. Roots (empty `last_path`) get nothing.
        let prefix = tree_prefix(last_path);
        if !prefix.is_empty() {
            ui.label(
                egui::RichText::new(prefix)
                    .font(egui::FontId::monospace(13.0))
                    .color(COLOR_MUTED),
            );
        }

        // Disclosure glyph: clickable when this node has anything to hide.
        if has_descendants {
            let glyph = if is_collapsed { "▸" } else { "▾" };
            let resp = ui.add(
                egui::Label::new(egui::RichText::new(glyph).size(13.0).color(COLOR_MUTED))
                    .sense(egui::Sense::click()),
            );
            if resp.clicked() {
                collapsed.insert(key, !is_collapsed);
            }
        } else {
            ui.add_space(12.0);
        }

        let display = node_display_name(node);
        let display_shown = truncate_for_display(&display, 56);
        // The top-of-tree root keeps the "active focus" accent on its
        // name (the per-root border is gone now that the tree is one
        // unified pane, so the colour is the only cue).
        let mut name_text = egui::RichText::new(&display_shown)
            .font(egui::FontId::monospace(13.0))
            .strong();
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
                .color(COLOR_MUTED),
        );
        // Folded-run badge: "× 15" when 15 identical levels collapsed
        // into this row. Hover reveals the full pid range that the row
        // stands in for, in case the user wants to verify it.
        if run_count > 1 {
            let badge = ui.label(
                egui::RichText::new(format!("× {run_count}"))
                    .size(11.0)
                    .strong()
                    .color(COLOR_ACCENT),
            );
            let tip = format!(
                "Folded a chain of {run_count} processes with the same command, \
                 from pid {} (outermost) to pid {} (innermost). Approving here \
                 applies to all of them.",
                node.pid, bottom.pid
            );
            badge.on_hover_text(tip);
        }
        if is_collapsed && descendant_count > 0 {
            ui.label(
                egui::RichText::new(format!("({descendant_count} hidden)"))
                    .size(11.0)
                    .color(COLOR_MUTED),
            );
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let deny_label = if is_top_root && depth == 0 {
                "Deny all (Esc)"
            } else {
                "Deny all"
            };
            if styled_button(ui, deny_label, ButtonRole::Deny).clicked() {
                collect_subtree_actions(tree, node_idx, Decision::Deny, actions);
            }
            ui.add_space(4.0);
            let approve_label = if is_top_root && depth == 0 {
                "Approve all (⏎)"
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
            ui.add_space(2.0);
            render_wrap_leaf(ui, row, scope, &next_path, actions, audit);
            i += 1;
        }
    }
}

fn render_wrap_leaf(
    ui: &mut egui::Ui,
    row: &QueueRow,
    scope: ApprovalScope,
    last_path: &[bool],
    actions: &mut Vec<PendingAction>,
    audit: &AuditCache,
) {
    let tree_pfx = tree_prefix(last_path);
    let cont_pfx = continuation_prefix(last_path);

    ui.horizontal(|ui| {
        if !tree_pfx.is_empty() {
            ui.label(
                egui::RichText::new(&tree_pfx)
                    .font(egui::FontId::monospace(13.0))
                    .color(COLOR_MUTED),
            );
        }
        ui.label(egui::RichText::new("⊙").color(COLOR_MUTED));
        let cmd = row.representative.command.join(" ");
        let truncated = truncate_for_display(&cmd, 50);
        let resp = ui.label(
            egui::RichText::new(&truncated)
                .font(egui::FontId::monospace(13.0))
                .strong(),
        );
        if truncated.len() < cmd.len() {
            resp.on_hover_text(cmd);
        }
        if row.waiter_count > 1 {
            ui.label(
                egui::RichText::new(format!("× {} waiting", row.waiter_count))
                    .size(11.0)
                    .strong()
                    .color(COLOR_ACCENT),
            );
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if small_button(ui, "Deny", ButtonRole::Deny).clicked() {
                actions.push(PendingAction {
                    key: row.key.clone(),
                    decision: Decision::Deny,
                    scope,
                });
            }
            ui.add_space(2.0);
            if small_button(ui, "Approve", ButtonRole::Approve).clicked() {
                // Per-row Approve is intentionally one-shot — same
                // scope, but `Decision::Approve` doesn't write the
                // cache. The bulk buttons are how you opt into
                // "remember at this scope."
                actions.push(PendingAction {
                    key: row.key.clone(),
                    decision: Decision::Approve,
                    scope,
                });
            }
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(format!(
                    "{} ago",
                    humanize_duration(row.first_seen.elapsed())
                ))
                .size(11.0)
                .color(COLOR_MUTED),
            );
        });
    });

    // Audit history line. Matches on wrap + direct-caller name so
    // siblings of the same shell get the same summary. Without a direct
    // caller (an orphaned ask) we fall back to wrap-only.
    let direct_caller = row.representative.callers.first().map(|c| c.name.as_str());
    let summary = audit.summarize(&row.key.wrap, direct_caller);
    render_audit_line(ui, &cont_pfx, &summary, now_unix());

    render_secrets(ui, &row.representative.secrets, &cont_pfx);

    if !row.representative.cwd.is_empty() {
        let cwd_shown = truncate_for_display(&row.representative.cwd, 70);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(format!("{cont_pfx}    "))
                    .font(egui::FontId::monospace(13.0))
                    .color(COLOR_MUTED),
            );
            let resp = ui.label(
                egui::RichText::new(format!("cwd: {cwd_shown}"))
                    .size(11.0)
                    .color(COLOR_MUTED),
            );
            if cwd_shown.len() < row.representative.cwd.len() {
                resp.on_hover_text(&row.representative.cwd);
            }
        });
    }
}

/// One-line summary derived from `audit.log` history for this wrap +
/// caller. Empty history reads as "first request from this caller", a
/// reassuring counterpoint to wrap-rerun fatigue ("oh, I've approved this
/// 12 times before"). Color-coded only for the case worth a second look:
/// the last decision was a deny.
fn render_audit_line(ui: &mut egui::Ui, cont_pfx: &str, summary: &WrapHistorySummary, now: u64) {
    let (text, color) = format_audit_line(summary, now);
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(format!("{cont_pfx}    "))
                .font(egui::FontId::monospace(13.0))
                .color(COLOR_MUTED),
        );
        ui.label(egui::RichText::new(text).size(11.0).italics().color(color));
    });
}

const COLOR_DENY_HINT: egui::Color32 = egui::Color32::from_rgb(220, 130, 110);

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
        Some("approve") | Some("approve+remember") => ("approved", COLOR_MUTED),
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

fn render_secrets(ui: &mut egui::Ui, secrets: &[SecretAsk], cont_pfx: &str) {
    for s in secrets {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(format!("{cont_pfx}    "))
                    .font(egui::FontId::monospace(13.0))
                    .color(COLOR_MUTED),
            );
            ui.label(egui::RichText::new("•").color(COLOR_MUTED));
            ui.label(
                egui::RichText::new(&s.name)
                    .font(egui::FontId::monospace(12.0))
                    .strong(),
            );
            ui.label(egui::RichText::new("via").color(COLOR_MUTED));
            ui.label(
                egui::RichText::new(&s.provider)
                    .font(egui::FontId::monospace(12.0))
                    .color(COLOR_ACCENT),
            );
            if !s.locator.is_empty() {
                let loc_shown = truncate_for_display(&s.locator, 50);
                let resp = ui.label(
                    egui::RichText::new(&loc_shown)
                        .font(egui::FontId::monospace(11.0))
                        .color(COLOR_MUTED),
                );
                if loc_shown.len() < s.locator.len() {
                    resp.on_hover_text(&s.locator);
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
                ui.label(
                    egui::RichText::new(format!("{cont_pfx}      "))
                        .font(egui::FontId::monospace(13.0))
                        .color(COLOR_MUTED),
                );
                ui.label(
                    egui::RichText::new(why)
                        .size(11.0)
                        .italics()
                        .color(COLOR_MUTED),
                );
            });
        }
    }
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
    let rounding = ui.visuals().widgets.hovered.rounding;
    ui.painter().rect_filled(resp.rect, rounding, hover);
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
    use crate::daemon::proto::Ask;
    use std::collections::HashMap;

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
            },
            waiter_count: 1,
            first_seen: Instant::now() - Duration::from_secs(secs_ago),
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
    fn truncate_keeps_short_strings_as_is_and_ellipsizes_long_ones() {
        assert_eq!(truncate_for_display("hi", 10), "hi");
        assert_eq!(truncate_for_display("1234567890", 5), "1234…");
        let s = "café-au-lait-très-longue";
        let t = truncate_for_display(s, 8);
        assert!(t.ends_with('…'));
        assert!(t.chars().count() == 8);
    }

    #[test]
    fn tree_prefix_at_root_is_empty() {
        assert_eq!(tree_prefix(&[]), "");
    }

    #[test]
    fn tree_prefix_uses_branch_for_non_last_and_tail_for_last() {
        // Direct child of root.
        assert_eq!(tree_prefix(&[false]), "├── ");
        assert_eq!(tree_prefix(&[true]), "└── ");
    }

    #[test]
    fn tree_prefix_continues_vertical_bars_under_non_last_ancestors() {
        // Path: root → middle (NOT last) → leaf (last sibling).
        // Middle is non-last, so its column draws `│   `; leaf gets `└── `.
        assert_eq!(tree_prefix(&[false, true]), "│   └── ");
        // Both non-last.
        assert_eq!(tree_prefix(&[false, false]), "│   ├── ");
        // Middle is last → its column is blank, no vertical bar to
        // continue. Leaf is non-last under it: branch connector only.
        assert_eq!(tree_prefix(&[true, false]), "    ├── ");
    }

    #[test]
    fn continuation_prefix_matches_tree_prefix_columns_without_connector() {
        // Annotations under a row should align under that row's
        // connector slot. Each entry contributes "│   " or "    " — no
        // ├── tail.
        assert_eq!(continuation_prefix(&[]), "");
        assert_eq!(continuation_prefix(&[false]), "│   ");
        assert_eq!(continuation_prefix(&[true]), "    ");
        assert_eq!(continuation_prefix(&[false, true]), "│       ");
    }

    fn mk_audit(ts: u64, wrap: &str, caller: &str, decision: &str) -> AuditEntry {
        AuditEntry {
            ts_unix: ts,
            cwd: String::new(),
            command: vec![format!("wrap {wrap}")],
            callers: vec![caller.to_owned()],
            secrets: vec![],
            decision: decision.to_owned(),
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
