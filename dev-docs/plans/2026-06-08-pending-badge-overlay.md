# Pending-requests always-on-top badge

Status: design approved 2026-06-08

## Problem

A consent request blocks the requesting process **indefinitely** — there is
no timeout (`server.rs` and `ssh_agent.rs` both park on `rx.recv()` forever).
The consent window is deliberately ephemeral: it auto-exits when the queue
drains or when it loses focus (the macOS App-Nap / "forgotten window"
behaviour). The failure mode: the window gets backgrounded and forgotten while
processes stay hung, with no on-screen reminder that anything is waiting.

## Goal

While any request is pending, show a small **always-on-top floating badge**
("N pending") over all other apps so the queue can't be forgotten. Clicking it
raises the consent window.

## Decisions

- **Form:** floating always-on-top borderless pill badge.
- **Platform:** macOS-first, graceful degrade. macOS + X11 get true
  always-on-top; Wayland silently ignores it and shows a normal raised window
  (best-effort); headless gets no badge.
- **Process model:** a dedicated `secreq pending-badge` child, orchestrated by
  the daemon exactly like the consent window (one child per surface, single
  small viewport — sidesteps the eframe multi-viewport bugs we avoid).
- **Position/interaction:** fixed top-right corner, no drag, no persisted
  state. Single click asks the daemon to raise the consent window.
- **Timing:** badge appears immediately on the first pending request.
- **Persistence:** badge is a live counter — clicking raises the consent
  window but the badge stays up and decrements as requests resolve, vanishing
  only when the queue hits zero. It does **not** exit on focus loss (unlike the
  consent window).

## Architecture / lifecycle

```
queue becomes non-empty  ──▶  daemon: ensure_badge_window()
                                  └─ spawn `secreq pending-badge` (if none up)
                                       └─ connects back, subscribes to QueueSnapshot
queue count changes      ──▶  broadcast_consent_update()  (already exists)
                                  └─ badge re-renders "N pending"
queue drains to zero     ──▶  daemon: broadcast_badge_exit_please()
                                  └─ badge child exits
badge clicked            ──▶  ClientMsg::RaiseConsentRequested
                                  └─ daemon: ensure_consent_window() + raise
```

The badge subscribes to the **same** `QueueSnapshot` stream as the consent
window (`state.rs::broadcast_consent_update`). No new daemon data structures;
the count is the existing snapshot leaf-row count. Badge and consent window are
independent processes with independent lifecycles.

## Components

- `src/daemon/badge.rs` — `pending-badge` subcommand + eframe app (borderless,
  `with_always_on_top()`, `with_taskbar(false)`, top-right position, App-Nap
  disabled, 100ms repaint heartbeat). Mirrors `child.rs`.
- `src/daemon/ui.rs::render_badge(ui, count)` — single render fn (lives in
  `ui.rs` so the screenshot harness can reach it). Count-only, attention-red
  rounded pill, singular/plural handled.
- `state.rs` / `mod.rs` — `ensure_badge_window`, `broadcast_badge_exit_please`,
  a `Badge` subscriber kind sharing the snapshot broadcast.
- `proto.rs` — `ClientMsg::RaiseConsentRequested`, badge attach message,
  `DaemonMsg::BadgeExitPlease`.
- `server.rs` — handle badge attach + `RaiseConsentRequested`.

## Platform degradation

- macOS / X11: `with_always_on_top()` honoured.
- Wayland (detect via existing `$WAYLAND_DISPLAY` check in
  `client.rs::graphical_environment_available`): always-on-top ignored; spawn a
  normal small raised window, log once.
- Headless (`!gui_available`): no badge.

## Testing

- Screenshot fixtures (CLAUDE.md rule): `badge_three_pending` and
  `badge_one_pending` in `tests/ui_screenshots.rs`; regenerate PNGs; add README
  rows.
- Orchestration unit tests: queue non-empty ⇒ `ensure_badge_window`; queue
  drains ⇒ `badge_exit_please`; badge does **not** exit on focus loss.
