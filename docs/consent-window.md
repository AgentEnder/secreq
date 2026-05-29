# The consent window

When a wrap runs for the first time from a given parent process,
`secreq` shows a small native window asking you to approve the
release. The window is owned by a background daemon
(see [`cli.md`](./cli.md) under `daemon`); it's invisible by default
and pops up only when there's a decision to make or you ask for it
explicitly via `secreq pending` / `secreq view`.

## What it looks like

The window has two tabs at the top:

- **Pending** — consent requests waiting on your decision. Empty most
  of the time.
- **Audit log** — read-only history of past grant decisions. Names
  only; no secret values ever appear here.

The header line on the right shows the count of pending requests when
there are any, e.g. `3 pending across 2 processes`.

## Pending tab

Requests are grouped into a **process tree**: each ancestor process is
a node, the wrap being asked about hangs off its direct parent as a
leaf. Renders with `pstree`-style connectors (`├──`, `└──`, `│`):

```
Superset.app   pid 2831                                  [Approve all] [Deny all]
├── zsh   pid 7926                                      [Approve all] [Deny all]
│   ⊙ gh repo list                       12s ago    [Approve] [Deny]
│     ↳ approved 3h ago · 8 grants / 0 denies in 30d
│     • GITHUB_TOKEN via op  op://Personal/GitHub/credential
└── zsh   pid 7927                                      [Approve all] [Deny all]
    ⊙ aws s3 ls                          14s ago    [Approve] [Deny]
      ↳ first request from this caller
      • AWS_ACCESS_KEY_ID via op  …
```

### Approve all / Deny all (per process)

Every process node carries `[Approve all]` and `[Deny all]` buttons.
Clicking at a given node:

- **Resolves every queued wrap in that node's subtree** with the same
  decision (one click, many waiters).
- For `Approve all`, **remembers the decision at that node's scope**.
  Any future ask from any descendant of that node will hit the
  in-memory cache without re-prompting.

That's the load-bearing feature: clicking `Approve all` on
`Superset.app` once means the app's nested shells/scripts won't ask
again for the wraps they currently have queued. The scope is the
ancestor you clicked at, *not* the leaf.

### Approve / Deny (per leaf)

Per-row `[Approve]` and `[Deny]` are one-shot — same scope as the
direct parent, but they don't remember. Use when you want to release
secrets for *this* invocation only.

### Keyboard shortcuts (Pending tab only)

| Key | Effect |
|---|---|
| **Enter** | Approve all + remember for the **top-of-tree root** (the broadest scope on screen — typically "I trust this app"). |
| **Esc** | Deny all for the top-of-tree root. |

Per-leaf approve is mouse-only on purpose; it's a granular escape
hatch, not the default decision.

### Audit hints under each leaf

Each wrap leaf shows a one-line history summary built from your audit
log:

- `↳ first request from this caller` — fresh combination, nothing in
  history.
- `↳ approved 3h ago · 8 grants / 0 denies in 30d` — last decision +
  counts within a 30-day window.
- A last decision of `deny` gets a warning tint to draw the eye.

Counts match on **wrap + direct-caller process name**, so a `gh` from
your zsh and a `gh` from a Cron-spawned shell get different histories.

### Folded runs

When the same command shells into itself many times (e.g. `gh` calls
`gh` calls `gh` …), the chain collapses into one row with a `× N`
badge. Hover for the pid range; approve at this row applies to every
folded level.

## Audit log tab

Lists past grant decisions, newest first. Each row shows:

- Relative timestamp (`3h ago`)
- The wrap (`gh`, `aws`, …)
- The direct caller (`zsh`, `npm`, …)
- The decision (`approved`, `approved + remembered`, `denied` —
  colour-coded)
- The env-var names released (`GITHUB_TOKEN`)
- The cwd at the time of the decision

Up to 200 entries are rendered at once; the cache itself keeps a soft
ceiling of 5,000 in memory.

`secreq view` opens the window with this tab already selected and
**pins** the window so it doesn't auto-hide when the queue is empty.
Closing the window with the close button exits viewer mode but leaves
the daemon running.

## The audit log file

The audit tab reads from `$XDG_STATE_HOME/secreq/audit.log` (or
`~/.local/state/secreq/audit.log`). It's append-only JSON Lines —
greppable from the shell:

```sh
tail -f ~/.local/state/secreq/audit.log
jq -c 'select(.decision == "deny")' ~/.local/state/secreq/audit.log
```

Each line:

```json
{
  "ts_unix": 1748549237,
  "cwd": "/Users/you/repos/my-app",
  "command": ["wrap gh"],
  "callers": ["zsh", "iTerm2"],
  "secrets": ["GITHUB_TOKEN"],
  "decision": "approve+remember"
}
```

| Field | Notes |
|---|---|
| `ts_unix` | Seconds since the Unix epoch. |
| `cwd` | Working directory of the `wrap` invocation. |
| `command` | `["wrap <binary>"]` — the wrap name, not the full child argv (which could contain secrets in flags). |
| `callers` | Parent-process **names** only (no pids), nearest first. |
| `secrets` | Names of the env vars released. **Never values.** |
| `decision` | `"approve"`, `"approve+remember"`, or `"deny"`. |

The audit log is **never** written by the daemon — every `secreq`
client writes its own entry after the daemon replies. That means the
log captures fully-attributed grants even if the daemon crashes
between decision and append.

## Closing the window

The close button (or `Cmd+W` on macOS) **hides** the window; it
doesn't kill the daemon. Your in-memory approvals cache stays intact.

The supported ways to actually stop the daemon are:

- `secreq daemon stop` — graceful, clears the cache.
- `secreq daemon stop --force` — SIGKILLs the daemon when it's wedged.
- Walk away — the daemon idle-exits after 30 minutes of empty queue.

On macOS the daemon's activation policy is set to `Accessory`, so it
doesn't show in the Dock or Cmd+Tab while the window is hidden.
