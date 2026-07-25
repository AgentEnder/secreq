# The consent window

When a wrap runs and nothing already answers for it, `secreq` shows a
small native window asking whether to release the secret. The window is
owned by a background daemon (see [`cli.md`](./cli.md) under `daemon`);
it stays out of your way and appears only when there is a decision to
make, or when you ask for it with `secreq pending` / `secreq view`.

There are **two windows**, and they have different jobs:

- **The prompt** is transient. It holds exactly one request and exists
  to get an answer out of you. It appears on its own and goes away on
  its own.
- **The manager** is persistent. It holds your rules and your audit
  history — everything you browse rather than decide. You open it
  deliberately and close it yourself.

Splitting them is the point: the window that interrupts you asks one
question, and the window you go looking for never interrupts you.

## The prompt

::shot{id=02-single-pending}

The header says what wants what, with the command underneath. Below it
is the **evidence well** — the facts you need to answer, in the order
you need them. Then the decision.

Only the oldest request is shown. Anything else queued sits behind a
`N more waiting` line rather than opening a second window.

### The evidence well

**SECRET** — the environment variable being released and the locator it
resolves from. A request for more than one names them all; past five,
they group by locator prefix in a scroll-capped grid so the decision
buttons never leave the window.

**ASKED BY** — the process chain that led here, nearest last, each entry
with its argv and pid. This is the row that makes the question
answerable: `gh` asking from your shell and `gh` asking from an `npm`
postinstall hook look identical without it.

::shot{id=03-nested-tree}

When a command re-executes itself — `gh` calling `gh` calling `gh` — the
chain folds to one entry per distinct process instead of stacking
identical rows.

::shot{id=05-folded-run}

**IN** — the working directory the request came from.

**HISTORY** — how you answered last time, for this wrap and this direct
caller. `first request from this caller` means the combination is new. A
previous **deny** is tinted, so a repeat request from something you
already turned down is hard to approve out of habit.

History matches on the wrap plus the direct caller's process name, so
`gh` from your shell and `gh` from a cron-spawned shell carry separate
histories.

### Deciding

**Approve** releases the secret. **Deny** aborts the run; the wrapped
binary never starts.

| Key | Effect |
|---|---|
| <kbd>A</kbd> or <kbd>Enter</kbd> | Approve |
| <kbd>D</kbd> or <kbd>Esc</kbd> | Deny |

The buttons carry the same letters as underlined mnemonics. Keys are
live only while the current request is actually awaiting a decision, and
the prompt has no text fields, so bare letters are safe to press.

For an ordinary wrap, Approve also **remembers**: the daemon caches
`(wrap, parent pid, parent start time)` and stops asking for that
combination. The scope is the process that asked — approve `gh` for your
shell and that shell keeps its approval, while a different shell, an
editor, or a build script each get asked in their own right. Descendants
of a process you already approved for ride the same grant.

The cache lives in the daemon's memory. It has **no TTL and no disk
persistence**: it dies with the daemon, and pid reuse cannot resurrect it
because the parent's start time is part of the key.

Two requests deliberately do not remember:

- **`secreq run`** invocations, whose identity is fixed and would
  over-match. They ask every time.
- **SSH signatures**, which have their own session grants (below).

After you approve, the prompt goes read-only and reports `Resolving…`
while your provider is called — which is when a biometric prompt may
appear on top of it.

::shot{id=23-pending-resolving}

### More than one request at once

Two unrelated commands can ask at the same time. The prompt focuses the
oldest and counts the rest:

::shot{id=04-multi-root}

Answer the visible one and the next takes its place.

If a command exits before you get to it — you closed the terminal, or an
ancestor died and took it down — the daemon reaps the request and records
it as `abandoned`. Nothing is released, and it is not counted as a denial.

### When a rule answers first

If one of your [rules](#rules) matches, the request never reaches you. An
auto-deny says so, naming the rule that fired and the message you gave it:

::shot{id=12-auto-deny-toast}

### Other kinds of request

The prompt shapes itself to what is being asked for.

**SSH signatures.** With `SSH_AUTH_SOCK` pointed at secreq, each
signature is gated. The well leads with the key fingerprint and the
client's stated reason instead of a secret name, and the quiet buttons
offer session grants — this key for 30 minutes, or every key — rather
than a remembered approval. See [`ssh-agent.md`](./ssh-agent.md).

::shot{id=24-ssh-sign-pending}

**Sandboxes.** A request arriving over a scoped agent socket has no host
process tree behind it, so there is no ASKED BY and no IN. The scope you
declared when you opened the socket is the principal, and the grant is a
5-minute TTL anchored to it. See [`secret-agent.md`](./secret-agent.md).

::shot{id=34-agent-scope-pending}

**Gate-only wraps.** A wrap with no secrets still asks — it puts a
consent step in front of a command that manages its own credentials. The
SECRET row gives way to a gate-only marker.

## The manager

The manager holds the two things worth browsing. A segmented control
switches between them, and the header's search field binds to whichever
view is active.

Open it from the prompt's `Open Manager…` link, or with `secreq view`,
which opens straight to the audit log.

### Rules

Rules answer for you. Each matches on the wrap, the argv, and the
ancestor process, and either approves or denies. Rows show how often a
rule has fired, when it last fired, and which secrets it was trained on;
a rule can be disabled without deleting it.

::shot{id=09-rules-tab-list}

secreq also watches what you keep approving and proposes the rule you
were about to write, with the cluster of decisions it drew from. Saved
rules sort above suggestions.

::shot{id=13-rules-tab-suggestions}

Deny rules win over approve rules, and the most specific approve wins
ties. For decisions that pattern matching cannot express, see
[`wasm-rules.md`](./wasm-rules.md).

### Audit

Every decision, newest first — what asked, what it wanted, where from,
and how it went. Your answers, rule auto-fires, refused sandbox
requests, and abandoned requests all land in the same list.

::shot{id=07-audit-tab}

Search narrows across every field at once, and reports how much of the
log you are looking at. Each term may match a different field, so
`gh auth` finds the row where both are true.

::shot{id=15-audit-tab-search-filtering}

Up to 200 rows render at once; the cache holds a soft ceiling of 5,000
in memory.

## The audit log file

The manager reads `$XDG_STATE_HOME/secreq/audit.log` (or
`~/.local/state/secreq/audit.log`). It is append-only JSON Lines, so the
shell can read it too:

```sh
tail -f ~/.local/state/secreq/audit.log
jq -c 'select(.decision | startswith("deny"))' ~/.local/state/secreq/audit.log
```

Each line:

```json
{
  "ts_unix": 1748549237,
  "cwd": "/Users/you/repos/my-app",
  "wrap": "gh",
  "args": ["repo", "list"],
  "callers": [
    { "pid": 7926, "name": "zsh", "command": "zsh" },
    { "pid": 2831, "name": "iTerm2", "command": "iTerm2" }
  ],
  "secrets": ["GITHUB_TOKEN"],
  "decision": "approve+remember"
}
```

| Field | Notes |
|---|---|
| `ts_unix` | Seconds since the Unix epoch. |
| `cwd` | Working directory of the invocation. |
| `wrap` | The wrap that ran — the binary name from `wraps.json5`. |
| `args` | The argv passed through to the wrapped binary. Empty where arguments do not apply. |
| `callers` | The caller chain, nearest first: pid, process name, and the argv shown at decision time. |
| `secrets` | Names of the secrets released. **Never values.** |
| `decision` | See the table below. |
| `rule_id` | The auto-rule that produced the decision. Present only on `approve+auto` / `deny+auto`. |
| `fingerprint` | SHA256 fingerprint of the **public** key, on SSH sign rows only. Never the private key, never the signature. |
| `unverified_guest_chain` | A caller chain a sandbox guest reported *about itself*. A claim, not evidence — deliberately kept out of `callers`, and never read back by rule matching. |

Decisions distinguish what you did from what happened without you:

| `decision` | Meaning |
|---|---|
| `approve` | You approved this run only. |
| `approve+remember` | You approved and the parent scope was cached. |
| `approve+cached` | Released without asking — the cache already had a matching grant. |
| `approve+auto` | Released by a matching approve rule. Carries `rule_id`. |
| `approve+ssh-session` | You approved a signature and granted this key for the session. |
| `approve+ssh-session-all` | You approved a signature and granted every key for the session. |
| `approve+agent-session` | You approved a sandbox request and granted its scope for the TTL. |
| `deny` | You denied it. |
| `deny+auto` | Refused by a matching deny rule. Carries `rule_id`. |
| `deny+out-of-scope` | A sandbox asked for something outside its allowlist. Refused without asking you. |
| `abandoned` | The requesting process exited before you decided. Nothing was released. |

The distinctions are the point: `approve` and `approve+cached` both mean
the secret went out, but only one of them means you were asked, and
`deny` versus `deny+out-of-scope` separates "I refused this" from "a
sandbox probed for something it was never offered."

The log is written by the **wrap client** after the daemon replies, not
by the daemon — so a grant is recorded with full attribution even if the
daemon dies between the decision and the write. Two cases have no client
to do it and are written by the daemon itself: SSH signatures (where the
daemon *is* the agent) and abandoned requests (where the client is
already gone).

## Windows, and the daemon behind them

Closing either window leaves the daemon running, and your approvals
cache intact. The prompt also hides itself a couple of seconds after the
queue drains.

To actually stop the daemon:

- `secreq daemon stop` — graceful; clears the cache.
- `secreq daemon stop --force` — SIGKILL, for when it is wedged.
- Do nothing — it idle-exits after two hours with an empty queue.

On macOS the daemon runs with the `Accessory` activation policy, so it
stays out of the Dock and out of Cmd-Tab while no window is showing.
