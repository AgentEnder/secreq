# The windows

When a wrap runs and nothing already answers for it, `secreq` shows a small
native window asking whether to release the secret. There are **two
windows**, and they have different jobs:

- **The prompt** is transient. It holds exactly one request and exists to
  get an answer out of you. It appears on its own and goes away on its own.
- **The manager** is persistent. It holds your rules and your audit
  history, everything you browse rather than decide. You open it yourself,
  and close it yourself.

They are split so that the window which interrupts you only ever asks one
question, and the window you go looking for never interrupts you at all.

## The prompt

::shot{id=02-single-pending}

The header says what wants what, with the command underneath. Below it is
the **evidence well**: the facts you need in order to answer, in the order
you need them. Then the decision.

**SECRET** names the environment variable being released and the locator it
resolves from. A request for more than one names them all; past five they
group by locator prefix in a scroll-capped grid, so the decision buttons
never leave the window.

::shot{id=28-prompt-many-secrets}

**ASKED BY** is the process chain that led here, nearest last, each entry
carrying its argv and pid. This is the row that makes the question answerable:
`gh` asking from your shell and `gh` asking from an `npm` postinstall hook
look identical without it.

::shot{id=03-nested-tree}

When a command re-executes itself, as `gh` calling `gh` calling `gh` does,
the chain folds to one entry per distinct process rather than stacking
identical rows.

::shot{id=05-folded-run}

**IN** is the working directory the request came from.

**HISTORY** shows how you answered last time, for this wrap and this direct
caller. `first request from this caller` means the combination is new. A
previous **deny** is tinted, so a repeat request from something you already
turned down is hard to approve out of habit.

::shot{id=06-pending-denied-last}

History matches on the wrap plus the direct caller's process name, so `gh`
from your shell and `gh` from a cron-spawned shell carry separate
histories.

### Deciding

**Approve** releases the secret. **Deny** aborts the run; the wrapped binary
never starts. <kbd>A</kbd> or <kbd>Enter</kbd> approves, <kbd>D</kbd> or
<kbd>Esc</kbd> denies. The buttons carry the same letters as underlined
mnemonics. Keys are live only while a decision is actually pending, and the
prompt has no text fields, so bare letters are safe to press.

For an ordinary wrap, Approve also **remembers**, scoped to the process that
asked. That scoping, and why it has no TTL, is in
[wraps](./wraps.md#how-approval-is-scoped).

After you approve, the prompt goes read-only and reports `Resolving…` while
your provider is called, which is when a biometric prompt may appear on top
of it.

::shot{id=23-pending-resolving}

Only the oldest request is shown. Anything else queued sits behind an
`N more waiting` line rather than opening a second window:

::shot{id=04-multi-root}

If a command exits before you get to it, because you closed the terminal or
an ancestor died and took it down, the daemon reaps the request and records
it as `abandoned`. Nothing is released, and it is not counted as a denial.

### When a rule answers first

If one of your [rules](#rules) matches, the request never reaches you. An
auto-deny says so, naming the rule that fired and the message you gave it:

::shot{id=12-auto-deny-toast}

### Other kinds of request

The prompt shapes itself to what is being asked for.

**SSH signatures.** The well leads with the key fingerprint and the client's
stated reason instead of a secret name, and the quiet buttons offer session
grants (this key for 30 minutes, or every key) rather than a remembered
approval. See [ssh-agent](./ssh-agent.md).

::shot{id=24-ssh-sign-pending}

**Sandboxes.** A request arriving over a scoped agent socket has no host
process tree behind it, so there is no ASKED BY and no IN. The scope you
declared when you opened the socket is the principal. See
[secret-agent](./secret-agent.md).

::shot{id=34-agent-scope-pending}

**Gate-only wraps.** A wrap with no secrets still asks; the SECRET row
gives way to a gate-only marker. See
[wraps](./wraps.md#gate-only-wraps).

### The badge

While anything is waiting, a small always-on-top pill sits above your other
windows, so a backgrounded prompt can't be forgotten. Clicking it raises
the prompt.

::shot{id=26-badge-three-pending}

## The manager

Open it from the prompt's `Open Manager…` link, or with `secreq view`, which
lands on Audit. A segmented control switches between the two views, and the
header's search field binds to whichever is active.

The manager never holds a pending decision (that is the prompt's job), so
browsing your history never blocks a waiting request:

::shot{id=14-audit-tab-with-pending}

### Rules

Rules answer for you. Each matches on the wrap, the argv and the ancestor
process, and either approves or denies. Rows show how often a rule has
fired, when it last fired, and which secrets it was trained on; a rule can
be disabled without deleting it.

::shot{id=09-rules-tab-list}

New rules are written in a form here, or edited in place:

::shot{id=11-rules-form-edit-deny}

secreq also watches what you keep approving and proposes the rule you were
about to write, with the cluster of decisions it drew from. Saved rules
sort above suggestions.

::shot{id=13-rules-tab-suggestions}

Deny rules win over approve rules, and the most specific approve wins ties.
For decisions pattern matching can't express, see
[wasm-rules](./wasm-rules.md).

### Audit

Every decision, newest first: what asked, what it wanted, where from, and
how it went. Your answers, rule auto-fires, refused sandbox requests and
abandoned requests all land in the same list.

::shot{id=07-audit-tab}

Search narrows across every field at once and reports how much of the log
you're looking at. Each term may match a different field, so `gh auth` finds
the row where both are true.

::shot{id=15-audit-tab-search-filtering}

Up to 200 rows render at once; the cache holds a soft ceiling of 5,000.

## The audit log file

The manager reads `~/.secreq/audit.log` (or `$SECREQ_HOME/audit.log`). It is
append-only JSON Lines, so the shell can read it too:

```sh
tail -f ~/.secreq/audit.log
jq -c 'select(.decision | startswith("deny"))' ~/.secreq/audit.log
```

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

`secrets` holds **names only, never values**. That is the invariant the
whole file rests on. Three fields appear only when they apply: `rule_id` on
auto-decisions, `fingerprint` (of the **public** key) on SSH sign rows, and
`unverified_guest_chain` for a chain a sandbox guest reported about itself.
That last one is a claim rather than evidence, so it is kept out of `callers`
and never read by rule matching.

The `decision` values distinguish what you did from what happened without
you:

| `decision`                | Meaning                                                                          |
| ------------------------- | -------------------------------------------------------------------------------- |
| `approve`                 | You approved this run only.                                                      |
| `approve+remember`        | You approved and the parent scope was cached.                                    |
| `approve+cached`          | Released without asking; the cache already had a matching grant.                 |
| `approve+auto`            | Released by a matching approve rule. Carries `rule_id`.                          |
| `approve+ssh-session`     | You approved a signature and granted this key for the session.                   |
| `approve+ssh-session-all` | You approved a signature and granted every key for the session.                  |
| `approve+agent-session`   | You approved a sandbox request and granted its scope for the TTL.                |
| `deny`                    | You denied it.                                                                   |
| `deny+auto`               | Refused by a matching deny rule. Carries `rule_id`.                              |
| `deny+out-of-scope`       | A sandbox asked for something outside its allowlist. Refused without asking you. |
| `abandoned`               | The requesting process exited before you decided. Nothing was released.          |

The distinctions are the point. `approve` and `approve+cached` both mean the
secret went out, but only one means you were asked. `deny` versus
`deny+out-of-scope` separates "I refused this" from "a sandbox probed for
something it was never offered."

::shot{id=27-audit-tab-abandoned}

The **wrap client** writes the log after the daemon replies; the daemon does
not. A grant is therefore recorded with full attribution even if the daemon
dies between the decision and the write. Two cases have no client to do it,
so the daemon writes them itself: SSH signatures, where the daemon _is_ the
agent, and abandoned requests, where the client is already gone.

## The daemon behind them

Closing either window leaves the daemon running and your approvals cache
intact. The prompt also hides itself a couple of seconds after the queue
drains. To actually stop it:

- `secreq daemon stop`: graceful; clears the cache.
- `secreq daemon stop --force`: SIGKILL, for when it is wedged.
- Do nothing; it idle-exits after two hours with an empty queue.

On macOS the daemon runs with the `Accessory` activation policy, so it stays
out of the Dock and out of Cmd-Tab while no window is showing.
