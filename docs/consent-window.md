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
never starts. The optional reason field adds context to the terminal and
audit row, but leaving it empty keeps Deny a single click or keystroke.
<kbd>Cmd</kbd><kbd>Enter</kbd> approves (<kbd>Ctrl</kbd><kbd>Enter</kbd> off
macOS), <kbd>D</kbd> or <kbd>Esc</kbd> denies. Each button shows its own
binding. Those shortcuts are live only while a decision is pending and the
reason field is not focused.

Approve takes a modifier and Deny does not, because the two mistakes cost
different amounts. A stray Deny costs you a re-run; a stray Approve hands
out a credential and records that you meant to.

**Closing the prompt denies.** There is no timeout on a waiting request, so
a dismissed window would otherwise leave the asking command hung with
nothing on screen. Dismissing the question answers it.

### The keyboard arms a moment after you arrive

The prompt appears above your other windows without taking focus, so it
cannot swallow a sentence you were part-way through typing. Keystrokes keep
going wherever they were already going.

Once you do focus the prompt, its shortcuts stay inert for half a second —
long enough to notice where your keys are now landing. Clicking anywhere in
the window skips that wait, since a click already says you meant to be here.
While the shortcuts are inert the key hints on the buttons are dimmed.

::shot{id=54-pending-denial-reason}

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
fired, when it last fired, its consultation wrap scope, and which secrets it
was trained on; a rule can be disabled without deleting it.

::shot{id=09-rules-tab-list}

The consultation scope is an outer gate, separate from a declarative rule's
wrap match. It is read-only in the declarative editor:

::shot{id=51-rules-wrap-scope}

New rules are written in a form here, or edited in place:

::shot{id=11-rules-form-edit-deny}

An existing scoped rule cannot be edited into a match outside that scope.
The form explains the conflict and refuses the save:

::shot{id=52-rules-form-wrap-scope-conflict}

secreq also watches what you keep approving and proposes the rule you were
about to write, with the cluster of decisions it drew from. Saved rules
sort above suggestions.

::shot{id=13-rules-tab-suggestions}

Deny rules win over approve rules, and the most specific approve wins ties.
For decisions pattern matching can't express, see
[wasm-rules](./wasm-rules.md).

A pattern containing `*`, `?` or `[` is a glob. One that does not parse as
a glob is refused: the rule keeps the text you typed, matches nothing, and
is badged here. `rules list` marks the row `[REFUSED: bad argv glob]` and
`rules show` prints the reason.

::shot{id=45-rules-pattern-refused}

Which way a refused rule fails depends on what it decides. A refused
approve approves nothing, so asks it covered reach you as they did before
you wrote it. A refused **deny** is the one that would otherwise go wrong:
rather than let another rule's approve carry an ask your deny was written
to stop, secreq asks you.

The form holds a rule to the same standard while you write it, so a rule
that saves is a rule that runs. A pattern that will not compile blocks
the save, with the glob parser's complaint under the field and the cost
spelled out beside it: a broken deny sends its asks here, a broken
approve fires never. The field your cursor is in is left alone until you
ask to save: `[` is a legal thing to have typed so far.

::shot{id=47-rules-form-bad-glob}

### Audit

Every decision, newest first: what asked, what it wanted, where from, and
how it went. Your answers, rule auto-fires, refused sandbox requests and
abandoned requests all land in the same list.

::shot{id=07-audit-tab}

When a person or auto-deny rule supplied a reason, the denial row shows it
under the requested secret names.

A row's process tree is the ancestry secreq walked at the time, and it says
when that walk was not the whole story. `… more above` means the walk stopped
at its limit of 16 frames, so whatever launched the command sits above the
top row and was never read. `… may be more above` marks a row written before
secreq recorded the difference: the log cannot say whether anything is
missing, and a tree drawn without the marker would put the walk's stopping
point where you look for the origin.

::shot{id=40-audit-chain-completeness}

An SSH sign row also says whether the request arrived through an agent you
forwarded. The `ssh` client that carried it is the process on the socket, and
a sign's tree starts above that, so `signed through a forwarded agent` is the
only place the row names the session a remote host could have been asking
from. `agent forwarding not recorded` marks a row written before secreq kept
the difference.

::shot{id=43-audit-forwarded-sign}

A sandbox request records the local process that named its scope. secreq
cannot tell a sandbox agent you started from a process claiming to be one, so
it writes down what the kernel said and leaves the reading to you: a genuine
request names the `secreq agent open` you started, at the path you installed
it to.

::shot{id=44-audit-agent-declared-by}

Search narrows across every field at once and reports how much of the log
you're looking at. Each term may match a different field, so `gh auth` finds
the row where both are true.

::shot{id=15-audit-tab-search-filtering}

That includes a sandbox's claimed chain, so filtering by a process name
does not skip the rows where something only said it was that process. A
row found that way arrives marked the way it always is: `guest says` is a
claim, the tree above it is not.

::shot{id=48-audit-search-guest-claim}

A run of requests that differ only in when they ran and which pids were
involved folds into one row with a count and a span. A sandbox can ask as
often as it likes, and without the fold a long enough run of refusals pushes
everything else off the page. The span is there because the count alone does
not say what happened: 47 attempts inside three seconds is a loop on the
socket, 47 across three hours is something on a timer.

::shot{id=49-audit-burst-collapsed}

Opening the group puts every attempt back, each with its own time. The fold
never crosses a day, and anything unlike the run ends it, so 47 refusals with
one approval among them are never drawn as 47 in a row. Search filters before
the fold, so a group cannot hide a row you searched for.

::shot{id=50-audit-burst-expanded}

None of this touches the file. `audit.log` keeps every request as its own
line, unchanged, whatever the view does with it.

Up to 200 groups render at once; the cache holds a soft ceiling of 5,000
rows.

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
  "callers_truncated": false,
  "secrets": ["GITHUB_TOKEN"],
  "decision": "approve+remember"
}
```

`secrets` holds **names only, never values**. That is the invariant the
whole file rests on. `callers_truncated` answers whether `callers` is the
whole ancestry or only the part the walk reached; rows written before it
existed omit it, which reads as "unknown" rather than as "complete". Six
more fields appear only when they apply: `reason` on an explained denial,
`rule_id` on auto-decisions, `fingerprint` (of the **public** key) and
`sign_anchor` on SSH sign rows, and `declared_by` plus
`unverified_guest_chain` on sandbox rows.
That last one is a claim rather than evidence, so it is kept out of `callers`
and never read by rule matching. The audit view draws it beside the caveat
the prompt uses, on its own line and never truncated
(see [secret-agent](./secret-agent.md)).

`sign_anchor` names the process the signature was granted against, and its
`kind` is `forwarded_ssh` when the request came through an agent you forwarded
rather than from this machine:

```sh
jq -c 'select(.sign_anchor.kind == "forwarded_ssh")' ~/.secreq/audit.log
```

That process is the one the caller chain cannot hold, so on an `ssh:` row
written before the field existed the answer is absent, which again reads as
unknown rather than as "local".

`declared_by` names the local process that put a sandbox's scope name on the
consent socket, as the kernel reported it:

```json
"declared_by": {
  "peer": {
    "pid": 4711,
    "name": "secreq",
    "command": "secreq agent open brain-nx-t5",
    "exe": "/usr/local/bin/secreq"
  }
}
```

`name` is what the process called itself and `exe` is what was loaded, which
is why both are kept. Two other values appear in its place: `"gone"` when the
process had exited before the daemon could look it up, and `"not_read"` when
the release never reached the daemon at all, which is what an
`approve+cached` or `deny+out-of-scope` row records.

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
| `deny`                    | You denied it. Carries `reason` when you supplied one.                           |
| `deny+auto`               | Refused by a matching deny rule. Carries `rule_id` and its `reason`, when given. |
| `deny+out-of-scope`       | A sandbox asked for something outside its allowlist. Refused without asking you. |
| `abandoned`               | The requesting process exited before you decided. Nothing was released.          |

::shot{id=27-audit-tab-abandoned}

## The daemon behind them

Closing either window leaves the daemon running and your approvals cache
intact. The prompt also hides itself a couple of seconds after the queue
drains. To actually stop it:

- `secreq daemon stop`: graceful; clears the cache.
- `secreq daemon stop --force`: SIGKILL, for when it is wedged.
- Do nothing; it idle-exits after two hours with an empty queue.

On macOS the daemon runs with the `Accessory` activation policy, so it stays
out of the Dock and out of Cmd-Tab while no window is showing.
