# Secret agent — serving secrets to a sandbox

`secreq` can serve `secret://` references to a **guest** — a VM sandbox —
over a forwarded unix socket, instead of copying tokens into it. The guest
asks per use; the host prompts, resolves fresh, and audits. Nothing is
persisted in the guest.

This is [`ssh-agent.md`](./ssh-agent.md)'s pattern applied to secret
resolution, down to the convention: **an env var names a socket**
(`SECREQ_SOCK`, mirroring `SSH_AUTH_SOCK`), the socket *is* the capability,
and having it lets you ask — not decide.

## The two halves

| Where | Command | What it does |
|---|---|---|
| **Host** | `secreq agent open --scope <name> --allow <ref>… --sock <path>` | Binds a scoped, ephemeral socket. The scope name and the allowlist are declared here and are immutable for the socket's life. |
| **Guest** | `secreq resolve <ref>` | Dials `$SECREQ_SOCK` and asks. Prints the value on stdout. |

Between them: `ssh -R`, exactly as `ssh -A` forwards `SSH_AUTH_SOCK`. There
is no network listener and no new auth surface — SSH is the auth.

```sh
# On the host: open the socket, then forward it in.
secreq agent open --scope my-vm \
  --allow secret://op/Dev/gh/token \
  --allow secret://op/Dev/linear/token \
  --sock /tmp/secreq-my-vm.sock &

ssh -R /run/secreq.sock:/tmp/secreq-my-vm.sock my-vm
```

```sh
# In the guest:
export SECREQ_SOCK=/run/secreq.sock
export GH_TOKEN="$(secreq resolve secret://op/Dev/gh/token)"
```

Inside a brain `--vm` sandbox, both sides are wired for you: `SECREQ_SOCK`
is already set in the guest profile.

## `secreq resolve` (the guest side)

```
secreq resolve <REF>      # print one secret's value on stdout
secreq resolve --list     # print the refs this socket may resolve
```

`<REF>` is a full `secret://provider/locator` or the bare
`provider/locator` shorthand.

**The value, and only the value, goes to stdout.** Every diagnostic, error,
and denial goes to stderr. That's what makes the command substitutable:

```sh
export GH_TOKEN="$(secreq resolve secret://op/Dev/gh/token)"
```

The value is printed with a trailing newline (`op read`'s convention);
`$(…)` strips it, so the variable holds the value exactly.

`--list` prints the scope's allowed ref **names**, one per line — never
values. Listing is free: it prompts for nothing and releases nothing the
host didn't already declare to this very socket.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Released. The value is on stdout. |
| 3 | **Denied** by the host — you said no, a rule denied it, or the ref is outside this socket's declared scope. The reason is on stderr; stdout is empty. |
| 1 | Error: `$SECREQ_SOCK` unset, the agent unreachable, a malformed ref, or resolution failed on the host after approval. |

`3` and `1` are distinct on purpose. A denial is a normal, final answer —
**don't retry it**; retrying is how a user gets trained to click through
prompts. A `1` means something is broken and may be worth fixing and
retrying.

### When it doesn't work

- **`$SECREQ_SOCK is not set`** — you're on the host, or in a sandbox with
  no forward (brain's container tier has no sshd, so it can't be served this
  way; it still uses seeded env). Open and forward a socket as above.
- **`cannot reach the scoped secret agent on …`** — the socket path exists
  in your guest but nothing answers. Either the host's `secreq agent open`
  stopped, or the `ssh -R` forward is down. Check both; from inside the
  guest you can't tell which.
- **`denied by the host: reference is outside this socket's declared
  scope`** — the ref isn't in the `--allow` list this socket was opened
  with. This is refused **without a prompt** (and audited), so nobody on the
  host saw a window. Re-open the socket with the ref in its allowlist.

## Behavior on the host

- **The allowlist is the coarse bound.** A ref outside it is denied without
  a prompt and audited. A compromised guest can neither train you to click
  through nor enumerate your vault one prompt at a time.
- **Every allowed request is gated.** The prompt shows the **scope** as the
  principal — "sandbox `my-vm` wants `secret://op/Dev/gh/token`".

  ::shot{id=34-agent-scope-pending}

  A guest may volunteer a caller chain. It is shown, disclaimed, and
  audited as a claim — it never reaches the decision or the grant cache:

  ::shot{id=36-agent-guest-chain-pending}

- **Approvals cache per scope, with a 5-minute TTL.** "Approve for 5 min"
  anchors the decision to that `(scope, ref)`; requests within the window are
  silent. The *decision* is cached — the secret is resolved fresh and
  zeroized every single time.
- **The socket is ephemeral.** It lives exactly as long as the `agent open`
  process. Kill it and the grants die with it; there is nothing to revoke.
- **Every release is audited** — scope, ref, decision — never the value.

## Trust-model note: granularity is downgraded

Like [`ssh-agent.md`](./ssh-agent.md)'s key-custody note, the tradeoff is
worth stating plainly.

**For guest callers, secreq cannot see what is asking — only which sandbox.**
secreq's consent normally rests on a kernel fact: it reads the asking
process's pid and walks its parent tree, so you see `node → pnpm →
postinstall` and know it's true. A guest VM has no host pid, and over a
forwarded socket the socket's peer is the tunnel (sshd), not the asker.
There is nothing to check.

So the **sandbox is the principal**. Approving a ref for a sandbox approves
*everything running in that sandbox* for the TTL, not one process. That is
strictly weaker than the local wrap and SSH stories.

A guest may report its own caller chain, and the prompt shows it — marked
**guest-reported, not verifiable**, and filed in the audit log as
`unverified_guest_chain`. It is display only: it can't influence the
decision, can't key the approval cache, and can't talk an out-of-scope ref
past the allowlist. Read it as context from a source you may not trust.

What you gain over copying tokens into the guest: nothing is persisted
there, each use is gated and audited, and killing the socket revokes
everything immediately. If a workload needs per-process consent, it doesn't
belong in a VM the host can't inspect.
