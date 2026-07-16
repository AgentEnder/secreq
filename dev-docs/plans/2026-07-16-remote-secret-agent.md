# Remote secret agent — serving secrets to guest VMs

Date: 2026-07-16
Status: design (validated); **A + B + C implemented** (see "Build order" below)

*A guest VM resolves `secret://` refs from the HOST's secreq over a
forwarded unix socket — gated by host-side consent, bounded by a
host-declared allowlist — instead of having tokens copied into it.*

## Goal

Today brain's `sandbox.seed` **copies** `GH_TOKEN` / `LINEAR_TOKEN` /
`CLAUDE_CODE_OAUTH_TOKEN` into a VM's login profile. Open egress makes
anything in that env exfiltratable, so the tokens are minimized but
still *persisted in the guest*. Instead: the guest asks the host, per
use, and nothing is persisted.

This is the SSH-agent pattern applied to secret resolution — the same
move secreq already made for signing.

## The template: secreq's SSH agent

`docs/ssh-agent.md` + `src/daemon/{ssh_agent,ssh_proto,peercred}.rs`
already do this shape:

- a per-user **daemon** serving a unix socket
  (`~/Library/Caches/secreq/agent.sock`);
- clients point at it by env (`SSH_AUTH_SOCK`) or config
  (`IdentityAgent`);
- **listing is free**, every **sign is gated** by consent;
- approvals cache **per anchor** with a clock-bounded TTL (`SshAnchor` /
  `SshGrant` / `SshGrantScope` in `consent.rs`);
- the secret resolves **fresh** per use and is zeroized; only the result
  leaves;
- every use is **audited** (decision + caller chain, never the
  material).

Reuse: `resolve.rs` (`build_plan` / `resolve_all` / providers),
`reference.rs` (`secret://` parsing), `consent.rs`, `audit.rs`,
`daemon/{server,proto,state,cache,prompt_ui}.rs`.

## Where the template breaks: provenance

This is the crux, and it must be stated plainly rather than papered
over.

`peercred.rs` — *"The SSH client is a socket peer, not our parent, so we
read its pid **from the kernel**"* — and `provenance.rs` — *"walks the
parent process tree so the consent prompt can show the caller chain…
**This is the 'awareness' the design is built around: you see what is
asking before you allow.**"*

secreq's consent rests on an **unforgeable kernel fact**: `SO_PEERCRED`
→ pid → local process tree. **A guest VM has neither.** There is no
local pid for a process inside another kernel, and over a forwarded
socket `peer_pid()` returns the *tunnel* (sshd), not the asker. The
guest cannot be made to prove what it is.

### Decision: the sandbox is the principal

- **Gate on the sandbox.** The host owns the socket→sandbox mapping (it
  created the scoped socket and forwarded it), so *"sandbox
  `brain-nx-t5` wants `GH_TOKEN`"* is unforgeable. This matches brain's
  own invariant: **a sandbox is a workspace, not an identity**.
- **Display the guest's self-reported chain, marked untrusted.** Useful
  when the guest is honest; **never load-bearing** — not for the
  decision, and never as a cache key. A guest-controlled cache key would
  mean a compromised guest could claim a previously-approved chain and
  get a *silent* release.
- **Accept the loss of granularity.** One approval covers that sandbox
  for the TTL. There is no per-process granularity because none is
  verifiable, and inventing one would be theater.

```
┌─ secreq ───────────────────────────────┐
│ sandbox  brain-nx-t5  (vm · lima)      │
│ wants    GH_TOKEN                      │
│          secret://op/Dev/gh/token      │
│                                        │
│ guest says: node → pnpm → postinstall  │
│ ⚠ guest-reported — NOT verifiable      │
│                                        │
│   [Deny]  [Allow once]  [Allow 5 min]  │
└────────────────────────────────────────┘
```

## Transport: SSH-forwarded unix socket (VM tier only)

```
host                              guest (vm)
┌─────────────┐   ssh -R sock    ┌──────────────┐
│ scoped sock │<=================│ SECREQ_SOCK  │
│ + consent   │  (no listener)   │ → resolve    │
└─────────────┘                  └──────────────┘
```

`ssh -R /guest/secreq.sock:/host/scoped.sock` — exactly how `ssh -A`
already forwards `SSH_AUTH_SOCK`. **No network listener, no new auth
surface**: SSH is the auth, and brain's VM sandboxes already dial over
SSH (`Connection { kind: 'ssh' }`).

**VM tier only.** brain's container tier attaches via `incus exec` with
**no sshd in the guest** (`Connection { kind: 'exec' }`), so a forwarded
socket can't serve it — containers keep `sandbox.seed` for now. A future
`exec`-pump carrier could relay the same protocol; the protocol must not
assume its carrier.

## Scope + allowlist: declared by the host at open time

The host declares what a socket may ask for, when it creates it:

```sh
secreq agent open \
  --scope brain-nx-t5 \
  --allow secret://op/Dev/gh/token \
  --allow secret://op/Dev/linear/token \
  --sock /tmp/secreq-brain-nx-t5.sock
```

- brain already knows this list — it is exactly `sandbox.seed.env`'s
  refs, which today it *copies*. Same declaration, different verb.
- **A ref outside the allowlist is denied without a prompt** (and
  audited). Never train click-through, and never let a compromised guest
  enumerate the vault one prompt at a time.
- **No config coupling either way**: secreq doesn't read brain's
  manifest; brain doesn't maintain a second list in `wraps.json5`.

## Protocol

Small and carrier-agnostic (framed request/response over the socket):

- `resolve <secret://ref>` → the secret, or a denial. Resolved fresh per
  call via `resolve.rs`, zeroized after; only the value crosses.
- `list` → the scope's *allowed ref names* (never values). Free, no
  prompt — mirrors "listing is free".
- Everything else → error. No enumeration surface.

### Wire format as implemented (A)

`[u32 big-endian payload length][JSON payload]`, one frame per message,
request and response alternating on a connection held open across calls.

The framing is deliberately **carrier-agnostic**: it needs a reliable
in-order byte stream and nothing else. No `SO_PEERCRED`, no fd passing,
no line-orientation, no socket-only syscalls — so the same codec runs
unchanged over a unix socket, an SSH-forwarded socket, or a future
`incus exec` pump's stdin/stdout pipe pair. The length prefix (capped,
like the SSH agent's `MAX_AGENT_MSG_LEN`) means a carrier that chunks or
coalesces writes can't desynchronize the parser, which a line-delimited
codec could not promise across an arbitrary pump.

JSON payloads match `daemon/proto.rs`'s existing idiom and are
self-describing, so an older guest and a newer host degrade to a defined
error instead of a misparse.

## Invariants

- **No outward-acting credential is persisted in the guest** — that's
  the point; it strengthens brain's `#16` trust boundary rather than
  competing with it.
- **The gate rests only on host-verifiable facts.** Guest input may
  inform the display, never the decision or the cache key.
- **Deny-by-default outside the declared scope**, silently (audited, no
  prompt).
- **Resolve fresh, zeroize, never cache the material** — only the
  *decision* caches, per scope anchor, clock-bounded.
- Every release (approved, cached, or denied) is audited with scope +
  ref + decision — never the value.

## Trust-model note: granularity is downgraded

Mirroring `docs/ssh-agent.md`'s own "key custody is downgraded" note,
state the tradeoff honestly:

**For guest callers, secreq cannot see what is asking — only which
sandbox.** Approving a sandbox approves *everything running in it* for
the TTL, not one process. That is strictly weaker than the local
wrap/SSH story, where the caller chain is kernel-sourced. What you gain
over `seed`: nothing is persisted in the guest, each use is gated and
audited, and a revoked approval takes effect immediately. If a workload
needs per-process consent, it doesn't belong in a VM the host can't
inspect.

## Build order

- **A — scoped agent + protocol + allowlist** (`secreq agent open`,
  resolve/list, deny-outside-scope silently, consent per request,
  audit). Testable over a local unix socket; no VM. **Implemented** —
  `src/scoped_agent/`, `tests/scoped_agent.rs`.
- **B — scope anchoring**: TTL-cached approvals keyed to the scope, +
  the untrusted guest-chain display in the prompt. **Implemented** —
  `consent::{AgentAnchor, AgentGrant}`, `scoped_agent::{ScopeApprovals,
  GuestChain, Clock}`, the prompt's GUEST SAYS row.
- **C — guest client**: `secreq resolve <ref>` dialing `$SECREQ_SOCK`,
  and the env convention. Needs A. **Implemented** —
  `src/scoped_agent/client.rs`, `commands::resolve`,
  `tests/resolve_client.rs`, `docs/secret-agent.md`.
- **D — brain wiring** (brain project): `secreq agent open` + `ssh -R`
  at sandbox start, `SECREQ_SOCK` in the guest profile; VM tier stops
  copying env. Needs A + C.

## Notes from implementing A

- **The gate is a decision, not a resolve.** The scoped agent sends the
  daemon an `Ask` carrying **no `SecretAsk`** — exactly like
  `ssh_agent.rs::sign_ask` — so the daemon prompts but resolves nothing
  and caches nothing. On approve, the agent resolves the ref *itself*
  through `resolve.rs::resolve_all` and zeroizes. Routing through the
  daemon's resolve path (the way `secreq read` does) would have put the
  material in the daemon's `SecretCache`, breaking the "resolve fresh,
  never cache the material" invariant above.
- **No peercred on this path.** `Ask.callers` is deliberately **empty**
  and `daemon/peercred.rs` is never consulted for the scoped socket:
  over a forwarded socket the peer pid is the tunnel (sshd), so a caller
  chain here would be a fabricated one. The prompt renders the scope as
  the principal instead (`AgentAskInfo` on the `Ask`).
- **"Ephemeral" needed a signal handler, not just a `Drop`.** The accept
  loop never returns, so the socket guard's `Drop` never runs — and a
  signal is the *normal* stop (brain kills the process at sandbox
  teardown). Without a SIGTERM/SIGINT/SIGHUP handler, every stop leaked
  the socket file and the next `agent open` on that path failed. A
  SIGKILL still leaks it (nothing can run), so `open` also reclaims a
  socket path when it can *prove* nothing is listening (connect fails);
  a path with a live listener is refused, since clobbering it would
  silently redirect another scope's guest onto our allowlist.
- **Dedupe key is finer than the audit label.** `dedupe_key.wrap` is
  `agent:<scope>:<ref>` so two concurrent asks for *different* refs from
  one scope can't coalesce into a single prompt (which would release a
  ref the user was never shown). The audit row's `wrap` stays
  `agent:<scope>` with the ref in `secrets`, mirroring `ssh:<key_id>`.
</content>
</invoke>

## Notes from implementing B

- **The anchor is the scope; the grant is per-`(scope, ref)`.**
  `consent::AgentGrant` mirrors `SshGrant` — an anchor plus a wall-clock
  `expires_at` — but anchors on the host-declared scope name rather than
  a kernel `(pid, start_time)`, because a guest has no host pid to
  anchor on. It is *not* per-scope alone: approving `GH_TOKEN` for a
  sandbox must not silently release `LINEAR_TOKEN` to it, since the user
  was shown one ref and consented to that one. There is deliberately no
  `AllKeys`-style wildcard (the SSH prompt has one); the allowlist is
  already the coarse bound, and a second wildcard inside it would make
  the prompt a rubber stamp.
- **TTL is 5 minutes, half the SSH agent's 30.** A weaker principal
  earns a shorter leash: an SSH grant covers one key driven by a local
  session whose process tree the host can see; a scope grant covers
  everything running in a VM the host cannot inspect at all.
- **The cache lives in the agent process, not the daemon.** That is what
  makes "the second request is silent" true at the `Gate` — the daemon
  is never dialled on a hit, so no prompt can even be queued — and it
  keeps `Ask::allow_remember` at `false`, holding the daemon's
  parent-keyed cache (which keys on `(wrap, ppid, parent_start_time)`,
  none of which means anything for a guest) out of the path. The
  lifetime story falls out of where it lives: the cache is the process,
  the process is the socket, the socket is the sandbox. Teardown drops
  the grants with no invalidation logic to get wrong.
- **`Gate` had to split into `consent` + `resolve`.** A fused "gate this
  ref" call makes the cheap implementation of a TTL cache *also* cache
  the secret. Splitting lets `handle_request` skip the prompt on a hit
  while still resolving fresh every single time, which is the design's
  "only the decision caches" invariant made structural rather than
  remembered. It's also what makes the property observable: the test
  gate counts prompts and resolves separately, and a cached release is
  provably 1 prompt / 2 resolves.
- **The guest chain is display-only, enforced by types.** The rule is
  easy to state and easy to erode, so it isn't left to care:
  - `GuestChain` implements neither `Hash` nor `Eq` nor `Ord`, and holds
    a *rendered string* rather than the guest's list. There is no map it
    can key and no comparison a policy branch can make — the invariant
    fails to compile rather than failing in production.
  - `ScopeApprovals::{granted, remember}` and `AgentGrant::matches` take
    a scope and a ref and nothing else. There is no parameter to pass a
    claim through, and no field on `AgentGrant` to store one in.
  - It never enters `Ask::callers` (what `rules.rs` matches on and
    `provenance.rs` fills from the kernel), only
    `AgentAskInfo::guest_chain`, whose sole consumer is the prompt
    renderer. A guest able to write to `callers` could name a process
    that fires an auto-approve rule and collect a silent release.
  - The audit row files it under `unverified_guest_chain`, never
    `callers`. A log outlives its context; the field name has to carry
    the caveat.
  - The pinning test is behavioural, not structural: two requests with
    **different** claimed chains and the same `(scope, ref)` hit the
    same entry and raise one prompt. If the chain keyed anything, the
    second would miss and re-prompt.
- **A claim is untrusted input into a consent UI, so it's sanitized.**
  `GuestChain::new` strips control characters (a chain of
  `"node\n⚠ host-verified — TRUSTED"` must not be able to paint a line
  forging the very marker that discredits it) and caps links and link
  widths (a guest can put ~64 KiB in a frame, and a prompt it can flood
  is a prompt whose SCOPE row scrolls away).
- **The prompt says what Approve means.** The TTL grant is a quiet
  secondary action — "Scope: Approve for 5 min" — reusing the SSH
  prompt's session-grant idiom, leaving the footer's Approve as "this
  request only". An "Approve" that silently meant "approve for five
  minutes" would be a consent UI lying by omission.

## Notes from implementing C

- **stdout is the interface, not the output.** `secreq resolve` exists to
  be substituted — `export GH_TOKEN="$(secreq resolve …)"` — so the value
  and nothing else goes to stdout and every diagnostic goes to stderr. The
  failure mode is what makes it worth a rule rather than a habit: a stray
  progress line lands *inside* someone's token, and a denial printed to
  stdout would export the word "denied" as a credential. `tests/
  resolve_client.rs` asserts the streams byte-for-byte, and asserts the
  substitution itself through a real `sh -c`, because that shell contract
  is the thing being promised.
- **A denial gets its own exit code (3), distinct from an error (1).**
  `proto` already splits `Denied` from `Error` so a guest doesn't retry a
  refusal into click-training; that split is worth nothing if the shell
  can't see it. `3` means "the host said no — final"; `1` means "something
  is broken, maybe retry".
- **The ref is parsed before the socket is dialled.** A typo should read as
  a typo, not as "no agent" (on a host) or a remote refusal (in a guest) —
  neither of which is about the typo. It also means the host parses exactly
  the canonical form the client validated.
- **The guest chain is wired, and it is the one place `provenance.rs` is
  legitimately called on this feature.** `CLAUDE.md`'s rule is that the
  *host* side must never consult `provenance`/`peercred`, because a guest
  has no host pid and the socket's peer is the tunnel. `client::
  self_reported_chain` runs in the **guest**, in the guest's own kernel,
  about its own tree: locally true, remotely a claim — which is exactly
  what `GuestChain` is for. Best-effort: a kernel `sysinfo` can't read
  yields an empty chain and no prompt row, and nothing depends on it.
- **`resolve` shares nothing with `read`.** `read` needs a config, a
  provider and a consent window; a guest has none of the three — it has a
  socket. Every policy-shaped thing (allowlist, prompt, TTL, audit row)
  happens on the host, so the client is deliberately thin enough that
  there is nothing in it to get wrong.
