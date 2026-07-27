# Security Policy

`secreq` sits directly on the credential path: it resolves `secret://`
references from your secret stores, injects them into wrapped processes,
and gates every release behind a provenance-aware consent prompt. A
vulnerability here can leak a live credential or let an untrusted caller
obtain one it should never have seen. We take reports seriously and want
to make disclosing one easy.

## Supported versions

`secreq` is pre-1.0 and moves fast. Security fixes land on `main` and in
the next release; there is **no backport support for older versions**.
Always run the latest release (or `main`) to be sure you have current
fixes.

| Version                 | Supported           |
| ----------------------- | ------------------- |
| latest release / `main` | ✅                  |
| any earlier version     | ❌ (please upgrade) |

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a
security problem.** Public disclosure before a fix is available puts
every user at risk.

Report privately through **GitHub's private vulnerability reporting**:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** to open a private advisory visible
   only to you and the maintainers.
3. Fill in the details (see below).

> Maintainers: private vulnerability reporting must be enabled in
> **Settings → Code security and analysis** for the button above to
> appear. If it is not yet enabled, or you cannot reach it, contact a
> maintainer privately via their GitHub profile before posting anything
> publicly.

Please include as much of the following as you can:

- A description of the vulnerability and the **impact** (what an
  attacker gains — e.g. reads a secret without consent, bypasses the
  consent prompt, escapes the wasm rule sandbox).
- Step-by-step **reproduction**, including the relevant `wraps.json5` /
  rule configuration and the OS.
- The affected version or commit.
- Any proof-of-concept — but **redact real secrets**. Use placeholder
  values and `secret://` refs that point at nothing live.

## What to expect

This is a small project, so timelines are best-effort rather than
contractual:

- **Acknowledgement** of your report within **3 business days**.
- An initial **assessment** (severity, whether we can reproduce it)
  within **7 business days**.
- We will keep you updated as we work on a fix and will credit you in
  the advisory and release notes unless you ask us not to.
- We practice **coordinated disclosure**: we ask that you give us a
  reasonable window to ship a fix before disclosing publicly, and we
  will publish a GitHub Security Advisory when the fix is released.

## Scope

Security-relevant behavior for `secreq` centers on its trust boundaries.
Reports in these areas are especially valuable:

- **Consent bypass** — a secret released without an approved decision,
  or the fail-closed defaults failing open (no daemon / no `--yes`; no
  graphical env; daemon unreachable or exiting early; a required secret
  missing — all of these must **deny**, never proceed).
- **Cache-scope escape** — an approval reused by a process that isn't
  the direct parent it was granted to. The cache key is
  `(wrap_name, ppid, parent_start_time)`; pid recycling must not let a
  new process inherit an old approval.
- **Secret leakage** — a resolved value appearing anywhere it must not:
  logs, the consent prompt, the audit log (names only), the approvals
  cache, or output that should have been masked.
- **Masking bypass** — a secret value reaching the wrapped binary's
  stdout/stderr un-redacted, including values split across write chunks.
- **wasm rule sandbox escape** — a registered rule module reaching
  outside the ctx it is handed (filesystem, network, host state), or a
  drifted module being accepted despite the sha256 pin.
- **Provenance spoofing** — forging or corrupting the caller chain the
  consent prompt shows.
- **Scoped / remote agent boundary** — the `secret://`-serving agent
  releasing a ref outside the host-declared scope, or trusting a
  guest-supplied identity as if it were a host caller chain.
- **SSH agent** — signing without consent, or the resolved private key
  escaping the daemon's encrypted secret cache: reaching plaintext outside
  the single in-process signing use, or surviving `secreq daemon stop`.
- **SSH session grants under agent forwarding** — a "for 30 minutes" grant
  is anchored on the innermost forwarding `ssh` process when `ForwardAgent`
  is in play, not on the shell, so it ends when that SSH session does. A
  remote host signing on a grant that should have expired with the session
  it was granted in is in scope. So is defeating the detection: it reads the
  peer's argv **and** checks the peer is SSH-family by its executable path,
  and the two failure directions are deliberately asymmetric — over-detecting
  narrows the grant, under-detecting leaves it as wide as it would have been
  anyway. A report showing a process can _widen_ its own grant that way is a
  vulnerability; one showing it can narrow it is not.
  Forwarding declared only in `~/.ssh/config` or a `-F` file is **not**
  detected, and that limit is known rather than a finding.

The threat model these boundaries defend is summarised in
[`docs/overview.md`](./docs/overview.md); the enforcement points are
`src/daemon/peercred.rs`, `src/provenance.rs`, and `src/mask.rs`.

### Out of scope

- The security of the underlying secret stores themselves (1Password,
  macOS Keychain, `pass`, LastPass) and their CLIs — report those to
  their vendors.
- Reading an injected secret out of a live process. Once a value reaches a
  wrapped process's environment, any same-UID process can read it
  (`/proc/<pid>/environ` on Linux, `KERN_PROCARGS2` on macOS), as can root.
  Environment variables are the delivery channel, and this is a property of
  that channel.
- Findings that a value you deliberately opted out of masking with
  `--sq-raw` was not masked.

**Same-UID is not a blanket exclusion.** The bullet above covers the
credential after release, not the decision to release it. Telling same-UID
processes apart is the job of the consent prompt, the caller chain, the
approvals cache and the rules engine, so a report that a local process can
fool any of them is in scope. "A script running as you obtained a secret it
should have been prompted for" is a vulnerability. "A script running as you
read the token out of `gh`'s environment while it ran" is not.

## Safe harbor

We consider security research conducted in good faith under this policy
to be authorized. We will not pursue or support legal action against you
for research that respects this policy — please avoid privacy violations,
data destruction, and any disruption of other users while you test, and
only ever test against secrets and configuration you own.
