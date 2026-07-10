# Design: provenance-aware SSH agent

Date: 2026-06-04
Status: design (pre-implementation)

## Motivation

1Password ships an SSH agent (`~/.1password/agent.sock`,
`SSH_AUTH_SOCK` / `IdentityAgent`) that signs auth challenges behind a
biometric prompt. It has the **same gap as the `gh` shell plugin**:
when a key is requested, the prompt shows *which key* and *which auth
method* — but **not which program is asking**. There is no provenance.

secreq's whole reason to exist is to close that gap for CLIs. This
design extends the same guarantee to SSH key usage: **show the caller
chain at the moment a key is requested, and gate the signature on
consent.**

## Decisions (settled in brainstorming)

1. **Interception shape — provider-backed SSH agent (not a proxy).**
   secreq runs its *own* SSH agent and signs in-process. It does **not**
   forward to 1Password's agent. The private key is fetched through the
   existing provider machinery (`secret://op/.../private key`) like any
   other secret. No two-agent duplexing; one agent on the box.

2. **Hosting — the daemon owns `agent.sock`.** The existing consent
   daemon gains a second listener (`~/.secreq/agent.sock`) alongside its
   control socket. It reuses the daemon's queue, consent UI, approvals
   cache, rules engine, resolve/batch path, and audit. **When the SSH
   agent is enabled the daemon does not idle-exit** (`SSH_AUTH_SOCK` must
   stay valid), and signing happens inside the daemon process.

3. **Key custody — provider-backed only; not hardware-sealed.** The
   private key is resolved via `op read` into the **daemon's** memory,
   used to sign, and zeroized. This *gives up* 1Password's
   hardware-sealing (key never leaves 1Password) in exchange for
   provenance + single-agent simplicity. It is consistent with how
   secreq already treats every other secret. Blast radius is tighter
   than a normal wrap: the key never crosses a socket to a client — only
   the signature does. **This is a trust-model change** and is recorded
   here deliberately.

4. **Config — a reserved `ssh` block in `wraps.json5`.** Parallel to
   `providers`. Keyed by identity name; public key inline (non-secret,
   so identity listing is biometric-free); private key as a `secret://`
   reference; optional `$reason`.

5. **Consent scope — ancestor anchor + short TTL.** A SIGN approval is
   cached on `(key_id, anchor_pid, anchor_start_time, expires_at)`, where
   the *anchor* is the first meaningful ancestor after skipping ephemeral
   transport frames (`ssh`/`scp`/`sftp`). Adds a **clock-based TTL**
   (default 5 min, configurable) — a deliberate departure from the
   no-TTL wrap cache, because an anchor (shell/IDE/git session) can live
   for hours.

## Architecture

```
ssh / git ──connect──▶  ~/.secreq/agent.sock   (daemon, NEW listener)
                          │
                          │ 1. peer pid  ← SO_PEERCRED / LOCAL_PEERPID
                          │ 2. caller_chain_from_pid(peer) → provenance
                          │ 3. anchor = skip transport frames
                          │ 4. cache check (key_id, anchor, ttl)
                          │      hit  → sign now
                          │      miss → enqueue Ask → consent UI
                          │ 5. on approve: resolve secret://.../private key
                          │      (existing resolve+batch, one biometric)
                          │ 6. PrivateKey::sign(challenge); zeroize key
                          ▼
                       SIGN response (signature only) ──▶ ssh / git
```

The SSH client never learns there's anything between it and a normal
agent. 1Password is involved only as the *provider backend* during the
private-key resolve (step 5), exactly as it is for an API token today.

## Components

### 1. SSH agent listener (`src/daemon/ssh_agent.rs`, new)
- Binds `~/.secreq/agent.sock` (`0600`), accepts connections, frames the
  SSH agent protocol (length-prefixed messages).
- Implements the **minimum** message set:
  - `SSH_AGENTC_REQUEST_IDENTITIES` → `SSH_AGENT_IDENTITIES_ANSWER`
    listing configured public keys + comments. No resolve, no consent,
    no biometric.
  - `SSH_AGENTC_SIGN_REQUEST` (key blob, data, flags) → consent + resolve
    + sign → `SSH_AGENT_SIGN_RESPONSE`, or `SSH_AGENT_FAILURE` on
    deny/error. Honors `SSH_AGENT_RSA_SHA2_256/512` flags for RSA keys.
  - `ADD_IDENTITY` / `REMOVE_IDENTITY` / `LOCK` / `UNLOCK` →
    `SSH_AGENT_FAILURE` (we are read-only; keys come from config).
- Maps the incoming key blob → configured identity by comparing the
  wire-encoded public key.

### 2. Peer provenance (`src/provenance.rs`, extend)
- New `caller_chain_from_pid(pid: u32) -> Vec<Caller>`; refactor the
  existing `caller_chain()` to call it with `getppid()`. Same
  `is_self_frame` filtering and caps.
- New `peer_pid(socket_fd) -> Option<u32>`: `SO_PEERCRED` (Linux) /
  `LOCAL_PEERPID` via `getsockopt` (macOS). `libc` already a dep.
- New transport-frame skip for anchor selection (`ssh`, `scp`, `sftp`,
  configurable), analogous to `is_self_frame`.

### 3. Config (`src/wraps.rs`, `src/schema.rs`, extend)
```json5
{
  providers: { /* unchanged */ },
  ssh: {
    "github-personal": {
      $reason: "git pushes to github",
      public_key: "ssh-ed25519 AAAAC3Nz... me@mac",
      private_key: "secret://op/Private/gh-key/private key",
    },
  },
  // optional global: ssh approval TTL in seconds (default 300)
}
```
- `WrapsConfig` gains `ssh: BTreeMap<String, SshIdentity>`, parsed off
  the reserved `ssh` key in `WrapsConfig::parse` (same seam as
  `providers`). `SshIdentity { reason, public_key, private_key: Reference }`.
- `schema.rs::wraps_schema()` gains an `ssh` property; regenerate
  `docs/wraps.schema.json` via `cargo run --example gen-schema`;
  `tests/schema_drift.rs` guards it.

### 4. Signing (`src/ssh_sign.rs`, new) + crypto dependency
- Add RustCrypto `ssh-key` (parse OpenSSH private keys, sign) and
  `ssh-encoding` (wire framing). `zeroize` already present for the
  resolved key bytes.
- `sign(private_key_pem, data, flags) -> Signature`. Supports
  `ssh-ed25519`, `rsa-sha2-256/512`, `ecdsa-sha2-nistp256/384/521`.

### 5. Consent + cache (`src/consent.rs`, `src/daemon/state.rs`, extend)
- New `Decision` is unnecessary — reuse `Approve`/`ApproveRemember`/
  `ApproveCached`/`Deny`. SSH asks resolve **no value to a client**, so
  the existing "decision-only crosses the wire" property holds; the
  resolve+sign happens inside the daemon.
- `ApprovalEntry` gains an SSH variant (or a sibling
  `SshApprovalEntry { key_id, anchor_pid, anchor_start_time, expires_at }`).
  `expires_at` is the new field; wrap entries keep no TTL.
- Anchor selection done once when building the Ask; cache lookup and
  insert use the anchor, not the direct peer.

### 6. Consent UI (`src/daemon/ui.rs`, extend) + screenshots
- A SIGN ask renders: identity name, key fingerprint (SHA256), the
  `$reason`, and the peer caller chain — reusing the existing pending-row
  + provenance layout, relabeled for "SSH key request."
- **Per project convention:** add new screenshot fixtures for the SSH
  sign prompt (at least: pending SSH sign; cached/auto if visually
  distinct), regenerate all PNGs, inspect them, and add README rows.

### 7. Audit (`src/audit.rs`, extend) + convention carve-out
- SSH signs have **no wrap client** to write the audit row, so the
  **daemon writes the audit row** for SSH signs. This is an explicit
  exception to "the daemon never writes audit rows" and must be noted in
  `CLAUDE.md`. Row carries identity name, fingerprint, decision, and the
  caller chain — never the key or signature.

### 8. Setup (`src/path_setup.rs` / `secreq init`, extend)
- `secreq init` advises/sets `SSH_AUTH_SOCK=~/.secreq/agent.sock` (or an
  `IdentityAgent` block in `~/.ssh/config`). Document the one-agent
  caveat (don't also point at 1Password's socket).

## Data flow (SIGN, miss → approve)

1. `git push` → spawns `ssh` → `ssh` connects `agent.sock`.
2. Daemon reads peer pid; `caller_chain_from_pid` walks ancestry;
   anchor = first non-transport frame (e.g. the `git` / shell / IDE).
3. Cache miss (or expired) → enqueue an `Ask` (reuses the queue/coalesce
   path; dedupe key uses the anchor).
4. Consent UI shows identity + fingerprint + caller chain; user approves.
5. Daemon resolves `secret://op/.../private key` via the existing
   resolve+batch path (one biometric; `SECREQ_RESOLVING` already prevents
   a wrapped `op` from re-gating).
6. `ssh_sign::sign(...)`; zeroize the key bytes; return
   `SSH_AGENT_SIGN_RESPONSE`. Cache `(key_id, anchor, now+ttl)`.
7. Daemon appends the audit row.

## Error handling

- No graphical environment / consent unavailable → `SSH_AGENT_FAILURE`
  (fail closed), same posture as `SECREQ_NO_DAEMON`.
- Provider resolve fails (item missing, `op` locked, field not
  exportable) → `SSH_AGENT_FAILURE`; surface detail in daemon log + audit.
- Unknown key blob in SIGN (not in config) → `SSH_AGENT_FAILURE`.
- Unsupported message types → `SSH_AGENT_FAILURE` (never silently OK).
- Daemon must `SSH_AGENT_FAILURE` rather than hang if the UI is dismissed.

## Testing

- Unit: agent-protocol framing (round-trip a real `ssh-add -l` /
  sign request), anchor selection (skips ssh/scp/sftp; falls through to
  shell), TTL expiry, key-blob → identity matching, sign correctness per
  algorithm (verify signature against the public key).
- Integration: a fake provider returning a test key; drive a SIGN
  through the daemon; assert signature verifies and audit row written.
- Screenshot fixtures for the SSH sign prompt (see Components §6).
- `schema_drift` covers the `ssh` config block.

## Open questions / assumptions to verify

- **`op` can export the private key field.** Assumes
  `op read "op://.../private key"` returns an OpenSSH private key. Some
  vault/item settings may forbid export — verify before relying on it.
- **TTL granularity.** Default 5 min, global. Per-identity override
  later if needed (YAGNI for v1).
- **macOS App Nap.** The daemon already opts out via
  `begin Activity`; confirm the agent listener stays responsive in the
  background.

## Security / trust-model implications (must stay in sync with overview)

- The private key is decrypted into daemon RAM; mitigated by zeroize and
  by never sending it to a client. Documented downgrade vs. 1Password's
  sealed agent.
- A **clock-based TTL** enters the approvals model for SSH only.
- The daemon writes audit rows for SSH signs (carve-out from the
  client-writes-audit rule).

These three points should be reflected in `docs/overview.md` (non-goals
/ trust) and `CLAUDE.md` (audit carve-out) when the code lands.

### Update (2026-06-15): resolved key is cached, session grants replace the per-key TTL approval

Two changes landed after the original design, both deliberate trust-model
moves agreed with the user:

- **The resolved private key is now cached like any other secret.** The
  SIGN path routes through the shared `SecretCache`
  (`state::resolve_single_cached`) under
  `CacheKey { wrap: "ssh:<key_id>", provider, locator }`. The original
  design's flow diagram said "one biometric" per approval, but the first
  implementation re-resolved on *every* sign (no key caching), so a
  provider with its own biometric (e.g. `op read`) prompted on every
  `git push`. The key is ChaCha20-Poly1305-encrypted at rest in daemon
  RAM with a per-entry derived key, and — like wrap secrets — has **no
  TTL**: it lives for the daemon's lifetime, so the provider/biometric
  runs at most once per key until `secreq daemon stop`. This is a further
  custody downgrade beyond the original "decrypted into RAM per sign": the
  key now *persists* (encrypted) for the daemon's life. Accepted because
  it matches how every other secret is already handled, and the encrypted
  cache is the same threat-model mitigation used there.

- **Per-key TTL approvals became session grants.** `SshApprovalEntry`
  (one key, anchor, `expires_at`) is replaced by `SshGrant { scope:
  OneKey|AllKeys, anchor, expires_at }`. The consent prompt offers
  **Approve once · Approve 30m · Approve all keys 30m · Deny**; the two
  30m choices remember a grant scoped to the current anchor (one key, or
  every key) for `SSH_SESSION_GRANT_TTL_SECS` (30 min). The grant gates
  the *prompt*; the secret cache gates the *biometric*. So after a grant
  expires the user is re-prompted (re-confirming intent) but pays no
  biometric, because the key is still cached. New `Decision` variants:
  `ApproveSshSession`, `ApproveSshSessionAll`.

- **The anchor is now the shell/session, not the per-command process.**
  `select_anchor` originally skipped only transport frames (`ssh`/`scp`/
  `sftp`) and anchored on the first non-transport frame — which for
  `git push` is the `git` process. But `git push` spawns a fresh `git`
  (and a fresh `ssh`) on *every* push, so a grant keyed on that pid never
  matched the next push and the user was re-prompted constantly. The same
  "spawned fresh per op → no reuse" reasoning that rejected `ssh` applies
  to `git`. `select_anchor` now anchors on the nearest **session frame**
  (shell / `tmux` / `screen`; see `SESSION_FRAMES`), which survives across
  pushes, falling back to the first non-transport frame then the last.
  Consequence: a session grant covers the whole shell session (every
  descendant), which is exactly the "approve for this session" intent —
  and is what makes the 30m grant actually suppress re-prompts.
