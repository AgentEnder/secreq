# SSH agent

`secreq` doubles as a **provenance-aware SSH agent**. When `ssh`, `git`,
or any SSH client asks it to sign with one of your keys, `secreq` shows
*who is asking* — the caller process chain plus the key's fingerprint —
and gates the signature on your consent. It's the consent ceremony you
already get for wrapped binaries, applied to SSH key use.

If you want the mental model for the rest of `secreq` first, read
[`overview.md`](./overview.md).

## What it does

- **Lists your keys without a biometric.** `ssh-add -l` (and any client's
  identity listing) answers from the inline public keys in your config.
  No provider call, no prompt.
- **Gates every new signature.** The first sign per *anchor* (your shell,
  IDE, or git session) pops the consent window showing the caller chain
  and the key's SHA256 fingerprint. You approve or deny.
- **Resolves the private key fresh, then drops it.** On approval `secreq`
  reads the private key from your provider, signs in-process, and zeroizes
  the key material. Only the signature leaves the daemon.

## Configure

Add an `ssh` block to your `wraps.json5`. Each entry is one identity: the
public key inline (it isn't secret), the private key as a `secret://`
reference resolved only at sign time, and an optional `$reason` shown in
the consent prompt.

```json5
{
  // ... your providers and wraps ...
  ssh: {
    "github-personal": {
      $reason: "git pushes to github",
      public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... me@mac",
      private_key: "secret://op/Private/gh-key/private key",
    },
  },
}
```

- `public_key` — the full OpenSSH public-key line. Answers identity
  listings directly.
- `private_key` — a `secret://<provider>/<locator>` reference. Resolved
  fresh at every sign; never cached.
- `$reason` — optional human label, shown in the consent prompt.

## The `op`-export requirement

The provider-backed model only works if resolving the reference returns
an **OpenSSH private key**. For 1Password, that means

```sh
op read "op://Private/gh-key/private key"
```

must print a `-----BEGIN OPENSSH PRIVATE KEY-----` block. Store the key so
that field holds the exported private key text. If the provider returns
anything else, signing fails (the key can't be parsed). Listing still
works — listing never resolves the reference.

## Set up your SSH client

Point your SSH client's `SSH_AUTH_SOCK` at the secreq agent socket. The
path is per-user and platform-dependent:

- **macOS:** `~/Library/Caches/secreq/agent.sock`
- **Linux/BSD:** `$XDG_RUNTIME_DIR/secreq/agent.sock` (e.g.
  `/run/user/1000/secreq/agent.sock`)

`secreq init` prints the exact path for your machine. Use one of:

```sh
# shell rc (~/.zshrc, ~/.bashrc, …)
export SSH_AUTH_SOCK="$HOME/Library/Caches/secreq/agent.sock"
```

```
# ~/.ssh/config
Host *
    IdentityAgent "~/Library/Caches/secreq/agent.sock"
```

### One agent only

`secreq` *is* your agent now — it resolves keys through your provider. Do
**not** also point `SSH_AUTH_SOCK` or `IdentityAgent` at 1Password's SSH
agent (or any other agent). Pick one. Running both means SSH talks to
whichever it finds first, and you lose secreq's consent gating for keys
the other agent answers.

## Behavior

- **First sign prompts.** The first signature per anchor opens the consent
  window with the caller chain and the key's fingerprint. `ssh` itself is
  treated as a transport frame and skipped, so the prompt anchors on the
  real initiator — your git command, shell, or IDE.
- **Approvals cache per anchor, with a TTL.** Approving "remember" caches
  the *decision* (not the key) for that anchor for about five minutes.
  Subsequent signs within the window sign silently — each still resolves
  the key fresh and zeroizes it. Unlike the wrap cache, which lives as long
  as the parent process, the SSH approval cache is clock-bounded: an anchor
  (shell/IDE/git session) can live for hours, so the approval expires on a
  timer rather than tracking the session's whole lifetime.
- **Listing is free.** `ssh-add -l` and identity listings never prompt and
  never touch a provider.
- **Every sign is audited.** Each signature (approved, cached, or denied)
  is recorded in the audit log with the key id, fingerprint, decision, and
  caller chain — never the key or the signature bytes. (For SSH signs the
  daemon writes the audit row itself, since there's no wrap client in the
  loop.)

## Trust-model note: key custody is downgraded

This is the important tradeoff. **Unlike 1Password's sealed SSH agent,
secreq's agent resolves the private key into the daemon's memory to sign,
then zeroizes it.** 1Password's agent keeps the key hardware-sealed: the
key never leaves 1Password, and a signature is produced inside the sealed
boundary. secreq cannot do that — it signs in-process, so the key is
briefly decrypted in the daemon's RAM.

What you gain is provenance-aware consent (you see who's asking, and can
deny) and a single agent across every provider. What you give up is
hardware sealing. If your threat model requires the key to never enter
process memory, keep using 1Password's sealed agent for those keys and
don't route them through secreq.

Mitigations on the secreq side: the resolved key is zeroized immediately
after signing, it is never sent to a client, and every use is gated by
consent and recorded in the audit log.
