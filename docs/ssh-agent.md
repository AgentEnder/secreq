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

## Onboarding

Getting secreq serving your SSH keys is three steps: **declare the
identity**, **keep the daemon running**, and **point your SSH clients at
it**. The guided command walks all three:

```sh
secreq ssh-setup
```

Run bare, it offers each step in turn (each is skippable): add an
identity if you have none, install the login service if it isn't there,
then wire your clients. `secreq init` also offers `ssh-setup` once it has
set up your PATH. The rest of this section covers each step as a
standalone command, so you can run them granularly or by hand.

### 1. Declare the identity

```sh
secreq ssh-add github \
  --public-key ~/.ssh/id_ed25519.pub \
  --private-key "secret://op/Private/GitHub/private key"
```

This writes the identity into the `ssh` block of `wraps.json5`. The
public key is stored inline; the private key is the `secret://` reference
resolved only at sign time. With both keys on the command line the
command runs without prompts.

Omit `--public-key` or `--private-key` and `secreq` resolves the missing
pieces interactively. When 1Password's `op` is on `PATH` it offers
**op-assisted discovery**: it lists your SSH-Key items, you pick one, and
it derives the private-key reference (`secret://op/<vault>/<title>/private
key`) — and fetches the public key too if you didn't supply one. Without
`op`, it prompts for the reference manually. You can also skip the
command entirely and hand-edit the `ssh` block (see [Configure](#configure)).

### 2. Keep the daemon running

The agent socket only exists **while the daemon runs**. Wraps auto-spawn
the daemon on demand, but nothing spawns it for an *incoming* SSH sign —
so `SSH_AUTH_SOCK` points at a dead socket unless a daemon already
happens to be up. Install a per-user login service to fix that:

```sh
secreq daemon install
```

This shows the service file it will write, then (after you confirm)
writes and loads it so the daemon is running immediately and restarts at
every login. What it writes, per platform:

- **macOS:** a launchd LaunchAgent at
  `~/Library/LaunchAgents/com.secreq.daemon.plist` running `secreq daemon
  --fg`, with `RunAtLoad` and `KeepAlive` set (start at login, restart on
  exit). launchd hands jobs a near-empty environment, so the plist pins a
  `PATH` (`/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`)
  so the daemon can find `op` and other provider binaries. **If your `op`
  lives somewhere unusual** (outside those directories), add that
  directory to the plist's `EnvironmentVariables.PATH`.
- **Linux:** a systemd `--user` unit at
  `~/.config/systemd/user/secreq.service` running `secreq daemon --fg`
  with `Restart=on-failure`. systemd `--user` inherits your login
  environment, so no `PATH` is pinned — but **`op` (and any other provider
  binary) must be reachable on your user systemd `PATH`** for the daemon to
  resolve secrets.

Undo it (unload and remove the service) with:

```sh
secreq daemon install --undo
```

### 3. Point SSH clients at it

Your SSH client needs to know where secreq's agent socket lives. The
socket path is per-user and platform-dependent:

- **macOS:** `~/Library/Caches/secreq/agent.sock`
- **Linux/BSD:** `$XDG_RUNTIME_DIR/secreq/agent.sock` (e.g.
  `/run/user/1000/secreq/agent.sock`)

Let secreq wire it for you. The scripted form does only this client
wiring (it skips the identity and auto-start prompts):

```sh
secreq ssh-setup --yes --method ssh-config   # ~/.ssh/config IdentityAgent
secreq ssh-setup --yes --method shell-rc     # SSH_AUTH_SOCK export
```

This resolves the socket path for your machine, shows you the exact block
it will write, and applies it after you confirm. The block is bracketed
by sentinel comments, so the command is **idempotent** (re-running is a
no-op) and **reversible**:

```sh
secreq ssh-setup --undo
```

**Pick a method.** Omit `--method` for an interactive prompt, or name one
directly:

- **`ssh-config`** prepends a `Host *` / `IdentityAgent` stanza to
  `~/.ssh/config`. Scoped to SSH only — it doesn't touch other clients'
  environments. (It's prepended because ssh applies the *first*
  `IdentityAgent` it finds for a host.) secreq creates `~/.ssh` as
  `0700` and keeps the config `0600`, which ssh requires.
- **`shell-rc`** appends an `SSH_AUTH_SOCK` export to your shell rc
  (`~/.zshrc`, `~/.bashrc`, fish `conf.d`, …). Affects *every* SSH
  client launched from that shell, not just `ssh`.

After it writes, restart your shell (`exec $SHELL`) or open a new SSH
session so the change takes effect. With the login service from step 2
in place, the daemon is already running — the new session just picks up
the socket.

**Or add it by hand.** If you'd rather not let secreq edit your dotfiles,
write one of these yourself (substitute the socket path for your
platform):

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

### Verify it works

```sh
secreq ssh-test            # test every configured identity
secreq ssh-test github     # test just one
```

`ssh-test` proves the wiring end to end: it connects to the agent socket,
asks the agent to sign a fixed test message with the key, and verifies the
returned signature against the key's public half — the same
consent → resolve → sign path a real `git push` takes. A passing run prints
`✓ <name>: agent signed; signature verifies`.

Because it performs a **real** signature, it needs the daemon running (it
talks to the live socket) and **may prompt for consent** the first time
(answer the prompt if the window appears). If the socket is unreachable, the
daemon probably isn't running yet — `secreq daemon install` sets it to start
at login.

You don't have to run it by hand: both `secreq ssh-setup` (the guided flow)
and `secreq ssh-add` offer to run the self-test for you right after they wire
things up.

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
