# SSH agent

`secreq` doubles as a **provenance-aware SSH agent**. When `ssh`, `git`,
or any SSH client asks it to sign with one of your keys, `secreq` shows
_who is asking_ (the caller process chain plus the key's fingerprint) and
gates the signature on your consent. It's the consent ceremony you
already get for wrapped binaries, applied to SSH key use.

If you want the mental model for the rest of `secreq` first, read
[`overview.md`](./overview.md).

## What it does

`ssh-add -l` and other identity listings answer from the public keys in your
config: no provider call, no prompt. The first signature per _anchor_ (your
shell, IDE, or git session) opens the consent window instead. `ssh` itself is
treated as a transport frame and skipped, so the prompt names the real
initiator rather than `ssh`.

On approval secreq resolves the private key through your provider and
signs in-process. Only the signature leaves the daemon; the plaintext key
exists for the length of that one signing call.

::shot{id=24-ssh-sign-pending}

## Configure

> **The short way is `secreq ssh setup`.** It declares the identity,
> offers to keep the daemon alive, and wires your SSH clients, showing you
> every file it wants to touch first. See [Onboarding](#onboarding). This
> section describes the config it writes, for when you'd rather write it
> yourself or want to know what a field means.

Add an `ssh` block to your `wraps.json5`. Each entry is one identity: the
public key inline (it isn't secret), the private key as a `secret://`
reference resolved only at sign time, and an optional `$reason` shown in
the consent prompt.

```json5
{
  // ... your providers and wraps ...
  ssh: {
    'github-personal': {
      $reason: 'git pushes to github',
      public_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... me@mac',
      private_key: 'secret://op/Private/gh-key/private key',
    },
  },
}
```

- `public_key`: the full OpenSSH public-key line. Answers identity
  listings directly.
- `private_key`: a `secret://<provider>/<locator>` reference. Resolved at
  the first signature, then held in the daemon's encrypted secret cache
  for the daemon's lifetime, like any other secret. See
  [Behavior](#behavior).
- `$reason`: optional human label, shown in the consent prompt.

## The `op`-export requirement

The provider-backed model only works if resolving the reference returns
an **OpenSSH private key**. For 1Password, that means

```sh
op read "op://Private/gh-key/private key"
```

must print a `-----BEGIN OPENSSH PRIVATE KEY-----` block. Store the key so
that field holds the exported private key text. If the provider returns
anything else, signing fails (the key can't be parsed). Listing still
works; listing never resolves the reference.

## Onboarding

Getting secreq serving your SSH keys is three steps: **declare the
identity**, **keep the daemon running**, and **point your SSH clients at
it**. The guided command walks all three:

::term{id=ssh-setup}

Every step is skippable, and `secreq init` offers the same flow once it has
set up your PATH. Each block it writes is bracketed by sentinel comments, so
re-running changes nothing and `secreq ssh setup --undo` removes it.

The three steps run standalone too, for scripting or for doing it by hand.

### Declare the identity

```sh
secreq ssh add github \
  --public-key ~/.ssh/id_ed25519.pub \
  --private-key "secret://op/Private/GitHub/private key"
```

The public key is stored inline in `wraps.json5`; the private key stays a
`secret://` reference, resolved only at sign time. Omit either flag and
secreq asks, offering to pick the item out of `op` when it is on `PATH`.

### Keep the daemon running

The agent socket exists only while the daemon does. Wraps auto-spawn it, but
nothing spawns it for an _incoming_ sign, so `SSH_AUTH_SOCK` points at a dead
socket unless one is already up. `secreq daemon install` writes a launchd
LaunchAgent or a systemd `--user` unit, shows it to you first, and loads it;
`--undo` removes it.

One gotcha on macOS: launchd starts jobs with almost no environment, so the
plist pins a `PATH` covering the usual install locations. If your `op` lives
somewhere else, add that directory to the plist's
`EnvironmentVariables.PATH`.

### Point SSH clients at it

The socket is at `~/Library/Caches/secreq/agent.sock` on macOS, and
`$XDG_RUNTIME_DIR/secreq/agent.sock` on Linux and BSD. Two ways to name it:

```sh
secreq ssh setup --yes --method ssh-config   # ~/.ssh/config IdentityAgent
secreq ssh setup --yes --method shell-rc     # SSH_AUTH_SOCK export
```

`ssh-config` prepends a `Host *` stanza, which affects `ssh` alone. `shell-rc`
exports `SSH_AUTH_SOCK`, which affects every SSH client launched from that
shell. Start a new shell afterwards so the change takes effect.

To write it yourself instead:

```
# ~/.ssh/config
Host *
    IdentityAgent "~/Library/Caches/secreq/agent.sock"
```

### One agent only

`secreq` _is_ your agent now, resolving keys through your provider. Do
**not** also point `SSH_AUTH_SOCK` or `IdentityAgent` at 1Password's SSH
agent (or any other agent). Pick one. Running both means SSH talks to
whichever it finds first, and you lose secreq's consent gating for keys
the other agent answers.

### Verify it works

```sh
secreq ssh validate            # test every configured identity
secreq ssh validate github     # test just one
```

`ssh validate` proves the wiring end to end: it connects to the agent socket,
asks the agent to sign a fixed test message with the key, and verifies the
returned signature against the key's public half: the same
consent → resolve → sign path a real `git push` takes. A passing run prints
`✓ <name>: agent signed; signature verifies`.

Because it performs a **real** signature, it needs the daemon running (it
talks to the live socket) and **may prompt for consent** the first time
(answer the prompt if the window appears). If the socket is unreachable, the
daemon probably isn't running yet. `secreq daemon install` sets it to start
at login.

You don't have to run it by hand: both `secreq ssh setup` (the guided flow)
and `secreq ssh add` offer to run the self-test for you right after they wire
things up.

## Behavior

Approving "remember" gives that anchor thirty minutes of silent signing:
"Approve for 30 min" covers the one key, "All keys for 30 min" covers
every configured identity. The wrap cache lives as long as the parent
process; this one expires on a clock, because an anchor like a shell or an
IDE can stay open for hours.

Two caches are in play and they hold different things. The grant above
caches the _decision_. The private key is cached separately, encrypted, in
the same daemon secret cache a wrap's secrets live in, so your provider
(and its biometric) runs at most once per key rather than once per
signature. Plaintext exists only inside the signing call, which zeroizes
it on the way out, and the key is never sent to a client. `secreq daemon
stop` clears both caches.

Every signature is audited whether approved or denied, with the key id,
fingerprint, decision, and caller chain. Never the key or the signature
bytes.

### Agent forwarding ends a grant with the SSH session

`ssh -A` puts a second party inside your terminal. A grant anchored on the
shell would mean that approving thirty minutes during a `git push` also
covered every signature the forwarded host cared to request over that half
hour: silently, with no window, on your keys.

So when the `ssh` client that opened the agent connection is forwarding,
the grant binds to that client rather than to the shell. "30 minutes" then
also means "and no longer than this SSH session": close the session and
the grant goes with it. Behind a jump host the innermost forwarding `ssh`
wins, which is the tightest live bound the process tree offers.

The prompt says which anchor it is offering. A forwarded ask draws a
`FORWARDED BY` row naming the host, and its grant row reads `Forwarded:`
where a local one reads `Session:`.

::shot{id=41-ssh-forwarded-agent}

Detection reads the `ssh` process's own command line (`-A`, `-tA`,
`-o ForwardAgent=yes`, and the spellings that fold into those) and asks
the kernel whether that process really is SSH-family. Argv is read, not
trusted: over-claiming forwarding can only narrow a grant, so nothing a
process writes there widens its own reach.

**Forwarding declared only in `~/.ssh/config` or in a `-F` file is not
detected.** A sign under one of those falls back to the shell anchor, so
put `-A` on the command line when you want a grant that ends with the
session.

## Trust-model note: key custody is downgraded

This is the important tradeoff. **Unlike 1Password's sealed SSH agent,
secreq's agent resolves the private key into the daemon's memory to
sign.** 1Password's agent keeps the key hardware-sealed: the key never
leaves 1Password, and a signature is produced inside the sealed boundary.
secreq cannot do that: it signs in-process, so the key is decrypted in the
daemon's RAM for each signature, and an encrypted copy sits there between
them until the daemon stops.

What you gain is provenance-aware consent (you see who's asking, and can
deny) and a single agent across every provider. What you give up is
hardware sealing. If your threat model requires the key to never enter
process memory, keep using 1Password's sealed agent for those keys and
don't route them through secreq.

Mitigations on the secreq side: plaintext lives only inside the signing
call and is zeroized on the way out, the cached copy is encrypted and dies
with the daemon, the key is never sent to a client, and consent gates
every use, which the audit log then records.
