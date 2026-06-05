# Provenance-Aware SSH Agent — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make secreq a provenance-aware SSH agent — when `ssh`/`git`
requests a signature, show the caller chain, gate on consent, then
resolve the private key from a provider (`secret://op/.../private key`)
and sign in-process.

**Architecture:** The existing consent daemon gains a second listener at
`~/.secreq/agent.sock` speaking the SSH agent protocol. On `SIGN_REQUEST`
it derives the connecting peer pid from socket peer-credentials, walks
that pid's ancestry (skipping ephemeral `ssh`/`scp`/`sftp` frames to find
an anchor), runs the normal consent + cache + audit flow, resolves the
private key through the existing provider/resolve path, signs with a
RustCrypto SSH crate, zeroizes, and returns only the signature.
Approvals cache on `(key_id, anchor_pid, anchor_start_time, expires_at)`
with a 5-minute TTL.

**Tech Stack:** Rust; `ssh-key` + `ssh-encoding` (RustCrypto) for key
parsing/signing/wire framing; `libc` (already a dep) for `getsockopt`
peer credentials; `zeroize` (already a dep); existing `sysinfo`-based
provenance; existing daemon/egui consent infra.

**Design doc:** `dev-docs/plans/2026-06-04-1password-ssh-agent-design.md`

**Working tree note:** Built on the current uncommitted `main` working
tree (the SSH work depends on in-progress `state.rs`/`ui.rs`/`proto.rs`
changes). Not isolated in a worktree.

---

## Conventions for the executing engineer

- This is a Rust crate (`secreq`). Build: `cargo build`. Test:
  `cargo test`. Lint (BLOCKING, must be green): `cargo clippy --all-targets
  -- -D warnings` and `cargo fmt --all`.
- TDD: write the failing test, run it to see it fail, write minimal code,
  run it to see it pass, commit. One behavior per test.
- **UI changes regenerate screenshots** — see `CLAUDE.md`. The
  screenshot harness is `tests/ui_screenshots.rs`, regenerated with
  `cargo test --test ui_screenshots -- --ignored --nocapture --test-threads=1`.
- Locate seams by symbol name (the plan gives names, not line numbers,
  because the working tree is mid-change): `WrapsConfig::parse`,
  `PROVIDERS_KEY`, `wraps_schema()`, `ApprovalEntry`, `resolve_for_ask`,
  `build_manifest`, `caller_chain`, `is_self_frame`.

---

## Task 0: Add SSH crypto dependencies

**Files:**
- Modify: `Cargo.toml` (`[dependencies]`)

**Step 1: Add the crates**

In `[dependencies]` add:

```toml
ssh-key = { version = "0.6", features = ["ed25519", "rsa", "ecdsa"] }
ssh-encoding = "0.2"
```

(`ssh-key` re-exports `ssh-encoding` types but we use the framing
helpers directly for the agent protocol.)

**Step 2: Verify it builds**

Run: `cargo build`
Expected: compiles, new crates downloaded.

**Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build: add ssh-key + ssh-encoding for the SSH agent"
```

---

## Task 1: `caller_chain_from_pid` (provenance from an arbitrary pid)

**Files:**
- Modify: `src/provenance.rs`
- Test: `src/provenance.rs` (`#[cfg(test)]` module)

**Step 1: Write the failing test**

```rust
#[test]
fn chain_from_pid_starts_above_the_given_pid_and_excludes_self_frames() {
    // Our own parent chain, requested explicitly, equals caller_chain().
    let me = std::process::id();
    let explicit = caller_chain_from_pid(me);
    let implicit = caller_chain();
    // Both anchor on our parent; neither contains our own pid.
    assert!(explicit.iter().all(|c| c.pid != me));
    assert_eq!(
        explicit.iter().map(|c| c.pid).collect::<Vec<_>>(),
        implicit.iter().map(|c| c.pid).collect::<Vec<_>>(),
    );
}
```

**Step 2: Run it to see it fail**

Run: `cargo test -p secreq provenance::tests::chain_from_pid -- --nocapture`
Expected: FAIL — `caller_chain_from_pid` not found.

**Step 3: Refactor `caller_chain` to delegate**

Extract the walk into a pid-seeded function. `caller_chain()` becomes the
`getppid()` caller; `caller_chain_from_pid(pid)` starts the walk at
`pid`'s parent (so the given pid is the requester, not included), reusing
`is_self_frame` and the same caps.

```rust
/// Walk the ancestry of `seed_pid` (its parent and up), newest first,
/// excluding secreq self-frames. `seed_pid` itself is the requester and
/// is NOT included — we report who is *behind* it. Used by the SSH agent,
/// where the requester is the socket peer rather than our own parent.
pub fn caller_chain_from_pid(seed_pid: u32) -> Vec<Caller> {
    caller_chain_from_pid_with_limit(seed_pid, 16, 256)
}

fn caller_chain_from_pid_with_limit(seed_pid: u32, max_chain: usize, max_walk: usize) -> Vec<Caller> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::Always)
            .with_exe(UpdateKind::Always),
    );
    let my_exe = std::env::current_exe().ok();
    let seed = sysinfo::Pid::from_u32(seed_pid);
    let mut current = sys.process(seed).and_then(|p| p.parent());
    walk(&sys, current.take(), my_exe.as_deref(), max_chain, max_walk)
}
```

Then rewrite `caller_chain()` to seed from `get_current_pid()` and the
existing body to call a shared `walk(...)` helper that contains the
`while let Some(pid) = current` loop you already have. Keep all existing
tests passing.

**Step 4: Run tests to see them pass**

Run: `cargo test -p secreq provenance`
Expected: PASS (old tests + the new one).

**Step 5: Commit**

```bash
git add src/provenance.rs
git commit -m "feat(provenance): caller_chain_from_pid for socket-peer ancestry"
```

---

## Task 2: Anchor selection (skip ephemeral transport frames)

**Files:**
- Modify: `src/provenance.rs`
- Test: `src/provenance.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn anchor_skips_transport_frames() {
    let chain = vec![
        mk_caller(10, "ssh", Some("/usr/bin/ssh")),
        mk_caller(11, "git", Some("/usr/bin/git")),
        mk_caller(12, "zsh", Some("/bin/zsh")),
    ];
    let anchor = select_anchor(&chain).unwrap();
    assert_eq!(anchor.name, "git"); // ssh skipped, git is the real actor
}

#[test]
fn anchor_skips_consecutive_transport_then_falls_through() {
    let chain = vec![
        mk_caller(10, "ssh", None),
        mk_caller(11, "scp", None),
        mk_caller(12, "bash", Some("/bin/bash")),
    ];
    assert_eq!(select_anchor(&chain).unwrap().name, "bash");
}

#[test]
fn anchor_is_none_for_empty_chain() {
    assert!(select_anchor(&[]).is_none());
}
```

**Step 2: Run it to see it fail**

Run: `cargo test -p secreq provenance::tests::anchor`
Expected: FAIL — `select_anchor` not found.

**Step 3: Implement**

```rust
const TRANSPORT_FRAMES: &[&str] = &["ssh", "scp", "sftp", "ssh-agent"];

/// Pick the meaningful ancestor a SIGN approval should be scoped to.
/// The connecting peer is almost always `ssh` (spawned fresh per git op),
/// so caching on it gives no reuse. Skip transport frames to anchor on
/// the real initiator (git / shell / IDE). Falls through to the last
/// frame if the whole chain is transport.
pub fn select_anchor(chain: &[Caller]) -> Option<&Caller> {
    chain
        .iter()
        .find(|c| !TRANSPORT_FRAMES.contains(&c.name.as_str()))
        .or_else(|| chain.last())
}
```

**Step 4: Run tests**

Run: `cargo test -p secreq provenance`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/provenance.rs
git commit -m "feat(provenance): anchor selection skips ssh/scp/sftp frames"
```

---

## Task 3: Socket peer pid (`SO_PEERCRED` / `LOCAL_PEERPID`)

**Files:**
- Create: `src/daemon/peercred.rs`
- Modify: `src/daemon/mod.rs` (`mod peercred;`)
- Test: `src/daemon/peercred.rs`

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn peer_pid_of_local_connection_is_us() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (server_conn, _) = listener.accept().unwrap();
        // The connecting peer is this same test process.
        let pid = peer_pid(&server_conn).unwrap();
        assert_eq!(pid, std::process::id());
    }
}
```

**Step 2: Run it to see it fail**

Run: `cargo test -p secreq peercred`
Expected: FAIL — `peer_pid` not found.

**Step 3: Implement (platform split via cfg)**

```rust
//! Peer-credential lookup for the SSH agent socket. The SSH client is a
//! socket peer, not our parent, so we read its pid from the kernel and
//! feed it to `provenance::caller_chain_from_pid`.

use std::os::unix::io::AsRawFd;

/// Best-effort pid of the process on the other end of `conn`.
#[cfg(target_os = "linux")]
pub fn peer_pid<F: AsRawFd>(conn: &F) -> Option<u32> {
    use std::mem;
    let fd = conn.as_raw_fd();
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 && cred.pid > 0 { Some(cred.pid as u32) } else { None }
}

#[cfg(target_os = "macos")]
pub fn peer_pid<F: AsRawFd>(conn: &F) -> Option<u32> {
    use std::mem;
    // <sys/un.h>: SOL_LOCAL / LOCAL_PEERPID. Not in libc's constants on
    // all versions; define locally.
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;
    let fd = conn.as_raw_fd();
    let mut pid: libc::pid_t = 0;
    let mut len = mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 && pid > 0 { Some(pid as u32) } else { None }
}
```

**Step 4: Run tests**

Run: `cargo test -p secreq peercred`
Expected: PASS on the current platform.

**Step 5: Commit**

```bash
git add src/daemon/peercred.rs src/daemon/mod.rs
git commit -m "feat(daemon): socket peer-pid lookup for the SSH agent"
```

---

## Task 4: Config — `ssh` block in `wraps.json5`

**Files:**
- Modify: `src/wraps.rs` (add `SshIdentity`, `SSH_KEY` const, parse in
  `WrapsConfig::parse`, field on `WrapsConfig`)
- Modify: `src/reference.rs` (no change expected — reuse `Reference::parse`)
- Test: `src/wraps.rs` `#[cfg(test)]`

**Step 1: Write the failing test**

```rust
#[test]
fn parses_ssh_identities() {
    let cfg = WrapsConfig::parse(&json5::from_str(r#"{
        ssh: {
            "github": {
                $reason: "git pushes",
                public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac",
                private_key: "secret://op/Private/gh/private key",
            }
        }
    }"#).unwrap()).unwrap();

    let id = cfg.ssh.get("github").unwrap();
    assert_eq!(id.reason.as_deref(), Some("git pushes"));
    assert_eq!(id.public_key, "ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac");
    assert_eq!(id.private_key.provider, "op");
    assert_eq!(id.private_key.locator, "Private/gh/private key");
}

#[test]
fn ssh_identity_requires_public_and_private_key() {
    let err = WrapsConfig::parse(&json5::from_str(r#"{
        ssh: { "x": { public_key: "ssh-ed25519 AAAA x" } }
    }"#).unwrap()).unwrap_err();
    assert!(err.to_string().contains("private_key"));
}
```

**Step 2: Run it to see it fail**

Run: `cargo test -p secreq wraps::tests::parses_ssh`
Expected: FAIL — no `ssh` field.

**Step 3: Implement**

Add near the other reserved-key constants:

```rust
const SSH_KEY: &str = "ssh";
```

Add the struct:

```rust
/// One SSH identity served by the agent. The public key is stored inline
/// (it isn't secret) so the agent can answer REQUEST_IDENTITIES without a
/// resolve. The private key is a `secret://` reference resolved only at
/// SIGN time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshIdentity {
    pub reason: Option<String>,
    pub public_key: String,
    pub private_key: Reference,
}
```

Add `pub ssh: BTreeMap<String, SshIdentity>` to `WrapsConfig`. In
`WrapsConfig::parse`, pull the `ssh` key (like `PROVIDERS_KEY`) and parse
each entry: require `public_key` (string) and `private_key` (parse via
`Reference::parse`), accept optional `$reason`, reject unknown keys.
Ensure `ssh` is treated as reserved so it isn't mistaken for a wrap.

**Step 4: Run tests**

Run: `cargo test -p secreq wraps`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/wraps.rs
git commit -m "feat(config): parse ssh identity block in wraps.json5"
```

---

## Task 5: Schema + drift

**Files:**
- Modify: `src/schema.rs` (`wraps_schema()`)
- Regenerate: `docs/wraps.schema.json`
- Verify: `tests/schema_drift.rs` (no edit; must pass)

**Step 1: Add the `ssh` property to `wraps_schema()`**

Add an `ssh` object property: `additionalProperties` an object with
`public_key` (string), `private_key` (string, pattern
`^secret://[^/]+/.+$`), optional `$reason` (string), `required:
["public_key", "private_key"]`.

**Step 2: Regenerate the JSON schema**

Run: `cargo run --example gen-schema > docs/wraps.schema.json`
(Confirm the example writes to stdout or a path — match existing usage.)

**Step 3: Run the drift test**

Run: `cargo test -p secreq --test schema_drift`
Expected: PASS (generated == committed).

**Step 4: Commit**

```bash
git add src/schema.rs docs/wraps.schema.json
git commit -m "feat(schema): ssh identity block + regen wraps.schema.json"
```

---

## Task 6: Signing (`src/ssh_sign.rs`)

**Files:**
- Create: `src/ssh_sign.rs`
- Modify: `src/lib.rs` (`mod ssh_sign;`)
- Test: `src/ssh_sign.rs`

**Step 1: Write the failing test (generate a key, sign, verify)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::PrivateKey;

    fn ed25519_pem() -> String {
        // Deterministic test key generated once and pasted here, OR
        // generate in-test via ssh_key::private::Ed25519Keypair::from_seed.
        PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap()
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    #[test]
    fn signs_and_verifies_ed25519() {
        let pem = ed25519_pem();
        let key = PrivateKey::from_openssh(&pem).unwrap();
        let data = b"challenge bytes";
        let sig = sign(&pem, data, 0).unwrap();
        // signature blob verifies against the public key
        assert!(verify_for_test(&key.public_key(), data, &sig));
    }
}
```

**Step 2: Run it to see it fail**

Run: `cargo test -p secreq ssh_sign`
Expected: FAIL — `sign` not found.

**Step 3: Implement**

```rust
//! In-process SSH signing. The private key arrives as an OpenSSH PEM
//! string resolved from a provider; we sign the agent's challenge and
//! return the wire-encoded signature blob. The PEM is zeroized by the
//! caller after we return.

use anyhow::{Context, Result};
use ssh_key::PrivateKey;

/// SIGN_REQUEST flags (see PROTOCOL.agent).
pub const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// Sign `data` with `private_key_pem`, honoring RSA SHA2 flags. Returns
/// the SSH wire encoding of the signature (algorithm name + blob).
pub fn sign(private_key_pem: &str, data: &[u8], flags: u32) -> Result<Vec<u8>> {
    let key = PrivateKey::from_openssh(private_key_pem)
        .context("parsing resolved private key (is the field an OpenSSH key?)")?;
    // ssh-key's signer picks rsa-sha2-512 by default for RSA; map flags.
    let sig = key
        .sign("", ssh_key::HashAlg::default(), data) // adjust per ssh-key API + flags
        .context("signing challenge")?;
    Ok(ssh_encoding::Encode::encode_vec(&sig)?)
}
```

> NOTE for engineer: pin the exact `ssh-key` 0.6 signing API while
> implementing (the crate exposes `PrivateKey`-based signing through the
> `signature`/`SigningKey` traits and an `SshSig`/`Signature` type). The
> test (generate → sign → verify) is the contract; make the bodies match
> whatever the crate version provides. Map `SSH_AGENT_RSA_SHA2_256/512`
> to the RSA hash algorithm; reject unsupported flag combos with an error.

**Step 4: Run tests**

Run: `cargo test -p secreq ssh_sign`
Expected: PASS. Add an RSA test and an ecdsa test the same way.

**Step 5: Commit**

```bash
git add src/ssh_sign.rs src/lib.rs
git commit -m "feat: in-process SSH signing (ed25519/rsa/ecdsa)"
```

---

## Task 7: Agent protocol framing (`src/daemon/ssh_proto.rs`)

**Files:**
- Create: `src/daemon/ssh_proto.rs`
- Modify: `src/daemon/mod.rs`
- Test: `src/daemon/ssh_proto.rs`

**Step 1: Write the failing test (round-trip a request)**

```rust
#[test]
fn parses_request_identities() {
    // length-prefixed: [u32 len=1][u8 type=11]
    let bytes = [0,0,0,1, 11];
    assert!(matches!(parse_request(&bytes).unwrap(), AgentRequest::RequestIdentities));
}

#[test]
fn parses_sign_request() {
    let req = encode_sign_request(b"KEYBLOB", b"DATA", 0);
    match parse_request(&req).unwrap() {
        AgentRequest::Sign { key_blob, data, flags } => {
            assert_eq!(key_blob, b"KEYBLOB");
            assert_eq!(data, b"DATA");
            assert_eq!(flags, 0);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn encodes_identities_answer_and_failure() {
    let ans = encode_identities_answer(&[("ssh-ed25519 AAAA".into(), "blob".into())]);
    assert_eq!(ans[4], SSH_AGENT_IDENTITIES_ANSWER);
    assert_eq!(encode_failure()[4], SSH_AGENT_FAILURE);
}
```

**Step 2: Run it to see it fail**

Run: `cargo test -p secreq ssh_proto`
Expected: FAIL.

**Step 3: Implement message constants + parse/encode**

Constants (from PROTOCOL.agent):
`SSH_AGENTC_REQUEST_IDENTITIES=11`, `SSH_AGENT_IDENTITIES_ANSWER=12`,
`SSH_AGENTC_SIGN_REQUEST=13`, `SSH_AGENT_SIGN_RESPONSE=14`,
`SSH_AGENT_FAILURE=5`, `SSH_AGENT_SUCCESS=6`.

`AgentRequest` enum: `RequestIdentities`, `Sign { key_blob, data, flags }`,
`Unsupported(u8)`. Parse the `[u32 length][u8 type][payload]` frame; for
SIGN, payload is `string key_blob`, `string data`, `u32 flags` (SSH
`string` = `[u32 len][bytes]`). Encoders mirror it. Reuse
`ssh-encoding`'s `Reader`/`Writer` if convenient, or hand-roll the
big-endian framing (it's small).

**Step 4: Run tests**

Run: `cargo test -p secreq ssh_proto`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/daemon/ssh_proto.rs src/daemon/mod.rs
git commit -m "feat(daemon): SSH agent protocol framing (parse/encode)"
```

---

## Task 8: SSH approval cache entry + TTL

**Files:**
- Modify: `src/consent.rs` (`SshApprovalEntry`)
- Modify: `src/daemon/state.rs` (cache store/lookup with expiry)
- Test: both modules

**Step 1: Write the failing test**

```rust
// in consent.rs tests
#[test]
fn ssh_approval_expires() {
    let entry = SshApprovalEntry {
        key_id: "github".into(),
        anchor_pid: 42,
        anchor_start_time: 1000,
        expires_at: 5000,
    };
    assert!(entry.matches("github", 42, 1000, /*now=*/4999));
    assert!(!entry.matches("github", 42, 1000, /*now=*/5001)); // expired
    assert!(!entry.matches("other", 42, 1000, 4999));          // wrong key
    assert!(!entry.matches("github", 43, 1000, 4999));         // wrong anchor
}
```

**Step 2: Run it to see it fail**

Run: `cargo test -p secreq consent::tests::ssh_approval`
Expected: FAIL.

**Step 3: Implement**

```rust
/// Remembered SSH sign approval. Unlike wrap approvals this carries a
/// wall-clock `expires_at` (Unix seconds): an anchor (shell/IDE/git
/// session) can live for hours, so a SIGN approval is time-bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshApprovalEntry {
    pub key_id: String,
    pub anchor_pid: u32,
    pub anchor_start_time: u64,
    pub expires_at: u64,
}

impl SshApprovalEntry {
    pub fn matches(&self, key_id: &str, pid: u32, start: u64, now: u64) -> bool {
        self.key_id == key_id
            && self.anchor_pid == pid
            && self.anchor_start_time == start
            && now < self.expires_at
    }
}
```

In `state.rs`, add a `Vec<SshApprovalEntry>` (or map) next to the wrap
cache. Lookup uses `now = SystemTime::now()`. On `ApproveRemember`,
insert with `expires_at = now + ttl_secs` (ttl from config, default 300).
Prune expired entries on access.

**Step 4: Run tests**

Run: `cargo test -p secreq consent state`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/consent.rs src/daemon/state.rs
git commit -m "feat(daemon): TTL-bounded SSH sign approval cache"
```

---

## Task 9: SSH agent listener — bind + REQUEST_IDENTITIES

**Files:**
- Create: `src/daemon/ssh_agent.rs`
- Modify: `src/daemon/server.rs` (spawn the listener when `ssh` config
  non-empty), `src/daemon/mod.rs`
- Test: `tests/ssh_agent.rs` (new integration test)

**Step 1: Write the failing integration test**

Bind the agent, connect a `UnixStream`, send a REQUEST_IDENTITIES frame,
assert the answer lists the configured public keys. Drive
`ssh-add -l`-equivalent purely over the socket (no real `ssh`).

```rust
#[test]
fn lists_configured_identities_without_resolving() {
    // start agent with one identity whose private_key reference would
    // FAIL to resolve; listing must still succeed (no resolve on list).
    // ... bind, send [0,0,0,1, 11], read SSH_AGENT_IDENTITIES_ANSWER ...
    // assert the pubkey blob + comment match config; assert the provider
    // was never invoked.
}
```

**Step 2: Run it to see it fail**

Run: `cargo test --test ssh_agent`
Expected: FAIL.

**Step 3: Implement the accept loop + identities answer**

- `~/.secreq/agent.sock` path helper (mirror the control-socket path
  logic); `0600`; unlink-on-start if stale.
- Accept loop: read a frame, dispatch via `ssh_proto::parse_request`.
- `RequestIdentities` → encode each config identity's public key blob +
  comment. Parse the inline `public_key` string with
  `ssh_key::PublicKey::from_openssh` to get the wire blob + comment. **No
  resolve, no consent.**

**Step 4: Run tests**

Run: `cargo test --test ssh_agent`
Expected: PASS (list works, provider untouched).

**Step 5: Commit**

```bash
git add src/daemon/ssh_agent.rs src/daemon/server.rs src/daemon/mod.rs tests/ssh_agent.rs
git commit -m "feat(daemon): SSH agent listener answers REQUEST_IDENTITIES"
```

---

## Task 10: SIGN flow — peer → provenance → consent → resolve → sign → audit

**Files:**
- Modify: `src/daemon/ssh_agent.rs`
- Reuse: `src/daemon/state.rs` (`resolve_for_ask` / `build_manifest`),
  consent queue, `src/audit.rs`
- Test: `tests/ssh_agent.rs`

**Step 1: Write the failing integration test**

With a fake provider that returns a known test private key, send a
SIGN_REQUEST for the configured key blob. Stub consent to auto-approve
(inject an approval cache entry, or a test hook on the queue). Assert:
the returned signature verifies against the public key; a second SIGN
from the same anchor within TTL is served from cache (no second
resolve); an audit row was appended with the key id + caller chain and
NO key/signature bytes.

**Step 2: Run it to see it fail**

Run: `cargo test --test ssh_agent`
Expected: FAIL.

**Step 3: Implement the SIGN handler**

1. `peercred::peer_pid(&conn)` → `provenance::caller_chain_from_pid` →
   `provenance::select_anchor`.
2. Map `key_blob` → config identity (compare wire blobs). Unknown →
   `SSH_AGENT_FAILURE`.
3. Cache check `(key_id, anchor_pid, anchor_start_time, now)`. Hit →
   skip to resolve+sign with `ApproveCached` audit decision.
4. Miss → enqueue an `Ask` onto the existing consent queue (build it
   from the identity: a single secret = the private_key reference,
   `command`/label = key id + fingerprint, `callers` = the chain,
   dedupe = anchor). Await the `Decision`.
5. Deny → `SSH_AGENT_FAILURE` + audit deny.
6. Approve → resolve the private key via the existing resolve path
   (`SECREQ_RESOLVING` already guards a wrapped `op`); `ssh_sign::sign`;
   `zeroize` the resolved PEM; encode `SSH_AGENT_SIGN_RESPONSE`.
7. `ApproveRemember` → insert TTL cache entry.
8. Append audit row (Task 12).

**Step 4: Run tests**

Run: `cargo test --test ssh_agent`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/daemon/ssh_agent.rs tests/ssh_agent.rs
git commit -m "feat(daemon): gated SSH SIGN — provenance, consent, sign"
```

---

## Task 11: Consent UI for SSH sign + screenshot fixtures

**Files:**
- Modify: `src/daemon/ui.rs` (render an SSH-sign ask: identity name, key
  fingerprint, `$reason`, caller chain)
- Modify: `tests/ui_screenshots.rs` (new fixture(s))
- Modify: `dev-docs/ui-screenshots/README.md` (table rows)
- Create: PNGs under `dev-docs/ui-screenshots/`

**Step 1: Add the UI rendering branch**

Reuse the existing pending-row + provenance layout; relabel for "SSH key
request" and show the SHA256 fingerprint. If the `Ask` model needs a flag
to distinguish SSH from wrap asks, add a minimal enum/bool to the
in-memory ask (NOT a new wire type — the SSH path is in-process).

**Step 2: Add a fixture** (per `CLAUDE.md` "How to add a fixture")

Add a fixture that submits an SSH-sign ask via a public
`ConsentWindowState` entry point (add one if needed, mirroring
`open_new_rule_form`). One fixture per visual state: at minimum a pending
SSH sign. Add a second if cached/auto looks different.

**Step 3: Regenerate ALL screenshots and inspect**

Run: `cargo test --test ui_screenshots -- --ignored --nocapture --test-threads=1`
Then open the new PNG and one existing PNG to confirm the change landed
and nothing regressed.

**Step 4: Update the README table** with a row per new fixture.

**Step 5: Commit**

```bash
git add src/daemon/ui.rs tests/ui_screenshots.rs dev-docs/ui-screenshots/
git commit -m "feat(ui): SSH sign consent prompt + screenshot fixtures"
```

---

## Task 12: Audit row for SSH signs (daemon-written carve-out)

**Files:**
- Modify: `src/audit.rs` (`AuditEntry` — support an SSH-sign shape)
- Modify: `src/daemon/ssh_agent.rs` (call `audit::append`)
- Modify: `CLAUDE.md` (document the carve-out)
- Test: `tests/daemon_log.rs` or `src/audit.rs`

**Step 1: Write the failing test**

Assert an SSH-sign `AuditEntry` serializes with the key id, fingerprint,
decision, and caller chain — and contains neither the private key nor the
signature.

**Step 2–4:** Implement the entry shape + append at each SIGN outcome;
run tests green.

**Step 5: Update `CLAUDE.md`** — add a bullet under "Other project
conventions" noting: *SSH-agent signs are audited by the daemon itself
(there is no wrap client to do it); this is the one exception to
"the daemon never writes audit rows."* Commit:

```bash
git add src/audit.rs src/daemon/ssh_agent.rs CLAUDE.md tests/
git commit -m "feat(audit): record SSH signs (daemon-written carve-out)"
```

---

## Task 13: Daemon stays alive while the agent is enabled

**Files:**
- Modify: `src/daemon/server.rs` / `src/daemon/state.rs` (idle-exit logic)
- Test: existing daemon lifecycle test or a new unit test on the
  idle-exit predicate

**Step 1: Write the failing test** for the predicate: "idle-exit is
disabled when `ssh` config is non-empty."

**Step 2–4:** Gate the ~2h idle-exit on `config.ssh.is_empty()`; green.

**Step 5: Commit**

```bash
git add src/daemon/server.rs src/daemon/state.rs tests/
git commit -m "feat(daemon): never idle-exit while the SSH agent is enabled"
```

---

## Task 14: Setup ergonomics + user docs

**Files:**
- Modify: `src/path_setup.rs` and/or `secreq init` handler in
  `src/commands.rs` (print `SSH_AUTH_SOCK` / `IdentityAgent` guidance)
- Create: `docs/ssh-agent.md`
- Modify: `docs/overview.md` (trust/non-goals: key-custody downgrade,
  TTL), `docs/getting-started.md` (link), `README.md`

**Step 1:** `secreq init` advises exporting
`SSH_AUTH_SOCK=~/.secreq/agent.sock` (or an `~/.ssh/config` `IdentityAgent`
block) and warns not to also point at 1Password's socket (one agent).

**Step 2:** Write `docs/ssh-agent.md`: config example, the `op`-export
requirement, the TTL, and the explicit trust-model downgrade vs.
1Password's sealed agent.

**Step 3:** Use the elements-of-style writing skill if available; keep it
tight.

**Step 4: Commit**

```bash
git add src/path_setup.rs src/commands.rs docs/ README.md
git commit -m "docs: SSH agent setup + trust-model notes"
```

---

## Task 15: Final verification pass

**Files:** none (verification only) — see
superpowers:verification-before-completion.

**Steps:**
1. `cargo fmt --all` — clean.
2. `cargo clippy --all-targets -- -D warnings` — zero warnings.
3. `cargo test` — all green.
4. `cargo test --test ui_screenshots -- --ignored --nocapture --test-threads=1`
   — fixtures regenerate; inspect at least one new + one existing PNG.
5. Manual smoke (engineer's machine, requires a real vault):
   `export SSH_AUTH_SOCK=~/.secreq/agent.sock; ssh-add -l` lists keys
   with no biometric; `ssh -T git@github.com` triggers one consent prompt
   showing the caller chain, then succeeds.
6. Confirm the design doc's three trust-model changes are reflected in
   `docs/overview.md` and `CLAUDE.md`.

No commit — this task gates the PR.

---

## Risks / notes for the executor

- **`op` private-key export is a hard prerequisite.** If `op read
  "op://.../private key"` does not return an OpenSSH key on the target
  vault, Tasks 6/10 cannot pass against a real provider — escalate before
  proceeding past Task 6.
- **`ssh-key` 0.6 signing API:** pin the exact call shape during Task 6;
  the generate→sign→verify test is the contract.
- **macOS `LOCAL_PEERPID`** constant is defined locally in Task 3;
  confirm against `<sys/un.h>` on the build target.
- Keep the SSH path **in-process** in the daemon — do not add SSH message
  types to the control-socket `proto.rs`; the only new wire format is the
  SSH agent protocol on `agent.sock`.
