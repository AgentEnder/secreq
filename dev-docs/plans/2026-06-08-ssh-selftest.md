# SSH agent self-test — implementation plan

> **For Claude:** REQUIRED SUB-SKILL: superpowers:executing-plans.

**Goal:** Prove the agent can actually sign. A `secreq ssh-test [<name>]`
command (and a post-step after `ssh-setup` and `ssh-add`) connects to the
agent socket, asks it to sign some test bytes with the configured key, and
verifies the returned signature against the key's public half — exercising
the real consent→resolve→sign path.

---

## Task A — self-test plumbing + core + `secreq ssh-test`

**Files:** `src/daemon/ssh_proto.rs` (client encode/decode), `src/ssh_sign.rs`
(`verify`), new `src/ssh_selftest.rs`, `src/cli.rs`, `src/commands.rs`, tests.

1. **`ssh_proto` client side** (it currently only encodes server replies):
   - Promote/add `pub fn encode_sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8>` (a framed SSH_AGENTC_SIGN_REQUEST). A test helper already exists in the test module — make a production version.
   - Add `pub fn encode_request_identities() -> Vec<u8>`.
   - Add a client response decoder: `pub enum AgentResponse { Identities(Vec<(Vec<u8>, String)>), SignResponse(Vec<u8>), Failure, Success, Unsupported(u8) }` and `pub fn parse_response(frame: &[u8]) -> Result<AgentResponse>` (mirror `parse_request`'s framing/validation; SignResponse carries the inner signature string bytes). Unit-test round-trips with the existing encoders.
2. **`ssh_sign::verify`**: `pub fn verify(public_key_openssh: &str, data: &[u8], sig_blob: &[u8]) -> Result<bool>` — parse the public key (`PublicKey::from_openssh`), decode an `ssh_key::Signature` from `sig_blob` (`ssh_encoding::Decode`), and `signature::Verifier::verify` (the same path the existing `verify_blob` test helper uses — promote that logic to production). Unit-test: sign via `ssh_sign::sign` then `verify` returns true; a tampered blob/data returns false/err.
3. **`ssh_selftest` module**: `pub struct SelfTest { pub key_id: String, pub listed: bool, pub verified: bool }` and
   `pub fn run(agent_sock: &Path, identity: &SshIdentity, key_id: &str) -> Result<SelfTest>`:
   - Connect a `UnixStream` to `agent_sock`; a connection error → a clear `anyhow` error ("couldn't reach the agent socket at <path>; is the daemon running? try `secreq daemon install`").
   - Compute the key blob = `PublicKey::from_openssh(identity.public_key)?.to_bytes()?`.
   - Send `encode_request_identities()`, read one frame (small client-side framed read: 4-byte BE len + payload, bounded by the same 256 KiB cap), `parse_response` → `listed` = blob present in the answer.
   - Pick `flags`: RSA key → `SSH_AGENT_RSA_SHA2_256`, else `0` (detect via `PublicKey::algorithm()`).
   - Send `encode_sign_request(&blob, TEST_DATA, flags)` where `TEST_DATA = b"secreq ssh agent self-test"`; read the response. `Failure` → error ("agent refused to sign — denied, or the key didn't resolve"). `SignResponse(sig)` → `verified = ssh_sign::verify(&identity.public_key, TEST_DATA, &sig)?`.
   - Return the `SelfTest`.
4. **`secreq ssh-test [<name>]` command** (`commands::ssh_test(name: Option<String>, config_path)`):
   - Resolve `agent_sock` via `daemon::ssh_agent::default_agent_socket_path()`.
   - Load config; pick the identity by `<name>`, or iterate ALL `config.ssh` when no name. Empty config → friendly error pointing to `secreq ssh-add`.
   - For each: `ssh_selftest::run(...)`; print `✓ <name>: agent signed and the signature verifies` or a clear failure with the reason. Note that signing may prompt for consent (it's a real sign). Return non-zero if any verification fails.
   - Wire in `cli.rs`.
5. **Tests:** reuse the in-process agent harness from `tests/ssh_agent.rs` (stand up `serve_on` with a `SignContext` carrying a `State`, a `cat`-based fake provider returning a generated key, and a seeded `SshApprovalEntry` so no UI is needed). Then call `ssh_selftest::run(socket, identity, key_id)` and assert `listed == true` and `verified == true`. Add a negative: unknown key blob / no approval → `Failure` surfaces as an error. Plus the `ssh_proto`/`ssh_sign::verify` unit tests.

**Commit:** `feat(cli): secreq ssh-test — prove the agent can sign with a key`

## Task B — wire the post-step + docs + verify

**Files:** `src/commands.rs` (post-step in `ssh_setup_core` + `ssh_add_core`),
`docs/ssh-agent.md`, `docs/cli.md`.

- After `ssh-add` writes an identity (interactive path): `confirm_default_yes
  ("Test that the agent can sign with <name> now?")` → `ssh_test` for that
  name. Non-fatal; skip in the non-interactive (`--public-key`+`--private-key`)
  path. NOTE: a successful test requires the daemon to be running and the key
  to resolve (may prompt for consent / biometric) — message accordingly; if
  the socket isn't reachable, report it as a hint (run `secreq daemon install`),
  not a hard failure.
- After `ssh-setup`'s wiring step completes (guided, non-scripted): offer the
  same self-test for a chosen/most-recent identity.
- Keep scripted `ssh-setup --yes --method ...` unchanged (no self-test prompt).
- Docs: add `secreq ssh-test` to `docs/cli.md`; in `docs/ssh-agent.md` add a
  "Verify it works" note after onboarding (`secreq ssh-test`), explaining it
  performs a real signature and may prompt for approval.
- `cargo fmt`/`clippy -D warnings`/`cargo test` green; no UI change → no
  screenshots; no TODO/Task markers.

**Commit:** `feat(cli): self-test step after ssh-setup and ssh-add + docs`
