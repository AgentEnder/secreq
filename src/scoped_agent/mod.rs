//! Scoped secret agent — serving `secret://` refs to a guest over a socket.
//!
//! `secreq agent open --scope <name> --allow <ref>… --sock <path>` binds an
//! **ephemeral, scoped** listener. A guest (today: a VM reaching it through
//! `ssh -R`; tomorrow: an exec-pump — see [`proto`]) speaks the framed
//! protocol in [`proto`] to resolve refs from the *host's* secreq instead of
//! having tokens copied into it.
//!
//! Design: `dev-docs/plans/2026-07-16-remote-secret-agent.md`.
//!
//! ## Why this is not `daemon/ssh_agent.rs`
//!
//! The SSH agent is the template — per-user socket, listing is free, every
//! use is gated, resolve fresh + zeroize, audit the decision — and this
//! module follows it closely. It diverges on exactly one thing, and that
//! divergence is the whole point of the design:
//!
//! **There is no provenance here, and we do not fake one.** `ssh_agent.rs`
//! reads the peer pid from the kernel (`daemon/peercred.rs`) and walks it to
//! an anchor (`provenance.rs`), because a local SSH client *is* a local
//! process. A guest VM is not: there is no host pid for a process inside
//! another kernel, and over a forwarded socket the peer pid is the **tunnel**
//! (sshd), not the asker. So this module **never calls `peercred` or
//! `provenance`** — [`Ask::callers`] is deliberately empty — and the consent
//! prompt gates on the **scope** instead, which the host declared when it
//! created the socket and which the guest therefore cannot forge.
//!
//! ## The three rules this module exists to enforce
//!
//! 1. **The allowlist is immutable for the socket's life.** [`Scope`] is
//!    built once, at open time, from the host's `--allow` flags, and is
//!    shared behind an `Arc` — there is no protocol verb that can add to it.
//! 2. **Out of scope → denied without a prompt.** [`handle_request`] checks
//!    the allowlist *before* it consults the [`Gate`], so an out-of-scope ref
//!    cannot reach the consent machinery at all. This is load-bearing twice
//!    over: it never trains click-through, and it denies a compromised guest
//!    the ability to enumerate the vault one prompt at a time.
//! 3. **Only the decision goes through the daemon; the material never does.**
//!    The [`Ask`] carries no `SecretAsk` (exactly like `ssh_agent::sign_ask`),
//!    so the daemon prompts but resolves nothing and caches nothing. On
//!    approve, [`DaemonGate`] resolves the ref itself through
//!    [`crate::resolve::resolve_all`] — fresh, per call — and zeroizes.

pub mod proto;

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

use crate::audit::{self, AuditEntry};
use crate::consent::Decision;
use crate::daemon::proto::{AgentAskInfo, Ask, DedupeKey};
use crate::manifest::{Manifest, Provider};
use crate::reference::Reference;
use crate::resolve::{resolve_all, ResolutionPlan, SecretRequest, Source};
use crate::secret::SecretValue;

use self::proto::{Request, Response};

/// A socket's declared scope: the principal name the consent prompt shows,
/// and the exact set of refs it may ask for.
///
/// Both halves are declared **by the host** at `agent open` time and are
/// immutable for the socket's life — the type has no mutating method, and
/// the server holds it behind an `Arc`. A guest can neither widen the
/// allowlist nor rename the principal, which is what makes "sandbox
/// `brain-nx-t5` wants `GH_TOKEN`" an unforgeable statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    name: String,
    allow: Vec<Reference>,
}

impl Scope {
    /// Build a scope from the host's declaration.
    ///
    /// An empty allowlist is rejected: a socket that may ask for nothing can
    /// only produce denials, so it's a mistake in the caller's invocation
    /// (brain passing an empty `sandbox.seed.env`), not a useful state.
    pub fn new(name: impl Into<String>, allow: Vec<Reference>) -> Result<Scope> {
        let name = name.into();
        if name.trim().is_empty() {
            bail!("scope name must not be empty");
        }
        if allow.is_empty() {
            bail!(
                "scope `{name}` has an empty allowlist: pass at least one --allow <secret://ref>"
            );
        }
        Ok(Scope { name, allow })
    }

    /// The principal the consent prompt shows.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Is `reference` inside this socket's declared scope?
    ///
    /// Exact match on both provider and locator. There is no prefix or glob
    /// matching, deliberately: a wildcard is how an allowlist quietly becomes
    /// a rubber stamp, and the host already knows the exact list (it's
    /// `sandbox.seed.env`'s refs).
    pub fn allows(&self, reference: &Reference) -> bool {
        self.allow.contains(reference)
    }

    /// The allowed ref **names**, as the host typed them — what `list`
    /// answers. Never values.
    pub fn allowed_refs(&self) -> Vec<String> {
        self.allow.iter().map(Reference::to_string).collect()
    }
}

/// The outcome of gating (and, on approve, resolving) one **allowed** ref.
///
/// Carries the [`Decision`] on every arm so the caller writes one audit row
/// per outcome with the decision that actually authorized (or refused) it —
/// `Approve` vs `ApproveAuto` vs `DenyAuto` are meaningfully different in
/// the log.
pub enum GateOutcome {
    /// Consent granted and the ref resolved fresh.
    Approved {
        decision: Decision,
        value: SecretValue,
    },
    /// Consent refused (user clicked Deny, an auto-deny rule fired, or the
    /// consent machinery was unreachable and we failed closed).
    Denied { decision: Decision },
    /// Approved, but resolution then failed. Distinct from `Denied`: the
    /// user said yes and the *provider* broke, which the guest should see as
    /// an error rather than a policy refusal.
    Error { message: String },
}

/// Gates one allowed ref: consent, then resolve.
///
/// A trait so the server's allowlist enforcement can be tested without a
/// daemon or a display: a test gate records its calls, and the out-of-scope
/// tests assert it was **never called** — which is the precise, observable
/// meaning of "denied without a prompt", since this trait is the only door
/// to the consent machinery.
///
/// Implementations are only ever called for refs that [`Scope::allows`];
/// [`handle_request`] enforces that before it gets here.
pub trait Gate: Send + Sync {
    fn resolve(&self, scope: &Scope, reference: &Reference) -> GateOutcome;
}

/// The production [`Gate`]: prompt through the consent daemon, then resolve
/// the ref in-process.
///
/// The daemon is asked for a **decision only** — the [`Ask`] carries no
/// `SecretAsk`, mirroring `daemon/ssh_agent.rs::sign_ask`. That keeps the
/// design's "resolve fresh, zeroize, never cache the material" invariant
/// true: routing through the daemon's resolve path (the way `secreq read`
/// does) would leave the value in the daemon's `SecretCache` for its
/// lifetime, which is exactly what a per-use guest gate must not do.
pub struct DaemonGate {
    /// Providers-only manifest, built once from the user's config.
    /// [`resolve_all`] reads `manifest.providers` and nothing else for a
    /// plan whose requests carry explicit provider names.
    manifest: Manifest,
}

impl DaemonGate {
    pub fn new(providers: BTreeMap<String, Provider>) -> DaemonGate {
        DaemonGate {
            manifest: Manifest {
                groups: BTreeMap::new(),
                providers,
            },
        }
    }
}

impl Gate for DaemonGate {
    fn resolve(&self, scope: &Scope, reference: &Reference) -> GateOutcome {
        let ask = agent_ask(scope, reference);
        // `show_indicator = false`: the wait indicator writes to the
        // *host's* stderr, which for a long-lived `agent open` is a log,
        // not a terminal a human is watching for this specific ref.
        let outcome = match crate::daemon::client::request_consent(ask, false) {
            Ok(outcome) => outcome,
            // Fail closed. `request_consent` already folds "no daemon" and
            // "no display" into a deny; an Err here is a real transport or
            // daemon-side failure, and a guest must not get a secret out of
            // one.
            Err(err) => {
                return GateOutcome::Error {
                    message: format!("consent request failed: {err:#}"),
                }
            }
        };
        if !outcome.decision.approved() {
            return GateOutcome::Denied {
                decision: outcome.decision,
            };
        }
        match resolve_fresh(&self.manifest, reference) {
            Ok(value) => GateOutcome::Approved {
                decision: outcome.decision,
                value,
            },
            Err(err) => GateOutcome::Error {
                message: format!("resolution failed after approval: {err:#}"),
            },
        }
    }
}

/// Resolve exactly one ref through [`resolve_all`], fresh.
///
/// A one-request [`ResolutionPlan`] built by hand rather than through
/// `build_plan`: `build_plan` derives its requests from the manifest's eager
/// set and the ambient environment, and a guest's request is neither — it's
/// one explicit ref that the allowlist has already authorized. Everything
/// downstream of the plan (provider lookup, `retrieve`, not-found handling)
/// is the shared `resolve.rs` path.
///
/// The returned [`SecretValue`] zeroizes on drop.
fn resolve_fresh(manifest: &Manifest, reference: &Reference) -> Result<SecretValue> {
    let plan = ResolutionPlan {
        requests: vec![SecretRequest {
            name: reference.to_string(),
            provider: reference.provider.clone(),
            locator: reference.locator.clone(),
            group: None,
            reason: None,
            description: None,
            // No fallback: a guest asking for a ref that doesn't resolve
            // must get an error, never a silent default.
            default: None,
            // The ref came from outside our own manifest, like an ambient
            // `secret://` env value would have.
            source: Source::Ambient,
        }],
    };
    let (mut resolved, _stats) = resolve_all(manifest, &plan)
        .with_context(|| format!("resolving {reference} for the scoped agent"))?;
    let secret = resolved
        .pop()
        .context("resolve_all returned no secret for a one-request plan")?;
    Ok(secret.value)
}

/// Build the consent [`Ask`] for one scoped-agent resolve.
///
/// Three fields carry the design decisions and are worth reading as such:
///
/// - **`callers` is empty.** Not "not yet populated" — *empty on purpose*.
///   See the module docs: there is no host-verifiable caller chain behind a
///   guest, and displaying an unverifiable one as if it were provenance
///   would be theater. The scope is the principal.
/// - **`secrets` is empty.** The daemon decides; it does not resolve. See
///   [`DaemonGate`].
/// - **`dedupe_key.wrap` names the scope *and* the ref.** Coalescing folds
///   asks with an equal key into one queue entry answered by one decision,
///   so a scope-only key would let a request for ref B ride a prompt the
///   user saw for ref A — releasing a secret that was never shown. The
///   audit row's `wrap` stays the coarser `agent:<scope>` (see
///   [`AuditEntry::agent_resolve`]); a dedupe key is an internal coalescing
///   identity and is free to be finer than a log label.
fn agent_ask(scope: &Scope, reference: &Reference) -> Ask {
    Ask {
        command: vec![format!("agent-resolve {reference}")],
        // A guest has no host cwd. Empty, like the SSH sign path's.
        cwd: String::new(),
        callers: Vec::new(),
        secrets: Vec::new(),
        providers: HashMap::new(),
        dedupe_key: DedupeKey {
            wrap: format!("agent:{}:{reference}", scope.name),
            // Our own pid: the scoped socket's lifetime is this process's
            // lifetime, so it's the honest "who is parked on this decision".
            ppid: std::process::id(),
            parent_start_time: 0,
        },
        ssh: None,
        agent: Some(AgentAskInfo {
            scope: scope.name.clone(),
            reference: reference.to_string(),
        }),
        // TTL-cached approvals per scope anchor are build step B; for now
        // every allowed request prompts. `false` also keeps the daemon's
        // parent-keyed approvals cache out of this path entirely.
        allow_remember: false,
        nested_run: false,
    }
}

/// Answer one request.
///
/// **This function is where deny-without-prompt lives.** The [`Scope::allows`]
/// check runs before `gate` is touched, so an out-of-scope ref is audited and
/// refused without the consent machinery ever seeing it. Everything else the
/// server does around this (framing, threads, zeroizing) is plumbing; this is
/// the policy.
pub fn handle_request(scope: &Scope, gate: &dyn Gate, request: Request) -> Response {
    match request {
        Request::List => {
            // Listing is free — no prompt, no consent, no audit row. It
            // releases nothing the host didn't already declare to this very
            // socket, and it mirrors the SSH agent's REQUEST_IDENTITIES.
            log(
                scope,
                format_args!("← list; answering {} ref(s)", scope.allow.len()),
            );
            Response::Refs {
                refs: scope.allowed_refs(),
            }
        }
        Request::Resolve { reference } => {
            let Some(reference) = Reference::parse(&reference) else {
                // Malformed input is an error, not a denial: nothing was
                // refused because nothing coherent was asked. The message
                // echoes no other ref.
                return Response::Error {
                    message: "not a well-formed secret://provider/locator reference".to_owned(),
                };
            };

            // ── The gate before the gate ──────────────────────────────
            if !scope.allows(&reference) {
                audit_release(scope, &reference, Decision::DenyOutOfScope);
                log(
                    scope,
                    format_args!("← resolve {reference}: OUTSIDE SCOPE; denied without a prompt"),
                );
                return Response::out_of_scope();
            }

            match gate.resolve(scope, &reference) {
                GateOutcome::Approved { decision, value } => {
                    audit_release(scope, &reference, decision);
                    log(
                        scope,
                        format_args!("← resolve {reference}: {}", decision.as_str()),
                    );
                    // `expose().to_owned()` is the one plaintext copy that
                    // leaves the zeroizing type; the caller
                    // (`write_response`) scrubs it and the encoded frame
                    // after the write. `value` itself zeroizes here on drop.
                    Response::Value {
                        value: value.expose().to_owned(),
                    }
                }
                GateOutcome::Denied { decision } => {
                    audit_release(scope, &reference, decision);
                    log(
                        scope,
                        format_args!("← resolve {reference}: {}", decision.as_str()),
                    );
                    Response::Denied {
                        message: "denied".to_owned(),
                    }
                }
                GateOutcome::Error { message } => {
                    log(
                        scope,
                        format_args!("← resolve {reference}: error: {message}"),
                    );
                    Response::Error { message }
                }
            }
        }
    }
}

/// Write one audit row for a release attempt: scope + ref + decision, and
/// **never the value**.
///
/// The scoped agent is a *client* of the consent daemon, like the wrap
/// client in `commands.rs` — so it writes its own rows, and this adds no new
/// exception to `CLAUDE.md`'s "the daemon never writes audit rows" rule.
///
/// Audit-write failure is non-fatal, mirroring every other audit site: a
/// missing row is a worse-than-nothing outcome, but failing a release the
/// user just approved (or, worse, erroring differently on the deny path and
/// leaking that a ref exists) would be worse still.
fn audit_release(scope: &Scope, reference: &Reference, decision: Decision) {
    let entry = AuditEntry::agent_resolve(scope.name(), &reference.to_string(), decision);
    if let Err(err) = audit::append(&entry) {
        log(
            scope,
            format_args!("failed to write audit row for {reference}: {err:#}"),
        );
    }
}

/// Log to the daemon's shared log file, tagged with the scope so several
/// concurrent scoped sockets are tellable apart in one log.
fn log(scope: &Scope, args: std::fmt::Arguments<'_>) {
    crate::daemon::log::log_at(&format!("agent:{}", scope.name), args);
}

/// Bind `socket_path` and serve until the listener is dropped or the process
/// exits. Blocks.
///
/// **Ephemeral**: the socket never outlives the process that declared it.
/// Three paths cover that, because the caller (brain, at sandbox teardown)
/// will use all three:
///
/// - normal return → [`SocketGuard`] unlinks on drop;
/// - **SIGTERM / SIGINT / SIGHUP** → a handler unlinks and exits. This is the
///   path that actually matters: the accept loop below never returns, so
///   without a handler `Drop` would never run and every stop would leak the
///   socket;
/// - SIGKILL / crash → nothing can run, so the *next* `open` reclaims the
///   stale file (see [`clear_stale_socket`]).
pub fn open(socket_path: &Path, scope: Scope, gate: Arc<dyn Gate>) -> Result<()> {
    clear_stale_socket(socket_path)?;
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind scoped agent socket {}", socket_path.display()))?;
    install_signal_cleanup(socket_path)?;
    // 0600 — same trust boundary as the daemon's own sockets: the socket is
    // the capability, so only this user may dial it. (A forwarded socket's
    // guest-side end is governed by SSH; see the design's transport section.)
    let mut perms = std::fs::metadata(socket_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(socket_path, perms)?;

    log(
        &scope,
        format_args!(
            "scoped listener bound at {} allowing {} ref(s)",
            socket_path.display(),
            scope.allowed_refs().len()
        ),
    );

    let guard = SocketGuard(socket_path.to_path_buf());
    serve_on(listener, Arc::new(scope), gate);
    drop(guard);
    Ok(())
}

/// Unlink the socket on the way out so a scope's socket never outlives the
/// process that declared it — an orphaned socket file would make the next
/// `agent open` on that path fail for no reason a user could see.
struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Make an existing socket path usable, but **only** when we can prove
/// nothing is listening on it.
///
/// A leftover socket file is ambiguous: it's either a live scope's socket
/// (clobbering it would silently hijack that guest's requests to *our*
/// allowlist — a security-relevant mix-up) or the corpse of a SIGKILLed
/// predecessor (refusing is then a dead end the user can't diagnose).
///
/// Connecting to it settles the question with a fact rather than a guess: a
/// live listener accepts, a stale file refuses. This is the same question the
/// daemon answers with its pidfile flock; a scoped socket has no pidfile
/// (its path is the caller's to choose), so we ask the socket itself.
fn clear_stale_socket(socket_path: &Path) -> Result<()> {
    if !socket_path.exists() {
        return Ok(());
    }
    if UnixStream::connect(socket_path).is_ok() {
        bail!(
            "socket path {} is already served by a live agent; refusing to clobber it (pick another --sock)",
            socket_path.display()
        );
    }
    std::fs::remove_file(socket_path).with_context(|| {
        format!(
            "remove stale socket {} left by a previous agent",
            socket_path.display()
        )
    })
}

/// Unlink the socket on SIGTERM / SIGINT / SIGHUP, then exit.
///
/// Necessary because [`serve_on`]'s accept loop never returns, so the
/// `SocketGuard` `Drop` in [`open`] can't run on a signal — and a signal is
/// the *normal* way this process stops (brain kills it at sandbox teardown;
/// a human Ctrl-Cs it). Without this, every stop would leave a socket file
/// behind.
///
/// Exiting from the handler thread is safe here: there is no state to flush
/// (approvals live in the daemon, audit rows are appended synchronously as
/// they happen) and any in-flight resolve is one we *want* to abandon — the
/// scope is going away.
fn install_signal_cleanup(socket_path: &Path) -> Result<()> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let path = socket_path.to_path_buf();
    let mut signals = signal_hook::iterator::Signals::new([SIGTERM, SIGINT, SIGHUP])
        .context("register scoped agent signal handler")?;
    thread::Builder::new()
        .name("secreq-agent-signals".to_owned())
        .spawn(move || {
            if signals.forever().next().is_some() {
                let _ = std::fs::remove_file(&path);
                std::process::exit(0);
            }
        })
        .context("spawn scoped agent signal thread")?;
    Ok(())
}

/// Accept loop: one thread per connection.
///
/// The testable entry point — a test binds a `UnixListener` on a tempdir
/// path and calls this directly with a synthetic [`Gate`], no daemon and no
/// VM. Mirrors `daemon/ssh_agent.rs::serve_on`.
pub fn serve_on(listener: UnixListener, scope: Arc<Scope>, gate: Arc<dyn Gate>) {
    for incoming in listener.incoming() {
        let Ok(stream) = incoming else {
            break; // Listener closed or unrecoverable accept error.
        };
        let scope = Arc::clone(&scope);
        let gate = Arc::clone(&gate);
        thread::Builder::new()
            .name("secreq-agent-conn".to_owned())
            .spawn(move || {
                if let Err(err) = handle_connection(stream, &scope, gate.as_ref()) {
                    log(&scope, format_args!("connection error: {err:#}"));
                }
            })
            .ok();
    }
}

/// Read framed requests off `stream` until the peer hangs up, answering each
/// in turn. The connection is held open across calls so a guest can list and
/// then resolve without redialing.
fn handle_connection(mut stream: UnixStream, scope: &Scope, gate: &dyn Gate) -> Result<()> {
    while let Some(payload) = proto::read_payload(&mut stream)? {
        let response = match serde_json::from_slice::<Request>(&payload) {
            Ok(request) => handle_request(scope, gate, request),
            // An unparseable frame is the guest's fault. Answer a defined
            // error and keep serving — and say nothing about what *would*
            // have parsed, so a malformed frame is not a probe.
            Err(err) => {
                log(scope, format_args!("malformed request frame: {err}"));
                Response::Error {
                    message: "unsupported or malformed request".to_owned(),
                }
            }
        };
        write_response(&mut stream, response)?;
    }
    Ok(())
}

/// Encode and write one response, scrubbing both plaintext copies of any
/// secret value it carried: the `Response`'s own `String` and the encoded
/// frame buffer. The frame is zeroized even if the write failed — a failed
/// write is exactly when the bytes are most likely to still be sitting in a
/// buffer we're about to drop.
fn write_response(stream: &mut UnixStream, response: Response) -> Result<()> {
    let mut frame = proto::encode(&response)?;
    if let Response::Value { mut value } = response {
        value.zeroize();
    }
    let result = stream
        .write_all(&frame)
        .and_then(|()| stream.flush())
        .context("write scoped-agent response");
    frame.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn reference(s: &str) -> Reference {
        Reference::parse(s).expect("valid reference")
    }

    fn test_scope() -> Scope {
        Scope::new(
            "brain-nx-t5",
            vec![
                reference("secret://op/Dev/gh/token"),
                reference("secret://op/Dev/linear/token"),
            ],
        )
        .expect("valid scope")
    }

    /// A [`Gate`] that records every ref it was asked to gate and answers
    /// with a canned outcome. The recording is the whole point: the
    /// out-of-scope tests assert the recorder stayed **empty**, which is how
    /// "no prompt was raised" is observable — this trait is the only path to
    /// the consent machinery.
    struct RecordingGate {
        calls: Mutex<Vec<String>>,
        value: String,
    }

    impl RecordingGate {
        fn new(value: &str) -> RecordingGate {
            RecordingGate {
                calls: Mutex::new(Vec::new()),
                value: value.to_owned(),
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("calls mutex").clone()
        }
    }

    impl Gate for RecordingGate {
        fn resolve(&self, _scope: &Scope, reference: &Reference) -> GateOutcome {
            self.calls
                .lock()
                .expect("calls mutex")
                .push(reference.to_string());
            GateOutcome::Approved {
                decision: Decision::Approve,
                value: SecretValue::new(self.value.clone()),
            }
        }
    }

    #[test]
    fn scope_allows_only_exact_declared_refs() {
        let scope = test_scope();
        assert!(scope.allows(&reference("secret://op/Dev/gh/token")));
        assert!(scope.allows(&reference("secret://op/Dev/linear/token")));
        // A different locator under an allowed provider is NOT allowed —
        // there is no prefix matching.
        assert!(!scope.allows(&reference("secret://op/Dev/gh/other")));
        assert!(!scope.allows(&reference("secret://op/Prod/gh/token")));
        // A different provider with an allowed locator is NOT allowed.
        assert!(!scope.allows(&reference("secret://keychain/Dev/gh/token")));
    }

    /// A path with nothing listening is a corpse (a SIGKILLed predecessor),
    /// and reclaiming it is what makes a restart work.
    #[test]
    fn clear_stale_socket_reclaims_a_dead_socket_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stale.sock");
        // Bind and immediately drop the listener: the file survives, but
        // nothing is accepting on it — exactly the SIGKILL aftermath.
        drop(UnixListener::bind(&path).expect("bind"));
        assert!(path.exists(), "precondition: the stale file is present");

        clear_stale_socket(&path).expect("a dead socket must be reclaimable");
        assert!(!path.exists(), "the stale socket should have been removed");
    }

    /// A path with a *live* listener must NOT be clobbered: taking it over
    /// would silently redirect another scope's guest onto our allowlist.
    #[test]
    fn clear_stale_socket_refuses_a_live_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("live.sock");
        let _listener = UnixListener::bind(&path).expect("bind");

        let err = clear_stale_socket(&path).expect_err("a live socket must not be clobbered");
        assert!(
            format!("{err:#}").contains("live agent"),
            "error should name the live owner, got: {err:#}"
        );
        assert!(path.exists(), "the live socket must be left alone");
    }

    /// A free path is a no-op — the common case.
    #[test]
    fn clear_stale_socket_is_a_noop_for_a_free_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        clear_stale_socket(&dir.path().join("free.sock")).expect("a free path is fine");
    }

    #[test]
    fn scope_rejects_empty_name_or_allowlist() {
        assert!(Scope::new("", vec![reference("secret://op/a/b")]).is_err());
        assert!(Scope::new("  ", vec![reference("secret://op/a/b")]).is_err());
        assert!(Scope::new("s", vec![]).is_err());
    }

    /// The load-bearing test: a ref outside the declared scope is denied
    /// **without the gate ever being consulted** — i.e. without a prompt.
    #[test]
    fn out_of_scope_ref_is_denied_without_consulting_the_gate() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::new("s3cret");

            let response = handle_request(
                &scope,
                &gate,
                Request::Resolve {
                    reference: "secret://op/Prod/aws/key".to_owned(),
                },
            );

            assert!(
                matches!(response, Response::Denied { .. }),
                "out-of-scope ref must be denied, got {response:?}"
            );
            assert!(
                gate.calls().is_empty(),
                "the gate (and therefore the prompt) must never be reached for an out-of-scope ref"
            );
        });
    }

    /// The same denial must be audited — a silent deny is invisible to a
    /// user trying to spot a guest probing the vault.
    #[test]
    fn out_of_scope_denial_is_audited_with_scope_ref_and_decision() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::new("s3cret");

            handle_request(
                &scope,
                &gate,
                Request::Resolve {
                    reference: "secret://op/Prod/aws/key".to_owned(),
                },
            );

            let history = audit::read_history(None).expect("read audit history");
            assert_eq!(history.len(), 1, "expected exactly one audit row");
            let row = &history[0];
            assert_eq!(row.wrap, "agent:brain-nx-t5");
            assert_eq!(row.secrets, vec!["secret://op/Prod/aws/key"]);
            assert_eq!(row.decision, "deny+out-of-scope");
            assert!(
                row.callers.is_empty(),
                "a guest has no host caller chain; the row must not invent one"
            );
        });
    }

    #[test]
    fn allowed_ref_reaches_the_gate_and_returns_the_value() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::new("ghp_token_value");

            let response = handle_request(
                &scope,
                &gate,
                Request::Resolve {
                    reference: "secret://op/Dev/gh/token".to_owned(),
                },
            );

            assert_eq!(
                response,
                Response::Value {
                    value: "ghp_token_value".to_owned()
                }
            );
            assert_eq!(gate.calls(), vec!["secret://op/Dev/gh/token"]);

            let history = audit::read_history(None).expect("read audit history");
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].decision, "approve");
            assert_eq!(history[0].wrap, "agent:brain-nx-t5");
        });
    }

    /// `list` is free: no gate call, no prompt, no audit row.
    #[test]
    fn list_returns_allowed_names_without_gating_or_auditing() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::new("s3cret");

            let response = handle_request(&scope, &gate, Request::List);

            assert_eq!(
                response,
                Response::Refs {
                    refs: vec![
                        "secret://op/Dev/gh/token".to_owned(),
                        "secret://op/Dev/linear/token".to_owned(),
                    ]
                }
            );
            assert!(gate.calls().is_empty(), "list must never prompt");
            assert!(
                audit::read_history(None)
                    .expect("read audit history")
                    .is_empty(),
                "list releases nothing, so it writes no audit row"
            );
        });
    }

    #[test]
    fn malformed_reference_is_an_error_not_a_denial() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::new("s3cret");

            let response = handle_request(
                &scope,
                &gate,
                Request::Resolve {
                    reference: "not-a-ref".to_owned(),
                },
            );

            assert!(matches!(response, Response::Error { .. }));
            assert!(gate.calls().is_empty());
        });
    }

    /// The ask the daemon sees must gate on the scope and carry no caller
    /// chain and no secrets — the three decisions in `agent_ask`'s docs.
    #[test]
    fn agent_ask_gates_on_scope_with_no_provenance_and_no_secrets() {
        let scope = test_scope();
        let reference = reference("secret://op/Dev/gh/token");
        let ask = agent_ask(&scope, &reference);

        let info = ask.agent.expect("agent asks carry AgentAskInfo");
        assert_eq!(info.scope, "brain-nx-t5");
        assert_eq!(info.reference, "secret://op/Dev/gh/token");

        assert!(
            ask.callers.is_empty(),
            "a guest has no host-verifiable caller chain; peercred/provenance must not be wired in"
        );
        assert!(
            ask.secrets.is_empty(),
            "the daemon decides but must not resolve — the material must not enter its cache"
        );
        assert!(ask.cwd.is_empty());
        assert!(ask.ssh.is_none());
        assert!(!ask.allow_remember);
    }

    /// Two refs in one scope must produce distinct dedupe keys, or the
    /// daemon would coalesce them into a single prompt and answer one with
    /// the other's decision.
    #[test]
    fn dedupe_key_distinguishes_refs_within_a_scope() {
        let scope = test_scope();
        let gh = agent_ask(&scope, &reference("secret://op/Dev/gh/token"));
        let linear = agent_ask(&scope, &reference("secret://op/Dev/linear/token"));
        assert_ne!(
            gh.dedupe_key.wrap, linear.dedupe_key.wrap,
            "two refs from one scope must not coalesce into one prompt"
        );
    }
}
