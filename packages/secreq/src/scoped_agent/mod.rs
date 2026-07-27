//! Scoped secret agent — serving `secret://` refs to a guest over a socket.
//!
//! `secreq agent open --scope <name> --allow <ref>… --sock <path>` binds an
//! **ephemeral, scoped** listener. A guest (today: a VM reaching it through
//! `ssh -R`; tomorrow: an exec-pump — see [`proto`]) speaks the framed
//! protocol in [`proto`] to resolve refs from the *host's* secreq instead of
//! having tokens copied into it.
//!
//! The guest's half of that conversation is [`client`] — `secreq resolve
//! <ref>`, dialling `$SECREQ_SOCK`. This module is the host's half; nothing
//! the client can say changes anything it decides.
//!
//! Design: `brain: areas/secreq/design/2026-07-16-remote-secret-agent.md`.
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
//! ## The four rules this module exists to enforce
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
//! 4. **The gate rests only on host-verifiable facts.** A guest may narrate
//!    its own caller chain ([`GuestChain`]); the user gets to read it, marked
//!    as the claim it is, and nothing else in this module may act on it. See
//!    below.
//!
//! ## Anchoring: what caches, and what cannot key the cache
//!
//! [`ScopeApprovals`] caches a **decision** — never material — against a
//! [`crate::consent::AgentGrant`], so a sandbox that was approved for a ref
//! isn't re-prompted for it for the next [`SCOPE_GRANT_TTL_SECS`] seconds.
//! The anchor is the scope, mirroring the SSH agent's `SshAnchor`/`SshGrant`
//! pair (and, like it, timer-bounded rather than lifetime-bounded, because a
//! scoped socket lives as long as the sandbox — hours).
//!
//! The [`GuestChain`] is **display-only**, and this module is built so that
//! it cannot be otherwise:
//!
//! - It reaches exactly one function, [`Gate::consent`], which returns a
//!   [`Decision`] for a human to make — and it is rendered there marked
//!   unverifiable. [`Gate::resolve`] has no parameter for it, so it cannot
//!   even influence *which material* is produced after an approval.
//! - It cannot key the cache: [`ScopeApprovals::granted`] and
//!   [`ScopeApprovals::remember`] take a `&Scope` and a `&Reference` and
//!   nothing else, and `AgentGrant` has no field to put one in.
//! - It cannot be *made* to key anything: [`GuestChain`] implements neither
//!   `Hash` nor `Eq` nor `Ord`, and holds a rendered display string rather
//!   than the guest's list, so there is nothing to compare and no map that
//!   will accept it.
//! - It never enters [`Ask::callers`], which is what `rules.rs` matches on
//!   and what `provenance.rs` fills from the kernel. A guest's story must not
//!   be able to fire an auto-approve rule.
//!
//! Why so much fuss for a display string: a guest-controlled cache key would
//! let a compromised guest replay a chain the user approved earlier and get a
//! **silent** release — no prompt, no chance to notice. The prompt is the
//! only place a claim is safe, because a human is reading it.

pub mod client;
pub mod proto;

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

use crate::audit::{self, AuditEntry, ScopeDeclarant};
use crate::consent::{AgentAnchor, AgentGrant, Decision};
use crate::daemon::proto::{AgentAskInfo, Ask, AskSubject, DedupeKey};
use crate::manifest::{Manifest, Provider};
use crate::reference::Reference;
use crate::resolve::{resolve_all, ResolutionPlan, SecretRequest, Source};
use crate::secret::SecretValue;

use self::proto::{Request, Response};

/// How long an approval anchors to its scope: **5 minutes**.
///
/// The same reasoning as `ssh_agent::SSH_SESSION_GRANT_TTL_SECS` (30
/// minutes), landing shorter. Both anchors outlive any single request by
/// hours, so both need a timer rather than a lifetime; the scoped agent takes
/// the tighter bound because its anchor is *coarser*. An SSH grant covers one
/// key used by one local session whose process tree the host can see; a scope
/// grant covers **everything running in a VM the host cannot inspect at all**
/// (see the design's "granularity is downgraded" note). A weaker principal
/// earns a shorter leash.
pub const SCOPE_GRANT_TTL_SECS: u64 = 300;

/// How many links of a guest's claimed chain are shown, and how wide each may
/// be. A guest can put ~64 KiB of anything in a frame; a prompt that a guest
/// can flood is a prompt whose *real* content (the SCOPE row) scrolls away,
/// which is a consent-UI attack rather than a cosmetic problem.
const MAX_GUEST_CHAIN_LINKS: usize = 12;
const MAX_GUEST_CHAIN_LINK_CHARS: usize = 48;

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

/// What a guest **claims** is asking — `node → pnpm → postinstall` — after
/// sanitizing. A claim, not a fact, and typed so that it can only ever be
/// used as one.
///
/// The host cannot verify a syllable of this (see the module docs): there is
/// no host pid behind a guest, so there is nothing to check the story
/// against. It is still worth showing — an honest guest's chain is exactly
/// the context a user wants, and a *dishonest* one is a signal in the audit
/// log — but only to a human, and only labelled.
///
/// ## Why this is a display string and not a `Vec<String>`
///
/// The type deliberately does not implement `Hash`, `Eq`, `Ord`, or
/// `PartialEq`, and does not expose the guest's list. Those are not
/// omissions to be filled in when something needs them; they are the
/// enforcement. A cache keyed on a guest's claim would let a compromised
/// guest replay an approved chain for a **silent** release, so the invariant
/// "guest input never keys the cache" is worth more than the convenience of a
/// derive. Without `Hash`/`Eq` there is no map this can key and no comparison
/// a policy branch can make: the invariant fails to compile rather than
/// failing in production.
///
/// Constructed once, at the wire boundary, by [`GuestChain::new`]. Past that
/// point the guest's structure is gone — only a string for a label remains.
#[derive(Debug, Clone, Default)]
pub struct GuestChain(Option<String>);

impl GuestChain {
    /// Sanitize a guest's claimed chain into something safe to render.
    ///
    /// Untrusted input on its way into a **consent UI**, so this is a trust
    /// boundary, not formatting:
    ///
    /// - **Control characters are stripped.** A chain of `"node\n⚠ verified
    ///   by host"` must not be able to paint a second line into the prompt.
    ///   Forging the very marker that says "don't trust me" would invert the
    ///   whole feature.
    /// - **Links and link widths are capped** ([`MAX_GUEST_CHAIN_LINKS`],
    ///   [`MAX_GUEST_CHAIN_LINK_CHARS`]), so a guest can't push the SCOPE row
    ///   — the part that is actually true — off the top of the prompt.
    /// - **Empty claims collapse to `None`**, which renders no row at all
    ///   rather than an empty one that reads as "nothing is asking".
    pub fn new(claimed: Vec<String>) -> GuestChain {
        let mut links: Vec<String> = claimed
            .iter()
            .map(|link| sanitize_link(link))
            .filter(|link| !link.is_empty())
            .take(MAX_GUEST_CHAIN_LINKS)
            .collect();
        if links.is_empty() {
            return GuestChain(None);
        }
        // Say so when there was more, rather than silently presenting a
        // truncated chain as the whole story.
        if claimed.len() > links.len() {
            links.push("…".to_owned());
        }
        GuestChain(Some(links.join(" → ")))
    }

    /// The rendered claim, for display next to an "unverifiable" marker, or
    /// `None` when the guest claimed nothing.
    ///
    /// The only accessor there is. It returns a `&str` for a label and an
    /// audit field — deliberately not the guest's list, because a list
    /// invites iteration and iteration invites a policy branch.
    pub fn display(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

/// Render a guest-supplied reference for the daemon log and the audit row.
///
/// **Every path that puts a ref in a file goes through here** — both log lines
/// and [`audit_release`]'s row. A ref that reaches one of them raw is the bug
/// this function exists to prevent, on either of two counts:
///
/// *Forging.* `Reference::parse` imposes no character restrictions, so
/// `secret://op/x\n[secreq +0.001s server] → Decision::Approve` is a
/// well-formed reference, and `daemon.log` is written by a bare `format!` — a
/// guest could write its own lines, in the house format, into the file a host
/// reads while investigating a suspected leak. `daemon.jsonl` and `audit.log`
/// escape through serde, but the Audit tab *renders* the row, so the
/// invisible-and-reordering filter earns its place there too.
///
/// *Volume.* A ref can be ~64 KiB, none of the three files rotates, and the
/// deny path is guest-triggerable without a prompt — three writes of that size
/// per request is a disk-filling loop whose real content is the length, not
/// the bytes.
fn display_ref(reference: &Reference) -> String {
    const MAX_REF_DISPLAY_CHARS: usize = 200;
    let rendered: String = reference
        .to_string()
        .chars()
        .filter(|c| !crate::provenance::is_invisible_or_reordering(*c))
        .take(MAX_REF_DISPLAY_CHARS)
        .collect();
    if rendered.chars().count() == MAX_REF_DISPLAY_CHARS {
        format!("{rendered}… (truncated)")
    } else {
        rendered
    }
}

/// One link of a claimed chain: visible characters only, trimmed, capped.
fn sanitize_link(link: &str) -> String {
    link.chars()
        .filter(|c| !crate::provenance::is_invisible_or_reordering(*c))
        .take(MAX_GUEST_CHAIN_LINK_CHARS)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// The consent door, and the resolve behind it — deliberately two methods.
///
/// A trait so the server's policy can be tested without a daemon or a
/// display: a test gate records its calls, and the out-of-scope and
/// cache-hit tests assert [`Gate::consent`] was **never called** — the
/// precise, observable meaning of "no prompt was raised", since this method
/// is the only route to the consent machinery.
///
/// ## Why consent and resolve are separate
///
/// They cache differently, and that is the design's central invariant:
/// *"resolve fresh, zeroize, never cache the material — only the decision
/// caches"*. [`handle_request`] can skip [`consent`](Gate::consent) on a
/// cache hit while still calling [`resolve`](Gate::resolve) every single
/// time. Fusing them into one "gate this ref" call would make the cheap
/// implementation of a TTL cache *also* cache the secret, which is exactly
/// the mistake worth making structurally impossible.
///
/// Note what each method is trusted with. `consent` gets the [`GuestChain`]
/// because a human is about to read it; `resolve` does not, because by then
/// there is nothing left for a claim to legitimately affect.
///
/// Implementations are only ever called for refs that [`Scope::allows`];
/// [`handle_request`] enforces that first.
pub trait Gate: Send + Sync {
    /// Ask the user (or the rules) about one allowed ref. Returns a
    /// **decision only** — never material.
    ///
    /// `Err` means the consent machinery itself was unreachable, which is
    /// distinct from a refusal: the guest is told the request errored rather
    /// than that policy refused it. Either way nothing is released.
    ///
    /// Returns [`Consented`] rather than a bare `Decision` because the audit
    /// row needs one more thing from this round-trip: the local process the
    /// **daemon** saw naming the scope. This process cannot supply it — it
    /// would be describing itself, and a forger describes itself just as
    /// fluently.
    fn consent(
        &self,
        scope: &Scope,
        reference: &Reference,
        guest_chain: &GuestChain,
    ) -> Result<Consented>;

    /// Resolve an **already-approved** ref, fresh. Called on every release,
    /// including one served from [`ScopeApprovals`] — the decision caches,
    /// the value never does.
    fn resolve(&self, scope: &Scope, reference: &Reference) -> Result<SecretValue>;
}

/// One answer from the host about one guest request.
///
/// The decision is what the guest experiences; `declared_by` is what the
/// **log** gets, and it is here rather than derived later because the daemon
/// is the only party that ever holds it. A scoped-agent audit row otherwise
/// records a scope name that any local process could have put on the wire,
/// which is exactly the forgery the prompt learned to render and the log
/// could not.
pub struct Consented {
    pub decision: Decision,
    pub declared_by: ScopeDeclarant,
}

/// The clock [`ScopeApprovals`] expires grants against.
///
/// Injectable because the alternative is a test that sleeps for five
/// minutes to prove one `if`. Production is [`SystemClock`]; tests hand in a
/// clock they can wind forward, which is the only way expiry gets asserted
/// as a *property* rather than assumed.
pub trait Clock: Send + Sync {
    /// Whole seconds since the Unix epoch.
    fn now_unix(&self) -> u64;
}

/// The real clock: wall time, in Unix seconds.
///
/// Wall time (not a monotonic instant) because that is what
/// `AgentGrant::expires_at` speaks, matching `SshGrant`. The tradeoff is
/// inherited and deliberate: a backwards clock step can end a grant early
/// (re-prompt — safe) but a forwards step can also end one early. Neither
/// direction can *extend* a grant past its stamp, so the failure mode is
/// always "ask the user again".
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// The scope anchor's approval cache: **decisions only**, clock-bounded.
///
/// Lives in the agent process rather than the daemon, which is what makes
/// "the second request is silent" true at the [`Gate`] — the daemon is never
/// dialled at all on a cache hit, so no prompt can even be queued. It also
/// keeps the daemon's parent-keyed approvals cache out of this path entirely
/// (`Ask::allow_remember` stays `false`): that cache keys on
/// `(wrap, ppid, parent_start_time)`, and a guest has no host parent to key
/// on, so its notion of identity is meaningless here.
///
/// The lifetime story falls out of where it lives: the cache is this
/// process's memory, and this process is the socket, and the socket is the
/// sandbox. Sandbox torn down → socket gone → grants gone, with no
/// invalidation logic to get wrong.
///
/// **What may key an entry:** the scope and the ref, both host-verifiable.
/// The method signatures below are the enforcement — there is no parameter
/// for a guest's claim, so "the guest chain is not in the cache key" is a
/// compile-time fact rather than a promise.
pub struct ScopeApprovals {
    grants: Mutex<Vec<AgentGrant>>,
    clock: Arc<dyn Clock>,
    ttl_secs: u64,
}

impl ScopeApprovals {
    /// Production: the real clock, the standard TTL.
    pub fn new() -> ScopeApprovals {
        ScopeApprovals::with_clock(Arc::new(SystemClock), SCOPE_GRANT_TTL_SECS)
    }

    /// Testing seam: an injectable clock and TTL.
    pub fn with_clock(clock: Arc<dyn Clock>, ttl_secs: u64) -> ScopeApprovals {
        ScopeApprovals {
            grants: Mutex::new(Vec::new()),
            clock,
            ttl_secs,
        }
    }

    /// Is there a live grant letting `scope` have `reference` without a
    /// prompt?
    ///
    /// Note the parameters: a host-declared scope and a ref the allowlist has
    /// already admitted. Nothing a guest said can reach this decision,
    /// because there is nowhere to pass it.
    pub fn granted(&self, scope: &Scope, reference: &Reference) -> bool {
        let now = self.clock.now_unix();
        let mut grants = self.grants.lock().expect("scope approvals mutex");
        // Prune on read: expired grants are dead weight, and dropping them
        // here means a long-lived socket's cache can't accumulate every ref
        // a chatty guest ever asked for.
        grants.retain(|grant| now < grant.expires_at);
        let reference = reference.to_string();
        grants
            .iter()
            .any(|grant| grant.matches(scope.name(), &reference, now))
    }

    /// Remember that `scope` may have `reference` for the TTL.
    ///
    /// Only ever called with a decision the user actively gave (see
    /// [`handle_request`]) — a denial has no path here, and could not express
    /// itself if it did: an [`AgentGrant`] is *only* a permission, so there
    /// is no such thing as a cached refusal to accidentally read as one.
    pub fn remember(&self, scope: &Scope, reference: &Reference) {
        let expires_at = self.clock.now_unix().saturating_add(self.ttl_secs);
        let reference = reference.to_string();
        let mut grants = self.grants.lock().expect("scope approvals mutex");
        // Re-approving refreshes rather than stacking duplicates.
        grants
            .retain(|grant| !(grant.anchor.scope == *scope.name() && grant.reference == reference));
        grants.push(AgentGrant {
            anchor: AgentAnchor {
                scope: scope.name().to_owned(),
            },
            reference,
            expires_at,
        });
    }
}

impl Default for ScopeApprovals {
    fn default() -> ScopeApprovals {
        ScopeApprovals::new()
    }
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
    fn consent(
        &self,
        scope: &Scope,
        reference: &Reference,
        guest_chain: &GuestChain,
    ) -> Result<Consented> {
        let ask = agent_ask(scope, reference, guest_chain);
        // `show_indicator = false`: the wait indicator writes to the
        // *host's* stderr, which for a long-lived `agent open` is a log,
        // not a terminal a human is watching for this specific ref.
        //
        // Fail closed on Err. `request_consent` already folds "no daemon"
        // and "no display" into a deny; an Err here is a real transport or
        // daemon-side failure, and a guest must not get a secret out of one.
        let outcome =
            crate::daemon::client::request_consent(ask, false).context("consent request failed")?;
        Ok(Consented {
            decision: outcome.decision,
            // Whatever the daemon read off `consent.sock`, unexamined. The
            // one field on this row we deliberately did not compute.
            declared_by: outcome.declared_by,
        })
    }

    fn resolve(&self, _scope: &Scope, reference: &Reference) -> Result<SecretValue> {
        resolve_fresh(&self.manifest, reference)
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
/// Most of what used to be a decision here is now a consequence of picking
/// [`AskSubject::ScopedAgent`], which is the point: the variant carries a
/// scope, a ref and the guest's claim, and nothing else exists to fill in.
///
/// - **There is no `callers` field.** Not "empty on purpose" — *absent*. See
///   the module docs: there is no host-verifiable caller chain behind a
///   guest, and displaying an unverifiable one as if it were provenance
///   would be theater. The scope is the principal.
/// - **`guest_chain` carries the guest's claim**, and it is the only place
///   it can go. A caller chain is what `rules.rs` matches on and what
///   `provenance.rs` fills from the kernel; a guest's story landing there
///   could fire an auto-approve rule, which would hand a compromised guest a
///   silent release by simply naming the right process. Two fields, because
///   they are two different kinds of thing: one the host saw, one the guest
///   said.
/// - **There is no `secrets` field either.** The daemon decides; it does not
///   resolve. See [`DaemonGate`].
/// - **`dedupe_key.wrap` names the scope *and* the ref — and nothing the
///   guest said.** Coalescing folds asks with an equal key into one queue
///   entry answered by one decision, so a scope-only key would let a request
///   for ref B ride a prompt the user saw for ref A — releasing a secret that
///   was never shown. By the same token the claimed chain must stay out of
///   it: a key a guest can vary is a key a guest can *steer*. The audit row's
///   `wrap` stays the coarser `agent:<scope>` (see
///   [`AuditEntry::agent_resolve`]); a dedupe key is an internal coalescing
///   identity and is free to be finer than a log label.
fn agent_ask(scope: &Scope, reference: &Reference, guest_chain: &GuestChain) -> Ask {
    Ask {
        command: vec![format!("agent-resolve {reference}")],
        dedupe_key: DedupeKey {
            wrap: format!("agent:{}:{reference}", scope.name),
            // Our own pid: the scoped socket's lifetime is this process's
            // lifetime, so it's the honest "who is parked on this decision".
            ppid: std::process::id(),
            parent_start_time: 0,
            subject_digest: None,
        },
        subject: AskSubject::ScopedAgent(AgentAskInfo {
            scope: scope.name.clone(),
            reference: reference.to_string(),
            guest_chain: guest_chain.display().map(str::to_owned),
            // Left empty on purpose. The daemon reads the socket peer and
            // fills this in (`server::adopt_peer_provenance`), overwriting
            // anything a client writes — which is what makes the row worth
            // reading, and is why the genuine client does not try to be
            // helpful here. Writing our own pid would be a claim; the row is
            // supposed to be the kernel's answer.
            declared_by: None,
        }),
    }
}

/// Answer one request.
///
/// **This function is where the policy lives.** Everything the server does
/// around it (framing, threads, zeroizing) is plumbing. Three things happen
/// here in a deliberate order:
///
/// 1. [`Scope::allows`] runs *before* `gate` is touched, so an out-of-scope
///    ref is audited and refused without the consent machinery ever seeing
///    it (deny-without-prompt).
/// 2. [`ScopeApprovals::granted`] runs *before* [`Gate::consent`], so a
///    request the scope was already approved for within the TTL is served
///    silently — no daemon dial, no prompt, one `approve+cached` audit row.
/// 3. [`Gate::resolve`] runs on **every** release, cached or not. The
///    decision caches; the material never does.
///
/// The [`GuestChain`] threads through to exactly two places: [`Gate::consent`]
/// (a human reads it) and the audit row (a human reads it later). It reaches
/// neither the allowlist check nor the cache — see the module docs for why
/// that is enforced by types rather than by care.
pub fn handle_request(
    scope: &Scope,
    approvals: &ScopeApprovals,
    gate: &dyn Gate,
    request: Request,
) -> Response {
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
        Request::Resolve {
            reference,
            guest_chain,
        } => {
            // The guest's claim stops being a list of strings *here*, at the
            // wire boundary, and becomes an opaque display value. Nothing
            // below this line can hash it, compare it, or branch on it —
            // see [`GuestChain`].
            let guest_chain = GuestChain::new(guest_chain);

            let Some(reference) = Reference::parse(&reference) else {
                // Malformed input is an error, not a denial: nothing was
                // refused because nothing coherent was asked. The message
                // echoes no other ref.
                return Response::Error {
                    message: "not a well-formed secret://provider/locator reference".to_owned(),
                };
            };

            // ── The gate before the gate ──────────────────────────────
            // Note what this asks about: the ref, against the host's
            // allowlist. Not what the guest says is asking for it — a
            // compromised guest naming a friendly-looking chain must get
            // exactly as far as an honest one, which is nowhere.
            if !scope.allows(&reference) {
                // `NotRead`, and it is the honest answer: the allowlist
                // refused this before any daemon was dialled, so nothing read
                // a peer for this row.
                audit_release(
                    scope,
                    &reference,
                    Decision::DenyOutOfScope,
                    &guest_chain,
                    ScopeDeclarant::NotRead,
                );
                log(
                    scope,
                    format_args!(
                        "← resolve {}: OUTSIDE SCOPE; denied without a prompt",
                        display_ref(&reference)
                    ),
                );
                return Response::out_of_scope();
            }

            // ── The anchor cache: host-verifiable facts only ──────────
            // `granted` takes the scope and the ref. There is no third
            // argument, so no story a guest tells can turn a miss into a
            // hit — which is precisely the "silent release" this design
            // refuses to sell.
            let Consented {
                decision,
                declared_by,
            } = if approvals.granted(scope, &reference) {
                // Served by the scope's own grant, so again nothing read a
                // peer for *this* row. The prompt that granted it has its own
                // row, with its own declarant.
                Consented {
                    decision: Decision::ApproveCached,
                    declared_by: ScopeDeclarant::NotRead,
                }
            } else {
                match gate.consent(scope, &reference, &guest_chain) {
                    Ok(consented) => consented,
                    Err(err) => {
                        // Same reasoning as the resolution failure below: the
                        // chain here carries `default_socket_path()`, which
                        // spells out the host's username and home layout.
                        log(
                            scope,
                            format_args!(
                                "← resolve {}: consent request failed: {err:#}",
                                display_ref(&reference)
                            ),
                        );
                        return Response::Error {
                            message: "the host could not answer this request".to_owned(),
                        };
                    }
                }
            };

            if !decision.approved() {
                audit_release(scope, &reference, decision, &guest_chain, declared_by);
                log(
                    scope,
                    format_args!(
                        "← resolve {}: {}",
                        display_ref(&reference),
                        decision.as_str()
                    ),
                );
                return Response::Denied {
                    message: "denied".to_owned(),
                };
            }

            // Only an approval the user actively anchored is remembered, and
            // only after `approved()` above has already returned. A denial
            // cannot reach this line, and an `AgentGrant` could not express
            // one if it did.
            if decision == Decision::ApproveAgentSession {
                approvals.remember(scope, &reference);
            }

            // Fresh, every time — including on the cached-decision path.
            match gate.resolve(scope, &reference) {
                Ok(value) => {
                    audit_release(scope, &reference, decision, &guest_chain, declared_by);
                    log(
                        scope,
                        format_args!(
                            "← resolve {}: {}",
                            display_ref(&reference),
                            decision.as_str()
                        ),
                    );
                    // `expose().to_owned()` is the one plaintext copy that
                    // leaves the zeroizing type; the caller
                    // (`write_response`) scrubs it and the encoded frame
                    // after the write. `value` itself zeroizes here on drop.
                    Response::Value {
                        value: value.expose().to_owned(),
                    }
                }
                // The user said yes and the *provider* broke. An error, not
                // a policy refusal — a guest that conflated them would retry
                // a denial, which is the click-training the design forbids.
                Err(err) => {
                    // The chain names host paths (`/Users/<you>/.secreq/...`)
                    // and provider CLI stderr (vault names, store paths). The
                    // guest has no use for any of it and is not supposed to
                    // learn the host's shape; it goes to the host's log, and
                    // the guest gets a fixed string like every other refusal.
                    log(
                        scope,
                        format_args!(
                            "← resolve {}: resolution failed after approval: {err:#}",
                            display_ref(&reference)
                        ),
                    );
                    Response::Error {
                        message: "the host could not resolve this reference".to_owned(),
                    }
                }
            }
        }
    }
}

/// Write one audit row for a release attempt: scope + ref + decision, the
/// guest's claim marked as such, and **never the value**.
///
/// The scoped agent is a *client* of the consent daemon, like the wrap
/// client in `commands/run.rs` — so it writes its own rows, and this adds no new
/// exception to `CLAUDE.md`'s "the daemon never writes audit rows" rule.
///
/// Audit-write failure is non-fatal, mirroring every other audit site: a
/// missing row is a worse-than-nothing outcome, but failing a release the
/// user just approved (or, worse, erroring differently on the deny path and
/// leaking that a ref exists) would be worse still.
///
/// The guest's claim lands in `unverified_guest_chain`, never in `callers` —
/// the row records both what the host knew (the scope) and what the guest
/// said, without letting the second masquerade as the first.
///
/// The ref goes in through [`display_ref`], the same bounded rendering the
/// daemon log uses, and for both of that function's reasons. `audit.log` has
/// no rotation and no size cap, so a guest that pipelines ~64 KiB refs down
/// the deny path is writing unbounded rows into the file a host reads to
/// investigate — burying the real ones is exactly the forensic damage the
/// deny-path audit row exists to prevent. And the row is *displayed*, in the
/// consent window's Audit tab, so it needs the same invisible-and-reordering
/// filter every other displayed string gets.
fn audit_release(
    scope: &Scope,
    reference: &Reference,
    decision: Decision,
    guest_chain: &GuestChain,
    declared_by: ScopeDeclarant,
) {
    let rendered = display_ref(reference);
    let entry = AuditEntry::agent_resolve(
        scope.name(),
        &rendered,
        decision,
        guest_chain.display(),
        declared_by,
    );
    if let Err(err) = audit::append(&entry) {
        log(
            scope,
            format_args!("failed to write audit row for {rendered}: {err:#}"),
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
///
/// `on_bound` is called once the socket is bound **and** narrowed to 0600,
/// immediately before serving begins — the first moment the path is both
/// dialable and safe to hand out. `commands::agent_open` prints the path from
/// it, so a caller that reads that line can `ssh -R` the socket straight away
/// rather than poll for its existence. Reporting from the caller instead
/// would have to happen before this function blocks, i.e. before the bind.
pub fn open(
    socket_path: &Path,
    scope: Scope,
    gate: Arc<dyn Gate>,
    on_bound: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    clear_stale_socket(socket_path)?;
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let listener = bind_private(socket_path)?;
    install_signal_cleanup(socket_path)?;

    log(
        &scope,
        format_args!(
            "scoped listener bound at {} allowing {} ref(s)",
            socket_path.display(),
            scope.allowed_refs().len()
        ),
    );

    let guard = SocketGuard(socket_path.to_path_buf());
    // Bound and 0600: the path is now real and private, so it's safe to tell
    // the world where it is. Failing here aborts before serving, and `guard`
    // unlinks on the way out — a socket nobody can be told about is worse
    // than no socket.
    on_bound(socket_path)?;

    // The approvals cache is created here and dropped with this process, so
    // the grants a sandbox earns can never outlive the sandbox's socket.
    serve_on(
        listener,
        Arc::new(scope),
        Arc::new(ScopeApprovals::new()),
        gate,
    );
    drop(guard);
    Ok(())
}

/// 0600 — same trust boundary as the daemon's own sockets: the socket is the
/// capability, so only this user may dial it. (A forwarded socket's
/// guest-side end is governed by SSH; see the design's transport section.)
const SOCKET_MODE: u32 = 0o600;

/// Create a fresh owner-only directory beside `parent` to bind in.
///
/// Fresh, because two `agent open`s can share a `--sock` directory and the
/// second must not bind over the first's in-flight socket; the pid separates
/// processes and the counter separates one process's own opens. The name is
/// short on purpose: it is a component of the path handed to `bind(2)`, which
/// is capped at 104 bytes on macOS, and this keeps the staged path no longer
/// than the published one for any realistic socket name.
fn create_staging_dir(parent: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let mut last = None;
    for _ in 0..16 {
        let dir = parent.join(format!(".sq{}.{}", std::process::id(), next_seq()));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {
                // `DirBuilder::mode` is masked by the umask, which can only
                // clear bits — but an owner bit cleared there would leave a
                // directory we cannot bind in, so say it unmasked.
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("set mode 0700 on {}", dir.display()))?;
                return Ok(dir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(dir),
            Err(e) => return Err(e).with_context(|| format!("create {}", dir.display())),
        }
    }
    bail!(
        "could not find a free staging directory beside {} (last tried {})",
        parent.display(),
        last.map(|p| p.display().to_string()).unwrap_or_default(),
    )
}

fn next_seq() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Bind the scoped listener and publish it at `socket_path`, owner-only —
/// with no moment at which the published path is dialable by anyone else.
///
/// `bind(2)` creates the socket at `0777 & ~umask` and the chmod that narrows
/// it lands on the *next* syscall. A unix socket's permissions are consulted
/// at `connect(2)` only, so a peer that dials inside those two syscalls keeps
/// a usable fd no matter what the mode becomes afterwards — and under the
/// 002/000 umask that container and CI images set, it is dialable for the
/// whole window.
///
/// The daemon's own sockets close this with a second lock, a peer-uid check
/// (`daemon::peercred`). **That answer is unavailable here by design**: over a
/// forwarded socket the peer is the tunnel (sshd), not the asker, so this
/// module never asks the kernel who its peer is (see the module docs and the
/// design's provenance section). Narrowing the socket's directory is not
/// available either — the directory is the caller's (`--sock /tmp/…`) and
/// chmodding it would be actively wrong.
///
/// So the window is removed rather than guarded: bind inside a 0700 directory
/// of our own that no other user can traverse, narrow the socket there, and
/// publish the finished socket with `rename`. The path the guest is handed
/// only ever exists 0600. `rename` also replaces the destination without
/// following a symlink at it, so a planted link cannot redirect the publish.
fn bind_private(socket_path: &Path) -> Result<UnixListener> {
    let parent = match socket_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let staging = create_staging_dir(parent)?;
    let staged = staging.join("s");

    let result = bind_staged(&staged, socket_path);

    // On success the socket has been renamed away and only the directory is
    // left; on failure both may be. Neither is anything to fail the open over.
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_dir(&staging);
    result
}

/// Bind at `staged` (inside the 0700 directory), narrow it, publish it.
fn bind_staged(staged: &Path, socket_path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let listener = UnixListener::bind(staged)
        .with_context(|| format!("bind scoped agent socket for {}", socket_path.display()))?;
    // Unmasked, and before the rename: the socket reaches the published path
    // already narrowed, which is the whole point of staging it.
    std::fs::set_permissions(staged, std::fs::Permissions::from_mode(SOCKET_MODE))
        .with_context(|| format!("set mode {SOCKET_MODE:o} on {}", staged.display()))?;
    std::fs::rename(staged, socket_path).with_context(|| {
        format!(
            "publish scoped agent socket at {} (bound at {})",
            socket_path.display(),
            staged.display()
        )
    })?;
    Ok(listener)
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
/// Exiting from the handler thread is safe here: there is no state worth
/// flushing (audit rows are appended synchronously as they happen, and the
/// [`ScopeApprovals`] grants are *meant* to die with the scope — they are
/// deliberately never persisted) and any in-flight resolve is one we *want*
/// to abandon: the scope is going away.
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
/// path and calls this directly with a synthetic [`Gate`] and a
/// [`ScopeApprovals`] on a fake [`Clock`], no daemon and no VM. Mirrors
/// `daemon/ssh_agent.rs::serve_on`.
///
/// `approvals` is shared across connections on purpose: a grant anchors to
/// the **scope**, not to a TCP-ish session, so a guest that hangs up and
/// redials within the TTL must not be re-prompted. The socket is the sandbox;
/// one connection is just one of its processes.
/// Concurrent guest connections served at once.
///
/// The guest is the one genuinely untrusted party in this codebase and it
/// opens the connections. Unbounded `thread::spawn` per accept meant a guest
/// could park thousands of threads — each with a stack reservation — by
/// connecting and saying nothing. Sixteen is far more than a sandbox
/// resolving a handful of refs needs, and the cap is on *concurrency*, not on
/// total connections: past it a guest waits rather than being refused.
const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// How long a connection may stay silent before it is dropped.
///
/// Pairs with the cap above: without a timeout, a guest that connects and
/// never writes holds one of the sixteen slots forever, so the cap alone
/// would just make the wedge cheaper. Generous, because a legitimate
/// connection can be idle while the *user* thinks about a prompt — that wait
/// happens after a request has been read, not before one.
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub fn serve_on(
    listener: UnixListener,
    scope: Arc<Scope>,
    approvals: Arc<ScopeApprovals>,
    gate: Arc<dyn Gate>,
) {
    // A permit per in-flight connection. Cloned into each thread and dropped
    // when it finishes, so the count falls back as connections close.
    let live = Arc::new(());

    for incoming in listener.incoming() {
        let Ok(stream) = incoming else {
            break; // Listener closed or unrecoverable accept error.
        };

        // `Arc::strong_count` is the number of live handlers plus our own
        // handle. Racy by nature — two accepts can read it at once — which is
        // fine: this bounds a resource, it does not enforce a policy, and
        // being off by one under a burst costs nothing.
        while Arc::strong_count(&live) > MAX_CONCURRENT_CONNECTIONS {
            thread::sleep(Duration::from_millis(20));
        }

        // A guest that connects and never speaks must not hold a slot.
        let _ = stream.set_read_timeout(Some(CONNECTION_IDLE_TIMEOUT));

        let scope = Arc::clone(&scope);
        let approvals = Arc::clone(&approvals);
        let gate = Arc::clone(&gate);
        let permit = Arc::clone(&live);
        thread::Builder::new()
            .name("secreq-agent-conn".to_owned())
            .spawn(move || {
                let _permit = permit;
                if let Err(err) = handle_connection(stream, &scope, &approvals, gate.as_ref()) {
                    log(&scope, format_args!("connection error: {err:#}"));
                }
            })
            .ok();
    }
}

/// Read framed requests off `stream` until the peer hangs up, answering each
/// in turn. The connection is held open across calls so a guest can list and
/// then resolve without redialing.
fn handle_connection(
    mut stream: UnixStream,
    scope: &Scope,
    approvals: &ScopeApprovals,
    gate: &dyn Gate,
) -> Result<()> {
    while let Some(payload) = proto::read_payload(&mut stream)? {
        let mut response = match serde_json::from_slice::<Request>(&payload) {
            Ok(request) => handle_request(scope, approvals, gate, request),
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
        write_response(&mut stream, &mut response)?;
    }
    Ok(())
}

/// Encode and write one response, scrubbing both plaintext copies of any
/// secret value it carried: the `Response`'s own `String` and the encoded
/// frame buffer.
///
/// **Both are scrubbed on every path out, including the failing ones.** A
/// failed write is exactly when the bytes are most likely to still be sitting
/// in a buffer we're about to drop, and a failed *encode* is worse: `encode`
/// bails when the payload clears [`proto::MAX_FRAME_LEN`], which a real secret
/// reaches — a certificate, or a large private key. So the encode's `Result`
/// is bound rather than `?`-ed, the response is scrubbed, and only then does
/// the error propagate. `response` is borrowed rather than consumed so that
/// postcondition is something a caller (and a test) can observe.
fn write_response(stream: &mut UnixStream, response: &mut Response) -> Result<()> {
    // Bound, not `?`-ed: the scrub below has to run even when this failed.
    let encoded = proto::encode(&*response);
    if let Response::Value { value } = response {
        value.zeroize();
    }
    let mut frame = encoded?;
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

    /// A [`Gate`] that records every **prompt** it was asked to raise and
    /// answers with a canned decision.
    ///
    /// The recording is the whole point: `consent` is the only path to the
    /// consent machinery, so "`prompts()` is empty" is precisely "no prompt
    /// was raised" — an observable fact rather than a proxy for one. The
    /// out-of-scope tests and the cache-hit tests both rest on it.
    ///
    /// `resolves` is recorded separately because the two must diverge: a
    /// cached release prompts zero times and resolves once, which is the
    /// "decision caches, material doesn't" invariant made countable.
    struct RecordingGate {
        prompts: Mutex<Vec<String>>,
        resolves: Mutex<Vec<String>>,
        /// What the guest claimed, as seen by `consent`. Asserted on to prove
        /// the chain reaches the *prompt* — the one place it is allowed to go.
        seen_chains: Mutex<Vec<Option<String>>>,
        decision: Decision,
        value: String,
    }

    impl RecordingGate {
        fn new(value: &str) -> RecordingGate {
            RecordingGate::deciding(Decision::Approve, value)
        }

        fn deciding(decision: Decision, value: &str) -> RecordingGate {
            RecordingGate {
                prompts: Mutex::new(Vec::new()),
                resolves: Mutex::new(Vec::new()),
                seen_chains: Mutex::new(Vec::new()),
                decision,
                value: value.to_owned(),
            }
        }

        fn prompts(&self) -> Vec<String> {
            self.prompts.lock().expect("prompts mutex").clone()
        }

        fn resolves(&self) -> Vec<String> {
            self.resolves.lock().expect("resolves mutex").clone()
        }

        fn seen_chains(&self) -> Vec<Option<String>> {
            self.seen_chains.lock().expect("chains mutex").clone()
        }
    }

    impl Gate for RecordingGate {
        fn consent(
            &self,
            _scope: &Scope,
            reference: &Reference,
            guest_chain: &GuestChain,
        ) -> Result<Consented> {
            self.prompts
                .lock()
                .expect("prompts mutex")
                .push(reference.to_string());
            self.seen_chains
                .lock()
                .expect("chains mutex")
                .push(guest_chain.display().map(str::to_owned));
            Ok(Consented {
                decision: self.decision,
                declared_by: test_declarant(),
            })
        }

        fn resolve(&self, _scope: &Scope, reference: &Reference) -> Result<SecretValue> {
            self.resolves
                .lock()
                .expect("resolves mutex")
                .push(reference.to_string());
            Ok(SecretValue::new(self.value.clone()))
        }
    }

    /// The declarant a genuine `secreq agent open` produces, as the daemon
    /// hands it back: the installed binary at the path the kernel loaded it
    /// from. Fixtures that care about a forgery build their own.
    fn test_declarant() -> ScopeDeclarant {
        ScopeDeclarant::Peer(crate::audit::AuditLocalPeer {
            pid: 4711,
            name: "secreq".to_owned(),
            command: "secreq agent open brain-nx-t5".to_owned(),
            exe: Some("/usr/local/bin/secreq".to_owned()),
        })
    }

    /// A clock a test winds by hand. Expiry is a property worth asserting,
    /// and a test that sleeps for five minutes to assert it would be deleted
    /// by the first person who ran the suite.
    struct FakeClock(Mutex<u64>);

    impl FakeClock {
        fn at(now: u64) -> Arc<FakeClock> {
            Arc::new(FakeClock(Mutex::new(now)))
        }
        fn advance(&self, secs: u64) {
            *self.0.lock().expect("clock mutex") += secs;
        }
    }

    impl Clock for FakeClock {
        fn now_unix(&self) -> u64 {
            *self.0.lock().expect("clock mutex")
        }
    }

    /// Approvals on a real clock, for tests that don't care about time.
    fn approvals() -> ScopeApprovals {
        ScopeApprovals::new()
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

    /// Closing our listener does not always make the socket dead *yet*.
    ///
    /// Other tests in this binary run real subprocesses (`provider::tests`
    /// shells out to `sh`), and `Command::spawn` forks. A fork that lands
    /// between our `bind` and our `drop` copies the listening fd into the
    /// child, which holds it until `exec` closes it (Rust sets `CLOEXEC`).
    /// For that window the socket is still listening on someone else's fd
    /// and `connect()` keeps succeeding — so the "corpse" this test means to
    /// build is briefly alive, and `clear_stale_socket` correctly refuses it.
    ///
    /// So wait for the precondition instead of assuming it: poll until the
    /// socket really is refusing connections. The wait is for a condition,
    /// not a duration, and it fails loudly rather than silently proceeding
    /// against a live socket.
    fn wait_until_socket_is_dead(path: &Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while UnixStream::connect(path).is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "{} never stopped accepting: an inherited fd outlived its exec, \
                 or something really is listening",
                path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
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
        wait_until_socket_is_dead(&path);

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

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    /// The published socket is dialable and owner-only — the shape the guest
    /// side depends on, unchanged by how it got there.
    #[test]
    fn bind_private_publishes_an_owner_only_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scope.sock");

        let _listener = bind_private(&path).expect("bind");

        assert_eq!(mode_of(&path), 0o600, "the published socket must be 0600");
        UnixStream::connect(&path).expect("the published path must be dialable");
    }

    /// **The window.** `bind(2)` creates the socket at `0777 & ~umask` and the
    /// chmod lands on the *next* syscall; a unix socket's permissions are
    /// checked at `connect(2)` only, so a peer that dials inside that window
    /// keeps a usable fd whatever the mode becomes afterwards.
    ///
    /// The daemon's sockets close this with a peer-uid check; this one may
    /// never ask who the peer is (over a forward it is sshd, not the asker),
    /// so it closes the window by construction instead: the socket is bound
    /// somewhere the published path is not, and only *arrives* there — by
    /// rename, already 0600 — once it is safe to dial.
    ///
    /// A second user racing the window is not reachable from a unit test, so
    /// what is asserted is the construction: `getsockname` still names the
    /// staging path, proving the published path was never the bind target.
    #[test]
    fn bind_private_never_binds_at_the_published_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scope.sock");

        let listener = bind_private(&path).expect("bind");

        let bound = listener
            .local_addr()
            .expect("local_addr")
            .as_pathname()
            .expect("a pathname socket")
            .to_path_buf();
        assert_ne!(
            bound, path,
            "the socket must be bound out of reach and renamed into place, \
             not bound at the path the guest is handed"
        );
    }

    /// The directory the socket is bound in is the whole fix: 0700 means the
    /// window between `bind` and `chmod` is inside a directory no other user
    /// can traverse, so there is no moment at which anyone else could dial.
    #[test]
    fn the_staging_directory_is_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let staging = create_staging_dir(dir.path()).expect("staging dir");

        assert_eq!(
            mode_of(&staging),
            0o700,
            "the socket is bound in here; anything wider reopens the window"
        );
    }

    /// Two openers on one directory must not collide onto one staging name —
    /// the second would bind over the first's in-flight socket.
    #[test]
    fn staging_directories_are_unique() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = create_staging_dir(dir.path()).expect("first");
        let second = create_staging_dir(dir.path()).expect("second");
        assert_ne!(first, second);
    }

    /// Staging is an implementation detail: nothing of it may survive beside
    /// the socket, or the next `agent open` inherits litter it can't explain.
    #[test]
    fn bind_private_leaves_no_staging_litter() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scope.sock");

        let _listener = bind_private(&path).expect("bind");

        let names: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["scope.sock".to_string()]);
    }

    /// The socket's parent is the *caller's* choice (`--sock /tmp/…`), so it
    /// is not ours to narrow — the reason `1adfb15` left this socket alone.
    /// Closing the window must not become a chmod of someone's `/tmp`.
    #[test]
    fn bind_private_does_not_narrow_the_parent_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let parent = dir.path().join("shared");
        std::fs::create_dir(&parent).expect("mkdir");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let _listener = bind_private(&parent.join("scope.sock")).expect("bind");

        assert_eq!(
            mode_of(&parent),
            0o755,
            "the caller's directory is not ours"
        );
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
                &approvals(),
                &gate,
                Request::resolve("secret://op/Prod/aws/key"),
            );

            assert!(
                matches!(response, Response::Denied { .. }),
                "out-of-scope ref must be denied, got {response:?}"
            );
            assert!(
                gate.prompts().is_empty(),
                "the gate (and therefore the prompt) must never be reached for an out-of-scope ref"
            );
        });
    }

    /// The gap this closes: an `agent:` row named a scope any local process
    /// could have put on the wire, and nothing on it said which one did. The
    /// prompt renders that peer; the row now keeps it, so a forgery is still
    /// legible after the window is gone.
    #[test]
    fn a_released_row_records_the_process_the_daemon_saw_naming_the_scope() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::new("s3cret");

            handle_request(
                &scope,
                &approvals(),
                &gate,
                Request::resolve("secret://op/Dev/gh/token"),
            );

            let history = audit::read_history(None).expect("read audit history");
            let row = history.last().expect("one row");
            let Some(ScopeDeclarant::Peer(peer)) = row.declared_by.as_ref() else {
                panic!(
                    "expected the daemon's reading of the peer, got {:?}",
                    row.declared_by
                );
            };
            assert_eq!(peer.pid, 4711);
            assert_eq!(peer.exe.as_deref(), Some("/usr/local/bin/secreq"));
            assert!(
                row.callers.is_empty(),
                "the peer is not a caller chain and must not become one"
            );
        });
    }

    /// A release the *scope* decided — refused by its allowlist, or served by
    /// its cached grant — never reached the daemon, so nothing read a peer.
    /// Recording that as `NotRead` rather than as an unreadable peer is the
    /// difference between "nobody looked" and "we looked and it was gone".
    #[test]
    fn a_release_that_never_reached_the_daemon_records_that_nothing_looked() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::new("s3cret");

            // Refused by the allowlist, before any consent request.
            handle_request(
                &scope,
                &approvals(),
                &gate,
                Request::resolve("secret://op/Prod/aws/key"),
            );
            // Served by the scope's own grant: approve once with the grant
            // decision, then ask again.
            let granting = RecordingGate::deciding(Decision::ApproveAgentSession, "s3cret");
            let approvals = approvals();
            handle_request(
                &scope,
                &approvals,
                &granting,
                Request::resolve("secret://op/Dev/gh/token"),
            );
            handle_request(
                &scope,
                &approvals,
                &granting,
                Request::resolve("secret://op/Dev/gh/token"),
            );

            let history = audit::read_history(None).expect("read audit history");
            assert_eq!(history.len(), 3);
            assert_eq!(history[0].declared_by, Some(ScopeDeclarant::NotRead));
            assert!(
                matches!(history[1].declared_by, Some(ScopeDeclarant::Peer(_))),
                "the prompted release records the peer the daemon read"
            );
            assert_eq!(
                history[2].decision, "approve+cached",
                "the second ask rides the grant"
            );
            assert_eq!(
                history[2].declared_by,
                Some(ScopeDeclarant::NotRead),
                "a cached release consulted nothing; the row that granted it \
                 carries the declarant"
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
                &approvals(),
                &gate,
                Request::resolve("secret://op/Prod/aws/key"),
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

    /// The deny path is the only unauthenticated, unprompted, guest-triggerable
    /// write path on the host, and `Reference::parse` caps nothing — a ~64 KiB
    /// ref is well-formed. The daemon log has been bounded since `display_ref`
    /// landed; `audit.log` was still taking the whole thing, which is the same
    /// disk-filling loop against a file with no rotation.
    #[test]
    fn an_overlong_out_of_scope_ref_is_bounded_in_the_audit_row() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::new("s3cret");
            let long = format!("secret://op/{}", "A".repeat(65_000));

            handle_request(&scope, &approvals(), &gate, Request::resolve(&long));

            let history = audit::read_history(None).expect("read audit history");
            let row = &history[0];
            let audited = &row.secrets[0];
            assert!(
                audited.chars().count() < 300,
                "{} chars reached audit.log",
                audited.chars().count()
            );
            assert!(audited.ends_with("… (truncated)"), "{audited}");
        });
    }

    /// A locator may contain a newline, so a raw ref in a `format!`-written
    /// daemon log line is a log-forging primitive. `display_ref` strips them;
    /// the audit row must be given the same rendering, since the consent UI's
    /// Audit tab displays it.
    #[test]
    fn a_forged_out_of_scope_ref_cannot_forge_an_audit_row_display() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::new("s3cret");

            handle_request(
                &scope,
                &approvals(),
                &gate,
                Request::resolve("secret://op/x\u{202E}y\nz"),
            );

            let history = audit::read_history(None).expect("read audit history");
            let audited = &history[0].secrets[0];
            assert!(!audited.contains('\n'), "{audited:?}");
            assert!(!audited.contains('\u{202E}'), "{audited:?}");
        });
    }

    #[test]
    fn allowed_ref_reaches_the_gate_and_returns_the_value() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::new("ghp_token_value");

            let response = handle_request(
                &scope,
                &approvals(),
                &gate,
                Request::resolve("secret://op/Dev/gh/token"),
            );

            assert_eq!(
                response,
                Response::Value {
                    value: "ghp_token_value".to_owned()
                }
            );
            assert_eq!(gate.prompts(), vec!["secret://op/Dev/gh/token"]);
            assert_eq!(gate.resolves(), vec!["secret://op/Dev/gh/token"]);

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

            let response = handle_request(&scope, &approvals(), &gate, Request::List);

            assert_eq!(
                response,
                Response::Refs {
                    refs: vec![
                        "secret://op/Dev/gh/token".to_owned(),
                        "secret://op/Dev/linear/token".to_owned(),
                    ]
                }
            );
            assert!(gate.prompts().is_empty(), "list must never prompt");
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

            let response =
                handle_request(&scope, &approvals(), &gate, Request::resolve("not-a-ref"));

            assert!(matches!(response, Response::Error { .. }));
            assert!(gate.prompts().is_empty());
        });
    }

    /// The ask the daemon sees must gate on the scope and carry no caller
    /// chain and no secrets — the three decisions in `agent_ask`'s docs.
    ///
    /// Two of those three are now the variant's shape rather than this
    /// function's discipline, so the assertions read them back through the
    /// accessors every consumer uses: whatever a guest ask is asked for, the
    /// answer must stay empty.
    #[test]
    fn agent_ask_gates_on_scope_with_no_provenance_and_no_secrets() {
        let scope = test_scope();
        let reference = reference("secret://op/Dev/gh/token");
        let ask = agent_ask(&scope, &reference, &GuestChain::default());

        let AskSubject::ScopedAgent(info) = &ask.subject else {
            panic!("agent asks carry a ScopedAgent subject");
        };
        assert_eq!(info.scope, "brain-nx-t5");
        assert_eq!(info.reference, "secret://op/Dev/gh/token");

        assert!(
            ask.callers().is_empty(),
            "a guest has no host-verifiable caller chain; peercred/provenance must not be wired in"
        );
        assert!(
            ask.secrets().is_empty(),
            "the daemon decides but must not resolve — the material must not enter its cache"
        );
        assert!(ask.cwd().is_empty());
        assert!(!ask.allow_remember());
    }

    /// A cached decision skips the prompt but **not** the resolve. This is
    /// the invariant the split [`Gate`] exists to make expressible: one
    /// prompt, two resolutions.
    #[test]
    fn a_cached_decision_skips_the_prompt_and_still_resolves_fresh() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::deciding(Decision::ApproveAgentSession, "ghp_token_value");
            let approvals = ScopeApprovals::with_clock(FakeClock::at(1000), 300);

            for _ in 0..2 {
                let response = handle_request(
                    &scope,
                    &approvals,
                    &gate,
                    Request::resolve("secret://op/Dev/gh/token"),
                );
                assert_eq!(
                    response,
                    Response::Value {
                        value: "ghp_token_value".to_owned()
                    }
                );
            }

            assert_eq!(gate.prompts().len(), 1, "the second release must be silent");
            assert_eq!(
                gate.resolves().len(),
                2,
                "the decision caches; the material must not"
            );
        });
    }

    /// A denial must never populate the cache — a cached "no" that read back
    /// as a hit would become a silent "yes".
    #[test]
    fn a_denial_populates_no_grant() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::deciding(Decision::Deny, "ghp_token_value");
            let approvals = ScopeApprovals::with_clock(FakeClock::at(1000), 300);

            let response = handle_request(
                &scope,
                &approvals,
                &gate,
                Request::resolve("secret://op/Dev/gh/token"),
            );

            assert!(matches!(response, Response::Denied { .. }));
            assert!(
                approvals.grants.lock().expect("grants").is_empty(),
                "a denial must leave the approvals cache untouched"
            );
            assert!(
                gate.resolves().is_empty(),
                "a denied ref must never be resolved"
            );
        });
    }

    /// `handle_request` hands the guest's claim to `consent` — and to
    /// nothing else. The claim's *only* job is to be shown, so it must
    /// actually arrive where it can be.
    #[test]
    fn handle_request_gives_the_claim_to_consent_and_the_cache_ignores_it() {
        audit::with_temp_log(|| {
            let scope = test_scope();
            let gate = RecordingGate::deciding(Decision::ApproveAgentSession, "v");
            let approvals = ScopeApprovals::with_clock(FakeClock::at(1000), 300);

            handle_request(
                &scope,
                &approvals,
                &gate,
                Request::resolve_claiming(
                    "secret://op/Dev/gh/token",
                    vec!["node".to_owned(), "pnpm".to_owned()],
                ),
            );
            // A different story, same scope + ref: rides the grant.
            handle_request(
                &scope,
                &approvals,
                &gate,
                Request::resolve_claiming(
                    "secret://op/Dev/gh/token",
                    vec!["curl".to_owned(), "exfiltrate.sh".to_owned()],
                ),
            );

            assert_eq!(
                gate.seen_chains(),
                vec![Some("node → pnpm".to_owned())],
                "the claim must reach the prompt that was actually raised"
            );
            assert_eq!(
                gate.prompts().len(),
                1,
                "and a different claim must not buy a second prompt — it is not in the key"
            );
        });
    }

    // ── GuestChain: sanitizing an untrusted claim for display ────────────

    #[test]
    fn guest_chain_renders_links_nearest_first() {
        let chain = GuestChain::new(vec![
            "node".to_owned(),
            "pnpm".to_owned(),
            "postinstall".to_owned(),
        ]);
        assert_eq!(chain.display(), Some("node → pnpm → postinstall"));
    }

    #[test]
    fn an_empty_claim_renders_no_row_at_all() {
        // Nothing claimed, and nothing but whitespace claimed, are the same
        // thing: no row. An empty GUEST SAYS row would read as a positive
        // assertion that nothing is asking.
        assert!(GuestChain::new(vec![]).display().is_none());
        assert!(GuestChain::default().display().is_none());
        assert!(GuestChain::new(vec!["  ".to_owned(), String::new()])
            .display()
            .is_none());
    }

    /// A guest must not be able to paint its own lines into the consent
    /// prompt — least of all a forged "verified" marker, which would invert
    /// the entire feature.
    #[test]
    fn control_characters_are_stripped_from_a_claim() {
        let chain = GuestChain::new(vec![
            "node\n⚠ host-verified — TRUSTED".to_owned(),
            "pnpm\r\t\x1b[31m".to_owned(),
        ]);
        let rendered = chain.display().expect("a chain was claimed");
        assert!(
            !rendered.contains('\n') && !rendered.contains('\r') && !rendered.contains('\x1b'),
            "rendered: {rendered:?}"
        );
    }

    /// `char::is_control` is Unicode category Cc only. A bidi override is Cf
    /// and passes it, so `U+202E` used to survive into the prompt and reverse
    /// the text after it — the row whose one job is showing the reader what
    /// the guest actually said.
    #[test]
    fn bidi_and_zero_width_characters_are_stripped_from_a_claim() {
        let chain = GuestChain::new(vec![
            "\u{202E}rekcatta".to_owned(),
            "pn\u{200B}pm".to_owned(),
            "np\u{2066}m\u{2069}".to_owned(),
            "x\u{FEFF}y".to_owned(),
        ]);
        let rendered = chain.display().expect("a chain was claimed");
        for bad in ['\u{202E}', '\u{200B}', '\u{2066}', '\u{2069}', '\u{FEFF}'] {
            assert!(
                !rendered.contains(bad),
                "{bad:?} survived into: {rendered:?}"
            );
        }
        // The visible characters are kept, so the row still says something.
        assert!(rendered.contains("rekcatta") && rendered.contains("pnpm"));
    }

    /// A guest can put ~64 KiB in a frame. A prompt it can flood is a prompt
    /// whose true content scrolls out of view, so the claim is capped — and
    /// says when it was.
    #[test]
    fn an_overlong_claim_is_capped_and_marked_as_truncated() {
        let claimed: Vec<String> = (0..100).map(|i| format!("proc{i}")).collect();
        let rendered = GuestChain::new(claimed)
            .display()
            .expect("chain")
            .to_owned();
        assert_eq!(
            rendered.matches(" → ").count(),
            MAX_GUEST_CHAIN_LINKS,
            "expected {MAX_GUEST_CHAIN_LINKS} links plus an ellipsis: {rendered}"
        );
        assert!(
            rendered.ends_with("…"),
            "a truncated chain must not present itself as the whole story: {rendered}"
        );
    }

    #[test]
    fn an_overwide_link_is_capped() {
        let rendered = GuestChain::new(vec!["x".repeat(500)])
            .display()
            .expect("chain")
            .to_owned();
        assert_eq!(rendered.chars().count(), MAX_GUEST_CHAIN_LINK_CHARS);
    }

    // ── ScopeApprovals: the anchor cache ─────────────────────────────────

    #[test]
    fn approvals_are_a_miss_until_remembered_then_expire_on_the_clock() {
        let scope = test_scope();
        let gh = reference("secret://op/Dev/gh/token");
        let clock = FakeClock::at(1000);
        let approvals = ScopeApprovals::with_clock(clock.clone(), 300);

        assert!(
            !approvals.granted(&scope, &gh),
            "nothing is granted at first"
        );

        approvals.remember(&scope, &gh);
        assert!(approvals.granted(&scope, &gh));

        clock.advance(299);
        assert!(
            approvals.granted(&scope, &gh),
            "a grant covers its full TTL"
        );

        clock.advance(1);
        assert!(!approvals.granted(&scope, &gh), "and not one second longer");
    }

    /// Re-approving refreshes the same entry rather than stacking copies —
    /// a long-lived socket's cache must not grow without bound.
    #[test]
    fn remembering_the_same_grant_twice_refreshes_rather_than_stacks() {
        let scope = test_scope();
        let gh = reference("secret://op/Dev/gh/token");
        let clock = FakeClock::at(1000);
        let approvals = ScopeApprovals::with_clock(clock.clone(), 300);

        approvals.remember(&scope, &gh);
        clock.advance(200);
        approvals.remember(&scope, &gh);

        assert_eq!(
            approvals.grants.lock().expect("grants").len(),
            1,
            "a refresh must replace the grant, not add a second one"
        );
        // The refresh moved the deadline: the original would have died at
        // 1300, and we're past that.
        clock.advance(200);
        assert!(
            approvals.granted(&scope, &gh),
            "the refresh extended the TTL"
        );
    }

    /// A grant is per-`(scope, ref)`: approving one ref must not release
    /// another the user was never shown.
    #[test]
    fn a_grant_does_not_cover_a_different_ref() {
        let scope = test_scope();
        let approvals = ScopeApprovals::with_clock(FakeClock::at(1000), 300);

        approvals.remember(&scope, &reference("secret://op/Dev/gh/token"));

        assert!(!approvals.granted(&scope, &reference("secret://op/Dev/linear/token")));
    }

    /// A grant is per-scope: another sandbox never rides this one's
    /// approval, which is the anchor doing its job.
    #[test]
    fn a_grant_does_not_cover_a_different_scope() {
        let gh = reference("secret://op/Dev/gh/token");
        let approvals = ScopeApprovals::with_clock(FakeClock::at(1000), 300);
        let other = Scope::new("brain-nx-t6", vec![gh.clone()]).expect("valid scope");

        approvals.remember(&test_scope(), &gh);

        assert!(!approvals.granted(&other, &gh));
    }

    /// Expired grants are pruned on read, so a chatty guest can't make a
    /// long-lived socket accumulate an entry per ref it ever asked for.
    #[test]
    fn expired_grants_are_pruned_on_lookup() {
        let scope = test_scope();
        let gh = reference("secret://op/Dev/gh/token");
        let clock = FakeClock::at(1000);
        let approvals = ScopeApprovals::with_clock(clock.clone(), 300);

        approvals.remember(&scope, &gh);
        clock.advance(301);
        approvals.granted(&scope, &gh);

        assert!(
            approvals.grants.lock().expect("grants").is_empty(),
            "a dead grant must not linger in the cache"
        );
    }

    /// The claim rides the ask for the prompt to render — in the
    /// `ScopedAgent` subject, and **not** as a caller chain. A caller chain
    /// is what `rules.rs` matches on and what `provenance.rs` fills from the
    /// kernel; a guest able to write there could name a process that fires
    /// an auto-approve rule and collect a silent release.
    #[test]
    fn agent_ask_carries_the_guest_claim_for_display_but_never_as_callers() {
        let scope = test_scope();
        let chain = GuestChain::new(vec!["node".to_owned(), "pnpm".to_owned()]);
        let ask = agent_ask(&scope, &reference("secret://op/Dev/gh/token"), &chain);

        let AskSubject::ScopedAgent(info) = &ask.subject else {
            panic!("agent asks carry a ScopedAgent subject");
        };
        assert_eq!(info.guest_chain.as_deref(), Some("node → pnpm"));
        assert!(
            ask.callers().is_empty(),
            "a guest's claim must never be laundered into the kernel-sourced caller chain"
        );
    }

    /// The dedupe key must not vary with anything the guest says. A key a
    /// guest can steer is a coalescing identity a guest can steer.
    #[test]
    fn the_dedupe_key_is_unmoved_by_the_guest_claim() {
        let scope = test_scope();
        let gh = reference("secret://op/Dev/gh/token");

        let quiet = agent_ask(&scope, &gh, &GuestChain::default());
        let chatty = agent_ask(
            &scope,
            &gh,
            &GuestChain::new(vec!["curl".to_owned(), "exfiltrate.sh".to_owned()]),
        );

        assert_eq!(
            quiet.dedupe_key.wrap, chatty.dedupe_key.wrap,
            "the coalescing identity must rest on host-verifiable facts alone"
        );
    }

    /// Two refs in one scope must produce distinct dedupe keys, or the
    /// daemon would coalesce them into a single prompt and answer one with
    /// the other's decision.
    #[test]
    fn dedupe_key_distinguishes_refs_within_a_scope() {
        let scope = test_scope();
        let gh = agent_ask(
            &scope,
            &reference("secret://op/Dev/gh/token"),
            &GuestChain::default(),
        );
        let linear = agent_ask(
            &scope,
            &reference("secret://op/Dev/linear/token"),
            &GuestChain::default(),
        );
        assert_ne!(
            gh.dedupe_key.wrap, linear.dedupe_key.wrap,
            "two refs from one scope must not coalesce into one prompt"
        );
    }

    /// `Reference::parse` allows any bytes in a locator, and the deny path
    /// logs the ref to `daemon.log` — a bare `format!` with no escaping. A
    /// guest could therefore write its own lines, in the house format, into
    /// the file a host reads while investigating a suspected leak.
    #[test]
    fn a_logged_reference_cannot_forge_daemon_log_lines() {
        let forged = Reference::parse(
            "secret://op/x\n[secreq +100.000s server] → DaemonMsg::Decision::Approve",
        )
        .expect("a newline is a legal locator character");

        let rendered = display_ref(&forged);
        assert!(!rendered.contains('\n'), "rendered: {rendered:?}");
        assert!(!rendered.contains('\r'), "rendered: {rendered:?}");
    }

    /// A ref can be ~64 KiB and the deny path writes it to three files per
    /// request. What is worth recording about one that long is its length.
    #[test]
    fn an_overlong_reference_is_truncated_for_display() {
        let long = Reference::parse(&format!("secret://op/{}", "A".repeat(65_000)))
            .expect("a long locator is still a valid ref");
        let rendered = display_ref(&long);
        assert!(
            rendered.chars().count() < 300,
            "{} chars",
            rendered.chars().count()
        );
        assert!(rendered.ends_with("… (truncated)"), "{rendered}");
    }

    /// `write_response`'s contract is that the caller's plaintext is scrubbed
    /// by the time it returns, on **every** path. The over-cap path is the one
    /// that used to escape it: `encode` bails, the `?` propagates, and the
    /// value was freed intact. It is reachable with a real secret — a
    /// certificate or a large private key clears 64 KiB.
    #[test]
    fn an_over_cap_response_is_scrubbed_before_the_encode_error_propagates() {
        let (mut stream, _peer) = UnixStream::pair().expect("socketpair");
        let mut response = Response::Value {
            value: "A".repeat(proto::MAX_FRAME_LEN + 1),
        };

        let err = write_response(&mut stream, &mut response).expect_err("over-cap frame must bail");
        assert!(err.to_string().contains("exceeds the cap"), "{err:#}");

        let Response::Value { value } = &response else {
            panic!("the variant must survive the scrub, only its plaintext goes");
        };
        assert!(
            value.is_empty(),
            "{} bytes of plaintext survived the bail",
            value.len()
        );
    }

    /// The ordinary path holds the same postcondition — this is the one the
    /// original `value.zeroize()` already covered, kept so a future rewrite
    /// can't satisfy the test above by scrubbing only on the error path.
    #[test]
    fn a_written_response_is_scrubbed_after_a_successful_write() {
        let (mut stream, _peer) = UnixStream::pair().expect("socketpair");
        let mut response = Response::Value {
            value: "hunter2".to_owned(),
        };

        write_response(&mut stream, &mut response).expect("a small frame writes");

        let Response::Value { value } = &response else {
            panic!("the variant must survive the scrub, only its plaintext goes");
        };
        assert!(value.is_empty(), "plaintext survived a successful write");
    }
}
