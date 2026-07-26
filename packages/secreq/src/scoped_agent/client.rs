//! Guest-side client for the scoped secret agent — the other end of
//! [`super::serve_on`].
//!
//! This is what runs **inside the sandbox**. It dials the socket named by
//! [`SOCK_ENV`], speaks the framed protocol in [`super::proto`], and hands
//! the answer to `secreq resolve` (see [`crate::commands::resolve`]). It is
//! the reference implementation of the protocol's guest half: everything
//! here is what brain's `--vm` guests, and anything else behind a forwarded
//! socket, may assume works.
//!
//! ## `SECREQ_SOCK` mirrors `SSH_AUTH_SOCK`
//!
//! Deliberately the same convention as the thing this feature is modelled on
//! (`docs/ssh-agent.md`): an env var names a unix socket, the socket is the
//! capability, and a process that has it can ask — nothing else is
//! configured, and no credential is persisted anywhere in the guest. brain
//! sets it in the sandbox's profile the way `ssh -A` sets `SSH_AUTH_SOCK`.
//!
//! ## The client is not trusted, and knows it
//!
//! Nothing this module sends can widen what the guest may have: the
//! allowlist, the scope name, and the consent decision all live on the host
//! (see [`super`]'s docs). Two consequences shape the code below:
//!
//! - **A denial is a normal answer, not a failure to retry.** The protocol
//!   splits [`Response::Denied`] from [`Response::Error`] precisely so a
//!   client doesn't retry a refusal into a click-training loop, and the CLI
//!   surfaces that split as distinct exit codes.
//! - **The caller chain we send is a claim.** See
//!   [`self_reported_chain`].

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::proto::{self, Request, Response};

/// The env var naming the scoped agent's socket, mirroring `SSH_AUTH_SOCK`.
///
/// Set inside a brain `--vm` sandbox, where the host forwards its scoped
/// socket in over `ssh -R`. Unset means there is nothing to ask — which is
/// an error worth spelling out rather than a connection to fumble, since a
/// user hitting it is nearly always on the host or in a tier that has no
/// forward (brain's container tier — see the design's transport section).
pub const SOCK_ENV: &str = "SECREQ_SOCK";

/// The socket path from [`SOCK_ENV`], or an error that says what to do.
///
/// An empty value is treated as unset: `SECREQ_SOCK=` is what an
/// unconditional `export` of an unset variable leaves behind, and letting it
/// through would produce a confusing "cannot connect to ``" instead.
pub fn socket_from_env() -> Result<PathBuf> {
    match std::env::var_os(SOCK_ENV) {
        Some(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        _ => bail!(
            "${SOCK_ENV} is not set: there is no scoped secret agent to ask.\n\
             \n\
             It is set for you inside a brain `--vm` sandbox, where the host \
             forwards its scoped agent socket in. If you are on the host (or in \
             a sandbox tier with no forward), open one and forward it yourself:\n\
             \n    \
             secreq agent open --scope <name> --allow <secret://…> --sock /tmp/secreq-<name>.sock\n    \
             ssh -R /run/secreq.sock:/tmp/secreq-<name>.sock <guest>\n\
             \n\
             then set {SOCK_ENV}=/run/secreq.sock in the guest."
        ),
    }
}

/// A connection to a scoped agent socket.
///
/// Held open across calls, because the protocol is a request/response
/// alternation on one stream rather than one connection per message — a
/// guest may `list` and then `resolve` without redialing.
///
/// `Debug` is safe to derive: a client holds a socket and nothing else. No
/// secret ever lives in this type — a resolved value is handed straight to
/// the caller, which prints and scrubs it.
#[derive(Debug)]
pub struct AgentClient {
    stream: UnixStream,
}

impl AgentClient {
    /// Dial the scoped agent.
    ///
    /// A connect failure is the single most likely thing to go wrong on this
    /// path and the least self-explanatory (a guest sees a socket path that
    /// is not the host's), so the error names both halves of the setup that
    /// can be broken: the agent process on the host and the forward between.
    pub fn connect(socket_path: &Path) -> Result<AgentClient> {
        let stream = UnixStream::connect(socket_path).with_context(|| {
            format!(
                "cannot reach the scoped secret agent on {} (named by ${SOCK_ENV})\n\
                 \n\
                 Either the host's `secreq agent open` is no longer running, or the \
                 socket forward into this sandbox is down. Check both: the agent on \
                 the host, and (for a VM) the `ssh -R` forward that carries it in.",
                socket_path.display()
            )
        })?;
        Ok(AgentClient { stream })
    }

    /// Send one request and read its answer.
    ///
    /// An `Err` here is a *transport* failure — the frame didn't go, or what
    /// came back wasn't a frame. A refusal is not an error: it arrives as a
    /// perfectly well-formed [`Response::Denied`].
    pub fn request(&mut self, request: &Request) -> Result<Response> {
        proto::write_message(&mut self.stream, request)?;
        proto::read_message::<Response, _>(&mut self.stream)?.context(
            "the scoped secret agent closed the connection without answering — \
             check the host's agent log (`secreq daemon log-path`)",
        )
    }
}

/// This process's own ancestry, as **this guest's** kernel reports it, for
/// the host to display next to an "unverifiable" marker.
///
/// ## Why calling `provenance` here is not the thing `CLAUDE.md` forbids
///
/// The rule is that the *host* side of the scoped agent must never consult
/// `provenance.rs` or `daemon/peercred.rs`, because a guest has no host pid
/// and a forwarded socket's peer is the tunnel rather than the asker — a
/// chain sourced there would be a fabrication dressed as evidence.
///
/// This function runs on the **guest** side, in the guest's own kernel,
/// about its own process tree. That makes it a truthful statement *locally*
/// and a mere claim *remotely*, which is exactly what the design's
/// guest-reported chain is: `super::GuestChain`'s docs, the prompt's marked
/// GUEST SAYS row, and the audit log's `unverified_guest_chain` field all
/// exist to keep it in that box. Nothing on the host may act on what we send
/// here — it cannot key the cache, cannot enter `Ask::callers`, and cannot
/// talk an out-of-scope ref past the allowlist — and this client gets no say
/// in any of that.
///
/// Best-effort by construction: a guest kernel `sysinfo` can't read yields an
/// empty chain, which renders no row at all. Nothing depends on it, so
/// nothing needs to fail when it's missing.
pub fn self_reported_chain() -> Vec<String> {
    // `.frames` only: whether this guest's own walk reached the top is not a
    // fact the host could use for anything. The claim is unverifiable however
    // complete it is, and qualifying it would only make it look measured.
    crate::provenance::caller_chain()
        .frames
        .into_iter()
        .map(|caller| caller.name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `$SECREQ_SOCK` is process-global; serialize the tests that move it.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_sock<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var_os(SOCK_ENV);
        match value {
            Some(v) => std::env::set_var(SOCK_ENV, v),
            None => std::env::remove_var(SOCK_ENV),
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var(SOCK_ENV, v),
            None => std::env::remove_var(SOCK_ENV),
        }
        out
    }

    #[test]
    fn an_unset_sock_names_the_variable_and_says_where_it_comes_from() {
        with_sock(None, || {
            let err = socket_from_env().expect_err("unset must be an error");
            let msg = format!("{err:#}");
            assert!(msg.contains(SOCK_ENV), "the error must name the var: {msg}");
            assert!(
                msg.contains("--vm"),
                "the error must say where it is normally set: {msg}"
            );
        });
    }

    /// `SECREQ_SOCK=` is what exporting an unset variable leaves behind. It
    /// must read as "unset", not as a path of "" to fail to connect to.
    #[test]
    fn an_empty_sock_is_treated_as_unset() {
        with_sock(Some(""), || {
            assert!(socket_from_env().is_err());
        });
    }

    #[test]
    fn a_set_sock_is_the_socket_path() {
        with_sock(Some("/run/secreq.sock"), || {
            assert_eq!(
                socket_from_env().expect("a set sock is a path"),
                PathBuf::from("/run/secreq.sock")
            );
        });
    }

    /// A dead path must produce an error that points at both things that can
    /// be broken, rather than a bare ENOENT.
    #[test]
    fn a_dead_socket_error_names_the_agent_and_the_forward() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = AgentClient::connect(&dir.path().join("nothing-here.sock"))
            .expect_err("connecting to nothing must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("agent open"), "{msg}");
        assert!(msg.contains("forward"), "{msg}");
    }
}
