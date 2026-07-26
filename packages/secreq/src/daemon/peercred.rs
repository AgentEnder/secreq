//! Peer-credential lookup for the daemon's unix sockets. A client is a
//! socket peer, not our parent, so we read its pid from the kernel and
//! feed it to `provenance::caller_chain_from_pid`.
//!
//! Both facts here come from the kernel about the process that called
//! `connect(2)`, so neither is forgeable by the peer.

use std::os::unix::io::AsRawFd;

/// Is the peer on `conn` the same user the daemon runs as?
///
/// Every socket is bound `0600` inside a directory this process owns, which
/// should already exclude a foreign uid. Should, not does: a unix socket's
/// permissions are checked at `connect(2)` only, and each socket is created
/// by `bind` and chmod'd on the *next* syscall, so it exists briefly at
/// `0777 & ~umask`. That is harmless under the common umask 022 and
/// connectable under the 002/000 that container and CI images set. A peer
/// that wins the race keeps a usable fd no matter what the mode becomes
/// afterwards.
///
/// So the mode is the lock and this is the second one. `None` means the
/// platform would not say, which callers treat as a refusal: an unverifiable
/// peer on a socket that hands out credentials is not a peer to serve.
pub fn peer_is_same_user<F: AsRawFd>(conn: &F) -> Option<bool> {
    // SAFETY: `geteuid` reads this process's own effective uid. It takes no
    // arguments, touches no memory, and is documented as always succeeding.
    let ours = unsafe { libc::geteuid() };
    peer_uid(conn).map(|theirs| theirs == ours)
}

/// Effective uid of the process on the other end of `conn`.
#[cfg(target_os = "linux")]
fn peer_uid<F: AsRawFd>(conn: &F) -> Option<u32> {
    // The same `SO_PEERCRED` call `peer_pid` makes; the uid rides along in
    // the struct and used to be dropped on the floor.
    peer_ucred(conn).map(|cred| cred.uid)
}

/// Effective uid of the process on the other end of `conn`.
#[cfg(target_os = "macos")]
fn peer_uid<F: AsRawFd>(conn: &F) -> Option<u32> {
    let fd = conn.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: FFI call into `getpeereid`. `fd` is a valid socket fd held
    // alive by `conn` for the duration of the call, and both out-params are
    // initialised locals we hand out by pointer. No memory escapes.
    let rc = unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) };
    (rc == 0).then_some(uid)
}

/// Best-effort pid of the process on the other end of `conn`.
#[cfg(target_os = "linux")]
pub fn peer_pid<F: AsRawFd>(conn: &F) -> Option<u32> {
    // `ucred::pid` is a `pid_t` (i32); positive values convert losslessly.
    peer_ucred(conn)
        .filter(|c| c.pid > 0)
        .and_then(|c| u32::try_from(c.pid).ok())
}

/// The peer's `SO_PEERCRED` record: pid, uid and gid in one call.
#[cfg(target_os = "linux")]
fn peer_ucred<F: AsRawFd>(conn: &F) -> Option<libc::ucred> {
    use std::mem;
    let fd = conn.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: FFI call into `getsockopt`. `fd` is a valid socket fd held
    // alive by `conn` for the duration of the call. The option value
    // buffer is `&mut cred` (a fully-initialised `ucred`) and `len` is
    // its byte size passed in/out by pointer, exactly as the kernel's
    // `SO_PEERCRED` contract requires. No memory escapes the call.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    (rc == 0).then_some(cred)
}

/// Best-effort pid of the process on the other end of `conn`.
#[cfg(target_os = "macos")]
pub fn peer_pid<F: AsRawFd>(conn: &F) -> Option<u32> {
    use std::mem;
    // From `<sys/un.h>`: the local-domain socket option level and the
    // option that returns the peer's pid. libc doesn't expose these on
    // all versions, so define them locally.
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;
    let fd = conn.as_raw_fd();
    let mut pid: libc::pid_t = 0;
    let mut len = mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: FFI call into `getsockopt`. `fd` is a valid socket fd held
    // alive by `conn` for the duration of the call. The option value
    // buffer is `&mut pid` (an initialised `pid_t`) and `len` is its
    // byte size passed in/out by pointer, as the `LOCAL_PEERPID`
    // contract requires. No memory escapes the call.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            (&raw mut pid).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc == 0 && pid > 0 {
        // `pid_t` is an i32; we've checked it's positive, so the
        // conversion to u32 is lossless.
        u32::try_from(pid).ok()
    } else {
        None
    }
}

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

    /// The second lock on every socket. A connection from this same process
    /// is the same user by definition, which is the case that must keep
    /// working — the refusal path needs a second uid to exercise and cannot
    /// be reached from a unit test.
    #[test]
    fn a_local_connection_is_recognised_as_the_same_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (server_conn, _) = listener.accept().unwrap();
        assert_eq!(peer_is_same_user(&server_conn), Some(true));
    }
}
