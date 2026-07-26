//! Peer-credential lookup for the SSH agent socket. The SSH client is a
//! socket peer, not our parent, so we read its pid from the kernel and
//! feed it to `provenance::caller_chain_from_pid`.

use std::os::unix::io::AsRawFd;

/// Best-effort pid of the process on the other end of `conn`.
#[cfg(target_os = "linux")]
pub fn peer_pid<F: AsRawFd>(conn: &F) -> Option<u32> {
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
    if rc == 0 && cred.pid > 0 {
        // `ucred::pid` is a `pid_t` (i32); we've checked it's positive,
        // so the conversion to u32 is lossless.
        u32::try_from(cred.pid).ok()
    } else {
        None
    }
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
}
