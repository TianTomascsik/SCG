//! Low-level Linux IPC syscall helpers shared by the gateway and the client
//! libraries.
//!
//! Everything in this module is a thin, audited wrapper around `libc`. The
//! wrappers exist so that the unsafe surface is concentrated in one place and
//! the rest of the codebase can use ordinary `io::Result`-returning functions.
//!
//! All file descriptors created here are `O_CLOEXEC` by default so that a
//! forked/exec'd child never inherits a gateway endpoint by accident.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::path::Path;

use libc::{c_int, c_uint, c_void};

// ── memfd / sealing constants (defined locally so we do not depend on a
//    specific libc version exposing them) ──────────────────────────────────

/// `memfd_create` flag: set close-on-exec on the new descriptor.
pub const MFD_CLOEXEC: c_uint = 0x0001;
/// `memfd_create` flag: allow seals to be applied to the new descriptor.
pub const MFD_ALLOW_SEALING: c_uint = 0x0002;

/// `fcntl` command: add seals to a file.
pub const F_ADD_SEALS: c_int = 1033;
/// `fcntl` command: read the seals currently applied to a file.
pub const F_GET_SEALS: c_int = 1034;

/// Seal: prevent any further seals from being added.
pub const F_SEAL_SEAL: c_int = 0x0001;
/// Seal: prevent the file from being shrunk.
pub const F_SEAL_SHRINK: c_int = 0x0002;
/// Seal: prevent the file from being grown.
pub const F_SEAL_GROW: c_int = 0x0004;
/// Seal: prevent all writes through any descriptor or mapping.
pub const F_SEAL_WRITE: c_int = 0x0008;
/// Seal: prevent future writes while keeping existing writable mappings.
pub const F_SEAL_FUTURE_WRITE: c_int = 0x0010;

/// Peer credentials read from a connected `AF_UNIX` socket via `SO_PEERCRED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// Process ID of the connected peer at `connect`/`accept` time.
    pub pid: i32,
    /// Effective user ID of the connected peer.
    pub uid: u32,
    /// Effective group ID of the connected peer.
    pub gid: u32,
}

/// Fill `buf` with cryptographically secure random bytes.
///
/// Uses the `getrandom(2)` syscall and falls back to reading `/dev/urandom`
/// on the (very old) kernels that lack it.
pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let ret = unsafe {
            libc::getrandom(
                buf[filled..].as_mut_ptr() as *mut c_void,
                buf.len() - filled,
                0,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if err.raw_os_error() == Some(libc::ENOSYS) {
                return fill_random_urandom(buf);
            }
            return Err(err);
        }
        filled += ret as usize;
    }
    Ok(())
}

fn fill_random_urandom(buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(buf)
}

/// Create an anonymous, sealable in-memory file via `memfd_create(2)`.
///
/// The returned descriptor is created with `MFD_CLOEXEC | MFD_ALLOW_SEALING`
/// so that the gateway can later seal it read-only before sharing it.
pub fn memfd_create(name: &str) -> io::Result<RawFd> {
    let cname =
        CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "memfd name contains NUL"))?;
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, cname.as_ptr(), MFD_CLOEXEC | MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd as RawFd)
}

/// Resize a file (typically a memfd) to exactly `len` bytes.
pub fn ftruncate(fd: RawFd, len: u64) -> io::Result<()> {
    let ret = unsafe { libc::ftruncate(fd, len as libc::off_t) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Apply the given seal bitmask to a (memfd) descriptor.
pub fn add_seals(fd: RawFd, seals: c_int) -> io::Result<()> {
    let ret = unsafe { libc::fcntl(fd, F_ADD_SEALS, seals) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read the seal bitmask currently applied to a descriptor.
pub fn get_seals(fd: RawFd) -> io::Result<c_int> {
    let ret = unsafe { libc::fcntl(fd, F_GET_SEALS) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ret)
}

/// `PROT_*` protection flags for [`mmap_shared`].
#[derive(Debug, Clone, Copy)]
pub enum MapProt {
    /// Read-only mapping (`PROT_READ`).
    Read,
    /// Read/write mapping (`PROT_READ | PROT_WRITE`).
    ReadWrite,
}

impl MapProt {
    fn bits(self) -> c_int {
        match self {
            MapProt::Read => libc::PROT_READ,
            MapProt::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
        }
    }
}

/// A `MAP_SHARED` memory mapping that unmaps itself on drop.
pub struct Mapping {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: a `Mapping` only owns the raw pointer/length of a shared mapping.
// Concurrent access to the bytes is mediated by the atomics in the ring header
// (see `shm.rs`); moving the handle between threads is sound.
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

impl Mapping {
    /// Raw base pointer of the mapping.
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Length of the mapping in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the mapping has zero length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                libc::munmap(self.ptr as *mut c_void, self.len);
            }
        }
    }
}

/// `mmap` a descriptor `MAP_SHARED` with the requested protection.
pub fn mmap_shared(fd: RawFd, len: usize, prot: MapProt) -> io::Result<Mapping> {
    if len == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "mmap length must be non-zero"));
    }
    let ptr = unsafe { libc::mmap(std::ptr::null_mut(), len, prot.bits(), libc::MAP_SHARED, fd, 0) };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(Mapping { ptr: ptr as *mut u8, len })
}

/// Read the peer credentials of a connected `AF_UNIX` stream socket.
pub fn get_peer_cred(fd: RawFd) -> io::Result<PeerCred> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut c_void,
            &mut len,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCred { pid: cred.pid, uid: cred.uid, gid: cred.gid })
}

/// Open a `pidfd` for the given process so the peer's liveness/identity can be
/// pinned for the lifetime of the connection (defends against PID reuse).
pub fn pidfd_open(pid: i32) -> io::Result<RawFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd as RawFd)
}

/// Set the close-on-exec flag on a descriptor.
pub fn set_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Close a raw descriptor, ignoring `EINTR`.
pub fn close(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

/// Create a directory with the given mode, succeeding if it already exists.
///
/// The mode is applied with an explicit `chmod` afterwards so that the process
/// umask cannot loosen the requested permission bits.
pub fn mkdir_mode(path: &Path, mode: u32) -> io::Result<()> {
    let cpath = path_to_cstring(path)?;
    let ret = unsafe { libc::mkdir(cpath.as_ptr(), mode as libc::mode_t) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(err);
        }
    }
    chmod(path, mode)
}

/// Change the permission bits of a path.
pub fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    let cpath = path_to_cstring(path)?;
    let ret = unsafe { libc::chmod(cpath.as_ptr(), mode as libc::mode_t) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Change the owning uid/gid of a path. Pass `u32::MAX` to leave one unchanged.
pub fn chown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let cpath = path_to_cstring(path)?;
    let ret = unsafe { libc::chown(cpath.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn path_to_cstring(path: &Path) -> io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

/// Maximum number of descriptors that [`recv_with_fds`] will accept in a single
/// control message. The gateway only ever passes a memfd pair plus a notifier.
pub const MAX_PASSED_FDS: usize = 8;

/// Send `payload` plus a set of file descriptors over a connected `AF_UNIX`
/// socket using an `SCM_RIGHTS` control message.
pub fn send_with_fds(sock: RawFd, payload: &[u8], fds: &[RawFd]) -> io::Result<usize> {
    if fds.len() > MAX_PASSED_FDS {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many fds"));
    }
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut c_void,
        iov_len: payload.len(),
    };

    let fds_bytes = std::mem::size_of_val(fds);
    let cmsg_space = unsafe { libc::CMSG_SPACE(fds_bytes as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space.max(1)];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_space as _;

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fds_bytes as u32) as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr() as *const u8,
                libc::CMSG_DATA(cmsg),
                fds_bytes,
            );
        }
    }

    loop {
        let ret = unsafe { libc::sendmsg(sock, &msg, 0) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        return Ok(ret as usize);
    }
}

/// Result of [`recv_with_fds`]: the number of payload bytes received plus the
/// descriptors extracted from the `SCM_RIGHTS` control message.
pub struct ReceivedFds {
    /// Number of bytes written into the caller's payload buffer.
    pub bytes: usize,
    /// Descriptors received (already `O_CLOEXEC` thanks to `MSG_CMSG_CLOEXEC`).
    pub fds: Vec<RawFd>,
}

/// Receive a payload plus any attached file descriptors from an `AF_UNIX`
/// socket. Received descriptors are made close-on-exec atomically via
/// `MSG_CMSG_CLOEXEC`.
pub fn recv_with_fds(sock: RawFd, payload: &mut [u8]) -> io::Result<ReceivedFds> {
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut c_void,
        iov_len: payload.len(),
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE((MAX_PASSED_FDS * std::mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsg_space as _;

    let bytes = loop {
        let ret = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        break ret as usize;
    };

    let mut fds = Vec::new();
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg);
                let payload_len = (*cmsg).cmsg_len as usize - unsafe_cmsg_len_header();
                let n = payload_len / std::mem::size_of::<RawFd>();
                for i in 0..n {
                    let mut fd: RawFd = -1;
                    std::ptr::copy_nonoverlapping(
                        data.add(i * std::mem::size_of::<RawFd>()),
                        &mut fd as *mut RawFd as *mut u8,
                        std::mem::size_of::<RawFd>(),
                    );
                    fds.push(fd);
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok(ReceivedFds { bytes, fds })
}

/// Size of the `cmsghdr` portion preceding `SCM_RIGHTS` payload bytes, i.e.
/// `CMSG_LEN(0)`.
fn unsafe_cmsg_len_header() -> usize {
    unsafe { libc::CMSG_LEN(0) as usize }
}
