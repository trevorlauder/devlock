//! Seccomp filter install and the userspace supervisor.
//!
//! Everything lives in one libseccomp filter built from policy/seccomp.yaml.
//! Unconditional denies return EPERM, conditional rules carry their own
//! action (EPERM, EAFNOSUPPORT, etc.), and notify entries route the named
//! syscalls to the supervisor fd returned from install().

use crate::policy::seccomp as policy;

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::Component;
use std::path::{Path, PathBuf};

use libseccomp::{
    ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterAttr, ScmpFilterContext, ScmpSyscall,
};

use policy::{Action, Op};

const TARGET: &str = "seccomp";

/// Trimmed view of a seccomp notify request. The evaluate_* functions
/// only ever need id, pid, syscall nr, and args, so rather than couple
/// them to the libseccomp type we project into this local shape.
struct Notif {
    id: u64,
    pid: u32,
    data: NotifData,
}

struct NotifData {
    nr: i32,
    args: [u64; 6],
}

impl Notif {
    fn from_raw(req: &RawSeccompNotif) -> Self {
        Self {
            id: req.id,
            pid: req.pid,
            data: NotifData {
                nr: req.data_nr,
                args: req.data_args,
            },
        }
    }
}

/// Per-PID cache of `/proc/{pid}/mem` file descriptors. Avoids re-opening
/// the mem file on every intercepted syscall. Entries are evicted on read
/// failure (process exited) and by LRU when the cache is full.
struct MemCache {
    /// Pre-opened fd for the initial child (before PR_SET_DUMPABLE=0).
    primary: Option<std::fs::File>,
    primary_pid: u32,
    /// (pid, file) ordered by last use — most-recent at the back.
    entries: Vec<(u32, std::fs::File)>,
}

const MEM_CACHE_MAX: usize = 64;

impl MemCache {
    fn new(primary_pid: u32, primary: Result<std::fs::File, io::Error>) -> Self {
        Self {
            primary: primary.ok(),
            primary_pid,
            entries: Vec::new(),
        }
    }

    /// Get a mem fd for the given pid, opening and caching if needed.
    fn get(&mut self, pid: u32) -> Option<&std::fs::File> {
        // Fast path: initial child process (pre-dumpable fd).
        if pid == self.primary_pid
            && let Some(ref f) = self.primary
        {
            return Some(f);
        }
        // Check cache — move to back (most-recent) on hit.
        if let Some(pos) = self.entries.iter().position(|(p, _)| *p == pid) {
            let entry = self.entries.remove(pos);
            self.entries.push(entry);
            return self.entries.last().map(|(_, f)| f);
        }
        // Open new. Evict LRU (front) if full.
        if self.entries.len() >= MEM_CACHE_MAX {
            self.entries.remove(0);
        }
        if let Ok(f) = std::fs::File::open(format!("/proc/{pid}/mem")) {
            self.entries.push((pid, f));
            return self.entries.last().map(|(_, f)| f);
        }
        None
    }

    /// Evict a pid from the cache (read failed, process likely exited).
    fn evict(&mut self, pid: u32) {
        if pid == self.primary_pid {
            self.primary = None;
        }
        self.entries.retain(|(p, _)| *p != pid);
    }

    /// Read a path string from the child's memory.
    fn read_path(&mut self, pid: u32, ptr: u64) -> Option<PathBuf> {
        if let Some(f) = self.get(pid) {
            if let Some(p) = read_path_from_mem(f, ptr) {
                return Some(p);
            }
            // Read failed — pid likely exited, evict.
            self.evict(pid);
        }
        None
    }

    /// Read raw bytes from the child's memory.
    fn read_bytes(&mut self, pid: u32, ptr: u64, buf: &mut [u8]) -> Option<usize> {
        if let Some(f) = self.get(pid) {
            if let Ok(n) = f.read_at(buf, ptr) {
                return Some(n);
            }
            self.evict(pid);
        }
        None
    }
}

const SYS_OPENAT: i32 = libc::SYS_openat as i32;
const SYS_NEWFSTATAT: i32 = libc::SYS_newfstatat as i32;
const SYS_STATX: i32 = libc::SYS_statx as i32;
const SYS_STATFS: i32 = libc::SYS_statfs as i32;
const SYS_FACCESSAT: i32 = libc::SYS_faccessat as i32;
const SYS_FACCESSAT2: i32 = libc::SYS_faccessat2 as i32;
const SYS_INOTIFY_ADD_WATCH: i32 = libc::SYS_inotify_add_watch as i32;
const SYS_UNLINKAT: i32 = libc::SYS_unlinkat as i32;
const SYS_MKDIRAT: i32 = libc::SYS_mkdirat as i32;
const SYS_RENAMEAT: i32 = libc::SYS_renameat as i32;
const SYS_LINKAT: i32 = libc::SYS_linkat as i32;
const SYS_SYMLINKAT: i32 = libc::SYS_symlinkat as i32;
const SYS_EXECVEAT: i32 = libc::SYS_execveat as i32;
const SYS_RENAMEAT2: i32 = libc::SYS_renameat2 as i32;
const SYS_OPENAT2: i32 = libc::SYS_openat2 as i32;

const SYS_TRUNCATE: i32 = libc::SYS_truncate as i32;
const SYS_SETXATTR: i32 = libc::SYS_setxattr as i32;
const SYS_LSETXATTR: i32 = libc::SYS_lsetxattr as i32;
const SYS_REMOVEXATTR: i32 = libc::SYS_removexattr as i32;
const SYS_LREMOVEXATTR: i32 = libc::SYS_lremovexattr as i32;

const SYS_FCHMOD: i32 = libc::SYS_fchmod as i32;
const SYS_FCHOWN: i32 = libc::SYS_fchown as i32;
const SYS_FSETXATTR: i32 = libc::SYS_fsetxattr as i32;
const SYS_FREMOVEXATTR: i32 = libc::SYS_fremovexattr as i32;

/// XATTR_SIZE_MAX. Bounded here because the child picks the size arg
/// and an unbounded Vec alloc on u64::MAX aborts the supervisor.
const XATTR_VALUE_MAX: usize = 65_536;

const SYS_FCHMODAT: i32 = libc::SYS_fchmodat as i32;
const SYS_FCHOWNAT: i32 = libc::SYS_fchownat as i32;
const SYS_UTIMENSAT: i32 = libc::SYS_utimensat as i32;
const SYS_MKNODAT: i32 = libc::SYS_mknodat as i32;

const SYS_KILL: i32 = libc::SYS_kill as i32;
const SYS_TKILL: i32 = libc::SYS_tkill as i32;
const SYS_TGKILL: i32 = libc::SYS_tgkill as i32;

// Legacy (non-*at) syscall numbers. On aarch64 the kernel does not expose
// these at all, but the supervisor may run on x86_64 where they exist.
// Use architecture-specific values so the notify dispatch still lines up on
// x86_64 and never matches on aarch64.
#[cfg(target_arch = "x86_64")]
const SYS_CHMOD: i32 = libc::SYS_chmod as i32;
#[cfg(target_arch = "x86_64")]
const SYS_CHOWN: i32 = libc::SYS_chown as i32;
#[cfg(target_arch = "x86_64")]
const SYS_LCHOWN: i32 = libc::SYS_lchown as i32;
#[cfg(target_arch = "x86_64")]
const SYS_UTIMES: i32 = libc::SYS_utimes as i32;
#[cfg(target_arch = "x86_64")]
const SYS_MKNOD: i32 = libc::SYS_mknod as i32;
#[cfg(target_arch = "x86_64")]
const SYS_MKDIR: i32 = libc::SYS_mkdir as i32;
#[cfg(target_arch = "x86_64")]
const SYS_RMDIR: i32 = libc::SYS_rmdir as i32;
#[cfg(target_arch = "x86_64")]
const SYS_RENAME: i32 = libc::SYS_rename as i32;
#[cfg(target_arch = "x86_64")]
const SYS_LINK: i32 = libc::SYS_link as i32;
#[cfg(target_arch = "x86_64")]
const SYS_SYMLINK: i32 = libc::SYS_symlink as i32;
#[cfg(target_arch = "x86_64")]
const SYS_UNLINK: i32 = libc::SYS_unlink as i32;

// Placeholder values on architectures without the legacy syscalls. -1 is
// guaranteed never to equal an incoming syscall nr, so match arms using
// these constants become dead arms on that target.
#[cfg(not(target_arch = "x86_64"))]
const SYS_CHMOD: i32 = -1;
#[cfg(not(target_arch = "x86_64"))]
const SYS_CHOWN: i32 = -1;
#[cfg(not(target_arch = "x86_64"))]
const SYS_LCHOWN: i32 = -1;
#[cfg(not(target_arch = "x86_64"))]
const SYS_UTIMES: i32 = -1;
#[cfg(not(target_arch = "x86_64"))]
const SYS_MKNOD: i32 = -1;
#[cfg(not(target_arch = "x86_64"))]
const SYS_MKDIR: i32 = -1;
#[cfg(not(target_arch = "x86_64"))]
const SYS_RMDIR: i32 = -1;
#[cfg(not(target_arch = "x86_64"))]
const SYS_RENAME: i32 = -1;
#[cfg(not(target_arch = "x86_64"))]
const SYS_LINK: i32 = -1;
#[cfg(not(target_arch = "x86_64"))]
const SYS_SYMLINK: i32 = -1;
#[cfg(not(target_arch = "x86_64"))]
const SYS_UNLINK: i32 = -1;

// Mask of flags that indicate a write-mode open
const WRITE_FLAGS: u32 =
    (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u32;

// AT_FDCWD (-100) as u64
const AT_FDCWD: u64 = -100i64 as u64;

/// openat2 resolve flags. Not in libc yet.
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_BENEATH: u64 = 0x08;

// seccomp_notif_addfd: _IOW('!', 3, struct seccomp_notif_addfd) with 24 byte payload.
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x40182103;
#[allow(dead_code)]
const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1;
const SECCOMP_ADDFD_FLAG_SEND: u32 = 2;

// _IOWR('!', 0, struct seccomp_notif); 80-byte payload.
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xC0502100;
// _IOWR('!', 1, struct seccomp_notif_resp); 24-byte payload.
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xC0182101;

#[repr(C)]
struct SeccompNotifAddFd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

/// Raw seccomp_notif struct as defined in uapi/linux/seccomp.h. Used in place
/// of libseccomp's wrapper so the real errno from NOTIF_RECV reaches the
/// supervisor; libseccomp collapses every non-EINTR failure to ECANCELED.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct RawSeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data_nr: i32,
    data_arch: u32,
    data_ip: u64,
    data_args: [u64; 6],
}

/// Raw seccomp_notif_resp.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct RawSeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

fn notif_recv_raw(notify_fd: RawFd) -> io::Result<RawSeccompNotif> {
    loop {
        let mut notif = RawSeccompNotif::default();
        let rc = unsafe {
            libc::ioctl(
                notify_fd,
                SECCOMP_IOCTL_NOTIF_RECV,
                &mut notif as *mut RawSeccompNotif,
            )
        };
        if rc == 0 {
            return Ok(notif);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(err);
    }
}

fn notif_send_raw(notify_fd: RawFd, id: u64, val: i64, error: i32, flags: u32) -> io::Result<()> {
    let mut resp = RawSeccompNotifResp {
        id,
        val,
        error,
        flags,
    };
    let rc = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_SEND,
            &mut resp as *mut RawSeccompNotifResp,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    _resolve: u64,
}

/// Safe wrapper around openat2. Returns -1 on failure (errno set by kernel).
/// Used to atomically resolve path components and to refuse magic links.
#[allow(dead_code)]
fn openat2_atomic(parent_fd: RawFd, name: &CString, flags: i32, resolve: u64) -> RawFd {
    #[repr(C)]
    struct HowArg {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = HowArg {
        flags: flags as u64,
        mode: 0,
        resolve,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent_fd as libc::c_long,
            name.as_ptr(),
            &how as *const HowArg,
            std::mem::size_of::<HowArg>(),
        )
    };
    ret as RawFd
}

enum SupervisorReply {
    Continue,
    Deny(i32),
    /// ADDFD_SEND has already satisfied the notification; skip respond.
    Injected,
    /// Supervisor executed the syscall; reply with rc or -errno.
    SyscallResult {
        rc: i64,
        errno: i32,
    },
}

/// Open a pidfd for the task that triggered a seccomp notification.
///
/// `seccomp_notif.pid` is a TID and in a multithreaded tracee (bun
/// workers, node libuv pool) is routinely a non-leader thread. Plain
/// `pidfd_open(tid, 0)` rejects non-leaders with EINVAL. `PIDFD_THREAD`
/// (= `O_EXCL`, Linux 6.9+) lifts the restriction and returns a pidfd
/// bound to the exact thread.
fn pidfd_open(tid: u32) -> io::Result<OwnedFd> {
    const PIDFD_THREAD: u32 = libc::O_EXCL as u32;
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_open, tid as libc::pid_t, PIDFD_THREAD) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(rc as RawFd) })
}

/// Thin wrapper around SYS_pidfd_getfd. Returns an owned copy of the
/// target's fd in the supervisor's fd table.
fn pidfd_getfd(pidfd: RawFd, target_fd: i32) -> io::Result<OwnedFd> {
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, target_fd, 0u32) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(rc as RawFd) })
}

/// Resolve the child's dirfd argument into a supervisor-owned fd pointing at
/// the same directory inode. AT_FDCWD is translated to an O_PATH open of
/// `/proc/{pid}/cwd`, anything else is borrowed via pidfd_getfd so the
/// supervisor never touches a fd number that only lives in the child.
fn resolve_dirfd(pidfd: &OwnedFd, pid: u32, dirfd_arg: u64) -> io::Result<OwnedFd> {
    if dirfd_arg as i32 == libc::AT_FDCWD {
        let c_path = CString::new(format!("/proc/{pid}/cwd"))
            .map_err(|e| io::Error::other(e.to_string()))?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    pidfd_getfd(pidfd.as_raw_fd(), dirfd_arg as i32)
}

/// openat2 wrapper that returns an `OwnedFd` and preserves errno.
/// The path is resolved relative to `dirfd` with the supplied resolve
/// flags. RESOLVE_BENEATH+RESOLVE_NO_MAGICLINKS is the race-free mode:
/// no symlink can escape the dirfd and no /proc magic link can redirect
/// the walk.
fn openat2_pinned(dirfd: RawFd, path: &CString, flags: i32, resolve: u64) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct HowArg {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = HowArg {
        flags: flags as u64,
        mode: 0,
        resolve,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd as libc::c_long,
            path.as_ptr(),
            &how as *const HowArg,
            std::mem::size_of::<HowArg>(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
}

/// openat2 variant that creates the file when missing. Used on the O_CREAT
/// branch where the leaf does not exist yet.
fn openat2_create(
    dirfd: RawFd,
    path: &CString,
    flags: i32,
    mode: u32,
    resolve: u64,
) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct HowArg {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = HowArg {
        flags: flags as u64,
        mode: mode as u64,
        resolve,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd as libc::c_long,
            path.as_ptr(),
            &how as *const HowArg,
            std::mem::size_of::<HowArg>(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
}

/// Canonical path of an fd via readlink on /proc/self/fd/N.
fn resolved_path(fd: RawFd) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}"))
}

/// Kernel authoritative canonical path via openat2 anchored at the child's dirfd or at root
/// for absolute paths. Follows symlinks but blocks magic link redirection. Still TOCTOU
/// versus the child's eventual syscall, but drops the libc realpath intermediate so read and
/// write paths share the same resolution semantics.
fn pinned_canonical_path(pid: u32, dirfd_arg: u64, raw_path: &Path) -> Option<PathBuf> {
    let (anchor, rel) = if raw_path.is_absolute() {
        let c_root = CString::new("/").ok()?;
        let fd = unsafe {
            libc::open(
                c_root.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return None;
        }
        (
            unsafe { OwnedFd::from_raw_fd(fd) },
            raw_path.strip_prefix("/").unwrap_or(raw_path).to_path_buf(),
        )
    } else {
        let pidfd = pidfd_open(pid).ok()?;
        let anchor = resolve_dirfd(&pidfd, pid, dirfd_arg).ok()?;
        (anchor, raw_path.to_path_buf())
    };
    let c_path = CString::new(rel.as_os_str().as_bytes()).ok()?;
    let fd = openat2_pinned(
        anchor.as_raw_fd(),
        &c_path,
        libc::O_PATH | libc::O_CLOEXEC,
        RESOLVE_NO_MAGICLINKS,
    )
    .ok()?;
    resolved_path(fd.as_raw_fd()).ok()
}

/// Canonical of the deepest existing prefix of `path` plus the lexical
/// tail. Used by evaluate_stat_request when the full path fails to
/// resolve. An lstat fallback on a path like $CWD/x/missing (where x
/// is a symlink to /etc) would silently follow x, and starts_with
/// would still accept the lexical path, leaking ENOENT against EACCES
/// as an existence oracle for arbitrary trees.
fn canonical_with_existing_ancestor(path: &Path) -> Option<PathBuf> {
    canonical_with_existing_ancestor_depth(path, 40)
}

fn canonical_with_existing_ancestor_depth(path: &Path, depth: usize) -> Option<PathBuf> {
    if depth == 0 || !path.is_absolute() {
        return None;
    }
    if let Some(c) = pinned_canonical_path(0, 0, path) {
        return Some(c);
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if current.as_os_str() == "/" {
            let mut result = PathBuf::from("/");
            for comp in tail.iter().rev() {
                result.push(comp);
            }
            return Some(result);
        }
        let name = current.file_name().map(|n| n.to_os_string())?;
        let parent = current.parent().unwrap_or_else(|| Path::new("/"));
        let parent_canon = if parent.as_os_str() == "/" {
            Some(PathBuf::from("/"))
        } else {
            pinned_canonical_path(0, 0, parent)
        };
        if let Some(parent_canon) = parent_canon {
            let leaf_at_parent = parent_canon.join(&name);
            if let Ok(meta) = std::fs::symlink_metadata(&leaf_at_parent)
                && meta.file_type().is_symlink()
                && let Ok(link_target) = std::fs::read_link(&leaf_at_parent)
            {
                let abs_target = if link_target.is_absolute() {
                    link_target
                } else {
                    parent_canon.join(link_target)
                };
                let normalized = normalize_lexical_path(&abs_target);
                let resolved = canonical_with_existing_ancestor_depth(&normalized, depth - 1)?;
                let mut result = resolved;
                for comp in tail.iter().rev() {
                    result.push(comp);
                }
                return Some(result);
            }
            let mut result = parent_canon;
            result.push(&name);
            for comp in tail.iter().rev() {
                result.push(comp);
            }
            return Some(result);
        }
        tail.push(name);
        if !current.pop() {
            return None;
        }
    }
}

/// SECCOMP_IOCTL_NOTIF_ADDFD with ADDFD_FLAG_SEND. Atomically injects the
/// supervisor-opened `src_fd` into the target's fd table and satisfies
/// the notification with the injected fd number as the syscall return
/// value. Do NOT call respond() after this; the SEND flag already did.
fn addfd_send(notify_fd: RawFd, id: u64, src_fd: RawFd, newfd_flags: u32) -> io::Result<RawFd> {
    let mut addfd = SeccompNotifAddFd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: src_fd as u32,
        newfd: 0,
        newfd_flags,
    };
    let rc = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_ADDFD,
            &mut addfd as *mut SeccompNotifAddFd,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc as RawFd)
}

/// Load the YAML policy, compile every entry into a single libseccomp
/// filter on the calling thread, and return the notify fd. Call this
/// after Landlock restrict_self and before execve.
pub fn install() -> io::Result<RawFd> {
    let policy = policy::load()?;
    // Default is EACCES. Conditional denies use EPERM so libseccomp
    // does not reject them as redundant with the default.
    let mut ctx = ScmpFilterContext::new(ScmpAction::Errno(libc::EACCES))
        .map_err(|e| io::Error::other(format!("filter init: {e}")))?;

    // Conditional rules first; libseccomp rejects conditionals added
    // after an unconditional rule with an overlapping action.
    let (conditional, unconditional): (Vec<_>, Vec<_>) =
        policy.rules.iter().partition(|r| !r.when.is_empty());

    for rule in conditional {
        let sc = syscall(&rule.syscall)?;
        let action = scmp_action(rule.action);
        let conds = rule
            .when
            .iter()
            .map(|c| ScmpArgCompare::new(c.arg, compare_op(&c.op), c.value))
            .collect::<Vec<_>>();
        ctx.add_rule_conditional(action, sc, &conds)
            .map_err(|e| io::Error::other(format!("add conditional {}: {e}", rule.syscall)))?;
    }

    for rule in unconditional {
        let sc = syscall(&rule.syscall)?;
        ctx.add_rule(scmp_action(rule.action), sc)
            .map_err(|e| io::Error::other(format!("add rule {}: {e}", rule.syscall)))?;
    }

    // WAIT_KILLABLE_RECV (Linux 6.1+) lets the child transition to a
    // killable wait if the supervisor dies instead of becoming unkillable.
    let _ = ctx.set_filter_attr(ScmpFilterAttr::CtlWaitkill, 1);

    ctx.load()
        .map_err(|e| io::Error::other(format!("filter load: {e}")))?;
    ctx.get_notify_fd()
        .map_err(|e| io::Error::other(format!("notify fd: {e}")))
}

fn syscall(name: &str) -> io::Result<ScmpSyscall> {
    ScmpSyscall::from_name(name)
        .map_err(|e| io::Error::other(format!("unknown syscall {name}: {e}")))
}

fn scmp_action(action: Action) -> ScmpAction {
    match action {
        Action::Allow => ScmpAction::Allow,
        Action::Notify => ScmpAction::Notify,
        Action::Deny { errno } => ScmpAction::Errno(errno as i32),
    }
}

fn compare_op(op: &Op) -> ScmpCompareOp {
    match *op {
        Op::Eq => ScmpCompareOp::Equal,
        Op::Ne => ScmpCompareOp::NotEqual,
        Op::Lt => ScmpCompareOp::Less,
        Op::Le => ScmpCompareOp::LessOrEqual,
        Op::Gt => ScmpCompareOp::Greater,
        Op::Ge => ScmpCompareOp::GreaterEqual,
        Op::MaskedEq(mask) => ScmpCompareOp::MaskedEqual(mask),
    }
}

/// Send a file descriptor to the parent process via SCM_RIGHTS.
pub fn send_notify_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};

    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    let iov = [std::io::IoSlice::new(&[0u8])];

    sendmsg::<()>(sock, &iov, &cmsg, MsgFlags::empty(), None).map_err(io::Error::from)?;
    Ok(())
}

/// After the child sends the notify fd, it blocks on the socket until
/// the parent writes a single ready byte. This serves as a barrier so
/// the child does not execve the agent before the supervisor thread
/// has been scheduled; without it a notify syscall fired by the first
/// few instructions of the agent may wait indefinitely if the
/// supervisor thread is late to start or has crashed.
pub fn wait_for_supervisor_ready(sock: RawFd) -> io::Result<()> {
    let mut buf = [0u8; 1];
    let n = unsafe { libc::read(sock, buf.as_mut_ptr().cast(), 1) };
    if n == 1 {
        Ok(())
    } else if n == 0 {
        Err(io::Error::other("parent closed handshake socket"))
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Parent-side counterpart to `wait_for_supervisor_ready`. Must be
/// called only after the supervisor thread has been spawned, so the
/// child sees a ready byte that actually reflects a live supervisor.
pub fn signal_supervisor_ready(sock: RawFd) -> io::Result<()> {
    let n = unsafe { libc::write(sock, [1u8].as_ptr().cast(), 1) };
    if n == 1 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Receive a file descriptor from the child process via SCM_RIGHTS.
/// The fd is set close on exec so a future fork+exec in the parent
/// cannot leak the notify fd to an unrelated helper process.
pub fn recv_notify_fd(sock: RawFd) -> io::Result<RawFd> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};

    let mut buf = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let mut cmsg_buf = nix::cmsg_space!(RawFd);

    let msg = recvmsg::<()>(
        sock,
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .map_err(io::Error::from)?;

    for cmsg in msg.cmsgs().map_err(io::Error::from)? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg
            && let Some(&fd) = fds.first()
        {
            // Belt and braces: some kernels (pre 3.4) ignore
            // MSG_CMSG_CLOEXEC on the cmsg fds. Set FD_CLOEXEC
            // directly so newer kernels and older kernels land at
            // the same place.
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags >= 0 {
                    libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                }
            }
            return Ok(fd);
        }
    }

    Err(io::Error::other("no SCM_RIGHTS received"))
}

/// Configuration for the seccomp-notify supervisor.
pub struct SupervisorConfig {
    /// Paths declared `read_only` in policy. Landlock cannot enforce
    /// "no modification" on these when a parent directory is in
    /// `dir_create`/`read_write`/`full_access`, because Landlock access
    /// is additive and the parent's `RemoveFile`/`MakeReg`/etc grants
    /// propagate down. The supervisor enforces the stricter
    /// interpretation of `read_only` — no write, unlink, rename-over,
    /// link-to, symlink-at, or O_CREAT — so a read_only entry actually
    /// means "this file shall not be replaced" rather than just "grant
    /// read". Best-effort: subject to the same TOCTOU race as every
    /// other seccomp-notify path check (the supervisor reads the path
    /// from the child's memory and the kernel reads it again to act).
    pub read_only_enforced: Vec<PathBuf>,
    /// Mirrors Landlock's write grants so a Landlock bypass alone cannot
    /// cross the filesystem boundary.
    pub allowed_write: Vec<PathBuf>,
    /// Narrower subset of write grants that may *delete* entries:
    /// `full_access` and `read_write` only. `dir_create` is add-only, so
    /// unlink/rename/linkat new-side require this list rather than the
    /// broader `allowed_write`.
    pub allowed_delete: Vec<PathBuf>,
    /// Union of every Landlock read category plus home and /proc.
    pub allowed_read: Vec<PathBuf>,
    /// Mirrors Landlock's Execute grants.
    pub allowed_exec: Vec<PathBuf>,
    pub tunnel_port: u16,
    pub api_port: u16,
    pub child_pid: u32,
    /// Mask of clone3 flag bits the supervisor permits. Any bit
    /// outside this mask causes the call to be rejected.
    pub clone3_allowed_flags: u64,
    /// Syscall nr to handler mapping built from the notify rules.
    pub handlers: std::collections::HashMap<i32, crate::policy::seccomp::Handler>,
    /// Pre opened descriptor on /proc/{child_pid}/mem. Must be opened
    /// before the child drops dumpable.
    pub child_mem: Option<std::fs::File>,
}

/// Open /proc/{pid}/mem before the child drops dumpable.
pub fn open_child_mem(pid: u32) -> io::Result<std::fs::File> {
    std::fs::File::open(format!("/proc/{pid}/mem"))
}

/// Build the syscall nr to handler map from a loaded seccomp policy.
pub fn handler_map(
    policy: &crate::policy::seccomp::Policy,
) -> io::Result<std::collections::HashMap<i32, crate::policy::seccomp::Handler>> {
    let mut out = std::collections::HashMap::new();
    for rule in &policy.rules {
        if let Some(handler) = rule.handler {
            let nr = syscall(&rule.syscall)?.as_raw_syscall();
            out.insert(nr, handler);
        }
    }
    Ok(out)
}

struct ResolvedRoots {
    read_only_enforced: Vec<PathBuf>,
    write: Vec<PathBuf>,
    delete: Vec<PathBuf>,
    read: Vec<PathBuf>,
    exec: Vec<PathBuf>,
}

/// Runs the seccomp-notify supervisor in the parent process.
/// Enforces filesystem write protection and network restrictions as a second layer
/// behind Landlock. Returns when the notify fd closes because the child has exited.
pub fn run_supervisor(notify_fd: RawFd, mut config: SupervisorConfig) {
    let canonicalize_all = |paths: &[PathBuf]| -> Vec<PathBuf> {
        paths
            .iter()
            .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
            .collect()
    };
    let roots = ResolvedRoots {
        read_only_enforced: canonicalize_all(&config.read_only_enforced),
        write: canonicalize_all(&config.allowed_write),
        delete: canonicalize_all(&config.allowed_delete),
        read: canonicalize_all(&config.allowed_read),
        exec: canonicalize_all(&config.allowed_exec),
    };

    let primary = config
        .child_mem
        .take()
        .ok_or_else(|| io::Error::other("missing pre opened child_mem"));
    let mut mem_cache = MemCache::new(config.child_pid, primary);

    // Enable synchronous wakeup on Linux 6.7+. When the supervisor
    // responds, the kernel wakes the blocked child thread directly
    // instead of going through the scheduler, cutting the per call
    // round trip from a few ms down to under 100 us. Older kernels
    // return EINVAL, which we ignore.
    const SECCOMP_IOCTL_NOTIF_SET_FLAGS: libc::c_ulong = 0x40082104;
    const SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP: u64 = 1;
    let wakeup_flags: u64 = SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP;
    unsafe {
        libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SET_FLAGS, &wakeup_flags);
    }

    let mut consecutive_recv_errors: u32 = 0;
    let mut consecutive_enoent: u32 = 0;
    loop {
        // Wait for an INIT-state notification before calling RECV. Without
        // this gate, a kernel wake without a ready notification (seen on
        // recent kernels when a tracee is signalled mid-syscall) turns into
        // a RECV that returns ENOENT immediately, and the plain continue
        // spins the CPU at hundreds of thousands of iterations per second
        // until the tracee makes progress.
        match poll_notify_fd(notify_fd) {
            PollOutcome::Ready => {}
            PollOutcome::Hup => break,
            PollOutcome::Retry => continue,
        }
        let req = match notif_recv_raw(notify_fd) {
            Ok(req) => {
                consecutive_recv_errors = 0;
                consecutive_enoent = 0;
                req
            }
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(0);
                if errno == libc::ENOENT {
                    // Race: poll saw INIT but the notification was cancelled
                    // (tracee signalled or exited) before RECV scanned it.
                    // Log the first handful, back off so bursts do not melt
                    // the CPU, and bail out if the tracee is gone.
                    consecutive_enoent = consecutive_enoent.saturating_add(1);
                    if consecutive_enoent <= 4 {
                        tracing::warn!(
                            target: TARGET,
                            event = "notify_recv_error",
                            errno,
                            error = %e,
                        );
                    }
                    if consecutive_enoent >= 64 {
                        if !pid_alive(config.child_pid) {
                            tracing::error!(target: TARGET, event = "notify_fd_dead", errno);
                            break;
                        }
                        consecutive_enoent = 0;
                    }
                    std::thread::sleep(std::time::Duration::from_micros(500));
                    continue;
                }
                tracing::warn!(
                    target: TARGET,
                    event = "notify_recv_error",
                    errno,
                    error = %e,
                );
                consecutive_recv_errors = consecutive_recv_errors.saturating_add(1);
                if consecutive_recv_errors > 16 {
                    tracing::error!(target: TARGET, event = "notify_fd_dead", errno);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_micros(100));
                continue;
            }
        };
        let notif = Notif::from_raw(&req);

        let mut reply = evaluate_request(&notif, notify_fd, &config, &roots, &mut mem_cache);

        // Pre-respond revalidation: if the child died or the syscall was
        // interrupted while we were working, any authorizing decision
        // would be applied to a recycled slot. Flip to Deny so stale
        // memory reads cannot authorize on a reused pid. Skip this for
        // Injected: ADDFD_SEND already atomically consumed the
        // notification, so the id is expected to be invalid now.
        if !matches!(reply, SupervisorReply::Injected) && !notify_id_valid(notify_fd, notif.id) {
            tracing::warn!(
                target: TARGET,
                event = "notify_id_stale",
                pid = notif.pid,
                syscall = notif.data.nr,
            );
            match &reply {
                SupervisorReply::Continue | SupervisorReply::SyscallResult { .. } => {
                    reply = SupervisorReply::Deny(libc::EPERM);
                }
                SupervisorReply::Deny(_) | SupervisorReply::Injected => {}
            }
        }

        match reply {
            SupervisorReply::Continue => {
                const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
                if let Err(e) =
                    notif_send_raw(notify_fd, notif.id, 0, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE)
                {
                    tracing::warn!(target: TARGET, event = "notify_respond_error", errno = e.raw_os_error().unwrap_or(0), error = %e);
                }
            }
            SupervisorReply::Deny(errno) => {
                if let Err(e) = notif_send_raw(notify_fd, notif.id, 0, -errno, 0) {
                    tracing::warn!(target: TARGET, event = "notify_respond_error", errno = e.raw_os_error().unwrap_or(0), error = %e);
                }
            }
            SupervisorReply::SyscallResult { rc, errno } => {
                let (val, err) = if errno != 0 { (0, -errno) } else { (rc, 0) };
                if let Err(e) = notif_send_raw(notify_fd, notif.id, val, err, 0) {
                    tracing::warn!(target: TARGET, event = "notify_respond_error", errno = e.raw_os_error().unwrap_or(0), error = %e);
                }
            }
            SupervisorReply::Injected => {
                // ADDFD_SEND already satisfied this notification.
            }
        }

        // After exec the kernel replaces the child's address space. The
        // pre opened /proc/pid/mem fd still points at the old mm_struct
        // whose pages are now unmapped, so reads return zero bytes.
        // Evict the stale fd so the next get() opens a fresh one.
        if is_exec_syscall(notif.data.nr) {
            mem_cache.evict(notif.pid);
        }
    }
}

fn is_exec_syscall(nr: i32) -> bool {
    [libc::SYS_execve as i32, libc::SYS_execveat as i32].contains(&nr)
}

enum PollOutcome {
    Ready,
    Hup,
    Retry,
}

/// Block until the notify fd has an INIT-state notification or all tracees
/// have released the filter. Returns Hup once POLLHUP fires so the caller
/// can exit the supervisor loop cleanly instead of spinning on RECV.
fn poll_notify_fd(notify_fd: RawFd) -> PollOutcome {
    let mut pfd = libc::pollfd {
        fd: notify_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, -1) };
    if rc < 0 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EINTR {
            return PollOutcome::Retry;
        }
        tracing::warn!(target: TARGET, event = "notify_poll_error", errno);
        return PollOutcome::Retry;
    }
    if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
        && pfd.revents & libc::POLLIN == 0
    {
        return PollOutcome::Hup;
    }
    PollOutcome::Ready
}

fn pid_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Ask the kernel whether the pending notification id is still valid.
/// Returns true if the child is still blocked on this specific
/// notification. A false result means the syscall has been interrupted
/// or the target has exited, so any subsequent /proc/pid/mem read or
/// response carries stale semantics and must not be trusted.
fn notify_id_valid(notify_fd: RawFd, id: u64) -> bool {
    // _IOW('!', 2, __u64) matching the Linux kernel's seccomp uapi.
    const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x40082102;
    let mut id_copy = id;
    let rc = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_ID_VALID,
            &mut id_copy as *mut u64,
        )
    };
    rc == 0
}

fn evaluate_request(
    notif: &Notif,
    notify_fd: RawFd,
    config: &SupervisorConfig,
    roots: &ResolvedRoots,
    mem: &mut MemCache,
) -> SupervisorReply {
    use crate::policy::seccomp::Handler;
    let Some(handler) = config.handlers.get(&notif.data.nr).copied() else {
        tracing::warn!(
            target: TARGET,
            event = "notify_unmapped",
            pid = notif.pid,
            syscall_nr = notif.data.nr,
        );
        return SupervisorReply::Deny(libc::EPERM);
    };
    match handler {
        Handler::OpenRequest => evaluate_open_request(
            notif,
            notify_fd,
            &roots.read_only_enforced,
            &roots.write,
            &roots.delete,
            &roots.read,
            mem,
        ),
        Handler::StatRequest => evaluate_stat_request(notif, notify_fd, &roots.read, mem),
        Handler::ExecRequest => evaluate_exec_request(notif, notify_fd, &roots.exec, mem),
        Handler::BindRequest => evaluate_bind_request(
            notif,
            notify_fd,
            &roots.write,
            &roots.read_only_enforced,
            mem,
        ),
        Handler::ConnectRequest => evaluate_connect_request(
            notif,
            notify_fd,
            config.tunnel_port,
            config.api_port,
            &roots.write,
            &roots.read_only_enforced,
            mem,
        ),
        Handler::Clone3Request => {
            evaluate_clone3_request(notif, notify_fd, config.clone3_allowed_flags, mem)
        }
        Handler::SignalRequest => evaluate_signal_request(notif, config.child_pid),
        Handler::FdWrite => {
            // Fd metadata mutations modify an existing inode. dir_create
            // only authorizes adding new entries so these require the
            // narrower overwrite bucket (full_access + read_write).
            evaluate_fd_write(notif, notify_fd, &roots.read_only_enforced, &roots.delete)
        }
        Handler::PathWrite => evaluate_path_write(
            notif,
            notify_fd,
            &roots.read_only_enforced,
            &roots.delete,
            mem,
        ),
        Handler::DirfdWrite => evaluate_dirfd_write(
            notif,
            notify_fd,
            &roots.read_only_enforced,
            &roots.delete,
            mem,
        ),
        Handler::StructuralWrite => evaluate_structural_write(
            notif,
            notify_fd,
            &roots.read_only_enforced,
            &roots.write,
            &roots.delete,
            mem,
        ),
    }
}

/// Returns true when `path` falls under a `read_only` policy entry and the
/// caller is trying a structural modification (unlink, rename-over, linkat
/// new path, symlinkat link path). Landlock alone cannot enforce this
/// because access is additive — a `dir_create` parent grants `RemoveFile`
/// and `MakeReg` that propagate down to the read_only child. The
/// supervisor makes `read_only` actually mean "do not replace this file".
fn is_read_only_target(path: &Path, read_only_enforced: &[PathBuf]) -> bool {
    read_only_enforced.iter().any(|root| path.starts_with(root))
}

/// Enforce the execute boundary for execve/execveat.
/// execve: pathname in arg0 (absolute or CWD-relative).
/// execveat: dirfd in arg0, pathname in arg1.
fn evaluate_exec_request(
    notif: &Notif,
    notify_fd: RawFd,
    allowed_exec: &[PathBuf],
    mem: &mut MemCache,
) -> SupervisorReply {
    let pid = notif.pid;
    let a = &notif.data.args;

    let (dirfd, path_ptr) = if notif.data.nr == SYS_EXECVEAT {
        (a[0], a[1])
    } else {
        (AT_FDCWD, a[0])
    };

    let Some(raw) = mem.read_path(pid, path_ptr) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }

    // execveat with empty pathname and AT_EMPTY_PATH executes the fd directly.
    if notif.data.nr == SYS_EXECVEAT && raw.as_os_str().is_empty() {
        let Some(fd_path) = std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).ok() else {
            return SupervisorReply::Deny(libc::EPERM);
        };
        let check_path =
            std::fs::canonicalize(&fd_path).unwrap_or_else(|_| normalize_lexical_path(&fd_path));
        if !allowed_exec.iter().any(|root| check_path.starts_with(root)) {
            tracing::warn!(
                target: TARGET,
                event = "execveat_fd_denied",
                pid,
                fd = dirfd,
                path = %check_path.display(),
            );
            return SupervisorReply::Deny(libc::EPERM);
        }
        if !notify_id_valid(notify_fd, notif.id) {
            return SupervisorReply::Deny(libc::EPERM);
        }
        return SupervisorReply::Continue;
    }

    let Some(resolved) = resolve_path(pid, dirfd, &raw) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    let check_path =
        std::fs::canonicalize(&resolved).unwrap_or_else(|_| normalize_lexical_path(&resolved));
    if !allowed_exec.iter().any(|root| check_path.starts_with(root)) {
        log_denial(pid, notif.data.nr, path_ptr);
        return SupervisorReply::Deny(libc::EPERM);
    }
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    SupervisorReply::Continue
}

/// Enforce the read boundary for path-based stat syscalls. Landlock has
/// no GetAttr access bit, so without this a child can statx("/etc/shadow")
/// and learn inode details for files outside every bucket. The handler
/// uses the same allowed_read union the Landlock layer was built from,
/// so rejections here match refusals a subsequent open would see.
///
/// newfstatat, statx: (dirfd, pathname, ...). statx with AT_EMPTY_PATH is
/// effectively fstat on the dirfd, which is already authorized via the
/// open that produced that fd. statfs: pathname in arg0.
fn evaluate_stat_request(
    notif: &Notif,
    notify_fd: RawFd,
    allowed_read: &[PathBuf],
    mem: &mut MemCache,
) -> SupervisorReply {
    let pid = notif.pid;
    let a = &notif.data.args;

    let (dirfd, path_ptr, flags) = match notif.data.nr {
        n if n == SYS_NEWFSTATAT => (a[0], a[1], a[3] as i32),
        n if n == SYS_STATX => (a[0], a[1], a[2] as i32),
        n if n == SYS_STATFS => (AT_FDCWD, a[0], 0),
        // faccessat(dirfd, path, mode) has no flags arg. faccessat2
        // adds flags in arg 3. Both can leak existence via ENOENT vs
        // EACCES, so they route through the same readability check.
        n if n == SYS_FACCESSAT => (a[0], a[1], 0),
        n if n == SYS_FACCESSAT2 => (a[0], a[1], a[3] as i32),
        // inotify_add_watch(fd, pathname, mask). arg 0 is the inotify
        // instance fd not a dirfd, so pathname resolves against
        // /proc/pid/cwd. Without this gate the kernel leaks EACCES vs
        // ENOENT on read_list trees like /etc.
        n if n == SYS_INOTIFY_ADD_WATCH => (AT_FDCWD, a[1], 0),
        _ => return SupervisorReply::Deny(libc::EPERM),
    };

    let Some(raw_path) = mem.read_path(pid, path_ptr) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }

    // statx/newfstatat with AT_EMPTY_PATH and an empty pathname operates
    // on dirfd directly, which the child already holds and Landlock
    // already approved at open time.
    if raw_path.as_os_str().is_empty() && (flags & libc::AT_EMPTY_PATH) != 0 {
        return SupervisorReply::Continue;
    }

    let Some(resolved) = resolve_path(pid, dirfd, &raw_path) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    let normalized = normalize_lexical_path(&resolved);
    let check_path = pinned_canonical_path(pid, dirfd, &raw_path)
        .or_else(|| canonical_with_existing_ancestor(&normalized))
        .unwrap_or_else(|| normalized.clone());
    if !is_read_permitted(&check_path, allowed_read)
        && !is_stat_ancestor_of_allowed(&check_path, allowed_read)
    {
        log_stat_denial(pid, &normalized, "stat_denied");
        return SupervisorReply::Deny(libc::EACCES);
    }
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    SupervisorReply::Continue
}

fn evaluate_open_request(
    notif: &Notif,
    notify_fd: RawFd,
    read_only_enforced: &[PathBuf],
    allowed: &[PathBuf],
    allowed_overwrite: &[PathBuf],
    allowed_read: &[PathBuf],
    mem: &mut MemCache,
) -> SupervisorReply {
    let pid = notif.pid;
    let a = &notif.data.args;

    let (dirfd, path_ptr, flags, mode) = match notif.data.nr {
        n if n == SYS_OPENAT => (a[0], a[1], a[2] as i32, a[3] as u32),
        n if n == SYS_OPENAT2 => {
            let how = match read_proc_open_how(mem, pid, a[2], a[3]) {
                Ok(how) => how,
                Err(_) => return SupervisorReply::Deny(libc::EPERM),
            };
            (a[0], a[1], how.flags as i32, how.mode as u32)
        }
        _ => return SupervisorReply::Deny(libc::EPERM),
    };

    let Some(raw_path) = mem.read_path(pid, path_ptr) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    let Some(resolved) = resolve_path(pid, dirfd, &raw_path) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    let normalized = normalize_lexical_path(&resolved);

    // /proc/*/mountinfo, /proc/*/mounts, and /proc/*/mountstats leak the
    // container's mount topology. Block them regardless of intent.
    if is_proc_mount_leak(&normalized) {
        log_open_denial(pid, &normalized, "proc_mount_leak");
        return SupervisorReply::Deny(libc::EACCES);
    }

    if is_write_open(flags) {
        let ctx = WriteOpenCtx {
            notif,
            notify_fd,
            read_only_enforced,
            allowed,
            allowed_overwrite,
        };
        return open_request_write(&ctx, dirfd, &raw_path, &normalized, flags, mode);
    }

    // Landlock enforces the inode read boundary. The supervisor only covers the gap Landlock
    // cannot express, per pid /proc scoping. Kernel canonical resolution catches symlinks
    // redirecting into /proc mount leaks.
    if let Some(canon) = pinned_canonical_path(pid, dirfd, &raw_path)
        && is_proc_mount_leak(&canon)
    {
        log_open_denial(pid, &canon, "proc_mount_leak");
        return SupervisorReply::Deny(libc::EACCES);
    }

    // Normalize the read denial so it does not leak existence. Without this,
    // Landlock returns EACCES for denied existing paths and the kernel
    // returns ENOENT for missing ones, an oracle on read_list trees like
    // /etc. Mirrors the stat_request gate. Continue only when the path sits
    // under a read bucket or is an ancestor of one (shells stat $HOME and
    // PATH components routinely).
    let check_path = pinned_canonical_path(pid, dirfd, &raw_path)
        .or_else(|| canonical_with_existing_ancestor(&normalized))
        .unwrap_or_else(|| normalized.clone());
    if !is_read_permitted(&check_path, allowed_read)
        && !is_stat_ancestor_of_allowed(&check_path, allowed_read)
    {
        log_open_denial(pid, &normalized, "read_denied");
        return SupervisorReply::Deny(libc::EACCES);
    }
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    SupervisorReply::Continue
}

/// Open request dispatch context. Bundles supervisor handles and the
/// bucket slices referenced by every write open path.
struct WriteOpenCtx<'a> {
    notif: &'a Notif,
    notify_fd: RawFd,
    read_only_enforced: &'a [PathBuf],
    allowed: &'a [PathBuf],
    allowed_overwrite: &'a [PathBuf],
}

/// TOCTOU-safe write-open path: borrow the child's dirfd, resolve the path
/// through the supervisor's own openat2 (RESOLVE_BENEATH|NO_MAGICLINKS),
/// validate against read_only and write buckets, and inject the fd via
/// ADDFD_SEND so the kernel never re-resolves.
fn open_request_write(
    ctx: &WriteOpenCtx<'_>,
    dirfd_arg: u64,
    raw_path: &Path,
    normalized: &Path,
    flags: i32,
    mode: u32,
) -> SupervisorReply {
    let WriteOpenCtx {
        notif,
        notify_fd,
        read_only_enforced,
        allowed,
        allowed_overwrite,
    } = *ctx;
    let pid = notif.pid;

    // Absolute paths get resolved against the child's root, which for us
    // is the same namespace, so anchor at `/` via an O_PATH open on root.
    // Relative paths anchor at the translated dirfd.
    let (anchor_fd, rel_path) = if raw_path.is_absolute() {
        let c_root = match CString::new("/") {
            Ok(c) => c,
            Err(_) => return SupervisorReply::Deny(libc::EPERM),
        };
        let fd = unsafe {
            libc::open(
                c_root.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return SupervisorReply::Deny(libc::EPERM);
        }
        let anchor = unsafe { OwnedFd::from_raw_fd(fd) };
        let stripped = raw_path.strip_prefix("/").unwrap_or(raw_path).to_path_buf();
        (anchor, stripped)
    } else {
        let pidfd = match pidfd_open(pid) {
            Ok(f) => f,
            Err(_) => return SupervisorReply::Deny(libc::EPERM),
        };
        let anchor = match resolve_dirfd(&pidfd, pid, dirfd_arg) {
            Ok(f) => f,
            Err(_) => return SupervisorReply::Deny(libc::EPERM),
        };
        (anchor, raw_path.to_path_buf())
    };

    let Ok(c_path) = CString::new(rel_path.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };

    // O_PATH validation: openat2 rejects any flag that is not one of
    // O_DIRECTORY, O_NOFOLLOW, O_PATH, O_CLOEXEC with EINVAL. zsh's
    // `2>/dev/null` passes O_NOCTTY, other callers pass O_SYNC/O_DIRECT
    // etc. Build the probe flags from the legal subset only.
    let keep = libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let validate_flags = (flags & keep) | libc::O_PATH | libc::O_CLOEXEC;

    let resolved_fd = openat2_pinned(
        anchor_fd.as_raw_fd(),
        &c_path,
        validate_flags,
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    );

    match resolved_fd {
        Ok(fd) => {
            let canonical =
                resolved_path(fd.as_raw_fd()).unwrap_or_else(|_| normalized.to_path_buf());
            if is_read_only_target(&canonical, read_only_enforced) {
                log_open_denial(pid, &canonical, "read_only_write");
                return SupervisorReply::Deny(libc::EACCES);
            }
            // File exists. Writing or truncating it requires a bucket that
            // permits overwriting an existing entry (full_access or
            // read_write). dir_create only authorizes adding new entries so
            // Landlock would have refused this write at the inode layer; the
            // supervisor reimplements that distinction because ADDFD_SEND
            // takes the open out of Landlock's jurisdiction.
            if !is_write_permitted(&canonical, allowed_overwrite, read_only_enforced) {
                log_open_denial(pid, &canonical, "overwrite_denied");
                return SupervisorReply::Deny(libc::EACCES);
            }
            // Re-open with real flags (drop O_PATH so reads/writes work).
            let real_flags = (flags & !libc::O_NOFOLLOW) | libc::O_CLOEXEC;
            let real = openat2_pinned(
                anchor_fd.as_raw_fd(),
                &c_path,
                real_flags,
                RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
            );
            match real {
                Ok(real_fd) => {
                    if !notify_id_valid(notify_fd, notif.id) {
                        return SupervisorReply::Deny(libc::EPERM);
                    }
                    let newfd_flags = if (flags & libc::O_CLOEXEC) != 0 {
                        libc::O_CLOEXEC as u32
                    } else {
                        0
                    };
                    match addfd_send(notify_fd, notif.id, real_fd.as_raw_fd(), newfd_flags) {
                        Ok(_) => SupervisorReply::Injected,
                        Err(e) => {
                            tracing::warn!(
                                target: TARGET,
                                event = "addfd_send_failed",
                                pid,
                                path = %canonical.display(),
                                error = %e,
                            );
                            SupervisorReply::Deny(libc::EPERM)
                        }
                    }
                }
                Err(e) => {
                    let errno = e.raw_os_error().unwrap_or(libc::EACCES);
                    // O_CREAT|O_EXCL on an existing file is a legitimate
                    // atomic-create probe; the caller expects EEXIST and
                    // falls back. Don't log it as a denial.
                    let atomic_create_probe = errno == libc::EEXIST
                        && (flags & libc::O_CREAT) != 0
                        && (flags & libc::O_EXCL) != 0;
                    if !atomic_create_probe {
                        log_open_denial(pid, &canonical, "reopen_failed");
                    }
                    SupervisorReply::Deny(errno)
                }
            }
        }
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(libc::EACCES);
            if errno == libc::ENOENT && (flags & libc::O_CREAT) != 0 {
                let create_ctx = WriteOpenCtx {
                    notif,
                    notify_fd,
                    read_only_enforced,
                    allowed,
                    allowed_overwrite,
                };
                return open_request_create(&create_ctx, &anchor_fd, &rel_path, flags, mode);
            }
            // EXDEV means resolution crossed an absolute symlink or ".." escape
            // out of the beneath anchor. Retry without BENEATH to fetch the
            // canonical leaf, then enforce policy on that canonical.
            if errno == libc::EXDEV {
                return open_request_symlink_escape(
                    notif,
                    notify_fd,
                    &anchor_fd,
                    &c_path,
                    flags,
                    read_only_enforced,
                    allowed_overwrite,
                );
            }
            log_open_denial(pid, normalized, "openat2_failed");
            SupervisorReply::Deny(errno)
        }
    }
}

/// Symlink leaf escapes the beneath anchor. Resolve canonical without BENEATH,
/// enforce policy on the canonical, and reopen anchored at `/` so the injected
/// fd still carries a kernel-pinned resolution.
fn open_request_symlink_escape(
    notif: &Notif,
    notify_fd: RawFd,
    anchor_fd: &OwnedFd,
    c_path: &CString,
    flags: i32,
    read_only_enforced: &[PathBuf],
    allowed_overwrite: &[PathBuf],
) -> SupervisorReply {
    let pid = notif.pid;
    let keep = libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let validate_flags = (flags & keep) | libc::O_PATH | libc::O_CLOEXEC;
    let probe_fd = match openat2_pinned(
        anchor_fd.as_raw_fd(),
        c_path,
        validate_flags,
        RESOLVE_NO_MAGICLINKS,
    ) {
        Ok(f) => f,
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(libc::EACCES);
            return SupervisorReply::Deny(errno);
        }
    };
    let canonical = match resolved_path(probe_fd.as_raw_fd()) {
        Ok(p) => p,
        Err(_) => return SupervisorReply::Deny(libc::EACCES),
    };
    if is_read_only_target(&canonical, read_only_enforced) {
        log_open_denial(pid, &canonical, "read_only_write");
        return SupervisorReply::Deny(libc::EACCES);
    }
    if !is_write_permitted(&canonical, allowed_overwrite, read_only_enforced) {
        log_open_denial(pid, &canonical, "overwrite_denied");
        return SupervisorReply::Deny(libc::EACCES);
    }

    let c_root = match CString::new("/") {
        Ok(c) => c,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };
    let root_raw = unsafe {
        libc::open(
            c_root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_raw < 0 {
        return SupervisorReply::Deny(libc::EPERM);
    }
    let root_fd = unsafe { OwnedFd::from_raw_fd(root_raw) };
    let rel = canonical.strip_prefix("/").unwrap_or(&canonical);
    let Ok(c_rel) = CString::new(rel.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    let real_flags = (flags & !libc::O_NOFOLLOW) | libc::O_CLOEXEC;
    let real = match openat2_pinned(
        root_fd.as_raw_fd(),
        &c_rel,
        real_flags,
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    ) {
        Ok(f) => f,
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(libc::EACCES);
            log_open_denial(pid, &canonical, "symlink_reopen_failed");
            return SupervisorReply::Deny(errno);
        }
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    let newfd_flags = if (flags & libc::O_CLOEXEC) != 0 {
        libc::O_CLOEXEC as u32
    } else {
        0
    };
    match addfd_send(notify_fd, notif.id, real.as_raw_fd(), newfd_flags) {
        Ok(_) => SupervisorReply::Injected,
        Err(e) => {
            tracing::warn!(
                target: TARGET,
                event = "addfd_send_failed",
                pid,
                path = %canonical.display(),
                error = %e,
            );
            SupervisorReply::Deny(libc::EPERM)
        }
    }
}

/// O_CREAT path: parent dir pinned, leaf validated, supervisor creates
/// the file itself and injects the resulting fd.
fn open_request_create(
    ctx: &WriteOpenCtx<'_>,
    anchor_fd: &OwnedFd,
    rel_path: &Path,
    flags: i32,
    mode: u32,
) -> SupervisorReply {
    let WriteOpenCtx {
        notif,
        notify_fd,
        read_only_enforced,
        allowed,
        ..
    } = *ctx;
    let pid = notif.pid;
    let (parent, leaf) = match split_parent_leaf(rel_path) {
        Some(pair) => pair,
        None => return SupervisorReply::Deny(libc::EPERM),
    };

    let parent_fd_owned;
    let parent_fd = if parent.as_os_str().is_empty() {
        anchor_fd.as_raw_fd()
    } else {
        let Ok(c_parent) = CString::new(parent.as_os_str().as_bytes()) else {
            return SupervisorReply::Deny(libc::EPERM);
        };
        match openat2_pinned(
            anchor_fd.as_raw_fd(),
            &c_parent,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
        ) {
            Ok(fd) => {
                parent_fd_owned = fd;
                parent_fd_owned.as_raw_fd()
            }
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(libc::EACCES);
                return SupervisorReply::Deny(errno);
            }
        }
    };

    let canonical_parent = resolved_path(parent_fd).unwrap_or_default();
    let canonical = canonical_parent.join(&leaf);

    if is_read_only_target(&canonical, read_only_enforced) {
        log_open_denial(pid, &canonical, "read_only_write");
        return SupervisorReply::Deny(libc::EACCES);
    }
    if !is_write_permitted(&canonical, allowed, read_only_enforced) {
        log_open_denial(pid, &canonical, "protected_write");
        return SupervisorReply::Deny(libc::EPERM);
    }

    let Ok(c_leaf) = CString::new(leaf.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };

    let create_flags = (flags & !libc::O_NOFOLLOW) | libc::O_CLOEXEC;
    let new_fd = match openat2_create(
        parent_fd,
        &c_leaf,
        create_flags,
        mode,
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    ) {
        Ok(fd) => fd,
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(libc::EACCES);
            log_open_denial(pid, &canonical, "create_failed");
            return SupervisorReply::Deny(errno);
        }
    };

    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    let newfd_flags = if (flags & libc::O_CLOEXEC) != 0 {
        libc::O_CLOEXEC as u32
    } else {
        0
    };
    match addfd_send(notify_fd, notif.id, new_fd.as_raw_fd(), newfd_flags) {
        Ok(_) => SupervisorReply::Injected,
        Err(e) => {
            tracing::warn!(
                target: TARGET,
                event = "addfd_send_failed",
                pid,
                path = %canonical.display(),
                error = %e,
            );
            SupervisorReply::Deny(libc::EPERM)
        }
    }
}

/// Split a relative path into (parent, leaf). Empty parent means the
/// path is a single component and the anchor itself is the parent.
fn split_parent_leaf(p: &Path) -> Option<(PathBuf, PathBuf)> {
    let leaf = p.file_name()?;
    let parent = p.parent().map(Path::to_path_buf).unwrap_or_default();
    Some((parent, PathBuf::from(leaf)))
}

/// Deny inet bind (extends Landlock BindTcp to UDP). Allow filesystem
/// AF_UNIX bind inside a writable root that is not under a read_only
/// entry so Jupyter, dbus, gRPC UDS clients work. Abstract AF_UNIX
/// (sun_path[0] == 0) is refused here so isolation does not rest on
/// the Landlock abstract socket scope alone.
fn evaluate_bind_request(
    notif: &Notif,
    notify_fd: RawFd,
    allowed: &[PathBuf],
    read_only: &[PathBuf],
    mem: &mut MemCache,
) -> SupervisorReply {
    let pid = notif.pid;
    let addr_ptr = notif.data.args[1];
    let addrlen = notif.data.args[2];

    let Some((family, port, addr)) = read_proc_sockaddr(mem, pid, addr_ptr, addrlen) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }

    if family == libc::AF_INET as u16 || family == libc::AF_INET6 as u16 {
        tracing::warn!(
            target: TARGET,
            event = "bind_denied",
            pid,
            family,
            port,
        );
        return SupervisorReply::Deny(libc::EACCES);
    }

    if family == libc::AF_UNIX as u16 {
        if is_filesystem_unix_socket(&addr) {
            let Some(path) = resolve_sun_path(pid, &addr) else {
                tracing::warn!(
                    target: TARGET,
                    event = "unix_bind_denied",
                    pid,
                    reason = "filesystem_socket",
                );
                return SupervisorReply::Deny(libc::EACCES);
            };
            let normalized = normalize_lexical_path(&path);
            if is_write_permitted(&normalized, allowed, read_only) {
                if !notify_id_valid(notify_fd, notif.id) {
                    return SupervisorReply::Deny(libc::EPERM);
                }
                return SupervisorReply::Continue;
            }
            tracing::warn!(
                target: TARGET,
                event = "unix_bind_denied",
                pid,
                reason = "filesystem_socket",
            );
            return SupervisorReply::Deny(libc::EACCES);
        }
        // Abstract (sun_path[0] == 0) or unnamed AF_UNIX bind. Refused
        // so isolation does not rest on Landlock scope alone.
        tracing::warn!(
            target: TARGET,
            event = "unix_bind_denied",
            pid,
            reason = "abstract_or_unnamed",
        );
        return SupervisorReply::Deny(libc::EACCES);
    }

    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    SupervisorReply::Continue
}

/// Allow inet connect only to the two local proxy ports (mirrors Landlock ConnectTcp).
/// Allow filesystem AF_UNIX connect when the path falls under a writable root
/// that is not under a read_only entry (symmetric with bind). Abstract unix
/// sockets are allowed via Landlock Scope::AbstractUnixSocket.
fn evaluate_connect_request(
    notif: &Notif,
    notify_fd: RawFd,
    tunnel_port: u16,
    api_port: u16,
    allowed: &[PathBuf],
    read_only: &[PathBuf],
    mem: &mut MemCache,
) -> SupervisorReply {
    let pid = notif.pid;
    let addr_ptr = notif.data.args[1];
    let addrlen = notif.data.args[2];

    // connect() with a NULL addr disconnects a UDP socket.
    if addr_ptr == 0 {
        return SupervisorReply::Continue;
    }

    let Some((family, port, addr)) = read_proc_sockaddr(mem, pid, addr_ptr, addrlen) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }

    let decision = match family {
        f if f == libc::AF_INET as u16 => {
            if addr == [127, 0, 0, 1] && (port == tunnel_port || port == api_port) {
                SupervisorReply::Continue
            } else {
                log_connect_denial(pid, family, port, &addr);
                SupervisorReply::Deny(libc::EPERM)
            }
        }
        f if f == libc::AF_INET6 as u16 => {
            let loopback_v6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            let mapped_v4_lo: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1];
            let is_loopback = addr == loopback_v6 || addr == mapped_v4_lo;
            if is_loopback && (port == tunnel_port || port == api_port) {
                SupervisorReply::Continue
            } else {
                log_connect_denial(pid, family, port, &addr);
                SupervisorReply::Deny(libc::EPERM)
            }
        }
        f if f == libc::AF_UNIX as u16 => {
            if is_filesystem_unix_socket(&addr) {
                let mut reply = SupervisorReply::Deny(libc::EPERM);
                if let Some(path) = resolve_sun_path(pid, &addr) {
                    let normalized = normalize_lexical_path(&path);
                    if is_write_permitted(&normalized, allowed, read_only) {
                        reply = SupervisorReply::Continue;
                    }
                }
                if matches!(reply, SupervisorReply::Deny(_)) {
                    tracing::warn!(
                        target: TARGET,
                        event = "unix_connect_denied",
                        pid,
                        reason = "filesystem_socket",
                    );
                }
                reply
            } else {
                // Abstract or unnamed AF_UNIX connect. Symmetric with bind.
                tracing::warn!(
                    target: TARGET,
                    event = "unix_connect_denied",
                    pid,
                    reason = "abstract_or_unnamed",
                );
                SupervisorReply::Deny(libc::EACCES)
            }
        }
        _ => SupervisorReply::Continue,
    };

    if matches!(decision, SupervisorReply::Continue) && !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    decision
}

/// Returns true if the AF_UNIX address represents a filesystem socket
/// (sun_path starts with a non-NUL byte). Abstract sockets have sun_path[0] == '\0',
/// and unnamed sockets have an empty addr.
fn is_filesystem_unix_socket(sun_path: &[u8]) -> bool {
    !sun_path.is_empty() && sun_path[0] != 0
}

/// Resolve a sockaddr_un sun_path to an absolute filesystem path. Relative
/// paths are joined against /proc/{pid}/cwd so Jupyter/gRPC style clients
/// that bind with a relative name still match the write bucket check.
fn resolve_sun_path(pid: u32, sun_path: &[u8]) -> Option<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let end = sun_path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(sun_path.len());
    if end == 0 {
        return None;
    }
    let os = OsStr::from_bytes(&sun_path[..end]);
    let pb = PathBuf::from(os);
    if pb.is_absolute() {
        return Some(pb);
    }
    let cwd = std::fs::read_link(format!("/proc/{pid}/cwd")).ok()?;
    Some(cwd.join(pb))
}

fn read_proc_sockaddr(
    mem: &mut MemCache,
    pid: u32,
    addr_ptr: u64,
    addrlen: u64,
) -> Option<(u16, u16, Vec<u8>)> {
    if addrlen < 2 {
        return None;
    }
    let len = (addrlen as usize).min(128);
    let mut buf = vec![0u8; len];
    mem.read_bytes(pid, addr_ptr, &mut buf)?;

    let family = u16::from_ne_bytes([buf[0], buf[1]]);

    if family == libc::AF_INET as u16 && len >= 8 {
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let addr = buf[4..8].to_vec();
        Some((family, port, addr))
    } else if family == libc::AF_INET6 as u16 && len >= 24 {
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let addr = buf[8..24].to_vec();
        Some((family, port, addr))
    } else if family == libc::AF_UNIX as u16 {
        // sun_path starts at offset 2 in sockaddr_un.
        // Return the path bytes so callers can distinguish filesystem vs abstract sockets.
        let path = if len > 2 { buf[2..].to_vec() } else { vec![] };
        Some((family, 0, path))
    } else {
        Some((family, 0, vec![]))
    }
}

/// Reject clone3 whose flags argument carries any bit outside
/// `allowed`. Flags live at offset 0 of `clone_args` pointed to by
/// arg0.
fn evaluate_clone3_request(
    notif: &Notif,
    notify_fd: RawFd,
    allowed: u64,
    mem: &mut MemCache,
) -> SupervisorReply {
    let pid = notif.pid;
    let args_ptr = notif.data.args[0];

    let mut buf = [0u8; 8];
    let Some(_) = mem.read_bytes(pid, args_ptr, &mut buf) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    let flags = u64::from_ne_bytes(buf);
    let unknown = flags & !allowed;
    if unknown != 0 {
        tracing::warn!(
            target: TARGET,
            event = "clone3_flags_denied",
            pid,
            flags = format!("{flags:#x}"),
            outside_allowed = format!("{unknown:#x}"),
        );
        return SupervisorReply::Deny(libc::EPERM);
    }
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    SupervisorReply::Continue
}

/// Reject cross-process signals aimed at the root sandbox process or the
/// supervisor itself. Landlock's Signal scope blocks cross-domain sends but
/// not intra-domain, so a descendant can still `kill(root_pid, SIGKILL)` and
/// end the session. We also refuse the process-group variant `kill(-pid,
/// ...)` for either protected pid, since in the normal configuration each
/// process leads its own group and that form otherwise bypasses the direct
/// pid check. Intra-process thread signaling (bun's GC stop-the-world via
/// tgkill, glibc pthread_kill) must stay allowed, so the check only fires
/// when the caller's tgid is not one of the protected pids.
fn evaluate_signal_request(notif: &Notif, root_pid: u32) -> SupervisorReply {
    let caller_tgid = read_tgid(notif.pid).unwrap_or(notif.pid);
    let supervisor_pid = std::process::id();
    if caller_tgid == root_pid || caller_tgid == supervisor_pid {
        return SupervisorReply::Continue;
    }
    let nr = notif.data.nr;
    let target = notif.data.args[0] as i32;
    let sig = notif.data.args[1] as i32;
    let root = root_pid as i32;
    let sup = supervisor_pid as i32;
    let hits_protected = match nr {
        SYS_KILL => {
            target == root
                || target == sup
                || target == -1
                || target == -root
                || target == -sup
                // kill(0, sig) targets the caller's process group. Deny
                // non-noop signals so descendants cannot kill protected
                // peers that share the same pgrp.
                || (target == 0 && sig != 0)
        }
        SYS_TKILL => {
            // tkill arg0 is a TID. SIGKILL to any thread kills the
            // whole group, so resolve TID to TGID before comparing
            // against the protected pids.
            let tgid = read_tgid(target as u32).unwrap_or(target as u32) as i32;
            tgid == root || tgid == sup
        }
        SYS_TGKILL => target == root || target == sup,
        _ => false,
    };
    if hits_protected {
        tracing::warn!(
            target: TARGET,
            event = "signal_denied_protected",
            pid = notif.pid,
            caller_tgid,
            syscall_nr = nr,
            target_pid = target,
            root_pid,
            supervisor_pid,
        );
        return SupervisorReply::Deny(libc::EPERM);
    }
    SupervisorReply::Continue
}

/// Read the Tgid field from /proc/<tid>/status. Returns None if the task has
/// already exited or the status file cannot be parsed.
fn read_tgid(tid: u32) -> Option<u32> {
    let data = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn log_connect_denial(pid: u32, family: u16, port: u16, addr: &[u8]) {
    let addr_str = if family == libc::AF_INET as u16 && addr.len() == 4 {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    } else {
        format!("{addr:?}")
    };
    tracing::warn!(
        target: TARGET,
        event = "connect_denied",
        pid,
        family,
        addr = addr_str,
        port,
    );
}

/// TOCTOU-safe fd-based metadata writes: borrow the child's fd via
/// pidfd_getfd, read the canonical path of the borrowed fd, check
/// read_only/write buckets against that inode, then execute the fd
/// variant from the supervisor and reply with the real result.
fn evaluate_fd_write(
    notif: &Notif,
    notify_fd: RawFd,
    read_only: &[PathBuf],
    allowed: &[PathBuf],
) -> SupervisorReply {
    let pid = notif.pid;
    let nr = notif.data.nr;
    let fd_arg = notif.data.args[0] as i32;

    let pidfd = match pidfd_open(pid) {
        Ok(f) => f,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };
    let borrowed = match pidfd_getfd(pidfd.as_raw_fd(), fd_arg) {
        Ok(f) => f,
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(libc::EBADF);
            return SupervisorReply::Deny(errno);
        }
    };
    let check_path =
        resolved_path(borrowed.as_raw_fd()).unwrap_or_else(|_| PathBuf::from("<unknown>"));

    if is_read_only_target(&check_path, read_only) {
        tracing::warn!(
            target: TARGET,
            event = "denied",
            pid,
            syscall = nr,
            fd = fd_arg,
            path = %check_path.display(),
            reason = "read_only",
        );
        return SupervisorReply::Deny(libc::EACCES);
    }
    if !is_write_permitted(&check_path, allowed, read_only) {
        tracing::warn!(
            target: TARGET,
            event = "denied",
            pid,
            syscall = nr,
            fd = fd_arg,
            path = %check_path.display(),
        );
        return SupervisorReply::Deny(libc::EPERM);
    }

    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }

    let a = &notif.data.args;
    let (rc, err) = unsafe {
        match nr {
            n if n == SYS_FCHMOD => {
                let r = libc::syscall(libc::SYS_fchmod, borrowed.as_raw_fd(), a[1] as libc::mode_t);
                (r, io::Error::last_os_error())
            }
            n if n == SYS_FCHOWN => {
                let r = libc::syscall(
                    libc::SYS_fchown,
                    borrowed.as_raw_fd(),
                    a[1] as libc::uid_t,
                    a[2] as libc::gid_t,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_FSETXATTR => {
                let Some(name) = read_c_str(pid, a[1]) else {
                    return SupervisorReply::Deny(libc::EFAULT);
                };
                let size = a[3] as usize;
                if size > XATTR_VALUE_MAX {
                    return SupervisorReply::Deny(libc::E2BIG);
                }
                let mut buf = vec![0u8; size];
                if size > 0
                    && std::fs::File::open(format!("/proc/{pid}/mem"))
                        .and_then(|f| f.read_at(&mut buf, a[2]).map(|_| ()))
                        .is_err()
                {
                    return SupervisorReply::Deny(libc::EFAULT);
                }
                let r = libc::syscall(
                    libc::SYS_fsetxattr,
                    borrowed.as_raw_fd(),
                    name.as_ptr(),
                    buf.as_ptr(),
                    size,
                    a[4] as libc::c_int,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_FREMOVEXATTR => {
                let Some(name) = read_c_str(pid, a[1]) else {
                    return SupervisorReply::Deny(libc::EFAULT);
                };
                let r = libc::syscall(libc::SYS_fremovexattr, borrowed.as_raw_fd(), name.as_ptr());
                (r, io::Error::last_os_error())
            }
            _ => return SupervisorReply::Deny(libc::EPERM),
        }
    };

    if rc < 0 {
        let errno = err.raw_os_error().unwrap_or(libc::EPERM);
        return SupervisorReply::SyscallResult { rc: -1, errno };
    }
    SupervisorReply::SyscallResult { rc, errno: 0 }
}

/// Read a NUL-terminated string from the child's memory. Caps at PATH_MAX
/// bytes; returns None on read failure.
fn read_c_str(pid: u32, ptr: u64) -> Option<CString> {
    let f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    f.read_at(&mut buf, ptr).ok()?;
    let end = buf.iter().position(|&b| b == 0)?;
    buf.truncate(end);
    CString::new(buf).ok()
}

/// Path-only write syscalls where the supervisor must execute the call
/// itself against a pinned parent fd so the kernel cannot re-resolve a
/// racing symlink. Covers truncate, [l]setxattr, [l]removexattr, the
/// legacy chmod/chown/lchown/utimes/mknod/mkdir/rmdir/unlink forms.
fn evaluate_path_write(
    notif: &Notif,
    notify_fd: RawFd,
    read_only: &[PathBuf],
    allowed: &[PathBuf],
    mem: &mut MemCache,
) -> SupervisorReply {
    let pid = notif.pid;
    let nr = notif.data.nr;
    let path_ptr = notif.data.args[0];

    let Some(raw) = mem.read_path(pid, path_ptr) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }

    let pidfd = match pidfd_open(pid) {
        Ok(f) => f,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };
    // Legacy path forms always use AT_FDCWD semantics.
    let anchor = match resolve_dirfd(&pidfd, pid, AT_FDCWD) {
        Ok(f) => f,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };

    let rel = if raw.is_absolute() {
        match raw.strip_prefix("/") {
            Ok(p) => p.to_path_buf(),
            Err(_) => raw.clone(),
        }
    } else {
        raw.clone()
    };
    let anchor_for_open: OwnedFd;
    let anchor_fd = if raw.is_absolute() {
        let c_root = match CString::new("/") {
            Ok(c) => c,
            Err(_) => return SupervisorReply::Deny(libc::EPERM),
        };
        let fd = unsafe {
            libc::open(
                c_root.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return SupervisorReply::Deny(libc::EPERM);
        }
        anchor_for_open = unsafe { OwnedFd::from_raw_fd(fd) };
        anchor_for_open.as_raw_fd()
    } else {
        anchor.as_raw_fd()
    };

    let (parent_path, leaf) = match split_parent_leaf(&rel) {
        Some(pair) => pair,
        None => return SupervisorReply::Deny(libc::EPERM),
    };

    let parent_fd_owned;
    let parent_fd = if parent_path.as_os_str().is_empty() {
        anchor_fd
    } else {
        let Ok(c_parent) = CString::new(parent_path.as_os_str().as_bytes()) else {
            return SupervisorReply::Deny(libc::EPERM);
        };
        match openat2_pinned(
            anchor_fd,
            &c_parent,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
        ) {
            Ok(fd) => {
                parent_fd_owned = fd;
                parent_fd_owned.as_raw_fd()
            }
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(libc::EACCES);
                log_denial(pid, nr, path_ptr);
                return SupervisorReply::Deny(errno);
            }
        }
    };

    let canonical_parent = resolved_path(parent_fd).unwrap_or_default();
    let canonical = canonical_parent.join(&leaf);

    if is_read_only_target(&canonical, read_only) {
        log_denial(pid, nr, path_ptr);
        return SupervisorReply::Deny(libc::EACCES);
    }
    if !is_write_permitted(&canonical, allowed, read_only) {
        log_denial(pid, nr, path_ptr);
        return SupervisorReply::Deny(libc::EPERM);
    }

    let Ok(c_leaf) = CString::new(leaf.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };

    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }

    // Execute the *at variant against the pinned parent.
    execute_path_write(notif, mem, parent_fd, &c_leaf, &canonical, read_only)
}

/// Dispatch the actual path-write syscall against a pinned parent fd.
/// Returns the real rc/errno so the child observes identical semantics.
fn execute_path_write(
    notif: &Notif,
    mem: &mut MemCache,
    parent_fd: RawFd,
    c_leaf: &CString,
    canonical: &Path,
    read_only: &[PathBuf],
) -> SupervisorReply {
    let pid = notif.pid;
    let nr = notif.data.nr;
    let a = &notif.data.args;

    let (rc, err) = unsafe {
        match nr {
            n if n == SYS_TRUNCATE => {
                // truncate follows symlinks. Open the leaf with RESOLVE_BENEATH
                // to catch a racing symlink flip, then ftruncate the fd.
                let fd = match openat2_pinned(
                    parent_fd,
                    c_leaf,
                    libc::O_WRONLY | libc::O_CLOEXEC,
                    RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
                ) {
                    Ok(fd) => fd,
                    Err(e) => {
                        return SupervisorReply::Deny(e.raw_os_error().unwrap_or(libc::EACCES));
                    }
                };
                let leaf_path =
                    resolved_path(fd.as_raw_fd()).unwrap_or_else(|_| canonical.to_path_buf());
                if is_read_only_target(&leaf_path, read_only) {
                    return SupervisorReply::Deny(libc::EACCES);
                }
                let r = libc::syscall(libc::SYS_ftruncate, fd.as_raw_fd(), a[1] as i64);
                (r, io::Error::last_os_error())
            }
            n if n == SYS_SETXATTR || n == SYS_LSETXATTR => {
                let Some(name) = read_c_str(pid, a[1]) else {
                    return SupervisorReply::Deny(libc::EFAULT);
                };
                let size = a[3] as usize;
                if size > XATTR_VALUE_MAX {
                    return SupervisorReply::Deny(libc::E2BIG);
                }
                let mut buf = vec![0u8; size];
                if size > 0 && mem.read_bytes(pid, a[2], &mut buf).is_none() {
                    return SupervisorReply::Deny(libc::EFAULT);
                }
                let follow = n == SYS_SETXATTR;
                let r = setxattr_via_parent(
                    parent_fd,
                    c_leaf,
                    name.as_c_str(),
                    &buf,
                    a[4] as libc::c_int,
                    follow,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_REMOVEXATTR || n == SYS_LREMOVEXATTR => {
                let Some(name) = read_c_str(pid, a[1]) else {
                    return SupervisorReply::Deny(libc::EFAULT);
                };
                let follow = n == SYS_REMOVEXATTR;
                let r = removexattr_via_parent(parent_fd, c_leaf, name.as_c_str(), follow);
                (r, io::Error::last_os_error())
            }
            n if n == SYS_CHMOD => {
                let r = libc::syscall(
                    libc::SYS_fchmodat,
                    parent_fd,
                    c_leaf.as_ptr(),
                    a[1] as libc::mode_t,
                    0i32,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_CHOWN => {
                let r = libc::syscall(
                    libc::SYS_fchownat,
                    parent_fd,
                    c_leaf.as_ptr(),
                    a[1] as libc::uid_t,
                    a[2] as libc::gid_t,
                    0i32,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_LCHOWN => {
                let r = libc::syscall(
                    libc::SYS_fchownat,
                    parent_fd,
                    c_leaf.as_ptr(),
                    a[1] as libc::uid_t,
                    a[2] as libc::gid_t,
                    libc::AT_SYMLINK_NOFOLLOW,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_UTIMES => {
                // utimes: a[1] is a pointer to struct timeval[2].
                let times_ptr = a[1];
                let (times_ok, mut tv) = if times_ptr == 0 {
                    (true, [0u8; 32])
                } else {
                    let mut b = [0u8; 32];
                    let ok = mem.read_bytes(pid, times_ptr, &mut b).is_some();
                    (ok, b)
                };
                if !times_ok {
                    return SupervisorReply::Deny(libc::EFAULT);
                }
                // Translate timeval to timespec for utimensat.
                let mut specs = [libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }; 2];
                if times_ptr != 0 {
                    for (i, spec) in specs.iter_mut().enumerate() {
                        let off = i * 16;
                        let sec = i64::from_le_bytes(tv[off..off + 8].try_into().unwrap());
                        let usec = i64::from_le_bytes(tv[off + 8..off + 16].try_into().unwrap());
                        spec.tv_sec = sec;
                        spec.tv_nsec = usec * 1000;
                    }
                    // silence unused warning for the buffer mutation above
                    let _ = &mut tv;
                }
                let times_arg: *const libc::timespec = if times_ptr == 0 {
                    std::ptr::null()
                } else {
                    specs.as_ptr()
                };
                let r = libc::syscall(
                    libc::SYS_utimensat,
                    parent_fd,
                    c_leaf.as_ptr(),
                    times_arg,
                    0i32,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_MKNOD => {
                let r = libc::syscall(
                    libc::SYS_mknodat,
                    parent_fd,
                    c_leaf.as_ptr(),
                    a[1] as libc::mode_t,
                    a[2] as libc::dev_t,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_MKDIR => {
                let r = libc::syscall(
                    libc::SYS_mkdirat,
                    parent_fd,
                    c_leaf.as_ptr(),
                    a[1] as libc::mode_t,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_RMDIR => {
                let r = libc::syscall(
                    libc::SYS_unlinkat,
                    parent_fd,
                    c_leaf.as_ptr(),
                    libc::AT_REMOVEDIR,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_UNLINK => {
                let r = libc::syscall(libc::SYS_unlinkat, parent_fd, c_leaf.as_ptr(), 0i32);
                (r, io::Error::last_os_error())
            }
            _ => return SupervisorReply::Deny(libc::EPERM),
        }
    };

    if rc < 0 {
        let errno = err.raw_os_error().unwrap_or(libc::EPERM);
        return SupervisorReply::SyscallResult { rc: -1, errno };
    }
    SupervisorReply::SyscallResult { rc, errno: 0 }
}

/// Perform (l)setxattr against a pinned parent by going through
/// /proc/self/fd/N. This avoids a direct path-form setxattr the kernel
/// might re-resolve.
fn setxattr_via_parent(
    parent_fd: RawFd,
    leaf: &CString,
    name: &std::ffi::CStr,
    value: &[u8],
    flags: libc::c_int,
    follow_symlinks: bool,
) -> libc::c_long {
    let resolve = if follow_symlinks {
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
    } else {
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | 0x04
    };
    let open_flags = libc::O_PATH | libc::O_CLOEXEC;
    let fd = match openat2_pinned(parent_fd, leaf, open_flags, resolve) {
        Ok(fd) => fd,
        Err(_) => return -1,
    };
    let proc_path = match CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    unsafe {
        libc::syscall(
            libc::SYS_setxattr,
            proc_path.as_ptr(),
            name.as_ptr(),
            value.as_ptr(),
            value.len(),
            flags,
        )
    }
}

fn removexattr_via_parent(
    parent_fd: RawFd,
    leaf: &CString,
    name: &std::ffi::CStr,
    follow_symlinks: bool,
) -> libc::c_long {
    let resolve = if follow_symlinks {
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
    } else {
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | 0x04
    };
    let open_flags = libc::O_PATH | libc::O_CLOEXEC;
    let fd = match openat2_pinned(parent_fd, leaf, open_flags, resolve) {
        Ok(fd) => fd,
        Err(_) => return -1,
    };
    let proc_path = match CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    unsafe { libc::syscall(libc::SYS_removexattr, proc_path.as_ptr(), name.as_ptr()) }
}

/// Evaluate dirfd+path write syscalls: fchmodat, fchownat, utimensat, mknodat.
/// dirfd is in arg0, path is in arg1. Supervisor pins the parent, validates
/// the leaf, and executes the *at syscall against the pinned parent fd.
fn evaluate_dirfd_write(
    notif: &Notif,
    notify_fd: RawFd,
    read_only: &[PathBuf],
    allowed: &[PathBuf],
    mem: &mut MemCache,
) -> SupervisorReply {
    let pid = notif.pid;
    let nr = notif.data.nr;
    let dirfd = notif.data.args[0];
    let path_ptr = notif.data.args[1];

    // utimensat(dirfd, NULL, ...) is "use dirfd directly" (AT_EMPTY_PATH).
    // Treat an empty leaf as the dirfd itself: open a throw-away path
    // that canonicalizes to the dirfd's inode and execute against it.
    let raw = if path_ptr == 0 {
        PathBuf::new()
    } else {
        let Some(r) = mem.read_path(pid, path_ptr) else {
            return SupervisorReply::Deny(libc::EPERM);
        };
        r
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }

    let pidfd = match pidfd_open(pid) {
        Ok(f) => f,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };

    // Empty pathname with a dirfd targets the fd itself (utimensat-with-NULL =
    // futimens). The fd was vetted at open time. pidfd_getfd here would fail
    // because the child is dumpable=0 post-exec, and we can't open
    // /proc/<pid>/fd/N either. Continue so the kernel executes against the
    // child's own fd. Kernel still checks write permission on the inode.
    if raw.as_os_str().is_empty() {
        if nr != SYS_UTIMENSAT {
            return SupervisorReply::Deny(libc::EFAULT);
        }
        if !notify_id_valid(notify_fd, notif.id) {
            return SupervisorReply::Deny(libc::EPERM);
        }
        return SupervisorReply::Continue;
    }

    let (anchor, rel) = if raw.is_absolute() {
        let c_root = match CString::new("/") {
            Ok(c) => c,
            Err(_) => return SupervisorReply::Deny(libc::EPERM),
        };
        let fd = unsafe {
            libc::open(
                c_root.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return SupervisorReply::Deny(libc::EPERM);
        }
        (
            unsafe { OwnedFd::from_raw_fd(fd) },
            raw.strip_prefix("/").unwrap_or(&raw).to_path_buf(),
        )
    } else {
        let anchor = match resolve_dirfd(&pidfd, pid, dirfd) {
            Ok(f) => f,
            Err(_) => return SupervisorReply::Deny(libc::EPERM),
        };
        (anchor, raw.clone())
    };

    let (parent_path, leaf) = match split_parent_leaf(&rel) {
        Some(pair) => pair,
        None => return SupervisorReply::Deny(libc::EPERM),
    };

    let parent_fd_owned;
    let parent_fd = if parent_path.as_os_str().is_empty() {
        anchor.as_raw_fd()
    } else {
        let Ok(c_parent) = CString::new(parent_path.as_os_str().as_bytes()) else {
            return SupervisorReply::Deny(libc::EPERM);
        };
        match openat2_pinned(
            anchor.as_raw_fd(),
            &c_parent,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
        ) {
            Ok(fd) => {
                parent_fd_owned = fd;
                parent_fd_owned.as_raw_fd()
            }
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(libc::EACCES);
                log_denial(pid, nr, path_ptr);
                return SupervisorReply::Deny(errno);
            }
        }
    };

    let canonical_parent = resolved_path(parent_fd).unwrap_or_default();
    let canonical = canonical_parent.join(&leaf);

    if is_read_only_target(&canonical, read_only) {
        log_denial(pid, nr, path_ptr);
        return SupervisorReply::Deny(libc::EACCES);
    }
    if !is_write_permitted(&canonical, allowed, read_only) {
        log_denial(pid, nr, path_ptr);
        return SupervisorReply::Deny(libc::EPERM);
    }

    let Ok(c_leaf) = CString::new(leaf.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };

    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }

    execute_dirfd_write(notif, mem, parent_fd, &c_leaf)
}

fn execute_dirfd_write(
    notif: &Notif,
    mem: &mut MemCache,
    parent_fd: RawFd,
    c_leaf: &CString,
) -> SupervisorReply {
    let pid = notif.pid;
    let nr = notif.data.nr;
    let a = &notif.data.args;
    let (rc, err) = unsafe {
        match nr {
            n if n == SYS_FCHMODAT => {
                let r = libc::syscall(
                    libc::SYS_fchmodat,
                    parent_fd,
                    c_leaf.as_ptr(),
                    a[2] as libc::mode_t,
                    a[3] as i32,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_FCHOWNAT => {
                let r = libc::syscall(
                    libc::SYS_fchownat,
                    parent_fd,
                    c_leaf.as_ptr(),
                    a[2] as libc::uid_t,
                    a[3] as libc::gid_t,
                    a[4] as i32,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_UTIMENSAT => {
                let times_ptr = a[2];
                let mut tv = [0u8; 32];
                let times_arg: *const libc::timespec = if times_ptr == 0 {
                    std::ptr::null()
                } else {
                    if mem.read_bytes(pid, times_ptr, &mut tv).is_none() {
                        return SupervisorReply::Deny(libc::EFAULT);
                    }
                    tv.as_ptr() as *const libc::timespec
                };
                let r = libc::syscall(
                    libc::SYS_utimensat,
                    parent_fd,
                    c_leaf.as_ptr(),
                    times_arg,
                    a[3] as i32,
                );
                (r, io::Error::last_os_error())
            }
            n if n == SYS_MKNODAT => {
                let r = libc::syscall(
                    libc::SYS_mknodat,
                    parent_fd,
                    c_leaf.as_ptr(),
                    a[2] as libc::mode_t,
                    a[3] as libc::dev_t,
                );
                (r, io::Error::last_os_error())
            }
            _ => return SupervisorReply::Deny(libc::EPERM),
        }
    };
    if rc < 0 {
        let errno = err.raw_os_error().unwrap_or(libc::EPERM);
        return SupervisorReply::SyscallResult { rc: -1, errno };
    }
    SupervisorReply::SyscallResult { rc, errno: 0 }
}

/// Structural filesystem modifications: the supervisor pins every parent
/// dirfd, validates both leaves against read_only/write buckets, and
/// executes the *at variant itself so the kernel cannot re-resolve a
/// symlink-flipped path between check and act.
fn evaluate_structural_write(
    notif: &Notif,
    notify_fd: RawFd,
    read_only_enforced: &[PathBuf],
    allowed: &[PathBuf],
    allowed_delete: &[PathBuf],
    mem: &mut MemCache,
) -> SupervisorReply {
    let pid = notif.pid;
    let a = &notif.data.args;
    let nr = notif.data.nr;

    let pidfd = match pidfd_open(pid) {
        Ok(f) => f,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };

    let delete_ctx = StructuralCtx {
        notif,
        notify_fd,
        pidfd: &pidfd,
        bucket: allowed_delete,
        read_only: read_only_enforced,
    };
    let create_ctx = StructuralCtx {
        notif,
        notify_fd,
        pidfd: &pidfd,
        bucket: allowed,
        read_only: read_only_enforced,
    };

    match nr {
        n if n == SYS_UNLINKAT => {
            let Some(raw) = mem.read_path(pid, a[1]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            if !notify_id_valid(notify_fd, notif.id) {
                return SupervisorReply::Deny(libc::EPERM);
            }
            structural_single(&delete_ctx, a[0], &raw, SYS_UNLINKAT, a[2])
        }
        n if n == SYS_MKDIRAT => {
            let Some(raw) = mem.read_path(pid, a[1]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            if !notify_id_valid(notify_fd, notif.id) {
                return SupervisorReply::Deny(libc::EPERM);
            }
            structural_mkdirat(&create_ctx, a[0], &raw, a[2] as libc::mode_t)
        }
        n if n == SYS_UNLINK => {
            let Some(raw) = mem.read_path(pid, a[0]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            if !notify_id_valid(notify_fd, notif.id) {
                return SupervisorReply::Deny(libc::EPERM);
            }
            structural_single(&delete_ctx, AT_FDCWD, &raw, SYS_UNLINKAT, 0)
        }
        n if n == SYS_RMDIR => {
            let Some(raw) = mem.read_path(pid, a[0]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            if !notify_id_valid(notify_fd, notif.id) {
                return SupervisorReply::Deny(libc::EPERM);
            }
            structural_single(
                &delete_ctx,
                AT_FDCWD,
                &raw,
                SYS_UNLINKAT,
                libc::AT_REMOVEDIR as u64,
            )
        }
        n if n == SYS_MKDIR => {
            let Some(raw) = mem.read_path(pid, a[0]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            if !notify_id_valid(notify_fd, notif.id) {
                return SupervisorReply::Deny(libc::EPERM);
            }
            structural_mkdirat(&create_ctx, AT_FDCWD, &raw, a[1] as libc::mode_t)
        }
        n if n == SYS_RENAMEAT || n == SYS_RENAMEAT2 => {
            let Some(old_raw) = mem.read_path(pid, a[1]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            let Some(new_raw) = mem.read_path(pid, a[3]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            if !notify_id_valid(notify_fd, notif.id) {
                return SupervisorReply::Deny(libc::EPERM);
            }
            let flags = if nr == SYS_RENAMEAT2 { a[4] as u32 } else { 0 };
            structural_rename(&delete_ctx, a[0], &old_raw, a[2], &new_raw, flags)
        }
        n if n == SYS_RENAME => {
            let Some(old_raw) = mem.read_path(pid, a[0]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            let Some(new_raw) = mem.read_path(pid, a[1]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            if !notify_id_valid(notify_fd, notif.id) {
                return SupervisorReply::Deny(libc::EPERM);
            }
            structural_rename(&delete_ctx, AT_FDCWD, &old_raw, AT_FDCWD, &new_raw, 0)
        }
        n if n == SYS_LINKAT => {
            let Some(old_raw) = mem.read_path(pid, a[1]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            let Some(new_raw) = mem.read_path(pid, a[3]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            if !notify_id_valid(notify_fd, notif.id) {
                return SupervisorReply::Deny(libc::EPERM);
            }
            structural_link(&create_ctx, a[0], &old_raw, a[2], &new_raw, a[4] as i32)
        }
        n if n == SYS_LINK => {
            let Some(old_raw) = mem.read_path(pid, a[0]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            let Some(new_raw) = mem.read_path(pid, a[1]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            if !notify_id_valid(notify_fd, notif.id) {
                return SupervisorReply::Deny(libc::EPERM);
            }
            structural_link(&create_ctx, AT_FDCWD, &old_raw, AT_FDCWD, &new_raw, 0)
        }
        n if n == SYS_SYMLINKAT => {
            // symlinkat(target, newdirfd, linkpath); target is literal.
            let Some(target) = mem.read_path(pid, a[0]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            let Some(link_raw) = mem.read_path(pid, a[2]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            if !notify_id_valid(notify_fd, notif.id) {
                return SupervisorReply::Deny(libc::EPERM);
            }
            structural_symlink(&create_ctx, &target, a[1], &link_raw)
        }
        n if n == SYS_SYMLINK => {
            let Some(target) = mem.read_path(pid, a[0]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            let Some(link_raw) = mem.read_path(pid, a[1]) else {
                return SupervisorReply::Deny(libc::EPERM);
            };
            if !notify_id_valid(notify_fd, notif.id) {
                return SupervisorReply::Deny(libc::EPERM);
            }
            structural_symlink(&create_ctx, &target, AT_FDCWD, &link_raw)
        }
        _ => SupervisorReply::Deny(libc::EPERM),
    }
}

/// Translate a raw path + dirfd_arg into (anchor_fd, rel_path). Caller
/// owns the returned fd.
fn anchor_and_rel(
    pidfd: &OwnedFd,
    pid: u32,
    dirfd_arg: u64,
    raw: &Path,
) -> io::Result<(OwnedFd, PathBuf)> {
    if raw.is_absolute() {
        let c_root = CString::new("/").unwrap();
        let fd = unsafe {
            libc::open(
                c_root.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            unsafe { OwnedFd::from_raw_fd(fd) },
            raw.strip_prefix("/").unwrap_or(raw).to_path_buf(),
        ))
    } else {
        Ok((resolve_dirfd(pidfd, pid, dirfd_arg)?, raw.to_path_buf()))
    }
}

fn open_parent(anchor: RawFd, parent: &Path) -> io::Result<Option<OwnedFd>> {
    if parent.as_os_str().is_empty() {
        return Ok(None);
    }
    let c_parent =
        CString::new(parent.as_os_str().as_bytes()).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(Some(openat2_pinned(
        anchor,
        &c_parent,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    )?))
}

/// Supervisor state shared by every structural syscall handler: notif
/// context, the borrowed pidfd used as the resolution anchor, and the
/// bucket slices validated on entry.
struct StructuralCtx<'a> {
    notif: &'a Notif,
    notify_fd: RawFd,
    pidfd: &'a OwnedFd,
    bucket: &'a [PathBuf],
    read_only: &'a [PathBuf],
}

fn structural_single(
    ctx: &StructuralCtx<'_>,
    dirfd_arg: u64,
    raw: &Path,
    exec_nr: i32,
    flags: u64,
) -> SupervisorReply {
    let StructuralCtx {
        notif,
        notify_fd,
        pidfd,
        bucket,
        read_only,
    } = *ctx;
    let pid = notif.pid;
    let nr = notif.data.nr;
    let (anchor, rel) = match anchor_and_rel(pidfd, pid, dirfd_arg, raw) {
        Ok(v) => v,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };
    let (parent, leaf) = match split_parent_leaf(&rel) {
        Some(p) => p,
        None => return SupervisorReply::Deny(libc::EPERM),
    };
    let parent_owned;
    let parent_fd = match open_parent(anchor.as_raw_fd(), &parent) {
        Ok(Some(fd)) => {
            parent_owned = fd;
            parent_owned.as_raw_fd()
        }
        Ok(None) => anchor.as_raw_fd(),
        Err(e) => {
            return SupervisorReply::Deny(e.raw_os_error().unwrap_or(libc::EACCES));
        }
    };
    let canonical = resolved_path(parent_fd).unwrap_or_default().join(&leaf);
    // For unlink: target existence matters for the read_only check.
    if exec_nr == SYS_UNLINKAT && is_read_only_target(&canonical, read_only) {
        log_denial_path(pid, nr, &canonical, "read_only");
        return SupervisorReply::Deny(libc::EPERM);
    }
    if !is_write_permitted(&canonical, bucket, read_only) {
        log_denial_path(pid, nr, &canonical, "not_permitted");
        return SupervisorReply::Deny(libc::EPERM);
    }
    let Ok(c_leaf) = CString::new(leaf.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    let rc = unsafe { libc::syscall(libc::SYS_unlinkat, parent_fd, c_leaf.as_ptr(), flags as i32) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return SupervisorReply::SyscallResult {
            rc: -1,
            errno: err.raw_os_error().unwrap_or(libc::EPERM),
        };
    }
    SupervisorReply::SyscallResult { rc, errno: 0 }
}

fn structural_mkdirat(
    ctx: &StructuralCtx<'_>,
    dirfd_arg: u64,
    raw: &Path,
    mode: libc::mode_t,
) -> SupervisorReply {
    let StructuralCtx {
        notif,
        notify_fd,
        pidfd,
        bucket,
        read_only,
    } = *ctx;
    let pid = notif.pid;
    let nr = notif.data.nr;
    let (anchor, rel) = match anchor_and_rel(pidfd, pid, dirfd_arg, raw) {
        Ok(v) => v,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };
    let Some((parent, leaf)) = split_parent_leaf(&rel) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    let parent_owned;
    let parent_fd = match open_parent(anchor.as_raw_fd(), &parent) {
        Ok(Some(fd)) => {
            parent_owned = fd;
            parent_owned.as_raw_fd()
        }
        Ok(None) => anchor.as_raw_fd(),
        Err(e) => return SupervisorReply::Deny(e.raw_os_error().unwrap_or(libc::EACCES)),
    };
    // Reject leaf names that slipped past split_parent_leaf as traversal
    // components. split_parent_leaf already uses Path::file_name, but be
    // defensive: any ../ or absolute fragment here is a bug.
    if leaf.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    let canonical = resolved_path(parent_fd).unwrap_or_default().join(&leaf);
    let Ok(c_leaf) = CString::new(leaf.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    // Existence check runs before bucket authorization so `mkdir -p` on an
    // already-present directory returns EEXIST instead of EPERM. Claude's
    // startup does this on $HOME, which is not in its writable bucket; the
    // EPERM path aborts the TUI before it renders. fstatat is a pure read
    // through the validated parent_fd and performs no write.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let stat_rc = unsafe {
        libc::fstatat(
            parent_fd,
            c_leaf.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if stat_rc == 0 {
        return SupervisorReply::SyscallResult {
            rc: -1,
            errno: libc::EEXIST,
        };
    }
    // Authorize the create against the bucket list. is_write_permitted only
    // returns true when canonical starts_with a caller-supplied writable
    // root and is not under a read_only root, giving a sanitizer barrier
    // against traversal.
    if !is_write_permitted(&canonical, bucket, read_only) {
        log_denial_path(pid, nr, &canonical, "not_permitted");
        return SupervisorReply::Deny(libc::EPERM);
    }
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    let rc = unsafe { libc::syscall(libc::SYS_mkdirat, parent_fd, c_leaf.as_ptr(), mode) };
    if rc < 0 {
        let errno = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EPERM);
        return SupervisorReply::SyscallResult { rc: -1, errno };
    }
    SupervisorReply::SyscallResult { rc, errno: 0 }
}

fn structural_rename(
    ctx: &StructuralCtx<'_>,
    old_dirfd: u64,
    old_raw: &Path,
    new_dirfd: u64,
    new_raw: &Path,
    flags: u32,
) -> SupervisorReply {
    let StructuralCtx {
        notif,
        notify_fd,
        pidfd,
        bucket: delete_bucket,
        read_only,
    } = *ctx;
    let pid = notif.pid;
    let nr = notif.data.nr;
    let (old_anchor, old_rel) = match anchor_and_rel(pidfd, pid, old_dirfd, old_raw) {
        Ok(v) => v,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };
    let (new_anchor, new_rel) = match anchor_and_rel(pidfd, pid, new_dirfd, new_raw) {
        Ok(v) => v,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };
    let (old_parent_path, old_leaf) = match split_parent_leaf(&old_rel) {
        Some(p) => p,
        None => return SupervisorReply::Deny(libc::EPERM),
    };
    let (new_parent_path, new_leaf) = match split_parent_leaf(&new_rel) {
        Some(p) => p,
        None => return SupervisorReply::Deny(libc::EPERM),
    };
    let op;
    let old_parent_fd = match open_parent(old_anchor.as_raw_fd(), &old_parent_path) {
        Ok(Some(fd)) => {
            op = fd;
            op.as_raw_fd()
        }
        Ok(None) => old_anchor.as_raw_fd(),
        Err(e) => {
            return SupervisorReply::Deny(e.raw_os_error().unwrap_or(libc::EACCES));
        }
    };
    let np;
    let new_parent_fd = match open_parent(new_anchor.as_raw_fd(), &new_parent_path) {
        Ok(Some(fd)) => {
            np = fd;
            np.as_raw_fd()
        }
        Ok(None) => new_anchor.as_raw_fd(),
        Err(e) => {
            return SupervisorReply::Deny(e.raw_os_error().unwrap_or(libc::EACCES));
        }
    };
    let old_canonical = resolved_path(old_parent_fd)
        .unwrap_or_default()
        .join(&old_leaf);
    let new_canonical = resolved_path(new_parent_fd)
        .unwrap_or_default()
        .join(&new_leaf);
    if is_read_only_target(&old_canonical, read_only)
        || is_read_only_target(&new_canonical, read_only)
    {
        log_denial(pid, nr, 0);
        return SupervisorReply::Deny(libc::EPERM);
    }
    if !is_write_permitted(&old_canonical, delete_bucket, read_only)
        || !is_write_permitted(&new_canonical, delete_bucket, read_only)
    {
        log_denial(pid, nr, 0);
        return SupervisorReply::Deny(libc::EPERM);
    }
    let Ok(c_old) = CString::new(old_leaf.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    let Ok(c_new) = CString::new(new_leaf.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_parent_fd,
            c_old.as_ptr(),
            new_parent_fd,
            c_new.as_ptr(),
            flags,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return SupervisorReply::SyscallResult {
            rc: -1,
            errno: err.raw_os_error().unwrap_or(libc::EPERM),
        };
    }
    SupervisorReply::SyscallResult { rc, errno: 0 }
}

fn structural_link(
    ctx: &StructuralCtx<'_>,
    old_dirfd: u64,
    old_raw: &Path,
    new_dirfd: u64,
    new_raw: &Path,
    flags: i32,
) -> SupervisorReply {
    let StructuralCtx {
        notif,
        notify_fd,
        pidfd,
        bucket,
        read_only,
    } = *ctx;
    let pid = notif.pid;
    let nr = notif.data.nr;
    let (old_anchor, old_rel) = match anchor_and_rel(pidfd, pid, old_dirfd, old_raw) {
        Ok(v) => v,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };
    let (new_anchor, new_rel) = match anchor_and_rel(pidfd, pid, new_dirfd, new_raw) {
        Ok(v) => v,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };
    let (old_parent_path, old_leaf) = match split_parent_leaf(&old_rel) {
        Some(p) => p,
        None => return SupervisorReply::Deny(libc::EPERM),
    };
    let (new_parent_path, new_leaf) = match split_parent_leaf(&new_rel) {
        Some(p) => p,
        None => return SupervisorReply::Deny(libc::EPERM),
    };
    let op;
    let old_parent_fd = match open_parent(old_anchor.as_raw_fd(), &old_parent_path) {
        Ok(Some(fd)) => {
            op = fd;
            op.as_raw_fd()
        }
        Ok(None) => old_anchor.as_raw_fd(),
        Err(e) => return SupervisorReply::Deny(e.raw_os_error().unwrap_or(libc::EACCES)),
    };
    let np;
    let new_parent_fd = match open_parent(new_anchor.as_raw_fd(), &new_parent_path) {
        Ok(Some(fd)) => {
            np = fd;
            np.as_raw_fd()
        }
        Ok(None) => new_anchor.as_raw_fd(),
        Err(e) => return SupervisorReply::Deny(e.raw_os_error().unwrap_or(libc::EACCES)),
    };
    let old_canonical = resolved_path(old_parent_fd)
        .unwrap_or_default()
        .join(&old_leaf);
    let new_canonical = resolved_path(new_parent_fd)
        .unwrap_or_default()
        .join(&new_leaf);
    if is_read_only_target(&new_canonical, read_only) {
        log_denial(pid, nr, 0);
        return SupervisorReply::Deny(libc::EPERM);
    }
    if (flags & libc::AT_SYMLINK_FOLLOW) != 0 && is_read_only_target(&old_canonical, read_only) {
        log_denial(pid, nr, 0);
        return SupervisorReply::Deny(libc::EPERM);
    }
    if !is_write_permitted(&old_canonical, bucket, read_only)
        || !is_write_permitted(&new_canonical, bucket, read_only)
    {
        log_denial(pid, nr, 0);
        return SupervisorReply::Deny(libc::EPERM);
    }
    let Ok(c_old) = CString::new(old_leaf.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    let Ok(c_new) = CString::new(new_leaf.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_linkat,
            old_parent_fd,
            c_old.as_ptr(),
            new_parent_fd,
            c_new.as_ptr(),
            flags,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return SupervisorReply::SyscallResult {
            rc: -1,
            errno: err.raw_os_error().unwrap_or(libc::EPERM),
        };
    }
    SupervisorReply::SyscallResult { rc, errno: 0 }
}

fn structural_symlink(
    ctx: &StructuralCtx<'_>,
    target: &Path,
    link_dirfd: u64,
    link_raw: &Path,
) -> SupervisorReply {
    let StructuralCtx {
        notif,
        notify_fd,
        pidfd,
        bucket,
        read_only,
    } = *ctx;
    let pid = notif.pid;
    let nr = notif.data.nr;
    let (link_anchor, link_rel) = match anchor_and_rel(pidfd, pid, link_dirfd, link_raw) {
        Ok(v) => v,
        Err(_) => return SupervisorReply::Deny(libc::EPERM),
    };
    let (parent_path, leaf) = match split_parent_leaf(&link_rel) {
        Some(p) => p,
        None => return SupervisorReply::Deny(libc::EPERM),
    };
    let po;
    let parent_fd = match open_parent(link_anchor.as_raw_fd(), &parent_path) {
        Ok(Some(fd)) => {
            po = fd;
            po.as_raw_fd()
        }
        Ok(None) => link_anchor.as_raw_fd(),
        Err(e) => return SupervisorReply::Deny(e.raw_os_error().unwrap_or(libc::EACCES)),
    };
    let canonical = resolved_path(parent_fd).unwrap_or_default().join(&leaf);
    if is_read_only_target(&canonical, read_only) {
        log_denial(pid, nr, 0);
        return SupervisorReply::Deny(libc::EPERM);
    }
    if !is_write_permitted(&canonical, bucket, read_only) {
        log_denial(pid, nr, 0);
        return SupervisorReply::Deny(libc::EPERM);
    }
    let Ok(c_target) = CString::new(target.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    let Ok(c_leaf) = CString::new(leaf.as_os_str().as_bytes()) else {
        return SupervisorReply::Deny(libc::EPERM);
    };
    if !notify_id_valid(notify_fd, notif.id) {
        return SupervisorReply::Deny(libc::EPERM);
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_symlinkat,
            c_target.as_ptr(),
            parent_fd,
            c_leaf.as_ptr(),
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return SupervisorReply::SyscallResult {
            rc: -1,
            errno: err.raw_os_error().unwrap_or(libc::EPERM),
        };
    }
    SupervisorReply::SyscallResult { rc, errno: 0 }
}

fn log_denial(pid: u32, syscall_nr: i32, path_ptr: u64) {
    let path_str = read_proc_path(pid, path_ptr)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "<unreadable>".to_string());
    tracing::warn!(
        target: TARGET,
        event = "denied",
        pid,
        syscall = syscall_nr,
        path = path_str,
    );
}

fn log_denial_path(pid: u32, syscall_nr: i32, path: &Path, reason: &str) {
    tracing::warn!(
        target: TARGET,
        event = "denied",
        pid,
        syscall = syscall_nr,
        path = %path.display(),
        reason,
    );
}

fn log_open_denial(pid: u32, path: &Path, reason: &str) {
    tracing::warn!(
        target: TARGET,
        event = "denied",
        pid,
        syscall = "open",
        path = %path.display(),
        reason,
    );
}

fn log_stat_denial(pid: u32, path: &Path, reason: &str) {
    tracing::warn!(
        target: TARGET,
        event = "denied",
        pid,
        syscall = "stat",
        path = %path.display(),
        reason,
    );
}

/// Check whether `path` is allowed to be written.
///
/// A write is permitted only when the path is under at least one allowed
/// root and is not under any read_only root. Both `path` and the entries
/// in `allowed` and `read_only` must already be fully resolved.
///
/// A read_only entry sits inside a broader write grant (e.g. a config
/// file inside $CWD's full_access bucket) and Landlock alone cannot
/// deny writes to it because access is additive. The supervisor path
/// check is the only layer that can, and like every seccomp path check
/// it is subject to TOCTOU: the supervisor reads the path from the
/// child's memory and the kernel reads it again to act, so a racing
/// child can swap the target between the two reads. Best-effort.
///
/// Also permits writes to temp file siblings of an allowed file: if
/// `/dir/foo.json` is allowed, then `/dir/foo.json.tmp.123` is also
/// permitted, which supports atomic write patterns. The sibling
/// allowance only fires when the allowed entry's leaf already contains a
/// dot, so directory roots like `/home/user/work` cannot be used to
/// approve writes to `/home/user/work.evil`.
fn is_write_permitted(path: &Path, allowed: &[PathBuf], read_only: &[PathBuf]) -> bool {
    if read_only.iter().any(|root| path.starts_with(root)) {
        return false;
    }
    if allowed.iter().any(|root| path.starts_with(root)) {
        return true;
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) {
        return allowed.iter().any(|root| {
            matches!(
                (root.parent(), root.file_name().and_then(|n| n.to_str())),
                (Some(rp), Some(rn))
                    if rp == parent
                        && rn.contains('.')
                        && name.len() > rn.len()
                        && name.starts_with(rn)
                        && name.as_bytes()[rn.len()] == b'.'
            )
        });
    }
    false
}

/// Check whether `path` is allowed to be read.
///
/// A read is permitted when the path is under at least one allowed-read root.
/// Unlike writes, there is no read_only exclusion — the read set already
/// reflects Landlock's full grant list.  This is a lexical check on the
/// normalized path; Landlock enforces the real inode-level boundary.
fn is_read_permitted(path: &Path, allowed_read: &[PathBuf]) -> bool {
    allowed_read.iter().any(|root| path.starts_with(root))
}

/// The ancestor chain (/, /home, /home/devcontainer, ...) of any allowed
/// read path is non sensitive by construction: the caller already can
/// see directory entries underneath, so the parent directory's
/// existence, owner, and mtime are trivially derivable. Permit stat on
/// these so shells, PATH lookups, and $HOME existence checks work
/// without leaving a path based existence oracle on unrelated paths.
fn is_stat_ancestor_of_allowed(path: &Path, allowed_read: &[PathBuf]) -> bool {
    allowed_read.iter().any(|root| root.starts_with(path))
}

/// Match /proc/*/mountinfo, /proc/*/mounts, /proc/*/mountstats, and
/// /proc/mounts. These files expose the caller's mount namespace and
/// reveal that devlock is sandboxing them.
fn is_proc_mount_leak(path: &Path) -> bool {
    if !path.starts_with("/proc") {
        return false;
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    matches!(name, "mountinfo" | "mounts" | "mountstats")
}

fn read_proc_path(pid: u32, ptr: u64) -> Option<PathBuf> {
    let f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    read_path_from_mem(&f, ptr)
}

fn read_path_from_mem(f: &std::fs::File, ptr: u64) -> Option<PathBuf> {
    let mut buf = [0u8; libc::PATH_MAX as usize];
    f.read_at(&mut buf, ptr).ok()?;
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len])))
}

fn read_proc_open_how(mem: &mut MemCache, pid: u32, ptr: u64, size: u64) -> io::Result<OpenHow> {
    if size < std::mem::size_of::<OpenHow>() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "open_how smaller than expected",
        ));
    }

    let mut buf = [0u8; std::mem::size_of::<OpenHow>()];
    mem.read_bytes(pid, ptr, &mut buf)
        .ok_or_else(|| io::Error::other("failed to read open_how"))?;

    let flags = u64::from_le_bytes(buf[0..8].try_into().unwrap_or([0u8; 8]));
    let mode = u64::from_le_bytes(buf[8..16].try_into().unwrap_or([0u8; 8]));
    let resolve = u64::from_le_bytes(buf[16..24].try_into().unwrap_or([0u8; 8]));

    Ok(OpenHow {
        flags,
        mode,
        _resolve: resolve,
    })
}

/// Resolve the final component of a supervisor-checked write path so an
/// attacker-planted symlink cannot redirect the kernel's actual write into a
/// path that the supervisor would otherwise reject (e.g. a read_only root).
///
/// Only run when there is at least one read_only root to guard and the leaf
/// is actually a symlink. The common case (no read_only list, or leaf is a
/// regular file or doesn't exist) falls through with a single lstat at
/// most, keeping the notified-syscall hot path cheap.
///
/// `canonicalize` handles the usual case where the symlink target exists.
/// For O_CREAT-style writes the target may not exist yet, so fall back to
/// `read_link` + lexical normalization so a symlink like `.git/HEAD` is
/// still resolved correctly.
#[allow(dead_code)]
fn resolve_write_leaf(path: &Path, read_only: &[PathBuf]) -> PathBuf {
    if read_only.is_empty() {
        return path.to_path_buf();
    }
    let lmeta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return path.to_path_buf(),
    };
    if !lmeta.file_type().is_symlink() {
        return path.to_path_buf();
    }
    if let Ok(canon) = std::fs::canonicalize(path) {
        return canon;
    }
    match std::fs::read_link(path) {
        Ok(target) => {
            let joined = if target.is_absolute() {
                target
            } else {
                path.parent().map(|p| p.join(&target)).unwrap_or(target)
            };
            normalize_lexical_path(&joined)
        }
        Err(_) => path.to_path_buf(),
    }
}

fn normalize_lexical_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();

    for component in path.components() {
        match component {
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop();
            }
            Component::Normal(part) => out.push(part),
            Component::Prefix(_) => {}
        }
    }

    if out.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        out
    }
}

fn is_write_open(flags: i32) -> bool {
    (flags as u32 & WRITE_FLAGS) != 0
}

fn resolve_path(pid: u32, dirfd: u64, path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    // AT_FDCWD (-100 as int) may arrive zero-extended (0x00000000FFFFFF9C) or
    // sign-extended (0xFFFFFFFFFFFFFF9C) depending on the syscall ABI and compiler.
    // Truncating to i32 gives -100 in both cases.
    let link = if dirfd as i32 == libc::AT_FDCWD {
        format!("/proc/{pid}/cwd")
    } else {
        format!("/proc/{pid}/fd/{dirfd}")
    };
    std::fs::read_link(&link).ok().map(|base| base.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    fn pb(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn recv_notify_fd_sets_cloexec_on_received_fd() {
        // Send a harmless fd (a pipe read end) through a socketpair
        // and confirm the receiver side comes back with FD_CLOEXEC
        // set. Covers the defence in depth against accidentally
        // leaking the notify fd to a post-install exec.
        let (parent_sock, child_sock) = UnixStream::pair().unwrap();
        let mut pipe = [0i32; 2];
        unsafe { assert_eq!(libc::pipe(pipe.as_mut_ptr()), 0) };
        let (r_fd, w_fd) = (pipe[0], pipe[1]);

        let parent_raw = parent_sock.as_raw_fd();
        send_notify_fd(child_sock.as_raw_fd(), r_fd).expect("sendmsg");
        let received = recv_notify_fd(parent_raw).expect("recvmsg");

        let flags = unsafe { libc::fcntl(received, libc::F_GETFD) };
        assert!(flags >= 0, "fcntl getfd failed");
        assert!(
            flags & libc::FD_CLOEXEC != 0,
            "received fd must be close on exec: flags={flags}"
        );

        unsafe {
            libc::close(received);
            libc::close(w_fd);
            libc::close(r_fd);
        }
        let _ = parent_sock.into_raw_fd();
        let _ = child_sock.into_raw_fd();
    }

    #[test]
    fn write_permitted_simple_allowed_root() {
        let allowed = vec![pb("/home/user/work")];
        assert!(is_write_permitted(
            &pb("/home/user/work/file.txt"),
            &allowed,
            &[]
        ));
        assert!(is_write_permitted(
            &pb("/home/user/work/nested/file"),
            &allowed,
            &[]
        ));
    }

    #[test]
    fn write_denied_outside_allowed() {
        let allowed = vec![pb("/home/user/work")];
        assert!(!is_write_permitted(&pb("/etc/passwd"), &allowed, &[]));
        assert!(!is_write_permitted(&pb("/home/user/other"), &allowed, &[]));
    }

    #[test]
    fn read_only_always_wins_over_allowed() {
        let allowed = vec![pb("/repo")];
        let read_only = vec![pb("/repo/.git/config")];
        assert!(!is_write_permitted(
            &pb("/repo/.git/config"),
            &allowed,
            &read_only
        ));
        assert!(!is_write_permitted(
            &pb("/repo/.git/config/nested"),
            &allowed,
            &read_only
        ));
        assert!(is_write_permitted(
            &pb("/repo/src/main.rs"),
            &allowed,
            &read_only
        ));
    }

    #[test]
    fn sibling_match_permits_temp_files() {
        let allowed = vec![pb("/a/foo.json")];
        assert!(is_write_permitted(
            &pb("/a/foo.json.tmp.123"),
            &allowed,
            &[]
        ));
        assert!(is_write_permitted(&pb("/a/foo.json.swp"), &allowed, &[]));
    }

    #[test]
    fn sibling_match_does_not_cross_directory() {
        let allowed = vec![pb("/a/foo.json")];
        assert!(!is_write_permitted(&pb("/b/foo.json.tmp"), &allowed, &[]));
        assert!(!is_write_permitted(&pb("/a/other.tmp"), &allowed, &[]));
    }

    #[test]
    fn sibling_match_requires_dot_in_allowed_leaf() {
        // When the allowed entry has no extension, the sibling clause
        // must not fire, otherwise a directory root like
        // /home/user/work could approve writes to /home/user/work.evil.
        let allowed = vec![pb("/a/foo")];
        assert!(!is_write_permitted(&pb("/a/foobar"), &allowed, &[]));
        assert!(!is_write_permitted(&pb("/a/foo.bar"), &allowed, &[]));
    }

    #[test]
    fn sibling_match_rejects_directory_root_namesakes() {
        // Canonical case for the bug: CWD or any directory allowed
        // root must not approve siblings with matching name prefix.
        let allowed = vec![pb("/home/user/work")];
        assert!(!is_write_permitted(
            &pb("/home/user/work.evil"),
            &allowed,
            &[]
        ));
        assert!(!is_write_permitted(
            &pb("/home/user/work.ssh"),
            &allowed,
            &[]
        ));
        // Writes inside the directory still go through the prefix match.
        assert!(is_write_permitted(
            &pb("/home/user/work/notes.md"),
            &allowed,
            &[]
        ));
    }

    #[test]
    fn sibling_match_respects_read_only_root() {
        let allowed = vec![pb("/repo/foo.json")];
        let read_only = vec![pb("/repo/.git/config")];
        assert!(!is_write_permitted(
            &pb("/repo/.git/config"),
            &allowed,
            &read_only
        ));
    }

    #[test]
    fn read_permitted_matches_any_allowed_root() {
        let reads = vec![pb("/usr"), pb("/etc"), pb("/home/user")];
        assert!(is_read_permitted(&pb("/usr/bin/zsh"), &reads));
        assert!(is_read_permitted(&pb("/etc/passwd"), &reads));
        assert!(!is_read_permitted(&pb("/var/log/syslog"), &reads));
    }

    #[test]
    fn lexical_normalize_drops_curdir_and_pops_parent() {
        assert_eq!(normalize_lexical_path(&pb("/a/./b/../c")), pb("/a/c"));
        assert_eq!(normalize_lexical_path(&pb("/a/b/../../../x")), pb("/x"));
        assert_eq!(normalize_lexical_path(&pb("/")), pb("/"));
        assert_eq!(normalize_lexical_path(&pb("/a")), pb("/a"));
    }

    #[test]
    fn path_traversal_cannot_escape_allowed_lexically() {
        let allowed = vec![pb("/a/b")];
        let attempt = normalize_lexical_path(&pb("/a/b/../../etc/passwd"));
        assert_eq!(attempt, pb("/etc/passwd"));
        assert!(!is_write_permitted(&attempt, &allowed, &[]));
    }

    #[test]
    fn read_only_parent_prefix_match_is_exact() {
        let read_only = vec![pb("/repo/.git")];
        assert!(!is_write_permitted(
            &pb("/repo/.git/HEAD"),
            &[pb("/repo")],
            &read_only
        ));
        // A sibling directory that merely shares a name prefix must not be
        // treated as the read_only root itself.
        assert!(is_write_permitted(
            &pb("/repo/.github/workflows/ci.yml"),
            &[pb("/repo")],
            &read_only
        ));
    }

    #[test]
    fn canonical_with_existing_ancestor_follows_intermediate_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        let probe = link.join("devlock_oracle_missing_xyz");
        let got = canonical_with_existing_ancestor(&probe).expect("resolve");
        assert_eq!(got, pb("/etc/devlock_oracle_missing_xyz"));
    }

    #[test]
    fn canonical_with_existing_ancestor_follows_dangling_leaf_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let escape = root.join("escape");
        std::os::unix::fs::symlink("/etc/devlock_oracle_probe", &escape).unwrap();
        let got = canonical_with_existing_ancestor(&escape).expect("resolve");
        assert_eq!(got, pb("/etc/devlock_oracle_probe"));
    }

    #[test]
    fn canonical_with_existing_ancestor_preserves_in_bucket_missing_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let probe = root.join("not_yet_created");
        let got = canonical_with_existing_ancestor(&probe).expect("resolve");
        assert_eq!(got, probe);
    }

    #[test]
    fn canonical_with_existing_ancestor_handles_root_and_missing_top() {
        assert_eq!(canonical_with_existing_ancestor(&pb("/")).unwrap(), pb("/"));
        assert_eq!(
            canonical_with_existing_ancestor(&pb("/devlock_no_such_top_xyz/a")).unwrap(),
            pb("/devlock_no_such_top_xyz/a")
        );
    }
}
