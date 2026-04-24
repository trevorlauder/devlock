//! Applies `restrict_proxy_worker` in process, then runs one named probe
//! and exits 0 on BLOCKED, 1 on ESCAPED. The proxy sandbox is an in process
//! landlock + seccomp shell, so the probe does not need a separate
//! supervisor the way the agent sandbox does.

use devlock::sandbox::proxy_restrict::restrict_proxy_worker;
use std::env;
use std::ffi::CString;
use std::net::TcpListener;
use std::ptr;
use tempfile::tempdir;

enum Outcome {
    Blocked(String),
    Escaped(String),
}

fn blocked(msg: impl Into<String>) -> Outcome {
    Outcome::Blocked(msg.into())
}

fn escaped(msg: impl Into<String>) -> Outcome {
    Outcome::Escaped(msg.into())
}

fn last_errno() -> String {
    let err = std::io::Error::last_os_error();
    format!("{err} (errno={})", err.raw_os_error().unwrap_or(0))
}

fn main() {
    let probe = env::args().nth(1).unwrap_or_default();
    // Capture the parent pid BEFORE restrict: after landlock's Scope::Signal
    // applies, getppid is still allowed (it reads task state, no signal sent),
    // but grabbing it here keeps the probe symmetric with the agent harness.
    let parent_pid = unsafe { libc::getppid() };

    let log_dir = tempdir().expect("log tempdir");
    restrict_proxy_worker(log_dir.path()).expect("restrict_proxy_worker");

    let outcome = match probe.as_str() {
        "fs_write_etc" => fs_write_etc(),
        "fs_write_tmp" => fs_write_tmp(),
        "fs_write_home" => fs_write_home(),
        "fs_create_in_etc" => fs_create_in_etc(),
        "net_bind_tcp" => net_bind_tcp(),
        "net_bind_inet6" => net_bind_inet6(),
        "sys_signal_parent" => sys_signal_parent(parent_pid),
        "sys_execve" => sys_execve(),
        "sys_unshare" => sys_unshare(),
        "sys_setns" => sys_setns(),
        "sys_chroot" => sys_chroot(),
        "sys_mount" => sys_mount(),
        "sys_pivot_root" => sys_pivot_root(),
        "sys_bpf" => sys_bpf(),
        "sys_io_uring_setup" => sys_io_uring_setup(),
        "sys_keyctl" => sys_keyctl(),
        "sys_add_key" => sys_add_key(),
        "sys_reboot" => sys_reboot(),
        "sys_init_module" => sys_init_module(),
        "sys_kexec_load" => sys_kexec_load(),
        "sys_setuid" => sys_setuid(),
        "sys_setgid" => sys_setgid(),
        "sys_setgroups" => sys_setgroups(),
        "sys_chmod" => sys_chmod(),
        "sys_chown" => sys_chown(),
        "sys_setxattr" => sys_setxattr(),
        "sys_inotify_init1" => sys_inotify_init1(),
        "sys_fanotify_init" => sys_fanotify_init(),
        "sys_ptrace" => sys_ptrace(),
        "sys_perf_event_open" => sys_perf_event_open(),
        "sys_userfaultfd" => sys_userfaultfd(),
        "sys_syslog" => sys_syslog(),
        "sys_uselib" => sys_uselib(),
        "sys_swapon" => sys_swapon(),
        "sys_process_vm_readv" => sys_process_vm_readv(),
        "sys_seccomp" => sys_seccomp(),
        "sys_landlock_restrict_self" => sys_landlock_restrict_self(),
        "net_socket_netlink" => net_socket_netlink(),
        "net_socket_packet" => net_socket_packet(),
        "net_socket_vsock" => net_socket_vsock(),
        "net_socket_bluetooth" => net_socket_bluetooth(),
        "net_socket_raw_inet" => net_socket_raw_inet(),
        "sys_pidfd_getfd" => sys_pidfd_getfd(),
        "caps_zeroed" => caps_zeroed(),
        "sys_tiocsti" => sys_tiocsti(),
        "sys_clone_newuser" => sys_clone_newuser(),
        "sys_clone3_newuser_inherits_filter" => sys_clone3_newuser_inherits_filter(),
        "sys_prctl_set_mm" => sys_prctl_set_mm(),
        other => {
            eprintln!("unknown probe: {other}");
            std::process::exit(2);
        }
    };

    match outcome {
        Outcome::Blocked(msg) => {
            println!("BLOCKED: {msg}");
            std::process::exit(0);
        }
        Outcome::Escaped(msg) => {
            println!("ESCAPED: {msg}");
            std::process::exit(1);
        }
    }
}

fn fs_write_etc() -> Outcome {
    match std::fs::OpenOptions::new().append(true).open("/etc/hosts") {
        Ok(_) => escaped("opened /etc/hosts for write"),
        Err(_) => blocked(format!("/etc/hosts write denied: {}", last_errno())),
    }
}

fn fs_write_tmp() -> Outcome {
    // /tmp itself is outside the proxy's landlock allow list. Only the
    // per session log dir (a subdir of /tmp) is writable.
    let path = "/tmp/devlock-proxy-escape-probe-outside-log";
    match std::fs::write(path, b"x") {
        Ok(()) => {
            let _ = std::fs::remove_file(path);
            escaped(format!("wrote outside log_dir at {path}"))
        }
        Err(_) => blocked(format!("/tmp write denied: {}", last_errno())),
    }
}

fn fs_write_home() -> Outcome {
    let home = sanitize_home();
    let path = home.join("devlock-proxy-escape-test");
    match std::fs::write(&path, b"x") {
        Ok(()) => {
            let _ = std::fs::remove_file(&path);
            escaped(format!("wrote {}", path.display()))
        }
        Err(_) => blocked(format!("{} write denied: {}", path.display(), last_errno())),
    }
}

/// Canonicalize $HOME and bound it to an allowlist of expected sandbox
/// locations. Falls back to /tmp if the env var is missing, unresolvable,
/// or points outside the allowlist. CodeQL recognizes canonicalize +
/// starts_with as a sanitizer for rust/path-injection.
fn sanitize_home() -> std::path::PathBuf {
    use std::path::{Path, PathBuf};
    let raw = env::var("HOME").unwrap_or_else(|_| "/home".into());
    let canonical = std::fs::canonicalize(&raw).unwrap_or_else(|_| PathBuf::from("/tmp"));
    for root in [
        Path::new("/home"),
        Path::new("/root"),
        Path::new("/tmp"),
        Path::new("/var/tmp"),
        Path::new("/workspace"),
    ] {
        if canonical.starts_with(root) {
            return canonical;
        }
    }
    PathBuf::from("/tmp")
}

fn fs_create_in_etc() -> Outcome {
    // MakeReg under /etc must be refused even though /etc is in the
    // read_only allow root. Landlock's read_only access mask omits
    // MakeReg / WriteFile / Truncate.
    let path = "/etc/devlock-proxy-escape-probe";
    match std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(path);
            escaped(format!("created {path}"))
        }
        Err(_) => blocked(format!("/etc file creation denied: {}", last_errno())),
    }
}

fn net_bind_tcp() -> Outcome {
    // AccessNet::BindTcp is declared with no NetPort rules, the landlock
    // idiom for "deny every TCP bind". The production listeners were bound
    // by the supervisor before fork and inherited as already bound fds.
    match TcpListener::bind("127.0.0.1:0") {
        Ok(_) => escaped("TCP bind accepted"),
        Err(_) => blocked(format!("TCP bind denied: {}", last_errno())),
    }
}

fn net_bind_inet6() -> Outcome {
    match TcpListener::bind("[::1]:0") {
        Ok(_) => escaped("TCP6 bind accepted"),
        Err(_) => blocked(format!("TCP6 bind denied: {}", last_errno())),
    }
}

fn sys_signal_parent(parent_pid: libc::pid_t) -> Outcome {
    // Scope::Signal denies cross domain signals. The test runner is outside
    // the proxy landlock domain, so kill(ppid, 0) must return EPERM.
    let r = unsafe { libc::kill(parent_pid, 0) };
    if r == 0 {
        escaped(format!("kill({parent_pid}, 0) accepted"))
    } else {
        blocked(format!("kill to parent denied: {}", last_errno()))
    }
}

fn sys_execve() -> Outcome {
    let path = CString::new("/bin/true").unwrap();
    let argv: [*const libc::c_char; 2] = [path.as_ptr(), ptr::null()];
    let envp: [*const libc::c_char; 1] = [ptr::null()];
    let r = unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    if r == 0 {
        escaped("execve returned 0")
    } else {
        blocked(format!("execve denied: {}", last_errno()))
    }
}

fn sys_unshare() -> Outcome {
    let r = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
    if r == 0 {
        escaped("unshare accepted")
    } else {
        blocked(format!("unshare denied: {}", last_errno()))
    }
}

fn sys_setns() -> Outcome {
    let r = unsafe { libc::setns(-1, 0) };
    if r == 0 {
        escaped("setns accepted")
    } else {
        blocked(format!("setns denied: {}", last_errno()))
    }
}

fn sys_chroot() -> Outcome {
    let p = CString::new(".").unwrap();
    let r = unsafe { libc::chroot(p.as_ptr()) };
    if r == 0 {
        escaped("chroot accepted")
    } else {
        blocked(format!("chroot denied: {}", last_errno()))
    }
}

fn sys_mount() -> Outcome {
    let src = CString::new("none").unwrap();
    let tgt = CString::new("/mnt").unwrap();
    let fs = CString::new("tmpfs").unwrap();
    let r = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fs.as_ptr(), 0, ptr::null()) };
    if r == 0 {
        escaped("mount accepted")
    } else {
        blocked(format!("mount denied: {}", last_errno()))
    }
}

fn sys_pivot_root() -> Outcome {
    let a = CString::new(".").unwrap();
    let b = CString::new(".").unwrap();
    let r = unsafe { libc::syscall(libc::SYS_pivot_root, a.as_ptr(), b.as_ptr()) };
    if r == 0 {
        escaped("pivot_root accepted")
    } else {
        blocked(format!("pivot_root denied: {}", last_errno()))
    }
}

fn sys_bpf() -> Outcome {
    let r = unsafe { libc::syscall(libc::SYS_bpf, 0, 0, 0) };
    if r >= 0 {
        escaped(format!("bpf returned {r}"))
    } else {
        blocked(format!("bpf denied: {}", last_errno()))
    }
}

fn sys_io_uring_setup() -> Outcome {
    let mut params = [0u8; 120];
    let r = unsafe { libc::syscall(425, 8i64, params.as_mut_ptr()) };
    if r >= 0 {
        unsafe { libc::close(r as i32) };
        escaped("io_uring_setup accepted")
    } else {
        blocked(format!("io_uring_setup denied: {}", last_errno()))
    }
}

fn sys_keyctl() -> Outcome {
    let r = unsafe { libc::syscall(libc::SYS_keyctl, 0i32, -3i32, 1i32) };
    if r >= 0 {
        escaped(format!("keyctl returned {r}"))
    } else {
        blocked(format!("keyctl denied: {}", last_errno()))
    }
}

fn sys_add_key() -> Outcome {
    let kind = CString::new("user").unwrap();
    let desc = CString::new("devlock-probe").unwrap();
    let payload = b"x";
    let r = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            kind.as_ptr(),
            desc.as_ptr(),
            payload.as_ptr() as *const libc::c_void,
            payload.len(),
            -3i32,
        )
    };
    if r >= 0 {
        escaped(format!("add_key returned {r}"))
    } else {
        blocked(format!("add_key denied: {}", last_errno()))
    }
}

fn sys_reboot() -> Outcome {
    let r = unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_CAD_OFF) };
    if r == 0 {
        escaped("reboot accepted")
    } else {
        blocked(format!("reboot denied: {}", last_errno()))
    }
}

fn sys_init_module() -> Outcome {
    let r = unsafe { libc::syscall(libc::SYS_init_module, ptr::null::<u8>(), 0u64, c"".as_ptr()) };
    if r == 0 {
        escaped("init_module accepted")
    } else {
        blocked(format!("init_module denied: {}", last_errno()))
    }
}

fn sys_kexec_load() -> Outcome {
    let r = unsafe { libc::syscall(libc::SYS_kexec_load, 0u64, 0u64, ptr::null::<u8>(), 0u64) };
    if r == 0 {
        escaped("kexec_load accepted")
    } else {
        blocked(format!("kexec_load denied: {}", last_errno()))
    }
}

fn sys_setuid() -> Outcome {
    let r = unsafe { libc::setuid(0) };
    if r == 0 {
        escaped("setuid(0) accepted")
    } else {
        blocked(format!("setuid denied: {}", last_errno()))
    }
}

fn sys_setgid() -> Outcome {
    let r = unsafe { libc::setgid(0) };
    if r == 0 {
        escaped("setgid(0) accepted")
    } else {
        blocked(format!("setgid denied: {}", last_errno()))
    }
}

fn sys_setgroups() -> Outcome {
    let groups: [libc::gid_t; 1] = [0];
    let r = unsafe { libc::setgroups(groups.len(), groups.as_ptr()) };
    if r == 0 {
        escaped("setgroups accepted")
    } else {
        blocked(format!("setgroups denied: {}", last_errno()))
    }
}

fn sys_chmod() -> Outcome {
    let p = CString::new("/etc/hosts").unwrap();
    let r = unsafe { libc::chmod(p.as_ptr(), 0o777) };
    if r == 0 {
        escaped("chmod /etc/hosts accepted")
    } else {
        blocked(format!("chmod denied: {}", last_errno()))
    }
}

fn sys_chown() -> Outcome {
    let p = CString::new("/etc/hosts").unwrap();
    let r = unsafe { libc::chown(p.as_ptr(), 0, 0) };
    if r == 0 {
        escaped("chown /etc/hosts accepted")
    } else {
        blocked(format!("chown denied: {}", last_errno()))
    }
}

fn sys_setxattr() -> Outcome {
    let path = CString::new("/etc/hosts").unwrap();
    let name = CString::new("user.devlock.probe").unwrap();
    let value = b"x";
    let r = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    if r == 0 {
        escaped("setxattr accepted")
    } else {
        blocked(format!("setxattr denied: {}", last_errno()))
    }
}

fn sys_inotify_init1() -> Outcome {
    let r = unsafe { libc::inotify_init1(0) };
    if r >= 0 {
        unsafe { libc::close(r) };
        escaped("inotify_init1 accepted")
    } else {
        blocked(format!("inotify_init1 denied: {}", last_errno()))
    }
}

fn sys_fanotify_init() -> Outcome {
    let r = unsafe { libc::syscall(libc::SYS_fanotify_init, 0u32, 0u32) };
    if r >= 0 {
        unsafe { libc::close(r as i32) };
        escaped("fanotify_init accepted")
    } else {
        blocked(format!("fanotify_init denied: {}", last_errno()))
    }
}

fn sys_ptrace() -> Outcome {
    const PTRACE_TRACEME: libc::c_uint = 0;
    let r = unsafe {
        libc::ptrace(
            PTRACE_TRACEME,
            0,
            ptr::null_mut::<libc::c_void>(),
            ptr::null_mut::<libc::c_void>(),
        )
    };
    if r == 0 {
        escaped("ptrace accepted")
    } else {
        blocked(format!("ptrace denied: {}", last_errno()))
    }
}

fn sys_perf_event_open() -> Outcome {
    let mut attr = [0u64; 16];
    let r = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            attr.as_mut_ptr(),
            0i32,
            -1i32,
            -1i32,
            0u64,
        )
    };
    if r >= 0 {
        unsafe { libc::close(r as i32) };
        escaped("perf_event_open accepted")
    } else {
        blocked(format!("perf_event_open denied: {}", last_errno()))
    }
}

fn sys_userfaultfd() -> Outcome {
    let r = unsafe { libc::syscall(libc::SYS_userfaultfd, 0) };
    if r >= 0 {
        unsafe { libc::close(r as i32) };
        escaped("userfaultfd accepted")
    } else {
        blocked(format!("userfaultfd denied: {}", last_errno()))
    }
}

fn sys_syslog() -> Outcome {
    let r = unsafe { libc::syscall(libc::SYS_syslog, 10i32, ptr::null::<u8>(), 0i32) };
    if r >= 0 {
        escaped(format!("syslog returned {r}"))
    } else {
        blocked(format!("syslog denied: {}", last_errno()))
    }
}

fn sys_uselib() -> Outcome {
    // uselib is obsolete and explicitly on the deny list. Skipped on
    // architectures where libseccomp cannot resolve the name.
    let path = CString::new("/nonexistent").unwrap();
    let r = unsafe { libc::syscall(134, path.as_ptr()) };
    if r == 0 {
        escaped("uselib accepted")
    } else {
        blocked(format!("uselib denied: {}", last_errno()))
    }
}

fn sys_swapon() -> Outcome {
    let p = CString::new("/nonexistent").unwrap();
    let r = unsafe { libc::swapon(p.as_ptr(), 0) };
    if r == 0 {
        escaped("swapon accepted")
    } else {
        blocked(format!("swapon denied: {}", last_errno()))
    }
}

fn sys_process_vm_readv() -> Outcome {
    let r = unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            1i32,
            ptr::null::<libc::iovec>(),
            0u64,
            ptr::null::<libc::iovec>(),
            0u64,
            0u64,
        )
    };
    if r >= 0 {
        escaped(format!("process_vm_readv returned {r}"))
    } else {
        blocked(format!("process_vm_readv denied: {}", last_errno()))
    }
}

fn sys_seccomp() -> Outcome {
    let r = unsafe { libc::syscall(libc::SYS_seccomp, 0u32, 0u32, ptr::null::<u8>()) };
    if r == 0 {
        escaped("seccomp syscall accepted (filter re entered)")
    } else {
        blocked(format!("seccomp syscall denied: {}", last_errno()))
    }
}

fn sys_landlock_restrict_self() -> Outcome {
    // Unconditional deny in the proxy filter. A successful return would
    // mean the proxy can add its own ruleset on top and hypothetically
    // widen itself (landlock access cannot widen in practice, but the
    // filter denies entry anyway).
    let r = unsafe { libc::syscall(445, -1i32, 0u32) };
    if r == 0 {
        escaped("landlock_restrict_self accepted")
    } else {
        blocked(format!("landlock_restrict_self denied: {}", last_errno()))
    }
}

fn net_socket_netlink() -> Outcome {
    let r = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 0) };
    if r >= 0 {
        unsafe { libc::close(r) };
        escaped("AF_NETLINK socket created")
    } else {
        blocked(format!("netlink socket denied: {}", last_errno()))
    }
}

fn net_socket_packet() -> Outcome {
    let r = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    if r >= 0 {
        unsafe { libc::close(r) };
        escaped("AF_PACKET socket created")
    } else {
        blocked(format!("packet socket denied: {}", last_errno()))
    }
}

fn net_socket_vsock() -> Outcome {
    let r = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if r >= 0 {
        unsafe { libc::close(r) };
        escaped("AF_VSOCK socket created")
    } else {
        blocked(format!("vsock socket denied: {}", last_errno()))
    }
}

fn net_socket_bluetooth() -> Outcome {
    let r = unsafe { libc::socket(libc::AF_BLUETOOTH, libc::SOCK_RAW, 0) };
    if r >= 0 {
        unsafe { libc::close(r) };
        escaped("AF_BLUETOOTH socket created")
    } else {
        blocked(format!("bluetooth socket denied: {}", last_errno()))
    }
}

fn caps_zeroed() -> Outcome {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

    let hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(), CapData::default()];
    let r = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &hdr as *const CapHeader,
            data.as_mut_ptr(),
        )
    };
    if r != 0 {
        return escaped(format!("capget failed: {}", last_errno()));
    }
    let nonzero = data
        .iter()
        .any(|d| d.effective != 0 || d.permitted != 0 || d.inheritable != 0);
    if nonzero {
        escaped(format!(
            "residual caps: eff={:08x}{:08x} prm={:08x}{:08x} inh={:08x}{:08x}",
            data[1].effective,
            data[0].effective,
            data[1].permitted,
            data[0].permitted,
            data[1].inheritable,
            data[0].inheritable,
        ))
    } else {
        blocked("all caps zero")
    }
}

fn sys_pidfd_getfd() -> Outcome {
    // Hit the syscall with any fds; seccomp filters on the nr, not args.
    const SYS_PIDFD_GETFD: libc::c_long = 438;
    let r = unsafe { libc::syscall(SYS_PIDFD_GETFD, -1i32, -1i32, 0u32) };
    if r >= 0 {
        unsafe { libc::close(r as i32) };
        escaped("pidfd_getfd accepted")
    } else {
        blocked(format!("pidfd_getfd denied: {}", last_errno()))
    }
}

fn net_socket_raw_inet() -> Outcome {
    // Assert EAFNOSUPPORT (from the filter) rather than EACCES (from
    // CAP_NET_RAW) so a missing filter rule fails the test.
    let r = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if r >= 0 {
        unsafe { libc::close(r) };
        return escaped("AF_INET SOCK_RAW socket created");
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if errno == libc::EAFNOSUPPORT {
        blocked(format!("raw socket: EAFNOSUPPORT (seccomp), errno={errno}"))
    } else {
        escaped(format!(
            "raw socket denied but not by seccomp (expected EAFNOSUPPORT, got errno={errno})"
        ))
    }
}

fn sys_tiocsti() -> Outcome {
    const TIOCSTI: libc::c_ulong = 0x5412;
    let c: u8 = b'x';
    let r = unsafe { libc::ioctl(0, TIOCSTI, &c as *const u8) };
    if r == 0 {
        escaped("TIOCSTI accepted")
    } else {
        blocked(format!("TIOCSTI denied: {}", last_errno()))
    }
}

fn sys_clone_newuser() -> Outcome {
    // Legacy clone() with CLONE_NEWUSER. The proxy seccomp filter has a
    // masked equality rule on the flags arg to catch any CLONE_NEW* bit.
    let r = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::CLONE_NEWUSER as u64 | libc::SIGCHLD as u64,
            0u64,
            0u64,
            0u64,
            0u64,
        )
    };
    if r == 0 {
        unsafe { libc::_exit(0) };
    }
    if r > 0 {
        let mut status = 0;
        unsafe { libc::waitpid(r as i32, &mut status, 0) };
        escaped("clone(CLONE_NEWUSER) accepted")
    } else {
        blocked(format!("clone denied: {}", last_errno()))
    }
}

/// Regression for the documented exception in
/// src/sandbox/proxy_restrict.rs: libseccomp cannot filter clone3 by
/// flags (the flags live in a userspace struct), so clone3 is allowed.
/// The comment argues that a clone3(CLONE_NEWUSER) child still inherits
/// the seccomp filter and so cannot reach mount, bpf, or unshare. This
/// probe enforces that claim.
fn sys_clone3_newuser_inherits_filter() -> Outcome {
    // Minimal clone3 args. Layout matches the kernel struct clone_args
    // (flags, pidfd, child_tid, parent_tid, exit_signal, stack,
    // stack_size, tls). u64 each, 64 bytes total for v0 size.
    #[repr(C)]
    struct CloneArgs {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
    }
    let args = CloneArgs {
        flags: libc::CLONE_NEWUSER as u64,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
    };
    const SYS_CLONE3: libc::c_long = 435;
    let r = unsafe {
        libc::syscall(
            SYS_CLONE3,
            &args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if r < 0 {
        // clone3 itself was denied. Different from the case the
        // regression targets, but still not an escape.
        return blocked(format!("clone3 denied: {}", last_errno()));
    }
    if r == 0 {
        // Child. Attempt each blocked syscall. Exit with a code that
        // lets the parent identify which call leaked.
        let src = CString::new("none").unwrap();
        let tgt = CString::new("/mnt").unwrap();
        let fs = CString::new("tmpfs").unwrap();
        if unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fs.as_ptr(), 0, ptr::null()) } == 0 {
            unsafe { libc::_exit(10) };
        }
        if unsafe { libc::syscall(libc::SYS_bpf, 0, 0, 0) } >= 0 {
            unsafe { libc::_exit(20) };
        }
        if unsafe { libc::unshare(libc::CLONE_NEWNS) } == 0 {
            unsafe { libc::_exit(30) };
        }
        unsafe { libc::_exit(0) };
    }
    // Parent.
    let mut status = 0;
    unsafe { libc::waitpid(r as i32, &mut status, 0) };
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    match code {
        0 => blocked("clone3(CLONE_NEWUSER) child could not mount, bpf, or unshare (EPERM)"),
        10 => escaped("clone3 child: mount accepted"),
        20 => escaped("clone3 child: bpf accepted"),
        30 => escaped("clone3 child: unshare accepted"),
        other => escaped(format!("clone3 child exited abnormally: {other}")),
    }
}

fn sys_prctl_set_mm() -> Outcome {
    const PR_SET_MM: i32 = 35;
    // arg2 = PR_SET_MM_START_CODE (1), arg3 = garbage. The kernel rejects
    // with EINVAL / EPERM on success; the filter rejects with EPERM
    // before the kernel sees it.
    let r = unsafe { libc::prctl(PR_SET_MM, 1, 0, 0, 0) };
    if r == 0 {
        escaped("prctl PR_SET_MM accepted")
    } else {
        blocked(format!("prctl PR_SET_MM denied: {}", last_errno()))
    }
}
