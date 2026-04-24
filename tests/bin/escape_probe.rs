//! Runs one named escape probe and exits 0 when the kernel blocked it, 1
//! when it succeeded, 2 when the probe name is not recognised.

use std::env;
use std::ffi::CString;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::ptr;

/// Canonicalize a raw base path from an env var and confirm it resolves
/// into one of the expected sandbox roots. Falls back to `/tmp` if the
/// raw path is missing, unresolvable, or outside every allowlisted root.
/// CodeQL recognizes canonicalize + starts_with as a path-injection
/// sanitizer, which clears this binary's flow from `env::var` to file
/// operations.
fn sanitize_probe_base(raw: &str) -> PathBuf {
    let canonical = std::fs::canonicalize(raw).unwrap_or_else(|_| PathBuf::from("/tmp"));
    const ALLOWED: &[&str] = &[
        "/tmp",
        "/var/tmp",
        "/home",
        "/root",
        "/workspace",
        "/dev/shm",
        "/run",
        "/private/tmp",
        "/private/var",
    ];
    for root in ALLOWED {
        if canonical.starts_with(root) {
            return canonical;
        }
    }
    PathBuf::from("/tmp")
}

fn probe_home() -> PathBuf {
    sanitize_probe_base(&env::var("HOME").unwrap_or_else(|_| "/root".into()))
}

fn probe_tmp() -> PathBuf {
    sanitize_probe_base(&env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into()))
}

fn probe_cwd() -> PathBuf {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    sanitize_probe_base(&cwd.to_string_lossy())
}

/// Panic if `suffix` contains a traversal, separator, or absolute prefix.
/// Every join target in this binary is a hard-coded literal, so a panic
/// here is a programming error rather than an attack surface.
fn probe_join(base: &Path, suffix: &str) -> PathBuf {
    assert!(!suffix.is_empty(), "probe_join: empty suffix");
    for comp in Path::new(suffix).components() {
        assert!(
            !matches!(
                comp,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            ),
            "probe_join: suffix {suffix:?} escapes its parent"
        );
    }
    base.join(suffix)
}

fn main() {
    let probe = env::args().nth(1).unwrap_or_default();
    let outcome = match probe.as_str() {
        "fs_write_etc" => fs_write_etc(),
        "fs_read_shadow" => fs_read_shadow(),
        "fs_stat_shadow" => fs_stat_shadow(),
        "fs_stat_vscode_server" => fs_stat_vscode_server(),
        "fs_write_home_root" => fs_write_home_root(),
        "fs_symlink_to_shadow" => fs_symlink_to_shadow(),
        "fs_proc_self_root" => fs_proc_self_root(),
        "fs_symlink_to_mountinfo" => fs_symlink_to_mountinfo(),
        "fs_hardlink_passwd" => fs_hardlink_etc_entry(),
        "fs_write_vscode_tasks" => fs_write_vscode_tasks(),
        "sys_ptrace_traceme" => sys_ptrace_traceme(),
        "sys_unshare_newuser" => sys_unshare_newuser(),
        "sys_bpf" => sys_bpf(),
        "sys_memfd_exec" => sys_memfd_exec(),
        "sys_io_uring_setup" => sys_io_uring_setup(),
        "sys_mount" => sys_mount(),
        "sys_mount_setattr" => sys_mount_setattr_probe(),
        "sys_pidfd_open" => sys_pidfd_open(),
        "sys_fsopen" => sys_fsopen(),
        "sys_userfaultfd" => sys_userfaultfd(),
        "sys_perf_event_open" => sys_perf_event_open(),
        "sys_keyctl" => sys_keyctl(),
        "sys_chroot" => sys_chroot(),
        "sys_tiocsti" => sys_tiocsti(),
        "sys_tiocsti_high_bits" => sys_tiocsti_high_bits(),
        "net_raw_socket" => net_raw_socket(),
        "net_udp_socket" => net_udp_socket(),
        "net_netlink_socket" => net_netlink_socket(),
        "net_packet_socket" => net_packet_socket(),
        "net_vsock_socket" => net_vsock_socket(),
        "net_connect_external" => net_connect_external(),
        "net_bind_inet" => net_bind_inet(),
        "proc_parent_environ" => proc_parent_environ(),
        "env_no_secrets" => env_absence_check(),
        "fs_write_proc_self_mem" => fs_write_proc_self_mem(),
        "fs_rename_out_of_cwd" => fs_rename_out_of_cwd(),
        "sys_clone3_newuser" => sys_clone3_newuser(),
        "net_af_unix_fs_bind" => net_af_unix_fs_bind(),
        "net_af_unix_fs_bind_outside_allowed" => net_af_unix_fs_bind_outside_allowed(),
        "exec_from_sandbox_tmp" => exec_from_sandbox_tmp(),
        "sys_ptrace_attach_parent" => sys_ptrace_attach_parent(),
        "sys_clone_newuser" => sys_clone_newuser(),
        "sys_setxattr_on_etc" => sys_setxattr_on_etc(),
        "fs_write_via_fchmod" => fs_write_via_fchmod(),
        "sys_swapon" => sys_swapon(),
        "sys_reboot" => sys_reboot(),
        "sys_init_module" => sys_init_module(),
        "fs_write_to_read_only_dir" => fs_write_to_read_only_dir(),
        "fs_symlink_into_read_only_dir" => fs_symlink_into_read_only_dir(),
        "fs_truncate_via_symlink_into_read_only" => fs_truncate_via_symlink_into_read_only(),
        "sys_notify_id_invalidation_race" => sys_notify_id_invalidation_race(),
        "fs_unlink_read_only_file" => fs_unlink_read_only_file(),
        "fs_rename_over_read_only_file" => fs_rename_over_read_only_file(),
        "fs_toctou_symlink_swap_open" => fs_toctou_symlink_swap_open(),
        "fs_toctou_rename_swap" => fs_toctou_rename_swap(),
        "fs_openat2_resolve_beneath_bypass" => fs_openat2_resolve_beneath_bypass(),
        "fs_symlinkat_into_read_only" => fs_symlinkat_into_read_only(),
        "fs_linkat_over_read_only" => fs_linkat_over_read_only(),
        "fs_rename_out_of_read_only" => fs_rename_out_of_read_only(),
        "fs_utimensat_writable_path" => fs_utimensat_writable_path(),
        "fs_futimens_writable_fd" => fs_futimens_writable_fd(),
        "fs_faccessat2_existence_leak" => fs_faccessat2_existence_leak(),
        "fs_faccessat_existence_leak" => fs_faccessat_existence_leak(),
        "fs_inotify_add_watch_existence_leak" => fs_inotify_add_watch_existence_leak(),
        "fs_open_existence_leak" => fs_open_existence_leak(),
        "sys_signal_root_sandbox_pid" => sys_signal_root_sandbox_pid(),
        "fs_stat_root_allowed" => fs_stat_root_allowed(),
        "fs_stat_home_ancestor_allowed" => fs_stat_home_ancestor_allowed(),
        "fs_stat_etc_ancestor_allowed" => fs_stat_etc_ancestor_allowed(),
        "net_af_unix_abstract_bind" => net_af_unix_abstract_bind(),
        "net_af_unix_abstract_connect" => net_af_unix_abstract_connect(),
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

fn last_errno_desc() -> String {
    let err = std::io::Error::last_os_error();
    format!("{err} (errno={})", err.raw_os_error().unwrap_or(0))
}

fn fs_write_etc() -> Outcome {
    match std::fs::OpenOptions::new().append(true).open("/etc/hosts") {
        Ok(mut f) => match f.write_all(b"\n") {
            Ok(()) => escaped("wrote byte to /etc/hosts"),
            Err(e) => blocked(format!("write failed: {e}")),
        },
        Err(e) => blocked(format!("open /etc/hosts: {e}")),
    }
}

fn fs_read_shadow() -> Outcome {
    match std::fs::read_to_string("/etc/shadow") {
        Ok(c) if !c.is_empty() => escaped("read /etc/shadow contents"),
        Ok(_) => blocked("open succeeded but read returned empty"),
        Err(e) => blocked(format!("open /etc/shadow: {e}")),
    }
}

fn fs_stat_shadow() -> Outcome {
    // Landlock has no GetAttr bit, so statx() on /etc/shadow would return
    // real inode metadata unless the supervisor intercepts the call.
    match std::fs::metadata("/etc/shadow") {
        Ok(_) => escaped("statx /etc/shadow leaked metadata"),
        Err(e) => blocked(format!("stat /etc/shadow: {e}")),
    }
}

fn fs_stat_vscode_server() -> Outcome {
    // Before the hardcoded $HOME grant was removed, $HOME/.vscode-server
    // was listable. Stat should now be denied because $HOME itself is
    // not in any bucket for the test agent.
    let home = probe_home();
    let target = probe_join(&home, ".vscode-server");
    match std::fs::metadata(&target) {
        Ok(_) => escaped(format!("stat {} leaked metadata", target.display())),
        Err(e) => blocked(format!("stat {}: {e}", target.display())),
    }
}

fn fs_write_home_root() -> Outcome {
    let home = probe_home();
    let path = probe_join(&home, ".devlock_escape_marker");
    match std::fs::write(&path, b"x") {
        Ok(()) => {
            let _ = std::fs::remove_file(&path);
            escaped("wrote to HOME root")
        }
        Err(e) => blocked(format!("write HOME: {e}")),
    }
}

fn fs_symlink_to_shadow() -> Outcome {
    let link = Path::new("./devlock_shadow_link");
    if let Err(e) = std::os::unix::fs::symlink("/etc/shadow", link) {
        return blocked(format!("symlink denied: {e}"));
    }
    let outcome = match std::fs::read_to_string(link) {
        Ok(c) if !c.is_empty() => escaped("read /etc/shadow through symlink"),
        Ok(_) => blocked("symlink read empty"),
        Err(e) => blocked(format!("symlink read: {e}")),
    };
    let _ = std::fs::remove_file(link);
    outcome
}

fn fs_proc_self_root() -> Outcome {
    match std::fs::read_to_string("/proc/self/root/etc/shadow") {
        Ok(c) if !c.is_empty() => escaped("read shadow via /proc/self/root"),
        Ok(_) => blocked("open succeeded but read empty"),
        Err(e) => blocked(format!("deny: {e}")),
    }
}

fn fs_symlink_to_mountinfo() -> Outcome {
    // Attacker pattern: make a symlink in an allowed dir pointing at
    // /proc/self/mountinfo, then read through it. The supervisor must
    // resolve the leaf and apply is_proc_mount_leak on the canonical
    // path, not just the lexical one (which sits under an allowed_read
    // root and would otherwise pass the fast path).
    let cwd = probe_cwd();
    let link = probe_join(&cwd, ".redteam-mountinfo-link");
    let _ = std::fs::remove_file(&link);
    if let Err(e) = std::os::unix::fs::symlink("/proc/self/mountinfo", &link) {
        return blocked(format!("symlink creation denied: {e}"));
    }
    let result = std::fs::read_to_string(&link);
    let _ = std::fs::remove_file(&link);
    match result {
        Ok(c) if c.contains(" / ") || c.contains(" - ") => {
            escaped(format!("read mountinfo via symlink ({} bytes)", c.len()))
        }
        Ok(_) => blocked("read succeeded but empty"),
        Err(e) => blocked(format!("read via symlink denied: {e}")),
    }
}

fn fs_write_to_read_only_dir() -> Outcome {
    // The test runner lists $TMPDIR/read_only_dir under `read_only_enforced`.
    // A read_only directory must reject every write underneath, including
    // O_CREAT of a new file. Supervisor does this lexically in
    // is_write_permitted even when the parent is a full_access bucket.
    let tmpdir = probe_tmp();
    let target = probe_join(&probe_join(&tmpdir, "read_only_dir"), "HEAD");
    match std::fs::write(&target, b"x") {
        Ok(()) => {
            let _ = std::fs::remove_file(&target);
            escaped(format!("wrote to read_only path {}", target.display()))
        }
        Err(e) => blocked(format!("write denied: {e}")),
    }
}

fn fs_symlink_into_read_only_dir() -> Outcome {
    let tmpdir = probe_tmp();
    let target = probe_join(&probe_join(&tmpdir, "read_only_dir"), "HEAD");
    let cwd = probe_cwd();
    let link = probe_join(&cwd, ".redteam-sym-to-read-only");
    let _ = std::fs::remove_file(&link);
    if let Err(e) = std::os::unix::fs::symlink(&target, &link) {
        return blocked(format!("symlink creation denied: {e}"));
    }
    let result = std::fs::write(&link, b"pwned");
    let _ = std::fs::remove_file(&link);
    match result {
        Ok(()) => escaped(format!(
            "wrote to read_only file {} via symlink",
            target.display()
        )),
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(0);
            if errno == libc::EXDEV {
                return escaped(format!("misleading EXDEV for symlink into read_only: {e}"));
            }
            blocked(format!("write via symlink denied: {e} (errno={errno})"))
        }
    }
}

fn fs_truncate_via_symlink_into_read_only() -> Outcome {
    // truncate(2) follows leaf symlinks. Same pattern as above: place a
    // symlink in the allowed CWD pointing at a read_only-protected file
    // and call truncate on the symlink path. Supervisor must resolve
    // the leaf and reject.
    let tmpdir = probe_tmp();
    let target = probe_join(&probe_join(&tmpdir, "read_only_dir"), "HEAD");
    let cwd = probe_cwd();
    let link = probe_join(&cwd, ".redteam-trunc-sym");
    let _ = std::fs::remove_file(&link);
    if let Err(e) = std::os::unix::fs::symlink(&target, &link) {
        return blocked(format!("symlink creation denied: {e}"));
    }
    let c_path = CString::new(link.to_string_lossy().into_owned()).unwrap();
    let rc = unsafe { libc::truncate(c_path.as_ptr(), 0) };
    let _ = std::fs::remove_file(&link);
    if rc == 0 {
        escaped(format!(
            "truncated read_only file {} via symlink",
            target.display()
        ))
    } else {
        blocked(format!(
            "truncate via symlink denied: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn fs_hardlink_etc_entry() -> Outcome {
    let link = Path::new("./devlock_hardlink_probe");
    match std::fs::hard_link("/etc/passwd", link) {
        Ok(()) => {
            let _ = std::fs::remove_file(link);
            escaped("created hardlink to protected /etc entry in CWD")
        }
        Err(e) => blocked(format!("hardlink denied: {e}")),
    }
}

fn fs_write_vscode_tasks() -> Outcome {
    // default profile protects .vscode/tasks.json because VS Code task
    // execution happens outside the sandbox when a developer runs tasks.
    let cwd = probe_cwd();
    let vscode = probe_join(&cwd, ".vscode");
    if let Err(e) = std::fs::create_dir_all(&vscode) {
        return blocked(format!("could not prepare .vscode dir: {e}"));
    }
    let target = probe_join(&vscode, "tasks.json");
    match std::fs::write(&target, b"{\"version\":\"2.0.0\",\"tasks\":[]}\n") {
        Ok(()) => {
            let _ = std::fs::remove_file(&target);
            escaped(format!(
                "wrote protected VS Code task file {}",
                target.display()
            ))
        }
        Err(e) => blocked(format!("write denied: {e}")),
    }
}

fn sys_ptrace_traceme() -> Outcome {
    // PTRACE_TRACEME is allowed by policy: it lets the agent request to
    // be traced by its parent, which is what gdb --args and rr record
    // need. A *successful* return here is the expected outcome. The
    // broader ptrace block still applies to PTRACE_ATTACH and friends
    // (see sys_ptrace_attach_parent).
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
        blocked("PTRACE_TRACEME allowed as expected")
    } else {
        escaped(format!(
            "PTRACE_TRACEME rejected unexpectedly: {}",
            last_errno_desc()
        ))
    }
}

fn sys_unshare_newuser() -> Outcome {
    let r = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
    if r == 0 {
        escaped("unshare(CLONE_NEWUSER) succeeded")
    } else {
        blocked(format!("unshare: {}", last_errno_desc()))
    }
}

fn sys_bpf() -> Outcome {
    let r = unsafe { libc::syscall(libc::SYS_bpf, 0, 0, 0) };
    if r >= 0 {
        escaped(format!("bpf returned fd {r}"))
    } else {
        blocked(format!("bpf: {}", last_errno_desc()))
    }
}

fn sys_memfd_exec() -> Outcome {
    // memfd_create itself is allowed. The defense lives in evaluate_exec_request,
    // which resolves /proc/<pid>/fd/<fd> and denies paths outside allowed_exec.
    // Stage a valid ELF in the memfd then try execveat(fd, "", AT_EMPTY_PATH);
    // if it returns, the supervisor denied it.
    let name = CString::new("probe").unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) };
    if fd < 0 {
        return blocked(format!("memfd_create: {}", last_errno_desc()));
    }
    let fd = fd as i32;

    let bytes = match std::fs::read("/usr/bin/true") {
        Ok(b) => b,
        Err(e) => {
            unsafe { libc::close(fd) };
            return blocked(format!("stage binary read: {e}"));
        }
    };
    let mut written = 0usize;
    while written < bytes.len() {
        let r = unsafe {
            libc::write(
                fd,
                bytes[written..].as_ptr() as *const libc::c_void,
                bytes.len() - written,
            )
        };
        if r <= 0 {
            unsafe { libc::close(fd) };
            return blocked(format!("write memfd: {}", last_errno_desc()));
        }
        written += r as usize;
    }

    let empty = CString::new("").unwrap();
    let argv0 = CString::new("probe").unwrap();
    let argv: [*const libc::c_char; 2] = [argv0.as_ptr(), ptr::null()];
    let envp: [*const libc::c_char; 1] = [ptr::null()];
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            fd,
            empty.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
    }
    let err = last_errno_desc();
    unsafe { libc::close(fd) };
    blocked(format!("execveat on memfd denied: {err}"))
}

fn sys_io_uring_setup() -> Outcome {
    // io_uring_setup takes entries and a pointer to io_uring_params.
    let mut params = [0u8; 120];
    let r = unsafe {
        libc::syscall(425 /* SYS_io_uring_setup */, 8i64, params.as_mut_ptr())
    };
    if r >= 0 {
        unsafe { libc::close(r as i32) };
        escaped("io_uring_setup returned fd")
    } else {
        blocked(format!("io_uring_setup: {}", last_errno_desc()))
    }
}

fn sys_mount() -> Outcome {
    let src = CString::new("tmpfs").unwrap();
    let tgt = CString::new("/tmp").unwrap();
    let fs = CString::new("tmpfs").unwrap();
    let r = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fs.as_ptr(), 0, ptr::null()) };
    if r == 0 {
        escaped("mount succeeded")
    } else {
        blocked(format!("mount: {}", last_errno_desc()))
    }
}

fn sys_mount_setattr_probe() -> Outcome {
    let r = unsafe {
        libc::syscall(
            442, /* SYS_mount_setattr */
            -100i64,
            c"/".as_ptr(),
            0u32,
            ptr::null::<u8>(),
            0u64,
        )
    };
    if r == 0 {
        escaped("mount_setattr returned 0")
    } else {
        blocked(format!("mount_setattr: {}", last_errno_desc()))
    }
}

fn sys_pidfd_open() -> Outcome {
    let r = unsafe {
        libc::syscall(434 /* SYS_pidfd_open */, 1i64, 0u32)
    };
    if r >= 0 {
        unsafe { libc::close(r as i32) };
        escaped("pidfd_open returned fd")
    } else {
        blocked(format!("pidfd_open: {}", last_errno_desc()))
    }
}

fn sys_fsopen() -> Outcome {
    let name = CString::new("tmpfs").unwrap();
    let r = unsafe {
        libc::syscall(430 /* SYS_fsopen */, name.as_ptr(), 0u32)
    };
    if r >= 0 {
        unsafe { libc::close(r as i32) };
        escaped("fsopen returned fd")
    } else {
        blocked(format!("fsopen: {}", last_errno_desc()))
    }
}

fn sys_userfaultfd() -> Outcome {
    let r = unsafe { libc::syscall(libc::SYS_userfaultfd, 0) };
    if r >= 0 {
        unsafe { libc::close(r as i32) };
        escaped("userfaultfd returned fd")
    } else {
        blocked(format!("userfaultfd: {}", last_errno_desc()))
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
        escaped("perf_event_open returned fd")
    } else {
        blocked(format!("perf_event_open: {}", last_errno_desc()))
    }
}

fn sys_keyctl() -> Outcome {
    // keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 1)
    let r = unsafe { libc::syscall(libc::SYS_keyctl, 0i32, -3i32, 1i32) };
    if r >= 0 {
        escaped(format!("keyctl returned id {r}"))
    } else {
        blocked(format!("keyctl: {}", last_errno_desc()))
    }
}

fn sys_chroot() -> Outcome {
    let p = CString::new(".").unwrap();
    let r = unsafe { libc::chroot(p.as_ptr()) };
    if r == 0 {
        escaped("chroot succeeded")
    } else {
        blocked(format!("chroot: {}", last_errno_desc()))
    }
}

fn sys_tiocsti() -> Outcome {
    const TIOCSTI: libc::c_ulong = 0x5412;
    let c: u8 = b'x';
    let r = unsafe { libc::ioctl(0, TIOCSTI, &c as *const u8) };
    if r == 0 {
        escaped("ioctl TIOCSTI succeeded")
    } else {
        blocked(format!("TIOCSTI: {}", last_errno_desc()))
    }
}

fn sys_tiocsti_high_bits() -> Outcome {
    // The kernel declares the ioctl cmd as unsigned int and therefore
    // ignores any bits above bit 31. A seccomp rule built with
    // `op: eq, value: TIOCSTI` on a 64 bit register misses a cmd of
    // 0x1_0000_5412, because the full compare is not equal to 0x5412.
    // Issue the raw syscall directly so the glibc wrapper cannot clip
    // the value back down to u32 for us.
    const TIOCSTI_WITH_HIGH: u64 = 0x0000_0001_0000_5412;
    let c: u8 = b'x';
    let r = unsafe { libc::syscall(libc::SYS_ioctl, 0i32, TIOCSTI_WITH_HIGH, &c as *const u8) };
    if r == 0 {
        escaped("ioctl TIOCSTI via high bits succeeded")
    } else {
        blocked(format!("TIOCSTI high bits: {}", last_errno_desc()))
    }
}

fn net_raw_socket() -> Outcome {
    let r = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if r >= 0 {
        unsafe { libc::close(r) };
        escaped("AF_INET SOCK_RAW created")
    } else {
        blocked(format!("raw socket: {}", last_errno_desc()))
    }
}

fn sys_swapon() -> Outcome {
    // Exercises deny-by-default: swapon was never on the explicit
    // deny list but must still be refused because it is not on the
    // allow list.
    let p = CString::new("/nonexistent").unwrap();
    let r = unsafe { libc::swapon(p.as_ptr(), 0) };
    if r == 0 {
        escaped("swapon unexpectedly succeeded")
    } else {
        blocked(format!("swapon: {}", last_errno_desc()))
    }
}

fn sys_reboot() -> Outcome {
    // Validates deny-by-default for the classic "kill the box"
    // syscall. Needs CAP_SYS_BOOT anyway, but the filter should
    // reject it before the capability check. Explicit EPERM rule
    // avoids the misleading default EACCES.
    let r = unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_CAD_OFF) };
    if r == 0 {
        return escaped("reboot accepted");
    }
    let errno = unsafe { *libc::__errno_location() };
    if errno != libc::EPERM {
        return escaped(format!("reboot denied with errno {errno}, expected EPERM"));
    }
    blocked(format!("reboot: {}", last_errno_desc()))
}

fn fs_unlink_read_only_file() -> Outcome {
    // The `read_only` policy entry must mean "this file cannot be replaced",
    // not just "grant ReadFile". Landlock can't enforce that when a parent
    // directory grants RemoveFile/MakeReg (additive policy), so the
    // supervisor has to deny the unlink. The test runner pre-creates
    // $TMPDIR/read_only_test and lists it in `read_only_enforced`.
    let tmpdir = probe_tmp();
    let target = probe_join(&tmpdir, "read_only_test");
    match std::fs::remove_file(&target) {
        Ok(()) => escaped(format!("unlinked read_only file {}", target.display())),
        Err(e) => blocked(format!("unlink denied: {e}")),
    }
}

fn fs_rename_over_read_only_file() -> Outcome {
    // Attacker variant: drop a decoy file alongside and rename it over the
    // read_only target to atomically replace it. Supervisor must deny.
    let tmpdir = probe_tmp();
    let target = probe_join(&tmpdir, "read_only_test");
    let decoy = probe_join(&tmpdir, "read_only_decoy");
    if let Err(e) = std::fs::write(&decoy, b"attacker content\n") {
        return blocked(format!("could not stage decoy: {e}"));
    }
    let result = std::fs::rename(&decoy, &target);
    let _ = std::fs::remove_file(&decoy);
    match result {
        Ok(()) => escaped(format!(
            "renamed decoy over read_only file {}",
            target.display()
        )),
        Err(e) => blocked(format!("rename denied: {e}")),
    }
}

fn sys_notify_id_invalidation_race() -> Outcome {
    // Regression probe for a supervisor liveness bug: if a thread issues a
    // notified syscall and the whole process exit_group()s before the
    // supervisor responds, the supervisor used to skip `respond` entirely
    // (on stale notify_id) or break out of its loop (on any receive
    // error). Either state left the kernel's in-flight notification slot
    // occupied and every subsequent notified syscall from another child
    // blocked forever in seccomp_do_user_notification.
    //
    // Pattern per iteration: fork → child spawns a worker thread that
    // loops `openat(O_CREAT)` → child main exit_groups after a short
    // delay so the worker dies mid-syscall. After N iterations, confirm
    // the supervisor is still responsive by issuing one more notified
    // syscall from this process. If that hangs, the test driver times
    // out and this test fails.
    const ITERATIONS: i32 = 200;
    const SLEEP_NS: i64 = 50_000;

    extern "C" fn worker(_: *mut libc::c_void) -> *mut libc::c_void {
        loop {
            let fd = unsafe {
                libc::openat(
                    libc::AT_FDCWD,
                    c"notify_race_tgt".as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT,
                    0o600,
                )
            };
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }

    let mut reaped = 0;
    for i in 0..ITERATIONS {
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return blocked(format!("fork failed at {i}: {}", last_errno_desc()));
        }
        if pid == 0 {
            let mut th: libc::pthread_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::pthread_create(&mut th, std::ptr::null(), worker, std::ptr::null_mut())
            };
            if rc != 0 {
                unsafe { libc::_exit(3) };
            }
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: SLEEP_NS,
            };
            unsafe {
                libc::nanosleep(&ts, std::ptr::null_mut());
            }
            unsafe {
                libc::syscall(libc::SYS_exit_group, 0_i32);
            }
            unsafe { libc::_exit(0) };
        }
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            reaped += 1;
        } else {
            return blocked(format!("waitpid failed at {i}: {}", last_errno_desc()));
        }
    }

    // Sanity: supervisor must still answer a fresh notified openat.
    // If this hangs forever, the test runner's overall timeout catches it.
    let fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            c"notify_race_post".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT,
            0o600,
        )
    };
    if fd < 0 {
        return escaped(format!(
            "supervisor wedged after {reaped}/{ITERATIONS} race iterations: {}",
            last_errno_desc()
        ));
    }
    unsafe {
        libc::close(fd);
        libc::unlink(c"notify_race_post".as_ptr());
        libc::unlink(c"notify_race_tgt".as_ptr());
    }

    blocked(format!(
        "supervisor survived {reaped}/{ITERATIONS} notify_id-invalidation iterations"
    ))
}

fn sys_init_module() -> Outcome {
    // Loading a kernel module would be a complete break. An explicit
    // deny rule returns EPERM so the errno reads as "operation not
    // permitted" rather than the misleading default EACCES.
    let r = unsafe {
        libc::syscall(
            libc::SYS_init_module,
            std::ptr::null::<u8>(),
            0u64,
            c"".as_ptr(),
        )
    };
    if r == 0 {
        return escaped("init_module accepted");
    }
    let errno = unsafe { *libc::__errno_location() };
    if errno != libc::EPERM {
        return escaped(format!(
            "init_module denied with errno {errno}, expected EPERM"
        ));
    }
    blocked(format!("init_module: {}", last_errno_desc()))
}

fn net_udp_socket() -> Outcome {
    let r = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if r >= 0 {
        unsafe { libc::close(r) };
        escaped("AF_INET SOCK_DGRAM created")
    } else {
        blocked(format!("udp socket: {}", last_errno_desc()))
    }
}

fn net_netlink_socket() -> Outcome {
    let r = unsafe {
        libc::socket(16 /* AF_NETLINK */, libc::SOCK_RAW, 0)
    };
    if r >= 0 {
        unsafe { libc::close(r) };
        escaped("AF_NETLINK socket created")
    } else {
        blocked(format!("netlink: {}", last_errno_desc()))
    }
}

fn net_packet_socket() -> Outcome {
    let r = unsafe {
        libc::socket(17 /* AF_PACKET */, libc::SOCK_RAW, 0)
    };
    if r >= 0 {
        unsafe { libc::close(r) };
        escaped("AF_PACKET socket created")
    } else {
        blocked(format!("packet: {}", last_errno_desc()))
    }
}

fn net_vsock_socket() -> Outcome {
    let r = unsafe {
        libc::socket(40 /* AF_VSOCK */, libc::SOCK_STREAM, 0)
    };
    if r >= 0 {
        unsafe { libc::close(r) };
        escaped("AF_VSOCK socket created")
    } else {
        blocked(format!("vsock: {}", last_errno_desc()))
    }
}

fn net_connect_external() -> Outcome {
    match TcpStream::connect_timeout(
        &"8.8.8.8:53".parse().unwrap(),
        std::time::Duration::from_millis(500),
    ) {
        Ok(mut s) => {
            let _ = s.write_all(b"x");
            escaped("connected to 8.8.8.8:53")
        }
        Err(e) => blocked(format!("connect blocked: {e}")),
    }
}

fn net_bind_inet() -> Outcome {
    match std::net::TcpListener::bind("0.0.0.0:0") {
        Ok(_) => escaped("bound 0.0.0.0 TCP port"),
        Err(e) => blocked(format!("bind denied: {e}")),
    }
}

fn proc_parent_environ() -> Outcome {
    let ppid = unsafe { libc::getppid() };
    let path = format!("/proc/{ppid}/environ");
    match std::fs::File::open(&path) {
        Ok(mut f) => {
            let mut buf = vec![0u8; 4096];
            match f.read(&mut buf) {
                Ok(n) if n > 0 => escaped(format!("read {n} bytes of parent environ")),
                Ok(_) => blocked("parent environ empty"),
                Err(e) => blocked(format!("read: {e}")),
            }
        }
        Err(e) => blocked(format!("open /proc/ppid/environ: {e}")),
    }
}

fn fs_write_proc_self_mem() -> Outcome {
    match std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/self/mem")
    {
        Ok(_) => escaped("opened /proc/self/mem for write"),
        Err(e) => blocked(format!("deny: {e}")),
    }
}

fn fs_rename_out_of_cwd() -> Outcome {
    let src = Path::new("./devlock_rename_src");
    let dst = Path::new("/etc/devlock_rename_dst");
    if std::fs::write(src, b"x").is_err() {
        return blocked("could not create source in CWD");
    }
    let outcome = match std::fs::rename(src, dst) {
        Ok(()) => {
            let _ = std::fs::remove_file(dst);
            escaped("renamed CWD file into /etc")
        }
        Err(e) => blocked(format!("rename denied: {e}")),
    };
    let _ = std::fs::remove_file(src);
    outcome
}

fn fs_utimensat_writable_path() -> Outcome {
    let path = Path::new("./devlock_probe_utime");
    let _ = std::fs::remove_file(path);
    if std::fs::write(path, b"x").is_err() {
        return escaped("create in CWD unexpectedly denied");
    }
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        let _ = std::fs::remove_file(path);
        return escaped("CString");
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_utimensat,
            libc::AT_FDCWD,
            c_path.as_ptr(),
            ptr::null::<libc::timespec>(),
            0,
        )
    };
    let _ = std::fs::remove_file(path);
    if rc == 0 {
        blocked("utimensat on writable CWD path permitted (expected)")
    } else {
        escaped(format!(
            "utimensat on writable CWD path unexpectedly denied: {}",
            last_errno_desc()
        ))
    }
}

fn fs_futimens_writable_fd() -> Outcome {
    let path = Path::new("./devlock_probe_futime");
    let _ = std::fs::remove_file(path);
    let fd = match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
    {
        Ok(f) => {
            use std::os::unix::io::IntoRawFd;
            f.into_raw_fd()
        }
        Err(_) => {
            let _ = std::fs::remove_file(path);
            return escaped("create in CWD unexpectedly denied");
        }
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_utimensat,
            fd,
            ptr::null::<libc::c_char>(),
            ptr::null::<libc::timespec>(),
            0,
        )
    };
    unsafe { libc::close(fd) };
    let _ = std::fs::remove_file(path);
    if rc == 0 {
        blocked("futimens on writable fd permitted (expected)")
    } else {
        escaped(format!(
            "futimens on writable fd unexpectedly denied: {}",
            last_errno_desc()
        ))
    }
}

fn fs_faccessat2_existence_leak() -> Outcome {
    // faccessat2 with F_OK on a real but out-of-bucket path must not
    // succeed. Without the stat_request gate, the child could probe
    // existence of files it cannot read, distinguishing ENOENT from
    // EACCES. The supervisor must return EACCES uniformly.
    let p = CString::new("/etc/shadow").unwrap();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            libc::AT_FDCWD,
            p.as_ptr(),
            libc::F_OK,
            0,
        )
    };
    if rc == 0 {
        return escaped("faccessat2 F_OK on /etc/shadow succeeded");
    }
    let errno = unsafe { *libc::__errno_location() };
    if errno == libc::ENOENT {
        return escaped("faccessat2 leaked non-existence on /etc/shadow");
    }
    if errno != libc::EACCES {
        return escaped(format!(
            "faccessat2 denied with errno {errno}, expected EACCES"
        ));
    }
    blocked(format!("faccessat2: {}", last_errno_desc()))
}

fn fs_stat_root_allowed() -> Outcome {
    // stat("/") must succeed so `mv` and `cp -p` do not print spurious
    // attribute-preservation warnings. The filesystem root leaks nothing.
    let rc = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        libc::stat(c"/".as_ptr(), &mut st)
    };
    if rc != 0 {
        return escaped(format!("stat(/) denied: {}", last_errno_desc()));
    }
    blocked("stat(/) permitted")
}

fn fs_stat_home_ancestor_allowed() -> Outcome {
    // The parent of $CWD is an ancestor of the test agent's full_access
    // bucket. The supervisor must allow stat on ancestor paths because
    // the caller can already observe the directory entry from the child
    // subtree, so blocking gives no isolation and only produces spurious
    // EACCES on every `stat($HOME)` from a shell or editor.
    let cwd = probe_cwd();
    let parent = cwd.parent().expect("cwd parent").to_path_buf();
    let c = CString::new(parent.as_os_str().as_bytes()).unwrap();
    let rc = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        libc::stat(c.as_ptr(), &mut st)
    };
    if rc != 0 {
        return escaped(format!(
            "stat({}) denied: {}",
            parent.display(),
            last_errno_desc()
        ));
    }
    blocked(format!("stat({}) permitted", parent.display()))
}

fn fs_stat_etc_ancestor_allowed() -> Outcome {
    // /etc is an ancestor of /etc/hosts (read_only for the test agent).
    // Dynamic linker and PATH lookups routinely stat /etc; blocking them
    // turns into EACCES instead of the ENOENT callers expect.
    let rc = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        libc::stat(c"/etc".as_ptr(), &mut st)
    };
    if rc != 0 {
        return escaped(format!("stat(/etc) denied: {}", last_errno_desc()));
    }
    blocked("stat(/etc) permitted")
}

fn fs_faccessat_existence_leak() -> Outcome {
    // Same check via the legacy faccessat (no flags argument). Some
    // archs still route callers through SYS_faccessat, so it must be
    // gated too.
    let p = CString::new("/etc/shadow").unwrap();
    let rc = unsafe { libc::syscall(libc::SYS_faccessat, libc::AT_FDCWD, p.as_ptr(), libc::F_OK) };
    if rc == 0 {
        return escaped("faccessat F_OK on /etc/shadow succeeded");
    }
    let errno = unsafe { *libc::__errno_location() };
    if errno == libc::ENOENT {
        return escaped("faccessat leaked non-existence on /etc/shadow");
    }
    if errno != libc::EACCES {
        return escaped(format!(
            "faccessat denied with errno {errno}, expected EACCES"
        ));
    }
    blocked(format!("faccessat: {}", last_errno_desc()))
}

fn sys_signal_root_sandbox_pid() -> Outcome {
    // signal_request refuses kill(root_pid, ...), kill(-root_pid, ...),
    // tkill, tgkill, and kill(-1, sig) when the caller tgid is not the
    // root itself. The probe binary IS the root here, so fork first and
    // drive the syscalls from the descendant. Supervisor pid is the
    // agent's PPid, root is the probe's own pid.
    let root_pid = unsafe { libc::getpid() };
    let sup_pid = unsafe { libc::getppid() };
    let (rx, tx) = {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return blocked(format!("pipe: {}", last_errno_desc()));
        }
        (fds[0], fds[1])
    };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return blocked(format!("fork: {}", last_errno_desc()));
    }
    if pid == 0 {
        unsafe { libc::close(rx) };
        let mut fails: Vec<String> = Vec::new();
        let mut try_kill = |label: &str, tgt: libc::pid_t, sig: i32| {
            let r = unsafe { libc::kill(tgt, sig) };
            let e = unsafe { *libc::__errno_location() };
            if r == 0 {
                fails.push(format!("{label} accepted"));
            } else if e != libc::EPERM {
                fails.push(format!("{label} errno={e}, expected EPERM"));
            }
        };
        try_kill("kill(root, 0)", root_pid, 0);
        try_kill("kill(root, SIGUSR1)", root_pid, libc::SIGUSR1);
        try_kill("kill(-root, SIGTERM)", -root_pid, libc::SIGTERM);
        try_kill("kill(sup, 0)", sup_pid, 0);
        try_kill("kill(sup, SIGTERM)", sup_pid, libc::SIGTERM);
        try_kill("kill(-1, SIGTERM)", -1, libc::SIGTERM);
        let r = unsafe { libc::syscall(libc::SYS_tkill, root_pid, 0) };
        let e = unsafe { *libc::__errno_location() };
        if r == 0 {
            fails.push("tkill(root, 0) accepted".into());
        } else if e != libc::EPERM {
            fails.push(format!("tkill errno={e}, expected EPERM"));
        }
        let r = unsafe { libc::syscall(libc::SYS_tgkill, root_pid, root_pid, 0) };
        let e = unsafe { *libc::__errno_location() };
        if r == 0 {
            fails.push("tgkill(root, root, 0) accepted".into());
        } else if e != libc::EPERM {
            fails.push(format!("tgkill errno={e}, expected EPERM"));
        }
        let report = fails.join("; ");
        unsafe {
            libc::write(tx, report.as_ptr() as *const libc::c_void, report.len());
            libc::close(tx);
            libc::_exit(if fails.is_empty() { 0 } else { 1 });
        }
    }
    unsafe { libc::close(tx) };
    let mut buf = vec![0u8; 1024];
    let n = unsafe { libc::read(rx, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    unsafe { libc::close(rx) };
    let report = if n > 0 {
        String::from_utf8_lossy(&buf[..n as usize]).to_string()
    } else {
        String::new()
    };
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    // Supervisor alive check, kill(root, 0) from inside the probe (root
    // itself, so it is allowed and tells us whether the session is still
    // up).
    let alive = unsafe { libc::kill(root_pid, 0) };
    if alive != 0 {
        return escaped(format!(
            "root pid {root_pid} no longer signalable from within"
        ));
    }
    if !report.is_empty() {
        return escaped(format!("signal refusal gap: {report}"));
    }
    blocked(format!(
        "all kill/tkill/tgkill to root={root_pid} sup={sup_pid} refused with EPERM"
    ))
}

fn fs_open_existence_leak() -> Outcome {
    // open(O_RDONLY) on a read_denied existing path must return the
    // same errno as open on a missing neighbor. Without the read bucket
    // gate the kernel returns EACCES for the denied existing one and
    // ENOENT for the missing one, an existence oracle.
    let shadow = CString::new("/etc/shadow").unwrap();
    let nosuch = CString::new("/etc/__devlock_open_nosuch__").unwrap();
    let r1 = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            shadow.as_ptr(),
            libc::O_RDONLY,
            0,
        )
    };
    let e1 = unsafe { *libc::__errno_location() };
    let r2 = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            nosuch.as_ptr(),
            libc::O_RDONLY,
            0,
        )
    };
    let e2 = unsafe { *libc::__errno_location() };
    if r1 >= 0 {
        unsafe { libc::close(r1 as i32) };
        return escaped("open on /etc/shadow succeeded");
    }
    if r2 >= 0 {
        unsafe { libc::close(r2 as i32) };
    }
    if e1 == libc::ENOENT {
        return escaped("open leaked non-existence on /etc/shadow");
    }
    if e1 != e2 {
        return escaped(format!(
            "open existence oracle, /etc/shadow errno={e1}, nonexistent errno={e2}"
        ));
    }
    if e1 != libc::EACCES {
        return escaped(format!("open denied with errno {e1}, expected EACCES"));
    }
    blocked(format!(
        "open normalized, errno={e1} both exists and missing"
    ))
}

fn fs_inotify_add_watch_existence_leak() -> Outcome {
    // Without the stat_request gate the kernel returns EACCES for
    // denied existing paths and ENOENT for missing ones. Both errnos
    // must match on read_list trees like /etc.
    let ifd = unsafe { libc::syscall(libc::SYS_inotify_init1, 0) };
    if ifd < 0 {
        return blocked(format!("inotify_init1: {}", last_errno_desc()));
    }
    let ifd = ifd as libc::c_int;

    let shadow = CString::new("/etc/shadow").unwrap();
    let nosuch = CString::new("/etc/__devlock_nosuch_xyz__").unwrap();
    let mask: u32 = 0x00000002; // IN_MODIFY

    let r1 = unsafe { libc::syscall(libc::SYS_inotify_add_watch, ifd, shadow.as_ptr(), mask) };
    let errno_shadow = unsafe { *libc::__errno_location() };
    let _r2 = unsafe { libc::syscall(libc::SYS_inotify_add_watch, ifd, nosuch.as_ptr(), mask) };
    let errno_nosuch = unsafe { *libc::__errno_location() };
    unsafe { libc::close(ifd) };

    if r1 >= 0 {
        return escaped("inotify_add_watch on /etc/shadow succeeded");
    }
    if errno_shadow == libc::ENOENT {
        return escaped("inotify_add_watch leaked non-existence on /etc/shadow");
    }
    if errno_shadow != errno_nosuch {
        return escaped(format!(
            "inotify_add_watch existence oracle: /etc/shadow errno={errno_shadow}, nonexistent errno={errno_nosuch}"
        ));
    }
    if errno_shadow != libc::EACCES {
        return escaped(format!(
            "inotify_add_watch denied with errno {errno_shadow}, expected EACCES"
        ));
    }
    blocked(format!(
        "inotify_add_watch normalized (errno={errno_shadow} both exists+nonexistent)"
    ))
}

fn net_af_unix_abstract_bind() -> Outcome {
    // Abstract AF_UNIX (sun_path[0] == 0) must be refused at bind so
    // isolation does not rest on Landlock scope alone.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return blocked(format!("socket(AF_UNIX): {}", last_errno_desc()));
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // sun_path[0] == 0 marks abstract namespace, bytes after are the name.
    let name = b"devlock_probe_abs";
    for (i, b) in name.iter().enumerate() {
        addr.sun_path[i + 1] = *b as libc::c_char;
    }
    let addrlen = 2 + 1 + name.len();
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            addrlen as libc::socklen_t,
        )
    };
    let errno = unsafe { *libc::__errno_location() };
    unsafe { libc::close(fd) };
    if rc == 0 {
        return escaped("bind(AF_UNIX, abstract) succeeded");
    }
    if errno != libc::EACCES && errno != libc::EPERM {
        return escaped(format!(
            "abstract bind denied with errno {errno}, expected EACCES/EPERM"
        ));
    }
    blocked(format!("abstract bind denied (errno={errno})"))
}

fn net_af_unix_abstract_connect() -> Outcome {
    // Symmetric with bind. ECONNREFUSED means the supervisor let the
    // call through and the kernel refused because no peer exists,
    // still a miss at the classifier.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return blocked(format!("socket(AF_UNIX): {}", last_errno_desc()));
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let name = b"devlock_probe_abs_connect";
    for (i, b) in name.iter().enumerate() {
        addr.sun_path[i + 1] = *b as libc::c_char;
    }
    let addrlen = 2 + 1 + name.len();
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            addrlen as libc::socklen_t,
        )
    };
    let errno = unsafe { *libc::__errno_location() };
    unsafe { libc::close(fd) };
    if rc == 0 {
        return escaped("connect(AF_UNIX, abstract) succeeded");
    }
    if errno != libc::EACCES && errno != libc::EPERM && errno != libc::ECONNREFUSED {
        return escaped(format!(
            "abstract connect denied with errno {errno}, expected EACCES/EPERM"
        ));
    }
    if errno == libc::ECONNREFUSED {
        return escaped("abstract connect reached the kernel (ECONNREFUSED)");
    }
    blocked(format!("abstract connect denied (errno={errno})"))
}

fn sys_clone3_newuser() -> Outcome {
    // clone_args struct: flags at offset 0, pidfd at 8, child_tid at 16, parent_tid at 24, exit_signal at 32, stack at 40
    let mut args = [0u64; 11];
    args[0] = libc::CLONE_NEWUSER as u64;
    args[4] = libc::SIGCHLD as u64;
    let r = unsafe {
        libc::syscall(435 /* SYS_clone3 */, args.as_mut_ptr(), 88u64)
    };
    if r == 0 {
        // This is the child. Exit fast so the parent sees the escape.
        unsafe { libc::_exit(0) };
    }
    if r > 0 {
        let mut status = 0;
        unsafe { libc::waitpid(r as i32, &mut status, 0) };
        escaped("clone3 with CLONE_NEWUSER succeeded")
    } else {
        blocked(format!("clone3: {}", last_errno_desc()))
    }
}

fn net_af_unix_fs_bind() -> Outcome {
    // Binding an AF_UNIX filesystem socket INSIDE an allowed write bucket
    // (CWD / TMPDIR) is permitted so Jupyter, dbus, gRPC UDS clients work.
    // The probe confirms the bind is allowed; the denial case is covered
    // by net_af_unix_fs_bind_outside_allowed.
    use std::os::unix::net::UnixListener;
    let p = Path::new("./devlock_probe.sock");
    let _ = std::fs::remove_file(p);
    match UnixListener::bind(p) {
        Ok(_) => {
            let _ = std::fs::remove_file(p);
            blocked("bind in CWD permitted (expected)")
        }
        Err(e) => escaped(format!("bind in full_access CWD unexpectedly denied: {e}")),
    }
}

fn net_af_unix_fs_bind_outside_allowed() -> Outcome {
    // Binding an AF_UNIX filesystem socket OUTSIDE any writable bucket
    // must stay denied so a sandboxed agent cannot plant an IPC endpoint
    // in a shared dir (e.g. /tmp, /etc) that another sandbox could reach.
    use std::os::unix::net::UnixListener;
    let p = Path::new("/tmp/devlock_probe_shared.sock");
    let _ = std::fs::remove_file(p);
    match UnixListener::bind(p) {
        Ok(_) => {
            let _ = std::fs::remove_file(p);
            escaped(format!(
                "bound AF_UNIX filesystem socket at {}",
                p.display()
            ))
        }
        Err(e) => blocked(format!("bind outside allowed denied: {e}")),
    }
}

fn exec_from_sandbox_tmp() -> Outcome {
    // The sandbox tmp dir is reachable via TMPDIR and is writable but should
    // not be in the exec allowed set. Dropping a binary there and running it
    // exercises that boundary.
    let tmp = probe_tmp();
    let target = probe_join(&tmp, "devlock_probe_exec");
    // Copy /usr/bin/true so we have something syntactically valid to exec.
    if std::fs::copy("/usr/bin/true", &target).is_err() {
        return blocked("could not stage binary in sandbox tmp");
    }
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755));
    let outcome = match std::process::Command::new(&target).status() {
        Ok(s) if s.success() => escaped("ran binary planted in sandbox tmp"),
        Ok(s) => blocked(format!("exec status {s}")),
        Err(e) => blocked(format!("exec denied: {e}")),
    };
    let _ = std::fs::remove_file(&target);
    outcome
}

fn env_absence_check() -> Outcome {
    // Keep the sensitive env var names themselves out of the result
    // string so the cleartext-logging query does not see them flow to
    // stdout. The probe's exit code is the authoritative signal; the
    // human-readable message only surfaces the kind of leak.
    let sensitive = [
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "GITHUB_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ];
    for key in sensitive {
        if env::var(key).is_ok() {
            let idx = sensitive.iter().position(|k| *k == key).unwrap_or(0);
            return escaped(format!("sensitive env var #{idx} leaked into sandbox"));
        }
    }
    blocked("no sensitive env vars present")
}

fn sys_ptrace_attach_parent() -> Outcome {
    // PTRACE_ATTACH against the parent process. The filter blocks every
    // ptrace call, so even requesting a different action should be
    // denied before Yama ptrace_scope has a chance to weigh in.
    const PTRACE_ATTACH: libc::c_uint = 16;
    let ppid = unsafe { libc::getppid() };
    let r = unsafe {
        libc::ptrace(
            PTRACE_ATTACH,
            ppid,
            ptr::null_mut::<libc::c_void>(),
            ptr::null_mut::<libc::c_void>(),
        )
    };
    if r == 0 {
        escaped(format!("PTRACE_ATTACH accepted against ppid {ppid}"))
    } else {
        blocked(format!("ptrace attach: {}", last_errno_desc()))
    }
}

fn sys_clone_newuser() -> Outcome {
    // Legacy clone() with CLONE_NEWUSER. Covers the flag based
    // conditional rule in policy.yaml. Different entrypoint than
    // clone3, which is handled via the notify filter.
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
        escaped("clone(CLONE_NEWUSER) succeeded")
    } else {
        blocked(format!("clone: {}", last_errno_desc()))
    }
}

fn sys_setxattr_on_etc() -> Outcome {
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
        escaped("setxattr wrote to /etc/hosts")
    } else {
        blocked(format!("setxattr: {}", last_errno_desc()))
    }
}

fn fs_write_via_fchmod() -> Outcome {
    // Open a protected file via openat (will be denied). If for some
    // reason the open succeeded, try fchmod through the resulting fd to
    // ensure the fd-based rule catches it.
    let fd = unsafe { libc::openat(libc::AT_FDCWD, c"/etc/hosts".as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return blocked(format!("open /etc/hosts: {}", last_errno_desc()));
    }
    let r = unsafe { libc::fchmod(fd, 0o777) };
    unsafe { libc::close(fd) };
    if r == 0 {
        escaped("fchmod succeeded on /etc/hosts fd")
    } else {
        blocked(format!("fchmod: {}", last_errno_desc()))
    }
}

// Shared helper used by the TOCTOU probes. Points a symlink at `target`
// atomically via rename so no reader ever observes a missing link.
fn atomic_symlink(target: &Path, link: &Path, staging: &Path) {
    let _ = std::fs::remove_file(staging);
    let _ = std::os::unix::fs::symlink(target, staging);
    let _ = std::fs::rename(staging, link);
}

fn fs_toctou_symlink_swap_open() -> Outcome {
    // Regression probe for the TOCTOU window between supervisor path check
    // and kernel re-resolution. A background thread flips a symlink between
    // an allowed file (in CWD) and a read_only file. The main thread opens
    // the link for write in a tight loop. If the supervisor checks the
    // resolved path but the kernel re-resolves at syscall time, the write
    // can land on the read_only file. With the new supervisor, the kernel
    // sees the exact fd the supervisor opened, so no write can slip
    // through.
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let cwd = probe_cwd();
    let tmpdir = probe_tmp();
    let benign = probe_join(&cwd, ".toctou_benign");
    let protected = probe_join(&tmpdir, "read_only_test");
    let link = probe_join(&cwd, ".toctou_link");
    let staging = probe_join(&cwd, ".toctou_stage");

    let _ = std::fs::write(&benign, b"benign\n");

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thr = stop.clone();
    let benign_thr = benign.clone();
    let protected_thr = protected.clone();
    let link_thr = link.clone();
    let staging_thr = staging.clone();
    let handle = std::thread::spawn(move || {
        let mut toggle = false;
        while !stop_thr.load(Ordering::Relaxed) {
            let tgt = if toggle { &protected_thr } else { &benign_thr };
            atomic_symlink(tgt, &link_thr, &staging_thr);
            toggle = !toggle;
        }
    });

    let original_before = std::fs::read(&protected).ok();
    let mut attempts: u64 = 0;
    let mut writes_to_protected: u64 = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
    while std::time::Instant::now() < deadline {
        attempts += 1;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .write(true)
            .create(false)
            .open(&link)
        {
            let _ = f.write_all(b"pwned\n");
        }
        let now = std::fs::read(&protected).ok();
        if now != original_before {
            writes_to_protected += 1;
            let _ = std::fs::write(&protected, original_before.clone().unwrap_or_default());
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_file(&staging);
    let _ = std::fs::remove_file(&benign);

    if writes_to_protected == 0 {
        blocked(format!(
            "no protected writes across {attempts} TOCTOU open attempts"
        ))
    } else {
        escaped(format!(
            "{writes_to_protected}/{attempts} writes landed on read_only file via symlink swap"
        ))
    }
}

fn fs_toctou_rename_swap() -> Outcome {
    // Attacker flips a directory component of a rename target between an
    // allowed location and a read_only one. If the supervisor resolves
    // lexically and the kernel re-resolves, a rename can land the source
    // on top of a read_only file. The pinned dirfd implementation must
    // block every such flip.
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let cwd = probe_cwd();
    let tmpdir = probe_tmp();
    let benign_dir = probe_join(&cwd, ".toctou_dir_a");
    let protected_dir = probe_join(&tmpdir, "read_only_dir");
    let link_dir = probe_join(&cwd, ".toctou_dir_link");
    let staging = probe_join(&cwd, ".toctou_dir_stage");
    let src = probe_join(&cwd, ".toctou_src");

    let _ = std::fs::create_dir_all(&benign_dir);
    let _ = std::fs::write(&src, b"attacker\n");

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thr = stop.clone();
    let benign_thr = benign_dir.clone();
    let protected_thr = protected_dir.clone();
    let link_thr = link_dir.clone();
    let staging_thr = staging.clone();
    let handle = std::thread::spawn(move || {
        let mut toggle = false;
        while !stop_thr.load(Ordering::Relaxed) {
            let tgt = if toggle { &protected_thr } else { &benign_thr };
            atomic_symlink(tgt, &link_thr, &staging_thr);
            toggle = !toggle;
        }
    });

    let head_before = std::fs::read(probe_join(&protected_dir, "HEAD")).ok();
    let mut attempts: u64 = 0;
    let mut protected_renames: u64 = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
    while std::time::Instant::now() < deadline {
        attempts += 1;
        let dst = probe_join(&link_dir, "HEAD");
        let _ = std::fs::rename(&src, &dst);
        let _ = std::fs::write(&src, b"attacker\n");
        let now = std::fs::read(probe_join(&protected_dir, "HEAD")).ok();
        if now != head_before {
            protected_renames += 1;
            if let Some(ref b) = head_before {
                let _ = std::fs::write(probe_join(&protected_dir, "HEAD"), b);
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    let _ = std::fs::remove_file(&link_dir);
    let _ = std::fs::remove_file(&staging);
    let _ = std::fs::remove_dir_all(&benign_dir);
    let _ = std::fs::remove_file(&src);

    if protected_renames == 0 {
        blocked(format!(
            "no protected rename across {attempts} TOCTOU rename attempts"
        ))
    } else {
        escaped(format!(
            "{protected_renames}/{attempts} renames landed inside read_only dir"
        ))
    }
}

fn fs_openat2_resolve_beneath_bypass() -> Outcome {
    // Call openat2 with a path that uses .. to climb out of the dirfd.
    // The kernel itself rejects this when RESOLVE_BENEATH is set, but the
    // supervisor must also refuse the notification when the client asks
    // for something outside the allowed bucket. Use O_RDONLY targeting
    // /etc/shadow via ../.. from CWD; the read_only list does not cover
    // /etc/shadow, but the allowed_read set also does not cover it, so
    // the supervisor should deny.
    let path = CString::new("../../etc/shadow").unwrap();
    let fd = unsafe { libc::openat(libc::AT_FDCWD, path.as_ptr(), libc::O_RDONLY) };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        escaped("openat with ../../etc/shadow succeeded")
    } else {
        blocked(format!("openat escape denied: {}", last_errno_desc()))
    }
}

fn fs_symlinkat_into_read_only() -> Outcome {
    // symlinkat(2) into a read_only directory. Even though symlink creation
    // does not write to an existing inode, it adds a new name inside the
    // protected directory and must be rejected.
    let tmpdir = probe_tmp();
    let ro_dir = probe_join(&tmpdir, "read_only_dir");
    let dir_fd = unsafe {
        libc::open(
            CString::new(ro_dir.to_string_lossy().as_ref())
                .unwrap()
                .as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY,
        )
    };
    if dir_fd < 0 {
        return blocked(format!("open read_only dir: {}", last_errno_desc()));
    }
    let target = CString::new("/etc/passwd").unwrap();
    let leaf = CString::new("pwned_symlink").unwrap();
    let rc = unsafe { libc::symlinkat(target.as_ptr(), dir_fd, leaf.as_ptr()) };
    unsafe { libc::close(dir_fd) };
    if rc == 0 {
        let _ = std::fs::remove_file(probe_join(&ro_dir, "pwned_symlink"));
        escaped("symlinkat placed link inside read_only directory")
    } else {
        blocked(format!("symlinkat denied: {}", last_errno_desc()))
    }
}

fn fs_linkat_over_read_only() -> Outcome {
    // linkat(2) creating a hardlink from /etc/passwd into the read_only
    // directory. Linkat does not support replacing an existing target so
    // the probe targets a new name inside the protected dir; supervisor
    // must deny either way.
    let tmpdir = probe_tmp();
    let ro_dir = probe_join(&tmpdir, "read_only_dir");
    let dir_fd = unsafe {
        libc::open(
            CString::new(ro_dir.to_string_lossy().as_ref())
                .unwrap()
                .as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY,
        )
    };
    if dir_fd < 0 {
        return blocked(format!("open read_only dir: {}", last_errno_desc()));
    }
    let src = CString::new("/etc/passwd").unwrap();
    let leaf = CString::new("pwned_link").unwrap();
    let rc = unsafe { libc::linkat(libc::AT_FDCWD, src.as_ptr(), dir_fd, leaf.as_ptr(), 0) };
    unsafe { libc::close(dir_fd) };
    if rc == 0 {
        let _ = std::fs::remove_file(probe_join(&ro_dir, "pwned_link"));
        escaped("linkat created hardlink inside read_only directory")
    } else {
        blocked(format!("linkat denied: {}", last_errno_desc()))
    }
}

fn fs_rename_out_of_read_only() -> Outcome {
    // Rename of a read_only-protected file to a new name within a writable
    // bucket. This would be a way to smuggle the file out of its protected
    // identity if the supervisor only checked the destination.
    let tmpdir = probe_tmp();
    let src = probe_join(&tmpdir, "read_only_test");
    let dst = probe_join(&tmpdir, "read_only_test.bak");
    match std::fs::rename(&src, &dst) {
        Ok(()) => {
            let _ = std::fs::rename(&dst, &src);
            escaped(format!(
                "renamed read_only file {} -> {}",
                src.display(),
                dst.display()
            ))
        }
        Err(e) => blocked(format!("rename of read_only denied: {e}")),
    }
}
