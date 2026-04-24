//! Containment applied to the forked proxy worker.
//!
//! The proxy worker inherits the supervisor's privileges at fork time: no
//! landlock, no seccomp, full FS and syscall surface. Without extra
//! restrictions a compromise of the proxy code would hand the attacker the
//! host filesystem (including `/etc/shadow`, the agent's credentials file,
//! every bind mount the devcontainer exposes) and every escape class
//! syscall the seccomp filter denies to the sandboxed agent (mount, bpf,
//! io_uring, ptrace, the module family, etc.).
//!
//! The restriction here shares the mechanisms used for the agent (Landlock
//! V6, seccomp BPF) but with a profile shaped to what the proxy actually
//! does: accept loopback connections, connect out to public IPs over TLS,
//! append to its log files, and read the system resolver and trust store.
//! The filter is deny list style rather than allow list because hyper,
//! rustls, and tokio's syscall footprint varies across versions; a
//! missing allow entry breaks the proxy with no useful diagnostic, a
//! missing deny entry does not widen the attack surface beyond what is
//! already listed here.

use landlock::*;
use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};
use std::io;
use std::path::Path;

/// Apply landlock and seccomp to the proxy worker. Call exactly once, in
/// the forked child, after tracing has opened its log files (the landlock
/// rules permit writes to `log_dir` but not path creation anywhere else,
/// so existing fds keep working but new files outside `log_dir` fail) and
/// before the tokio runtime starts.
pub fn restrict_proxy_worker(log_dir: &Path) -> io::Result<()> {
    super::privs::set_no_new_privs()?;
    apply_landlock(log_dir).map_err(|e| io::Error::other(format!("proxy landlock: {e}")))?;
    // Drop caps before seccomp: capset is in the deny list, and we want
    // any sandbox bypass not to inherit residual privilege.
    super::privs::drop_bounding_set();
    super::privs::clear_ambient_caps();
    super::privs::lock_securebits();
    super::privs::drop_all_caps();
    apply_seccomp().map_err(|e| io::Error::other(format!("proxy seccomp: {e}")))?;
    Ok(())
}

fn apply_landlock(log_dir: &Path) -> anyhow::Result<()> {
    const ABI: ABI = ABI::V6;

    let read_exec = AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir;
    let read_only = AccessFs::ReadFile | AccessFs::ReadDir;
    // Log directory is the only FS write surface the proxy needs. MakeReg
    // and Truncate so tracing can rotate. Explicitly exclude MakeSym and
    // MakeSock so a compromise cannot drop a symlink or unix socket into
    // the log tree that is later followed by something outside the proxy.
    let log_rw = AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::Truncate
        | AccessFs::MakeReg
        | AccessFs::RemoveFile
        | AccessFs::MakeDir
        | AccessFs::RemoveDir;

    let read_exec_roots: Vec<&Path> = [Path::new("/usr"), Path::new("/lib"), Path::new("/lib64")]
        .into_iter()
        .filter(|p| p.exists())
        .collect();
    let read_only_roots: Vec<&Path> = [Path::new("/etc")]
        .into_iter()
        .filter(|p| p.exists())
        .collect();

    // Scope::Signal blocks signals to processes outside the landlock
    // domain (the supervisor, the agent child, anything on the host). The
    // proxy never needs to signal them and the main escape motivation to
    // do so is SIGKILL ing the agent to truncate the transcript.
    let scopes = Scope::AbstractUnixSocket | Scope::Signal;

    // Declare BindTcp so landlock enforces it, then add no NetPort rule
    // for it. That is the landlock idiom for "deny every bind". The two
    // listener sockets were bound in the parent before fork and are
    // inherited as already-bound fds, so the proxy never needs to bind
    // a new port.
    //
    // Do NOT declare AccessNet::ConnectTcp. Declaring it without
    // corresponding NetPort rules would deny every outbound connect,
    // which breaks the proxy's entire job (reaching Anthropic on 443,
    // DNS resolver fallbacks on 53, etc.). Leaving it undeclared lets
    // connect() through at the landlock layer; seccomp still gates the
    // socket family to AF_INET / AF_INET6 / AF_UNIX.
    let net_access = AccessNet::BindTcp;

    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI))?
        .handle_access(net_access)?
        .scope(scopes)?
        .create()?
        .add_rules(path_beneath_rules(&read_exec_roots, read_exec))?
        .add_rules(path_beneath_rules(&read_only_roots, read_only))?
        .add_rules(path_beneath_rules([log_dir], log_rw))?;

    ruleset.restrict_self()?;
    Ok(())
}

fn apply_seccomp() -> anyhow::Result<()> {
    let ctx = build_proxy_filter()?;
    ctx.load()?;
    Ok(())
}

fn build_proxy_filter() -> anyhow::Result<ScmpFilterContext> {
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;

    for name in UNCONDITIONAL_DENIES {
        add_deny(&mut ctx, name)?;
    }

    // socket(family, ...) deny when family is not one the proxy needs.
    // AF_INET and AF_INET6 for TCP to Anthropic, AF_UNIX for the glibc
    // resolver's nscd and nsswitch fallbacks. Everything else (AF_PACKET,
    // AF_NETLINK, AF_VSOCK, AF_XDP, AF_BLUETOOTH, AF_RDS, AF_TIPC, ...)
    // is refused.
    for family in DISALLOWED_SOCKET_FAMILIES {
        ctx.add_rule_conditional(
            ScmpAction::Errno(libc::EAFNOSUPPORT),
            ScmpSyscall::from_name("socket")?,
            &[ScmpArgCompare::new(0, ScmpCompareOp::Equal, *family as u64)],
        )?;
    }

    // SOCK_RAW is gated by CAP_NET_RAW at the kernel; don't lean on
    // that. Mask with 0xf to strip SOCK_CLOEXEC / SOCK_NONBLOCK.
    const SOCK_TYPE_MASK: u64 = 0xf;
    ctx.add_rule_conditional(
        ScmpAction::Errno(libc::EAFNOSUPPORT),
        ScmpSyscall::from_name("socket")?,
        &[ScmpArgCompare::new(
            1,
            ScmpCompareOp::MaskedEqual(SOCK_TYPE_MASK),
            libc::SOCK_RAW as u64,
        )],
    )?;

    // ioctl cmd = TIOCSTI pushes bytes into the controlling tty's input
    // queue. Guard both the canonical 32 bit cmd and the variant with the
    // high 32 bits set so a filter that only matched the low word is not
    // bypassed by sign extension.
    let tiocsti: u64 = libc::TIOCSTI as u32 as u64;
    ctx.add_rule_conditional(
        ScmpAction::Errno(libc::EPERM),
        ScmpSyscall::from_name("ioctl")?,
        &[ScmpArgCompare::new(1, ScmpCompareOp::Equal, tiocsti)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(libc::EPERM),
        ScmpSyscall::from_name("ioctl")?,
        &[ScmpArgCompare::new(
            1,
            ScmpCompareOp::MaskedEqual(0xFFFF_FFFF),
            tiocsti,
        )],
    )?;

    // One rule per CLONE_NEW_* flag: SCMP_CMP_MASKED_EQ is
    // (arg & mask) == value, so a combined rule only fires when every
    // bit is set at once.
    let ns_flags = [
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWNS,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWCGROUP,
    ];
    for flag in ns_flags {
        let flag = flag as u64;
        ctx.add_rule_conditional(
            ScmpAction::Errno(libc::EPERM),
            ScmpSyscall::from_name("clone")?,
            &[ScmpArgCompare::new(
                0,
                ScmpCompareOp::MaskedEqual(flag),
                flag,
            )],
        )?;
    }
    // clone3 takes a pointer to struct clone_args, not a flags register,
    // so BPF cannot filter on flags (seccomp never dereferences user
    // pointers). Allow clone3 since glibc 2.34+ uses it exclusively for
    // pthread_create; the worker cannot spawn at all without it. A
    // clone3(CLONE_NEWUSER|...) slips through here, but once the new
    // namespace exists the inherited seccomp filter still denies mount,
    // unshare, bpf, and the rest of the escape class, so the bypass
    // buys nothing.

    // prctl deny list. Default-Allow filters cannot express an allow-list
    // within a syscall (libseccomp refuses any Allow rule when the filter
    // default is already Allow). Deny the specific options that open
    // useful attack surface, leave boring ones (PR_SET_NAME,
    // PR_SET_PDEATHSIG, PR_GET_DUMPABLE, ...) at the default.
    for opt in DENIED_PRCTL_OPTIONS {
        ctx.add_rule_conditional(
            ScmpAction::Errno(libc::EPERM),
            ScmpSyscall::from_name("prctl")?,
            &[ScmpArgCompare::new(0, ScmpCompareOp::Equal, *opt as u64)],
        )?;
    }

    Ok(ctx)
}

fn add_deny(ctx: &mut ScmpFilterContext, name: &str) -> anyhow::Result<()> {
    // Not every kernel knows every syscall name we want to refuse. A name
    // libseccomp cannot resolve on this arch (e.g. modify_ldt on aarch64)
    // would not be reachable at runtime anyway, so skip it silently
    // instead of failing filter install.
    let sc = match ScmpSyscall::from_name(name) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    ctx.add_rule(ScmpAction::Errno(libc::EPERM), sc)?;
    Ok(())
}

const UNCONDITIONAL_DENIES: &[&str] = &[
    "execve",
    "execveat",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "process_madvise",
    "pidfd_getfd",
    "fork",
    "vfork",
    "setsid",
    "unshare",
    "setns",
    "chroot",
    "pivot_root",
    "open_tree",
    "name_to_handle_at",
    "open_by_handle_at",
    "move_mount",
    "fsopen",
    "fsmount",
    "fsconfig",
    "fspick",
    "mount",
    "mount_setattr",
    "umount",
    "umount2",
    "bpf",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "perf_event_open",
    "userfaultfd",
    "fanotify_init",
    "fanotify_mark",
    "memfd_secret",
    "keyctl",
    "add_key",
    "request_key",
    "init_module",
    "finit_module",
    "delete_module",
    "create_module",
    "get_kernel_syms",
    "query_module",
    "kexec_load",
    "kexec_file_load",
    "reboot",
    "swapon",
    "swapoff",
    "nfsservctl",
    "uselib",
    "ustat",
    "sysfs",
    "lookup_dcookie",
    "seccomp",
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
    "setuid",
    "setgid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
    "setfsuid",
    "setfsgid",
    "setgroups",
    "capset",
    "chown",
    "fchown",
    "lchown",
    "fchownat",
    "chmod",
    "fchmod",
    "fchmodat",
    "fchmodat2",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "listxattr",
    "flistxattr",
    "llistxattr",
    "getxattr",
    "lgetxattr",
    "fgetxattr",
    "adjtimex",
    "clock_adjtime",
    "settimeofday",
    "clock_settime",
    "stime",
    "sched_setattr",
    "sched_setaffinity",
    "sched_setscheduler",
    "sched_setparam",
    "setpriority",
    "setrlimit",
    "personality",
    "modify_ldt",
    "iopl",
    "ioperm",
    "io_setup",
    "io_submit",
    "io_cancel",
    "io_destroy",
    "io_getevents",
    "io_pgetevents",
    "inotify_init",
    "inotify_init1",
    "inotify_add_watch",
    "inotify_rm_watch",
    "shmget",
    "shmat",
    "shmdt",
    "shmctl",
    "msgget",
    "msgctl",
    "msgrcv",
    "msgsnd",
    "semget",
    "semctl",
    "semop",
    "semtimedop",
    "mq_open",
    "mq_unlink",
    "mq_timedsend",
    "mq_timedreceive",
    "mq_notify",
    "mq_getsetattr",
    "mbind",
    "set_mempolicy",
    "migrate_pages",
    "move_pages",
    "get_mempolicy",
    "set_mempolicy_home_node",
    "mlock",
    "mlock2",
    "mlockall",
    "munlock",
    "munlockall",
    "pkey_alloc",
    "pkey_free",
    "pkey_mprotect",
    "syslog",
    "sethostname",
    "setdomainname",
    "acct",
    "quotactl",
    "quotactl_fd",
    "vhangup",
    "map_shadow_stack",
];

const DISALLOWED_SOCKET_FAMILIES: &[i32] = &[
    libc::AF_NETLINK,
    libc::AF_PACKET,
    libc::AF_VSOCK,
    libc::AF_XDP,
    libc::AF_BLUETOOTH,
    libc::AF_RDS,
    libc::AF_TIPC,
    libc::AF_ALG,
    libc::AF_KEY,
    libc::AF_CAN,
    libc::AF_AX25,
    libc::AF_X25,
    libc::AF_APPLETALK,
    libc::AF_IPX,
    libc::AF_DECnet,
    libc::AF_NFC,
    libc::AF_ATMPVC,
    libc::AF_ATMSVC,
    libc::AF_LLC,
    libc::AF_IB,
    libc::AF_MPLS,
    libc::AF_CAIF,
    libc::AF_PPPOX,
    libc::AF_IRDA,
    libc::AF_ISDN,
    libc::AF_PHONET,
    libc::AF_IEEE802154,
];

// Dangerous prctl options. PR_SET_NO_NEW_PRIVS was applied before the
// filter loaded; the kernel makes it one way so denying it after the
// fact is unnecessary. PR_SET_SECCOMP (op 22) is covered by the
// unconditional seccomp deny. PR_SET_MM (35) rewrites argv / env /
// exe / brk pointers and takes CAP_SYS_RESOURCE, not a real escape
// here but denied for defence in depth. PR_SET_PTRACER (0x59616d61)
// widens who can ptrace us. PR_SET_SECUREBITS (28) unlocks the
// securebits model and is meaningless without CAP_SETPCAP but still
// worth refusing. PR_SET_SPECULATION_CTRL (53), PR_SET_FP_MODE (45),
// and PR_SET_SYSCALL_USER_DISPATCH (59) are niche knobs.
const DENIED_PRCTL_OPTIONS: &[i32] = &[
    35,         // PR_SET_MM
    28,         // PR_SET_SECUREBITS
    45,         // PR_SET_FP_MODE
    53,         // PR_SET_SPECULATION_CTRL
    59,         // PR_SET_SYSCALL_USER_DISPATCH
    62,         // PR_SCHED_CORE
    0x59616d61, // PR_SET_PTRACER
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    use tempfile::tempfile;

    // Export the compiled filter so tests can inspect rules directly
    // without depending on kernel DAC, YAMA, or capability checks.
    fn filter_pfc() -> String {
        let ctx = build_proxy_filter().expect("build proxy filter");
        let mut f = tempfile().expect("tempfile");
        ctx.export_pfc(&f).expect("export_pfc");
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        s
    }

    fn has_rule_for(pfc: &str, syscall: &str) -> bool {
        pfc.contains(&format!("syscall \"{syscall}\""))
    }

    #[test]
    fn every_unconditional_deny_is_in_the_filter() {
        let pfc = filter_pfc();
        for name in UNCONDITIONAL_DENIES {
            if ScmpSyscall::from_name(name).is_err() {
                continue;
            }
            assert!(has_rule_for(&pfc, name), "missing deny rule for {name}");
        }
    }

    #[test]
    fn every_disallowed_socket_family_is_in_the_filter() {
        let pfc = filter_pfc();
        for family in DISALLOWED_SOCKET_FAMILIES {
            let needle = format!("$a0.lo32 == {}", *family as u32);
            assert!(
                pfc.contains(&needle),
                "missing socket family deny for {family} (looking for `{needle}`)"
            );
        }
    }

    #[test]
    fn every_denied_prctl_option_is_in_the_filter() {
        let pfc = filter_pfc();
        for opt in DENIED_PRCTL_OPTIONS {
            let needle = format!("$a0.lo32 == {}", *opt as u32);
            assert!(
                pfc.contains(&needle),
                "missing prctl option deny for {opt:#x} (looking for `{needle}`)"
            );
        }
    }

    #[test]
    fn denies_clone_for_each_namespace_flag() {
        // Regression for the (mask=all, value=all) rule that only fired
        // when every CLONE_NEW_* bit was set at once.
        let pfc = filter_pfc();
        let ns_flags: [(&str, i32); 7] = [
            ("CLONE_NEWUSER", libc::CLONE_NEWUSER),
            ("CLONE_NEWNS", libc::CLONE_NEWNS),
            ("CLONE_NEWPID", libc::CLONE_NEWPID),
            ("CLONE_NEWNET", libc::CLONE_NEWNET),
            ("CLONE_NEWIPC", libc::CLONE_NEWIPC),
            ("CLONE_NEWUTS", libc::CLONE_NEWUTS),
            ("CLONE_NEWCGROUP", libc::CLONE_NEWCGROUP),
        ];
        for (name, flag) in ns_flags {
            let needle = format!("$a0.lo32 & {:#010x} == {}", flag as u32, flag as u32);
            assert!(
                pfc.contains(&needle),
                "missing per-flag clone rule for {name} (looking for `{needle}`)"
            );
        }
    }

    #[test]
    fn denies_tiocsti_ioctl() {
        let pfc = filter_pfc();
        assert!(
            has_rule_for(&pfc, "ioctl"),
            "expected ioctl deny rule (TIOCSTI) in filter"
        );
    }

    #[test]
    fn denies_raw_socket_on_every_family() {
        let pfc = filter_pfc();
        let sock_raw = libc::SOCK_RAW as u32;
        let needle = format!("$a1.lo32 & 0x0000000f == {sock_raw}");
        assert!(
            pfc.contains(&needle),
            "missing SOCK_RAW deny rule (looking for `{needle}`)\n{pfc}"
        );
    }
}
