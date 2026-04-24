//! Spawns the forked proxy worker's landlock + seccomp profile around a
//! probe binary and asserts that every known escape attempt is denied.
//! The proxy sandbox is applied in process (no seccomp notify supervisor),
//! so the probe binary calls `restrict_proxy_worker` itself before running
//! the attempt.

use std::process::{Command, Output};

fn run_probe(name: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_proxy-escape-probe"))
        .arg(name)
        .output()
        .unwrap_or_else(|_| {
            panic!("failed to execute proxy-escape-probe binary for probe '{name}'")
        })
}

fn assert_blocked(probe: &str) {
    let out = run_probe(probe);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        out.status.success(),
        "probe {probe} was NOT blocked.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("BLOCKED"),
        "probe {probe} did not print BLOCKED marker.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        combined.contains("EPERM")
            || combined.contains("EACCES")
            || combined.contains("EAFNOSUPPORT")
            || combined.contains("EINVAL")
            || combined.contains("ENOSYS")
            || combined.contains("Operation not permitted")
            || combined.contains("Permission denied")
            || combined.contains("Address family not supported by protocol")
            || combined.contains("Invalid argument")
            || combined.contains("Function not implemented"),
        "probe {probe} did not report permission-denied errno/text (expected EPERM/EACCES).\nstdout: {stdout}\nstderr: {stderr}"
    );
}

// Filesystem (Landlock)
#[test]
fn denies_writing_to_etc() {
    assert_blocked("fs_write_etc");
}

#[test]
fn denies_writing_to_tmp_outside_log_dir() {
    assert_blocked("fs_write_tmp");
}

#[test]
fn denies_writing_to_home() {
    assert_blocked("fs_write_home");
}

#[test]
fn denies_creating_file_in_etc() {
    assert_blocked("fs_create_in_etc");
}

// Network (Landlock BindTcp deny)
#[test]
fn denies_tcp_bind_ipv4() {
    assert_blocked("net_bind_tcp");
}

#[test]
fn denies_tcp_bind_ipv6() {
    assert_blocked("net_bind_inet6");
}

// Landlock Scope::Signal
#[test]
fn denies_signal_to_parent() {
    assert_blocked("sys_signal_parent");
}

// Seccomp unconditional denies (exec, ptrace, fork, ns, mount, kernel)
#[test]
fn denies_execve() {
    assert_blocked("sys_execve");
}

#[test]
fn denies_unshare() {
    assert_blocked("sys_unshare");
}

#[test]
fn denies_setns() {
    assert_blocked("sys_setns");
}

#[test]
fn denies_chroot() {
    assert_blocked("sys_chroot");
}

#[test]
fn denies_mount() {
    assert_blocked("sys_mount");
}

#[test]
fn denies_pivot_root() {
    assert_blocked("sys_pivot_root");
}

#[test]
fn denies_bpf() {
    assert_blocked("sys_bpf");
}

#[test]
fn denies_io_uring_setup() {
    assert_blocked("sys_io_uring_setup");
}

#[test]
fn denies_keyctl() {
    assert_blocked("sys_keyctl");
}

#[test]
fn denies_add_key() {
    assert_blocked("sys_add_key");
}

#[test]
fn denies_reboot() {
    assert_blocked("sys_reboot");
}

#[test]
fn denies_init_module() {
    assert_blocked("sys_init_module");
}

#[test]
fn denies_kexec_load() {
    assert_blocked("sys_kexec_load");
}

// Seccomp credential / ownership denies
#[test]
fn denies_setuid() {
    assert_blocked("sys_setuid");
}

#[test]
fn denies_setgid() {
    assert_blocked("sys_setgid");
}

#[test]
fn denies_setgroups() {
    assert_blocked("sys_setgroups");
}

#[test]
fn denies_chmod() {
    assert_blocked("sys_chmod");
}

#[test]
fn denies_chown() {
    assert_blocked("sys_chown");
}

#[test]
fn denies_setxattr() {
    assert_blocked("sys_setxattr");
}

// Seccomp file watch / trace denies
#[test]
fn denies_inotify_init1() {
    assert_blocked("sys_inotify_init1");
}

#[test]
fn denies_fanotify_init() {
    assert_blocked("sys_fanotify_init");
}

#[test]
fn denies_ptrace() {
    assert_blocked("sys_ptrace");
}

#[test]
fn denies_perf_event_open() {
    assert_blocked("sys_perf_event_open");
}

#[test]
fn denies_userfaultfd() {
    assert_blocked("sys_userfaultfd");
}

#[test]
fn denies_syslog() {
    assert_blocked("sys_syslog");
}

#[test]
fn denies_uselib() {
    assert_blocked("sys_uselib");
}

#[test]
fn denies_swapon() {
    assert_blocked("sys_swapon");
}

#[test]
fn denies_process_vm_readv() {
    assert_blocked("sys_process_vm_readv");
}

// Seccomp self-re-entry / security subsystem
#[test]
fn denies_seccomp_syscall() {
    assert_blocked("sys_seccomp");
}

#[test]
fn denies_landlock_restrict_self() {
    assert_blocked("sys_landlock_restrict_self");
}

// Seccomp socket family filter
#[test]
fn denies_netlink_socket() {
    assert_blocked("net_socket_netlink");
}

#[test]
fn denies_packet_socket() {
    assert_blocked("net_socket_packet");
}

#[test]
fn denies_vsock_socket() {
    assert_blocked("net_socket_vsock");
}

#[test]
fn denies_bluetooth_socket() {
    assert_blocked("net_socket_bluetooth");
}

// Probe asserts EAFNOSUPPORT (seccomp) not EACCES (CAP_NET_RAW).
#[test]
fn denies_raw_inet_socket() {
    assert_blocked("net_socket_raw_inet");
}

#[test]
fn denies_pidfd_getfd() {
    assert_blocked("sys_pidfd_getfd");
}

// In unprivileged CI this is trivially green (caps already zero); the
// value is regression detection if restrict_proxy_worker drops a privs
// call, plus real coverage when the suite runs with file caps or sudo.
#[test]
fn drops_all_capabilities() {
    let out = run_probe("caps_zeroed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("BLOCKED: all caps zero"),
        "caps_zeroed did not report zero caps.\nstdout: {stdout}\nstderr: {stderr}"
    );
}

// Seccomp ioctl cmd filter
#[test]
fn denies_tiocsti() {
    assert_blocked("sys_tiocsti");
}

// Seccomp clone flag filter
#[test]
fn denies_clone_newuser() {
    assert_blocked("sys_clone_newuser");
}

// Regression for the clone3 allowance in proxy_restrict: a clone3 with
// CLONE_NEWUSER slips past libseccomp flag filtering, but the inherited
// seccomp filter must still block mount, bpf, and unshare from the new
// namespace.
#[test]
fn clone3_newuser_child_still_blocked() {
    assert_blocked("sys_clone3_newuser_inherits_filter");
}

// Seccomp prctl option filter
#[test]
fn denies_prctl_set_mm() {
    assert_blocked("sys_prctl_set_mm");
}
