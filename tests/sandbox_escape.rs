//! Spawns the real sandbox around a probe binary and asserts that every
//! known escape attempt is denied. Requires a kernel with Landlock.

use std::process::{Command, Output};

fn run_probe(name: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sandbox-test-runner"))
        .arg(name)
        .env("DEVLOCK_PROBE_BIN", env!("CARGO_BIN_EXE_escape-probe"))
        .output()
        .expect("runner")
}

fn assert_blocked(probe: &str) {
    let out = run_probe(probe);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "probe {probe} was NOT blocked.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("BLOCKED"),
        "probe {probe} did not print BLOCKED marker.\nstdout: {stdout}\nstderr: {stderr}"
    );
}

// Filesystem escape attempts
#[test]
fn denies_writing_to_etc() {
    assert_blocked("fs_write_etc");
}

#[test]
fn denies_reading_shadow() {
    assert_blocked("fs_read_shadow");
}

#[test]
fn denies_stat_shadow() {
    assert_blocked("fs_stat_shadow");
}

#[test]
fn denies_stat_vscode_server() {
    assert_blocked("fs_stat_vscode_server");
}

#[test]
fn denies_writing_to_home_root() {
    assert_blocked("fs_write_home_root");
}

#[test]
fn denies_symlink_escape_to_shadow() {
    assert_blocked("fs_symlink_to_shadow");
}

#[test]
fn denies_traversal_via_proc_self_root() {
    assert_blocked("fs_proc_self_root");
}

#[test]
fn denies_mountinfo_read_via_symlink_leaf() {
    assert_blocked("fs_symlink_to_mountinfo");
}

#[test]
fn denies_hardlinking_passwd_into_cwd() {
    assert_blocked("fs_hardlink_passwd");
}

#[test]
fn denies_writing_vscode_tasks_json() {
    assert_blocked("fs_write_vscode_tasks");
}

#[test]
fn denies_writing_to_read_only_dir() {
    assert_blocked("fs_write_to_read_only_dir");
}

#[test]
fn denies_writing_via_symlink_into_read_only_dir() {
    assert_blocked("fs_symlink_into_read_only_dir");
}

#[test]
fn denies_truncate_via_symlink_into_read_only_dir() {
    assert_blocked("fs_truncate_via_symlink_into_read_only");
}

#[test]
fn supervisor_survives_notify_id_invalidation_race() {
    assert_blocked("sys_notify_id_invalidation_race");
}

#[test]
fn denies_unlink_of_read_only_file() {
    assert_blocked("fs_unlink_read_only_file");
}

#[test]
fn denies_rename_over_read_only_file() {
    assert_blocked("fs_rename_over_read_only_file");
}

// Syscall blocks
#[test]
fn allows_ptrace_traceme() {
    assert_blocked("sys_ptrace_traceme");
}

#[test]
fn denies_unshare_newuser() {
    assert_blocked("sys_unshare_newuser");
}

#[test]
fn denies_bpf() {
    assert_blocked("sys_bpf");
}

#[test]
fn denies_exec_from_memfd() {
    assert_blocked("sys_memfd_exec");
}

#[test]
fn denies_io_uring_setup() {
    assert_blocked("sys_io_uring_setup");
}

#[test]
fn denies_mount() {
    assert_blocked("sys_mount");
}

#[test]
fn denies_mount_setattr() {
    assert_blocked("sys_mount_setattr");
}

#[test]
fn denies_pidfd_open() {
    assert_blocked("sys_pidfd_open");
}

#[test]
fn denies_fsopen() {
    assert_blocked("sys_fsopen");
}

#[test]
fn denies_userfaultfd() {
    assert_blocked("sys_userfaultfd");
}

#[test]
fn denies_perf_event_open() {
    assert_blocked("sys_perf_event_open");
}

#[test]
fn denies_keyctl() {
    assert_blocked("sys_keyctl");
}

#[test]
fn denies_chroot() {
    assert_blocked("sys_chroot");
}

#[test]
fn denies_tiocsti_terminal_injection() {
    assert_blocked("sys_tiocsti");
}

#[test]
fn denies_tiocsti_with_high_bits_set() {
    assert_blocked("sys_tiocsti_high_bits");
}

// Network blocks
#[test]
fn denies_raw_socket() {
    assert_blocked("net_raw_socket");
}

#[test]
fn denies_udp_socket() {
    assert_blocked("net_udp_socket");
}

#[test]
fn denies_netlink_socket() {
    assert_blocked("net_netlink_socket");
}

#[test]
fn denies_packet_socket() {
    assert_blocked("net_packet_socket");
}

#[test]
fn denies_vsock_socket() {
    assert_blocked("net_vsock_socket");
}

#[test]
fn denies_external_tcp_connect() {
    assert_blocked("net_connect_external");
}

#[test]
fn denies_binding_inet_port() {
    assert_blocked("net_bind_inet");
}

// Process information and env isolation
#[test]
fn blocks_reading_parent_environ() {
    assert_blocked("proc_parent_environ");
}

#[test]
fn env_has_no_sensitive_secrets() {
    assert_blocked("env_no_secrets");
}

#[test]
fn denies_opening_proc_self_mem_for_write() {
    assert_blocked("fs_write_proc_self_mem");
}

#[test]
fn denies_renaming_out_of_sandbox() {
    assert_blocked("fs_rename_out_of_cwd");
}

#[test]
fn denies_clone3_with_newuser() {
    assert_blocked("sys_clone3_newuser");
}

#[test]
fn allows_filesystem_af_unix_bind_in_allowed_bucket() {
    // CWD is a full_access bucket for the test agent. Binding a UDS
    // there must succeed so Jupyter/dbus/gRPC UDS flows work.
    assert_blocked("net_af_unix_fs_bind");
}

#[test]
fn denies_filesystem_af_unix_bind_outside_allowed_buckets() {
    // /tmp is NOT in the test agent's writable set. The supervisor must
    // still deny UDS bind there to keep cross-sandbox IPC closed.
    assert_blocked("net_af_unix_fs_bind_outside_allowed");
}

#[test]
fn denies_executing_binary_planted_in_sandbox_tmp() {
    assert_blocked("exec_from_sandbox_tmp");
}

#[test]
fn denies_ptrace_attach_to_parent() {
    assert_blocked("sys_ptrace_attach_parent");
}

#[test]
fn denies_legacy_clone_with_newuser() {
    assert_blocked("sys_clone_newuser");
}

#[test]
fn denies_setxattr_on_etc_host_files() {
    assert_blocked("sys_setxattr_on_etc");
}

#[test]
fn denies_fchmod_through_opened_fd_on_etc() {
    assert_blocked("fs_write_via_fchmod");
}

#[test]
fn denies_swapon_via_default_deny() {
    assert_blocked("sys_swapon");
}

#[test]
fn denies_reboot_via_default_deny() {
    assert_blocked("sys_reboot");
}

#[test]
fn denies_init_module_via_default_deny() {
    assert_blocked("sys_init_module");
}

// TOCTOU / openat2 regression probes for the pinned-dirfd supervisor.
#[test]
fn denies_toctou_symlink_swap_open() {
    assert_blocked("fs_toctou_symlink_swap_open");
}

#[test]
fn denies_toctou_rename_swap() {
    assert_blocked("fs_toctou_rename_swap");
}

#[test]
fn denies_openat2_resolve_beneath_bypass() {
    assert_blocked("fs_openat2_resolve_beneath_bypass");
}

#[test]
fn denies_symlinkat_into_read_only() {
    assert_blocked("fs_symlinkat_into_read_only");
}

#[test]
fn denies_linkat_over_read_only() {
    assert_blocked("fs_linkat_over_read_only");
}

#[test]
fn denies_rename_out_of_read_only() {
    assert_blocked("fs_rename_out_of_read_only");
}

#[test]
fn allows_utimensat_on_writable_path() {
    assert_blocked("fs_utimensat_writable_path");
}

#[test]
fn allows_futimens_on_writable_fd() {
    assert_blocked("fs_futimens_writable_fd");
}

#[test]
fn denies_faccessat2_existence_leak() {
    assert_blocked("fs_faccessat2_existence_leak");
}

#[test]
fn denies_faccessat_existence_leak() {
    assert_blocked("fs_faccessat_existence_leak");
}

#[test]
fn denies_inotify_add_watch_existence_leak() {
    assert_blocked("fs_inotify_add_watch_existence_leak");
}

#[test]
fn denies_open_existence_leak() {
    assert_blocked("fs_open_existence_leak");
}

#[test]
fn denies_signal_to_root_sandbox_pid() {
    assert_blocked("sys_signal_root_sandbox_pid");
}

#[test]
fn denies_af_unix_abstract_bind() {
    assert_blocked("net_af_unix_abstract_bind");
}

#[test]
fn denies_af_unix_abstract_connect() {
    assert_blocked("net_af_unix_abstract_connect");
}

#[test]
fn allows_stat_of_root() {
    assert_blocked("fs_stat_root_allowed");
}

#[test]
fn allows_stat_of_cwd_ancestor() {
    assert_blocked("fs_stat_home_ancestor_allowed");
}

#[test]
fn allows_stat_of_etc_ancestor() {
    assert_blocked("fs_stat_etc_ancestor_allowed");
}
