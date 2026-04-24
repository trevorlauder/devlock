//! Parent side setup shared between production `main` and the test harness so drift cannot hide
//! bugs like the dumpable or child_mem race.

use crate::seccomp;
use crate::sys;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::io;
use std::os::fd::RawFd;
use std::path::PathBuf;

pub struct SupervisorInputs {
    pub read_only_enforced: Vec<PathBuf>,
    pub allowed_write: Vec<PathBuf>,
    pub allowed_delete: Vec<PathBuf>,
    pub allowed_read: Vec<PathBuf>,
    pub allowed_exec: Vec<PathBuf>,
    pub tunnel_port: u16,
    pub api_port: u16,
    pub clone3_allowed_flags: u64,
    pub handlers: HashMap<i32, crate::policy::seccomp::Handler>,
}

/// Drops dumpable, snapshots /proc/<child>/mem before it closes, receives the notify fd,
/// spawns the supervisor, then releases the child. SIGKILLs the child and closes the socket
/// on any failure.
pub fn activate_supervisor(
    child: Pid,
    parent_sock_fd: RawFd,
    child_sock_fd: RawFd,
    inputs: SupervisorInputs,
) -> io::Result<()> {
    sys::close_fd(child_sock_fd);

    // Must come after fork so the child inherited dumpable=1 long enough for open_child_mem
    // to succeed.
    let _ = nix::sys::prctl::set_dumpable(false);

    let fail = |msg: &str, e: &dyn std::fmt::Display| -> io::Error {
        let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
        sys::close_fd(parent_sock_fd);
        io::Error::other(format!("{msg}. {e}"))
    };

    let child_mem = seccomp::open_child_mem(child.as_raw() as u32)
        .map(Some)
        .map_err(|e| {
            fail(
                &format!(
                    "open /proc/{}/mem before child dropped dumpable",
                    child.as_raw()
                ),
                &e,
            )
        })?;

    let notify_fd =
        seccomp::recv_notify_fd(parent_sock_fd).map_err(|e| fail("receive notify fd", &e))?;

    let supervisor_cfg = seccomp::SupervisorConfig {
        read_only_enforced: inputs.read_only_enforced,
        allowed_write: inputs.allowed_write,
        allowed_delete: inputs.allowed_delete,
        allowed_read: inputs.allowed_read,
        allowed_exec: inputs.allowed_exec,
        tunnel_port: inputs.tunnel_port,
        api_port: inputs.api_port,
        child_pid: child.as_raw() as u32,
        clone3_allowed_flags: inputs.clone3_allowed_flags,
        handlers: inputs.handlers,
        child_mem,
    };
    std::thread::spawn(move || {
        seccomp::run_supervisor(notify_fd, supervisor_cfg);
    });

    seccomp::signal_supervisor_ready(parent_sock_fd).map_err(|e| fail("signal child ready", &e))?;
    sys::close_fd(parent_sock_fd);
    Ok(())
}
