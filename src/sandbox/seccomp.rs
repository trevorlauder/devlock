use std::os::fd::RawFd;

pub fn install_seccomp_notify(notify_sock: RawFd) -> anyhow::Result<()> {
    let notify_fd = crate::seccomp::install()?;

    if let Err(e) = crate::seccomp::send_notify_fd(notify_sock, notify_fd) {
        crate::sys::close_fd(notify_fd);
        crate::sys::close_fd(notify_sock);
        return Err(e.into());
    }

    // Block until the parent confirms the supervisor thread has been
    // spawned. Without this the child can exec and start firing notify
    // syscalls before the supervisor is ready to receive; the kernel
    // queues them correctly, but verify() probes take seconds if
    // answered by a not-yet-scheduled thread. If the read returns 0 or
    // errors, the parent died between fork and supervisor start, and
    // the child must not proceed.
    if let Err(e) = crate::seccomp::wait_for_supervisor_ready(notify_sock) {
        crate::sys::close_fd(notify_fd);
        crate::sys::close_fd(notify_sock);
        return Err(e.into());
    }

    crate::sys::close_fd(notify_fd);
    crate::sys::close_fd(notify_sock);
    Ok(())
}
