use std::io;
use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Base dir for devlock ephemeral runtime state (policy overlay, agent scratch).
///
/// Prefers `$XDG_RUNTIME_DIR` which systemd exposes as `/run/user/<uid>/` —
/// mode 0700 on the whole tree, per-UID isolated, wiped at logout. Falls
/// back to `std::env::temp_dir()` on macOS and non-systemd Linux where
/// `$XDG_RUNTIME_DIR` is unavailable. Creates the `devlock` subdirectory
/// and chmods it to 0700 defensively.
pub fn devlock_runtime_root() -> io::Result<PathBuf> {
    let base = dirs::runtime_dir().unwrap_or_else(std::env::temp_dir);
    let dir = base.join("devlock");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

/// Base dir for devlock logs. Unlike the runtime root, this survives
/// logout so developers can inspect logs from prior sessions.
/// Uses `$XDG_STATE_HOME` (`~/.local/state`) per the XDG spec; falls
/// back to `~/.local/state` or the temp dir if neither is available.
pub fn devlock_logs_root() -> io::Result<PathBuf> {
    let base = dirs::state_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".local").join("state")))
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("devlock").join("logs");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

/// Close a raw fd owned by the caller.
pub fn close_fd(fd: RawFd) {
    // SAFETY: caller owns the fd and knows that close invalidates it.
    unsafe {
        libc::close(fd);
    }
}

/// Generate `n_bytes` of cryptographic random data and return it as a
/// lowercase hex string of length `2 * n_bytes`.
pub fn random_hex(n_bytes: usize) -> anyhow::Result<String> {
    let mut bytes = vec![0u8; n_bytes];
    getrandom::fill(&mut bytes)
        .map_err(|e| anyhow::anyhow!("failed to generate random bytes: {e}"))?;
    Ok(hex::encode(bytes))
}
