use std::fs::{OpenOptions, Permissions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use tempfile::{Builder, TempDir};

/// Create the per run devlock scratch directory. The caller owns the
/// returned `TempDir` so its `Drop` cleans the tree up after the agent
/// exits, even on panic. The directory is mode 0700 and seeded with an
/// empty `.zshrc` so zsh does not fall back to the user's real startup
/// files when `ZDOTDIR` points here.
pub fn create_devlock_tmp_dir() -> anyhow::Result<TempDir> {
    let dir = Builder::new()
        .prefix("scratch-")
        .tempdir_in(crate::sys::devlock_runtime_root()?)?;
    std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700))?;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(dir.path().join(".zshrc"))?;
    Ok(dir)
}
