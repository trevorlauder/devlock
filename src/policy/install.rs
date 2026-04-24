//! Resolve the effective policy directory for a running `devlock`.
//!
//! Layering (highest to lowest precedence):
//! 1. `DEVLOCK_POLICY_DIR` env var (used verbatim; overlay skipped).
//! 2. Files under `~/.config/devlock/policy/` that shadow bundled ones.
//! 3. Bundled defaults baked into the binary via `include_dir!`.
//!
//! At startup the bundled tree is materialized to a temp dir, then any
//! user files are copied on top at matching relative paths, and that
//! temp dir is handed to the loader. The `TempDir` is held for the
//! process lifetime so the overlay is torn down at exit.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tempfile::TempDir;

use super::bundled;

struct OverlayState {
    #[allow(dead_code)]
    dir: TempDir,
    canonical: PathBuf,
}

static OVERLAY: Mutex<Option<OverlayState>> = Mutex::new(None);

/// Tear down the materialized overlay. Safe to call once all policy files
/// have been read into memory. Rust statics do not Drop at process exit,
/// so without this the overlay dir would leak until logout (systemd
/// wipes `$XDG_RUNTIME_DIR` then). No-op when the env-pointed dev path
/// is in use or when cleanup has already run.
pub fn cleanup() {
    if let Ok(mut guard) = OVERLAY.lock() {
        *guard = None;
    }
}

/// RAII guard that runs `cleanup` on drop. Holds the overlay dir alive
/// only for the span where policy YAML is still being read; drop it once
/// the in-memory policy is assembled so even an early `?` return on a
/// subsequent error path does not strand the overlay in
/// `$XDG_RUNTIME_DIR/devlock`.
pub struct OverlayGuard;

impl Drop for OverlayGuard {
    fn drop(&mut self) {
        cleanup();
    }
}

pub fn effective_policy_dir() -> io::Result<PathBuf> {
    if let Some(from_env) = policy_dir_from_env()? {
        return Ok(from_env);
    }

    let mut guard = OVERLAY
        .lock()
        .map_err(|e| io::Error::other(format!("{e}")))?;
    if let Some(state) = guard.as_ref() {
        return Ok(state.canonical.clone());
    }

    let dir = tempfile::Builder::new()
        .prefix("policy-")
        .tempdir_in(crate::sys::devlock_runtime_root()?)?;
    build_overlay_into(user_policy_dir().as_deref(), dir.path())?;
    let canonical = std::fs::canonicalize(dir.path())?;
    *guard = Some(OverlayState {
        dir,
        canonical: canonical.clone(),
    });
    Ok(canonical)
}

fn policy_dir_from_env() -> io::Result<Option<PathBuf>> {
    let Ok(d) = std::env::var("DEVLOCK_POLICY_DIR") else {
        return Ok(None);
    };
    let candidate = PathBuf::from(&d);
    if let Ok(canonical) = std::fs::canonicalize(&candidate)
        && canonical.is_dir()
    {
        return Ok(Some(canonical));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("DEVLOCK_POLICY_DIR {d} is not a directory"),
    ))
}

fn user_policy_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|c| c.join("devlock").join("policy"))
}

/// Materialize bundled files into `dest`, then overlay any files from
/// `user_dir` on top at matching relative paths. Testable pure function.
fn build_overlay_into(user_dir: Option<&Path>, dest: &Path) -> io::Result<()> {
    bundled::materialize_to(dest)?;
    if let Some(user) = user_dir
        && user.is_dir()
    {
        overlay_tree(user, dest)?;
    }
    Ok(())
}

fn overlay_tree(src: &Path, dest: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = dest.join(entry.file_name());
        if file_type.is_dir() {
            std::fs::create_dir_all(&target)?;
            overlay_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(entry.path(), &target)?;
        }
        // Symlinks under the user dir are skipped. The yaml loader's
        // canonical-root guard would reject any escape anyway.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_materializes_known_files() {
        let dest = tempfile::tempdir().unwrap();
        build_overlay_into(None, dest.path()).unwrap();
        assert!(dest.path().join("agents/claude.yaml").exists());
        assert!(dest.path().join("profiles/base.yaml").exists());
        assert!(dest.path().join("profiles/default.yaml").exists());
        assert!(dest.path().join("profiles/partials/git.yaml").exists());
    }

    #[test]
    fn user_profile_shadows_bundled() {
        let user = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(user.path().join("profiles")).unwrap();
        std::fs::write(
            user.path().join("profiles/default.yaml"),
            "includes: [base.yaml]\nnetwork_allowlist: [custom-override.example]\n",
        )
        .unwrap();

        let dest = tempfile::tempdir().unwrap();
        build_overlay_into(Some(user.path()), dest.path()).unwrap();

        let got = std::fs::read_to_string(dest.path().join("profiles/default.yaml")).unwrap();
        assert!(
            got.contains("custom-override.example"),
            "user file should win"
        );
        // Bundled base must still be present so the include resolves.
        assert!(dest.path().join("profiles/base.yaml").exists());
    }

    #[test]
    fn user_partial_shadows_bundled_partial() {
        let user = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(user.path().join("profiles/partials")).unwrap();
        std::fs::write(
            user.path().join("profiles/partials/git.yaml"),
            "# custom git partial\n",
        )
        .unwrap();

        let dest = tempfile::tempdir().unwrap();
        build_overlay_into(Some(user.path()), dest.path()).unwrap();

        let got = std::fs::read_to_string(dest.path().join("profiles/partials/git.yaml")).unwrap();
        assert_eq!(got, "# custom git partial\n");
    }

    #[test]
    fn overlay_guard_drop_removes_tempdir() {
        // Seed the static overlay via effective_policy_dir so the guard's
        // Drop has something to tear down. Without this, a later `?` return
        // from `main` leaves a `policy-*` tempdir stranded in $XDG_RUNTIME_DIR.
        let path = effective_policy_dir().expect("overlay install");
        assert!(path.exists(), "overlay dir must exist while guard lives");
        {
            let _g = OverlayGuard;
        }
        assert!(
            !path.exists(),
            "OverlayGuard must remove the materialized overlay on drop"
        );
    }

    #[test]
    fn user_novel_file_is_copied() {
        let user = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(user.path().join("agents")).unwrap();
        std::fs::write(
            user.path().join("agents/custom.yaml"),
            "executable: custom\n",
        )
        .unwrap();

        let dest = tempfile::tempdir().unwrap();
        build_overlay_into(Some(user.path()), dest.path()).unwrap();

        let got = std::fs::read_to_string(dest.path().join("agents/custom.yaml")).unwrap();
        assert_eq!(got, "executable: custom\n");
    }
}
