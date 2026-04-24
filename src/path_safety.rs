//! Small path-sanitizer helpers used wherever a path derives from an
//! untrusted source (env vars, policy, syscall arguments). Each helper
//! canonicalizes, bounds the result to an allowlisted root, and rejects
//! traversal in any user-supplied tail component. CodeQL recognizes the
//! canonicalize + starts_with + reject-traversal pattern as a sanitizer
//! for rust/path-injection.

use std::io;
use std::path::{Component, Path, PathBuf};

fn invalid<S: Into<String>>(msg: S) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

fn permission_denied<S: Into<String>>(msg: S) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg.into())
}

/// Fail if `component` is empty, absolute, contains a path separator, or
/// contains `..`. Intended for a single path segment supplied by code
/// that sits next to untrusted input.
pub fn reject_traversal(component: &str) -> io::Result<&str> {
    if component.is_empty() {
        return Err(invalid("empty path component"));
    }
    if component.contains('/') || component.contains('\\') {
        return Err(invalid("path component contains a separator"));
    }
    // Reject ASCII control bytes (NUL, CR, LF, TAB, DEL, etc.) so a
    // path segment cannot smuggle line splits into a log line or a NUL
    // truncation into downstream C string APIs.
    if component.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(invalid("path component contains a control character"));
    }
    for comp in Path::new(component).components() {
        if matches!(
            comp,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(invalid("path component escapes its parent"));
        }
    }
    Ok(component)
}

/// Canonicalize `p`, then fail unless the result starts with one of
/// `allowed_roots` (also canonicalized). The returned path is absolute
/// and free of `..`/symlink components.
pub fn safe_canonical_under(p: &Path, allowed_roots: &[&Path]) -> io::Result<PathBuf> {
    let canonical = std::fs::canonicalize(p)?;
    for root in allowed_roots {
        if let Ok(root_c) = std::fs::canonicalize(root)
            && canonical.starts_with(&root_c)
        {
            return Ok(canonical);
        }
    }
    Err(permission_denied(format!(
        "{} is not inside an allowed root",
        canonical.display()
    )))
}

/// Canonicalize `base`, require it to fall within `allowed_roots`, and
/// return `canonical_base.join(suffix)` after rejecting traversal in the
/// suffix. `suffix` is a single path component.
pub fn safe_join_under(base: &Path, allowed_roots: &[&Path], suffix: &str) -> io::Result<PathBuf> {
    reject_traversal(suffix)?;
    let canonical = safe_canonical_under(base, allowed_roots)?;
    Ok(canonical.join(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_component() {
        reject_traversal("seccomp.log").unwrap();
    }

    #[test]
    fn rejects_empty() {
        assert!(reject_traversal("").is_err());
    }

    #[test]
    fn rejects_separator() {
        assert!(reject_traversal("a/b").is_err());
        assert!(reject_traversal("a\\b").is_err());
    }

    #[test]
    fn rejects_parent_and_root() {
        assert!(reject_traversal("..").is_err());
        assert!(reject_traversal("/abs").is_err());
    }

    #[test]
    fn rejects_nul_byte() {
        assert!(reject_traversal("name\0payload").is_err());
    }

    #[test]
    fn rejects_newline_and_cr() {
        assert!(reject_traversal("name\nsplit").is_err());
        assert!(reject_traversal("name\rsplit").is_err());
    }

    #[test]
    fn rejects_tab_and_del() {
        assert!(reject_traversal("name\tx").is_err());
        assert!(reject_traversal("name\x7fx").is_err());
    }
}
