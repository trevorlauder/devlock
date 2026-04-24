//! Shared YAML loader with extends and includes support. Used by agent
//! and profile policy loading. Composition rules: extends first, then
//! each include in order, then the file itself on top. Lists append,
//! maps upsert, scalars from the outer file win.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

pub fn load_and_merge(
    path: &Path,
    root: &Path,
    visited: &mut HashSet<PathBuf>,
) -> io::Result<serde_norway::Value> {
    let canon = path
        .canonicalize()
        .map_err(|e| io::Error::new(e.kind(), format!("unable to read {}: {e}", path.display())))?;
    // Refuse extends or includes that resolve outside the policy tree, so a
    // compromised partial cannot pull in arbitrary host files.
    let root_canon = root
        .canonicalize()
        .map_err(|e| io::Error::new(e.kind(), format!("policy root unreachable: {e}")))?;
    if !canon.starts_with(&root_canon) {
        return Err(io::Error::other(format!(
            "{} resolves outside policy root {}",
            canon.display(),
            root_canon.display()
        )));
    }
    if !visited.insert(canon.clone()) {
        return Err(io::Error::other(format!(
            "extends cycle at {}",
            canon.display()
        )));
    }
    // `visited` tracks the active recursion stack, not all files seen in the
    // whole load. A file that appears twice through different include branches
    // is legal and should not be treated as a cycle.
    let result = (|| -> io::Result<serde_norway::Value> {
        let raw = std::fs::read_to_string(&canon).map_err(|e| {
            io::Error::new(e.kind(), format!("unable to read {}: {e}", canon.display()))
        })?;
        let mut doc: serde_norway::Value = serde_norway::from_str(&raw)
            .map_err(|e| io::Error::other(format!("{}: {e}", canon.display())))?;

        let extends_key: serde_norway::Value = "extends".into();
        let includes_key: serde_norway::Value = "includes".into();
        let extends = doc.as_mapping_mut().and_then(|m| m.remove(&extends_key));
        let includes = doc.as_mapping_mut().and_then(|m| m.remove(&includes_key));

        let parent: Option<String> = match extends {
            None => None,
            Some(serde_norway::Value::String(s)) => Some(s),
            Some(_) => {
                return Err(io::Error::other(format!(
                    "{}: extends must be a single path string",
                    canon.display()
                )));
            }
        };
        let include_paths: Vec<String> = match includes {
            None => Vec::new(),
            Some(serde_norway::Value::Sequence(seq)) => seq
                .into_iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Some(_) => {
                return Err(io::Error::other(format!(
                    "{}: includes must be a list of path strings",
                    canon.display()
                )));
            }
        };
        // Reject absolute paths and explicit .. segments up front. The canonical
        // starts_with check above catches symlink tricks; these rules also stop
        // surprises before any fs access.
        for p in parent.iter().chain(include_paths.iter()) {
            let candidate = Path::new(p);
            if candidate.is_absolute()
                || candidate
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(io::Error::other(format!(
                    "{}: extends/includes path must be relative and not use ..: {p}",
                    canon.display()
                )));
            }
        }

        let base_dir = canon.parent().unwrap_or(Path::new("")).to_path_buf();
        let mut acc = serde_norway::Value::Null;
        if let Some(rel) = parent {
            let parent_path = base_dir.join(&rel);
            acc = merge_values(acc, load_and_merge(&parent_path, root, visited)?);
        }
        for rel in include_paths {
            let included_path = base_dir.join(&rel);
            acc = merge_values(acc, load_and_merge(&included_path, root, visited)?);
        }
        Ok(merge_values(acc, doc))
    })();
    visited.remove(&canon);
    result
}

/// Append-only merge: lists concatenate, maps upsert, scalars overwritten by
/// overlay, nulls replaced.
pub fn merge_values(
    base: serde_norway::Value,
    overlay: serde_norway::Value,
) -> serde_norway::Value {
    use serde_norway::Value;
    match (base, overlay) {
        (Value::Null, o) => o,
        (b, Value::Null) => b,
        (Value::Mapping(mut bm), Value::Mapping(om)) => {
            for (k, v) in om {
                let merged = match bm.remove(&k) {
                    Some(bv) => merge_values(bv, v),
                    None => v,
                };
                bm.insert(k, merged);
            }
            Value::Mapping(bm)
        }
        (Value::Sequence(mut bs), Value::Sequence(os)) => {
            bs.extend(os);
            Value::Sequence(bs)
        }
        (_, o) => o,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(s: &str) -> serde_norway::Value {
        serde_norway::from_str(s).expect("parse yaml")
    }

    #[test]
    fn merge_overlay_scalar_wins() {
        let base = yaml("executable: a\n");
        let overlay = yaml("executable: b\n");
        let out = merge_values(base, overlay);
        assert_eq!(out["executable"].as_str(), Some("b"));
    }

    #[test]
    fn merge_list_append() {
        let base = yaml("network_allowlist: [a.com]\n");
        let overlay = yaml("network_allowlist: [b.com]\n");
        let out = merge_values(base, overlay);
        let seq = out["network_allowlist"].as_sequence().unwrap();
        assert_eq!(seq.len(), 2);
    }

    #[test]
    fn merge_map_recursive_upsert() {
        let base = yaml("tunnel: { max_per_host: 8, idle_timeout_secs: 30 }\n");
        let overlay = yaml("tunnel: { max_per_host: 16 }\n");
        let out = merge_values(base, overlay);
        assert_eq!(out["tunnel"]["max_per_host"].as_u64(), Some(16));
        assert_eq!(out["tunnel"]["idle_timeout_secs"].as_u64(), Some(30));
    }

    #[test]
    fn extends_absolute_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("agents")).unwrap();
        std::fs::write(dir.path().join("agents/a.yaml"), "extends: /etc/passwd\n").unwrap();
        let mut v = HashSet::new();
        let err =
            load_and_merge(&dir.path().join("agents/a.yaml"), dir.path(), &mut v).unwrap_err();
        assert!(err.to_string().contains("relative"), "{err}");
    }

    #[test]
    fn extends_parent_dir_escape_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("agents")).unwrap();
        std::fs::write(
            dir.path().join("agents/a.yaml"),
            "extends: ../../../etc/hostname\n",
        )
        .unwrap();
        let mut v = HashSet::new();
        let err =
            load_and_merge(&dir.path().join("agents/a.yaml"), dir.path(), &mut v).unwrap_err();
        assert!(
            err.to_string().contains("relative") || err.to_string().contains("outside"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_include_via_parent_is_not_cycle() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("agents")).unwrap();
        std::fs::write(
            dir.path().join("agents/partial.yaml"),
            "network_allowlist: [a.example]\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("agents/base.yaml"),
            "includes: [partial.yaml]\nexecutable: base\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("agents/child.yaml"),
            "extends: base.yaml\nincludes: [partial.yaml]\n",
        )
        .unwrap();

        let mut visited = HashSet::new();
        let merged = load_and_merge(
            &dir.path().join("agents/child.yaml"),
            dir.path(),
            &mut visited,
        )
        .expect("duplicate include through parent should not be treated as a cycle");
        let seq = merged["network_allowlist"]
            .as_sequence()
            .expect("network_allowlist should merge as sequence");
        assert_eq!(seq.len(), 2);
    }
}
