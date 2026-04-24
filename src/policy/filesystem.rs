//! Loads a profile from policy/profiles/<name>.yaml at runtime. Paths feed
//! both Landlock and the seccomp supervisor. Profiles compose with extends
//! and includes. Vars: $CWD, $TMP_DIR. Tilde expands to $HOME.

use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawFilesystemPolicy {
    #[serde(default)]
    pub paths: super::agent::PathBundle,
    /// Directories prepended to the child's PATH. Listed roughly in priority
    /// order; later profiles' entries append after earlier ones.
    #[serde(default)]
    pub path_prepend: Vec<String>,
    /// Domain patterns the proxy allows outbound. Merges with the agent's
    /// own network_allowlist at runtime.
    #[serde(default)]
    pub network_allowlist: Vec<String>,
    /// Env vars set for the child shell. Applied at the same precedence
    /// as devlock's hardcoded shell defaults: above them but below
    /// passthrough/agent/locked. Values go through $VAR / ~/ expansion.
    /// Base-level: applies to every agent regardless of profile.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
}

pub struct Vars<'a> {
    pub home: &'a Path,
    pub cwd: &'a Path,
    pub tmp_dir: &'a Path,
}

pub fn load(profile: &str) -> io::Result<RawFilesystemPolicy> {
    let dir = super::agent::policy_dir()?;
    load_from(&dir, profile)
}

pub fn load_from(dir: &Path, profile: &str) -> io::Result<RawFilesystemPolicy> {
    let path = dir.join("profiles").join(format!("{profile}.yaml"));
    let mut visited = std::collections::HashSet::new();
    let merged = super::yaml_merge::load_and_merge(&path, dir, &mut visited)?;
    let policy: RawFilesystemPolicy = serde_norway::from_value(merged)
        .map_err(|e| io::Error::other(format!("{}: {e}", path.display())))?;
    validate_buckets(&policy).map_err(|e| io::Error::other(format!("{}: {e}", path.display())))?;
    Ok(policy)
}

/// Reject bucket conflicts where a write grant sits at or below a
/// read_only path. Flags equality and the "write carved inside a
/// read_only region" case (e.g. `read_only: ~/.config` with
/// `read_write: ~/.config/app`). The reverse, a read_only inside a
/// wider write grant, is intentional: the supervisor enforces the
/// narrower read_only at runtime, which is how `full_access: $CWD` plus
/// `read_only: $CWD/.git/config` works. Compares by path components so
/// sibling paths sharing a string prefix do not collide.
fn validate_buckets(p: &RawFilesystemPolicy) -> Result<(), String> {
    let write: [(&str, &[String]); 3] = [
        ("full_access", &p.paths.full_access),
        ("read_write", &p.paths.read_write),
        ("dir_create", &p.paths.dir_create),
    ];
    for ro in &p.paths.read_only {
        for (wn, wlist) in &write {
            if let Some(w) = wlist.iter().find(|w| write_inside_readonly(ro, w)) {
                return Err(format!(
                    "bucket conflict: {w:?} in {wn} sits inside read_only {ro:?}. \
                     A write grant cannot be carved inside a protected path."
                ));
            }
        }
    }
    Ok(())
}

/// True if `write` equals `ro` or is a component descendant of it.
fn write_inside_readonly(ro: &str, write: &str) -> bool {
    let pro = Path::new(ro.trim_end_matches('/'));
    let pw = Path::new(write.trim_end_matches('/'));
    pw.starts_with(pro)
}

pub fn resolve(policy: &RawFilesystemPolicy, vars: &Vars<'_>) -> ResolvedPaths {
    let p = &policy.paths;
    let full_access = expand_all(&p.full_access, vars);
    let read_exec = expand_all(&p.read_exec, vars);
    let read_list = expand_all(&p.read_list, vars);
    let dir_create = expand_all(&p.dir_create, vars);
    let read_write = expand_all(&p.read_write, vars);
    let read_only = expand_all(&p.read_only, vars);
    let path_prepend: Vec<PathBuf> = expand_all(&policy.path_prepend, vars)
        .into_iter()
        .filter(|p| p.exists())
        .collect();
    let env: Vec<(String, String)> = policy
        .env
        .iter()
        .map(|(k, v)| (k.clone(), expand(v, vars).to_string_lossy().into_owned()))
        .collect();

    ResolvedPaths {
        full_access,
        read_exec,
        read_list,
        dir_create,
        read_write,
        read_only,
        path_prepend,
        network_allowlist: policy.network_allowlist.clone(),
        env,
    }
}

#[derive(Debug)]
pub struct ResolvedPaths {
    pub full_access: Vec<PathBuf>,
    pub read_exec: Vec<PathBuf>,
    pub read_list: Vec<PathBuf>,
    pub dir_create: Vec<PathBuf>,
    pub read_write: Vec<PathBuf>,
    pub read_only: Vec<PathBuf>,
    pub path_prepend: Vec<PathBuf>,
    pub network_allowlist: Vec<String>,
    pub env: Vec<(String, String)>,
}

fn expand_all(entries: &[String], vars: &Vars<'_>) -> Vec<PathBuf> {
    entries.iter().map(|s| expand(s, vars)).collect()
}

fn expand(raw: &str, vars: &Vars<'_>) -> PathBuf {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            let name: String = std::iter::from_fn(|| {
                chars
                    .peek()
                    .and_then(|c| {
                        c.is_ascii_alphanumeric()
                            .then_some(*c)
                            .or_else(|| (*c == '_').then_some(*c))
                    })
                    .map(|_| chars.next().unwrap())
            })
            .collect();
            match name.as_str() {
                "CWD" => out.push_str(&vars.cwd.to_string_lossy()),
                "TMP_DIR" => out.push_str(&vars.tmp_dir.to_string_lossy()),
                other => {
                    out.push('$');
                    out.push_str(other);
                }
            }
        } else if c == '~' && chars.peek() == Some(&'/') {
            out.push_str(&vars.home.to_string_lossy());
        } else {
            out.push(c);
        }
    }
    PathBuf::from(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_parses() {
        let dir = tempfile::tempdir().unwrap();
        super::super::bundled::materialize_to(dir.path()).unwrap();
        let p = load_from(dir.path(), "default").expect("bundled profiles/default.yaml must load");
        assert!(!p.paths.full_access.is_empty());
    }

    #[test]
    fn default_profile_includes_git_protections() {
        let dir = tempfile::tempdir().unwrap();
        super::super::bundled::materialize_to(dir.path()).unwrap();
        let p = load_from(dir.path(), "default").expect("bundled profiles/default.yaml must load");
        assert!(p.paths.read_only.contains(&"$CWD/.git/config".to_string()));
        assert!(p.paths.read_only.contains(&"$CWD/.git/hooks".to_string()));
    }

    #[test]
    fn default_profile_includes_vscode_protections() {
        let dir = tempfile::tempdir().unwrap();
        super::super::bundled::materialize_to(dir.path()).unwrap();
        let p = load_from(dir.path(), "default").expect("bundled profiles/default.yaml must load");
        assert!(p.paths.read_only.contains(&"$CWD/.vscode".to_string()));
    }

    #[test]
    fn security_probe_profile_parses() {
        let dir = tempfile::tempdir().unwrap();
        super::super::bundled::materialize_to(dir.path()).unwrap();
        let _ = load_from(dir.path(), "security-probe")
            .expect("bundled profiles/security-probe.yaml must load");
    }

    #[test]
    fn github_partial_does_not_grant_hosts_yml() {
        let dir = tempfile::tempdir().unwrap();
        super::super::bundled::materialize_to(dir.path()).unwrap();
        std::fs::write(
            dir.path().join("profiles").join("github-test.yaml"),
            "includes: [partials/github.yaml]\n",
        )
        .unwrap();
        let p = load_from(dir.path(), "github-test")
            .expect("test profile including github partial should load");
        assert!(
            p.paths
                .read_only
                .contains(&"~/.config/gh/config.yml".to_string())
        );
        assert!(
            !p.paths
                .read_only
                .contains(&"~/.config/gh/hosts.yml".to_string())
        );
    }

    #[test]
    fn bucket_conflict_write_inside_readonly_is_rejected() {
        let p = RawFilesystemPolicy {
            paths: super::super::agent::PathBundle {
                read_only: vec!["~/.config".into()],
                read_write: vec!["~/.config/app".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_buckets(&p).expect_err("write inside read_only must fail");
        assert!(err.contains("inside read_only"), "{err}");
    }

    #[test]
    fn bucket_conflict_equal_path_is_rejected() {
        let p = RawFilesystemPolicy {
            paths: super::super::agent::PathBundle {
                read_only: vec!["~/.config".into()],
                full_access: vec!["~/.config".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        validate_buckets(&p).expect_err("equal paths in read_only and full_access must fail");
    }

    #[test]
    fn readonly_inside_write_is_allowed() {
        let p = RawFilesystemPolicy {
            paths: super::super::agent::PathBundle {
                full_access: vec!["$CWD".into()],
                read_only: vec!["$CWD/.git/config".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        validate_buckets(&p).expect("supervisor-enforced read_only inside a write grant is fine");
    }

    #[test]
    fn sibling_with_string_prefix_is_not_a_conflict() {
        let p = RawFilesystemPolicy {
            paths: super::super::agent::PathBundle {
                read_only: vec!["~/.config".into()],
                read_write: vec!["~/.configapp".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        validate_buckets(&p).expect("component prefix must not confuse siblings");
    }

    #[test]
    fn expand_substitutes_known_variables() {
        let home = PathBuf::from("/home/u");
        let cwd = PathBuf::from("/repo");
        let tmp = PathBuf::from("/tmp/x");
        let v = Vars {
            home: &home,
            cwd: &cwd,
            tmp_dir: &tmp,
        };
        assert_eq!(
            expand("$HOME/.gitconfig", &v),
            PathBuf::from("$HOME/.gitconfig")
        );
        assert_eq!(expand("$CWD", &v), PathBuf::from("/repo"));
        assert_eq!(expand("$TMP_DIR/foo", &v), PathBuf::from("/tmp/x/foo"));
        assert_eq!(
            expand("~/.gitconfig", &v),
            PathBuf::from("/home/u/.gitconfig")
        );
        assert_eq!(expand("/usr", &v), PathBuf::from("/usr"));
    }
}
