use crate::agent::Agent;
use crate::policy::filesystem::{self, Vars};
use std::env;
use std::path::{Path, PathBuf};

pub struct ResolvedPaths {
    pub full_access: Vec<PathBuf>,
    pub read_exec: Vec<PathBuf>,
    pub read_list: Vec<PathBuf>,
    pub dir_create: Vec<PathBuf>,
    pub read_write: Vec<PathBuf>,
    pub read_only: Vec<PathBuf>,
    pub path_prepend: Vec<PathBuf>,
    pub network_allowlist: Vec<String>,
    pub base_env: Vec<(String, String)>,
}

impl ResolvedPaths {
    /// Write-allowed paths for seccomp: full_access + read_write + dir_create.
    pub fn seccomp_write(&self) -> Vec<PathBuf> {
        let mut paths = self.full_access.to_vec();
        paths.extend_from_slice(&self.read_write);
        paths.extend_from_slice(&self.dir_create);
        paths
    }

    /// Delete-allowed paths for seccomp: full_access + read_write only.
    /// dir_create is add-only, so unlink/rename-over must live under a
    /// bucket that explicitly grants delete.
    pub fn seccomp_delete(&self) -> Vec<PathBuf> {
        let mut paths = self.full_access.to_vec();
        paths.extend_from_slice(&self.read_write);
        paths
    }

    /// Read-allowed paths for seccomp: every bucket that grants reads at
    /// the Landlock layer (full_access, read_write, dir_create via write
    /// grants, plus read_exec, read_list, and read_only).
    pub fn seccomp_read(&self) -> Vec<PathBuf> {
        let mut paths = self.seccomp_write();
        paths.extend(self.read_exec.iter().cloned());
        paths.extend(self.read_list.iter().cloned());
        paths.extend(self.read_only.iter().cloned());
        paths
    }

    /// Exec-allowed paths for seccomp: full_access + read_exec.
    pub fn seccomp_exec(&self) -> Vec<PathBuf> {
        let mut paths = self.full_access.to_vec();
        paths.extend(self.read_exec.iter().cloned());
        paths
    }
}

pub fn collect_paths(
    agent: &dyn Agent,
    config: &crate::config::Config,
    home: &Path,
    tmp_dir: Option<&Path>,
    profile: &str,
) -> anyhow::Result<ResolvedPaths> {
    let expand_home = |p: &str| -> PathBuf {
        p.strip_prefix("~/")
            .map_or_else(|| PathBuf::from(p), |rest| home.join(rest))
    };

    let cwd = env::current_dir()?;
    // The base policy expects a concrete tmp_dir; tests sometimes pass
    // None. Use the current tmp_dir for substitution when unavailable,
    // which is an uncreated placeholder but still a valid path string.
    let placeholder_tmp;
    let tmp_path = match tmp_dir {
        Some(t) => t,
        None => {
            placeholder_tmp = env::temp_dir().join("devlock-unused");
            &placeholder_tmp
        }
    };

    let policy = filesystem::load(profile)?;
    let vars = Vars {
        home,
        cwd: &cwd,
        tmp_dir: tmp_path,
    };
    let base = filesystem::resolve(&policy, &vars);

    let mut agent_paths = agent.paths(home);

    // When tmp_dir is None (collect_paths is called pre fork to compute
    // seccomp lists before the tmp dir exists), drop the $TMP_DIR entry
    // from full_access so we don't record an imaginary path.
    let mut full_access: Vec<PathBuf> = if tmp_dir.is_some() {
        base.full_access
    } else {
        base.full_access
            .into_iter()
            .filter(|p| p != tmp_path)
            .collect()
    };
    full_access.extend(agent_paths.full_access);

    let mut read_exec = base.read_exec;
    read_exec.extend(agent_paths.read_exec);
    read_exec.extend(config.read_exec_paths.iter().map(|p| expand_home(p)));

    let read_list = base.read_list;

    let mut read_write = base.read_write;
    read_write.append(&mut agent_paths.read_write);

    let mut read_only = base.read_only;
    read_only.append(&mut agent_paths.read_only);
    read_only.extend(config.read_only_paths.iter().map(|p| expand_home(p)));

    let mut dir_create = base.dir_create;
    dir_create.append(&mut agent_paths.dir_create);

    Ok(ResolvedPaths {
        full_access,
        read_exec,
        read_list,
        dir_create,
        read_write,
        read_only,
        path_prepend: base.path_prepend,
        network_allowlist: base.network_allowlist,
        base_env: base.env,
    })
}

pub struct InspectContext<'a> {
    pub agent: &'a dyn Agent,
    pub agent_name: &'a str,
    pub profile_name: &'a str,
    pub tunnel_port: u16,
    pub api_port: u16,
    pub home: &'a Path,
    pub tmp_dir: &'a Path,
    pub allowlist: &'a [String],
    pub paths: &'a ResolvedPaths,
}

pub fn log_resolved_config(ctx: &InspectContext<'_>) {
    let InspectContext {
        agent,
        agent_name,
        profile_name,
        tunnel_port,
        api_port,
        home,
        tmp_dir,
        allowlist,
        paths,
    } = *ctx;
    fn print_paths<P: AsRef<Path>>(label: &str, ps: &[P]) {
        eprintln!("  {label}:");
        for p in ps {
            eprintln!("    {}", p.as_ref().display());
        }
    }
    fn print_strings(label: &str, items: &[String]) {
        eprintln!("  {label}:");
        for item in items {
            eprintln!("    {item}");
        }
    }

    eprintln!("Agent: {agent_name}");
    eprintln!("  executable: {}", agent.executable().display());
    if let Some(p) = agent.inaccessible_path() {
        eprintln!(
            "  credentials file (inaccessible to agent): {}",
            p.display()
        );
    }
    let env = agent.env_vars(home, tmp_dir, tunnel_port, api_port, "<session-token>");
    if !env.is_empty() {
        eprintln!("  env:");
        for (k, v) in &env {
            eprintln!("    {k}={v}");
        }
    }
    let args = agent.extra_args(tmp_dir);
    if !args.is_empty() {
        eprintln!("  extra args:");
        for a in &args {
            eprintln!("    {a}");
        }
    }

    eprintln!("Profile: {profile_name}");
    print_paths("full_access", &paths.full_access);
    print_paths("read_exec", &paths.read_exec);
    print_paths("read_list", &paths.read_list);
    print_paths("read_only", &paths.read_only);
    print_paths("read_write", &paths.read_write);
    print_paths("dir_create", &paths.dir_create);
    print_paths("path_prepend", &paths.path_prepend);
    if !paths.base_env.is_empty() {
        eprintln!("  env:");
        for (k, v) in &paths.base_env {
            eprintln!("    {k}={v}");
        }
    }

    eprintln!("Network:");
    eprintln!("  TCP connect (loopback only): tunnel port {tunnel_port}, api port {api_port}");
    eprintln!("  Scopes: abstract Unix sockets, signals");
    print_strings("allowed domains", allowlist);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{Agent, AgentCredentials, AgentPaths};

    struct FakeAgent {
        paths: fn(&Path) -> AgentPaths,
    }

    impl FakeAgent {
        fn new() -> Self {
            Self {
                paths: |home| AgentPaths {
                    read_write: vec![home.join(".cache/agent")],
                    read_only: vec![home.join(".config/agent")],
                    full_access: vec![home.join(".local/share/agent")],
                    dir_create: vec![home.join(".local/share")],
                    read_exec: vec![PathBuf::from("/opt/agent/bin")],
                },
            }
        }
    }

    impl Agent for FakeAgent {
        fn is_authenticated(&self) -> bool {
            true
        }
        fn login(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn credentials(&self) -> anyhow::Result<AgentCredentials> {
            Ok(AgentCredentials {
                access_token: "test".into(),
                refresh_token: "test".into(),
                expires_at_ms: 0,
            })
        }
        fn paths(&self, home: &Path) -> AgentPaths {
            (self.paths)(home)
        }
        fn allowlist(&self) -> Vec<String> {
            vec![]
        }
        fn executable(&self) -> &Path {
            Path::new("/opt/agent/bin/agent")
        }
        fn env_vars(
            &self,
            _h: &Path,
            _t: &Path,
            _a: u16,
            _b: u16,
            _s: &str,
        ) -> Vec<(String, String)> {
            vec![]
        }
        fn inaccessible_path(&self) -> Option<PathBuf> {
            None
        }
    }

    fn test_home() -> PathBuf {
        PathBuf::from("/home/testuser")
    }

    #[test]
    fn collect_paths_expands_home_tilde_in_config_paths() {
        let agent = FakeAgent::new();
        let cfg = crate::config::Config {
            read_only_paths: vec!["~/.extra_config".to_string()],
            read_exec_paths: vec!["~/custom/bin".to_string()],
            ..Default::default()
        };
        let resolved = collect_paths(&agent, &cfg, &test_home(), None, "default").expect("collect");
        let reads = resolved.seccomp_read();
        assert!(
            reads
                .iter()
                .any(|p| p == &test_home().join(".extra_config"))
        );
        let exec = resolved.seccomp_exec();
        assert!(exec.iter().any(|p| p == &test_home().join("custom/bin")));
    }
}
