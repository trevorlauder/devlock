use std::path::{Path, PathBuf};

pub struct AgentCredentials {
    pub access_token: String,
    pub refresh_token: String,
    /// Unix epoch milliseconds. Zero means no expiry tracking.
    pub expires_at_ms: u64,
}

pub struct AgentPaths {
    /// Full access including execute
    pub full_access: Vec<PathBuf>,
    /// Read + execute access (for agent binary and its install tree)
    pub read_exec: Vec<PathBuf>,
    /// Read-only access
    pub read_only: Vec<PathBuf>,
    /// Read and write access
    pub read_write: Vec<PathBuf>,
    /// Directory listing + create new entries, no read/write of existing file contents
    pub dir_create: Vec<PathBuf>,
}

pub trait Agent {
    fn is_authenticated(&self) -> bool;
    fn login(&self) -> anyhow::Result<()>;
    fn credentials(&self) -> anyhow::Result<AgentCredentials>;
    fn paths(&self, home: &Path) -> AgentPaths;
    fn allowlist(&self) -> Vec<String>;
    fn executable(&self) -> &Path;
    fn env_vars(
        &self,
        home: &Path,
        tmp_dir: &Path,
        tunnel_port: u16,
        api_port: u16,
        session_token: &str,
    ) -> Vec<(String, String)>;
    /// A path that must be inaccessible inside the sandbox (e.g. credentials file).
    fn inaccessible_path(&self) -> Option<PathBuf>;
    /// Extra CLI arguments to prepend before passthrough args.
    fn extra_args(&self, _tmp_dir: &Path) -> Vec<String> {
        Vec::new()
    }
}
