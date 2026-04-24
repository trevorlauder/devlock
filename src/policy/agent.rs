//! Loads policy/agents/<name>.yaml. A file can point at a single parent
//! with extends and pull in any number of partials with includes. The
//! parent is merged first, then each include in order, then the file
//! itself on top. Lists append, maps upsert, scalars from the outer file
//! win.
//!
//! Effective policy tree: bundled defaults (baked into the binary) plus
//! any file the user drops into `~/.config/devlock/policy/` at a matching
//! relative path. `DEVLOCK_POLICY_DIR` bypasses the overlay entirely and
//! is used verbatim (handy during development). See
//! `crate::policy::install::effective_policy_dir`.

use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicy {
    #[serde(default)]
    pub executable: String,
    #[serde(default)]
    pub credentials: CredentialsConfig,
    #[serde(default)]
    pub network_allowlist: Vec<String>,
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub agent_args: Vec<String>,
    #[serde(default)]
    pub paths: PathBundle,
    #[serde(default)]
    pub tunnel: TunnelConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(default)]
    pub api_base_url: String,
    #[serde(default)]
    pub oauth: Option<OauthConfig>,
    #[serde(default)]
    pub inject_headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub path_rewrites: Vec<PathRewrite>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OauthConfig {
    pub token_url: String,
    pub client_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRewrite {
    pub from: String,
    pub to: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_max_per_host")]
    pub max_per_host: usize,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

fn default_max_connections() -> usize {
    128
}
fn default_max_per_host() -> usize {
    32
}
fn default_idle_timeout_secs() -> u64 {
    30
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            max_per_host: default_max_per_host(),
            idle_timeout_secs: default_idle_timeout_secs(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathBundle {
    #[serde(default)]
    pub full_access: Vec<String>,
    #[serde(default)]
    pub read_exec: Vec<String>,
    #[serde(default)]
    pub read_list: Vec<String>,
    #[serde(default)]
    pub read_only: Vec<String>,
    #[serde(default)]
    pub read_write: Vec<String>,
    #[serde(default)]
    pub dir_create: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CredentialsConfig {
    #[serde(default)]
    pub format: CredentialsFormat,
    #[serde(default)]
    pub file: Option<String>,
    /// Args for the login command. Run against `login_executable` if set,
    /// otherwise against the agent's `executable`.
    #[serde(default)]
    pub login_args: Vec<String>,
    #[serde(default)]
    pub login_executable: Option<String>,
    #[serde(default)]
    pub device_flow: Option<DeviceFlowConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFlowConfig {
    pub device_code_url: String,
    pub token_url: String,
    pub client_id: String,
    #[serde(default)]
    pub scope: String,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialsFormat {
    ClaudeAiOauth,
    StaticToken,
    OauthDeviceFlow,
    #[default]
    TestStub,
}

pub fn load(policy_dir: &Path, agent: &str) -> io::Result<AgentPolicy> {
    let entry = policy_dir.join("agents").join(format!("{agent}.yaml"));
    let mut visited = std::collections::HashSet::new();
    let merged = super::yaml_merge::load_and_merge(&entry, policy_dir, &mut visited)?;
    let policy: AgentPolicy = serde_norway::from_value(merged)
        .map_err(|e| io::Error::other(format!("{}: {e}", entry.display())))?;
    if policy.executable.is_empty() {
        return Err(io::Error::other(format!(
            "{}: executable is required (set in this file or an included one)",
            entry.display()
        )));
    }
    if policy.proxy.api_base_url.is_empty() {
        return Err(io::Error::other(format!(
            "{}: proxy.api_base_url is required",
            entry.display()
        )));
    }
    match policy.credentials.format {
        CredentialsFormat::StaticToken if policy.credentials.file.is_none() => {
            return Err(io::Error::other(format!(
                "{}: credentials.file is required for static_token",
                entry.display()
            )));
        }
        CredentialsFormat::OauthDeviceFlow if policy.credentials.device_flow.is_none() => {
            return Err(io::Error::other(format!(
                "{}: credentials.device_flow is required for oauth_device_flow",
                entry.display()
            )));
        }
        _ => {}
    }
    Ok(policy)
}

/// Returns the effective policy directory: bundled defaults overlaid with
/// anything the user placed under `~/.config/devlock/policy/`, or
/// `DEVLOCK_POLICY_DIR` used verbatim when set.
pub fn policy_dir() -> io::Result<PathBuf> {
    super::install::effective_policy_dir()
}

pub struct Vars<'a> {
    pub home: &'a Path,
    pub cwd: &'a Path,
    pub tmp_dir: &'a Path,
    pub tunnel_port: u16,
    pub api_port: u16,
    pub session_token: &'a str,
    pub probe_bin: Option<&'a Path>,
}

/// Substitute known `$VAR` and `~/`. Unknown names pass through.
pub fn expand(raw: &str, vars: &Vars<'_>) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            let mut name = String::new();
            while let Some(next) = chars.peek() {
                if next.is_ascii_alphanumeric() || *next == '_' {
                    name.push(chars.next().unwrap());
                } else {
                    break;
                }
            }
            match name.as_str() {
                "CWD" => out.push_str(&vars.cwd.to_string_lossy()),
                "TMP_DIR" => out.push_str(&vars.tmp_dir.to_string_lossy()),
                "TUNNEL_PORT" => out.push_str(&vars.tunnel_port.to_string()),
                "API_PORT" => out.push_str(&vars.api_port.to_string()),
                "SESSION_TOKEN" => out.push_str(vars.session_token),
                "DEVLOCK_PROBE_BIN" => {
                    if let Some(p) = vars.probe_bin {
                        out.push_str(&p.to_string_lossy());
                    } else {
                        out.push('$');
                        out.push_str(&name);
                    }
                }
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp_policy(dir: &Path, name: &str, body: &str) {
        let p = dir.join("agents");
        std::fs::create_dir_all(&p).unwrap();
        let mut f = std::fs::File::create(p.join(format!("{name}.yaml"))).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    /// Materialize the bundled policy tree into a fresh tempdir so tests that
    /// assert "as shipped" behavior aren't influenced by user overrides.
    fn bundled_policy_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        super::super::bundled::materialize_to(dir.path()).unwrap();
        dir
    }

    #[test]
    fn claude_yaml_parses_as_shipped() {
        let dir = bundled_policy_dir();
        let policy = load(dir.path(), "claude").expect("bundled agents/claude.yaml must load");
        assert_eq!(policy.executable, "claude");
        assert!(
            policy
                .network_allowlist
                .contains(&"anthropic.com".to_string())
        );
        assert_eq!(policy.proxy.api_base_url, "https://api.anthropic.com");
        let oauth = policy.proxy.oauth.as_ref().expect("oauth config present");
        assert_eq!(
            oauth.token_url,
            "https://platform.claude.com/v1/oauth/token"
        );
        assert_eq!(
            policy
                .proxy
                .inject_headers
                .get("anthropic-beta")
                .map(String::as_str),
            Some("oauth-2025-04-20")
        );
    }

    #[test]
    fn static_token_requires_credentials_file() {
        let dir = tempfile::tempdir().unwrap();
        write_tmp_policy(
            dir.path(),
            "pat",
            "executable: bin\nproxy:\n  api_base_url: https://x.test\ncredentials:\n  format: static_token\n",
        );
        let err = load(dir.path(), "pat").unwrap_err();
        assert!(
            err.to_string().contains("credentials.file is required"),
            "{err}"
        );
    }

    #[test]
    fn device_flow_requires_device_flow_block() {
        let dir = tempfile::tempdir().unwrap();
        write_tmp_policy(
            dir.path(),
            "df",
            "executable: bin\nproxy:\n  api_base_url: https://x.test\ncredentials:\n  format: oauth_device_flow\n  file: /tmp/x\n",
        );
        let err = load(dir.path(), "df").unwrap_err();
        assert!(err.to_string().contains("device_flow is required"), "{err}");
    }

    #[test]
    fn missing_api_base_url_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write_tmp_policy(dir.path(), "noproxy", "executable: bin\n");
        let err = load(dir.path(), "noproxy").unwrap_err();
        assert!(
            err.to_string().contains("api_base_url is required"),
            "{err}"
        );
    }

    #[test]
    fn test_yaml_parses_as_shipped() {
        let dir = bundled_policy_dir();
        let policy = load(dir.path(), "test").expect("bundled agents/test.yaml must load");
        assert_eq!(policy.executable, "$DEVLOCK_PROBE_BIN");
    }

    #[test]
    fn extends_single_parent_merges() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("agents")).unwrap();
        std::fs::write(
            dir.path().join("agents/base.yaml"),
            "executable: base\nnetwork_allowlist: [a.com]\nproxy:\n  api_base_url: https://example.test\n",
        )
        .unwrap();
        write_tmp_policy(
            dir.path(),
            "child",
            "extends: base.yaml\nnetwork_allowlist: [b.com]\n",
        );
        let merged = load(dir.path(), "child").unwrap();
        assert_eq!(merged.executable, "base");
        assert_eq!(merged.network_allowlist, vec!["a.com", "b.com"]);
    }

    #[test]
    fn includes_list_merges_each_partial() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("agents")).unwrap();
        std::fs::write(
            dir.path().join("agents/p1.yaml"),
            "paths:\n  read_only: [\"~/.a\"]\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("agents/p2.yaml"),
            "paths:\n  read_only: [\"~/.b\"]\n",
        )
        .unwrap();
        write_tmp_policy(
            dir.path(),
            "bar",
            "includes: [p1.yaml, p2.yaml]\nexecutable: bar\nproxy:\n  api_base_url: https://example.test\npaths:\n  read_only: [\"~/.c\"]\n",
        );
        let merged = load(dir.path(), "bar").unwrap();
        assert_eq!(merged.executable, "bar");
        assert_eq!(
            merged.paths.read_only,
            vec!["~/.a".to_string(), "~/.b".to_string(), "~/.c".to_string()]
        );
    }

    #[test]
    fn cycle_detected_between_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("agents")).unwrap();
        std::fs::write(dir.path().join("agents/a.yaml"), "extends: b.yaml\n").unwrap();
        std::fs::write(dir.path().join("agents/b.yaml"), "extends: a.yaml\n").unwrap();
        let err = load(dir.path(), "a").unwrap_err();
        assert!(err.to_string().contains("cycle"), "{err}");
    }

    #[test]
    fn missing_executable_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write_tmp_policy(dir.path(), "empty", "network_allowlist: []\n");
        let err = load(dir.path(), "empty").unwrap_err();
        assert!(err.to_string().contains("executable"), "{err}");
    }

    #[test]
    fn missing_agent_file_reports_path() {
        let dir = tempfile::tempdir().unwrap();
        let err = load(dir.path(), "missing").unwrap_err();
        assert!(err.to_string().contains("missing.yaml"), "{err}");
    }

    #[test]
    fn expand_substitutes_every_known_variable() {
        let home = PathBuf::from("/home/u");
        let cwd = PathBuf::from("/work");
        let tmp = PathBuf::from("/tmp/x");
        let probe = PathBuf::from("/probe");
        let vars = Vars {
            home: &home,
            cwd: &cwd,
            tmp_dir: &tmp,
            tunnel_port: 1234,
            api_port: 5678,
            session_token: "tok",
            probe_bin: Some(&probe),
        };
        assert_eq!(expand("~/x", &vars), "/home/u/x");
        assert_eq!(expand("$CWD/.git", &vars), "/work/.git");
        assert_eq!(expand("$HOME/x", &vars), "$HOME/x");
        assert_eq!(expand("$TMP_DIR/y", &vars), "/tmp/x/y");
        assert_eq!(expand("$TUNNEL_PORT", &vars), "1234");
        assert_eq!(
            expand("http://127.0.0.1:$API_PORT", &vars),
            "http://127.0.0.1:5678"
        );
        assert_eq!(expand("Bearer $SESSION_TOKEN", &vars), "Bearer tok");
        assert_eq!(expand("$DEVLOCK_PROBE_BIN", &vars), "/probe");
        assert_eq!(expand("$UNKNOWN/y", &vars), "$UNKNOWN/y");
    }
}
