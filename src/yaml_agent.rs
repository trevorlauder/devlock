//! Data driven agent backed by an `AgentPolicy` YAML overlay.

use crate::agent::{Agent, AgentCredentials, AgentPaths};
use crate::policy::agent::{
    AgentPolicy, CredentialsFormat, DeviceFlowConfig, Vars, expand, load, policy_dir,
};
use anyhow::{Context, ensure};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use which::which;

pub struct YamlAgent {
    policy: AgentPolicy,
    executable: PathBuf,
    credentials_path: Option<PathBuf>,
    probe_bin: Option<PathBuf>,
}

#[derive(Deserialize)]
struct ClaudeCredentialsFile {
    #[serde(rename = "claudeAiOauth")]
    oauth: ClaudeOAuthCredentials,
}

#[derive(Deserialize)]
struct ClaudeOAuthCredentials {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    /// The upstream claudeAiOauth JSON keeps this in unix epoch
    /// milliseconds. The Rust name makes the unit explicit.
    #[serde(rename = "expiresAt", default)]
    expires_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct StoredDeviceFlowCredentials {
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    /// Unix epoch milliseconds. Serialized with the same wire name so
    /// existing on-disk credentials stay readable.
    #[serde(rename = "expires_at", default)]
    expires_at_ms: u64,
}

#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default = "default_poll_interval")]
    interval: u64,
    #[serde(default = "default_expires_in")]
    expires_in: u64,
}

fn default_poll_interval() -> u64 {
    5
}
fn default_expires_in() -> u64 {
    900
}

/// Write credentials JSON with 0600 and parent dir 0700. Overwrites any
/// existing file at `path`. OAuth tokens must never be world readable.
fn write_credentials<T: Serialize>(path: &Path, creds: &T) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating credentials dir {}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", parent.display()))?;
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {} for write", path.display()))?;
    let body = serde_json::to_vec_pretty(creds)?;
    f.write_all(&body)?;
    Ok(())
}

impl YamlAgent {
    pub fn policy(&self) -> &AgentPolicy {
        &self.policy
    }

    pub fn new(name: &str, home: &Path) -> anyhow::Result<Self> {
        let dir = policy_dir()?;
        let policy = load(&dir, name).with_context(|| format!("loading agent policy `{name}`"))?;

        let probe_bin = std::env::var("DEVLOCK_PROBE_BIN").ok().map(PathBuf::from);

        let vars = launch_time_vars(home, &probe_bin);
        let executable = Self::resolve_executable(&policy.executable, &vars)?;
        let credentials_path = policy
            .credentials
            .file
            .as_deref()
            .map(|p| PathBuf::from(expand(p, &vars)));

        Ok(Self {
            policy,
            executable,
            credentials_path,
            probe_bin,
        })
    }

    fn resolve_executable(exe: &str, vars: &Vars<'_>) -> anyhow::Result<PathBuf> {
        let expanded = expand(exe, vars);
        let as_path = PathBuf::from(&expanded);
        if as_path.is_absolute() {
            Ok(as_path)
        } else {
            which(&expanded).with_context(|| format!("{expanded} not found in PATH"))
        }
    }

    fn vars<'a>(&'a self, home: &'a Path, tmp_dir: &'a Path, cwd: &'a Path) -> Vars<'a> {
        // SESSION_TOKEN is handed over via the FIFO; placeholder here.
        Vars {
            home,
            cwd,
            tmp_dir,
            tunnel_port: 0,
            api_port: 0,
            session_token: "",
            probe_bin: self.probe_bin.as_deref(),
        }
    }
}

impl Agent for YamlAgent {
    fn is_authenticated(&self) -> bool {
        match self.policy.credentials.format {
            CredentialsFormat::ClaudeAiOauth
            | CredentialsFormat::StaticToken
            | CredentialsFormat::OauthDeviceFlow => self
                .credentials_path
                .as_ref()
                .map(|p| p.exists())
                .unwrap_or(false),
            CredentialsFormat::TestStub => true,
        }
    }

    fn login(&self) -> anyhow::Result<()> {
        match self.policy.credentials.format {
            CredentialsFormat::TestStub => Ok(()),
            CredentialsFormat::ClaudeAiOauth => {
                let creds_path = self
                    .credentials_path
                    .clone()
                    .context("credentials path missing for login")?;
                let creds = &self.policy.credentials;
                let program = creds
                    .login_executable
                    .as_deref()
                    .map(std::path::Path::new)
                    .map(std::path::Path::to_path_buf)
                    .unwrap_or_else(|| self.executable.clone());
                let mut cmd = Command::new(&program);
                cmd.args(&creds.login_args);
                let mut child = cmd.spawn()?;
                loop {
                    match child.try_wait()? {
                        Some(_) => break,
                        None if creds_path.exists() => {
                            std::thread::sleep(std::time::Duration::from_secs(1));
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        None => std::thread::sleep(std::time::Duration::from_millis(200)),
                    }
                }
                ensure!(
                    creds_path.exists(),
                    "login failed, no credentials written at {}",
                    creds_path.display()
                );
                Ok(())
            }
            CredentialsFormat::StaticToken => {
                let path = self
                    .credentials_path
                    .as_ref()
                    .context("credentials path missing for static_token")?;
                ensure!(
                    path.exists(),
                    "static_token credentials file not found at {}. Create it with your token as the file contents.",
                    path.display()
                );
                Ok(())
            }
            CredentialsFormat::OauthDeviceFlow => {
                let path = self
                    .credentials_path
                    .clone()
                    .context("credentials path missing for oauth_device_flow")?;
                let cfg = self
                    .policy
                    .credentials
                    .device_flow
                    .as_ref()
                    .context("device_flow config missing")?;
                let stored = run_device_flow(cfg)?;
                write_credentials(&path, &stored)?;
                Ok(())
            }
        }
    }

    fn credentials(&self) -> anyhow::Result<AgentCredentials> {
        match self.policy.credentials.format {
            CredentialsFormat::TestStub => Ok(AgentCredentials {
                access_token: "test-access".into(),
                refresh_token: "test-refresh".into(),
                expires_at_ms: 0,
            }),
            CredentialsFormat::ClaudeAiOauth => {
                let path = self
                    .credentials_path
                    .as_ref()
                    .context("credentials path missing")?;
                let creds: ClaudeCredentialsFile = serde_json::from_str(&fs::read_to_string(path)?)
                    .context("failed to parse credentials file")?;
                Ok(AgentCredentials {
                    access_token: creds.oauth.access_token,
                    refresh_token: creds.oauth.refresh_token,
                    expires_at_ms: creds.oauth.expires_at_ms,
                })
            }
            CredentialsFormat::StaticToken => {
                let path = self
                    .credentials_path
                    .as_ref()
                    .context("credentials path missing")?;
                let token = fs::read_to_string(path)?.trim().to_string();
                ensure!(
                    !token.is_empty(),
                    "static_token file is empty: {}",
                    path.display()
                );
                Ok(AgentCredentials {
                    access_token: token,
                    refresh_token: String::new(),
                    expires_at_ms: 0,
                })
            }
            CredentialsFormat::OauthDeviceFlow => {
                let path = self
                    .credentials_path
                    .as_ref()
                    .context("credentials path missing")?;
                let creds: StoredDeviceFlowCredentials =
                    serde_json::from_str(&fs::read_to_string(path)?)
                        .context("failed to parse device_flow credentials file")?;
                Ok(AgentCredentials {
                    access_token: creds.access_token,
                    refresh_token: creds.refresh_token,
                    expires_at_ms: creds.expires_at_ms,
                })
            }
        }
    }

    fn paths(&self, home: &Path) -> AgentPaths {
        let placeholder_tmp = std::env::temp_dir().join("devlock-unused");
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let vars = self.vars(home, &placeholder_tmp, &cwd);
        let fs = &self.policy.paths;

        let mut read_exec: Vec<PathBuf> = fs
            .read_exec
            .iter()
            .map(|s| PathBuf::from(expand(s, &vars)))
            .collect();
        if let Some(parent) = self.executable.parent() {
            read_exec.push(parent.to_path_buf());
        }

        AgentPaths {
            read_write: fs
                .read_write
                .iter()
                .map(|s| PathBuf::from(expand(s, &vars)))
                .collect(),
            read_only: fs
                .read_only
                .iter()
                .map(|s| PathBuf::from(expand(s, &vars)))
                .filter(|p| p.exists())
                .collect(),
            full_access: fs
                .full_access
                .iter()
                .map(|s| PathBuf::from(expand(s, &vars)))
                .collect(),
            dir_create: fs
                .dir_create
                .iter()
                .map(|s| PathBuf::from(expand(s, &vars)))
                .collect(),
            read_exec,
        }
    }

    fn allowlist(&self) -> Vec<String> {
        self.policy.network_allowlist.clone()
    }

    fn executable(&self) -> &Path {
        &self.executable
    }

    fn inaccessible_path(&self) -> Option<PathBuf> {
        self.credentials_path.clone()
    }

    fn env_vars(
        &self,
        home: &Path,
        tmp_dir: &Path,
        tunnel_port: u16,
        api_port: u16,
        session_token: &str,
    ) -> Vec<(String, String)> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let vars = Vars {
            home,
            cwd: &cwd,
            tmp_dir,
            tunnel_port,
            api_port,
            session_token,
            probe_bin: self.probe_bin.as_deref(),
        };
        self.policy
            .env
            .iter()
            .map(|(k, v)| (k.clone(), expand(v, &vars)))
            .collect()
    }

    fn extra_args(&self, tmp_dir: &Path) -> Vec<String> {
        let placeholder_home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let vars = Vars {
            home: &placeholder_home,
            cwd: &cwd,
            tmp_dir,
            tunnel_port: 0,
            api_port: 0,
            session_token: "",
            probe_bin: self.probe_bin.as_deref(),
        };
        self.policy
            .agent_args
            .iter()
            .map(|s| expand(s, &vars))
            .collect()
    }
}

fn launch_time_vars<'a>(home: &'a Path, probe_bin: &'a Option<PathBuf>) -> Vars<'a> {
    // cwd and tmp_dir expand later via explicit trait method args.
    Vars {
        home,
        cwd: Path::new(""),
        tmp_dir: Path::new(""),
        tunnel_port: 0,
        api_port: 0,
        session_token: "",
        probe_bin: probe_bin.as_deref(),
    }
}

fn run_device_flow(cfg: &DeviceFlowConfig) -> anyhow::Result<StoredDeviceFlowCredentials> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(device_flow_inner(cfg))
}

async fn device_flow_inner(cfg: &DeviceFlowConfig) -> anyhow::Result<StoredDeviceFlowCredentials> {
    // install_default errors only if a provider is already installed
    // in this process. Keep the existing one and carry on.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()?
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    let mut dc_body = format!("client_id={}", urlencoding::encode(&cfg.client_id));
    if !cfg.scope.is_empty() {
        dc_body.push_str(&format!("&scope={}", urlencoding::encode(&cfg.scope)));
    }
    let dc_req = Request::builder()
        .method("POST")
        .uri(&cfg.device_code_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(Full::new(Bytes::from(dc_body)))?;
    let dc_resp = client
        .request(dc_req)
        .await
        .context("device code request failed")?;
    anyhow::ensure!(
        dc_resp.status().is_success(),
        "device code request returned {}",
        dc_resp.status()
    );
    let dc_bytes = dc_resp.into_body().collect().await?.to_bytes();
    let dc: DeviceCodeResponse =
        serde_json::from_slice(&dc_bytes).context("parsing device code response")?;

    let verify = dc
        .verification_uri_complete
        .clone()
        .unwrap_or_else(|| dc.verification_uri.clone());
    eprintln!("Visit {verify} and enter code: {}", dc.user_code);

    let mut interval = Duration::from_secs(dc.interval.max(1));
    let deadline = Instant::now() + Duration::from_secs(dc.expires_in);

    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("device code expired before authorization");
        }
        tokio::time::sleep(interval).await;

        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}&client_id={}",
            urlencoding::encode(&dc.device_code),
            urlencoding::encode(&cfg.client_id),
        );
        let req = Request::builder()
            .method("POST")
            .uri(&cfg.token_url)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(Full::new(Bytes::from(body)))?;
        let resp = client.request(req).await.context("token poll failed")?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).context("parsing token response")?;

        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            match err {
                "authorization_pending" => continue,
                "slow_down" => {
                    interval += Duration::from_secs(5);
                    continue;
                }
                other => anyhow::bail!("device flow error: {other}"),
            }
        }

        let access_token = v
            .get("access_token")
            .and_then(|x| x.as_str())
            .context("token response missing access_token")?
            .to_string();
        let refresh_token = v
            .get("refresh_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let expires_in_s = v.get("expires_in").and_then(|x| x.as_u64()).unwrap_or(0);
        let expires_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64 + expires_in_s * 1000)
            .unwrap_or(0);
        return Ok(StoredDeviceFlowCredentials {
            access_token,
            refresh_token,
            expires_at_ms,
        });
    }
}
