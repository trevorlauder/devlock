//! Local loopback proxy that authenticates requests from the sandboxed
//! agent with a per session bearer token and forwards allowed traffic to
//! Anthropic endpoints.
//!
//! Architecture:
//! - auth: allowlist matching + session token checks
//! - http: request/response construction with streaming support
//! - server: the tunnel server (CONNECT only) and the api server (forwarding only)
//! - state: shared runtime state and HTTP client bootstrap
mod auth;
mod error;
mod http;
mod server;
mod state;

use std::sync::Arc;
use std::time::Duration;

pub struct ProxyCredentials {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at_ms: u64,
    pub session_token: String,
}

pub struct ProxyListeners {
    pub tunnel: std::net::TcpListener,
    pub api: std::net::TcpListener,
}

pub fn run_proxy(
    credentials: ProxyCredentials,
    listeners: ProxyListeners,
    allowlist: Vec<String>,
    tunnel_config: crate::policy::agent::TunnelConfig,
    proxy_config: crate::policy::agent::ProxyConfig,
) -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        let state = Arc::new(state::ProxyState::new(credentials, proxy_config)?);

        let ProxyListeners {
            tunnel: tunnel_listener,
            api: api_listener,
        } = listeners;

        tunnel_listener.set_nonblocking(true)?;
        let tunnel_listener = Arc::new(tokio::net::TcpListener::from_std(tunnel_listener)?);

        api_listener.set_nonblocking(true)?;
        let api_listener = Arc::new(tokio::net::TcpListener::from_std(api_listener)?);

        // Each server runs under a supervisor that respawns the accept loop
        // if the task panics or errors out, reusing the same listener
        // socket. Without this, any crash in proxy code ends the proxy,
        // which triggers SIGKILL of the child in main.rs (see the cleanup
        // coupling) — a remote-reachable session-kill primitive.
        let tunnel_supervisor = {
            let listener = tunnel_listener.clone();
            let session_token = state.session_token.clone();
            tokio::spawn(supervise("tunnel", move || {
                let listener = listener.clone();
                let allowlist = allowlist.clone();
                let session_token = session_token.clone();
                let tunnel_config = tunnel_config.clone();
                async move {
                    server::serve_tunnel(listener, allowlist, session_token, tunnel_config).await
                }
            }))
        };

        let api_supervisor = {
            let listener = api_listener.clone();
            let state = state.clone();
            tokio::spawn(supervise("api", move || {
                let listener = listener.clone();
                let state = state.clone();
                async move { server::serve_api(listener, state).await }
            }))
        };

        // Both supervisors loop forever; awaiting them keeps the runtime
        // alive. A supervisor itself panicking is the only way these ever
        // return, and tokio::join catches that so the session survives.
        let (tunnel_res, api_res) = tokio::join!(tunnel_supervisor, api_supervisor);
        if let Err(e) = tunnel_res {
            tracing::error!(target: "proxy", event = "tunnel_supervisor_died", error = %e);
        }
        if let Err(e) = api_res {
            tracing::error!(target: "proxy", event = "api_supervisor_died", error = %e);
        }

        anyhow::Ok(())
    })
}

/// Run the given server future under a restart loop. If the server task
/// panics or returns an error, log it, sleep with exponential backoff (cap
/// 5s), then spawn a fresh copy. The listener socket is owned by the
/// closure's captured Arc, so it outlives any individual server task.
async fn supervise<F, Fut>(label: &'static str, make: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<(), error::ProxyError>> + Send + 'static,
{
    let mut backoff = Duration::from_millis(100);
    let max_backoff = Duration::from_secs(5);
    loop {
        let task = tokio::spawn(make());
        match task.await {
            Ok(Ok(())) => {
                tracing::info!(target: "proxy", event = "server_exit_clean", label);
                return;
            }
            Ok(Err(e)) => {
                tracing::error!(target: "proxy", event = "server_exit_error", label, error = %e);
            }
            Err(e) if e.is_panic() => {
                tracing::error!(target: "proxy", event = "server_panic", label, error = %e);
            }
            Err(e) => {
                tracing::error!(target: "proxy", event = "server_cancelled", label, error = %e);
                return;
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(max_backoff);
    }
}
