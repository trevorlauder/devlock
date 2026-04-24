use crate::proxy::auth::{has_valid_session_token, host_allowed};
use crate::proxy::error::ProxyError;
use crate::proxy::http::{
    ClientBody, LimitedBody, ProxyBody, REQUEST_BODY_LIMIT, RESPONSE_BODY_LIMIT, bad_gateway,
    build_request, collect_limited, forbidden_host, full_client_body, internal_error,
    method_not_allowed, payload_too_large, proxy_auth_required, response_with_status,
    stream_response,
};
use crate::proxy::state::ProxyState;
use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const TARGET: &str = "proxy";

/// Upper bound on a single refresh attempt. The refresh_lock serializes
/// attempts, so a stalled upstream without a timeout would block every
/// concurrent API request.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);

/// Tracks active tunnel connections for rate limiting.
struct TunnelState {
    /// Per-host active connection counts.
    per_host: HashMap<String, usize>,
    /// Total active connections.
    total: usize,
    max_total: usize,
    max_per_host: usize,
}

impl TunnelState {
    fn new(max_total: usize, max_per_host: usize) -> Self {
        Self {
            per_host: HashMap::new(),
            total: 0,
            max_total,
            max_per_host,
        }
    }

    /// Try to acquire a slot for the given host.
    /// Returns false if either the global or per-host limit would be exceeded.
    fn try_acquire(&mut self, host: &str) -> bool {
        if self.total >= self.max_total {
            return false;
        }
        match self.per_host.get_mut(host) {
            Some(count) if *count >= self.max_per_host => return false,
            Some(count) => *count += 1,
            None => {
                self.per_host.insert(host.to_owned(), 1);
            }
        }
        self.total += 1;
        true
    }

    /// Release a slot for the given host.
    fn release(&mut self, host: &str) {
        if let Some(count) = self.per_host.get_mut(host) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_host.remove(host);
            }
        }
        self.total = self.total.saturating_sub(1);
    }
}

fn too_many_connections() -> Response<ProxyBody> {
    response_with_status(
        StatusCode::TOO_MANY_REQUESTS,
        Bytes::from_static(b"too many tunnel connections"),
    )
}

fn method_allowed(method: &Method, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    allowed
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method.as_str()))
}

fn rewrite_path(path: &str, rewrites: &[crate::policy::agent::PathRewrite]) -> String {
    let longest = rewrites
        .iter()
        .filter(|r| path.starts_with(&r.from))
        .max_by_key(|r| r.from.len());
    match longest {
        Some(r) => format!("{}{}", r.to, &path[r.from.len()..]),
        None => path.to_string(),
    }
}

async fn refresh_access_token(state: &ProxyState) -> Result<(), ProxyError> {
    let Some(oauth) = state.proxy.oauth.as_ref() else {
        return Ok(());
    };
    let refresh_token = state.refresh_token.read().await.clone();
    let form_body = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        urlencoding::encode(refresh_token.as_str()),
        urlencoding::encode(&oauth.client_id),
    );

    let req = Request::builder()
        .method("POST")
        .uri(&oauth.token_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(full_client_body(Bytes::from(form_body)))?;

    let resp = state
        .client
        .request(req)
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;
    let status = resp.status();
    let resp_body = collect_limited(resp.into_body(), RESPONSE_BODY_LIMIT).await?;

    if !status.is_success() {
        let snippet = String::from_utf8_lossy(&resp_body[..resp_body.len().min(256)]);
        return Err(ProxyError::Upstream(format!(
            "refresh returned {status}: {snippet}"
        )));
    }

    let json: serde_json::Value =
        serde_json::from_slice(&resp_body).map_err(|e| ProxyError::Upstream(e.to_string()))?;

    if json["access_token"].as_str().is_none() {
        return Err(ProxyError::Upstream(
            "refresh response missing access_token".to_string(),
        ));
    }

    if let Some(token) = json["access_token"].as_str() {
        state.set_access_token(token.to_string()).await;
        tracing::info!(target: TARGET, event = "token_refreshed");
    }
    if let Some(token) = json["refresh_token"].as_str() {
        state.set_refresh_token(token.to_string()).await;
    }
    // The refresh endpoint returns `expires_at` in unix epoch
    // milliseconds (Claude.ai OAuth convention). Store verbatim.
    if let Some(exp_ms) = json["expires_at"].as_u64() {
        *state.expires_at_ms.write().await = exp_ms;
    }

    Ok(())
}

async fn handle_connect(
    req: Request<Incoming>,
    allowlist: Arc<Vec<String>>,
    tunnel_state: Arc<Mutex<TunnelState>>,
    idle_timeout: Duration,
) -> Result<Response<ProxyBody>, ProxyError> {
    let authority = match req.uri().authority() {
        Some(a) => a.to_string(),
        None => {
            return Ok(response_with_status(
                StatusCode::BAD_REQUEST,
                Bytes::from_static(b"CONNECT requires an authority"),
            ));
        }
    };
    let host = req.uri().host().unwrap_or("").to_string();
    let port = req.uri().port_u16().unwrap_or(443);

    if !host_allowed(&host, &allowlist) {
        tracing::warn!(
            target: TARGET,
            event = "host_not_allowlisted",
            host = %host,
            port = port,
        );
        return Ok(forbidden_host());
    }

    if port != 443 {
        tracing::warn!(
            target: TARGET,
            event = "port_not_allowed",
            host = %host,
            port = port,
        );
        return Ok(forbidden_host());
    }

    // Enforce per-host and global connection limits.
    {
        let mut state = tunnel_state.lock().await;
        if !state.try_acquire(&host) {
            tracing::warn!(
                target: TARGET,
                event = "tunnel_limit_reached",
                host = %host,
                total = state.total,
            );
            return Ok(too_many_connections());
        }
    }

    // Resolve the hostname and validate that all resolved IPs are public.
    // This prevents DNS rebinding attacks where an allowlisted domain resolves
    // to a private/link-local/loopback address (e.g. cloud metadata 169.254.169.254).
    let addrs: Vec<std::net::SocketAddr> = match tokio::net::lookup_host(&authority).await {
        Ok(a) => a.collect(),
        Err(e) => {
            tunnel_state.lock().await.release(&host);
            return Err(ProxyError::Upstream(format!(
                "DNS resolution failed for {authority}: {e}"
            )));
        }
    };

    if addrs.is_empty() {
        tunnel_state.lock().await.release(&host);
        tracing::warn!(
            target: TARGET,
            event = "upstream_error",
            host = %host,
            error = format!("no addresses for {authority}"),
        );
        return Ok(bad_gateway(format!("no addresses for {authority}")));
    }

    for addr in &addrs {
        if is_non_public_ip(&addr.ip()) {
            tunnel_state.lock().await.release(&host);
            tracing::warn!(
                target: TARGET,
                event = "dns_rebind_blocked",
                host = %host,
                resolved_ip = %addr.ip(),
            );
            return Ok(forbidden_host());
        }
    }

    // Use the addresses we already resolved to avoid a second DNS lookup
    // that an attacker controlling DNS could use to return a different result.
    let stream = match tokio::net::TcpStream::connect(addrs.as_slice()).await {
        Ok(s) => s,
        Err(e) => {
            tunnel_state.lock().await.release(&host);
            tracing::warn!(
                target: TARGET,
                event = "upstream_error",
                host = %host,
                error = %e,
            );
            return Ok(bad_gateway(e));
        }
    };

    tracing::info!(target: TARGET, event = "tunnel_opened", host = %host);

    let upgrade = hyper::upgrade::on(req);
    let host_clone = host.clone();
    tokio::spawn(async move {
        let start = Instant::now();
        match upgrade.await {
            Ok(upgraded) => {
                let mut upgraded = TokioIo::new(upgraded);
                let mut stream = stream;
                // Wrap copy_bidirectional in an idle timeout so dormant tunnels
                // (e.g. a C2 channel waiting for commands) are terminated.
                let result =
                    copy_bidirectional_with_idle_timeout(&mut upgraded, &mut stream, idle_timeout)
                        .await;
                let duration = start.elapsed();
                let (up, down, reason) = match result {
                    Ok((up, down)) => (up, down, "completed"),
                    Err(_) => (0, 0, "idle_timeout"),
                };
                tracing::info!(
                    target: TARGET,
                    event = "tunnel_closed",
                    host = %host_clone,
                    bytes_up = up,
                    bytes_down = down,
                    duration_secs = duration.as_secs(),
                    reason,
                );
            }
            Err(e) => tracing::warn!(
                target: TARGET,
                event = "tunnel_upgrade_error",
                error = %e,
            ),
        }
        tunnel_state.lock().await.release(&host_clone);
    });

    Ok(response_with_status(StatusCode::OK, Bytes::new()))
}

/// Copies data bidirectionally between two streams with an idle timeout.
/// Returns the number of bytes transferred (client→server, server→client) on
/// success. Returns an error if no data flows in either direction for `timeout`.
async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    timeout: Duration,
) -> Result<(u64, u64), ProxyError>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf_a = vec![0u8; 8192];
    let mut buf_b = vec![0u8; 8192];
    let mut bytes_a_to_b: u64 = 0;
    let mut bytes_b_to_a: u64 = 0;
    let mut a_done = false;
    let mut b_done = false;

    loop {
        if a_done && b_done {
            break;
        }

        let result = tokio::time::timeout(timeout, async {
            tokio::select! {
                r = a.read(&mut buf_a), if !a_done => {
                    match r {
                        Ok(0) => { a_done = true; let _ = b.shutdown().await; }
                        Ok(n) => { b.write_all(&buf_a[..n]).await?; bytes_a_to_b += n as u64; }
                        Err(e) => return Err(ProxyError::Io(e)),
                    }
                }
                r = b.read(&mut buf_b), if !b_done => {
                    match r {
                        Ok(0) => { b_done = true; let _ = a.shutdown().await; }
                        Ok(n) => { a.write_all(&buf_b[..n]).await?; bytes_b_to_a += n as u64; }
                        Err(e) => return Err(ProxyError::Io(e)),
                    }
                }
            }
            Ok(())
        })
        .await;

        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                // Idle timeout expired — no data in either direction.
                return Err(ProxyError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "tunnel idle timeout",
                )));
            }
        }
    }

    Ok((bytes_a_to_b, bytes_b_to_a))
}

async fn handle_tunnel_request(
    req: Request<Incoming>,
    allowlist: Arc<Vec<String>>,
    tunnel_state: Arc<Mutex<TunnelState>>,
    idle_timeout: Duration,
) -> Result<Response<ProxyBody>, hyper::Error> {
    if req.method() != Method::CONNECT {
        return Ok(method_not_allowed());
    }

    match handle_connect(req, allowlist, tunnel_state, idle_timeout).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            tracing::error!(target: TARGET, event = "tunnel_error", error = %e);
            Ok(internal_error())
        }
    }
}

/// Returns true if the IP is loopback, private, link-local, or otherwise
/// non-public. Used to block DNS rebinding attacks where an allowlisted
/// domain resolves to an internal address.
fn is_non_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()                                       // 127.0.0.0/8
                || v4.is_private()                                 // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()                              // 169.254.0.0/16 (incl. metadata)
                || v4.is_broadcast()                               // 255.255.255.255
                || v4.is_unspecified()                              // 0.0.0.0
                || v4.is_multicast()                               // 224.0.0.0/4
                || o[0] >= 240                                      // 240.0.0.0/4 reserved (class E)
                || (o[0] == 100 && (64..=127).contains(&o[1]))    // 100.64.0.0/10 (CGNAT)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)        // 192.0.0.0/24 (IETF protocol)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 (benchmark)
        }
        IpAddr::V6(v6) => {
            // Treat IPv4-mapped IPv6 (::ffff:x.x.x.x) as its IPv4 equivalent
            // to prevent SSRF via DNS rebinding to internal addresses.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_non_public_ip(&IpAddr::V4(v4));
            }
            // 6to4 addresses embed an IPv4 in the middle two segments
            // and route to that IPv4 via a relay, so recurse on the
            // embedded address to catch private or loopback targets.
            if v6.segments()[0] == 0x2002 {
                let s = v6.segments();
                let embedded = std::net::Ipv4Addr::new(
                    (s[1] >> 8) as u8,
                    (s[1] & 0xff) as u8,
                    (s[2] >> 8) as u8,
                    (s[2] & 0xff) as u8,
                );
                return is_non_public_ip(&IpAddr::V4(embedded));
            }
            v6.is_loopback()                                       // ::1
                || v6.is_unspecified()                              // ::
                || v6.is_multicast()                               // ff00::/8
                || (v6.segments()[0] & 0xffc0) == 0xfe80           // fe80::/10 link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
        }
    }
}

pub async fn serve_tunnel(
    listener: Arc<TcpListener>,
    allowlist: Vec<String>,
    // Kept for API compatibility. The tunnel only gates by allowlist because
    // the destinations are the same public endpoints the agent's tools would
    // normally reach. The session token guards the API proxy instead.
    _session_token: String,
    tunnel_config: crate::policy::agent::TunnelConfig,
) -> Result<(), ProxyError> {
    let allowlist = Arc::new(allowlist);
    let idle_timeout = Duration::from_secs(tunnel_config.idle_timeout_secs);
    let tunnel_state = Arc::new(Mutex::new(TunnelState::new(
        tunnel_config.max_connections,
        tunnel_config.max_per_host,
    )));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // Transient accept errors (EMFILE, ENFILE, ECONNABORTED) must
                // not kill the proxy: a proxy death becomes a session death
                // via the main.rs cleanup path, giving remote callers a
                // trivial DoS primitive.
                tracing::warn!(target: TARGET, event = "tunnel_accept_error", error = %e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let allowlist = allowlist.clone();
        let tunnel_state = tunnel_state.clone();
        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req| {
                        let allowlist = allowlist.clone();
                        let tunnel_state = tunnel_state.clone();
                        async move {
                            handle_tunnel_request(req, allowlist, tunnel_state, idle_timeout).await
                        }
                    }),
                )
                .with_upgrades()
                .await;
        });
    }
}

async fn handle_api_request_inner(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<ProxyBody>, ProxyError> {
    if req.method() == Method::CONNECT {
        return Ok(method_not_allowed());
    }

    if !has_valid_session_token(&req, &state.session_token) {
        tracing::warn!(target: TARGET, event = "api_auth_rejected");
        return Ok(proxy_auth_required());
    }

    if !method_allowed(req.method(), &state.proxy.allowed_methods) {
        tracing::warn!(
            target: TARGET,
            event = "api_method_rejected",
            method = %req.method(),
        );
        return Ok(method_not_allowed());
    }

    let rewritten_path = rewrite_path(req.uri().path(), &state.proxy.path_rewrites);
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let uri = format!("{}{rewritten_path}{query}", state.proxy.api_base_url);

    let method = req.method().clone();
    let headers = req.headers().clone();
    let body: ClientBody = LimitedBody::new(req.into_body(), REQUEST_BODY_LIMIT).boxed_unsync();

    if state.proxy.oauth.is_some() {
        let expires_at_ms = *state.expires_at_ms.read().await;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ProxyError::Upstream(e.to_string()))?
            .as_millis() as u64;

        if expires_at_ms > 0 && now_ms > expires_at_ms.saturating_sub(3_600_000) {
            // Serialize refresh attempts so only one request refreshes at a time.
            // Other concurrent requests wait and pick up the new token.
            let _guard = state.refresh_lock.lock().await;
            // Re-check expiry after acquiring the lock in case another
            // request already refreshed.
            let refreshed_ms = *state.expires_at_ms.read().await;
            if now_ms > refreshed_ms.saturating_sub(3_600_000) {
                match tokio::time::timeout(REFRESH_TIMEOUT, refresh_access_token(&state)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::error!(
                        target: TARGET,
                        event = "token_refresh_failed",
                        error = %e,
                    ),
                    Err(_) => tracing::error!(
                        target: TARGET,
                        event = "token_refresh_timeout",
                        timeout_secs = REFRESH_TIMEOUT.as_secs(),
                    ),
                }
            }
        }
    }

    let access_token = state.access_token.read().await.clone();
    let forwarded = build_request(
        method,
        &uri,
        &headers,
        body,
        access_token.as_str(),
        &state.proxy.inject_headers,
    )?;

    match state.client.request(forwarded).await {
        Ok(resp) => Ok(stream_response(resp)),
        Err(e) => {
            tracing::error!(
                target: TARGET,
                event = "upstream_error",
                error = %e,
            );
            Ok(bad_gateway(e))
        }
    }
}

async fn handle_api_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    match handle_api_request_inner(req, state).await {
        Ok(resp) => Ok(resp),
        Err(ProxyError::BodyTooLarge { .. }) => Ok(payload_too_large()),
        Err(e) => {
            tracing::error!(target: TARGET, event = "api_error", error = %e);
            Ok(internal_error())
        }
    }
}

pub async fn serve_api(
    listener: Arc<TcpListener>,
    state: Arc<ProxyState>,
) -> Result<(), ProxyError> {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(target: TARGET, event = "api_accept_error", error = %e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req| {
                        let state = state.clone();
                        async move { handle_api_request(req, state).await }
                    }),
                )
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn public_ipv4_addresses_are_allowed() {
        assert!(!is_non_public_ip(&v4(1, 1, 1, 1)));
        assert!(!is_non_public_ip(&v4(8, 8, 8, 8)));
        assert!(!is_non_public_ip(&v4(104, 18, 0, 1)));
    }

    #[test]
    fn private_and_reserved_ipv4_are_blocked() {
        assert!(is_non_public_ip(&v4(127, 0, 0, 1)));
        assert!(is_non_public_ip(&v4(10, 0, 0, 1)));
        assert!(is_non_public_ip(&v4(172, 16, 5, 5)));
        assert!(is_non_public_ip(&v4(192, 168, 1, 1)));
        assert!(is_non_public_ip(&v4(169, 254, 169, 254)));
        assert!(is_non_public_ip(&v4(255, 255, 255, 255)));
        assert!(is_non_public_ip(&v4(0, 0, 0, 0)));
        assert!(is_non_public_ip(&v4(100, 64, 0, 1)));
        assert!(is_non_public_ip(&v4(192, 0, 0, 1)));
        assert!(is_non_public_ip(&v4(198, 18, 0, 1)));
    }

    #[test]
    fn ipv6_loopback_and_ula_blocked() {
        assert!(is_non_public_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_non_public_ip(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(is_non_public_ip(&IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(is_non_public_ip(&IpAddr::V6("fc00::1".parse().unwrap())));
        assert!(is_non_public_ip(&IpAddr::V6(
            "fd12:3456:789a::1".parse().unwrap()
        )));
    }

    #[test]
    fn ipv4_mapped_ipv6_is_treated_as_ipv4() {
        // Metadata IP routed through an ipv4 mapped ipv6 address must still
        // be recognised and refused, otherwise a DNS rebind attack could
        // smuggle 169.254.169.254 past the proxy filter as ::ffff:169.254.169.254.
        let mapped: Ipv6Addr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(is_non_public_ip(&IpAddr::V6(mapped)));

        let mapped_loopback: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_non_public_ip(&IpAddr::V6(mapped_loopback)));
    }

    #[test]
    fn ipv4_multicast_and_reserved_are_blocked() {
        assert!(is_non_public_ip(&v4(224, 0, 0, 1)));
        assert!(is_non_public_ip(&v4(239, 255, 255, 250)));
        assert!(is_non_public_ip(&v4(240, 0, 0, 1)));
        assert!(is_non_public_ip(&v4(255, 255, 255, 254)));
    }

    #[test]
    fn ipv6_multicast_is_blocked() {
        assert!(is_non_public_ip(&IpAddr::V6("ff02::1".parse().unwrap())));
        assert!(is_non_public_ip(&IpAddr::V6("ff0e::1".parse().unwrap())));
    }

    #[test]
    fn ipv6_6to4_decodes_embedded_ipv4() {
        let private: Ipv6Addr = "2002:0a00:0001::".parse().unwrap();
        assert!(is_non_public_ip(&IpAddr::V6(private)));
        let loopback: Ipv6Addr = "2002:7f00:0001::".parse().unwrap();
        assert!(is_non_public_ip(&IpAddr::V6(loopback)));
        let metadata: Ipv6Addr = "2002:a9fe:a9fe::".parse().unwrap();
        assert!(is_non_public_ip(&IpAddr::V6(metadata)));
        let public: Ipv6Addr = "2002:0808:0808::".parse().unwrap();
        assert!(!is_non_public_ip(&IpAddr::V6(public)));
    }

    #[test]
    fn tunnel_state_honours_both_limits() {
        let mut state = TunnelState::new(2, 1);
        assert!(state.try_acquire("a.com"));
        assert!(!state.try_acquire("a.com"));
        assert!(state.try_acquire("b.com"));
        assert!(!state.try_acquire("c.com"));
        state.release("a.com");
        assert!(state.try_acquire("a.com"));
    }

    #[test]
    fn tunnel_release_restores_capacity() {
        let mut state = TunnelState::new(1, 1);
        assert!(state.try_acquire("a.com"));
        assert!(!state.try_acquire("b.com"));
        state.release("a.com");
        assert!(state.try_acquire("b.com"));
    }

    #[test]
    fn method_allowed_empty_list_allows_any() {
        assert!(method_allowed(&Method::GET, &[]));
        assert!(method_allowed(&Method::POST, &[]));
    }

    #[test]
    fn method_allowed_case_insensitive() {
        let allowed = vec!["post".to_string()];
        assert!(method_allowed(&Method::POST, &allowed));
        assert!(!method_allowed(&Method::GET, &allowed));
    }

    #[test]
    fn rewrite_path_longest_prefix_wins() {
        let rewrites = vec![
            crate::policy::agent::PathRewrite {
                from: "/v1".into(),
                to: "/api/v1".into(),
            },
            crate::policy::agent::PathRewrite {
                from: "/v1/messages".into(),
                to: "/api/chat".into(),
            },
        ];
        assert_eq!(rewrite_path("/v1/messages", &rewrites), "/api/chat");
        assert_eq!(rewrite_path("/v1/other", &rewrites), "/api/v1/other");
        assert_eq!(rewrite_path("/v2/x", &rewrites), "/v2/x");
    }

    #[test]
    fn rewrite_path_empty_rewrites_returns_input() {
        assert_eq!(rewrite_path("/anything", &[]), "/anything");
    }

    #[test]
    fn rewrite_path_no_matching_rule_passes_through() {
        let rewrites = vec![crate::policy::agent::PathRewrite {
            from: "/v1".into(),
            to: "/api".into(),
        }];
        assert_eq!(rewrite_path("/other", &rewrites), "/other");
        assert_eq!(rewrite_path("", &rewrites), "");
    }

    #[test]
    fn rewrite_path_empty_to_strips_prefix() {
        let rewrites = vec![crate::policy::agent::PathRewrite {
            from: "/v1".into(),
            to: String::new(),
        }];
        assert_eq!(rewrite_path("/v1/messages", &rewrites), "/messages");
        assert_eq!(rewrite_path("/v1", &rewrites), "");
    }

    #[test]
    fn rewrite_path_preserves_suffix_across_trailing_slash() {
        let rewrites = vec![crate::policy::agent::PathRewrite {
            from: "/v1/".into(),
            to: "/api/".into(),
        }];
        assert_eq!(rewrite_path("/v1/messages", &rewrites), "/api/messages");
        // A path that does not carry the trailing slash of `from` does not match.
        assert_eq!(rewrite_path("/v1", &rewrites), "/v1");
    }

    #[test]
    fn rewrite_path_to_without_leading_slash_is_kept_verbatim() {
        // Operator-supplied; the proxy does not re-anchor it. Documents
        // current behavior so a future change is an informed choice.
        let rewrites = vec![crate::policy::agent::PathRewrite {
            from: "/v1".into(),
            to: "api/v1".into(),
        }];
        assert_eq!(rewrite_path("/v1/x", &rewrites), "api/v1/x");
    }
}
