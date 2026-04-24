//! Proxy resilience harness. Spawns the real proxy against fresh
//! loopback listeners and exercises the class of attacks an in-sandbox
//! agent can reach: flood, slowloris, oversized headers, malformed TLS,
//! CONNECT line fuzz. Each sub probe runs in isolation; a hang or crash
//! in one must not affect the others. After each sub probe, confirm the
//! fail closed contract still holds (407 with no token, 403 on a
//! disallowed CONNECT).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use devlock::policy::agent::{ProxyConfig, TunnelConfig};
use devlock::proxy;

const SESSION_TOKEN: &str = "00000000000000000000000000000000";

struct ProxyHandles {
    tunnel_port: u16,
    api_port: u16,
}

fn spawn_proxy() -> ProxyHandles {
    let tunnel = TcpListener::bind("127.0.0.1:0").expect("tunnel bind");
    let api = TcpListener::bind("127.0.0.1:0").expect("api bind");
    let tunnel_port = tunnel.local_addr().unwrap().port();
    let api_port = api.local_addr().unwrap().port();

    let allowlist = vec!["api.anthropic.com".to_string()];
    let tunnel_cfg = TunnelConfig::default();
    let proxy_cfg = ProxyConfig {
        api_base_url: "https://api.anthropic.com".to_string(),
        oauth: None,
        inject_headers: Default::default(),
        allowed_methods: vec!["POST".into(), "GET".into()],
        path_rewrites: vec![],
    };

    thread::spawn(move || {
        let _ = proxy::run_proxy(
            proxy::ProxyCredentials {
                access_token: "placeholder-access".into(),
                refresh_token: "placeholder-refresh".into(),
                expires_at_ms: u64::MAX,
                session_token: SESSION_TOKEN.into(),
            },
            proxy::ProxyListeners { tunnel, api },
            allowlist,
            tunnel_cfg,
            proxy_cfg,
        );
    });

    // Wait for listeners to be accepting. The proxy takes a moment to
    // enter its tokio runtime.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(("127.0.0.1", tunnel_port)).is_ok()
            && TcpStream::connect(("127.0.0.1", api_port)).is_ok()
        {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("proxy listeners never came up");
        }
        thread::sleep(Duration::from_millis(25));
    }
    ProxyHandles {
        tunnel_port,
        api_port,
    }
}

fn short_request(addr: (&str, u16), req: &[u8], read_up_to: usize) -> Vec<u8> {
    let mut s = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    s.set_read_timeout(Some(Duration::from_secs(2))).ok();
    s.set_write_timeout(Some(Duration::from_secs(2))).ok();
    let _ = s.write_all(req);
    let mut buf = vec![0u8; read_up_to];
    let mut got = 0;
    while got < read_up_to {
        match s.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => {
                got += n;
                if buf[..got].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    buf.truncate(got);
    buf
}

fn fail_closed_intact(h: &ProxyHandles) -> (Vec<u8>, Vec<u8>) {
    let api_resp = short_request(
        ("127.0.0.1", h.api_port),
        b"GET / HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: close\r\n\r\n",
        512,
    );
    let tun_resp = short_request(
        ("127.0.0.1", h.tunnel_port),
        b"CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n",
        512,
    );
    (api_resp, tun_resp)
}

fn assert_fail_closed(h: &ProxyHandles, label: &str) {
    let (api, tun) = fail_closed_intact(h);
    assert!(
        api.starts_with(b"HTTP/1.1 407"),
        "{label}: API port did not 407 after attack. got: {:?}",
        String::from_utf8_lossy(&api)
    );
    assert!(
        tun.starts_with(b"HTTP/1.1 403"),
        "{label}: tunnel did not 403 disallowed CONNECT after attack. got: {:?}",
        String::from_utf8_lossy(&tun)
    );
}

#[test]
fn proxy_survives_connect_line_fuzz_and_stays_fail_closed() {
    let h = spawn_proxy();
    let fuzz: &[&[u8]] = &[
        b"\x00\x01\x02 garbage\r\n\r\n",
        b"CONNECT \xff\xfe:443 HTTP/1.1\r\n\r\n",
        b"CONNECT target\x00tail:443 HTTP/1.1\r\n\r\n",
        b"CONNECT %00%00%00:443 HTTP/1.1\r\n\r\n",
        b"CONNECT github.com:99999999 HTTP/1.1\r\n\r\n",
        b"CONNECT ::1:443 HTTP/1.1\r\n\r\n",
        b"github.com:443 HTTP/1.1\r\n\r\n",
        b"CONNECT github.com:443 HTTP/1.1\r\n\r\nCONNECT evil.example:443 HTTP/1.1\r\n\r\n",
    ];
    for req in fuzz {
        let _ = short_request(("127.0.0.1", h.tunnel_port), req, 256);
    }
    assert_fail_closed(&h, "after CONNECT fuzz");
}

#[test]
fn proxy_survives_oversized_requests_and_stays_fail_closed() {
    let h = spawn_proxy();
    let big_host = vec![b'X'; 1 << 20]; // 1 MiB Host
    let mut req = Vec::with_capacity(big_host.len() + 128);
    req.extend_from_slice(b"CONNECT ");
    req.extend_from_slice(&big_host);
    req.extend_from_slice(b":443 HTTP/1.1\r\nHost: z\r\n\r\n");
    let _ = short_request(("127.0.0.1", h.tunnel_port), &req, 256);

    let mut many = Vec::new();
    many.extend_from_slice(b"CONNECT github.com:443 HTTP/1.1\r\n");
    for i in 0..2000 {
        many.extend_from_slice(format!("X-Fuzz-{i}: y\r\n").as_bytes());
    }
    many.extend_from_slice(b"\r\n");
    let _ = short_request(("127.0.0.1", h.tunnel_port), &many, 256);

    let huge_header = format!(
        "CONNECT github.com:443 HTTP/1.1\r\nX-Big: {}\r\n\r\n",
        "y".repeat(256 * 1024)
    );
    let _ = short_request(("127.0.0.1", h.tunnel_port), huge_header.as_bytes(), 256);

    assert_fail_closed(&h, "after oversized");
}

#[test]
fn proxy_survives_slowloris_and_stays_fail_closed() {
    let h = spawn_proxy();
    let mut holders = Vec::new();
    for _ in 0..16 {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", h.tunnel_port)) {
            s.set_write_timeout(Some(Duration::from_millis(200))).ok();
            let _ = s.write_all(b"CONNECT api.anthropic.com:443\r\n");
            holders.push(s);
        }
    }
    thread::sleep(Duration::from_millis(300));
    assert_fail_closed(&h, "during slowloris");
    drop(holders);
    thread::sleep(Duration::from_millis(100));
    assert_fail_closed(&h, "after slowloris drop");
}

#[test]
fn proxy_survives_flood_and_stays_fail_closed() {
    let h = spawn_proxy();
    let mut threads = Vec::new();
    for _ in 0..8 {
        let tp = h.tunnel_port;
        threads.push(thread::spawn(move || {
            for _ in 0..128 {
                let _ = TcpStream::connect_timeout(
                    &format!("127.0.0.1:{tp}").parse().unwrap(),
                    Duration::from_millis(100),
                );
            }
        }));
    }
    for t in threads {
        let _ = t.join();
    }
    assert_fail_closed(&h, "after flood");
}

#[test]
fn api_port_rejects_malformed_tls_bytes() {
    let h = spawn_proxy();
    // Garbage bytes framed as a ClientHello would be interpreted as a
    // plain HTTP request by the non TLS API port. Send a byte string
    // that starts with 0x16 0x03 (TLS handshake / TLS 1.x) then junk.
    let junk: &[&[u8]] = &[b"\x16\x03\x01\x00\x01A", b"\x00\x00\x00", b"GET ????\r\n"];
    for j in junk {
        let _ = short_request(("127.0.0.1", h.api_port), j, 256);
    }
    assert_fail_closed(&h, "after malformed bytes on API port");
}

#[test]
fn proxy_rejects_http2_preface_and_websocket_upgrade() {
    let h = spawn_proxy();
    let r1 = short_request(
        ("127.0.0.1", h.tunnel_port),
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        256,
    );
    assert!(
        r1.is_empty() || r1.starts_with(b"HTTP/1.1 4"),
        "tunnel must not accept HTTP/2 preface: {:?}",
        String::from_utf8_lossy(&r1)
    );
    let r2 = short_request(
        ("127.0.0.1", h.tunnel_port),
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        256,
    );
    assert!(
        r2.starts_with(b"HTTP/1.1 405") || r2.starts_with(b"HTTP/1.1 400"),
        "tunnel must refuse WS upgrade: {:?}",
        String::from_utf8_lossy(&r2)
    );
    assert_fail_closed(&h, "after preface/upgrade attempts");
}
