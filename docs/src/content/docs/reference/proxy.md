---
title: Proxy
description: The CONNECT proxy and the agent API proxy.
---

There are two separate proxies, each on its own local port. They do different jobs and are documented separately below. Both bind on `127.0.0.1:0` at startup so the kernel picks a free port, and both ports get written into the Landlock network rules and the agent's environment.

## CONNECT proxy

Port available as `$TUNNEL_PORT`. This is a plain HTTP proxy that the agent's tools use through `HTTPS_PROXY`. It handles CONNECT to allowed upstream hosts.

It does three things on every request.

**Port restriction.** Only port 443 is accepted. CONNECT to any other port is refused before the allowlist check runs.

**Allowlist matching.** The destination host is checked against the merged agent and profile allowlists. `anthropic.com` is an exact match. `*.anthropic.com` covers the apex and any subdomain at any depth. Anything else fails before the proxy dials.

**DNS rebind defense.** After a host matches, the resolved IP is checked against all non public ranges. Loopback, link local, private RFC 1918, cloud metadata (`169.254.169.254`), multicast, broadcast, and reserved addresses all fail. An allowlist entry whose DNS points at an internal address cannot sneak through.

Tunnel connections are subject to three limits set in the agent file under `tunnel`. `max_connections` caps concurrent tunnels across all hosts (default 128). `max_per_host` caps concurrent tunnels to any one host (default 32). `idle_timeout_secs` closes tunnels with no traffic for that many seconds (default 30).

This proxy never sees the agent's session token, and it does not hold the upstream OAuth credentials. Its only job is allowlist enforcement.

## Agent API proxy

Port available as `$API_PORT`. The agent uses this to make its own API calls, usually by pointing its own `ANTHROPIC_BASE_URL` style env var at it. The agent sends plain HTTP on loopback, and the proxy forwards each request over HTTPS to the `api_base_url` set in the agent file.

This proxy does the same allowlist and DNS rebind checks described above, plus everything below.

**Session token.** Every request must carry `Authorization: Bearer <session-token>`. The token is a 64-character hex string (32 bytes from `getrandom`) generated at startup and handed to the agent through an env var after the sandbox is in place. It is never persisted.

**Credential swap.** For agents that use OAuth, the proxy strips the session token from `Authorization` and replaces it with the real upstream access token it holds. The agent never sees the real token. When the token expires, the proxy refreshes it using the refresh token in the background.

**Header injection.** The `proxy.inject_headers` map in the agent file adds headers to every forwarded request. Injected values replace whatever the agent sent under the same name.

**Method filter.** `proxy.allowed_methods` in the agent file, if set, restricts which HTTP methods the proxy forwards. Anything not on the list gets rejected before the body is read.

**Path rewrites.** `proxy.path_rewrites` is a list of `from`/`to` prefix pairs. The longest matching prefix rewrites the path on the way upstream.

```yaml
proxy:
  path_rewrites:
    - from: /v1/
      to: /api/v1/
```

**Body limits.** Request bodies cap at 8 MB. Response bodies cap at 16 MB. Larger payloads abort with an error. Streaming responses within the cap pass through.

## Restart on crash

Each listener runs under a small supervisor loop inside the proxy process. A panic or fatal error in the accept loop gets logged, the supervisor sleeps with exponential backoff (100 ms up to 5 s), and then starts the listener again on the same socket. A crash in one request does not end the session.

## The proxy's own sandbox

The proxy process applies its own Landlock and seccomp rules after startup. It can read `/usr`, `/lib`, `/lib64`, and all of `/etc` for TLS certificates and DNS. It can write only to the session log directory. It cannot open new listening sockets or signal processes outside the sandbox. Even if the proxy is compromised it cannot escape to the host.
