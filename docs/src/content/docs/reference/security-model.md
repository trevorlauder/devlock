---
title: Security model
description: What the sandbox protects against, what it does not, and where the boundaries sit.
---

The agent is treated as untrusted. The kernel, the invoking user, and the rest of the host are the things being protected.

## What gets protected

### File system

The agent cannot read or write outside the buckets the agent and profile files grant. Landlock enforces that at the kernel on every access.

Inside a `full_access` area like `$CWD`, specific files can still be marked `read_only`. Landlock cannot enforce this because its grants are additive. The write permission on the parent propagates down. The supervisor is the only gate. A TOCTOU race is possible between when the supervisor reads the path and when the kernel acts on the call.

The default policy uses this for `.git/config` and `.git/hooks`. Both can trigger code execution on the host: `.git/config` through git aliases and `core.sshCommand`, `.git/hooks` through post-commit and pre-push hooks that run whenever the user invokes git. The rest of `.git` is left writable so normal git operations work. The protection is best-effort for the reason above.

The agent's credentials file is never reachable from inside the sandbox. The policy loader refuses to open it through any bucket, and a startup check confirms it is not covered by any Landlock rule.

### Network

The agent cannot open a raw socket to the internet. Landlock's network rules only allow connections to the two proxy ports, and binding new ports is blocked entirely.

All outbound HTTPS traffic is routed through the tunnel proxy (`$TUNNEL_PORT`). It only accepts `CONNECT` requests to port 443. Every target host is matched against the merged allowlist before a connection is opened. The proxy also resolves the hostname before connecting and rejects any address that is loopback, private, link-local, or otherwise non-public. That is the DNS rebind defense. The proxy runs as the host user outside the sandbox, so a connection it opens to `127.0.0.1` or `169.254.169.254` reaches host-local services and cloud metadata endpoints that the sandboxed agent cannot touch directly. An attacker-controlled domain on the allowlist that resolves to such an address would let the agent reach those services through the proxy.

Direct API calls go through the API forwarder (`$API_PORT`). This port requires a valid session token on every request. Anything without one is rejected before any forwarding happens. The forwarder also strips the agent's token and replaces it with the real upstream credential before sending, so the agent never sees the actual key.

### Credentials

The agent never sees the upstream credentials. The proxy holds the credential in memory and injects it on outbound requests. The token the agent sees is a per-session token scoped to the current run. It only unlocks calls through the proxy to hosts on the allowlist.

Three credential formats are supported. `claude_ai_oauth` and `oauth_device_flow` hold an access token and a refresh token. `static_token` holds a single API key read from a file. In all cases the proxy injects the real credential and the agent never receives it.

After the proxy worker starts, the parent process clears its own copy of the credential from memory. If something later breaks into the parent, it still cannot read it out of its memory.

### Privilege

A kernel flag called `PR_SET_NO_NEW_PRIVS` stops any setuid binary from gaining privileges inside the sandbox. Every Linux capability set that could hand power back to the agent is cleared, and the capability lock bits get pinned so nothing can bring them back.

### Other processes

Landlock also scopes abstract Unix sockets and signals to the agent's own process tree. The agent cannot talk to a daemon on the host through an abstract socket, and it cannot send signals to other processes outside the sandbox.

### Environment

A long list of environment variables gets stripped on the way in. Loader hooks like `LD_PRELOAD`, proxy overrides like `HTTP_PROXY`, runtime module hooks like `PYTHONPATH`, and shell startup hooks like `BASH_ENV` never reach the child. Listing them in an agent file's `env` map does not change that. See [environment variables](/devlock/reference/environment/).

## What is not protected

### Kernel bugs

Landlock and seccomp are kernel features. A kernel exploit that bypasses them sits outside this model. Landlock ABI v6 is pinned partly to keep the attack surface stable, but a kernel level compromise defeats the whole design.

### /proc/self

The agent can read its own process state through `/proc/self`, including its environment variables and open file descriptors. Anything the parent hands to the agent at startup is visible to it. The credentials file and a fixed list of sensitive variables are explicitly kept out, but any sensitive value you add to the `env` map in a policy file will be readable by the agent.

### Resource exhaustion

The agent can fill `$CWD` or `$TMP_DIR` with junk and crash the parent if memory runs out. The proxy caps connection counts but not bandwidth. CPU and memory usage are not sandboxed.

### Policy mistakes

Whatever policy you write is what gets enforced. Listing `$HOME` as `full_access` means the agent can read your SSH keys. The bundled policies are defensive about what they grant. Custom policies are on you.

## Defense in depth

The design is layered so that one layer breaking does not break the whole sandbox.

The kernel file system boundary, the system call supervisor, the capability reset, and the local proxy all have to hold together for the sandbox to be sound. A race in the supervisor cannot get past Landlock. A bug in the proxy cannot open a raw socket because the kernel refuses them. A capability escalation goes nowhere because `PR_SET_NO_NEW_PRIVS` blocks it.
