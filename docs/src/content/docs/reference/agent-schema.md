---
title: Agent YAML schema
description: Every field accepted in an agent file.
---

Custom agent files shadow the built-in ones. See [user policy overrides](/devlock/guides/overrides/) for where to place them. Unknown fields are rejected, so anything not listed here is an error.

## Top level fields

### executable

Required string. The binary to exec after sandbox apply. An absolute path is used directly. Otherwise the name is looked up on `PATH`. Variable substitution runs first, so `~/bin/agent` works too.

```yaml
executable: claude
```

### extends

Optional string. Names a single parent agent to extend. The parent loads first, then this file overlays on top. Lists add up, map keys combine, and plain values from this file win.

```yaml
extends: base-bot.yaml
```

### includes

Optional list. Each entry names another YAML file to merge in before the outer file. Order matters. Later includes override earlier ones, and the outer file overrides all of them.

```yaml
includes:
  - partials/local-cache.yaml
  - partials/debug-logging.yaml
```

### credentials

Optional. Controls how devlock checks the agent is authenticated and how it runs the login flow on first use. See the section below.

### network_allowlist

Optional list of domain patterns. The proxy only forwards outbound requests to hosts that match one of these patterns. A pattern like `*.example.com` covers the apex and any subdomain at any depth.

```yaml
network_allowlist:
  - "*.anthropic.com"
  - anthropic.com
```

The agent's list merges with the profile's list at runtime.

### env

Optional map of environment variables to set in the child. Values go through variable substitution. This map cannot override devlock's blocked variables. See [environment variables](/devlock/reference/environment/).

```yaml
env:
  ANTHROPIC_BASE_URL: "http://127.0.0.1:$API_PORT"
  ANTHROPIC_AUTH_TOKEN: "$SESSION_TOKEN"
```

### agent_args

Optional list of extra arguments always prepended to the agent's argv. Passthrough args from the command line append after these.

```yaml
agent_args:
  - --non-interactive
```

### paths

Optional. The path buckets that apply to this agent. See [path access buckets](/devlock/reference/path-buckets/).

```yaml
paths:
  read_write:
    - "~/.cache/my-bot"
  read_only:
    - "~/.config/my-bot/settings.toml"
  dir_create:
    - "~/.cache/my-bot"
```

### tunnel

Optional map of connection limits for the proxy's CONNECT tunnel. All fields are positive integers.

```yaml
tunnel:
  max_connections: 128
  max_per_host: 32
  idle_timeout_secs: 30
```

The defaults above are what devlock uses if you omit the field.

### proxy

Required map describing the upstream API the proxy talks to. The `api_base_url` field is required. Everything else is optional.

```yaml
proxy:
  api_base_url: https://api.example.com
  oauth:
    token_url: https://auth.example.com/v1/oauth/token
    client_id: your-client-id
  inject_headers:
    x-custom-header: value
  allowed_methods:
    - GET
    - POST
  path_rewrites:
    - from: /v1/
      to: /api/v1/
```

`allowed_methods` restricts which HTTP methods the proxy will forward. Empty means no method restriction beyond the proxy's defaults.

`path_rewrites` is a list of prefix rewrites, applied longest match first.

`inject_headers` is a map of headers the proxy adds to every forwarded request.

## credentials

```yaml
credentials:
  format: claude_ai_oauth
  file: "~/.claude/.credentials.json"
  login_args:
    - /login
  login_executable: null
  device_flow: null
```

### format

Required. One of `claude_ai_oauth`, `static_token`, or `oauth_device_flow`.

`claude_ai_oauth` reads tokens from a Claude Code format JSON file. The file contains an `oauth` map with `accessToken`, `refreshToken`, and `expiresAt` fields.

`static_token` reads a single bearer token from a plain text file. The whole file contents become the token.

`oauth_device_flow` runs a browser device code flow and writes the resulting tokens to `file`.

### file

Path where credentials live on disk. Required for every format. Variable substitution applies.

### login_args

List of arguments passed to the login command on first run.

### login_executable

Optional path to a different binary to invoke for login. Defaults to the agent's own `executable`. Use this when the login flow is a separate tool from the agent.

### device_flow

Required when `format` is `oauth_device_flow`. Describes the OAuth device flow endpoints.

```yaml
device_flow:
  device_code_url: https://auth.example.com/device/code
  token_url: https://auth.example.com/oauth/token
  client_id: your-client-id
  scope: "read write"
```

## Validation

Agent files are validated at load time. Loading fails if the file is missing required fields, if `extends` or `includes` form a cycle, or if an unknown field is present.

Required field checks.

- `executable` must be set in this file or one of its ancestors.
- `proxy.api_base_url` must be a non empty URL.
- `credentials.file` must be present when `format` is `static_token`.
- `credentials.device_flow` must be present when `format` is `oauth_device_flow`.
