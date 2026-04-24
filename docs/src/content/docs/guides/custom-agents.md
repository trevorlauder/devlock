---
title: Writing a custom agent
description: Extend a built-in agent or point devlock at a new binary.
---

An agent file names the binary to run, describes how it authenticates, lists the domains it needs, and sets the paths it should be allowed to touch.

## Extending a built-in agent

The most common case is adding paths or domains on top of a built-in agent. Use `extends` to inherit everything from it and add only what you need.

```yaml
extends: claude.yaml

paths:
  read_write:
    - "~/.config/my-team/shared-cache"

network_allowlist:
  - registry.example.com
```

Drop this file in `~/.config/devlock/policy/agents/my-claude.yaml` and run:

```sh
devlock --agent my-claude
```

Lists merge (your entries add to the parent's), map keys combine, and plain scalar values from your file win over the parent's.

## Writing a new agent from scratch

For a completely new binary, the two required fields are `executable` and `proxy.api_base_url`. Everything else has sensible defaults.

```yaml
executable: my-bot

proxy:
  api_base_url: https://api.example.com

credentials:
  format: static_token
  file: "~/.config/my-bot/token"

network_allowlist:
  - api.example.com
```

Drop this in `~/.config/devlock/policy/agents/my-bot.yaml` and run:

```sh
devlock --agent my-bot
```

## Credential formats

Three credential flows are supported.

`claude_ai_oauth` reads OAuth tokens from a JSON file in the Claude Code format. Pair it with a `login_args` list and the first run will invoke your agent with those args to populate the file. See the [Claude Code agent guide](/devlock/guides/agents/claude/) for details on this format.

`static_token` reads a single bearer token from a file. Nothing fetches it for you, so a missing file causes login to print an error telling you where to put the token.

`oauth_device_flow` runs a browser device code flow against a custom OAuth provider. Provide `device_code_url`, `token_url`, `client_id`, and an optional `scope`. The verification URL and user code print on login, the token endpoint gets polled, and the result lands on disk.

See the [agent schema](/devlock/reference/agent-schema/) for every field and its defaults.

## Paths

The path buckets in an agent file merge with the profile's. Use them for paths the agent specifically needs. Put shared host configuration in a profile, not an agent file.

```yaml
paths:
  read_write:
    - "~/.cache/my-bot"
    - "~/.local/share/my-bot"
  read_only:
    - "~/.config/my-bot/config.toml"
  dir_create:
    - "~/.cache/my-bot"
```

[Path access buckets](/devlock/reference/path-buckets/) explains what each bucket allows.

## Environment variables

Agents usually need a base URL, an auth header, or similar wired through the process environment. Set them in the `env` map with variable substitution.

```yaml
env:
  MYBOT_API_URL: "http://127.0.0.1:$API_PORT"
  MYBOT_AUTH_TOKEN: "$SESSION_TOKEN"
  MYBOT_TMPDIR: "$TMP_DIR"
```

`$API_PORT` is the loopback port used for API style traffic. `$SESSION_TOKEN` is the 64-character hex token the proxy requires on every request. `$TMP_DIR` is the session scratch directory. See [variables](/devlock/reference/variables/) for the full list.

An `env` map cannot override the [blocked environment variables](/devlock/reference/environment/). That list includes things like `LD_PRELOAD`, `HTTP_PROXY`, and `PYTHONPATH` that would undermine the sandbox if set from inside.

## Network allowlist

List the domains your agent needs to talk to. Both wildcards and exact hostnames work. A `*.example.com` entry covers the apex and any subdomain at any depth.

```yaml
network_allowlist:
  - "*.example.com"
  - api.example.com
  - auth.example.com
```

At runtime this list merges with the profile's allowlist, gets lowercased, and deduplicates. The proxy matches the `Host` header on inbound requests against the merged set.

## Composing with includes

Both built-in and custom agents can pull in partials to share reusable chunks across agent files.

```yaml
extends: base-bot.yaml

includes:
  - partials/local-cache.yaml
  - partials/debug-logging.yaml

executable: my-bot
```

Lists add up, map keys combine, and plain values from the outer file win.

## Verifying

Run inspect mode to check your file parses and the paths resolve.

```sh
devlock --agent my-agent --inspect
```

If it prints without errors, the file is valid.
