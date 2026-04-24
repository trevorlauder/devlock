---
title: Running an agent
description: Pick an agent, pick a profile, pass through arguments.
---

```sh
devlock --agent <name> --profile <name> [--] [agent args]
```

The `--agent` flag names the agent to run. The `--profile` flag names the policy profile and defaults to `default`. Anything after `--` is passed through to the agent as its own argv.

## Picking an agent

The bundled `claude` agent runs Claude Code. See the [Claude Code agent guide](/devlock/guides/agents/claude/) for login, credentials, and Claude-specific configuration. For your own agents, see the [custom agents guide](/devlock/guides/custom-agents/).

## Picking a profile

The `default` profile composes the base filesystem policy with the git, devcontainer, and VS Code protections.

The `base` profile has the minimum system grants. Other profiles extend it.

See the [profile schema](/devlock/reference/profile-schema/) for how composition works.

## Passing arguments to the agent

Everything after `--` goes to the agent binary without interpretation.

```sh
devlock --agent claude -- --print "what does this repo do"
```

The argument parser accepts leading hyphens, so you can pass flags directly.

```sh
devlock --agent claude -- --continue
```

## Where your current directory matters

The agent gets `full_access` to `$CWD`. The `default` profile marks specific files inside it read only (`.git/config`, `.git/hooks`, `.devcontainer`, `.vscode`), but the rest of `$CWD` is writable. Launch from a project directory, not your home directory.

## First run and login

When no credentials exist, the login flow runs first, then re-execs with the original arguments.

- `oauth_device_flow`: prints a URL and user code, then polls until the token arrives.
- `static_token`: prints an error with the expected file path.
- `claude_ai_oauth`: see the [Claude Code agent guide](/devlock/guides/agents/claude/).

## Stopping a session

The session ends when the agent exits normally or when you press `Ctrl C`. The parent shuts down the proxy and exits.
