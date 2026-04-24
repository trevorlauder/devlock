---
title: Claude Code
description: Login, credentials, and troubleshooting for the Claude Code agent.
---

The bundled `claude` agent runs [Claude Code](https://claude.ai/code) inside the sandbox. For the full agent YAML see the [claude agent reference](/devlock/guides/agents/claude/).

## First run

The first time you run devlock with no credentials on disk, the login flow starts automatically, then devlock re-executes with your original arguments once the credentials are in place.

```sh
devlock --agent claude
```

This shells out to `claude /login` and waits for `~/.claude/.credentials.json` to appear. Complete the OAuth flow in the browser. When the credentials file is written, the login process exits and devlock starts the session.

## Credentials

The Claude agent uses `claude_ai_oauth`. Credentials are stored in `~/.claude/.credentials.json`. The proxy reads the access token from that file at startup, holds it in memory, and injects it on every outbound request. The agent never sees the real token.

The proxy refreshes the token automatically when it is close to expiry. If the refresh fails, the session ends. Delete `~/.claude/.credentials.json` and run devlock again to get a fresh token.

## Troubleshooting

**Login failed, no credentials written.** The `claude` binary is not on `PATH`, the browser did not complete the OAuth round trip, or the credentials file path was overridden. Check that `claude` is installed and accessible, then try again.

**OAuth refresh failed.** The refresh token was revoked, the clock is skewed, or `https://platform.claude.com` is unreachable. Delete `~/.claude/.credentials.json` and run devlock again to trigger a fresh login.
