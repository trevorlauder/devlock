---
title: Troubleshooting
description: Things that commonly go wrong on a devlock session.
---

Check [inspect mode](/devlock/guides/inspect/) and the seccomp log first.

## Landlock ABI V6 not supported by this kernel

Your kernel is older than 6.10 or was built with Landlock disabled. `uname -r` tells you the version. On Ubuntu LTS, the HWE kernel in the backports repo is usually new enough.

The tool refuses to run on a kernel without Landlock v6 support.

## login failed, no credentials written at ...

For `claude_ai_oauth` agents, the login process shells out to the agent binary with the configured `login_args` and waits for the credentials file to appear. When that file never shows up, the error reports where it was looking.

For `static_token` agents, this error means the file has not been created yet. Write your bearer token into the path listed in `credentials.file` and try again.

For Claude-specific login troubleshooting, see the [Claude Code agent guide](/devlock/guides/agents/claude/).

## zsh or bash not found in PATH

One of them is required at runtime. Install whichever you prefer with your package manager. `apt install zsh`, `brew install zsh`, `apt install bash`, whatever fits your distro.

## bucket conflict errors

The error reads something like `bucket conflict: "..." is listed in read_only and full_access`. A profile after merge contains the same path string in `read_only` and in a write capable bucket. The check is string equality, so a `$CWD/.git/config` in `read_only` and a `$CWD` in `full_access` do not conflict. This error means a later include or override put the literal same string in both.

Fix the YAML to pick one bucket.

## Agent exits immediately with a denial

The agent tried a syscall that policy refuses before it could even start. The denial will be in `seccomp.log` and on stderr through the auto post mortem.

Common offenders. Reading a config file whose path is not in any bucket. Opening a local cache directory the profile did not grant. Spawning a helper whose binary is not on any `read_exec` path.

Run inspect mode and look at the resolved paths. If the path the agent wanted is not there, add it either to the agent file or the profile, depending on whether it is agent specific or host wide.

## Network requests fail with 401

The proxy could not match the request's session token against the one it generated. That almost always means the agent did not read `ANTHROPIC_AUTH_TOKEN` (or whatever your agent's auth variable is named) before making the request.

Check your agent file's `env` map. Whatever variable your agent uses for auth needs to be set to `$SESSION_TOKEN` so the proxy can validate it.

## Network requests fail with "host not allowed"

The destination host did not match the merged allowlist. Add it to the profile's `network_allowlist` or, if it is strictly an agent concern, the agent's `network_allowlist`.

`*.anthropic.com` matches the apex and any subdomain at any depth. If your host still fails to match, double check for typos and make sure it does not end with an extra unrelated suffix.

## OAuth refresh failed

The proxy refreshes OAuth tokens when the upstream returns an auth error. If the refresh itself fails, the session ends. Usually this means the refresh token was revoked, the clock is skewed, or the token URL is unreachable. Delete the credentials file and start again to trigger a fresh login. See your agent's guide for the credentials file location.
