---
title: Shell mode
description: Open an interactive shell inside the sandbox.
---

Shell mode runs an interactive shell under the same Landlock and seccomp policies as the agent.

## Start a sandboxed shell

```sh
devlock --agent claude --shell
```

The agent's paths, the profile's paths, and the merged environment all apply, then the shell execs in place of the agent binary. Devlock picks zsh or bash: `$SHELL` wins if it names one of them, otherwise zsh is preferred and bash is the fallback.

## What you can and cannot do

The shell is under the same restrictions as the agent. Reads and writes outside `$CWD` fail unless the profile opens them up. Network calls have to go through the proxy on loopback, and the proxy still checks the session token and the domain allowlist.

```sh
# Inside the sandboxed shell
cat ~/.ssh/id_rsa          # blocked by Landlock
touch /etc/hosts           # blocked
curl https://example.com   # blocked at the Landlock network layer
env | grep ANTHROPIC       # shows the injected base url and session token
```

An outbound request through the proxy does work if the destination is on the agent's allowlist.

## Why your dotfiles do not load

Devlock skips user startup files. For zsh the scratch temp directory is seeded with an empty `.zshrc` and zsh's startup file lookup is redirected there via `ZDOTDIR`. For bash the shell is launched with `--norc --noprofile`. Your `HOME` is still set, but your real dotfiles never run. That keeps shell hooks, PATH shims, and plugin managers from contaminating the session.

If you need a setting for your work, put it in the profile's `env` map or `path_prepend` list instead of in your shell rc.

## Scratch paths

Shell mode exposes the same variables the YAML loader uses. `$TMP_DIR` points at the session scratch directory inside `$XDG_RUNTIME_DIR/devlock/`. Everything inside has `full_access`, and it gets cleaned up when the session ends.

## Exiting

`exit` or `Ctrl D` ends the shell. The parent kills the proxy and exits with the shell's status.
