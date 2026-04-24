---
title: Environment variables
description: What gets set, what gets forwarded, and what gets refused.
---

The agent's environment is built from scratch rather than carried over from the parent. Three sets of variables go in. A small set is locked and cannot be overridden.

## Variables set by the sandbox

The following are set unconditionally and cannot be overridden by profile or agent `env` maps.

**HOME** is forwarded from the parent so the agent can find its own config directory.

**PATH** is built from the base profile's defaults (`/usr/local/bin`, `/usr/bin`, `/bin`) plus any `path_prepend` entries from merged profiles. Entries that do not exist on disk are dropped.

**TMPDIR** points at the session scratch directory, the same as `$TMP_DIR` in YAML substitution.

**HTTPS_PROXY** is set to the loopback tunnel proxy URL (`http://127.0.0.1:$TUNNEL_PORT`). This is how the agent's outbound traffic is routed through the proxy.

**NO_PROXY** is set to `127.0.0.1,localhost` so the agent does not try to tunnel loopback traffic through itself.

The sandbox also sets a handful of variables unconditionally to keep zsh well-behaved inside the session: **ZDOTDIR** (redirects startup file lookup to the scratch directory), **ZSH_COMPDUMP**, **ZSH_DISABLE_COMPFIX**, **HISTFILE**, **HISTSIZE**, and **SAVEHIST** (disables history). **TERM** is forwarded from the parent.

## Variables from the profile's env map

Profile level `env` entries add after the sandbox defaults, but before the locked vars above. Values go through variable substitution.

The base profile sets **TMPPREFIX** (so zsh's named pipe scratch files land under `$TMP_DIR/zsh`) and **PYTHONDONTWRITEBYTECODE** (so Python skips writing `.pyc` files next to read-only stdlib modules). Partials add things like `HOMEBREW_PREFIX` and `MISE_SHELL`.

## Variables from the agent's env map

The agent level `env` map applies after the profile level map. This is where the auth wiring lives. Each agent's YAML sets the variables it needs — for example the proxy URL and session token.

If the same variable is set by the profile and the agent, the agent value wins. The locked variables above always win over both.

## Variables the parent does not pass through

The env is built from scratch so nothing from the parent process leaks in. Additionally, if any passthrough pathway were used, the following variables are explicitly blocked because they could undermine the sandbox.

Loader hooks that inject code into every dynamic executable.

- `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_ASSUME_KERNEL`, `LD_BIND_NOW`, `LD_DYNAMIC_WEAKER`, `LD_POINTER_GUARD`, `LD_PROFILE`, `LD_PROFILE_OUTPUT`, `LD_SHOW_AUXV`, `LD_USE_LOAD_BIAS`
- `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`

glibc loader paths that read arbitrary files at startup.

- `GCONV_PATH`, `GETCONF_DIR`, `HOSTALIASES`, `LOCPATH`, `NLSPATH`, `RES_OPTIONS`

Shell startup hooks.

- `BASH_ENV`, `ENV`, `PROMPT_COMMAND`

Language runtime module and script paths.

- `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`, `PYTHONINSPECT`
- `NODE_PATH`, `NODE_OPTIONS`, `NODE_ENV`
- `RUBYLIB`, `RUBYOPT`
- `PERL5LIB`, `PERL5OPT`

Proxy and API routing that the sandbox controls.

- `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`
- `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`

## What the child sees

Inside the sandbox run `env` to see the exact set of variables. In shell mode this is the fastest way to check the agent file and profile file landed where you expected.

```sh
devlock --agent claude --shell
# inside the shell
env
```
