---
title: Variables
description: Substitution tokens in agent and profile YAML.
---

A small set of variables gets expanded in YAML strings at load time. These are not shell environment variables. They are tokens devlock substitutes before the agent starts.

## Supported variables

### ~/

Expands to the user's home directory. Only at the start of a string, and only when followed by `/`. A literal `~` without a slash stays as is.

```yaml
paths:
  read_only:
    - "~/.gitconfig" # becomes /home/you/.gitconfig
    - "~/.config/gh/config.yml"
```

### $CWD

The current working directory at startup. This is the directory you ran the command from.

```yaml
paths:
  full_access:
    - "$CWD"
  read_only:
    - "$CWD/.git/config"
    - "$CWD/.vscode"
```

### $TMP_DIR

The session scratch directory created for this run. It lives under `$XDG_RUNTIME_DIR/devlock/`, falling back to a private directory under `/tmp` when that variable is unset. It gets cleaned up when the session ends.

```yaml
paths:
  full_access:
    - "$TMP_DIR"

env:
  MYBOT_TMPDIR: "$TMP_DIR"
```

### $TUNNEL_PORT

The loopback port the proxy's CONNECT tunnel listens on. Picked at startup by binding `127.0.0.1:0` and reading back the port.

```yaml
env:
  HTTPS_PROXY: "http://127.0.0.1:$TUNNEL_PORT"
```

### $API_PORT

The loopback port the proxy's API forwarder listens on. Separate from the tunnel port. Also picked at startup.

```yaml
env:
  ANTHROPIC_BASE_URL: "http://127.0.0.1:$API_PORT"
```

### $SESSION_TOKEN

The 64-character hex token (32 bytes of random data) the proxy requires on every inbound request. It gets created at startup and handed to both the proxy and the agent. The agent reads it from whatever environment variable you wired it to in the agent file.

```yaml
env:
  ANTHROPIC_AUTH_TOKEN: "$SESSION_TOKEN"
```

## Where substitution happens

Substitution applies to any string value in an agent or profile file. That covers entries in every path bucket, every item in `path_prepend`, every value in the `env` map, the `executable` string, `credentials.file`, and the `proxy.inject_headers` values.

The `extends` and `includes` strings do not get substitution. Those are file names resolved against the policy directory at load time.

## Scope

Profile files only use `$CWD`, `$TMP_DIR`, and `~/`. The port and token variables are not available at profile resolve time because profiles bind to the host, not the session.

## Variables the parent does not pass through

The agent environment is built from scratch. Nothing from your shell session passes in automatically.

If a profile or agent file uses the `passthrough_env` key, the following variables are still blocked regardless.

**Variables devlock sets itself.** A value from the parent process would conflict or be wrong.

- `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` — managed by the proxy subsystem
- `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` — devlock routes API traffic and injects credentials
- `PATH`, `HOME`, `ZDOTDIR`, `TMPDIR` — set to sandbox-appropriate values at startup

**Variables blocked as sandbox escape vectors.** These can inject code or redirect file lookups before Landlock and seccomp take effect.

Dynamic linker:

- `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT` — load arbitrary native code
- `LD_ASSUME_KERNEL`, `LD_BIND_NOW`, `LD_DEBUG`, `LD_DYNAMIC_WEAKER`, `LD_POINTER_GUARD`, `LD_PROFILE`, `LD_PROFILE_OUTPUT`, `LD_SHOW_AUXV`, `LD_USE_LOAD_BIAS` — linker tuning and diagnostics
- `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH` — macOS linker equivalents, blocked defensively

glibc internals:

- `GCONV_PATH`, `GETCONF_DIR`, `GLIBC_TUNABLES`, `HOSTALIASES`, `LOCPATH`, `NLSPATH`, `RES_OPTIONS` — redirect charset, locale, and resolver lookups to arbitrary files

Shell startup hooks:

- `BASH_ENV` — sourced by bash on every non-interactive invocation
- `ENV` — sourced by sh/dash at startup
- `PROMPT_COMMAND` — executed before every prompt

Language runtimes:

- `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS` — JVM flag injection, including `-agentlib` for native code loading
- `NODE_OPTIONS`, `NODE_PATH` — Node.js code injection via `--require` and `--experimental-loader`
- `PERL5LIB`, `PERL5OPT` — Perl library path and interpreter options
- `PYTHONHOME`, `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONINSPECT` — Python runtime hooks
- `RUBYLIB`, `RUBYOPT`, `GEM_PATH`, `GEM_HOME` — Ruby library and gem paths
