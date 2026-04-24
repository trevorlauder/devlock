---
title: Logs and post mortems
description: Where devlock writes logs and how to read them after a bad session.
---

Every session writes two log files into its own log directory under `$XDG_STATE_HOME/devlock/logs/`. The directory name is `logs-<unix-timestamp>-<pid>`. Anything older than 14 days gets pruned at the next startup.

The session banner tells you where the logs landed.

```
[devlock] logs: /home/you/.local/state/devlock/logs/logs-1713808123-4321
[devlock] proxy pid: 4322
```

## seccomp.log

`seccomp.log` is the supervisor log. Every line is a JSON record emitted by the tracing crate in a stable schema. The interesting fields are `level`, `event`, `syscall`, and `path`.

A denial looks like this.

```json
{
  "level": "WARN",
  "event": "denied",
  "syscall": "openat",
  "path": "/etc/hosts",
  "mode": "write"
}
```

A fatal event (supervisor cannot continue, or a syscall the supervisor refuses to handle) looks like this.

```json
{ "level": "ERROR", "event": "supervisor_error", "reason": "..." }
```

Denials are expected. Policy refused a syscall, the child got `EACCES` or `EPERM`, and continued.

Errors mean a supervisor invariant failed or the path could not be read from the child's memory.

## network.log

`network.log` is the proxy log. One JSON record per request. Useful fields are the method, the host, the status code, and an explanation field if the request was blocked.

Blocked examples include

- requests without a valid session token
- hosts that do not match the allowlist
- bodies that exceed the 8 MB request limit or the 16 MB response limit
- methods that the agent's profile does not allow for that path

Successful requests show the upstream status code.

## Auto post mortem on abnormal exit

If the agent exits with a non zero code or gets killed by a signal, the parent tails the seccomp log for you on the way out. A block like this prints on stderr.

```
[devlock] agent exited with code 1
[devlock] fatal events:
  {"level":"ERROR","event":"supervisor_error",...}
[devlock] last denials:
  {"level":"WARN","event":"denied","syscall":"openat","path":"..."}
  ...
[devlock] log: /home/you/.local/state/devlock/logs/logs-1713808123-4321/seccomp.log
```

Denials are capped at the last five so the terminal does not drown in noise. The full log is still at the path it prints.

On a clean exit nothing prints.

## Reading logs after the fact

Both files are newline delimited JSON, so `jq` is the easiest tool.

```sh
# All denials for a session
jq -c 'select(.event == "denied")' seccomp.log

# Unique paths that got denied
jq -r 'select(.event == "denied") | .path' seccomp.log | sort -u

# All upstream requests that returned 4xx or 5xx
jq -c 'select(.status != null and .status >= 400)' network.log
```

## Common denial patterns

Some denials are expected noise and do not mean anything is broken.

Python bytecode writes. Python tries to write `__pycache__` next to every module it imports. The base profile sets `PYTHONDONTWRITEBYTECODE=1` for this reason, but if you bypass that, you will see a lot of `openat` denials for `.pyc` files.

Shell scratch files. zsh writes named pipe scratch files under `$TMPPREFIX`. The base profile redirects that to `$TMP_DIR/zsh`. Without that you would see denials against `/tmp/zsh*`.

Proc access. Tools sometimes scan `/proc/<other_pid>/*` looking for information about other processes. Those reads return `EACCES` from the supervisor's proc mount leak handler. Ignore them unless they are from a process that legitimately needed the info.
