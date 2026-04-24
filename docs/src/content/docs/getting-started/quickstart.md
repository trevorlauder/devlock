---
title: Quickstart
description: Run an agent inside devlock for the first time.
---

## 1. Change into a project directory

The agent gets full access to the directory you launch devlock from and nothing else by default. That directory is captured at startup as `$CWD` and does not change if the agent runs `cd` internally. A profile can open up more, but nothing outside that directory is reachable otherwise.

```sh
cd ~/code/my-project
```

## 2. Launch the agent

This example uses the bundled `claude` agent. If your agent requires login on first run, it will run the login flow and re-execute automatically. See the [Claude Code agent guide](/devlock/guides/agents/claude/) for details.

```sh
devlock --agent claude
```

Uses the `default` profile.

## 3. Pass arguments through to the agent

Anything after `--` goes to the agent verbatim. That is how you hand it a prompt, flags, or a one shot command.

```sh
devlock --agent claude -- "summarize the README"
```

## 4. Read the session banner

A few lines print before the agent starts.

```
Landlock ABI: V6
  fs:    Execute | WriteFile | ReadFile | ReadDir | RemoveDir | RemoveFile | MakeChar | MakeDir | MakeReg | MakeSock | MakeFifo | MakeBlock | MakeSym | Refer | Truncate | IoctlDev
  net:   BindTcp (denied) | ConnectTcp (ports 38223, 43245)
  scope: AbstractUnixSocket | Signal
[devlock] logs: /home/you/.local/state/devlock/logs/logs-1713808123-4321
[devlock] proxy pid: 4322
```

The first block is the active Landlock policy. It shows the ABI version negotiated with the kernel, the filesystem operations the agent is allowed, any network port restrictions, and scope isolation settings. The `logs` line is the directory where this session's logs are written. The `proxy pid` line is the PID of the HTTP proxy the agent's traffic is routed through.

## What to do next

See [shell mode](/devlock/guides/shell/) and [writing a custom agent](/devlock/guides/custom-agents/).
