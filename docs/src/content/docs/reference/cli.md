---
title: CLI flags
description: Every flag devlock accepts.
---

```
devlock --agent <name> [--profile <name>] [--inspect] [--shell] [-- <args>]
```

## --agent &lt;name&gt;

Required. Names the agent to run. Built-in agents are listed under [Built-in agents](/devlock/guides/agents/claude/). See [user policy overrides](/devlock/guides/overrides/) to add your own.

```sh
devlock --agent claude
devlock --agent my-custom-agent
```

## --profile &lt;name&gt;

Optional. Defaults to `default`. Names the profile to apply. Built-in profiles are listed under [Built-in profiles](/devlock/guides/profiles/default/). See [user policy overrides](/devlock/guides/overrides/) to add your own.

```sh
devlock --agent claude --profile default
devlock --agent claude --profile my-profile
```

## --inspect

Optional. Print the resolved configuration and exit. Does not start the proxy, does not fork the agent, does not apply any sandbox. See [inspect mode](/devlock/guides/inspect/).

```sh
devlock --agent claude --inspect
```

## --shell

Optional. Open an interactive zsh inside the sandbox instead of launching the agent binary. The shell runs under the same Landlock and seccomp policy the agent would. See [shell mode](/devlock/guides/shell/).

```sh
devlock --agent claude --shell
```

## -- &lt;args&gt;

Everything after `--` is passed to the agent as its own argv. Leading hyphens are allowed, so you can forward flags straight through.

```sh
devlock --agent claude -- --print "hello"
devlock --agent claude -- --continue
```

## Environment variables

`XDG_RUNTIME_DIR` controls where the scratch directory goes. When unset, a private directory under `/tmp` is used instead.

`XDG_STATE_HOME` controls where logs land. When unset, the default is `~/.local/state`.

## Exit codes

A clean run exits with the agent's own exit code. Zero if the agent returned zero, whatever the agent returned otherwise.

An agent killed by a signal causes a post mortem to print on stderr and a non zero exit.

A failure before the agent even forks (bad policy, missing kernel feature, missing binary) also exits non zero with an error on stderr.
