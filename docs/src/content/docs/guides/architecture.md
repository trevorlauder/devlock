---
title: How devlock works
description: The processes, kernel features, and proxy that make up the sandbox.
---

The sandbox is built from four pieces working together. A kernel level file system boundary, a system call supervisor in user space, a capability reset, and a local proxy that holds your credentials. This page walks through how they fit together.

## Process layout

Every session runs three processes.

The **parent** stays alive for the whole session, running the supervisor that answers system call questions from the agent and reaping its children on exit.

The **proxy worker** hosts two separate proxies on two loopback ports. A CONNECT proxy the agent's tools use via `HTTPS_PROXY` for general traffic, and an API proxy the agent uses for its own upstream calls. If a listener crashes, an internal restart loop brings it back on the same socket.

The **agent** is the third process. It runs under all the sandbox restrictions and exec's the binary you configured.

When the agent exits, the parent kills the proxy and exits.

## File system boundary

Before exec, a Landlock rule set binds to the agent and every process it spawns. The kernel checks those rules on every file access. Landlock ABI V6 is required. Devlock refuses to start on kernels that do not support it.

The one thing Landlock cannot do is take access away. A rule can only add permission to a path, not narrow a grant that a parent path already gave. If `$CWD` has full access and you want to protect `$CWD/.git/config`, Landlock alone is not enough.

Path permissions are grouped into buckets (`full_access`, `read_exec`, `read_write`, `dir_create`, `read_list`, `read_only`). [Path access buckets](/devlock/reference/path-buckets/) lists what each bucket allows.

Network rules also come from Landlock. The only TCP ports the agent can connect to are the proxy's tunnel port and its API port. Every other destination gets refused by the kernel. Abstract Unix sockets and signals are scoped out the same way, so the agent cannot reach anything outside its own process tree.

## System call supervisor

A seccomp filter routes suspect syscalls to the supervisor in the parent process. The kernel suspends the agent, the supervisor reads the arguments from the child's memory, checks them against policy, and returns a decision.

For most syscalls this is defense in depth behind Landlock. A supervisor race on a path Landlock also covers cannot succeed. Landlock is the final kernel gate.

The exception is `read_only` enforcement inside a write-capable parent. Landlock grants are additive. `full_access` on `$CWD` propagates write permission to every file inside it, so Landlock cannot protect `$CWD/.git/config` within that tree. The supervisor is the only gate there, and a TOCTOU race is possible between when the supervisor reads the path and when the kernel acts on the call. `SECCOMP_IOCTL_NOTIF_ID_VALID` narrows the window but does not close it.

## Capability reset

Before exec, every Linux capability is dropped. Setuid binaries, file capabilities, and inheritable capability sets stop working. `PR_SET_NO_NEW_PRIVS` is set so any later exec cannot gain privileges either way.

## The two proxies

The agent cannot open a raw socket. All outbound traffic goes through one of the two proxy ports.

The **CONNECT proxy** is a plain HTTP proxy the agent's tools use through `HTTPS_PROXY`. It filters requests against the merged agent and profile allowlists, and refuses any host whose DNS resolves to an internal address.

The **API proxy** handles the agent's upstream API calls. The agent points its auth env var at this port and the proxy swaps the session token for the real OAuth credentials before forwarding. The proxy refreshes the token when it expires.

The proxy process runs under its own Landlock and seccomp rules. It cannot read most of the file system, and it cannot open new listening ports.

See [proxy](/devlock/reference/proxy/) for the full details.

## Configuration layering

Two YAML files load at startup.

An **agent file** names the binary, declares credentials, lists allowed domains, and sets required paths. A `claude` agent file ships with the binary. Custom agent files are described in [user policy overrides](/devlock/guides/overrides/).

A **profile file** sets the filesystem buckets, `PATH` prepends, env vars, and allowed domains for every agent using it. `default` is the bundled default. Custom profile files are described in [user policy overrides](/devlock/guides/overrides/).

Profile and agent files can use `extends` to pull in a single parent and `includes` to pull in any number of partials. When files merge, lists add up, map keys combine, and plain values from the outer file win. See [agent schema](/devlock/reference/agent-schema/) and [profile schema](/devlock/reference/profile-schema/).

## Log output

Every run writes two log streams.

`seccomp.log` holds one JSON record per supervisor event. Each record has a `level`, an `event`, a system call name, and a path. Denials show up as `"event":"denied"` and fatal supervisor errors show up as `"level":"ERROR"`. If the agent exits with an error, the last few denials print to the terminal automatically.

`network.log` holds one JSON record per tunnel or forwarded request through the proxy. See [logs and post mortems](/devlock/guides/logs/) for how to read them.
