---
title: Installation
description: Kernel, toolchain, and build requirements for devlock.
---

Linux is the only supported platform.

## Kernel requirements

Linux 6.10 or newer is required. That is the first kernel to include Landlock ABI V6, which added the abstract Unix socket and signal scoping that devlock relies on. An older kernel will refuse to start the sandbox and print a message saying so. Check your version with `uname -r`.

The required features (Landlock, seccomp, user namespaces) come standard with mainstream distribution kernels. A custom built kernel with any of them disabled will not work.

## Toolchain

Building from source needs a recent Rust toolchain. The `mise.toml` at the repo root pins the version the project is tested against. If you use [mise](https://mise.jdx.dev/) the tool versions install automatically.

At runtime either `zsh` or `bash` must be somewhere on `PATH`. Shell mode uses whichever one `$SHELL` names if it matches, otherwise zsh if installed and bash as a fallback.

## Install from a release binary

Pre-built binaries for `x86_64` and `aarch64` are attached to every [GitHub release](https://github.com/trevorlauder/devlock/releases). Download the one that matches your architecture, make it executable, and place it on your `PATH`.

```sh
# Adjust the version and arch (x86_64 or aarch64) as needed
VERSION=v0.1.0
ARCH=$(uname -m)   # x86_64 or aarch64
curl -fsSL "https://github.com/trevorlauder/devlock/releases/download/${VERSION}/devlock-linux-${ARCH}" \
  -o devlock
chmod +x devlock
sudo mv devlock /usr/local/bin/devlock
```

## Build from source

Clone the repo and build a release binary.

```sh
git clone https://github.com/trevorlauder/devlock.git
cd devlock
cargo build --release
```

The binary lands at `target/release/devlock`. Copy it onto your `PATH` or invoke it with the full path.

Running straight from the workspace with Cargo also works.

```sh
cargo run --release -- --agent claude
```

## Runtime directories

Two directories get created at startup if they do not already exist.

Scratch state lives under `$XDG_RUNTIME_DIR/devlock/`, falling back to a private directory under `/tmp` when that variable is not set. It is mode 0700 so only you can read it, and it goes away when the session ends.

Logs live under `$XDG_STATE_HOME/devlock/logs/` (typically `~/.local/state/devlock/logs/`). Each run writes a fresh `logs-<timestamp>-<pid>/` subdirectory, and entries older than 14 days are pruned at the next startup.

## Verify the install

Run [inspect mode](/devlock/guides/inspect/). It resolves your configuration and prints what the sandbox would enforce without starting an agent.

```sh
devlock --agent claude --inspect
```

If you see the resolved path buckets, network allowlist, and kernel version check, your install works.
