---
title: Writing a custom profile
description: Extend a built-in profile or describe the host policy from scratch.
---

A profile file describes what the host lets the sandbox see, not what a specific agent needs. Things like "the whole workspace is writable", "`/usr` is executable", "protect `.git/config`" live here. Anything agent specific belongs in an agent file.

## Extending the default profile

The most common case is adding something on top of the `default` profile, which already includes the base filesystem grants and the git, devcontainer, and VS Code protections.

```yaml
extends: default.yaml

paths:
  read_only:
    - "~/.config/my-team/settings.toml"

network_allowlist:
  - registry.example.com
```

Drop this in `~/.config/devlock/policy/profiles/my-profile.yaml` and run:

```sh
devlock --agent <name> --profile my-profile
```

## Starting from base.yaml

If you want full control over which partials are included, extend `base.yaml` instead and add only what you need. `base.yaml` has the minimum grants every agent needs (`/usr` for libraries, `/proc` for per-process info, a dozen `/etc` config files for glibc and the resolver).

```yaml
extends: base.yaml

includes:
  - partials/git.yaml
  - partials/vscode.yaml

paths:
  read_only:
    - "~/.config/my-team/settings.toml"
```

## Use partials for reusable chunks

`partials/git.yaml` marks `~/.gitconfig`, `$CWD/.git/config`, and `$CWD/.git/hooks` read only. Writing to any of these would give a host-side git invocation a path to arbitrary code execution through aliases, `core.sshCommand`, or commit hooks. The rest of `.git` is left writable so host-side git operations and agent staging (`git add`, `git commit`) continue to work. The protection is best-effort because the supervisor enforces it through seccomp-notify, which has a TOCTOU race between the supervisor's path check and the kernel's execution of the syscall.

`partials/devcontainer.yaml` marks `$CWD/.devcontainer` read only. Fields like `initializeCommand` and `postCreateCommand` run on the host when the container is reopened, so a writable devcontainer directory is a durable host code execution path.

`partials/vscode.yaml` marks `$CWD/.vscode` read only for the same reason.

`partials/github.yaml` marks `~/.config/gh/config.yml` read only so `gh` can read its general settings. It does not grant access to `~/.config/gh/hosts.yml`, which holds the OAuth token from your main terminal. Set `GH_TOKEN` to a token in the agent or profile `env` map instead. This lets you give the agent a narrower fine-grained token than your dev terminal uses.

`partials/mise.yaml` opens the mise install directory, shim directory read and exec, and prepends the shim dir to `PATH`. Opens `~/.config/mise` read list and `~/.cache/mise` read write. Sets `MISE_SHELL`.

`partials/homebrew.yaml` opens `/home/linuxbrew/.linuxbrew` read and exec with the Homebrew bin dirs prepended to `PATH`.

## Path buckets

The schema has six buckets.

`full_access` allows read, write, create, delete, and execute. Use it for the workspace and scratch dirs.

`read_exec` allows read and execute. Use it for toolchains and system libraries.

`read_only` allows read. The supervisor also refuses writes, unlinks, and renames that would replace the target. Use it for files whose mutation has security impact, like `.git/config`.

`read_write` allows read, write, create, and delete. No execute. Use it for cache and state directories.

`dir_create` allows listing and creating entries, but not writing to files. Landlock's semantics for this bucket are a little surprising. See [path access buckets](/devlock/reference/path-buckets/).

`read_list` allows listing a directory and reading files inside. It is narrower than `read_exec` because it does not grant execute. Use it for config scan directories.

## Prepending to PATH

Profiles can add directories to the child's `PATH`. Order matters only relative to other entries from the same profile. Directories that do not exist at resolve time are silently dropped.

```yaml
path_prepend:
  - "~/.local/bin"
  - /opt/mytool/bin
```

## Setting environment variables

The profile level `env` map applies to every agent that uses this profile. Use it for global host conventions, not for agent specific wiring.

```yaml
env:
  EDITOR: vim
  PAGER: less
```

Variable substitution is the same as in paths. `$CWD`, `$TMP_DIR`, and `~/` expand. `$HOME` does not.

## Adding to the network allowlist

A profile can extend the set of reachable domains without editing any agent file.

```yaml
network_allowlist:
  - github.com
  - "*.githubusercontent.com"
```

At runtime the list merges with the agent's allowlist.

## Bucket conflict check

A profile is rejected at load time if the same path string appears in `read_only` and in any write capable bucket (`full_access`, `read_write`, or `dir_create`). A later partial cannot silently elevate a protected path. If you see a bucket conflict error, find the offending entry and pick one bucket.

The check is string equality after merge, so a `read_only` entry at `$CWD/.git/config` and a `full_access` entry at `$CWD` do not conflict. The supervisor enforces read only semantics on the specific path even though Landlock cannot.

## Verifying

Run inspect mode to confirm the profile parses and resolves cleanly.

```sh
devlock --agent claude --profile my-profile --inspect
```
