---
title: Profile YAML schema
description: Every field devlock accepts in a profile file.
---

Unknown fields are rejected.

## Top level fields

### extends

Optional string. Names a single parent profile.

```yaml
extends: base.yaml
```

### includes

Optional list. Each entry names another profile or partial to merge in before the outer file. Later includes override earlier ones.

```yaml
includes:
  - base.yaml
  - partials/git.yaml
  - partials/vscode.yaml
```

### paths

Optional. The path buckets that apply to every agent this profile is used with. See [path access buckets](/devlock/reference/path-buckets/) for what each bucket grants.

```yaml
paths:
  full_access:
    - "$CWD"
    - "$TMP_DIR"
  read_exec:
    - /usr
  read_list:
    - /proc
  read_only:
    - /etc/resolv.conf
    - "$CWD/.git/config"
  read_write: []
  dir_create: []
```

### path_prepend

Optional list of directories to prepend to the child's `PATH`. Order within this list is preserved. Entries that do not exist at resolve time are silently dropped.

```yaml
path_prepend:
  - "~/.local/share/mise/shims"
  - /home/linuxbrew/.linuxbrew/bin
```

### network_allowlist

Optional list of domain patterns. Merges with the agent's own `network_allowlist` at runtime. Same wildcard rules apply.

```yaml
network_allowlist:
  - github.com
  - "*.githubusercontent.com"
```

### env

Optional map of environment variables applied to every agent that uses this profile. Values go through variable substitution. Agent level `env` takes precedence over profile level `env`.

```yaml
env:
  TMPPREFIX: "$TMP_DIR/zsh"
  PYTHONDONTWRITEBYTECODE: "1"
```

## Composition rules

A merge happens in three passes.

First, the `extends` chain loads. Each parent fully resolves before the child layers on.

Second, the `includes` list processes in order. Each partial merges after the `extends` result but before the outer file.

Third, the outer file overlays on top of everything.

For each field, lists add up (so partials contribute entries without stepping on each other), map keys combine (so `env` and `inject_headers` blend cleanly), and plain values from the outer file win over the inner.

## Validation

Loading a profile fails if the same literal string appears in `read_only` and in a write capable bucket (`full_access`, `read_write`, or `dir_create`). This catches the case where a later partial silently elevates a protected path.

The check is exact string match after merge, so `$CWD/.git/config` in `read_only` and `$CWD` in `full_access` do not trip it. The supervisor enforces read only semantics on paths inside a broader parent grant, best effort.

## Bundled profiles

### base.yaml

Minimum policy every agent needs. Grants `$CWD`, `$TMP_DIR`, `/dev/null`, `/dev/urandom`, `/dev/tty`, `/dev/pts` full access. Grants `/usr` read and exec. Grants `/proc` read list. Marks a dozen `/etc` config files read only so glibc, the resolver, SSL, zsh, and git all work. Sets `TMPPREFIX` and `PYTHONDONTWRITEBYTECODE`.

### default.yaml

What you get when you omit `--profile`. Composes `base` plus `partials/git.yaml`, `partials/devcontainer.yaml`, and `partials/vscode.yaml`.

## Bundled partials

`partials/git.yaml` marks `~/.gitconfig`, `$CWD/.git/config`, and `$CWD/.git/hooks` read only.

`partials/devcontainer.yaml` marks `$CWD/.devcontainer` read only.

`partials/vscode.yaml` marks `$CWD/.vscode` read only.

`partials/github.yaml` grants read only access to `~/.config/gh/config.yml` for general `gh` settings. It intentionally does not expose `~/.config/gh/hosts.yml`. Set `GH_TOKEN` to a fine-grained token in the agent or profile `env` map to give the agent its own narrower token.

`partials/mise.yaml` grants read and exec on `~/.local/share/mise/installs` and `~/.local/share/mise/shims`. Grants read list on `~/.config/mise`. Grants read and write on `~/.cache/mise`. Prepends the shims dir to `PATH`. Sets `MISE_SHELL`.

`partials/homebrew.yaml` grants read and exec on `/home/linuxbrew/.linuxbrew`. Prepends the Homebrew bin and sbin dirs. Sets `HOMEBREW_PREFIX`, `HOMEBREW_CELLAR`, `HOMEBREW_REPOSITORY`, `HOMEBREW_NO_ENV_HINTS`.
