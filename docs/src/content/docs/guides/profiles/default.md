---
title: default profile
description: The standard profile for running an agent in a project workspace.
---

The `default` profile is the standard starting point, used when you run `devlock` without `--profile`. It extends [base](/devlock/guides/profiles/base/) and adds the git, devcontainer, and VS Code partials.

```yaml
includes:
  - base.yaml
  - partials/git.yaml
  - partials/devcontainer.yaml
  - partials/vscode.yaml
```

To add paths, partials, or environment variables on top of `default`:

```yaml
extends: default.yaml

includes:
  - partials/github.yaml
  - partials/mise.yaml

paths:
  read_write:
    - "~/.cache/my-tool"
```
