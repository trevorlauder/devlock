---
title: User policy overrides
description: Layer your own policy on top of the bundled defaults.
---

The bundled agents, profiles, and partials ship inside the binary. Anything you drop under `~/.config/devlock/policy/` shadows the bundled version at the matching relative path. Everything you do not override stays bundled.

## Override a bundled file

Say you want to add a domain to the default profile's allowlist. Create the file in your user tree.

```sh
mkdir -p ~/.config/devlock/policy/profiles
```

```yaml
# ~/.config/devlock/policy/profiles/default.yaml
includes:
  - base.yaml
  - partials/git.yaml
  - partials/devcontainer.yaml
  - partials/vscode.yaml

network_allowlist:
  - my-internal-registry.corp
```

Your file wins because it shadows the bundled one. The partials keep resolving from the bundled copies, so you only need to include the fields you want to change.

The same works for any bundled file. A partial, a profile, or an agent file. Recreate the same relative path under your user tree with the content you want.

```sh
# Shadow the git partial to loosen one of the read_only entries
~/.config/devlock/policy/profiles/partials/git.yaml
```

## Add a new file

You can drop agent and profile files that have no bundled counterpart. They just appear in the policy tree alongside the built in ones.

```sh
# A brand new agent
~/.config/devlock/policy/agents/my-agent.yaml

# A brand new profile
~/.config/devlock/policy/profiles/team-a.yaml
```

```sh
devlock --agent my-agent --profile team-a
```

## How merging works

Loading an agent or profile walks the `extends` chain and the `includes` list recursively. The merge order is `extends` parent first, then each include in order, then the file itself on top. List values add up, map keys combine, and plain values overwrite. Cycles are caught at load time and reported as an error.

An override only needs the fields you want to change. Any `includes` the original had are yours to re declare or drop, since the outer file wins for the `includes` list too.

## Picking up a change

Edits to files under `~/.config/devlock/policy/` take effect the next time you start a session. Nothing needs to be reloaded at runtime.
