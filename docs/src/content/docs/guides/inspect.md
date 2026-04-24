---
title: Inspect mode
description: Print the resolved configuration without starting the agent.
---

Inspect mode is the fastest way to answer "what would devlock actually do here". It loads the agent and profile, expands every variable, detects the Landlock ABI, and prints the resolved configuration. Then it exits without forking anything.

## Run it

```sh
devlock --agent claude --inspect
```

No proxy starts, no sandbox applies, and nothing execs. You can run this in any directory, with or without credentials, and it is safe to run repeatedly.

## What it prints

The numbers and paths a real run would use all show up here.

The Landlock ABI appears first. Version 6 is required, so a kernel that does not support it fails here with a clear message. That makes this a good first check on a new machine.

The resolved agent metadata follows. Agent name, profile name, executable path, tunnel port, API port, temp directory, and home directory all print as computed.

The merged network allowlist is the union of the agent file's allowlist and the profile file's allowlist, deduplicated and lowercased.

The resolved path buckets come next. Every entry has had `$CWD`, `$TMP_DIR`, `~`, and the port variables substituted, so the list is the exact set of paths Landlock would apply.

## Typical uses

**Verifying a custom profile.** After adding a new partial, run inspect mode to confirm it merged and your paths resolved.

**Debugging an "access denied" report.** Read through the resolved buckets and confirm the path you expected to grant is actually in the list.

**Checking a new install.** On a fresh machine, inspect mode confirms the Landlock ABI matches and the bundled policy files parse.

**Comparing profiles.** Run it once on each profile and diff the output to see what changes.

## Exit codes

Inspect mode exits zero on success. If policy loading fails (bad YAML, missing file, unknown field, bucket conflict) it exits non zero with the error on stderr. If the Landlock ABI is unsupported it exits non zero with an explanation.
