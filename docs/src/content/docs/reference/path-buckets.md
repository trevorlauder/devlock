---
title: Path access buckets
description: What each bucket allows, what it refuses, and why.
---

File system access is grouped into six buckets. Both agent files and profile files use the same vocabulary. Pick the narrowest bucket that still lets the agent do its job.

## full_access

Read, write, create, delete, run programs. All V6 Landlock access flags apply: `Execute`, `ReadFile`, `ReadDir`, `WriteFile`, `Truncate`, `MakeReg`, `RemoveFile`, `MakeDir`, `RemoveDir`, `MakeSock`, `MakeFifo`, `MakeChar`, `MakeBlock`, `MakeSym`, `Refer`, and `IoctlDev`.

Use it for the workspace (`$CWD`), the session scratch directory (`$TMP_DIR`), and character devices the agent needs (`/dev/null`, `/dev/urandom`, `/dev/tty`, `/dev/pts`).

## read_exec

Read files and run programs. Covers `Execute`, `ReadFile`, and `ReadDir`.

Use it for toolchains and system libraries. `/usr` is the canonical case.

## read_list

List directories and read files inside them. Covers `ReadFile` and `ReadDir`. Narrower than `read_exec` because it does not grant execute.

Use it for config scan trees where the agent walks a directory but does not run anything out of it.

## read_only

Read the listed files only. Landlock grants `ReadFile`.

The supervisor also refuses writes, unlinks, rename-replace, new hardlinks, new symlinks, and `O_CREAT` opens at the path. This is the only bucket that can protect a specific file inside a broader write grant.

The supervisor check is best effort due to TOCTOU: the supervisor reads the path from the child and the kernel reads it again to act. Use `read_only` for paths where a slipped write has security impact.

## read_write

Read, write, create, delete. Covers `ReadFile`, `ReadDir`, `WriteFile`, `Truncate`, `MakeReg`, `RemoveFile`, `MakeDir`, `RemoveDir`, `MakeSock`, and `MakeFifo`. Does not grant `Execute` or device/symlink/refer flags.

Use it for cache, state, and session data directories.

## dir_create

Add new entries to a directory. Covers `ReadDir`, `MakeReg`, `MakeDir`, `RemoveFile`, `RemoveDir`. Does not cover `ReadFile`, `WriteFile`, or `Truncate`.

Creates new files and directories inside the path but does not allow writing content into them. A create open succeeds. The write on the returned fd also succeeds because the agent holds the fd. Reading or overwriting an existing file is not permitted.

`RemoveFile` and `RemoveDir` are included in the Landlock ruleset so that rename-within the directory works (Landlock requires those flags on the source parent). The supervisor blocks `unlink` and `rmdir` directly, so entries cannot be deleted.

Use it for directory structure setup. For content writes or deletes, use `read_write` or `full_access`.

## Quick reference

| Bucket        | Read files | List dirs | Write files | Execute | Create entries | Delete entries |
| ------------- | :--------: | :-------: | :---------: | :-----: | :------------: | :------------: |
| `full_access` |     ✓      |     ✓     |      ✓      |    ✓    |       ✓        |       ✓        |
| `read_exec`   |     ✓      |     ✓     |      ✗      |    ✓    |       ✗        |       ✗        |
| `read_write`  |     ✓      |     ✓     |      ✓      |    ✗    |       ✓        |       ✓        |
| `read_list`   |     ✓      |     ✓     |      ✗      |    ✗    |       ✗        |       ✗        |
| `dir_create`  |     ✗      |     ✓     |      ✗      |    ✗    |       ✓        |       ✗        |
| `read_only`   |     ✓      |     ✗     |      ✗      |    ✗    |       ✗        |       ✗        |
