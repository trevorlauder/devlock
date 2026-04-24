---
title: base profile
description: The minimum filesystem grants every agent needs.
---

The `base` profile is the foundation all other profiles build on. It has no git, devcontainer, or VS Code protections. Extend it directly when you want full control over which partials are included.

```yaml
paths:
  full_access:
    - "$CWD"
    - /dev/null
    - /dev/urandom
    - /dev/tty
    - /dev/pts
    - "$TMP_DIR"
  read_exec:
    - /usr
  read_list:
    - /proc
  read_only:
    - /etc/gitconfig
    - /etc/passwd
    - /etc/group
    - /etc/nsswitch.conf
    - /etc/hosts
    - /etc/resolv.conf
    - /etc/profile
    - /etc/bash.bashrc
    - /etc/terminfo
    - /etc/ssl
    - /etc/ld.so.cache
    - /etc/ld.so.conf
    - /etc/ld.so.conf.d
    - /etc/zsh
    - /etc/shells
    - /etc/os-release
    - /etc/services
    - /etc/host.conf
    - /etc/machine-id
    - /etc/gitattributes
    - /var/lib/dbus/machine-id
    - /sys/devices/system/cpu
    - /sys/fs/cgroup
```
