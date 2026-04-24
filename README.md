# devlock

[![CI](https://github.com/trevorlauder/devlock/actions/workflows/ci.yaml/badge.svg)](https://github.com/trevorlauder/devlock/actions/workflows/ci.yaml)
[![Release](https://github.com/trevorlauder/devlock/actions/workflows/release.yaml/badge.svg)](https://github.com/trevorlauder/devlock/actions/workflows/release.yaml)

A Linux sandbox for running coding agents safely during development.

Restricts file system access with Landlock, filters syscalls with seccomp, and proxies network traffic so agents only reach what you allow.

> **Pre-1.0.0:** CLI flags, policy file formats, and configuration schemas may change in breaking ways between releases.

## Documentation

https://trevorlauder.github.io/devlock

## License

[Apache 2.0](LICENSE)
