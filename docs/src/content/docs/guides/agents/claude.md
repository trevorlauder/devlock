---
title: claude agent
description: The bundled agent for running Claude Code.
---

The `claude` agent runs [Claude Code](https://claude.ai/code). See the [Claude Code guide](/devlock/guides/claude/) for login, credentials, and troubleshooting.

```yaml
executable: claude

credentials:
  format: claude_ai_oauth
  file: "~/.claude/.credentials.json"
  login_args:
    - /login

network_allowlist:
  - "*.anthropic.com"
  - anthropic.com

proxy:
  api_base_url: https://api.anthropic.com
  oauth:
    token_url: https://platform.claude.com/v1/oauth/token
    client_id: 9d1c250a-e61b-44d9-88ed-5944d1962f5e
  inject_headers:
    anthropic-beta: oauth-2025-04-20

env:
  CLAUDE_CODE_TMPDIR: "$TMP_DIR"
  ANTHROPIC_BASE_URL: "http://127.0.0.1:$API_PORT"
  ANTHROPIC_AUTH_TOKEN: "$SESSION_TOKEN"

paths:
  read_write:
    - "~/.claude/backups"
    - "~/.claude/cache"
    - "~/.claude/file-history"
    - "~/.claude/paste-cache"
    - "~/.claude/projects"
    - "~/.claude/session-env"
    - "~/.claude/sessions"
    - "~/.claude/plans"
    - "~/.claude/shell-snapshots"
    - "~/.claude/tasks"
    - "~/.claude/telemetry"
    - "~/.claude/.deep-link-register-failed"
    - "~/.claude/history.jsonl"
    - "~/.claude/mcp-needs-auth-cache.json"
    - "~/.claude.json"
    - "~/.claude.json.lock"
  read_only:
    - "~/.claude/plugins"
    - "~/.claude/hooks"
    - "~/.claude/ide"
    - "~/.claude/settings.json"
    - /etc/claude-code
  dir_create:
    - "~/.claude"
```
