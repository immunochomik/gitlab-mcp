# gitlab-mcp — policy-controlled GitLab MCP server

A Go MCP server that exposes a **fixed, explicit set of GitLab actions** per project, while the GitLab token lives only in the server process — the agent can never read it. Actions like `merge_mr` / `approve_mr` simply do not exist in the catalog.

## Design intent

- **Token not visible to agents.** The token is read from an env var or a file at startup. The agent sees only MCP tool schemas; there is no generic "call the API" tool.
- **Per-project allow/deny via YAML.** Patterns use `*` as wildcard spanning `/`.
- **Read-only by default.** Only actions in `defaults.allow` (or project allow) exist as tools.
- **Default-deny for unknown projects.**
- **Log retedaction.** `get_job_log` is redacted by builtin patterns + optional entropy + custom regexes, so the agent can read CI logs without seeing tokens.
- **Trivy report extraction.** A dedicated tool downloads the job artifact archive and extracts only files matching `trivy.file_pattern` from the zip.

## Built-in actions (catalog)

Projects, branches, files:
- `list_projects`, `get_project`, `list_branches`, `get_file`, `list_tree`

Merge requests:
- `search_mrs`, `get_mr`, `list_mr_notes`, `get_mr_changes`, `create_mr` (never merges)

Writes (optional):
- `create_branch`, `commit_files`

Pipelines / jobs:
- `list_pipelines`, `get_pipeline`, `list_pipeline_jobs`, `get_job_log`, `get_trivy_report`

Anything not listed (merge, approve, close, delete, etc.) **is not registered** — the policy layer doesn't need to be consulted; it can't be called.

## Configuration

Copy `config.example.yaml` to `~/.config/gitlab-mcp/config.yaml` and edit.

```yaml
gitlab:
  url: https://gitlab.example.com
  token_env: GITLAB_TOKEN      # or token_file: ... (0600)
  # For username/password auth instead (takes precedence over token auth):
  # user_env: GITLAB_USER
  # password_env: GITLAB_PASSWORD
server:
  transport: http               # or stdio
  listen: 127.0.0.1:8787
```

**Http transport** (recommended): run as a daemon (launchd/systemd). The token never appears in the agent config; the agent just points at `http://127.0.0.1:8787/mcp`.

**Stdio**: useful if your harness only supports spawning the MCP process; be aware an agent with shell access may read whatever your user can read.

### HTTP smoke test

With the HTTP server running, test session initialization, tool discovery, and
an MR search with:

```bash
./scripts/mcp-smoke-test.sh
```

Pass a different endpoint and project as optional arguments:

```bash
./scripts/mcp-smoke-test.sh http://127.0.0.1:8787/mcp my-group/my-project
```

### Policy resolution

For each requested (project, action):

1. Find all `project` patterns that match the project path.
2. If any matching `deny` contains the action → **deny**.
3. Else if any matching `allow` contains the action → **allow**.
4. Else fall back to `defaults.allow` / `defaults.deny`.
5. If no pattern matches the project → **deny** (default-deny).

`list_projects` is special: it enumerates only the configured patterns and expands `group/*` federated patterns by listing group projects. Actions are then still filtered by the glob match.

## Redaction

- **Builtin regexes**: `glpat-*`, `AKIA*`, `ghp_`, JWTs, private-key blocks, `Authorization: Bearer`, and key=value assignments for `password|token|secret|...`.
- **Custom regexes**: `redaction.patterns`.
- **Entropy detection** (optional): `redaction.entropy.enabled: true`. Shannon entropy over tokens ≥ `min_length`; anything ≥ `threshold` gets redacted. Tuned to avoid replacer IDs, but you should test.

All logs pass through the redactor before returned to the agent.

## Tools details

- `get_job_log` — returns the job trace with log-level redaction applied; truncated at 256 KiB. The `log` field is the redacted content.
- `get_trivy_report` — downloads the artifacts zip for the given `job_id`, looks inside the archive for files matching `trivy.file_pattern` (default `(?i)trivy[^/]*\.(csv|json|txt|md)$`), extracts and redacts them.
- `commit_files` — sends `files_json` as a JSON array:
  ```json
  [
    {"path": "src/main.go", "content": "...", "action" "create"},
    {"path": "docs/readme.md", "action": "delete"}
  ]
  ```
  `action` defaults to `create` and may also be `update` or `delete`.
- `create_branch` — if `ref` omitted, uses the project's default branch.
- `create_mr` — requires `title` and `source_branch`; `target_branch` picks the project's default branch if absent. This only *creates* the MR; there is no way to merge (by design).

## Threat model

This server solves "the agent cannot retrieve the token through MCP tools" and "only explicitly allowed actions are exposed". It does **_not_** protect against:

- An agent with unrestricted shell/file access on the same machine where the token file is readable (then even a secret file is not safe — it's the agent's privilege level).
- A token that grants higher permissions than needed on GitLab itself (the token should have only `api` scope).

Both need OS-level containment to fully mitigate.

## Build & run

```bash
go build -o gitlab-mcp ./main.go
./gitlab-mcp --config ~/.config/gitlab-mcp/config.yaml --version
./gitlab-mcp --config ...  # starts the server
```

## Connecting agents

**Prerequisite:** the server must be running (`http` transport) or launchable (`stdio`).

### HTTP transport (recommended)

Start the server:
```bash
./gitlab-mcp --config ~/.config/gitlab-mcp/config.yaml
# logs: gitlab-mcp 0.1.0 listening on 127.0.0.1:8787 (streamable HTTP)
```

Then configure the agent harness to connect at `http://127.0.0.1:8787/mcp`.

**Claude Code** (`.claude.json` or `.mcp.json` in your project root):
```json
{
  "mcpServers": {
    "gitlab": {
      "transport": "http",
      "url": "http://127.0.0.1:8787/mcp"
    }
  }
}
```

### Stdio transport (fallback)

If your harness only supports stdio, set `server.transport: stdio` in the config.

**Claude Code** / **Cursor**:
```json
{
  "mcpServers": {
    "gitlab": {
      "command": "/path/to/gitlab-mcp",
      "args": ["--config", "/path/to/config.yaml", "--transport", "stdio"]
    }
  }
}
```

> ⚠ With stdio the agent spawns the process, so if the agent has shell access and runs as the same OS user, it could read your token file. HTTP + dedicated daemon user is the stronger posture. See Threat model for details.

### Agent MCP connection FAQ

**How does an agent find and use tools?** The agent harness (Claude Code / Cursor / etc.) connects to the MCP server. The server responds with a `tools/list` that describes every registered action (name, description, parameters). When you ask the agent to "search MRs in project X," it calls `tools/call` with name `search_mrs` and arguments `{"project": "X"}`. The server executes if policy allows, and returns the result.

**How do I verify the connection works?** With the server running, send a `tools/list` by hand:
```bash
curl -s http://127.0.0.1:8787/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```
You should see a list of all registered tools.

**Do I need to restart the agent after starting the server?** Usually yes — Claude Code and Cursor read the MCP config on startup. Restart the agent after starting `gitlab-mcp`.

### Optional: macOS launchd

```xml
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
  <dict>
    <key>Label</key><string>dev.gitlab.mcp</string>
    <key>ProgramArguments</key>
    <array>
      <string>/path/to/gitlab-mcp/gitlab-mcp</string>
      <string>--config</string>
      <string>/path/to/config.yaml</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict><key>GITLAB_TOKEN</key><string>glpat-xxx</string></dict>
    <key>KeepAlive</key><true/>
  </dict>
</plist>
```

Put token in `EnvironmentVariables` or have the config use `token_file` with `0600` permissions.

## Audit

Set `audit.file` in config to get a JSONL record of every tool call (`0600`).

## Tests

```bash
go test ./internal/... -v
```

## Tool catalog and descriptions

Register-all happens even for non-allowed projects; invocation checks policy before executing.
