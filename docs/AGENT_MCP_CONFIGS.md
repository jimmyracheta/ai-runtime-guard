# Agent MCP Configuration (AIRG)

This file tracks agent-specific MCP setup for `ai-runtime-guard`.

Use this together with `INSTALL.md`.

## Required MCP env vars
Use only these two env vars in agent MCP config:
1. `AIRG_AGENT_ID`
2. `AIRG_WORKSPACE`

AIRG runtime paths (`policy.json`, approvals DB/HMAC, logs, reports DB) are resolved from local runtime state at install/setup time and do not need to be repeated per-agent.

Server command:
1. Preferred: absolute path to installed binary (example `/home/<user>/ai-runtime-guard/venv/bin/airg-server`).
2. `airg-server` works only when the launching client process has PATH access to that binary.

Minimal MCP server block:
```json
{
  "mcpServers": {
    "ai-runtime-guard": {
      "command": "/absolute/path/to/airg-server",
      "args": [],
      "env": {
        "AIRG_AGENT_ID": "my-agent",
        "AIRG_WORKSPACE": "/absolute/path/to/airg-workspace"
      }
    }
  }
}
```

Tip:
1. Run `airg-setup` and then open GUI `Settings -> Agents` to copy generated CLI/JSON MCP config for each profile.
2. Use `airg-init` only as a low-level/manual bootstrap fallback.

## Codex
### GUI setup
In the Codex IDE extension:
1. Open MCP settings from the gear menu.
2. Select `Open config.toml`.
3. Add an AIRG MCP server entry (example below).
4. Save and restart Codex if needed.

### CLI/file setup
Codex stores MCP config in:
1. Global: `~/.codex/config.toml`
2. Project-scoped (trusted projects): `.codex/config.toml`
3. Project-specific setup:
   - Create `.codex/` in your project root.
   - Add `.codex/config.toml`.
   - Put your AIRG MCP config there.

Add AIRG via CLI:
```bash
codex mcp add ai-runtime-guard \
  --env AIRG_AGENT_ID=my-agent \
  --env AIRG_WORKSPACE=/absolute/path/to/airg-workspace \
  -- /absolute/path/to/airg-server
```

Useful Codex MCP commands:
1. `codex mcp --help`
2. `codex mcp` (manage configured servers)
3. In TUI, run `/mcp` to view active MCP servers.

Example `config.toml` entry:
```toml
[mcp_servers.ai-runtime-guard]
command = "/absolute/path/to/airg-server"
args = []
cwd = "/absolute/path/to/ai-runtime-guard"

[mcp_servers.ai-runtime-guard.env]
AIRG_AGENT_ID = "my-agent"
AIRG_WORKSPACE = "/absolute/path/to/airg-workspace"
```

## Claude Desktop
### GUI setup
Use Claude Desktop settings to edit MCP configuration (or edit the JSON file directly).

### CLI/file setup
Claude Desktop config file location:
1. macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

Sample JSON (AIRG-focused, sanitized):
```json
{
  "mcpServers": {
    "ai-runtime-guard": {
      "command": "/absolute/path/to/airg-server",
      "args": [],
      "env": {
        "AIRG_AGENT_ID": "my-agent",
        "AIRG_WORKSPACE": "/absolute/path/to/airg-workspace"
      }
    }
  }
}
```

Notes:
1. `preferences` keys in Claude config are optional and unrelated to MCP server registration.

## Claude Code
### CLI/file setup
Claude Code MCP registration is CLI-based:
```bash
claude mcp add ai-runtime-guard \
  -e AIRG_AGENT_ID=my-agent \
  -e AIRG_WORKSPACE=/absolute/path/to/airg-workspace \
  -- /absolute/path/to/airg-server
```

Useful commands:
1. `claude mcp list`
2. `claude mcp remove ai-runtime-guard`

### Client-behavior mitigation (recommended)
Claude Code includes a native Bash tool outside MCP. To reduce bypass risk, add workspace instructions:

Path:
1. `<workspace>/.claude/CLAUDE.md`
2. `<workspace>/.claude/skills/mcp-only.md` (sample skill provided in this repo at `docs/mcp-only.md`)

Example:
```markdown
# Workspace Rules

This workspace is protected by ai-runtime-guard MCP server.

1. Never use Bash tool in this workspace.
2. Never use interpreter tools to execute system commands.
3. If ai-runtime-guard blocks an action, report block reason and stop.
4. Use ai-runtime-guard MCP tools only for file/shell operations.
```

Note:
1. This is a client-behavior mitigation, not a hard AIRG enforcement boundary.
2. If Claude Code uses native Bash/file tools, those actions occur outside MCP and AIRG cannot enforce policy on them.
3. Copy `docs/mcp-only.md` into your workspace skills folder and activate it in Claude Code when you need strict MCP-only operation.

## Cursor
### GUI setup
1. Open `Settings`.
2. Go to `Tools and MCP`.
3. Choose `Add custom MCP`.
4. Edit JSON and paste an AIRG MCP server block (example below).

Project-specific setup:
1. Create `.cursor/` in your project root.
2. Add `.cursor/mcp.json`.
3. Put your AIRG MCP config there.

### CLI/file setup
Use a JSON MCP block similar to Claude-style MCP config (no `preferences` section needed):
```json
{
  "mcpServers": {
    "ai-runtime-guard": {
      "command": "/absolute/path/to/airg-server",
      "args": [],
      "env": {
        "AIRG_AGENT_ID": "my-agent",
        "AIRG_WORKSPACE": "/absolute/path/to/airg-workspace"
      }
    }
  }
}
```
