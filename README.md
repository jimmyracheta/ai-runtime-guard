# ai-runtime-guard

> Your agent can say anything. It can only do what policy allows.

AI agents with filesystem and shell access can delete files, leak credentials, or execute destructive commands, often without the user realizing it until it is too late.

`ai-runtime-guard` is an MCP server that sits between your AI agent and your system, enforcing a policy layer before any file or shell action takes effect. No retraining, no prompt engineering, no changes to your agent or workflow, just install, configure once, and your agent operates within the boundaries you set.

[![ai-runtime-guard MCP server](https://glama.ai/mcp/servers/jimmyracheta/ai-runtime-guard/badges/card.svg)](https://glama.ai/mcp/servers/jimmyracheta/ai-runtime-guard)

## What it does
1. **Blocks dangerous operations**: `rm -rf`, sensitive file access, privilege escalation, and more are denied before execution.
2. **Gates risky commands behind human approval (optional)**: configurable commands require explicit operator sign-off via a web GUI before the agent can proceed.
3. **Simulates blast radius**: wildcard operations like `rm *.tmp` are evaluated against real files before running, and blocked if they exceed a safe threshold.
4. **Controls network behavior**: configure command-level network policy with monitor-only mode, domain allowlist/denylist, and optional unknown-domain blocking.
5. **Supports multi-agent policy isolation**: apply per-agent policy overrides keyed by `AIRG_AGENT_ID` while keeping shared runtime controls.
6. **Backs up before it acts**: destructive or overwrite operations create automatic backups with full restore support.
7. **Provides robust logging and reporting**: all allowed/blocked actions are logged to `activity.log` and indexed into `reports.db` for dashboard/log views.

## Current state
1. Policy management is available in the local GUI (commands, paths, extensions, network, advanced policy).
2. Agent management is available in the GUI (`Settings -> Agents`), including profile-based MCP config generation.
3. Per-agent policy overrides are supported and enforced by `AIRG_AGENT_ID`.
4. Full runtime visibility is available through `activity.log` and reports/dashboard views (`reports.db`).
5. Stable release notes are tracked in `CHANGELOG.md`, with in-progress work in `docs/CHANGELOG_DEV.md`.

## Who it is for
Developers and power users running AI agents (Claude Desktop, Cursor, Codex, or any MCP-compatible client) who want guardrails on what the agent can actually do to their system.

## Known boundary
1. AIRG enforces policy only for actions that pass through AIRG MCP tools.
2. Native client tools outside MCP (for example Claude Code `Glob`, `Read`, `Write`, `Edit`, `Bash`) are outside AIRG enforcement and can bypass workspace/path restrictions.
3. For AIRG policy boundaries to be effective, operators must disable native shell/file tools in the client using official configuration methods.
4. Treat this as a deployment requirement, not optional hardening.
5. For Claude Code, an MCP-only sample skill is provided at `docs/mcp-only.md` and can be saved to `<workspace>/.claude/skills/mcp-only.md`.

## Design scope
1. AIRG is designed to reduce accidental damage from AI agent mistakes or hallucinations.
2. AIRG is not positioned as a full malicious-actor containment system.
3. Core controls:
   - block high-risk destructive/exfiltration commands and paths
   - enforce workspace boundaries
   - gate mass/wildcard actions with simulation and budget limits
   - optionally require human approval for selected risky actions
   - automatically back up destructive/overwrite targets before applying changes
   - log allowed/blocked actions and operator decisions to an audit trail

## How it works
- Python MCP server with policy-driven enforcement loaded from `policy.json`
- Default profile is **basic protection**: severe actions blocked, everything else allowed
- Advanced controls available for opt-in: simulation gating, human approval workflows, cumulative budget limits, and shell workspace containment modes (`off`/`monitor`/`enforce`)
- Local web GUI for policy editing, approval management, and audit log review

## Requirements
Python:
1. Required: Python `>=3.10` (project package metadata enforces this).
2. Recommended on macOS: Python `3.12+` (Homebrew or python.org install).
3. macOS system Python `3.9` is often too old and may fail dependency install.

## How to run
Quick start (package install):
1. `python3 -m venv .venv-airg && source .venv-airg/bin/activate`
2. `python -m pip install --upgrade pip`
3. `python -m pip install ai-runtime-guard`
4. `airg-setup` (guided) or `airg-setup --defaults --yes` (unattended defaults)
5. `airg-doctor`

For source-clone setup, TestPyPI flow, and advanced options, see [`docs/INSTALL.md`](docs/INSTALL.md).

## What is optional
1. Web GUI is optional, but strongly recommended for policy operations, approvals, agent profile management, and reporting.
2. GUI background service (`airg-service`) is optional; `airg-ui` can run manually.
3. `airg-init` is optional and low-level; `airg-setup` is the recommended onboarding path.

## Web GUI (optional)
A local web interface is available for:
1. Policy editing and per-agent overrides.
2. Approval management.
3. Agent profile/config management (`Settings -> Agents`).
4. Reports dashboard and event log.

Prebuilt UI assets are shipped for normal installs, so no frontend build is required unless you are modifying UI source.

Start it with:
```bash
airg-ui
```
Open `http://127.0.0.1:5001`

For persistent background run:
```bash
airg-service install --workspace /absolute/path/to/airg-workspace
airg-service start
```

See [INSTALL.md](docs/INSTALL.md) for advanced setup, service management, and frontend rebuild instructions.

## MCP client configuration (example)
Use generated profile config from GUI `Settings -> Agents` whenever possible.
That view generates client-ready JSON/CLI snippets with your runtime paths, workspace, and agent ID.

If you configure manually, use an absolute server command path (not a bare `airg-server` unless PATH is guaranteed):

```json
{
  "mcpServers": {
    "ai-runtime-guard": {
      "command": "/absolute/path/to/airg-server",
      "args": [],
      "env": {
        "AIRG_AGENT_ID": "claude-desktop",
        "AIRG_WORKSPACE": "/absolute/path/to/agent-workspace",
        "AIRG_POLICY_PATH": "/absolute/path/to/policy.json",
        "AIRG_APPROVAL_DB_PATH": "/absolute/path/to/approvals.db",
        "AIRG_APPROVAL_HMAC_KEY_PATH": "/absolute/path/to/approvals.db.hmac.key",
        "AIRG_LOG_PATH": "/absolute/path/to/activity.log",
        "AIRG_REPORTS_DB_PATH": "/absolute/path/to/reports.db",
        "AIRG_SERVER_COMMAND": "/absolute/path/to/airg-server"
      }
    }
  }
}
```

Best practice:
1. Run `airg-setup`, then open GUI `Settings -> Agents` and copy generated config for your profile.
2. Keep explicit `AIRG_*` paths in client config so launches are deterministic across restarts.

## AIRG_WORKSPACE (important)
`AIRG_WORKSPACE` is the default project root for agent operations.
In unattended defaults mode, AIRG creates/uses `~/airg-workspace` unless you set another path.

How it works:
1. `execute_command` starts from `AIRG_WORKSPACE` as its working directory.
2. File tools (`read_file`, `write_file`, `delete_file`, `list_directory`) enforce workspace/path policy relative to this root.
3. Traversal attempts outside this root are blocked by policy checks.

Workspace model:
1. You can use an existing folder as workspace.
2. Multiple workspaces are supported.
3. You can run multiple agents against the same workspace or separate workspaces per agent profile.
4. Each agent profile should set workspace explicitly in generated MCP config.

## Deployment model FAQ
1. Do I need to run `source scripts/setup_runtime_env.sh`?
   - If you use packaged flow with `airg-setup`, no. Setup initializes secure default paths and files.
   - If you run directly from source (`PYTHONPATH=src python -m server`, `PYTHONPATH=src python -m ui.backend_flask`), yes, it is recommended.
2. What folders are involved?
   - Install folder (`airg-install`): where the code/package lives.
   - Runtime state folder: where `policy.json`, `approvals.db`, HMAC key, logs, reports DB, and backups live.
   - Workspace folder (`AIRG_WORKSPACE`, often `airg-workspace`): where agent actions are intended to run.
3. Does the agent only work inside one workspace?
   - By default, yes, it is anchored to `AIRG_WORKSPACE`.
   - Additional allowed roots can be configured with `policy.allowed.paths_whitelist`.