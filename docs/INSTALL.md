# Installation Guide

This guide separates setup into:
1. Basic: MCP server only (default policy, no GUI required)
2. Advanced: MCP server + Web GUI

## Requirements
1. Python `>=3.10` (recommended `3.12+`, especially on macOS).
2. Git.
3. Node.js 18+ only if you plan to build or run the Web GUI frontend.

## Runtime model (important)
1. Install folder: where repo/package code lives.
2. Workspace (`AIRG_WORKSPACE`): where agent actions are intended to run.
3. Runtime state files: `policy.json`, `approvals.db`, HMAC key, backups.

Do not use the install folder as the workspace.

Default runtime state locations:
1. macOS: `~/Library/Application Support/ai-runtime-guard/`
2. Linux:
   - config: `${XDG_CONFIG_HOME:-~/.config}/ai-runtime-guard/`
   - state: `${XDG_STATE_HOME:-~/.local/state}/ai-runtime-guard/`

## Basic setup (MCP server only)
1. Clone and install:
```bash
git clone --branch main https://github.com/jimmyracheta/ai-runtime-guard.git
cd ai-runtime-guard
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install .
```
2. Initialize runtime files:
```bash
airg-setup --quickstart --yes
```
3. Create a dedicated workspace:
```bash
mkdir -p ~/airg-workspace
```
4. Use explicit env vars in your AI agent MCP config:
```json
{
  "mcpServers": {
    "ai-runtime-guard": {
      "command": "airg-server",
      "args": [],
      "env": {
        "AIRG_WORKSPACE": "/absolute/path/to/airg-workspace",
        "AIRG_POLICY_PATH": "/absolute/path/to/policy.json",
        "AIRG_APPROVAL_DB_PATH": "/absolute/path/to/approvals.db",
        "AIRG_APPROVAL_HMAC_KEY_PATH": "/absolute/path/to/approvals.db.hmac.key"
      }
    }
  }
}
```
5. Run diagnostics once:
```bash
airg-doctor
```

Notes:
1. You do not manually start MCP server in normal use. The AI client starts `airg-server` when MCP is configured.
2. Web GUI is not required for default/basic setup.
3. `airg-setup` is the recommended setup entrypoint; `airg-init` remains available as a low-level initializer.

## Advanced setup (MCP + Web GUI)
Use this when you want:
1. Easier policy edits (instead of editing `policy.json` manually).
2. Human approval workflow when `requires_confirmation` is enabled.

### Serve mode (recommended)
1. Build UI:
```bash
cd ui_v3
npm install
npm run build
cd ..
```
2. Start backend:
```bash
airg-ui
```
3. Open `http://127.0.0.1:5001`

### Dev mode (hot reload frontend)
1. Terminal A:
```bash
airg-ui
```
2. Terminal B:
```bash
cd ui_v3
npm install
npm run dev
```
3. Open `http://127.0.0.1:5173`

### Linux-specific GUI note
On Linux source installs, `airg-ui`/`airg-doctor` now probe common source/package UI locations automatically.

If detection still fails in your environment, set:
```bash
export AIRG_UI_DIST_PATH=/absolute/path/to/ai-runtime-guard/ui_v3/dist
airg-ui
```

Use the same env var when running `airg-doctor` if you need deterministic path resolution.

## Guided setup (optional)
Wizard:
```bash
airg-setup
```
Alias:
```bash
airg init --wizard
```
Quick non-interactive defaults:
```bash
airg-setup --quickstart --yes
```

Branch note:
1. Public installation should use `main` branch or tagged releases.
2. `dev` is for ongoing integration work and may be unstable.

## Policy change lifecycle
1. Policy edits can be done by file edit or GUI Apply.
2. Runtime enforcement updates only after full client/server restart.
3. Restart rule:
   - Quit AI app completely.
   - Wait for full process exit.
   - Start AI app again.

## Clarifications and current limitations
1. Web GUI is optional unless you need GUI-based approvals or easier policy editing.
2. Per-command budget shown in GUI is metadata only today.
3. Enforced budget is currently cumulative per session scope (policy-driven), not per-command.
4. Approval is out-of-band via GUI/API; agent cannot self-approve through MCP tool surface.
5. Blast-radius simulation, when configured, evaluates candidate targets relative to the current workspace context. Directory-depth/path checks are anchored from `AIRG_WORKSPACE`.
6. For Claude Code users, add client-side workspace guard instructions (see `AGENT_MCP_CONFIGS.md`); this is a client-behavior mitigation, not an AIRG enforcement boundary.
7. AIRG only enforces operations that flow through MCP tools. If the client has native shell/file tools outside MCP, those operations can bypass AIRG policy.

## Post-install smoke test
1. Confirm blocked command is denied (`rm -rf ...` test target in workspace).
2. Confirm normal command is allowed (`ls -la` in workspace).
3. Confirm `activity.log` gets entries.
4. If approval is enabled, confirm token appears and GUI approve/deny works.
5. Confirm backup/restore dry-run path works for destructive file action.
