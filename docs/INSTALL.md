# Installation Guide

This guide separates setup into:
1. Basic: MCP server only (default policy, no GUI required)
2. Advanced: MCP server + Web GUI

## Requirements
1. Python `>=3.10` (recommended `3.12+`, especially on macOS).
2. Git.
3. Node.js 18+ only if you plan to rebuild the Web GUI frontend in dev mode.

## Runtime model (important)
1. Install folder: where repo/package code lives.
2. Workspace (`AIRG_WORKSPACE`): where agent actions are intended to run.
3. Runtime state files: `policy.json`, `approvals.db`, HMAC key, backups.
4. Reports database: `reports.db` (derived from `activity.log`).
5. Runtime log file: `activity.log`.

Do not use the install folder as the workspace.

Default runtime state locations:
1. macOS: `~/Library/Application Support/ai-runtime-guard/`
2. Linux:
   - config: `${XDG_CONFIG_HOME:-~/.config}/ai-runtime-guard/`
   - state: `${XDG_STATE_HOME:-~/.local/state}/ai-runtime-guard/`

## Package install (PyPI/TestPyPI)
Install from package index instead of repo clone:
```bash
python3 -m venv .venv-airg
source .venv-airg/bin/activate
python -m pip install --upgrade pip
python -m pip install ai-runtime-guard
```

TestPyPI validation install:
```bash
python3 -m venv .venv-airg-test
source .venv-airg-test/bin/activate
python -m pip install --upgrade pip
python -m pip install --index-url https://test.pypi.org/simple --extra-index-url https://pypi.org/simple ai-runtime-guard==<test-version>
```
Note:
1. TestPyPI installs typically require `--extra-index-url https://pypi.org/simple` for dependencies.

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
airg-setup
```
Optional one-command fully unattended setup with GUI service:
```bash
airg-setup --silent
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
      "command": "/absolute/path/to/airg-server",
      "args": [],
      "env": {
        "AIRG_AGENT_ID": "claude-desktop",
        "AIRG_WORKSPACE": "/absolute/path/to/airg-workspace",
        "AIRG_POLICY_PATH": "/absolute/path/to/policy.json",
        "AIRG_APPROVAL_DB_PATH": "/absolute/path/to/approvals.db",
        "AIRG_APPROVAL_HMAC_KEY_PATH": "/absolute/path/to/approvals.db.hmac.key",
        "AIRG_LOG_PATH": "/absolute/path/to/activity.log",
        "AIRG_REPORTS_DB_PATH": "/absolute/path/to/reports.db"
      }
    }
  }
}
```
   - Recommended on Linux/macOS source installs: `<install_dir>/venv/bin/airg-server`.
   - In package installs, use the absolute venv path shown by `which airg-server`.
5. Run diagnostics once:
```bash
airg-doctor
```
   - Check reported `backup_root`; expected default is user runtime state (`~/.local/state/ai-runtime-guard/backups` on Linux, `~/Library/Application Support/ai-runtime-guard/backups` on macOS), not `site-packages`.

Notes:
1. You do not manually start MCP server in normal use. The AI client starts `airg-server` when MCP is configured.
2. Web GUI is not required for default/basic setup.
3. `airg-setup` is the recommended setup entrypoint; `airg-init` is a low-level/manual fallback.
4. `--defaults` uses default paths/non-interactive choices.
5. `--gui` enables GUI service setup (`launchd` on macOS, `systemd --user` on Linux).
6. `--no-gui` explicitly skips GUI service setup.
7. Deployment prerequisite: disable native shell/file tools in your AI client so actions are forced through AIRG MCP tools.
8. If `--agent-id` is omitted, AIRG auto-generates an ID like `unknown-482901`.

## Advanced setup (MCP + Web GUI)
Use this when you want:
1. Easier policy edits (instead of editing `policy.json` manually).
2. Human approval workflow when `requires_confirmation` is enabled.
3. Policy pages for commands, paths, extensions, network controls, and global advanced simulation/budget settings.
4. Reports dashboard/log pages sourced from `reports.db`.
5. Prebuilt GUI assets are shipped in the repository and package. For normal installs, you can start `airg-ui` directly without rebuilding frontend assets.

### Serve mode (recommended)
1. Start backend:
```bash
airg-ui
```
2. Open `http://127.0.0.1:5001`

Optional rebuild (only for frontend development changes):
```bash
cd ui_v3
npm install
npm run build
cd ..
```

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

For deterministic startup and path visibility, you can run:
```bash
airg-ui --with-runtime-env
```
This prints resolved runtime paths before launching the UI backend.

## Guided setup (optional)
Wizard:
```bash
airg-setup
```
Fully unattended bootstrap (defaults + yes + gui):
```bash
airg-setup --silent
```
Defaults-only (non-interactive path choices):
```bash
airg-setup --defaults --yes
```
Defaults with GUI service enabled:
```bash
airg-setup --defaults --yes --gui
```
Defaults with GUI service disabled:
```bash
airg-setup --defaults --yes --no-gui
```

Service management:
```bash
airg-service install --workspace /absolute/path/to/airg-workspace --agent-id claude-code-1
airg-service start
airg-service status
airg-service stop
airg-service uninstall
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
   - A sample MCP-only skill file is provided at `docs/mcp-only.md`.
   - Save it as `<workspace>/.claude/skills/mcp-only.md` to enforce MCP-only behavior in that workspace.
7. AIRG only enforces operations that flow through MCP tools. If the client has native shell/file tools outside MCP, those operations can bypass AIRG policy.
8. Product scope is accidental-safety first: block severe destructive actions, keep actions inside known workspace boundaries, gate mass/wildcard operations, back up destructive/overwrite targets automatically, and keep full audit logs.
9. Budget reset behavior is event-driven: counters are checked/reset when budgeted operations run (no background reset timer). With idle reset enabled, slow-drip patterns beyond `idle_reset_seconds` can avoid cumulative growth; budget controls are optimized for accidental burst-risk reduction during normal sessions.

### Known issue: native client tools bypass MCP policy
1. AIRG enforces only MCP tool calls routed to AIRG.
2. Native client tools (for example Claude Code `Glob`, `Read`, `Write`, `Edit`, `Bash`) run outside AIRG policy.
3. If these tools remain enabled, workspace boundary and path restrictions are not guaranteed.
4. This is a deployment prerequisite: disable native shell/file tools using official client controls.
5. For Claude Code, disable native tools in `.claude/settings.local.json` (or your official Claude config scope in use).
6. Apply the equivalent official controls for other agents/clients.
7. Optional: use the sample skill `docs/mcp-only.md` copied to `<workspace>/.claude/skills/mcp-only.md`.

## Post-install smoke test
1. Confirm blocked command is denied (`rm -rf ...` test target in workspace).
2. Confirm normal command is allowed (`ls -la` in workspace).
3. Confirm `activity.log` gets entries.
4. If approval is enabled, confirm token appears and GUI approve/deny works.
5. Confirm backup/restore dry-run path works for destructive file action.

## Troubleshooting
1. `claude mcp list` shows AIRG as disconnected:
   - Use absolute command path for server in client config.
   - Verify with `airg-doctor`.
2. UI loads legacy/minimal page:
   - Ensure prebuilt UI assets are present (normal package/repo flow includes them).
   - Rebuild only if you changed frontend source: `cd ui_v3 && npm install && npm run build`.
   - Ensure `AIRG_UI_DIST_PATH` points to `ui_v3/dist` only when custom path override is needed.
3. Approvals loop with new token on every retry:
   - Check HMAC key file is non-empty (`wc -c <approval_hmac_key_path>`).
   - Restart UI and MCP client after fixing paths/secrets.
4. Agent override in repo `policy.json` is ignored:
   - AIRG reads runtime policy from `AIRG_POLICY_PATH` (default `~/.config/ai-runtime-guard/policy.json` on Linux).
   - Edit runtime policy file or copy updated repo policy into that runtime location.
5. Exports do not seem to apply:
   - Env exports only affect the current shell process tree.
   - Start `airg-ui` and your client from shells with the intended env values.
6. Backups appear under install dir or `site-packages`:
   - Set `audit.backup_root` in runtime `policy.json` to user-local runtime state path.
   - Re-run `airg-doctor` and confirm resolved `backup_root`.
