# ai-runtime-guard

> Your agent can say anything. It can only do what policy allows.

AI agents with filesystem and shell access can delete files, leak credentials, or execute destructive commands, often without the user realizing it until it is too late.

`ai-runtime-guard` is an MCP server that sits between your AI agent and your system, enforcing a policy layer before any file or shell action takes effect. No retraining, no prompt engineering, no changes to your agent or workflow, just install, configure once, and your agent operates within the boundaries you set.

## Current state
1. Stable release lives on `main` (latest tagged release).
2. Ongoing integration work happens on `dev` (current integration-train branch).
3. Stable release notes are in `CHANGELOG.md`.
4. In-progress dev notes are in `docs/CHANGELOG_DEV.md`.

## What it does
1. **Blocks dangerous operations**: `rm -rf`, sensitive file access, privilege escalation, and more are denied before execution.
2. **Gates risky commands behind human approval**: configurable commands require explicit operator sign-off via a web GUI before the agent can proceed.
3. **Simulates blast radius**: wildcard operations like `rm *.tmp` are evaluated against real files before running, and blocked if they exceed a safe threshold.
4. **Backs up before it acts**: destructive or overwrite operations create automatic backups with full restore support.

All actions, allowed and blocked, are logged to a full audit trail.

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
See `docs/INSTALL.md` for full setup.

Quick start:
1. `python3 -m venv venv && source venv/bin/activate`
2. `pip install --upgrade pip && pip install .`
3. `airg-setup` (guided installer)
4. `airg-doctor`

Release branch note:
1. Public users should install from `main` (or a tagged release), not `dev`.

## What is optional
1. Web GUI (`airg-ui`) is optional unless you need GUI policy editing, approvals, or reports.
2. GUI service (`airg-service`) is optional; you can run `airg-ui` manually.
3. `airg-init` is optional and low-level; `airg-setup` is the recommended onboarding command.

## Web GUI (optional)
A local web interface is available for policy editing, approval management, and audit review.
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

See [INSTALL.md](docs/INSTALL.md) for advanced setup, service management, dev mode, and frontend rebuild instructions.

## MCP client configuration (example)
For clients that support a stdio command-based MCP config, point to the packaged entrypoint.

```json
{
  "mcpServers": {
    "ai-runtime-guard": {
      "command": "airg-server",
      "args": [],
      "env": {
        "AIRG_AGENT_ID": "claude-desktop",
        "AIRG_WORKSPACE": "/absolute/path/to/agent-workspace",
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

Best practice:
1. Run `airg-setup` and copy the printed env block into your MCP client config.
2. Keep explicit `AIRG_*` paths in client config so launches are deterministic across restarts.

## AIRG_WORKSPACE (important)
`AIRG_WORKSPACE` is the root directory that agent tool operations are allowed to act inside by default.

How it works:
1. `execute_command` starts from `AIRG_WORKSPACE` as its working directory.
2. File tools (`read_file`, `write_file`, `delete_file`, `list_directory`) enforce workspace/path policy relative to this root.
3. Traversal attempts outside this root are blocked by policy checks.

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

## How to test
1. Public smoke test guidance: `docs/TEST_PLAN.md`.
2. Install and operational validation: `docs/INSTALL.md`.
3. Automated tests:
   - `python3 -m unittest discover -s tests -p 'test_*.py'`

## Branch and release policy (current)
1. `main` is the release branch.
2. `dev` is the active integration branch for ongoing work.
3. Use short-lived feature branches from `dev`, then merge back into `dev`.
4. Promote releases by merging `dev` into `main` after gates are satisfied, then tag (`vX.Y.Z`).
5. `main` should stay protected in GitHub settings: no direct pushes, at least one review, and required checks before merge.
