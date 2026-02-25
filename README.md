# ai-runtime-guard

> Your agent can say anything. It can only do what policy allows.

AI agents with filesystem and shell access can delete files, leak credentials, or execute destructive commands — often without the user realizing it until it's too late.

`ai-runtime-guard` is an MCP server that sits between your AI agent and your system, enforcing a policy layer before any file or shell action takes effect.

## What it does
1. **Blocks dangerous operations** — `rm -rf`, sensitive file access, privilege escalation, and more are denied before execution.
2. **Gates risky commands behind human approval** — configurable commands require explicit operator sign-off via a web GUI before the agent can proceed.
3. **Simulates blast radius** — wildcard operations like `rm *.tmp` are evaluated against real files before running, and blocked if they exceed a safe threshold.
4. **Backs up before it acts** — destructive or overwrite operations create automatic backups with full restore support.

All actions — allowed and blocked — are logged to a full audit trail.

## Who it's for
Developers and power users running AI agents (Claude Desktop, Cursor, Codex, or any MCP-compatible client) who want guardrails on what the agent can actually do to their system.

## How it works
- Python MCP server with policy-driven enforcement loaded from `policy.json`
- Default profile is **basic protection**: severe actions blocked, everything else allowed
- Advanced tiers available for opt-in: simulation gating, human approval workflows, cumulative budget limits
- Local web GUI for policy editing, approval management, and audit log review

## Requirements
Python:
1. Required: Python `>=3.10` (project package metadata enforces this).
2. Recommended on macOS: Python `3.12+` (Homebrew or python.org install).
3. macOS system Python `3.9` is often too old and may fail dependency install (notably `mcp` package constraints and modern tooling expectations).

Why this matters:
1. `ai-runtime-guard` depends on package versions that are not reliably installable on Python 3.9.
2. Clean install friction is significantly lower with a modern Python runtime.

## How to run
See `INSTALL.md` for full setup.

Quick start:
1. `python3 -m venv venv && source venv/bin/activate`
2. `pip install --upgrade pip && pip install .`
3. `airg-setup` (or `airg init --wizard`)
4. `airg-doctor`

Release branch note:
1. Public users should install from `main` (or a tagged release), not `dev`.

Runtime notes:
1. In normal use, your AI client starts `airg-server` automatically via MCP config.
2. Web GUI (`airg-ui`) is optional unless you need GUI policy editing or approval actions.

## Local policy UI (v3)
React + Tailwind frontend (Vite) with Flask backend (`ui/backend_flask.py`).

Serve mode (recommended):
1. Build frontend once (or after frontend code changes):
   - `cd ui_v3`
   - `npm install`
   - `npm run build`
2. Start backend (serves API + built UI):
   - packaged workflow: `airg-ui`
   - source workflow: `python3 ui/backend_flask.py`
3. Open `http://127.0.0.1:5001`

Dev mode (frontend hot reload):
1. Terminal A: start backend API (`airg-ui` or `python3 ui/backend_flask.py`)
2. Terminal B:
   - `cd ui_v3`
   - `npm install`
   - `npm run dev`
3. Open `http://127.0.0.1:5173`

Rebuild rule:
1. Backend-only Python changes: no frontend rebuild required.
2. Frontend changes (`ui_v3/src/*`): run `npm run build` for serve mode.

Current UI v3 scope:
- three-layer navigation rail (`Approvals`, `Policy`, `Reports`, `Settings`) + policy tabs (`Commands`, `Paths`, `Extensions`) + main panel
- approvals panel with polling and approve/deny actions
- command table with tier columns, clickable command details modal, status badges, retry/budget metadata editors
- advanced JSON editor (bidirectional with table state)
- paths policy editor with absolute-path validation:
  - `Allowed` -> `allowed.paths_whitelist`
  - `Blocked` -> `blocked.paths`
  - `Requires Approval` -> `requires_confirmation.paths`
- runtime path display in `Paths` page is read-only and managed by MCP config/env
- extensions policy editor for blocked extension patterns (`blocked.extensions`)
- shared policy actions across tabs: reload, validate, apply, revert last apply, reset to defaults
- global header keeps policy hash + unsaved-changes indicator; per-tier status legend was removed to reduce cross-page noise
- `Revert Last Apply` and `Reset to Defaults` are enabled only when backend snapshot files exist (`policy.json.last-applied`, `policy.json.defaults`)

Security path note:
- `scripts/setup_runtime_env.sh` configures approval files outside workspace by default:
  - macOS: `~/Library/Application Support/ai-runtime-guard/`
  - Linux: `${XDG_STATE_HOME:-~/.local/state}/ai-runtime-guard/`
- This avoids repeated approval-store hardening warnings and is the recommended default for public packaging.
- Built UI path can be overridden with `AIRG_UI_DIST_PATH`.

## MCP client configuration (example)
For clients that support a stdio command-based MCP config, point to the packaged entrypoint.

Example JSON snippet:
```json
{
  "mcpServers": {
    "ai-runtime-guard": {
      "command": "airg-server",
      "args": [],
      "env": {
        "AIRG_WORKSPACE": "/absolute/path/to/agent-workspace",
        "AIRG_POLICY_PATH": "~/Library/Application Support/ai-runtime-guard/policy.json",
        "AIRG_APPROVAL_DB_PATH": "~/Library/Application Support/ai-runtime-guard/approvals.db",
        "AIRG_APPROVAL_HMAC_KEY_PATH": "~/Library/Application Support/ai-runtime-guard/approvals.db.hmac.key"
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

Recommended setup:
1. Keep install source code in one location (example: `~/Documents/Projects/ai-runtime-guard`).
2. Use a separate sandbox workspace for agent operations (example: `~/airg-workspace`).

Incorrect pattern (common friction):
1. Setting `AIRG_WORKSPACE` to the project install folder and testing destructive commands there.
2. This can mix runtime code/config with test side effects and produce confusing results.

Correct pattern:
1. Set `AIRG_WORKSPACE` to a dedicated disposable folder.
2. Keep project folder read-only from normal agent tasks whenever possible.

## Deployment model FAQ
1. Do I need to run `source scripts/setup_runtime_env.sh`?
   - If you use packaged flow with `airg-setup`/`airg-init`, no. Setup initializes secure default paths and files.
   - If you run directly from source (`python server.py`, `python ui/backend_flask.py`), yes, it is recommended.
2. What folders are involved?
   - Install folder (`airg-install`): where the code/package lives.
   - Runtime state folder (Application Support/state dir): where `approvals.db` and HMAC key live.
   - Workspace folder (`AIRG_WORKSPACE`, often `airg-workspace`): where agent actions are intended to run.
3. Does the agent only work inside one workspace?
   - By default, yes, it is anchored to `AIRG_WORKSPACE`.
   - Additional allowed roots can be configured with `policy.allowed.paths_whitelist`.

## How to test
Testing guidance is in `INSTALL.md` under `Post-install smoke test`.

Automated tests:
1. `python3 -m unittest discover -s tests -p 'test_*.py'`

## Branch and release policy (current)
1. `main` is the release branch (currently tagged `v0.9`).
2. `dev` is the active integration branch for ongoing work.
3. Use short-lived feature branches from `dev`, then merge back into `dev`.
4. Promote releases by merging `dev` -> `main` after gates are satisfied, then tag (`v1.0`, `v1.1`, etc.).
5. `main` should stay protected in GitHub settings: no direct pushes, at least one review, and required checks before merge.
6. Approval separation at MCP tool surface is complete (approval remains out-of-band via GUI/API).
