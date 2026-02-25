# ai-runtime-guard

A development MCP server that adds a security/policy layer in front of AI-agent filesystem and shell actions.

Operator reference:
- `MANUAL.md` contains the current behavioral guide (matching semantics, tier precedence, retries, budgets, UI metadata limits, and release gates).

## What this is
- Python MCP server with a thin entrypoint (`server.py`) and modular runtime components:
  - `policy_engine.py`, `approvals.py`, `budget.py`
  - `backup.py`, `audit.py`, `executor.py`
  - tool handlers under `tools/`
- Exposes guarded tools: `server_info`, `execute_command`, `read_file`, `write_file`, `delete_file`, `list_directory`, `restore_backup`.
- Policy-driven enforcement loaded from `policy.json` at startup.
- Audit-first behavior with JSONL logs in `activity.log` and pre-change backups in `backups/`.
- Default policy profile is **basic protection**: severe actions are blocked, all others are allowed.
- Advanced tiers (`requires_confirmation`, `requires_simulation`, cumulative budgets) remain available in policy for opt-in use.

## Requirements
Python:
1. Required: Python `>=3.10` (project package metadata enforces this).
2. Recommended on macOS: Python `3.12+` (Homebrew or python.org install).
3. macOS system Python `3.9` is often too old and may fail dependency install (notably `mcp` package constraints and modern tooling expectations).

Why this matters:
1. `ai-runtime-guard` depends on package versions that are not reliably installable on Python 3.9.
2. Clean install friction is significantly lower with a modern Python runtime.

## MVP capabilities and caveats
Capabilities:
1. Basic protection by default: explicitly destructive/sensitive actions are blocked; non-severe actions are allowed.
2. Advanced policy tiers are available per command/path: simulation and human approval.
3. Out-of-band approval workflow is active via GUI/API; agent self-approval via MCP tool surface is removed.
4. Audit logging is comprehensive across agent actions, operator approvals, and server-side events.
5. Backups are created for destructive/overwrite paths with restore support.
6. Command normalization and policy matching reduce common obfuscation bypasses.
7. Workspace/path protections and blocked sensitive paths harden the guardrails around the runtime and approval store.
8. GUI policy control supports command tiering plus user-added commands and user-added categories.

Caveats:
1. Policy updates are loaded at server startup; after Apply, restart MCP server (and usually reconnect/restart agent client) to enforce new runtime behavior.
2. “Basic vs Advanced” is a policy profile convention, not a separate runtime mode switch.
3. Redaction/obfuscation is pattern-based and not a formal guarantee for all sensitive data shapes.
4. Some shell-target inference remains heuristic for complex command constructs.
5. Cumulative budget behavior depends on configured thresholds; defaults may need tuning for your workflow.

## How to run
From source (current dev workflow):
1. `cd /Users/liviu/Documents/ai-runtime-guard`
2. `python3 -m venv venv && source venv/bin/activate`
3. `pip install -r requirements.txt`
4. Configure secure approval-store paths (recommended): `source scripts/setup_runtime_env.sh`
5. Optional workspace override: `export AIRG_WORKSPACE=/absolute/path/to/sandbox`
6. Start MCP server over stdio: `python server.py`

Packaged CLI workflow (Phase 1):
1. `pip install .`
2. `airg-init`
3. Optional workspace override: `export AIRG_WORKSPACE=/absolute/path/to/sandbox`
4. Start MCP server: `airg-server`
5. Optional one-command bring-up (UI sidecar + MCP stdio server): `airg-up`
6. Run health checks: `airg-doctor`

`airg-init` runtime defaults:
- Creates policy/runtime files in user-local config/state paths.
- Sets `audit.backup_root` in generated `policy.json` to a user-local runtime path (state dir + `/backups`) so installs do not inherit developer machine paths.

Using `uvx` (without persistent install):
1. `uvx --from /absolute/path/to/ai-runtime-guard airg-init`
2. `uvx --from /absolute/path/to/ai-runtime-guard airg-server`
3. Optional sidecar bring-up: `uvx --from /absolute/path/to/ai-runtime-guard airg-up`
4. Diagnostics: `uvx --from /absolute/path/to/ai-runtime-guard airg-doctor`

## Local policy UI (v3)
React + Tailwind frontend (Vite) with a Flask backend.

Production-style UI (recommended for packaging):
1. `cd ui_v3`
2. `npm install`
3. `npm run build`
4. Start backend that serves built UI + API:
   - source workflow: `python3 ui/backend_flask.py`
   - packaged workflow: `airg-ui`
5. Open `http://127.0.0.1:5001`

Backend API (dev mode):
1. `python3 -m venv venv && source venv/bin/activate`
2. `pip install -r requirements.txt`
3. `source scripts/setup_runtime_env.sh`
4. `python3 ui/backend_flask.py`

Packaged backend:
1. `pip install .`
2. `airg-init`
3. `airg-ui`

Frontend:
1. `cd ui_v3`
2. `npm install`
3. `npm run dev`
4. Open `http://127.0.0.1:5173`

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
        "AIRG_WORKSPACE": "/absolute/path/to/agent-workspace"
      }
    }
  }
}
```

If your client does not inherit shell environment, run `airg-init` first and pass explicit `AIRG_POLICY_PATH`, `AIRG_APPROVAL_DB_PATH`, and `AIRG_APPROVAL_HMAC_KEY_PATH` in client `env`.

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
   - If you use packaged flow with `airg-init`, no. `airg-init` sets up secure default paths and files.
   - If you run directly from source (`python server.py`, `python ui/backend_flask.py`), yes, it is recommended.
2. What folders are involved?
   - Install folder (`airg-install`): where the code/package lives.
   - Runtime state folder (Application Support/state dir): where `approvals.db` and HMAC key live.
   - Workspace folder (`AIRG_WORKSPACE`, often `airg-workspace`): where agent actions are intended to run.
3. Does the agent only work inside one workspace?
   - By default, yes, it is anchored to `AIRG_WORKSPACE`.
   - Additional allowed roots can be configured with `policy.allowed.paths_whitelist`.

## How to test
Primary workflow (recommended for destructive-behavior testing):
1. Register this MCP server in your AI agent/client.
2. Point `AIRG_WORKSPACE` to a disposable directory dedicated to test runs.
3. Run tool-driven scenarios, especially:
   - blocked destructive commands (`rm -rf`, `dd`, sensitive paths/extensions)
   - allow-path behavior for non-severe commands (low-friction default)
   - optional advanced-mode checks only if you enable them in policy:
     - simulation-gated wildcard deletes (`rm *.tmp`) over/under threshold
     - confirmation handshake (`execute_command` -> human approves in GUI/API -> re-run)
   - backup + recovery checks for write/delete/command-modify paths
   - optional cumulative budget checks (if enabled)

Optional local unit tests in this repo:
- `python3 -m unittest discover -s tests -p 'test_*.py'`

## Branch and release policy (current)
1. `main` is the release branch (currently tagged `v0.9`).
2. `dev` is the active integration branch for ongoing work.
3. Use short-lived feature branches from `dev`, then merge back into `dev`.
4. Promote releases by merging `dev` -> `main` after gates are satisfied, then tag (`v1.0`, `v1.1`, etc.).
5. `main` should stay protected in GitHub settings: no direct pushes, at least one review, and required checks before merge.
6. Approval separation at MCP tool surface is complete (approval remains out-of-band via GUI/API).

## Completed `v0.9` release checkpoints
1. Unit security regressions:
   - `python3 -m unittest discover -s tests -p 'test_*.py'`
2. Manual MCP integration validation:
   - at least 12 prompts from `tests.md`, including destructive block, confirmation flow, simulation, cumulative-budget behavior, restore flow, and network-policy checks.
3. Approval separation:
   - approvals come from a separate trusted/operator channel (GUI/API), not MCP tool calls
   - initiating agent cannot self-approve via MCP tool surface

## Post-merge validation (v1.1)
1. Linux validation is currently untested but expected to work.
2. Track Linux as a v1.1 validation task:
   - run the same unit suite on Linux
   - execute a reduced manual prompt set on Linux and record outcomes in `STATUS.md`
