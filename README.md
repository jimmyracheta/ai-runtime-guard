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
1. `cd /Users/liviu/Documents/ai-runtime-guard`
2. `python3 -m venv venv && source venv/bin/activate`
3. `pip install -r requirements.txt`
4. Optional workspace override: `export AIRG_WORKSPACE=/absolute/path/to/sandbox`
5. Start MCP server over stdio: `python server.py`

## Local policy UI (v3)
React + Tailwind frontend (Vite) with a Flask backend.

Backend:
1. `python3 -m venv venv && source venv/bin/activate`
2. `pip install -r requirements.txt`
3. `python3 ui/backend_flask.py`

Frontend:
1. `cd ui_v3`
2. `npm install`
3. `npm run dev`
4. Open `http://127.0.0.1:5173`

Current UI v3 scope:
- three-layer navigation rail + command tabs + main panel
- approvals panel with polling and approve/deny actions
- command table with tier columns, tooltip descriptions, status badges, retry/budget metadata editors
- advanced JSON editor (bidirectional with table state)
- validate/apply/reload flows against Flask REST API

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

## Merge and branch policy (MVP lock-down)
1. Development happens on feature branches (currently `refactor`), not `main`.
2. Merge path is `refactor` -> `main` only after the pre-merge gate is satisfied.
3. `main` should be protected in GitHub settings: no direct pushes, at least one review, and required checks before merge.
4. Approval separation at MCP tool surface is complete (approval remains out-of-band via GUI/API).

## Completed pre-merge checkpoints
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
