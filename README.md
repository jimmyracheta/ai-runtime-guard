# ai-runtime-guard

A development MCP server that adds a security/policy layer in front of AI-agent filesystem and shell actions.

## What this is
- Python MCP server with a thin entrypoint (`server.py`) and modular runtime components:
  - `policy_engine.py`, `approvals.py`, `budget.py`
  - `backup.py`, `audit.py`, `executor.py`
  - tool handlers under `tools/`
- Exposes guarded tools: `server_info`, `execute_command`, `approve_command`, `read_file`, `write_file`, `delete_file`, `list_directory`, `restore_backup`.
- Policy-driven enforcement loaded from `policy.json` at startup.
- Audit-first behavior with JSONL logs in `activity.log` and pre-change backups in `backups/`.

## How to run
1. `cd /Users/liviu/Documents/ai-runtime-guard`
2. `python3 -m venv venv && source venv/bin/activate`
3. `pip install -r requirements.txt`
4. Optional workspace override: `export AIRG_WORKSPACE=/absolute/path/to/sandbox`
5. Start MCP server over stdio: `python server.py`

## Local policy UI (MVP skeleton)
Run the local control-plane UI for policy editing:
1. `python3 -m ui.server --host 127.0.0.1 --port 8765`
2. Open `http://127.0.0.1:8765`
3. Optional passcode guard: `export AIRG_UI_PASSCODE=your-passcode` and send `X-UI-PASSCODE` in requests.

Current UI scope:
- load current `policy.json`
- tabbed command tier editing (`allowed`, `requires_simulation`, `requires_confirmation`, `blocked`)
- validate and apply with atomic write
- append-only config change log at `ui/config_changes.log`

## How to test
Primary workflow (recommended for destructive-behavior testing):
1. Register this MCP server in your AI agent/client.
2. Point `AIRG_WORKSPACE` to a disposable directory dedicated to test runs.
3. Run tool-driven scenarios, especially:
   - blocked destructive commands (`rm -rf`, `dd`, sensitive paths/extensions)
   - simulation-gated wildcard deletes (`rm *.tmp`) over/under threshold
   - confirmation handshake (`execute_command` -> `approve_command` -> re-run)
   - backup + recovery checks for write/delete/command-modify paths
   - cumulative budget checks (multiple sub-threshold commands should still hit aggregate limits)

Optional local unit tests in this repo:
- `python3 -m unittest discover -s tests -p 'test_*.py'`

## Merge and branch policy (MVP lock-down)
1. Development happens on feature branches (currently `refactor`), not `main`.
2. Merge path is `refactor` -> `main` only after the pre-merge gate is satisfied.
3. `main` should be protected in GitHub settings: no direct pushes, at least one review, and required checks before merge.
4. Merge freeze is active until approval separation-of-duties is enforced (an initiating agent must not be able to approve its own command).

## Minimum pre-merge gate
1. Unit security regressions pass:
   - `python3 -m unittest discover -s tests -p 'test_*.py'`
2. Manual MCP integration validation passes for at least 12 prompts from `tests.md`, including:
   - 3 blocked destructive command scenarios
   - 2 confirmation-handshake scenarios
   - 2 simulation scenarios (threshold + unresolved wildcard)
   - 2 cumulative-budget anti-bypass scenarios
   - 1 restore flow scenario (dry-run token + apply)
   - 2 network-policy scenarios
3. Linux checkpoint before MVP release:
   - run the same unit suite on Linux
   - execute a reduced manual prompt set on Linux and record outcomes in `STATUS.md`
4. Approval separation checkpoint:
   - verify approvals come from a separate trusted/operator channel
   - verify the initiating agent cannot self-approve its own command flow
