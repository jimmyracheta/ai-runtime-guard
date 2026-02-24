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
