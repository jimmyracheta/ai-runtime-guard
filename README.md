# ai-runtime-guard

A development MCP server that adds a security/policy layer in front of AI-agent filesystem and shell actions.

## What this is
- Python MCP server (`server.py`) exposing guarded tools: `server_info`, `execute_command`, `approve_command`, `read_file`, `write_file`, `delete_file`, `list_directory`.
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
2. Point workspace to a separate test directory (your current practice): `~/Documents/ai-runtime-guard-test`.
3. Run tool-driven scenarios, especially:
   - blocked destructive commands (`rm -rf`, `dd`, sensitive paths/extensions)
   - simulation-gated wildcard deletes (`rm *.tmp`) over/under threshold
   - confirmation handshake (`execute_command` -> `approve_command` -> re-run)
   - backup + recovery checks for write/delete/command-modify paths

Optional local unit tests in this repo:
- `python -m unittest test_attacker_suite.py`
- `pytest -q test_retry_clamp_pytest.py`
