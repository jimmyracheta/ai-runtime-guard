# AI Runtime Guard Manual

This manual explains current runtime behavior as implemented today.

## 0. Runtime prerequisites
Python:
1. Required: Python `>=3.10`.
2. Recommended: Python `3.12+`.
3. On macOS, system Python is often `3.9` and can cause dependency install failures; use a newer Python (Homebrew/python.org) and create a fresh venv from that version.

## 1. What the server does
- Exposes MCP tools: `server_info`, `execute_command`, `read_file`, `write_file`, `delete_file`, `list_directory`, `restore_backup`.
- Applies policy from `policy.json` before side effects.
- Logs all actions to `activity.log`.
- Creates backups for destructive operations in `backups/`.

### Runtime environment setup (recommended)
Before starting MCP server and UI backend, source:
- `source scripts/setup_runtime_env.sh`

This exports:
- `AIRG_APPROVAL_DB_PATH`
- `AIRG_APPROVAL_HMAC_KEY_PATH`

Default locations created by the script:
- macOS: `~/Library/Application Support/ai-runtime-guard/`
- Linux: `${XDG_STATE_HOME:-~/.local/state}/ai-runtime-guard/`

The script also enforces restrictive permissions (`700` for directories, `600` for files) to avoid approval-store hardening warnings and reduce tamper/exfiltration risk.

Packaged CLI alternative:
1. `airg-setup` (recommended)
2. Guided setup alias: `airg init --wizard`
3. `airg-server` (MCP server) and/or `airg-ui` (Flask backend for control plane)
4. `airg-up` starts Flask backend as a sidecar and then starts MCP server (stdio) in one command.
5. `airg-doctor` runs environment, path, permission, and UI-build diagnostics.
6. Recommended gate: run `airg-doctor` and resolve warnings before first MCP client connection.

Note:
1. In packaged flow, `airg-setup` already performs secure runtime path setup.
2. `scripts/setup_runtime_env.sh` is mainly for direct source/manual runs.
3. `airg-setup`/`airg-init` seed `policy.audit.backup_root` to a user-local runtime state path (`<state_dir>/backups`) when creating policy files.
4. `airg-setup`/`airg-init` print a ready-to-copy MCP config env block with resolved `AIRG_POLICY_PATH`, `AIRG_APPROVAL_DB_PATH`, and `AIRG_APPROVAL_HMAC_KEY_PATH`.
5. `airg-setup` asks guided questions (workspace, runtime paths, optional additional workspaces, agent type), updates policy safely, writes agent-compatible MCP config snippets under `./out/mcp-configs`, then runs `airg-doctor`.

### AIRG_WORKSPACE model
`AIRG_WORKSPACE` defines the operational sandbox root for AI agent actions.

Behavior:
1. `execute_command` runs with this directory as working directory.
2. File/tool path checks are evaluated against this root and policy path rules.
3. Traversal outside workspace is blocked.

Operational guidance:
1. Install folder and workspace should be separate.
2. Example install path: `~/Documents/Projects/ai-runtime-guard`
3. Example workspace path: `~/airg-workspace`
4. Do not use the install folder as the default destructive-test workspace.
5. If you need multiple workspaces, add explicit extra roots under `policy.allowed.paths_whitelist`.

### MVP capabilities and caveats snapshot
Capabilities:
1. Default basic profile blocks severe actions and allows non-severe actions.
2. Advanced tiers (`requires_simulation`, `requires_confirmation`) are policy-available and per-command configurable.
3. Approvals are out-of-band (GUI/API), not agent-invokable via MCP tools.
4. Runtime includes audit logging, backup/restore flows, normalization, and path/workspace hardening.
5. GUI supports policy editing, plus adding custom commands and custom categories.

Caveats:
1. Runtime policy reload is startup-based; after policy changes, restart MCP server (and usually reconnect agent client).
2. “Basic/Advanced” are policy conventions rather than hard runtime modes.
3. Redaction and obfuscation defenses are pattern-based and not exhaustive.
4. Some blast-radius/target inference for complex shell patterns is heuristic.
5. Cumulative budget efficacy depends on threshold tuning.

## 2. Policy tier order (most important)
Command checks run in strict precedence:
1. `blocked`
2. `requires_confirmation`
3. `requires_simulation`
4. `allowed`

If a command matches multiple tiers, the highest tier wins.

## 3. Action options (basic vs advanced)
Default profile:
- Runtime ships in basic-protection mode by default: severe commands/paths are blocked, all other actions are allowed.
- Advanced tiers remain in policy for opt-in hardening when desired.

### Basic options
- `allowed`:
  - Command/path passes policy and executes immediately.
  - No human checkpoint required.
- `blocked`:
  - Command/path is denied immediately.
  - No approval path for that request.
  - For `execute_command`, blocked outcomes (except confirmation-tier blocks) consume server-side retry budget until final block.

### Advanced options
- `requires_simulation`:
  - Runtime simulates blast radius for configured command families (wildcards, bulk actions).
  - If simulation exceeds threshold or cannot safely resolve wildcard targets, command is blocked with a simulation reason.
  - If `requires_confirmation` also matches, confirmation wins by precedence, and simulation context is still included in response/log.
- `requires_confirmation`:
  - Runtime returns an approval token and requires human/operator approval via GUI/API before retrying the exact command.
  - Approval is one-time for session+command and time-bounded.
  - This tier does not consume the server retry counter for blocked attempts.
  - In default basic profile, this tier is configured but inactive until commands/paths are populated.

## 4. Command matching behavior
- Matching is not strict full-string equality.
- Single-token patterns (example: `rm`) are token-aware.
- Multi-token patterns (example: `rm -rf`) match normalized command sequences.

Examples:
- `rm -rf /tmp/x` matches blocked `rm -rf`.
- `rm *.txt` does not match `rm -rf`; it can still be caught by `requires_confirmation`/`requires_simulation` if `rm` is configured there.

## 5. Confirmation handshake behavior
Current flow:
1. `execute_command` is blocked with a token when `requires_confirmation` matches.
2. A human operator approves out-of-band via control-plane GUI/API (`/approvals/approve`) using exact `command` + `token`.
3. Re-running the exact command can proceed.

Storage model:
- pending approvals are persisted in `approvals.db` (SQLite) so separate processes can read/update the same queue.
- each pending record includes `token`, `command`, `session_id`, `requested_at`, `expires_at`, and optional `affected_paths`.
- approved commands are persisted as one-time session+command grants in SQLite and consumed by MCP confirmation checks on retry.

Current security status:
- MCP no longer exposes an agent-callable approval tool.
- Approval decisions come from out-of-band operator channels (GUI/API) and are persisted in SQLite.
- Operator actions are logged as `source: "human-operator"` in `activity.log`.

## 6. Simulation behavior
- Simulation is used for wildcard blast-radius checks (`requires_simulation.commands`).
- Wildcard operations can be blocked if unresolved or above threshold.
- When confirmation wins tier precedence, simulation context is still included in confirmation response and audit fields.

## 7. Retry behavior
- Retries are server-side, not client-authoritative.
- Retry key is scoped to `(normalized_command + decision_tier + matched_rule)`.
- Retries are not one global counter for the entire session.
- Retries apply to blocked `execute_command` outcomes except `requires_confirmation`.

Practical effect:
- Different blocked command/rule combinations maintain independent retry counters.

## 8. Budget behavior
Current enforced budget:
- Global cumulative budget under `requires_simulation.cumulative_budget`.
- Scope is policy-driven (currently typically `session`).
- Aggregates operations/paths/bytes across included commands.

Budget fields visible in logs/UI (runtime-level):
- `budget ops`: cumulative total operations (`cumulative_total_operations`).
- `budget paths`: cumulative unique affected paths (`cumulative_unique_paths`).
- `budget bytes`: cumulative estimated bytes touched (`cumulative_total_bytes_estimate`).

Not currently enforced:
- Per-command budget overrides from UI metadata.
- Budget override tied to confirmation approvals is temporarily disabled during durable approval migration (pending explicit redesign).

## 9. UI retry/budget fields: what they mean today
The local policy UI writes optional per-command metadata:
- `policy.ui_overrides.commands.<command>.retry_override`
- `policy.ui_overrides.commands.<command>.budget.*`

Current status:
- Persisted in `policy.json`.
- Visible in UI status tags.
- Not enforced by runtime yet.

## 10. Backup and restore behavior
- Backup creation occurs before destructive/overwrite actions.
- Backups are timestamped directories with `manifest.json`.
- `restore_backup` supports dry run and apply.

Important improvement already implemented:
- Dry run issues a `restore_token` bound to the apply step.

## 11. Network behavior
- `network.enforcement_mode` controls behavior:
1. `off`: skip network policy checks.
2. `monitor`: evaluate policy and emit warnings/diagnostics, but do not block command execution.
3. `enforce`: evaluate policy and block when domain rules fail.

- `network.commands` is intent classification, not a direct deny list:
1. These command markers (`curl`, `wget`, `scp`, etc.) are used to decide whether network-domain policy should run.
2. Listing a command in `network.commands` alone does not block it.

- Domain rules:
1. `blocked_domains`: explicit deny list. Matching domains are blocked in `enforce` mode.
2. `allowed_domains`: allow list. When non-empty, domains not in this list are blocked in `enforce` mode.
3. If both `blocked_domains` and `allowed_domains` are empty, network commands are allowed (even in `enforce` mode).

Still limited:
1. `network.max_payload_size_kb` is currently policy metadata and not runtime-enforced.
2. Deep payload/protocol inspection is not implemented.

## 12. Local policy UI behavior (current)
Current recommended UI stack:
- Backend: Flask (`ui/backend_flask.py`)
- Frontend: Vite React + Tailwind (`ui_v3/`)

Behavior:
- Three-layer navigation: rail (`Approvals`, `Policy`, `Reports`, `Settings`) + policy tabs (`Commands`, `Paths`, `Extensions`) + content panel.
- Approvals panel polls backend and supports `approve`/`deny` actions against shared SQLite approval store.
- Commands panel supports search, tier radios, clickable command-info modal, applied-state badges, retry/budget metadata inputs, and advanced JSON editor.
- Commands panel supports adding custom commands (with optional description/comment) and assigning them to one or more categories.
- Commands panel supports adding custom categories.
- Paths panel is separate from Commands and includes:
  - read-only runtime path display (workspace/policy/approval paths)
  - instructions to update MCP config/env and restart for runtime path changes
  - policy-managed path rules with absolute-path validation
  - mapping: `Allowed` => `allowed.paths_whitelist`, `Blocked` => `blocked.paths`, `Requires Approval` => `requires_confirmation.paths`
  - editable/removable path entries
- Status badges reflect applied policy only (post-`Apply`).
- Shared policy actions are available across all policy tabs: `Reload`, `Validate`, `Apply`, `Revert Last Apply`, `Reset to Defaults`.
- `Apply`/`Revert`/`Reset` perform validation + atomic write and append `ui/config_changes.log`.
- Global header no longer shows tier legend badges; it retains policy hash and unsaved-changes state.

Snapshot behavior for policy actions:
- `Reset to Defaults` is enabled when a defaults snapshot exists (`policy.json.defaults`).
- `Revert Last Apply` is enabled after at least one apply/revert/reset operation creates a last-applied snapshot (`policy.json.last-applied`).

Serving model:
- `ui/backend_flask.py` now serves both REST API endpoints and built frontend assets from `ui_v3/dist` when present.
- If the frontend build is missing, backend API routes still work and `/` returns a build-missing hint.
- Override built UI path with `AIRG_UI_DIST_PATH` when needed.

## 13. What is automatic vs manual in UI command catalog
Automatic:
- Commands added to policy command lists appear in `All Commands`.
- Commands/categories added in UI are persisted in `policy.json` (`ui_catalog`) and reloaded automatically.

Manual:
- Editing base shipped defaults in `ui/catalog.json` is optional.
- Runtime enforcement still depends on MCP server restart after policy Apply.

## 14. Merge and release gates (current)
Before merge to `main`:
1. Unit tests must pass (`python3 -m unittest discover -s tests -p 'test_*.py'`).
2. Manual MCP gate from `tests.md` must pass.
3. Approval separation gate must pass (agent cannot approve via MCP tool surface).

Linux validation note:
- Linux is currently untested but expected to work.
- Linux validation is tracked as a post-merge v1.1 validation task.

## 15. Known high-priority limitations
- Operator endpoint authentication/authorization remains local-trust oriented and should be hardened before broad deployment.
- `shell=True` remains in command execution path.
- Cumulative budget defaults may be too high to trigger in typical manual runs.
- Per-command UI override fields are metadata only today.
