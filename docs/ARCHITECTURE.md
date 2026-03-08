# Architecture

## System overview
`ai-runtime-guard` is a Python MCP server (`FastMCP`) that places a policy decision layer in front of high-risk agent capabilities. The server exposes a small tool surface and funnels every tool call through deterministic checks before any filesystem or shell side effect.

Core design goals observed in code:
- Enforce explicit safety policy from config (`policy.json`), not hardcoded allow/deny logic.
- Keep an auditable trace for every call (allowed and blocked).
- Preserve recoverability for destructive operations through automatic backups.
- Bound risky operations with simulation and retry limits.

Primary runtime artifacts:
- `server.py`: thin MCP entrypoint and tool registration only.
- `config.py`: startup config load/normalize and shared runtime state.
- `policy_engine.py`: tiered policy evaluation, command parsing/simulation, path checks.
- `approvals.py`: command/restore token lifecycle and approval failure throttling.
- `budget.py`: cumulative budget accounting and scope/reset behavior.
- `backup.py`: backup extraction, dedupe/hash logic, retention/version pruning.
- `reports.py`: activity-log ingestion, reports SQLite schema, query aggregations, retention pruning.
- `audit.py`: canonical audit-log entry build + append helpers.
- `executor.py`: constrained subprocess environment and shell execution wrapper.
- `tools/`: tool surfaces split by concern (`command_tools.py`, `file_tools.py`, `restore_tools.py`).
- `policy.json`: runtime policy tiers and thresholds.
- `activity.log`: JSONL audit trail (one object per event).
- `reports.db`: SQLite analytics store derived from `activity.log` for UI reporting.
- `backups/`: timestamped snapshots with per-backup `manifest.json`.
- `ui/`: control-plane backend service modules (`ui/service.py`, `ui/backend_flask.py`).
- `ui/backend_flask.py`: REST backend for policy + approvals endpoints used by control-plane UI v3.
- `ui_v3/`: Vite React + Tailwind control-plane frontend.
- `agent_configs.py`: profile registry and MCP config generation engine for `Settings -> Agents`.

## Effective policy resolution
Policy is resolved in two stages at startup:
1. Load and normalize base `policy.json`.
2. If `policy.agent_overrides.<AIRG_AGENT_ID>` exists:
   - deep-merge optional `policy` overlay onto base policy
   - normalize merged document as effective policy used by runtime modules

Merge behavior:
- dictionary fields merge recursively
- scalar/list fields replace base values

This keeps single-policy installs backward compatible while enabling per-agent policy isolation in shared deployments.
Workspace remains sourced from `AIRG_WORKSPACE` in MCP/runtime env, not policy overrides.

Authoring model:
1. Base policy remains the source of truth.
2. Agent overrides are saved as diff overlays under `agent_overrides.<agent_id>.policy`.
3. Effective policy at runtime is base + overlay merge for the active `AIRG_AGENT_ID`.

## Dependency guardrails
The modular architecture assumes a one-way dependency direction:
- `config.py`/`models.py` at the base
- runtime modules (`audit`, `policy_engine`, `approvals`, `budget`, `backup`, `executor`) above
- `tools/*` at the top, with `server.py` only wiring registrations

To prevent future circular imports, keep `audit.py` independent of runtime modules (especially `policy_engine.py`) and avoid cross-importing between peers unless absolutely necessary. If shared behavior is needed, extract it into a lower-level helper module rather than introducing bidirectional imports.

## Policy tiers
Policy evaluation is centralized in `check_policy(command)` and uses strict priority:
1. `blocked`
2. `requires_confirmation`
3. `requires_simulation`
4. `allowed`

If multiple tiers match one command, highest-priority tier wins and a `policy_conflict_warning` event is appended to `activity.log`.

### `blocked`
Immediate deny. Used for known-dangerous commands, sensitive paths, and key/cert extensions.

Current defaults (from `policy.json`):
- commands: `rm -rf`, `mkfs`, `shutdown`, `reboot`, `format`, `dd`
- paths: `.env`, `.ssh`, `/etc/passwd`
- extensions: `.pem`, `.key`

### `requires_confirmation`
Soft block until one-time explicit approval is provided through handshake:
- `execute_command(...)` returns `approval_token` + expiry.
- human operator approves out-of-band via control-plane GUI/API (`/approvals/approve`) with exact command match.
- successful approval stores a one-time session+command grant in shared SQLite, consumed on next retry.
- pending approvals are persisted in SQLite (`approvals.db`) so multiple processes (MCP server + Flask UI) can read/update shared approval state.

### `requires_simulation`
For configured command families, wildcard impact is simulated before execution:
- command is tokenized per shell segment
- wildcard tokens are expanded with `glob`
- matches are constrained to workspace/allowed roots
- operation is blocked when affected path count exceeds `bulk_file_threshold`
- wildcard that cannot be safely resolved is blocked and requires explicit filenames

Current default profile:
- `requires_simulation.commands` is empty (basic-protection default).
- simulation logic becomes active when operators add command patterns to this tier.

### `allowed`
If no higher tier matched, the command/path is allowed, still logged, and then executed/read/written/deleted/listed subject to path boundary and size/depth limits for file tools.

Allowed-tier limits currently enforced in runtime:
- `allowed.max_file_size_mb` for `read_file`
- `allowed.max_files_per_operation` for default-allowed multi-target `execute_command` flows (resolved path targets)
- `allowed.max_directory_depth` for `list_directory`

## Retry logic
Retry enforcement is server-side, independent of any client-provided `retry_count`.

Mechanism:
- blocked non-confirmation decisions call `_register_retry(...)`
- retry key = SHA256(normalized command + decision tier + matched rule)
- counts are stored in `SERVER_RETRY_COUNTS`
- count is clamped at `MAX_RETRIES` (loaded from `policy.requires_simulation.max_retries`)

User-visible behavior in `execute_command`:
- before max: policy block message includes attempts remaining
- at max: final block message indicates permanent block for current request
- confirmation-tier blocks do not consume this retry bucket

## Simulation model
Simulation is implemented by `_simulate_blast_radius(command, sim_commands)`.

Model details:
- splits command on shell separators (`|`, `;`, `&`) and evaluates each segment
- parses with `shlex.split`; parse failure marks simulation ambiguous
- evaluates only operations listed in `requires_simulation.commands`
- expands wildcard args (`*`, `?`, `[...]`) using `glob.glob`
- normalizes paths to absolute and filters by `is_within_workspace(...)`
- does not hardcode command-specific destructive wrappers (for example `find -delete`) into simulation logic; those are expected to be expressed in policy command patterns for transparent operator control
- returns:
  - `affected`: sorted unique resolved paths
  - `saw_wildcard`: whether wildcard syntax was present
  - `parse_error`: whether shell tokenization failed

Blocking conditions:
- wildcard used + parse error or no concrete match => blocked (`requires_simulation.wildcard_unresolved`)
- `len(affected) > bulk_file_threshold` => blocked (`requires_simulation.bulk_file_threshold`)

## Logging schema
All operational logs are JSON objects written to `activity.log`.

Canonical builder: `build_log_entry(tool, PolicyResult, **kwargs)`.

Base fields:
- `timestamp` (UTC ISO8601 with `Z`)
- `source` (typically `ai-agent`, with `mcp-server` for internal side-effects/warnings and `human-operator` for GUI/API approvals)
- `session_id` (active session identity; connection-scoped during tool execution, process fallback outside tool context)
- `tool`
- `workspace`
- `policy_decision` (`allowed` or `blocked`)
- `decision_tier`

Conditional fields:
- `matched_rule` (when relevant)
- `block_reason` (when blocked)

Common extra fields by context:
- command flow: `command`, `normalized_command`, `retry_count`, `server_retry_count`, `final_block`
- path tools: `path`, `error`
- backup events: `backup_location`, `event=backup_created`
- confirmation flow: `approval_token`, `event=command_approved`
- policy overlap: `event=policy_conflict_warning`, `matching_tiers`, `resolved_to`
- identity/session flow: `agent_id` (configured identity), `agent_session_id` (connection-scoped identity), `session_id` (alias to active session identity for compatibility)

## Reporting pipeline
Reporting is read-optimized and does not alter enforcement flow.

Flow:
1. MCP/runtime writes JSONL events to `activity.log` in real time.
2. UI backend calls reports sync, which tails new log bytes into `reports.db` (`events` + `ingest_state` + `meta`).
3. Reports UI reads analytics from `reports.db`, not from raw log lines.

Design properties:
1. `activity.log` remains source of truth.
2. Reporting ingestion is best-effort and non-blocking for policy enforcement.
3. Retention/pruning is policy-driven (`reports.retention_days`, `reports.max_db_size_mb`, `reports.prune_interval_seconds`).
4. Ingested rows include `agent_id`, `agent_session_id`, and `session_id` for multi-agent attribution views.

## Backup and recovery model
Backups are created for destructive/overwrite operations:
- `execute_command`: when regex detects `rm`, `mv`, or overwrite redirect (`>` but not `>>`)
- `write_file`: before overwriting existing files
- `delete_file`: before deletion

Backup behavior:
- backup folder: `backups/<UTC timestamp>_<8-char uuid>/`
- source-relative path preservation to avoid basename collisions
- `manifest.json` records source/backup/type
- retention cleanup removes folders older than `audit.backup_retention_days`

## MCP tool to action map
- `server_info`: returns build/workspace/base metadata.
- `execute_command`: policy-check command (including optional shell workspace containment), track retries, optional backup, execute in constrained env (`shell=True`, `/bin/bash`, cwd=`WORKSPACE_ROOT`, 30s timeout).
- `read_file`: path policy + file-size guard, then read text (`errors="replace"`).
- `write_file`: path policy, optional pre-overwrite backup, write text.
- `delete_file`: path policy, existence/type checks, pre-delete backup, delete file.
- `list_directory`: path policy, existence/type/depth checks, return formatted listing with type/size/mtime.

## Agent profile/config architecture
Settings agent management persists runtime-scoped profile metadata and generated config artifacts:
1. Registry path: `<state_dir>/mcp-configs/agents.json`
2. Generated artifacts: `<state_dir>/mcp-configs/*.json` and instruction files
3. Shared runtime paths (`policy/db/log/reports`) are common across profiles; profile-specific values are `agent_id` and `workspace`.
4. Server command generation is deterministic:
   - explicit `AIRG_SERVER_COMMAND` if valid/resolvable
   - venv/sibling `airg-server`
   - fallback `<python> -m airg_cli server`

## Trust boundaries and notable gaps
Observed current gaps/risk areas:
- network policy is enforced at command gate level (domain intent + domain allow/block + optional unknown-domain default-deny), but redirect/final-destination inspection remains limited.
- command execution uses `shell=True`; mitigations exist but parser/shell complexity remains a core risk surface.
- optional shell containment (`execution.shell_workspace_containment`) provides best-effort path-boundary checks for shell command arguments/redirection, but cannot guarantee full shell semantic coverage.
- backup path extraction for command execution relies on token regex + existence checks and can miss some shell-expanded path forms.
- `execute_command` telemetry can undercount `affected_paths_count` for some shell-expanded/wrapper command forms; policy enforcement still applies, but path-impact metrics in logs/budget metadata can be lower than true impact until counting normalization is completed.

## Policy profile baseline
Current shipping policy baseline is basic protection:
- severe destructive/system commands are blocked by default
- `requires_confirmation.commands` and `requires_simulation.commands` are empty by default
- advanced tiers are opt-in via policy/UI configuration

This keeps default operation low-friction for accidental-safety use cases while preserving stricter controls for advanced deployments.

## Policy UI metadata
The UI can store per-command editor metadata in:
- `policy.ui_overrides.commands.<command>.retry_override`
- `policy.ui_overrides.commands.<command>.budget.*`

Current behavior:
- metadata is persisted by UI apply flow and included in audit diffs
- runtime enforcement is unchanged in current stable baseline; these fields are planning/config scaffolding for later per-command enforcement work
