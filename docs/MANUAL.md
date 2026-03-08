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
- Builds report views from `activity.log` into `reports.db` for dashboard and log analytics.
- Creates backups for destructive operations in `backups/`.

### Product scope (intentional)
1. AIRG is designed to prevent accidental damage (hallucinated deletes, wrong-path writes, broad wildcard actions, accidental secret access).
2. AIRG is not a full malicious-actor containment boundary.
3. Core controls:
   - block severe destructive/exfiltration actions by policy
   - enforce workspace/path boundaries
   - gate mass/wildcard actions through simulation/budget controls
   - optionally require operator approval for selected risky commands
   - automatically create backups before destructive/overwrite operations
   - comprehensively audit allowed/blocked actions and operator decisions
4. Enforcement boundary: AIRG controls MCP tool calls only. Native client tools outside MCP are out of scope for AIRG enforcement.

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
2. `airg-service` (GUI service management for macOS/Linux user sessions)
3. `airg-server` (MCP server) and/or `airg-ui` (Flask backend for control plane)
4. `airg-up` starts Flask backend as a sidecar and then starts MCP server (stdio) in one command.
5. `airg-doctor` runs environment, path, permission, and UI-build diagnostics.
6. `airg-ui --with-runtime-env` initializes and prints resolved runtime paths before launching UI backend.
7. Recommended gate: run `airg-doctor` and resolve warnings before first MCP client connection.

Note:
1. In packaged flow, `airg-setup` already performs secure runtime path setup.
2. `scripts/setup_runtime_env.sh` is mainly for direct source/manual runs.
3. `airg-setup` seeds `policy.audit.backup_root` to a user-local runtime state path (`<state_dir>/backups`) when creating policy files.
4. Runtime fallback for backup root also defaults to user-local runtime state (`<state_dir>/backups`) when policy does not define `audit.backup_root`.
5. `airg-setup` prints a ready-to-copy MCP config env block with resolved `AIRG_AGENT_ID`, `AIRG_POLICY_PATH`, `AIRG_APPROVAL_DB_PATH`, `AIRG_APPROVAL_HMAC_KEY_PATH`, `AIRG_LOG_PATH`, and `AIRG_REPORTS_DB_PATH`.
6. `airg-init` is available as a low-level/manual bootstrap fallback.
7. `airg-setup` asks guided questions (workspace, runtime paths, optional GUI service, agent type), updates policy safely, writes agent-compatible MCP config snippets under `./out/mcp-configs`, then runs `airg-doctor`.
8. `airg-setup --gui` performs setup and configures/starts GUI as a user service (`launchd` on macOS, `systemd --user` on Linux).
9. `airg-setup --defaults --yes` is unattended defaults mode; combine with `--gui` or `--no-gui` to control UI service setup.
10. `airg-setup --silent` is fully unattended bootstrap (`--defaults --yes --gui`) with one default Settings agent profile created automatically.
11. If `--agent-id` is omitted, AIRG auto-generates an ID like `unknown-482901`.
12. Setup/profile-generated MCP config includes `AIRG_SERVER_COMMAND` for deterministic startup across shells/services.

Backup-root diagnostics:
1. `airg-doctor` prints resolved `backup_root`.
2. If `backup_root` points to `site-packages` or project directory, treat it as misconfiguration and move it to user-local runtime state paths.

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

### Agent-specific policy overrides
Runtime supports optional per-agent overlays keyed by `AIRG_AGENT_ID`:
1. `policy.agent_overrides.<agent_id>.policy`:
   - deep-merged overlay applied on top of the base policy for that agent only.
   - dictionary values merge recursively, scalar/list values replace base values.
2. Supported per-agent override sections:
   - `blocked`
   - `requires_confirmation`
   - `requires_simulation`
   - `allowed`
   - `network`
   - `execution`
3. Not supported as per-agent overrides:
   - `reports.*`
   - `audit.*`
   - `backup_access.*`
   - `restore.*`
   - workspace path (`AIRG_WORKSPACE` remains MCP/env configured)

Notes:
1. If no override exists for current `AIRG_AGENT_ID`, base policy behavior remains unchanged.
2. Effective policy is resolved at startup, so restart MCP server after editing override entries.
3. This feature enables per-agent guardrails without maintaining separate policy files.
4. UI authoring path is available under `Policy -> Agent Overrides` with section-based editors and baseline info cards.
5. Saved overrides are diff-style overlays, not full copies of baseline sections.

### Current capabilities and caveats snapshot
Capabilities:
1. Default basic profile blocks severe actions and allows non-severe actions.
2. Advanced tiers (`requires_simulation`, `requires_confirmation`) are policy-available and per-command configurable.
3. Approvals are out-of-band (GUI/API), not agent-invokable via MCP tools.
4. Runtime includes audit logging, backup/restore flows, normalization, and path/workspace hardening.
5. GUI supports policy editing, plus adding custom commands and custom categories.
6. GUI `Settings -> Agents` supports profile-based MCP config generation and copy-assist modal flows for CLI/JSON.

Caveats:
1. Runtime policy reload is startup-based; after policy changes, restart MCP server (and usually reconnect agent client).
2. “Basic/Advanced” are policy conventions rather than hard runtime modes.
3. Redaction and obfuscation defenses are pattern-based and not exhaustive.
4. Some blast-radius/target inference for complex shell patterns is heuristic.
5. Cumulative budget efficacy depends on threshold tuning.

### Packaged UI/runtime path behavior
For package installs (PyPI/TestPyPI):
1. UI dist is served from installed package paths (for example `<venv>/ui_v3/dist`) when source-tree paths are not present.
2. Default workspace fallback (when `AIRG_WORKSPACE` is unset) is `~/airg-workspace`.
3. `airg-doctor` should not report workspace under `site-packages`; if it does, treat it as misconfiguration/regression.

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
- `find docs -delete` can be matched directly by blocked pattern `find -delete`.
- `find docs -exec rm {} +` can be matched by blocked pattern `find -exec rm`.
- `printf 'a.tmp\n' | xargs rm` can be matched by blocked pattern `xargs rm`.
- `for f in *.tmp; do rm "$f"; done` can be matched by blocked pattern `do rm`.

Notes:
- Command-level decisions are policy-driven for transparency (blocked/simulation/approval/allowed).
- Runtime still enforces non-command safety invariants in code (workspace boundary, protected runtime paths, control-char sanitization, optional shell containment).

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

Known limitation:
- `execute_command` telemetry can undercount `affected_paths_count` for some shell-expanded forms (for example certain wildcard/wrapper move/delete commands). Policy enforcement still applies, but count metrics in logs/budget metadata can be lower than real path impact until counting normalization is completed.

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

Reset behavior details (current implementation):
- Budget state is evaluated/reset on budget-checked operations (no background timer loop).
- `reset.idle_reset_seconds` performs a full budget-state reset after inactivity beyond the threshold.
- `reset.window_seconds` prunes path-timestamp history for unique-path accounting (sliding-window effect).
- `reset.mode` is currently metadata-level (no distinct mode-specific runtime branches yet).
- `reset.reset_on_server_restart` is effectively redundant while budget state is in-memory, because process restart resets counters.

Practical implication:
- Current settings are strong for burst/mass operations in normal coding sessions.
- Slow-drip patterns spaced beyond `idle_reset_seconds` can avoid meaningful cumulative growth (for example, one operation every 901 seconds with `idle_reset_seconds=900`).
- This is acceptable for accidental-safety-first scope, but should not be treated as malicious-intent containment.

## 9. UI retry/budget fields: what they mean today
The local policy UI writes optional per-command metadata:
- `policy.ui_overrides.commands.<command>.retry_override`
- `policy.ui_overrides.commands.<command>.budget.*`

Current status:
- Persisted in `policy.json`.
- Visible in UI status tags.
- Not enforced by runtime yet.

## 9.1 Allowed limits semantics
- `allowed.max_file_size_mb` is enforced per file, not cumulatively across all files in one operation.
- `allowed.max_files_per_operation` is enforced for default-allowed multi-target operations (safety cap).
- `allowed.max_directory_depth` is measured relative to the deepest matching allowed root (workspace root or a whitelisted root), not from filesystem `/`.
  - Example: if allowed root is `/home/user/airg-workspace` and max depth is `5`, then `/home/user/airg-workspace/a/b/c/d/e` is allowed depth, while adding one more segment exceeds it.
  - This is why the default stays high for normal workflows and is mainly for tight-access deployments.

## 10. Backup and restore behavior
- Backup creation occurs before destructive/overwrite actions.
- Backups are timestamped directories with `manifest.json`.
- `restore_backup` supports dry run and apply.

Important improvement already implemented:
- Dry run issues a `restore_token` bound to the apply step.

Restore confirmation token behavior:
1. `restore.require_dry_run_before_apply=true` means apply requires a valid token from a prior dry-run.
2. Token is time-bounded by `restore.confirmation_ttl_seconds`.
3. If apply is attempted after TTL expiry, restore is rejected and a new dry-run is required.
4. This is an operation-safety gate; it is not a human-approval workflow by itself.

Backup retention/pruning behavior:
1. `audit.backup_on_content_change_only=true` deduplicates backups by content hash (sha256) and skips redundant snapshots.
2. Version/day pruning is event-driven during backup operations (not a background scheduler).
3. `audit.max_versions_per_file` and `audit.backup_retention_days` govern cleanup.
4. Pruning does not currently emit a dedicated prune event for every removed backup artifact.

Audit logging detail:
1. `audit.redact_patterns` applies to log output redaction, not backup file payloads.
2. `audit.log_level` is currently configuration metadata with limited runtime differentiation.

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
2. `allowed_domains`: explicit allow list. Matching domains are allowed when not blocked.
3. `block_unknown_domains`:
   - `false` (default): domains not in either list are allowed.
   - `true`: domains not in `allowed_domains` are blocked (default-deny behavior).
4. If a domain appears in both `allowed_domains` and `blocked_domains`, blocklist wins.
5. Subdomains are matched (`example.com` also matches `api.example.com`).

Still limited:
1. Runtime evaluates domains parsed from command tokens/URLs; redirect chains and out-of-band destination changes are not deeply inspected.

## 12. Local policy UI behavior (current)
Current recommended UI stack:
- Backend: Flask (`ui/backend_flask.py`)
- Frontend: Vite React + Tailwind (`ui_v3/`)

Behavior:
- Three-layer navigation: rail (`Approvals`, `Policy`, `Reports`, `Settings`) + policy tabs (`Commands`, `Paths`, `Extensions`, `Network`, `Advanced Policy`) + content panel.
- Approvals panel polls backend and supports `approve`/`deny` actions against shared SQLite approval store.
- Commands panel supports search, tier radios, clickable command-info modal, applied-state badges, and advanced JSON editor.
- Commands panel supports adding custom commands (with optional description/comment) and assigning them to one or more categories.
- Commands panel supports adding custom categories.
- Commands panel advanced tier visibility toggle controls only command tier radios (`Simulation`, `Requires Approval`); global retry/budget controls are configured on `Advanced Policy`.
- Paths panel is separate from Commands and includes:
  - read-only runtime path display (workspace/policy/approval paths)
  - instructions to update MCP config/env and restart for runtime path changes
  - policy-managed path rules with absolute-path validation
  - mapping: `Allowed` => `allowed.paths_whitelist`, `Blocked` => `blocked.paths`, `Requires Approval` => `requires_confirmation.paths`
  - editable/removable path entries
- Network panel includes:
  - `network.enforcement_mode` control (`off` / `monitor` / `enforce`)
  - editable `network.commands` list (used to trigger network policy evaluation)
  - editable domain whitelist/blocklist with precedence guidance
- Advanced Policy panel includes global simulation/budget controls:
  - `requires_simulation.max_retries` and `bulk_file_threshold`
  - cumulative budget enable/scope/limits
  - counting controls (`mode`, `dedupe_paths`, `include_noop_attempts`, `commands_included`)
  - reset controls (`reset.window_seconds`, `reset.idle_reset_seconds`)
  - note: `cumulative_budget.audit.*` is still not exposed in GUI controls
- Advanced Policy panel also includes shell containment for `execute_command`:
  - `execution.shell_workspace_containment.mode` with `off` / `monitor` / `enforce`
  - this is a best-effort path guard for shell command arguments and redirection targets
  - `monitor` logs violations but allows execution; `enforce` blocks
- Status badges reflect applied policy only (post-`Apply`).
- Reports rail now includes:
  - `Dashboard` tab with totals, 7-day event/blocked trends, top commands/paths, blocked-by-rule.
  - `Log` tab with paginated events and filters (`agent_id`, `agent_session_id`, `source`, `tool`, `policy_decision`, `decision_tier`, `matched_rule`, `command`, `path`, `event`, time range).
  - automatic ingestion from `activity.log` into `reports.db`, with freshness metadata (`Last indexed`).
  - ingest sync runs on manual refresh and scheduled refresh, while filter changes query existing indexed data.
- Shared policy actions are available across all policy tabs: `Reload`, `Validate`, `Apply`, `Revert Last Apply`, `Reset to Defaults`.
- `Apply`/`Revert`/`Reset` perform validation + atomic write and append `ui/config_changes.log`.
- Global header no longer shows tier legend badges; it retains policy hash and unsaved-changes state.

Snapshot behavior for policy actions:
- `Reset to Defaults` is enabled when a defaults snapshot exists (`policy.json.defaults`).
- `Revert Last Apply` is enabled after at least one apply/revert/reset operation creates a last-applied snapshot (`policy.json.last-applied`).

Serving model:
- `ui/backend_flask.py` now serves both REST API endpoints and built frontend assets from `ui_v3/dist` when present.
- Prebuilt `ui_v3/dist` assets are committed and packaged for normal installs; rebuilding is only needed for local frontend development changes.
- If the frontend build is missing, backend API routes still work and `/` returns a build-missing hint.
- Override built UI path with `AIRG_UI_DIST_PATH` when needed.
- Legacy UI fallback is no longer used in normal flow, which prevents silent serving of stale assets.

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
2. Manual MCP gate from `TEST_PLAN.md` must pass.
3. Approval separation gate must pass (agent cannot approve via MCP tool surface).

Linux validation note:
- Linux validation summary is documented in `docs/LINUX_VALIDATION_SUMMARY.md`.

## 15. Known high-priority limitations
- Operator endpoint authentication/authorization remains local-trust oriented and should be hardened before broad deployment.
- `shell=True` remains in command execution path.
- `execution.shell_workspace_containment` can reduce accidental out-of-workspace shell access, but it is heuristic and does not replace OS-level sandboxing.
- Cumulative budget defaults may be too high to trigger in typical manual runs.
- Per-command UI override fields are metadata only today.
- AIRG enforcement only applies to MCP tool calls; native client shell/file tools (for example Claude Code Bash) can bypass AIRG controls.
- For Claude Code, a sample MCP-only skill is provided at `docs/mcp-only.md`; save it as `<workspace>/.claude/skills/mcp-only.md` to guide strict MCP-only behavior.
