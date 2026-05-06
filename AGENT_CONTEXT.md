# AIRG Agent Context (Local, Git-Ignored)

Purpose: fast, comprehensive handoff for any AI coding agent working in this repository.

Status timestamp: 2026-05-06
Active release-candidate version on dev: 2.3.1.dev3

## 1) Project Goal

`ai-runtime-guard` (AIRG) is a local MCP security/policy enforcement server plus web control plane.

Primary job:
1. Intercept tool calls routed through AIRG MCP tools.
2. Enforce policy tiers (`blocked`, `requires_confirmation`, `allowed`) with additional network/workspace/sentinel controls.
3. Maintain approval workflow, backups, and audit logs.
4. Provide a GUI for policy, approvals, reports, and agent hardening/posture management.

## 2) Scope + Security Boundary

AIRG enforces only actions that pass through AIRG tools:
- `execute_command`
- `read_file`
- `write_file`
- `edit_file`
- `delete_file`
- `list_directory`
- `restore_backup`

Out of scope unless separately hardened in client:
- Native IDE/client tools not routed via AIRG MCP (for example Cursor/Claude/Codex native file/shell tools).

Current enforcement limitations/failure modes:
1. Hook enforcement is client-dependent; some native tools may remain allowed or unmapped.
2. Shell parsing for substitutions/segments is best-effort static analysis, not full shell interpretation.
3. Network checks rely on marker/token/domain extraction from command text.
4. Shell workspace containment is heuristic path-token analysis and may run in `off` or `monitor`.
5. Script Sentinel write-time tagging applies only to files written via AIRG `write_file` / `edit_file`.
6. In local STDIO deployments, identity separation is profile/env based (`AIRG_AGENT_ID` + workspace), not authenticated per-instance identity.

## 3) High-Level Architecture

Layers:
1. Runtime core (`src/`): policy engine, approvals, backup, audit, execution, sentinel, telemetry, reports.
2. MCP server (`src/server.py`): registers tool handlers from `src/tools/`.
3. GUI backend (`src/ui/backend_flask.py`): REST API + static SPA serving.
4. GUI frontend (`ui_v3/src/App.jsx` + components): policy/admin UX.
5. Agent integration subsystem:
   - profiles (`src/agent_configs.py`)
   - hardening apply/undo (`src/agent_configurator.py`)
   - posture signals (`src/agent_posture.py`)
   - MCP config write/merge (`src/mcp_config_manager.py`)
   - hook entrypoint (`src/airg_hook.py`)

Current Codex integration model:
1. MCP apply/remove is scope-aware (`global` vs `project`) in `src/mcp_config_manager.py`.
2. Project-scoped Codex MCP can optionally bootstrap trust in `~/.codex/config.toml` via `[projects."<workspace>"].trust_level = "trusted"`.
3. Codex hardening artifacts are scope-aware in `src/agent_configurator.py`:
   - `config.toml`
   - `AGENTS.md`
   - `rules/airg.rules`
4. AIRG no longer uses Codex `default.rules` for managed policy mirror state.

Data stores/files:
1. Policy JSON: `policy.json` (or resolved `AIRG_POLICY_PATH`)
2. Audit log: `activity.log`
3. Approvals DB: `approvals.db` (+ HMAC key)
4. Reports DB: `reports.db` (indexed ingest from `activity.log`)
5. Backups: `backups/` (or configured backup root)

## 4) Runtime Flow (Command Path)

For `execute_command`:
1. Validate command payload format.
2. Enforce backup-access protections.
3. Enforce network policy (`off|monitor|enforce`).
4. Enforce shell workspace containment (`off|monitor|enforce`).
5. Resolve policy tier decision (`blocked`, `requires_confirmation`, `allowed`).
6. Run Script Sentinel execute-time checks.
7. If allowed, run command under executor limits.
8. Log structured event(s) to `activity.log`.
9. Reports subsystem ingests events into `reports.db` (poll/reconcile/prune).

## 5) Key Config/Env

Important env vars:
1. `AIRG_POLICY_PATH`
2. `AIRG_APPROVAL_DB_PATH`
3. `AIRG_APPROVAL_HMAC_KEY_PATH`
4. `AIRG_LOG_PATH`
5. `AIRG_REPORTS_DB_PATH`
6. `AIRG_WORKSPACE`
7. `AIRG_AGENT_ID`
8. `AIRG_UI_DIST_PATH`
9. `AIRG_SERVER_COMMAND`

Telemetry controls:
1. Source of truth is policy (`telemetry.enabled`, `telemetry.endpoint`).
2. Setup prompts for opt-in (default Yes).
3. GUI can toggle telemetry any time and preview payload.
4. Generator writes one payload per UTC day to telemetry outbox and updates `telemetry.last_payload_generated_date`.
5. Uploader sends outbox payloads and updates `telemetry.last_payload_uploaded_at` (`last_sent_date` retained as compatibility field).

Policy major sections:
1. `blocked`
2. `requires_confirmation`
3. `allowed`
4. `network`
5. `execution`
6. `backup_access`
7. `restore`
8. `audit`
9. `reports`
10. `telemetry`
11. `script_sentinel`
12. `agent_overrides`

## 6) File-by-File Map

### Core runtime (`src/`)
1. `src/config.py`
   - Runtime defaults/path resolution.
   - Policy load + validation/normalization schema.
2. `src/policy_engine.py`
   - Policy evaluation logic and command/path checks.
3. `src/executor.py`
   - Subprocess execution wrapper with timeout/output controls.
4. `src/approvals.py`
   - Approval token lifecycle, consume/deny logic, HMAC checks, DB state.
5. `src/audit.py`
   - Structured log append helpers.
6. `src/backup.py`
   - Backup create/list/retention primitives.
7. `src/script_sentinel.py`
   - Write-time artifact tracking and execute-time script continuity checks.
   - Own SQLite tables for sentinel artifacts/events/allowances.
8. `src/reports.py`
   - `activity.log` -> `reports.db` ingest, status/overview/event queries, pruning.
9. `src/telemetry.py`
   - Aggregate telemetry payload build/validate plus outbox spool generation/upload workers.
   - Service status state (`generator`/`uploader`) with hourly scheduler integration from Flask backend.
10. `src/runtime_context.py`
   - Session/connection context helpers.
11. `src/models.py`
   - Shared data models/types used by policy/runtime code.

### MCP + tool surface
1. `src/server.py`
   - FastMCP server registration for all AIRG tools.
2. `src/tools/command_tools.py`
   - `execute_command` tool implementation, sentinel hooks, logging.
3. `src/tools/file_tools.py`
   - `read_file`, `write_file`, `edit_file`, `delete_file`, `list_directory`.
4. `src/tools/restore_tools.py`
   - `restore_backup`.

### CLI + setup/service lifecycle
1. `src/airg_cli.py`
   - Entrypoints:
     - `airg`, `airg-init`, `airg-setup`, `airg-server`, `airg-ui`, `airg-up`, `airg-doctor`, `airg-service`.
   - Setup wizard, defaults, service install/start/stop/status, doctor checks.
   - Policy template and runtime env materialization.

### Agent integrations/hardening
1. `src/agent_configs.py`
   - Agent profile registry CRUD and generated config payloads.
2. `src/mcp_config_manager.py`
   - Apply/remove/merge MCP config in client config files.
3. `src/agent_configurator.py`
   - Apply/undo hardening options per agent type (Claude/Cursor/Codex/etc.).
4. `src/agent_posture.py`
   - Detect and score enforcement posture; powers GUI posture signals.
5. `src/airg_hook.py`
   - Hook executable for agent clients (especially Cursor/Claude flows).

### GUI backend (`src/ui/`)
1. `src/ui/backend_flask.py`
   - REST API routes:
     - policy load/validate/apply/revert/reset
     - approvals pending/history/approve/deny
     - reports status/overview/events/tops
     - agent settings/profile/posture/hardening endpoints
     - telemetry payload preview
   - Serves built SPA from `ui_v3/dist`.
2. `src/ui/service.py`
   - Policy IO, validation/apply snapshots, catalog merge, diff helpers.
3. `src/ui/catalog.json`
   - Command/tab catalog metadata used by policy UI.

### GUI frontend (`ui_v3/`)
1. `ui_v3/src/App.jsx`
   - Main app: navigation, policy editor, approvals, reports, settings/agents.
   - Contains telemetry panel, feedback/contact UI, modal handling.
2. `ui_v3/src/components/SegControl.jsx`
   - Toggle segmented control.
3. `ui_v3/src/components/IconBtn.jsx`
   - Small icon button primitives.
4. `ui_v3/src/components/CollapsibleSection.jsx`
   - Collapsible section wrapper.
5. `ui_v3/src/main.jsx`, `ui_v3/src/index.css`
   - Frontend boot + styling.
6. `ui_v3/index.html`
   - Vite HTML template (title, root).
7. `ui_v3/dist/*`
   - Built artifacts served by Flask backend.

### Tests (`tests/`)
1. `tests/test_attacker_suite.py`
   - adversarial scenarios and policy bypass coverage.
2. `tests/test_command_substitution_policy.py`
   - substitution enforcement regression tests.
3. `tests/test_airg_hook.py`
   - hook behavior tests.
4. `tests/test_approvals_store.py`
   - approvals DB/token lifecycle.
5. `tests/test_reports_store.py`
   - reports ingest/query/prune behavior.
6. `tests/test_telemetry.py`
   - bucket/platform/sanitization/validation/day-gating tests.
7. `tests/test_agent_configs.py`
   - agent profile/config generation behavior.
8. `tests/test_agent_configurator.py`
   - hardening apply/undo behavior.
9. `tests/test_agent_posture.py`
   - posture signal/scoring behavior.
10. `tests/test_mcp_config_manager.py`
    - MCP config file apply/merge/remove behavior.
11. `tests/test_ui_policy_service.py`
    - UI service validation/apply snapshot behaviors.
12. `tests/test_setup_wizard.py`
    - setup helper behavior.
13. `tests/test_backup_config.py`, `tests/test_retry_clamp.py`
    - backup config + retry controls.
14. `tests/test_helpers.py`
    - shared fixtures/environment patch helpers.

### Top-level docs
1. `README.md` - operator overview, install/run, boundaries, privacy.
2. `CHANGELOG.md` - stable release history.
3. `STATUS.md` - current branch/release/runtime summary.
4. `docs/MANUAL.md` - runtime behavior reference.
5. `docs/ARCHITECTURE.md` - architecture/system design notes.
6. `docs/INSTALL.md` - install/setup details.
7. `docs/AGENT_MCP_CONFIGS.md` - per-agent MCP integration guides.
8. `docs/telemetry.md` - telemetry payload/behavior/privacy details.
9. `docs/CHANGELOG_DEV.md` - development-side changelog stream.

## 7) Current UX/Release Notes (recent)

Recent release track:
1. `2.3.1.dev2` (release candidate on `dev`):
   - Reports -> Log UI stability/usability fixes:
     - fixed-width truncation in log table to prevent long text from blowing out column boundaries
     - consistent `Show more` modal actions for non-empty `Event`, `Matched Rule`, and `Command / Path` values.
   - fixed path-policy regression that could crash `write_file`/`edit_file` with `NameError: name 'lower' is not defined` during blocked-extension checks.
2. `2.3.1.dev1`:
   - telemetry architecture rewrite:
     - hourly scheduler wakes and runs generator/uploader in parallel
     - generator writes outbox payloads (`<state_dir>/telemetry/telemetry-YYYY-MM-DD.json`)
     - uploader scans outbox and posts pending payloads
     - stand-down states for disabled/same-day/empty-outbox
   - telemetry service status + restart controls in Advanced Policy telemetry UI.
3. `2.3.0`:
   - includes pass 1-4 enforcement hardening across policy parsing, restore integrity, local API hardening, and executor/bootstrap controls
   - telemetry reliability follow-ups:
     - telemetry policy persistence now backfills missing defaults (`enabled`, `endpoint`) when writing `last_sent_date`
     - daily telemetry ticker added to UI backend with wake-resilient bounded sleep intervals
   - approvals UX hardening:
     - pending-card expanded sections persist across refresh
     - polling updates are no-op when payload is unchanged to avoid unnecessary rerenders.
4. `2.2.2`: telemetry bugfix release:
   - fixed Python runtime telemetry POST compatibility by setting explicit request headers
   - added telemetry failure diagnostics when `AIRG_DEBUG=1`
   - updated telemetry/status/context documentation.
5. `2.2.1`: documentation polish release (README refresh, install-reference fixes, changelog/status alignment).
6. `2.2.0`: telemetry system + payload preview + privacy/docs + UI wording updates.
7. `2.1.1`: reports/dashboard string truncation + network input focus stability + smarter delta wording.
8. `2.1.0`: major command substitution hardening + Cursor posture/hardening support.

## 8) Active Implementation Plan

Canonical internal implementation plan is maintained in:
1. `TODO_INTERNAL.md`

Current priority phases:
1. P0 core enforcement correctness:
   - resolved-path enforcement for blocked path protections
   - restore integrity + Script Sentinel continuity
   - recursive inner-payload command policy checks and parser fail-closed behavior
2. P1 local hardening:
   - localhost API auth + Host/CORS tightening
   - tightening-only agent overrides
   - deterministic `airg-server` command resolution
   - executor env hardening
3. P2 resilience follow-ups:
   - approval key failure mode hardening
   - telemetry endpoint policy tightening
   - side-effect GET cleanup
   - audit tamper-evidence improvements
   - broader default sensitive-path protections

Implementation progress:
1. Pass 1 completed (2026-04-21):
   - `blocked.paths` command checks moved to resolved-path candidate matching.
   - runtime protected-path denylist expanded and made non-overridable for command checks.
   - recursive eval payload extraction added for `-c`/`--command`/`-e`/`--eval` contexts.
   - policy now fails closed on command parse failures.
   - workspace containment now fails closed on tokenization failures in enforce mode.
   - regression tests added/updated in `tests/test_command_substitution_policy.py` and `tests/test_attacker_suite.py`.
2. Pass 2 completed (2026-04-21):
   - backup manifest entries are now signed (`manifest_sig`) with approval-key material.
   - restore apply verifies manifest signatures and requires file hashes.
   - restore confirmation tokens are session-bound.
   - restored files are re-scanned via Script Sentinel tagging path.
   - regression tests added in `tests/test_attacker_suite.py` and `tests/test_approvals_store.py`.
3. Pass 3 completed (2026-04-21):
   - UI backend request guardrails added: strict localhost host checks and tighter same-origin CORS behavior.
   - mutating API routes now require API token auth or exact same-origin local Origin/Referer checks.
   - agent override validation now rejects less-restrictive overlay policies for key enforcement sections.
   - regression tests added in `tests/test_ui_policy_service.py` for tightening-only override validation.
4. Pass 4 completed (2026-04-21):
   - deterministic server launch command generation now uses `sys.executable -m airg_cli server` by default across config emitters.
   - PATH-based `airg-server` fallback resolution removed from generated config paths.
   - executor subprocess env model hardened to an allowlist with explicit dangerous-variable drops.
   - dangerous env-assignment prefixes are blocked in policy checks.
   - regression tests added in `tests/test_agent_configs.py`, `tests/test_executor.py`, and `tests/test_attacker_suite.py`.

## 9) Commands For New Agent Session

Suggested first commands:
1. `git status --short`
2. `python3 -m unittest`
3. `npm --prefix ui_v3 run build`

If touching runtime policy/tool logic, run relevant tests:
1. `python3 -m unittest tests.test_command_substitution_policy`
2. `python3 -m unittest tests.test_approvals_store tests.test_reports_store tests.test_telemetry`
3. `python3 -m unittest tests.test_agent_configurator tests.test_agent_posture tests.test_mcp_config_manager`

## 10) Common Pitfalls

1. Changing policy schema in `config.py` requires updating:
   - `policy.json` template/defaults
   - setup template in `airg_cli.py`
   - test fixtures (`tests/test_helpers.py`, UI service tests, others).
2. UI source changes require rebuilding `ui_v3/dist` if repo tracks built assets.
3. Agents/settings changes often span:
   - `agent_configs.py`
   - `agent_configurator.py`
   - `agent_posture.py`
   - `mcp_config_manager.py`
   - `ui_v3/src/App.jsx`
4. Keep changelog/status/manual consistent before release PRs.

## 11) Hardening Baseline Checklist (Current AIRG)

Recommended baseline:
1. Route all file/shell actions through AIRG MCP tools; disable risky native tools where the client supports it.
2. Enable/verify hook enforcement for supported clients (`preToolUse`, `beforeShellExecution`, `beforeMCPExecution`; optional `beforeReadFile`).
3. Use strict network settings for sensitive environments:
   - `network.enforcement_mode = "enforce"`
   - `network.block_unknown_domains = true`
   - explicit `network.allowed_domains`.
4. Enable shell containment enforcement:
   - `execution.shell_workspace_containment.mode = "enforce"`
   - keep `exempt_commands` minimal.
5. Keep Script Sentinel enabled; use `match_original` or `block` depending on risk tolerance.
6. Keep backup protections enabled and use `restore_backup` workflow for recovery.
7. Use unique `AIRG_AGENT_ID` per agent profile/workspace for better attribution and policy overlay isolation.
8. Validate posture and bypass coverage regularly via attacker/hook/substitution tests.

## 12) Intended Use Of This File

Use this file as a quick handoff entrypoint when:
1. Context window is reset/lost.
2. A new agent session starts.
3. A different model/agent takes over.

It is intentionally local + gitignored (`AGENT_CONTEXT.md`) so it can be edited freely without affecting repository history.
