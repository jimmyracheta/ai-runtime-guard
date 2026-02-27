# STATUS

Last updated: 2026-02-27

## Current branch
- `dev` (tracking `origin/dev`)
- Operator behavior reference: `docs/MANUAL.md`

## What was just changed
- Added packaged runtime CLI for public onboarding:
  - `airg-init`, `airg-server`, `airg-ui`, `airg-up`, `airg-doctor`
  - `pyproject.toml` entrypoints and install workflow (`pip install .`, `uvx --from ...`)
- Added release automation baseline:
  - `.github/workflows/ci-package.yml` runs tests, UI build, and Python package build
  - CI artifacts include `python-dist` and `ui-dist`
- Added production UI serving path:
  - Flask backend now serves built frontend from `ui_v3/dist` at `/` (with build-missing hint if absent)
- Added dedicated `Paths` page in UI:
  - runtime paths shown read-only with explicit restart guidance
  - path CRUD with absolute-path validation and policy tier mapping (`allowed.paths_whitelist`, `blocked.paths`, `requires_confirmation.paths`)
  - basic/advanced toggle behavior aligned with Commands page
- Updated docs to clarify:
  - Python version requirements (macOS 3.9 friction and recommended 3.12+)
  - install folder vs runtime state vs `AIRG_WORKSPACE` model
  - multi-workspace allowance via `allowed.paths_whitelist`
- Re-categorized default `policy.json` to basic-protection mode:
  - kept severe/high-impact operations in `blocked`.
  - moved default behavior to allow for non-severe commands (cleared default `requires_confirmation` and `requires_simulation` command/path lists).
  - disabled default cumulative budget enforcement (`requires_simulation.cumulative_budget.enabled=false`).
  - retained advanced tier sections in policy for opt-in use by advanced users.
- Hardened approval-store access and integrity:
  - `approvals.db` permissions are now enforced to `0600` at open/create.
  - approval-store parent directory world-access is now checked and logged as an `mcp-server` warning if too open.
  - approval-store path/key path inside workspace now triggers explicit `mcp-server` warnings.
  - approval grants now include an HMAC signature over `{session_id, command_hash, expires_at}` and tampered rows are rejected/purged.
- Added explicit malformed/suspicious approval-store row warnings to `activity.log` (`source: mcp-server`).
- Expanded confirmation coverage in `policy.json` for local DB/log inspection commands (`sqlite3`, `tail`, `grep`, `awk`, `sed`, `head`, `less`) and path markers (`activity.log`, `approvals.db`).
- Added blocked-path runtime protection in policy for `activity.log`, `approvals.db`, and `approvals.db.hmac.key`.
- Added approval-store startup health checks (`integrity_check` + schema expectations); startup now fails closed if store health checks fail.
- Restored simulation diagnostics for confirmation-gated commands: confirmation responses and audit logs now include simulation context when simulation would have triggered (`bulk_file_threshold` or `wildcard_unresolved`).
- Split monolithic `server.py` into focused modules:
  - `config.py`, `models.py`, `audit.py`, `policy_engine.py`, `approvals.py`, `budget.py`, `backup.py`, `executor.py`
  - `tools/command_tools.py`, `tools/file_tools.py`, `tools/restore_tools.py`
- Kept `server.py` as a thin MCP entrypoint wiring tool registrations.
- Added an in-repo modular test suite under `tests/`:
  - `tests/test_attacker_suite.py`
  - `tests/test_retry_clamp.py`
  - `tests/test_helpers.py`
- Updated test execution to `python3 -m unittest discover -s tests -p 'test_*.py'`.
- Moved mutable runtime state ownership out of `config.py` into owning modules:
  - approvals/session state in `approvals.py`
  - retry counters in `policy_engine.py`
  - cumulative budget state in `budget.py`
- Updated policy conflict logging to use shared audit schema construction.
- Removed duplicate blast-radius simulation in `execute_command` by reusing one computed simulation result across policy and budget checks.
- Replaced deprecated UTC helpers with timezone-aware UTC across runtime modules (`datetime.now(datetime.UTC)` / `datetime.fromtimestamp(..., datetime.UTC)`).
- Expanded `policy.json` command-family coverage for lock-down:
  - privilege escalation moved to `blocked` (`sudo`, `su`, `doas`)
  - added confirmation coverage for version-control, email, package-management, process-management, and exfiltration-oriented command families
- Documented merge policy and explicit pre-merge gate in `README.md`.
- Added Phase-1 local policy control-plane skeleton under `ui/` (policy load/validate/apply, command-tier editor tabs, atomic writes, change logging).
- Upgraded UI to v2 policy editor ergonomics:
  - explicit tier column headers
  - `All Commands` view + search filter so non-catalog commands are visible
  - command tooltip descriptions and applied-state status badges (updated after Apply)
  - per-command retry/budget editor fields persisted as `policy.ui_overrides.commands.*`
- Added v3 control plane architecture:
  - Flask backend (`ui/backend_flask.py`) with REST endpoints for policy + approvals
  - Vite + React + Tailwind frontend (`ui_v3/`) with three-layer navigation and approvals panel
- Replaced in-memory-only pending approval storage with a shared SQLite approval store in `approvals.py` (configurable path via `AIRG_APPROVAL_DB_PATH`).
- Fixed cross-process approval retry bug: GUI-approved commands now create durable session+command grants in SQLite and MCP confirmation checks consume those grants (one-time), so retry after out-of-band approval works without reissuing a token.
- Improved Linux/source-install UI path discovery in `airg-ui`, `airg-doctor`, and Flask backend by probing env, source-tree, and package-style locations before warning.

## Current known issues
- MCP `approve_command` tool exposure has been removed; approvals are now out-of-band via GUI/API only.
- AIRG policy enforcement applies only to MCP tool calls; AI clients with native shell/file tools outside MCP can bypass AIRG controls if those tools are used.
- `execute_command` still uses `shell=True` for compatibility; this remains the largest residual command-parsing risk surface.
- Network policy currently focuses on domain-level command checks; payload-size and protocol-depth enforcement are not yet comprehensive.
- Backup target detection for shell commands remains heuristic (`PATH_TOKEN_RE` + existing-path checks) and can miss some shell expansion edge cases.
- Runtime constants are still imported by multiple modules at load time (`WORKSPACE_ROOT`, `MAX_RETRIES`, `LOG_PATH`, `BACKUP_DIR`), so dynamic runtime reconfiguration remains non-centralized and requires careful patching in tests.
- Linux validation checkpoint has been executed (Ubuntu 24.04, Python 3.12, 26/26 tests passing; see `docs/LINUX_VALIDATION.md`).
- Cumulative budget limits are currently high enough that practical day-to-day prompt runs may not trigger budget blocks.
- Budget reset is operation-triggered with idle-reset behavior; slow-drip patterns spaced beyond `idle_reset_seconds` can avoid cumulative growth (acceptable for accidental-safety-first scope, but weak for malicious pacing).
- UI per-command retry/budget overrides are stored as policy metadata for now; runtime does not yet enforce per-command override values.
- Legacy UI server (`ui/server.py`) remains in repo; v3 runtime path is Flask backend + `ui_v3` frontend.
- Budget override-on-approval path is temporarily disabled during durable approval migration and should be explicitly redesigned for cross-process semantics.

## Core use cases (from README; do not edit without explicit product decision)
1. Block destructive commands and sensitive path/extension access.
2. Simulation-gate wildcard destructive operations and enforce blast-radius thresholds.
3. Require explicit confirmation handshake for configured risky commands.
4. Create backups before destructive/overwrite actions and validate recovery.

## Lock-down sequence (completed)
1. Branch protection + merge policy: documented in `README.md`; GitHub branch protection settings still need to be applied operationally.
2. UTC deprecation fix: completed.
3. Policy coverage audit and lock-down (`policy.json` only): completed.
4. Linux validation checkpoint: completed and documented (`docs/LINUX_VALIDATION.md`).
5. Release to `main`: completed (tagged `v1.1`).

## Merge freeze status
- Current state: no active merge freeze for approval separation.
- Approval separation checkpoint status: complete in current scope (no MCP approval tool; out-of-band approval via GUI/API).
- Remaining hardening before broader deployment: strengthen caller identity/authorization for operator approval endpoints.

## Release gate status (`v1.1`)
Completed checkpoints:
1. Unit test gate: complete (`python3 -m unittest discover -s tests -p 'test_*.py'` passes).
2. Manual integration gate: complete (12+ prompts validated, including destructive block, confirmation, simulation, cumulative budget behavior, restore flow, and network-policy checks).
3. Approval separation gate: complete (initiating agent cannot self-approve via MCP tool surface; approvals are out-of-band).
4. `main` release completed and tagged as `v1.1`.

## Post-release validation (v1.1)
1. Linux gate: completed (unit suite + integration prompts executed on Linux with outcomes recorded).

## Post-v1.1 backlog (grouped workstreams)
### Execution hardening
1. Harden command execution model: reduce dependence on `shell=True` with structured execution where feasible, and isolate a tightly-scoped legacy shell mode for cases that need pipes/redirection.
2. Strengthen network control depth: keep domain controls and add deeper protocol/redirect-aware enforcement for stronger destination assurance.

### Policy/code parity
3. Complete policy-to-code parity for remaining unused/partial keys: `audit.log_level`, cumulative budget `counting.mode`, `reset.mode`, `reset_on_server_restart`, `audit.log_budget_state`, `audit.fields`, `on_exceed.decision_tier`, and override metadata fields (`token_ttl_seconds`, `audit_reason_required`, `allowed_roles`).
4. Unify backup policy behavior across tools: enforce `audit.backup_enabled` consistently for `write_file` and `delete_file`, and keep backup access controls consistent between file tools and `execute_command`.
5. Improve backup mutation detection: replace or augment regex path extraction with parser-aware target resolution for shell expansions (`find -exec`, `xargs`, loops, substitutions).
6. Improve restore ergonomics and safety: add restore conflict strategies (`overwrite/skip/fail`) and clearer per-file restore result reporting.

### Release readiness
7. Add CI checks for policy parity regressions and run `python3 -m unittest discover -s tests -p 'test_*.py'` as a required check.
8. Strengthen release hygiene: dependency vulnerability checks (`pip-audit`), reproducible constraints/lock workflow, and branch protection enforcement in GitHub.
9. Formalize long-term two-layer test strategy maintenance for `tests/` and `docs/tests.md` prompt suites.

### Policy validation
10. Validate expanded command sets against real agent workflows to tune false-positive rate (especially for `find`, `xargs`, `sed`, `perl` in simulation tier).
11. Add focused integration tests for multi-command shell constructs (`find -exec`, `xargs`, loops, substitutions) that are represented in policy but only partially modeled by current simulation logic.
13. Tune cumulative budget defaults for regular operations so anti-bypass behavior is practically testable in manual integration runs without requiring unrealistic operation volume.
14. Add approval separation regression coverage: verify that a command requester cannot approve the same command within the same agent/tool context.
15. Add UI operator warnings:
    - when any command is set to `requires_confirmation`, show a warning that approval increases security but may reduce agent autonomy and introduce operational friction;
    - when command budget configuration is present, show a warning that budget is cumulative and applies per configured session scope (not per-command enforcement unless runtime override support is implemented).
16. Post-v1.1 hardening review (after packaging + approval workflow rewrite): evaluate restart-based budget bypass risk where MCP process restarts reset in-memory session state, and decide whether to persist budget state across restarts and/or block agent-driven service restart controls.
17. UI guardrails for edit relevance: enable/disable retry and budget inputs based on selected tier so irrelevant fields are visually greyed out (for example `allowed` should not expose retry controls), with clear helper text for why fields are disabled.
18. Re-evaluate human-approval workflow value: assess whether `requires_confirmation` should be optional behind an explicit UI toggle, with clear warning that enabling it can reduce agent autonomy; compare against security posture achieved by `blocked` + `requires_simulation` only.
19. Add interpreter command-family confirmation coverage in `policy.json` to reduce string-construction evasion risk (`python`, `python3`, `perl`, `ruby`, `node`, `php`, `lua`, `osascript`, `bash`, `sh`, `zsh`).
20. Add wrapper pattern confirmation rules in `policy.json` for inline code execution surfaces (`python3 -c`, `python -c`, `perl -e`, `node -e`, `bash -c`, `sh -c`, `zsh -c`) and evaluate whether interpreter `-c/-e` should be force-confirmed in code regardless of payload text.
21. GUI v3 visual redesign follow-up: improve information architecture and visual separation between Basic and Advanced protection settings (clearer section containers, full-height zone styling, and reduced header/control ambiguity across collapsed/expanded states).
22. GUI command lifecycle follow-up: allow removing user-added commands from the policy catalog (`ui_catalog`) with safe guardrails (confirmation dialog, impact warning if tiered outside `allowed`, and optional soft-delete/undo).
