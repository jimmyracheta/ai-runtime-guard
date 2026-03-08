# CHANGELOG_DEV

Note: older entries in this file are preserved as historical development records and may reference superseded setup flows or intermediate branch/release states.

## 2026-03-08 (v1.5.0 bump + documentation reconciliation)
- Bumped package version in `pyproject.toml` from `1.4.dev1` to `1.5.0` on `dev` for release preparation.
- Reconciled root/public changelog:
  - promoted `1.4-dev` snapshot entry to `1.5.0` release-track entry
  - included packaging/runtime hardening details validated in TestPyPI runs.
- Reconciled operator docs with latest runtime behavior:
  - `docs/INSTALL.md` now includes package-index install flow and TestPyPI install notes (`--extra-index-url` dependency resolution).
  - `docs/MANUAL.md` now reflects Settings profile/config generation behavior, diff-style agent overrides, and packaged UI/workspace path expectations.
  - `docs/ARCHITECTURE.md` now documents `agent_configs.py` role and runtime profile/artifact model.
  - `docs/roadmap.md` now marks v1.5 implementation progress and remaining stable-publish gate.
- Updated release-state wording in `README.md` and `STATUS.md` for current `v1.5.0` prep on `dev`.

## 2026-03-08 (PyPI packaging fixes: installed UI dist, workspace fallback, setup MCP consistency)
- Fixed installed-package UI dist discovery and packaging path handling:
  - added `sys.prefix/ui_v3/dist` lookup in CLI and Flask backend
  - added setuptools `data-files` entries so `ui_v3/dist` and assets are shipped with package installs.
- Fixed workspace fallback in packaged runtime:
  - when `AIRG_WORKSPACE` is unset, runtime now defaults to `~/airg-workspace` instead of module `site-packages`.
  - `airg-doctor` and overlap warnings now use workspace default logic aligned with setup/runtime expectations.
- Fixed setup output consistency for MCP config generation:
  - setup now pins `AIRG_AGENT_ID`/`AIRG_WORKSPACE` into process env before initial runtime init output
  - generated setup snippets now resolve deterministic server command/args and include `AIRG_SERVER_COMMAND` in env block.
- Hardened server command env resolution:
  - unresolved bare `airg-server` values now fall through to deterministic interpreter/module fallback instead of emitting fragile command values.

## 2026-03-08 (PyPI packaging hardening: metadata, CI validation, publish workflow)
- Expanded `pyproject.toml` package metadata for PyPI presentation:
  - added `keywords`
  - added classifiers for status/audience/topic/python versions
  - added project URLs (homepage/repository/issues/changelog).
- Updated CI package workflow (`ci-package.yml`):
  - install `twine`
  - run `twine check dist/*` after build.
- Added new publish workflow (`publish-pypi.yml`) with Trusted Publishing-compatible flow:
  - publish to TestPyPI via `workflow_dispatch` (`target=testpypi`)
  - publish to PyPI on stable tag push (`vX.Y.Z`) or manual dispatch (`target=pypi`)
  - artifact build and reuse between build/publish jobs.
- Updated release/docs runbooks:
  - `docs/RELEASE.md` now includes Trusted Publishing setup and TestPyPI dry-run process
  - `docs/RELEASE_CHECKLIST.md` now includes `twine check`, stable-tag format (`vX.Y.Z`), and optional TestPyPI preflight.
- Updated `docs/PACKAGING_TODO.md` to reflect completed automation and remaining operator-side Trusted Publisher verification.
- Minor README state wording refresh to remove stale integration train reference.

## 2026-03-08 (v1.4-dev tag prep, release notes, and docs reconciliation)
- Bumped package version to `1.4.dev0` to reflect integration-train status.
- Prepared `dev` for integration tag `v1.4-dev` while keeping latest public stable release at `1.3.0`.
- Updated root `CHANGELOG.md` with a dedicated `1.4-dev` snapshot section.
- Reconciled roadmap/status/release docs against completed v1.4 scope:
  - per-agent override runtime + GUI authoring is now tracked as implemented
  - v1.5 remains packaging hardening and publish readiness
  - v1.6 remains container/transport parity preparation.
- Updated release guidance to explicitly separate integration tags (`vX.Y-dev`) from public stable tags (`vX.Y.Z`).

## 2026-03-07 (v1.4 agent override editor: structured controls + diff-only persistence)
- Reworked the Policy -> Agent Overrides UI to remove raw JSON editing and expose section-specific controls.
- Added human-friendly section cards with:
  - `Inherit` / `Override` toggles per section
  - baseline info viewer (`Info`) for each section
  - expandable section editors with typed controls.
- Section editors now expose overridable controls per section:
  - `blocked`: commands, paths, extensions
  - `requires_confirmation`: commands, paths
  - `requires_simulation`: commands, bulk threshold, retries
  - `allowed`: limits + `paths_whitelist`
  - `network`: enforcement mode, unknown-domain toggle, commands, allow/block domain lists
  - `execution`: timeout/output limits + shell containment controls.
- Changed persistence behavior to store **only per-section diffs** in `agent_overrides.<agent_id>.policy` instead of full copied baseline section payloads.
- Kept baseline policy authoritative; effective per-agent policy remains baseline + overlay merge at runtime.
- Rebuilt `ui_v3/dist` for the updated Agent Overrides workflow.

## 2026-03-07 (agent config generation: guaranteed runnable server command)
- Updated generated agent MCP configs to avoid bare `airg-server` fallback when not resolvable from environment/PATH.
- New fallback now emits:
  - `command`: current Python interpreter path
  - `args`: `["-m", "airg_cli", "server"]`
- `AIRG_SERVER_COMMAND` now supports explicit command+args parsing, preserving operator overrides.
- Hardened explicit `AIRG_SERVER_COMMAND=airg-server` handling:
  - unresolved bare value no longer leaks into generated config
  - generator falls through to deterministic absolute command fallback.
- Replaced direct clipboard writes in GUI Settings agent actions with a copy-assist modal:
  - opens full CLI command/JSON in a modal
  - provides one-click `Select All` for manual copy in restricted browser contexts.

## 2026-03-07 (agent profile validation + workspace create-on-save)
- Added stricter `agent_id` validation in agent profile registry:
  - allowed: letters, numbers, `.`, `_`, `-`
  - length: 1-64 characters
  - spaces and other symbols rejected with clear error.
- Added workspace existence handling on profile save:
  - backend returns structured `workspace_missing` response when target folder does not exist
  - GUI prompts operator to confirm creating the missing workspace directory
  - on confirmation, save retries with `create_workspace=true` and proceeds with config generation.

## 2026-03-07 (runtime env server command propagation for service-backed UI)
- Added `AIRG_SERVER_COMMAND` to runtime env initialization and persisted service env file (`runtime.env`).
- Runtime now resolves a deterministic server command string using:
  - explicit env override
  - virtualenv `bin/airg-server`
  - sibling `airg-server` next to current Python
  - PATH `airg-server`
  - fallback: `<python> -m airg_cli server`.
- Updated setup/doctor MCP snippet output to emit resolved command/args and include `AIRG_SERVER_COMMAND` in env guidance.

## 2026-03-07 (default profile bootstrap in setup/service flows)
- Added automatic default agent profile bootstrap into runtime `mcp-configs` registry:
  - during `airg-setup`
  - during `airg-service install`.
- Default profile characteristics:
  - stable `profile_id`: `default-agent`
  - default name: `Default Agent`
  - workspace and `agent_id` sourced from setup/service inputs
  - generated config artifacts saved immediately.
- Normalized default runtime identity to `agent_id=default` in setup/service defaults and doctor output fallback.

## 2026-03-07 (settings phase 2: default runtime reconfigure + per-profile warnings)
- Added new backend API: `POST /settings/agents/reconfigure-runtime`
  - updates runtime env file for `default-agent` profile based on saved profile values
  - returns restart guidance (`restart_required`) for service-backed UI runtime.
- Settings save flow now triggers runtime reconfigure automatically for `default-agent`.
- Added per-profile Settings indicators:
  - `Unsaved changes for this profile`
  - `MCP reconfiguration required for this agent after profile changes` (for previously configured profiles changed and saved).

## 2026-03-07 (setup matrix + agent-id defaults)
- Added `airg-setup --silent` unattended mode (`--defaults --yes --gui`).
- Expanded setup agent type handling to include `claude_code`, `codex`, and `custom` options.
- If no `--agent-id` is provided, setup/service now auto-generate an ID like `unknown-<6 digits>`.
- Updated setup completion messaging:
  - GUI path points users to `Settings -> Agents` for MCP config copy
  - no-GUI path prints runtime MCP config artifact location.

## 2026-03-06 (agent config generation: explicit server command path)
- Updated generated MCP configs to prefer an explicit AIRG server command path when available.
- Resolution order: `AIRG_SERVER_COMMAND` env override, then `$VIRTUAL_ENV/bin/airg-server`, then `dirname(sys.executable)/airg-server`, fallback to `airg-server`.
- Claude Code add-json output and saved JSON now use the resolved command path, reducing PATH-related connection failures.

## 2026-03-06 (backup collision fix for confirmation retry commands)
- Fixed backup capture for shell commands that include workspace-root context tokens (for example `cd /workspace && rm ...`).
- `backup.backup_paths` now ignores workspace-root directory-only tokens so backup creation targets only actual destructive paths.
- Added dedupe for resolved backup targets within one operation to avoid duplicate path processing.
- Added regression test `test_backup_handles_workspace_root_and_file_targets_without_collision`.

## 2026-03-06 (v1.4 override-scope tightening)
- Removed workspace override behavior from `agent_overrides` runtime resolution.
  - Effective workspace now always comes from MCP/runtime env (`AIRG_WORKSPACE`).
- Restricted per-agent override scope to enforcement sections only:
  - `blocked`, `requires_confirmation`, `requires_simulation`, `allowed`, `network`, `execution`.
- Made non-enforcement/global sections unavailable for per-agent overrides:
  - `reports`, `audit`, `backup_access`, `restore`.
- Updated policy sample and operator docs to reflect supported/unsupported override sections.

## 2026-03-06 (v1.4 per-agent policy override runtime support)
- Added startup-time effective-policy resolution in `src/config.py`:
  - load and normalize base policy
  - resolve `policy.agent_overrides.<AIRG_AGENT_ID>`
  - apply deep-merge policy overlay for supported enforcement sections
  - re-normalize merged policy before runtime modules consume it.
- Added policy schema validation for `policy.agent_overrides`:
  - enforce object shape
  - enforce non-empty string keys
  - validate/normalize per-agent `policy` overlay fields.
- Updated policy templates:
  - root `policy.json` now includes documented `agent_overrides` example
  - fallback template in `airg_cli.py` now includes empty `agent_overrides`.
- Updated docs:
  - `docs/MANUAL.md` documents per-agent override behavior and merge semantics
  - `docs/ARCHITECTURE.md` documents effective-policy resolution flow
  - `docs/roadmap.md` marks v1.4 runtime override foundation as implemented with remaining UX/test work.

## 2026-03-06 (settings agents UI + generated MCP config workflow)
- Added agent-config generation module (`src/agent_configs.py`) to centralize:
  - agent profile validation (`agent_id`, workspace, type)
  - runtime-state registry storage
  - per-agent config generation and saved output metadata.
- Added new Settings API endpoints in Flask backend:
  - `GET /settings/agents`
  - `POST /settings/agents/upsert`
  - `POST /settings/agents/delete`
  - `POST /settings/agents/generate`
  - `GET /settings/agents/open-file`
- Added Settings UI rail tabs (`Agents`, `Advanced`) in `ui_v3`:
  - create/select/edit/delete agent profiles
  - generate config output
  - copy generated command to clipboard
  - save JSON + instruction file into runtime state `mcp-configs` folder
  - open/view saved configuration content
  - show `Last generated` timestamp and saved file paths.
- Current generation behavior:
  - Claude Code produces real `claude mcp add-json ...` command text plus JSON payload.
  - Other agent types currently produce placeholder command guidance with saved JSON blocks for manual insertion.
- Package metadata updated to include new top-level module:
  - `agent_configs` added to `pyproject.toml` `py-modules`.
- Rebuilt `ui_v3/dist` for the updated Settings/Agents UI flow.

## 2026-03-03 (v1.3 release prep and docs reconciliation)
- Bumped package version in `pyproject.toml` from `1.2-dev` to `1.3.0`.
- Added stable changelog entry for `v1.3.0` in root `CHANGELOG.md`.
- Reconciled public docs with latest runtime behavior and release state:
  - removed stale `1.2-dev` train references in release/status docs
  - aligned roadmap snapshot wording with current post-`v1.2` state
  - tracked known `affected_paths_count` undercount limitation in operator-facing docs.
- Updated agent MCP config documentation to include explicit `AIRG_REPORTS_DB_PATH` in recommended env blocks.

## 2026-03-03 (v1.3 approval UX + destructive command coverage)
- Improved approval workflow context in the UI:
  - pending approval records now store and return `agent_id`
  - Approvals panel now shows: `Agent <agent_id> needs approval for the following command: <truncated command>`
  - full command remains available in expandable details, with affected paths unchanged.
- Normalized destructive `find` / wrapper handling to policy-command rules:
  - removed hardcoded `find -delete` simulation branch from runtime logic
  - added explicit default blocked patterns for destructive wrappers: `find -delete`, `find -exec rm`, `xargs rm`, `xargs -0 rm`, `do rm`
  - kept non-destructive `find` allowed by default.
- Updated command catalog visibility for policy transparency:
  - added `find`, `find -delete`, `find -exec rm`, `xargs`, `xargs rm`, `xargs -0 rm`, `do rm` to Linux/macOS tabs.
- Added regression tests for policy-driven destructive wrapper blocking and non-destructive `find` allow behavior.
- Fixed backup-root defaults for installed/runtime mode:
  - default backup root now resolves to user runtime state (`<state_dir>/backups`) instead of module/package directory
  - removed unsafe fallback behavior that could place backups under `site-packages`.
- Aligned backup gating behavior:
  - `write_file` and `delete_file` now honor `audit.backup_enabled` consistently with `execute_command`.
- Expanded diagnostics:
  - `airg-doctor` now prints resolved `backup_root`
  - warns when `backup_root` is inside project directory or `site-packages`.
- Added regression tests for backup root defaults and backup-enabled gating behavior.
- Validation:
  - Python unit tests pass with `PYTHONPATH=src` (`41` tests).

## 2026-03-03 (v1.3 identity/session isolation - phase 1)
- Added runtime request/session context module (`src/runtime_context.py`) using context-local state to carry active MCP call identity.
- Tool execution paths now bind session identity per MCP call and reset automatically:
  - `execute_command`
  - `read_file` / `write_file` / `delete_file` / `list_directory`
  - `restore_backup`
- Approval, policy confirmation checks, retry/budget scope, and audit log entries now use active session context instead of only process-global startup UUID.
- Audit entries now include `agent_session_id` (with `session_id` kept as compatibility alias).
- Reports pipeline upgraded for session-aware analytics:
  - new `events.agent_session_id` column
  - migration/backfill for existing `reports.db` rows
  - filter support in backend/API and UI.
- Reports UI updates:
  - new `Agent Session` filter
  - Log table now shows session column for per-session attribution.
- Validation:
  - Python unit tests pass with `PYTHONPATH=src` (`32` tests).
  - `ui_v3` production build passes.

## 2026-03-01 (reports foundation: activity log -> reports db -> reports UI)
- Added reports runtime module (`src/reports.py`) with:
  - SQLite schema for `events`, `ingest_state`, and `meta`
  - incremental byte-offset ingestion from `activity.log`
  - rotation/truncation-aware offset recovery
  - policy-driven retention and size-prune logic.
- Added reports policy defaults/validation:
  - `reports.enabled`
  - `reports.ingest_poll_interval_seconds`
  - `reports.reconcile_interval_seconds`
  - `reports.retention_days`
  - `reports.max_db_size_mb`
  - `reports.prune_interval_seconds`.
- Added runtime env support for `AIRG_REPORTS_DB_PATH` in setup output, CLI env wiring, and doctor diagnostics.
- Added Flask reports API endpoints:
  - `/reports/status`
  - `/reports/overview`
  - `/reports/events`
  - `/reports/top-commands`
  - `/reports/top-paths`
  - `/reports/blocked-by-rule`
  - `/reports/confirmations`.
- Implemented Reports UI (replacing placeholder):
  - `Dashboard` tab with totals, 7-day trends, top commands/paths, blocked-by-rule
  - `Log` tab with paginated events and filters
  - auto-refresh and freshness indicator.
- Added tests for reports store sync/query/truncation handling (`tests/test_reports_store.py`).
- Updated docs (`docs/INSTALL.md`, `docs/MANUAL.md`, `docs/ARCHITECTURE.md`) for reports database/runtime behavior.

## 2026-03-01 (guided setup flow + GUI user service)
- Added GUI service management for local deployments:
  - macOS: user `launchd` agent (`com.ai-runtime-guard.ui`)
  - Linux/Ubuntu: user `systemd` unit (`airg-ui.service`)
  - new CLI entrypoint: `airg-service` with `install|start|stop|restart|status|uninstall`.
- Refactored setup UX to match guided install flow:
  - install confirmation prompt
  - workspace-first questions (existing vs create default sibling workspace)
  - runtime path defaults vs custom override prompts
  - optional GUI service enable prompt
  - final `airg-doctor` run.
- Added unattended setup flags aligned to the new flow:
  - `--defaults`
  - `--yes`
  - `--gui` / `--no-gui`.
- Removed setup flags that no longer match the agreed flow (`--quickstart`, wizard alias behavior, `--enable-ui`, additional-workspaces prompt path).
- Updated docs to reflect the new setup/service model (`README`, `docs/INSTALL.md`, `docs/MANUAL.md`).

## 2026-03-01 (ship prebuilt GUI assets in repo/package)
- Removed `ui_v3/dist` from `.gitignore` so release/source users receive prebuilt frontend assets by default.
- Added package-data inclusion for `ui_v3/dist` in `pyproject.toml` so installed packages can serve UI without local frontend rebuild.
- Updated docs to clarify normal `airg-ui` startup no longer requires `npm run build` unless frontend source has changed.

## 2026-02-28 (setup flag for automatic GUI build)
- Added `--gui` flag to setup flows (`airg-setup` and `airg init --wizard`) to build Web GUI assets automatically during installation.
- Setup now can run `npm install` and `npm run build` in `ui_v3` as part of one-command bootstrap, with explicit error output when npm/build prerequisites are missing or fail.
- Updated install/operator docs:
  - `docs/INSTALL.md` one-command setup example with `--gui`
  - `docs/MANUAL.md` packaged CLI behavior includes `airg-setup --gui`.

## 2026-02-28 (shell workspace containment for execute_command)
- Added advanced shell containment policy under `execution.shell_workspace_containment`:
  - `mode`: `off`, `monitor`, `enforce`
  - `exempt_commands`: optional command-level exemptions
  - `log_paths`: metadata toggle for path logging verbosity.
- Implemented runtime containment checks in `execute_command`:
  - best-effort parsing of shell segments, path-like arguments, `cd` targets, and redirection targets
  - resolves candidate paths and checks against workspace + whitelist roots
  - `monitor` mode logs warnings and offending paths without blocking
  - `enforce` mode blocks with matched rule `execution.shell_workspace_containment`.
- Exposed containment mode in GUI `Advanced Policy` page as:
  - `Attempt workspace shell command containment` (`off`/`monitor`/`enforce`).
- Updated policy defaults and templates:
  - `policy.json`
  - `src/config.py` validation/normalization defaults
  - `src/airg_cli.py` fallback template.
- Added tests for enforce/monitor containment behavior in `tests/test_attacker_suite.py` and updated policy fixtures.
- Updated docs:
  - `docs/MANUAL.md` advanced policy behavior and semantics
  - `docs/ARCHITECTURE.md` execute_command/containment notes.

## 2026-02-28 (linux friction hardening pass)
- Implemented runtime log path defaults to user state storage (`AIRG_LOG_PATH`, defaulting to platform state dir) instead of package/repo-local paths.
- Updated setup/runtime bootstrap to include `AIRG_LOG_PATH` in generated env blocks and MCP snippets.
- Fixed setup key-material bug: runtime init now creates non-empty approval HMAC key content instead of touching an empty file.
- Added approval self-heal for empty HMAC key files in `approvals.py`; empty key files are regenerated and warning-audited.
- Updated audit writer to create parent directories before appending entries to avoid first-write failures.
- Removed legacy UI static fallback from UI dist discovery in CLI and Flask backend; v3 build is now the deterministic target.
- Added `airg-ui --with-runtime-env` to initialize/print resolved runtime paths before launching UI backend.
- Expanded `airg-doctor` diagnostics:
  - prints resolved workspace/policy/db/key/log/ui paths
  - warns on empty HMAC key files
  - checks log file permissions and placement alongside existing runtime checks.
- Updated docs for Linux setup and MCP env guidance:
  - added `AIRG_LOG_PATH` to config examples
  - documented shell env scope pitfalls and UI startup troubleshooting
  - documented new UI startup mode (`--with-runtime-env`).
- Added validation and execution planning docs (later archived into internal historical notes).
- Added regression tests:
  - setup permissions test verifies non-empty HMAC key creation
  - approval store test verifies empty HMAC key regeneration behavior.

## 2026-02-27 (network policy precedence + default-deny toggle)
- Updated network enforcement logic to support explicit unknown-domain policy:
  - added `network.block_unknown_domains` (`false` by default)
  - when `false`, domains not in either list are allowed
  - when `true`, domains not in `allowed_domains` are blocked (default-deny)
- Kept list overlap precedence explicit: if a domain appears in both allowlist and blocklist, blocklist wins.
- Preserved enforcement-mode gating:
  - `off`: no blocking
  - `monitor`: diagnostics only
  - `enforce`: hard blocking
- Added GUI control on Network page (shown in `enforce` mode) for `block_unknown_domains`.
- Updated Network panel guidance text to match runtime precedence/behavior.
- Updated policy/docs/templates:
  - `policy.json` includes `network.block_unknown_domains`
  - `config.py` validates/normalizes the new boolean key
  - `airg_cli.py` default policy template includes the new key
  - test policy fixtures updated accordingly
  - `docs/MANUAL.md` network section now documents precedence, subdomain matching, and redirect-inspection limits.
- Removed `network.max_payload_size_kb` from active policy/schema defaults (`policy.json`, `config.py`, template/test fixtures) since payload-size enforcement is not implemented in runtime.
- Added a Network-page info panel in GUI with runtime domain-matching behavior notes (subdomains, redirects, short links, referral params).

## 2026-02-27 (allowed cap enforcement + advanced reset controls)
- Implemented runtime enforcement for `allowed.max_files_per_operation` in `execute_command` for default-allowed multi-target operations (resolved workspace/whitelist paths).
- Preserved tier separation intent:
  - simulation-tier wildcard handling remains governed by `requires_simulation` rules
  - confirmation-tier behavior remains approval-token based
  - allowed-tier safety caps are evaluated independently for non-simulated default-allowed flows.
- Added Advanced Policy UI controls for cumulative-budget reset:
  - `requires_simulation.cumulative_budget.reset.window_seconds`
  - `requires_simulation.cumulative_budget.reset.idle_reset_seconds`
  - plus helper text explaining age-out behavior for budget accounting.
- Removed non-actionable Advanced Policy controls:
  - removed `audit.log_level` from GUI (metadata-only today)
  - removed payload-size control from Advanced Policy (payload enforcement intentionally deferred; network remains domain-enforcement focused).
- Added policy comments clarifying metadata-only behavior:
  - `requires_simulation.cumulative_budget.audit.log_budget_state` / `audit.fields` are visibility metadata in current runtime.
  - `audit.log_level` is retained for future runtime log-level support.
- Updated `docs/MANUAL.md` to reflect:
  - enforced status of `allowed.max_files_per_operation`
  - reset controls now exposed in Advanced Policy
  - payload-size remains metadata (not enforced).
- Validation:
  - `python3 -m py_compile tools/command_tools.py`
  - `npm run build` in `ui_v3` passed.

## 2026-02-27 (policy UI parity pass: network + advanced settings split)
- Extended Policy tabs with `Network` and `Advanced Policy` pages.
- Commands page now focuses on tier selection only (basic/advanced radios) and removed per-command retry/budget fields to avoid implying unsupported runtime behavior.
- Added Commands-page guidance to configure global simulation/budget controls on `Advanced Policy`.
- Added Network page controls for:
  - `network.enforcement_mode` (`off`, `monitor`, `enforce`)
  - `network.commands` list management
  - domain whitelist + blocklist management with precedence guidance text.
- Added Advanced Policy page controls for global/session simulation and cumulative budget settings:
  - `requires_simulation.max_retries`, `bulk_file_threshold`
  - cumulative budget `enabled`, `scope`, `limits`
  - counting controls (`mode`, `dedupe_paths`, `include_noop_attempts`, `commands_included`).
- Updated docs (`docs/MANUAL.md`, `docs/INSTALL.md`) to reflect the new configuration layout and semantics.
- Verified frontend compiles successfully with `npm run build` in `ui_v3`.

## 2026-02-27 (v1.1 release flow + scope clarification)
- Updated release messaging/docs for `v1.1` readiness:
  - added `v1.1` section in `CHANGELOG.md`
  - aligned release references to `v1.0`/`v1.1` where needed
  - merged `dev` into `main` locally as part of release prep and tagged `v1.1`
- Added reusable release runbook: `docs/RELEASE_CHECKLIST.md` (prep, PR merge, tagging, verification, retag recovery).
- Added containerization artifacts/docs baseline:
  - root `Dockerfile`
  - `docs/DOCKER.md` with build/run/MCP Docker config examples
- Expanded `.gitignore` to exclude runtime/generated artifacts (`activity.log.*`, sqlite sidecars, `out/`) and local planning scratch (`containerization.md`).
- Clarified product scope across docs as accidental-safety-first (not full malicious-actor containment):
  - AIRG enforces MCP-routed actions only
  - native client shell/file tools outside MCP are out-of-scope for enforcement
  - core controls now explicitly include automatic backups before destructive/overwrite actions and comprehensive audit logging.

## 2026-02-26 (linux polish + packaging/doc hygiene)
- Added root `Dockerfile` for direct containerized MCP runtime (`airg-server`) and documented container usage in `docs/DOCKER.md`.
- Extended `.gitignore` for runtime sidecar artifacts (`*.db-wal`, `*.db-shm`, `*.db-journal`, `approvals.db-*`), rotated logs (`activity.log.*`), and setup output (`out/`).
- Completed docs reorganization by keeping only `README.md`, `CHANGELOG.md`, and `STATUS.md` at repo root and moving operational docs under `docs/`.
- Added/updated Linux validation documentation and reflected validation completion in status tracking.
- Improved Linux/source-install UI discovery in runtime code:
  - `airg-ui` now sets `AIRG_UI_DIST_PATH` automatically from discovered valid UI paths.
  - `airg-doctor` now checks multiple candidate UI build paths before warning.
  - Flask backend now resolves UI dist path from env, source-tree, and package-style locations.
- Added optional package-data wiring for `ui_v3/dist` when build artifacts are present at packaging time (`pyproject.toml`, `ui_v3/__init__.py`).
- Updated docs to clarify hard enforcement boundary: AIRG controls only MCP-routed actions; native client shell/file tools can bypass policy.
- Added Docker listing baseline docs intended to support MCP catalog validation workflows (including Glama-style checks).

## 2026-02-25 (packaging + paths UI iteration)
- Added Phase-1 packaging baseline via `pyproject.toml` with CLI entrypoints: `airg-init`, `airg-server`, `airg-ui`.
- Added `airg-up` one-command sidecar startup (UI backend + MCP server) for local operator convenience.
- Added `airg-doctor` environment diagnostics (policy readability, runtime path placement, file permissions, UI build presence, backend listen status).
- Made policy path configurable with `AIRG_POLICY_PATH` and aligned runtime init flow around explicit path/bootstrap behavior.
- Updated docs for packaging/public install flow, MCP config snippets, Python version requirements, and `AIRG_WORKSPACE` separation guidance.
- Added CI packaging workflow (`.github/workflows/ci-package.yml`) for tests, frontend build, and Python package build artifacts.
- Added dedicated `Paths` page to UI and moved runtime path display out of `Commands`.
- Added runtime path display as read-only with explicit instruction to change MCP config/env + restart.
- Added path policy CRUD in UI with absolute-path validation and tier mapping to `allowed.paths_whitelist`, `blocked.paths`, and `requires_confirmation.paths`.
- Standardized left rail card sizing and improved Paths UX labels/examples for operator clarity.

## 2026-02-25 (approval DB hardening)
- Added confirmation coverage in `policy.json` for `sqlite3`, `tail`, `grep`, `awk`, `sed`, `head`, and `less`.
- Added confirmation path guards for `activity.log` and `approvals.db` to increase visibility for sensitive command-path access.
- Added explicit blocked-path protection for runtime state files: `activity.log`, `approvals.db`, and `approvals.db.hmac.key`.
- Hardened approval store permissions in `approvals.py`: enforce `0600` on `approvals.db` at open/create and emit `mcp-server` audit warnings when DB or parent directory permissions are too open.
- Added warning when approval DB/HMAC key paths are configured inside workspace and should be moved out-of-workspace.
- Added startup approval-store health check (`integrity_check` + required schema); server now fails closed if the approval store is unhealthy.
- Added durable approval-grant integrity signatures (HMAC over `{session_id, command_hash, expires_at}`) and reject+purge tampered grants at consume time.
- Added explicit audit warnings for malformed approval-store rows (invalid `expires_at`, missing `session_id`, invalid `affected_paths` JSON/type).
- Added regression coverage for tampered approval signatures (`tests/test_approvals_store.py`) and protected runtime-file blocking for `read_file`/`write_file` (`tests/test_attacker_suite.py`).
- Restored simulation diagnostics for confirmation-gated commands so confirmation responses and `execute_command` logs carry simulation context when simulation would independently block.

## 2026-02-25 (approval surface hardening)
- Removed `approve_command` from the MCP tool surface (`server.py`, `tools/__init__.py`) so agents cannot self-approve via in-band tool calls.
- Updated confirmation block messaging in `execute_command` to require out-of-band human approval via control-plane GUI/API before retry.
- Kept approval logic in shared backend modules (`approvals.py`) and Flask endpoints (`/approvals/approve`, `/approvals/deny`) for operator-driven workflow continuity.
- Updated policy override metadata default/value from `approve_command` to `out_of_band_operator_approval` to match current architecture.
- Updated audit source attribution model docs and runtime behavior so server side-effects are `mcp-server` and operator decisions are `human-operator`.
- Updated test suite/docs to use out-of-band approval semantics instead of in-band `approve_command`.

## 2026-02-25 (control plane v3 foundation)
- Added shared SQLite approval store in `approvals.py` and migrated pending approval lifecycle to persistent records.
- Extended approval records with `requested_at`, `session_id`, `affected_paths`, and `expires_at` for UI/reporting use.
- Added Flask backend (`ui/backend_flask.py`) with policy and approvals REST endpoints for local UI integration.
- Added Vite + React + Tailwind frontend (`ui_v3/`) with three-layer navigation, command policy editor panel, and approvals queue panel.
- Added approvals store unit coverage (`tests/test_approvals_store.py`).
- Fixed approval continuity across processes by moving confirmation allow-list behavior from in-memory session state to durable SQLite session+command grants consumed by policy checks.

## 2026-02-24 (release freeze: approval separation flaw)
- Identified a release-blocking security gap during MVP gate testing: the same agent can request a confirmation-gated command and then call `approve_command` to approve itself.
- Declared merge freeze for `refactor` -> `main` until separation-of-duties is enforced for approvals.
- Added explicit unfreeze requirements in `STATUS.md`:
  - approvals must come from a separate trusted channel
  - runtime must enforce caller identity/role for approval
  - regression coverage must prove no self-approval path exists
- Added explicit approval-separation checkpoint requirements to `README.md` and test-plan docs.
- Added a Phase-1 local control-plane UI skeleton (`ui/`) for policy management (catalog tabs, tier toggles, validation, atomic apply, and change log), intended as the base for a future out-of-band approval interface.
- Added UI v2 improvements:
  - named tier columns and legend/status semantics
  - complete command visibility via `All Commands` + search
  - tooltip descriptions and applied-state badges next to command names
  - per-command retry/budget editor fields persisted to `policy.ui_overrides.commands.*` as non-enforced metadata for future runtime support

## 2026-02-24 (MVP lock-down prep)
- Added explicit merge/branch policy and pre-merge gate to `README.md` (unit tests + minimum manual integration prompts + Linux checkpoint).
- Replaced deprecated UTC datetime helpers with timezone-aware UTC usage across runtime modules.
- Expanded `policy.json` command-family coverage for lock-down without adding new runtime features:
  - blocked privilege-escalation commands (`sudo`, `su`, `doas`)
  - requires-confirmation coverage for version control, email, package-management, process-management, and exfiltration-oriented command families.
- Updated `ARCHITECTURE.md` with MVP command-coverage rationale and corrected network enforcement status.
- Reorganized `STATUS.md` into approved lock-down sequence (done vs pending), explicit minimum merge gate, and grouped post-MVP workstreams.
- Confirmed via 12-prompt MVP gate run that handshake controls now consistently gate risky command families (`rm`, `curl`, etc.) and that `restore_backup` dry-run now issues a restore token bound to the live apply step.

## 2026-02-24 (module split + test rewrite)
- Refactored runtime from monolithic `server.py` into focused modules (`config`, `policy_engine`, `approvals`, `budget`, `backup`, `audit`, `executor`, `tools/*`) with a thin `server.py` entrypoint.
- Preserved existing tool behavior and policy semantics while improving code isolation for future changes.
- Added modular regression tests in `tests/` (`test_attacker_suite.py`, `test_retry_clamp.py`, `test_helpers.py`) aligned to the new architecture.
- Replaced references to external test-workspace conventions with repo-local test execution guidance.
- Confirmed unittest discovery passes for refactored tests: `python3 -m unittest discover -s tests -p 'test_*.py'`.

## 2026-02-24 (documentation + repo analysis session)
- Audited all source and policy files to produce operator-facing docs tied to actual implementation behavior.
- Added `README.md` with concise project purpose, startup steps, and test workflow for disposable-workspace destructive scenarios.
- Added `ARCHITECTURE.md` covering tier precedence, retry enforcement, blast-radius simulation, audit schema, backup model, and tool/action mapping.
- Added `STATUS.md` as high-churn snapshot of branch, live workspace state, known issues, and immediate next tasks.
- Added `CHANGELOG_DEV.md` to standardize per-session change capture for faster handoff and historical context.
- Highlighted policy/implementation mismatch risk: `network` policy exists in config but has no runtime enforcement.
- Highlighted residual risk surface: shell execution uses `shell=True`; current mitigations reduce but do not eliminate parser-level attack complexity.
- Captured repo hygiene gap: runtime artifacts and local test data are present in workspace and should be managed explicitly.

## 2026-02-23 (recent hardening sequence from commit history)
- Enforced workspace and optional whitelist roots for file/path operations to reduce path-escape risk.
- Added session/workspace identifiers and centralized `build_log_entry` to make audit records consistent and correlatable.
- Added typed policy result (`PolicyResult`) with decision tier and matched rule metadata to improve explainability.
- Introduced command normalization and hash-based session whitelist so semantically identical commands share approval state.
- Refined destructive-operation handling: simulation checks, retry limits, and final-block behavior.
- Added/expanded file tools (`read_file`, `write_file`, `delete_file`, `list_directory`) with policy-first checks and backup support.
- Backed destructive operations with timestamped backups and manifests to improve recovery.
- Added attacker-focused tests and retry clamp checks to validate high-risk control paths.

## 2026-03-07 (first draft: Policy Agent Overrides editor)
- Added new Policy tab `Agent Overrides` in UI v3.
- Added agent selector and add-agent flow for override profiles sourced from `policy.agent_overrides` and known configured agents.
- Added section-level controls for supported override sections: `blocked`, `requires_confirmation`, `requires_simulation`, `allowed`, `network`, `execution`.
- Added per-section mode controls: `Inherit` (remove section override) and `Override` (seed from current baseline section).
- Added per-section JSON editor with explicit `Apply Section JSON` action and validation feedback.
- Added reset actions: reset all sections to inherited for selected agent, and delete selected agent override profile.
- Added override status badges (Inherited vs Overridden) and enabled-section counter.
- Added guardrail copy that workspace remains MCP/env managed (`AIRG_WORKSPACE`) and is not policy-overridable.
- Rebuilt `ui_v3/dist`.
