# CHANGELOG_DEV

Note: older entries in this file are preserved as historical development records and may reference superseded setup flows or intermediate branch/release states.

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
