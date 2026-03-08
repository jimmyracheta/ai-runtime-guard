# Changelog

All notable changes to this project are documented in this file.

## [1.5.0] - 2026-03-08

### Added
- Policy -> Agent Overrides GUI editor with section-based controls and baseline info views.
- Agent profile bootstrap during setup/service install:
  - default profile creation
  - generated MCP config artifacts in runtime state.
- Setup matrix extensions:
  - `airg-setup --silent`
  - auto-generated fallback `agent_id` values (`unknown-<random>`).
- PyPI publish workflow with Trusted Publishing support:
  - manual TestPyPI/PyPI publish targets
  - stable-tag (`vX.Y.Z`) publish path.

### Changed
- Per-agent override persistence now stores diff-style overlay values rather than baseline-copied section payloads.
- Generated MCP server command resolution is now deterministic across macOS/Linux install variants:
  - explicit `AIRG_SERVER_COMMAND` support (including args parsing)
  - safe fallback to `<python> -m airg_cli server` when needed.
- Settings -> Agents flow improved:
  - stricter `agent_id` validation
  - optional create-on-save for missing workspaces
  - runtime reconfigure path for default profile updates
  - copy-assist modal for CLI/JSON in restricted clipboard contexts.
- Package validation now includes `twine check dist/*` in CI/release flow.
- Packaged runtime defaults and diagnostics are now aligned:
  - workspace fallback defaults to `~/airg-workspace` when unset
  - UI dist discovery supports installed-package paths.

### Fixed
- Multiple MCP config generation failures caused by unresolved bare `airg-server` command outputs.
- Runtime env propagation gaps where UI/service-generated profile artifacts could miss server-command context.
- Agent Overrides UI synchronization issues between baseline policy changes and section editor state.
- Packaged UI asset detection/serving in TestPyPI installs (no manual frontend build required in normal flow).

## [1.3.0] - 2026-03-03
### Added
- Connection-scoped identity/session context in runtime and logs:
  - `agent_id` and `agent_session_id` are now carried through tool execution and audit events.
  - reports filtering now includes session-level attribution.
- Approval UX context improvements:
  - approvals now display agent-aware request context in the GUI while keeping full command details expandable.
- Destructive wrapper policy coverage made explicit and transparent:
  - added default blocked command patterns for destructive wrapper forms (`find -delete`, `find -exec rm`, `xargs rm`, `xargs -0 rm`, `do rm`).
  - non-destructive `find` flows remain allowed by default.

### Changed
- Command safety behavior is now more policy-driven for destructive wrapper forms, with less hidden command-specific branching in runtime logic.
- Default backup root behavior now resolves to user runtime state paths (`<state_dir>/backups`) for installed/runtime mode.
- `airg-doctor` diagnostics now include resolved `backup_root` and warnings for unsafe backup-root placement (`site-packages` or project directory).

### Fixed
- Backup creation path fallback that could resolve under package directories in some installed-mode cases.
- Backup gating consistency:
  - `write_file` and `delete_file` now honor `audit.backup_enabled` consistently with `execute_command`.
- Documentation now tracks a known telemetry limitation where `execute_command` may undercount `affected_paths_count` for some shell-expanded/wrapper forms.

## [1.2.0] - 2026-03-01
### Added
- Reports subsystem with SQLite-backed indexing from `activity.log`:
  - new runtime module `src/reports.py`
  - retention and size-prune controls
  - report status/overview/events/confirmations endpoints.
- Reports UI with Dashboard and Log pages:
  - totals, trends, top commands/paths, blocked-by-rule
  - filterable/paginated event log
  - auto-refresh and manual refresh controls.
- Guided setup and UI service lifecycle improvements:
  - simplified interactive setup flow and aligned unattended flags (`--defaults`, `--yes`, `--gui`, `--no-gui`)
  - `airg-service` CLI for user-level service management (`install`, `start`, `stop`, `restart`, `status`, `uninstall`) on macOS (`launchd`) and Linux (`systemd`).
- Agent identity support via `AIRG_AGENT_ID` with safe fallback (`Unknown`) and propagation into runtime audit/reporting data.
- Advanced `execute_command` workspace containment control (`execution.shell_workspace_containment`) with `off`, `monitor`, and `enforce` modes.
- Sample MCP-only Claude skill document (`docs/mcp-only.md`) for deployments that require strict MCP-tool-only operation.

### Changed
- Source layout refactor to `src/` package structure while preserving CLI/tool behavior.
- Runtime defaults and setup flow now consistently place policy/state artifacts in user runtime locations.
- UI build/discovery flow updated so prebuilt `ui_v3/dist` assets ship in repo/package for normal setup paths.
- Reports and advanced policy controls expanded in the GUI, including improved filtering and reset behavior.
- Documentation restructured and updated for v1.2 behavior, known boundaries, and setup expectations.

### Security
- Clarified and documented deployment requirement that AIRG enforces MCP-routed actions only; native agent tools (for example Bash/Glob/Read/Write/Edit) are outside AIRG policy control unless disabled by the operator.
- Hardened approval and runtime path handling through stricter path/env defaults and improved diagnostics in setup/doctor workflows.

## [1.1.1] - 2026-02-27
### Changed
- Network policy model clarified and hardened:
  - added `network.block_unknown_domains` to support optional default-deny for unknown domains.
  - blocklist precedence is explicit when a domain appears in both allowlist and blocklist.
  - runtime/domain behavior and limitations are now surfaced directly in the Network GUI.
- Removed non-enforced `network.max_payload_size_kb` from active policy/schema defaults to reduce operator confusion.
- Advanced Policy UI refinements:
  - section order and naming aligned to current runtime semantics.
  - backup-related audit controls merged into Backup & Restore.
  - removed fixed single-option controls (cumulative budget scope/counting mode) from GUI.
- Enforced `allowed.max_files_per_operation` in runtime for default-allowed multi-target command flows.

### Docs
- Updated architecture/manual/status/release-checklist docs to match current v1.1 baseline behavior and release flow.
- Release checklist now includes package build, UI build, and packaged CLI smoke checks.

## [1.1.0] - 2026-02-26
### Added
- Root `Dockerfile` for containerized MCP runtime startup (`airg-server`).
- Docker usage guide (`docs/DOCKER.md`) for listing/validation workflows.
- Linux validation summary (`docs/LINUX_VALIDATION_SUMMARY.md`) with Ubuntu 24.04 + Python 3.12 test outcomes.
- Optional packaging metadata for bundled `ui_v3/dist` artifacts.

### Changed
- Linux/source-install UI path discovery improved across `airg-ui`, `airg-doctor`, and Flask backend (`AIRG_UI_DIST_PATH` fallback behavior now probes multiple candidate paths).
- Installation and operator docs updated for current runtime model, known enforcement boundaries, and Linux notes.
- Documentation consolidated under `docs/` (root kept for `README.md`, `CHANGELOG.md`, `STATUS.md`).

### Fixed
- Linux/UI friction where frontend build detection could incorrectly point at package paths during source installs.
- Runtime artifact hygiene by expanding `.gitignore` for DB sidecars, rotated logs, and setup-generated output directories.

## [1.0.0] - 2026-02-25
### Added
- Guided setup wizard (`airg-setup` / `airg init --wizard`) with preflight checks, workspace/runtime path prompts, agent config generation, and automatic `airg-doctor` verification.
- Dedicated installation guide (`INSTALL.md`) with Basic (MCP-only) and Advanced (MCP+GUI) flows.
- Agent-specific MCP configuration guide (`AGENT_MCP_CONFIGS.md`) for Codex, Claude Desktop, and Cursor.
- Packaging baseline via `pyproject.toml` entrypoints (`airg-init`, `airg-server`, `airg-ui`, `airg-up`, `airg-doctor`).
- CI packaging workflow for tests + frontend build + Python package artifacts.
- Policy UI workflow enhancements:
  - shared `Reload / Validate / Apply` actions
  - `Revert Last Apply` and `Reset to Defaults` controls backed by policy snapshots.
  - dedicated `Paths` and `Extensions` policy tabs in the v3 control plane.

### Changed
- Documentation standardized around explicit AIRG env vars in MCP client configs for deterministic runtime paths.
- `airg-init` now sets `audit.backup_root` to a user-local runtime state path by default.
- Approval DB stability improved by closing SQLite connections reliably in polling paths.
- Simulation diagnostics are preserved for confirmation-gated commands (logs/responses include simulation context when relevant).

### Security
- Approval decisions remain out-of-band (GUI/API), preventing agent self-approval through MCP tools.
- Runtime warnings added when policy/approval state paths resolve inside workspace or project directory.
- Removed MCP `approve_command` surface so agents cannot self-approve in-band.
- Hardened approval store with DB health checks, permission enforcement, signed approval grants, and malformed-row/tamper rejection logging.
- Added explicit runtime-state path protections for `activity.log`, `approvals.db`, and HMAC key paths.

## [0.9.0]
### Added
- Core modular MCP runtime (`policy_engine`, `approvals`, `budget`, `backup`, `audit`, `executor`, tool modules).
- Default basic-protection policy profile (high-impact actions blocked, non-severe actions allowed).
- Web control plane foundation with approvals queue and policy editing.
- Durable approval store with signature checks and health checks.

### Notes
- Linux validation moved to v1.1 and completed there.
