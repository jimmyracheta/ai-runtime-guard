# Changelog

All notable changes to this project are documented in this file.

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
- Linux validation report (`docs/LINUX_VALIDATION.md`) with Ubuntu 24.04 + Python 3.12 test outcomes.
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
