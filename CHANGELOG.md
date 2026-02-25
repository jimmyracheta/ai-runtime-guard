# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] - Unreleased
### Added
- Guided setup wizard (`airg-setup` / `airg init --wizard`) with preflight checks, workspace/runtime path prompts, agent config generation, and automatic `airg-doctor` verification.
- Dedicated installation guide (`INSTALL.md`) with Basic (MCP-only) and Advanced (MCP+GUI) flows.
- Agent-specific MCP configuration guide (`AGENT_MCP_CONFIGS.md`) for Codex, Claude Desktop, and Cursor.
- Policy UI workflow enhancements:
  - shared `Reload / Validate / Apply` actions
  - `Revert Last Apply` and `Reset to Defaults` controls backed by policy snapshots.

### Changed
- Documentation standardized around explicit AIRG env vars in MCP client configs for deterministic runtime paths.
- `airg-init` now sets `audit.backup_root` to a user-local runtime state path by default.
- Approval DB stability improved by closing SQLite connections reliably in polling paths.

### Security
- Approval decisions remain out-of-band (GUI/API), preventing agent self-approval through MCP tools.
- Runtime warnings added when policy/approval state paths resolve inside workspace or project directory.

## [0.9.0]
### Added
- Core modular MCP runtime (`policy_engine`, `approvals`, `budget`, `backup`, `audit`, `executor`, tool modules).
- Default basic-protection policy profile (high-impact actions blocked, non-severe actions allowed).
- Web control plane foundation with approvals queue and policy editing.
- Durable approval store with signature checks and health checks.

### Notes
- Linux validation is tracked as post-merge v1.1 validation work.
