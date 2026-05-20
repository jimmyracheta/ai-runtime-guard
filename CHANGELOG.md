# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- Default blocked path coverage now includes common cloud and developer credential stores: `.aws`, `.azure`, `.config/gcloud`, `.docker/config.json`, `.kube`, `.netrc`, `.npmrc`, and `.pypirc`.
- CI now runs a local documentation check for Markdown link drift and release-version references.

### Fixed
- Shell workspace containment now tracks `cd` across chained shell segments, so relative targets after an out-of-workspace directory change are evaluated against the changed working directory.

### Tests
- Added regression coverage for chained `cd ... && ... && rm relative-file` containment analysis.
- Added default-policy coverage for common credential-store blocked paths.

## [2.3.1] - 2026-05-06

### Changed
- Promoted the `2.3.1` development train to release and aligned package, status, hook, and documentation version markers.
- Telemetry architecture moved to an hourly scheduler that runs generator/uploader workers in parallel.
- Telemetry state now tracks `telemetry.last_payload_generated_date` and `telemetry.last_payload_uploaded_at` in policy.
- Codex integration is now scope-aware across MCP apply/remove, hardening, and posture detection.
- Codex hardening now uses dedicated scoped `rules/airg.rules` policy-mirror files instead of managing Codex `default.rules`.

### Added
- Telemetry outbox persistence in the runtime data directory (`<state_dir>/telemetry/telemetry-YYYY-MM-DD.json`).
- Telemetry service status and restart API endpoints:
  - `GET /telemetry/service-status`
  - `POST /telemetry/service-restart`
- Advanced Policy telemetry UI now includes:
  - service status modal (`status` + `last run` for generator/uploader)
  - warning banner for stale generator/failing uploader
  - restart button.
- Codex project-scope trust bootstrap in `~/.codex/config.toml` via `[projects."<workspace>"].trust_level = "trusted"` with explicit GUI confirmation.
- Codex project-only AIRG tool approval entries in `<workspace>/.codex/config.toml` for `[mcp_servers.ai-runtime-guard.tools.*]`.

### Fixed
- Telemetry no longer depends on UTC day-rollover wake logic only; hourly scheduler runs continue while backend is active and stand down when no action is needed.
- Upload retries now persist naturally through outbox files instead of dropping failed sends.
- Fixed `write_file`/`edit_file` tool crashes caused by `NameError: name 'lower' is not defined` in `check_path_policy` extension checks.
- Reports -> Log table now enforces fixed-width column truncation for long event/rule/command/path values so oversized text no longer expands row/cell boundaries.
- Reports -> Log now exposes consistent `Show more` actions for trimmed `Event`, `Matched Rule`, and `Command / Path` values via modal expansion.
- Codex text rewrite/apply flows are now idempotent across scoped `config.toml`, `AGENTS.md`, and `rules/airg.rules`.
- Settings -> Agents no longer shows false `Pending Changes` for hardening state when posture already matches the applied baseline.

### Security
- Codex project scope now keeps AIRG-managed tool approvals local to the trusted project `.codex` layer instead of writing them to user `~/.codex/config.toml`.

### Tests
- Added regression coverage for:
  - telemetry generator/uploader scheduler behavior
  - blocked-extension write/edit regression after path-policy fix
  - Codex project-trust apply/remove behavior
  - Codex project-scope hardening targets and idempotency
  - Codex project-scope posture detection
  - Codex project-only tool approval sections.

## [2.3.0] - 2026-04-24

### Changed
- Bumped package version to `2.3.0` and aligned status/context/telemetry/versioned documentation for release.

### Fixed
- Telemetry policy persistence now backfills missing `telemetry.enabled` and `telemetry.endpoint` defaults when updating `telemetry.last_sent_date`, preventing partial telemetry sections from remaining in policy JSON.
- Flask backend now starts a daily UTC-boundary telemetry ticker thread so long-lived UI service processes continue evaluating daily telemetry sends without requiring service restarts.
- Telemetry ticker now handles host sleep/wake better by checking day rollover in bounded sleep intervals (max 15 minutes), preventing missed post-wake daily checks when a long sleep spans the scheduled UTC boundary.
- GUI Approvals `Pending` cards now preserve expanded "Full command details" and "Affected paths" sections across the 3-second polling refresh instead of collapsing automatically.
- Approvals background refresh no longer forces unnecessary app-wide rerenders: pending/history state now updates only on actual payload changes, and history polling is scoped to when history is visible.

### Security
- Pass 1 hardening for command-policy correctness:
  - `blocked.paths` command evaluation now uses resolved path candidates instead of raw substring matching.
  - execute-command policy now includes a non-overridable runtime-state denylist for sensitive AIRG artifacts (policy, approvals, reports, and logs).
  - shell/eval inner payload contexts (`-c`, `--command`, `-e`, `--eval`) are recursively surfaced for policy matching.
  - policy evaluation now fails closed when shell parsing/tokenization fails.
  - shell workspace containment in `enforce` mode now fails closed on segment tokenization errors.
- Pass 2 hardening for restore integrity:
  - backup manifests now include per-entry HMAC signatures (`manifest_sig`) derived from AIRG approval key material.
  - restore flow now verifies manifest signatures and requires per-file `sha256` hashes before applying file restores.
  - restore confirmation tokens are now session-bound and rejected on session mismatch.
  - restored file content is re-scanned through Script Sentinel tagging path after restore apply.
- Pass 3 localhost control-plane and override hardening:
  - added request guardrails for UI backend:
    - strict localhost host validation
  - mutating API calls require either API token (`X-AIRG-UI-TOKEN`/Bearer) or exact same-origin local Origin/Referer checks
  - tightened CORS to exact host-matching local origins
  - agent override validation now rejects less-restrictive `blocked`, `requires_confirmation`, `network`, and `execution.shell_workspace_containment` overlays.
- Pass 4 runtime execution/bootstrap hardening:
  - deterministic AIRG server launch command generation now defaults to `sys.executable -m airg_cli server` across CLI/config generators.
  - removed PATH-based `airg-server` auto-resolution fallbacks from generated config paths.
  - subprocess env sanitization switched to an allowlist model with explicit drops for dangerous loader/interpreter/shell-injection environment variables.
  - dangerous env-assignment prefixes in commands (for example `LD_PRELOAD=...`) are now blocked by policy tier checks.

### Tests
- Added pass-1 regression coverage:
  - shell `-c` payload blocking end-to-end.
  - parse-failure fail-closed behavior.
  - runtime path block behavior under quote-splitting patterns.
- Added pass-2 regression coverage:
  - restore rejects unsigned manifest entries.
  - backup manifest entries include signatures.
  - restore confirmation token session binding.
- Added pass-3 regression coverage:
  - policy validation rejects less-restrictive agent overrides.
  - policy validation accepts tightening-only agent overrides.
- Added pass-4 regression coverage:
  - generated agent config server command uses deterministic Python module entrypoint.
  - executor env allowlist/dangerous variable drops.
  - dangerous env-assignment prefix blocking in command policy.

## [2.2.2] - 2026-04-21

### Fixed
- Telemetry delivery reliability: added explicit HTTP request headers (`User-Agent`, `Accept`) for telemetry POSTs so endpoint-side filtering does not reject valid AIRG payloads sent by Python `urllib`.
- Telemetry diagnostics: when `AIRG_DEBUG=1`, telemetry send failures and non-`204` responses now emit debug traces to aid runtime troubleshooting.

### Documentation
- Updated telemetry docs to clarify runtime source of truth and troubleshooting path (policy state, `last_sent_date`, and runtime/service alignment checks).
- Updated local agent handoff context and status docs for the `2.2.2` bugfix release.

## [2.2.1] - 2026-04-20

### Changed
- README refreshed with clearer quick start, scope/boundary framing, and linked references to install/docs/changelog.
- Markdown code fences in README examples were corrected so command/output snippets render properly.
- Install reference polish in `docs/INSTALL.md`:
  - corrected source-clone path (`cd runtime-guard`)
  - clarified that Git is required for source-clone installs only.

## [2.2.0] - 2026-04-16

### Added
- Optional daily anonymous telemetry flow with setup opt-in prompt (default Yes), strict local payload validation, and non-blocking one-shot delivery.
- Telemetry payload preview endpoint and GUI `See Payload` action in Policy -> Advanced.
- Telemetry documentation: [`docs/telemetry.md`](docs/telemetry.md), plus README/MANUAL privacy links.

### Changed
- Policy telemetry schema now tracks `enabled`, `endpoint`, and `last_sent_date`.
- Advanced policy telemetry controls simplified to enable/disable + payload preview.
- Telemetry runtime control is now policy/GUI-driven only:
  - removed `AIRG_TELEMETRY_OPTOUT` and `AIRG_TELEMETRY_ENDPOINT` override paths
  - `telemetry.enabled` and `telemetry.endpoint` in policy are the source of truth.
- Sidebar/contact UX refinements:
  - removed legacy "Policy Control Plane" wording
  - removed hash display from header/topbar
  - Contact opens in-app popup with `admin@runtime-guard.ai`.

## [2.1.1] - 2026-04-15

### Fixed
- Reports dashboard top lists now truncate long command/path/rule strings so oversized entries do not consume full card width.
- Policy -> Network domain input focus stability improved by using stable component instances; periodic refresh/re-render no longer drops cursor focus while typing.
- Reports dashboard event-card deltas now handle inactivity gaps with clearer messaging (for example first activity after a quiet week) instead of always showing `vs yesterday`.

## [2.1.0] - 2026-04-15

### Security
- Fixed `execute_command` policy parsing to recursively inspect command-substitution contexts before shell execution:
  - `$(...)`
  - backticks `` `...` ``
  - process substitution `<(...)` and `>(...)`
  - nested substitution forms.
- Network policy enforcement now applies to inner commands discovered inside substitution contexts, not only top-level tokens.
- Command-tier matching (`blocked` / `requires_confirmation` / `allowed`) now applies to inner substitution commands as well.
- Script Sentinel execute-time command-context scanning now evaluates substitution contexts to preserve policy-intent continuity.

### Added
- Regression coverage for substitution bypass prevention in `tests/test_command_substitution_policy.py`, including:
  - direct command and `&&` baseline behavior
  - subshell and backtick substitution
  - process substitution
  - nested substitution
  - substitution in variable assignment
  - mixed top-level + substitution command chains
  - clean command and clean substitution allow cases.
- Cursor posture hardening support in Settings -> Agents, including:
  - strict hook enforcement controls (`preToolUse`, `beforeShellExecution`, `beforeMCPExecution`)
  - optional read-path enforcement (`beforeReadFile`)
  - fail-closed hook gate controls for security-critical paths
  - sandbox hardening controls mapped to `.cursor/sandbox.json`
  - optional `.cursorignore` synchronization from AIRG policy
  - optional `permissions.json` management for MCP allowlist and terminal allowlist lock.
- Cursor-specific posture signals and scoring in `agent_posture` for standard/strict/maximum posture classification.
- Cursor hook runtime support in `airg_hook` for Cursor-native events:
  - `beforeShellExecution`
  - `beforeMCPExecution`
  - `beforeReadFile`.

### Fixed
- Cursor scope selector fallback in the GUI now correctly shows `Project`/`Global` when backend scope payloads are legacy/invalid (`Default`-only).

## [2.0.0] - 2026-03-23

### Added
- Script Sentinel end-to-end workflow:
  - write-time content tagging on `write_file` and `edit_file`
  - execute-time policy-intent continuity checks in `execute_command`
  - modes for `match_original`, `block`, and `requires_confirmation`
  - context scanning modes for executable context and optional mention-only audit signals.
- New MCP `edit_file` tool for deterministic in-place text edits with backup and Script Sentinel integration.
- Expanded Settings -> Agents orchestration:
  - profile-based MCP apply/remove flows
  - posture and enforcement controls for supported agent types
  - Codex and Claude config handling improvements.

### Changed
- Policy model simplified to active tiers: `blocked`, `requires_confirmation`, `allowed`.
- Runtime/tooling/docs aligned around GUI-first setup and manual agent onboarding.
- Logging and reports surfaces aligned to include current enforcement and hook-related events in `activity.log` and `reports.db`.
- MCP config generation simplified to per-agent essentials:
  - `AIRG_AGENT_ID`
  - `AIRG_WORKSPACE`.

### Removed
- Active simulation-tier enforcement paths from runtime policy decisions.
- Active cumulative-budget enforcement logic and related GUI controls.
- Legacy/stale setup and documentation artifacts no longer matching v2 runtime behavior.

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
