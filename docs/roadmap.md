# Roadmap

This roadmap tracks next milestones after `v1.2.0`, aligned to current implementation status.

## Current reality snapshot
1. Reporting foundation is implemented (`reports.db`, ingest pipeline, reports API, dashboard/log UI).
2. Connection-scoped identity/session fields are implemented in runtime logs/reports (`agent_id`, `agent_session_id`).
3. Per-agent policy overlays and GUI authoring are implemented; next focus is packaging hardening and container/transport expansion.

## Guiding principles
1. Keep one core enforcement engine across all deployment channels.
2. Preserve behavior parity for policy decisions, approvals, backup, audit, and reports.
3. Complete per-agent policy isolation before SSE and multi-client transport expansion.

## v1.3 baseline - Identity/session completion (implemented)
Goal: complete connection-scoped identity/session model and remove process-global assumptions.

### Scope
1. Add connection-scoped identity fields:
   - `agent_id` (configured identity)
   - `agent_session_id` (connection/session-scoped id)
2. Refactor approval/budget/session state to avoid cross-connection leakage.
3. Ensure reports dimensions support reliable per-agent slicing.
4. Add migration path for single-policy installs.

### Acceptance gates
1. Two concurrent clients are distinguishable in logs/reports.
2. Approval and budget state are isolated per connection/session by design.
3. Backward-compatible defaults remain valid for single-agent setups.

## v1.4 - Per-agent policy and reporting segmentation (implemented)
Goal: support agent-specific policy context while preserving simple default operation and setting the foundation for orchestrator workflows.

### Scope
1. Add per-agent policy context model:
   - optional per-agent policy overlay
   - keep workspace binding in MCP/env configuration (`AIRG_WORKSPACE`)
2. Resolve effective policy by `AIRG_AGENT_ID` in runtime decision flow.
3. Update reports UI/API for first-class per-agent filtering and views.
4. Add operator guidance for multi-agent deployments.
5. Keep single-policy behavior as default path for backward compatibility.

### Current implementation status
1. Implemented:
   - runtime effective-policy resolution by `AIRG_AGENT_ID`
   - optional `policy.agent_overrides.<agent_id>.policy` overlay support for enforcement sections
   - workspace source remains MCP/env (`AIRG_WORKSPACE`) by design
   - first-class policy-override authoring UX in GUI (section-based editor with baseline info and diff-style persistence)
   - multi-agent operator workflow improvements through Settings -> Agents MCP config generation and profile management.
2. Ongoing validation:
   - expanded concurrent-agent scenario testing and release hardening coverage.

### Acceptance gates
1. Per-agent policy boundaries are enforceable and test-covered.
2. Reports correctly separate activity for concurrent agents.
3. Single-agent mode remains low-friction and backward compatible.
4. Runtime model is ready for future agent-adapter/orchestrator commands without policy-engine redesign.

## v1.5 - Packaging hardening (PyPI)
Goal: make PyPI distribution the primary host installation channel and prepare one-command operator workflows.

### Scope
1. Finalize package metadata and release process.
2. Validate clean-install workflows from package artifacts across macOS and Linux.
3. Stabilize onboarding docs and release automation for package consumers.
4. Verify parity of `airg-setup`, `airg-service`, `airg-doctor`, and runtime path defaults in package installs.
5. Introduce CLI scaffolding for future orchestrator commands (for example `airg add <agent>`, `airg verify`) without enabling agent-specific adapters yet.

### Current implementation status
1. Implemented:
   - package metadata expansion (`keywords`, `classifiers`, project URLs)
   - CI packaging validation includes `twine check`
   - Trusted Publishing workflow for TestPyPI/PyPI
   - packaged UI dist path detection and runtime default normalization (`~/airg-workspace` fallback)
   - TestPyPI/Linux and TestPyPI/macOS installation + MCP smoke validation.
2. Remaining:
   - execute stable publish from `main` (`v1.5.0`) and final post-publish smoke checks on PyPI artifacts.

### Acceptance gates
1. Build/install smoke checks pass in clean environments.
2. Release checklist includes package validation and rollback notes.
3. Runtime paths for policy/state/log/reports/backups are deterministic in package installs.
4. CLI command model is stable for v2 agent-adapter expansion.

## v1.6 - Container channel and transport prep
Goal: deliver reliable container deployment and transport parity while preserving enforcement behavior.

### Scope
1. Finalize container runtime path model (`/workspace`, `/config`, `/state`).
2. Add deterministic container startup and persistence checks.
3. Prepare for optional SSE/HTTP transport only after per-agent policy isolation is proven.
4. Validate stdio/SSE transport parity for identity/session guarantees and policy decisions.
5. Do not introduce client-specific orchestration logic in this phase; keep runtime core transport-agnostic.

### Acceptance gates
1. Containerized behavior matches host behavior for same policy and inputs.
2. No runtime writes occur outside mounted state/config/workspace paths.
3. Connection isolation guarantees remain intact in multi-client scenarios.
4. Container and transport readiness does not change policy semantics between stdio and SSE.

## Deferred topics
1. Network payload-size enforcement.
2. Runtime activation of metadata-only budget override fields.
3. Advanced anomaly detection (mass-delete and high-risk pattern alerting).
4. Improve `execute_command` affected-path counting coverage for shell-expanded/wrapper command forms so `affected_paths_count` and budget telemetry reflect real path impact more accurately.
5. Agent-specific configuration adapters and hooks orchestration (`v2.0+`).
6. Agent process isolation (`airg run <agent> --user <restricted_user>`, `v2.1+`).
