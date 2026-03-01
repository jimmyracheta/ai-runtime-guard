# Roadmap

This roadmap tracks next milestones after `v1.1.1`, aligned to current implementation status.

## Current reality snapshot
1. Reporting foundation is implemented (`reports.db`, ingest pipeline, reports API, dashboard/log UI).
2. Agent identity is partially implemented (`AIRG_AGENT_ID` in config and logs).
3. Remaining architecture work is connection-scoped identity/session and per-agent policy isolation.

## Guiding principles
1. Keep one core enforcement engine across all deployment channels.
2. Preserve behavior parity for policy decisions, approvals, backup, audit, and reports.
3. Complete identity/session refactor before SSE and multi-client transport expansion.

## v1.2.x - Identity model completion
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

## v1.3 - Per-agent policy and reporting segmentation
Goal: support agent-specific policy context while preserving simple default operation.

### Scope
1. Add per-agent policy context model:
   - workspace binding per agent
   - optional per-agent policy overlay
2. Update reports UI/API for first-class per-agent filtering and views.
3. Add operator guidance for multi-agent deployments.

### Acceptance gates
1. Per-agent policy boundaries are enforceable and test-covered.
2. Reports correctly separate activity for concurrent agents.
3. Single-agent mode remains low-friction and backward compatible.

## v1.4 - Packaging hardening (PyPI)
Goal: make PyPI distribution the primary host installation channel.

### Scope
1. Finalize package metadata and release process.
2. Validate clean-install workflows from TestPyPI and PyPI.
3. Stabilize onboarding docs and release automation for package consumers.

### Acceptance gates
1. Build/install smoke checks pass in clean environments.
2. Release checklist includes PyPI validation and rollback notes.

## v1.5 - Container channel and transport prep
Goal: deliver reliable container deployment while keeping behavior parity.

### Scope
1. Finalize container runtime path model (`/workspace`, `/config`, `/state`).
2. Add deterministic container startup and persistence checks.
3. Prepare for optional SSE/HTTP transport only after identity/session refactor is proven.

### Acceptance gates
1. Containerized behavior matches host behavior for same policy and inputs.
2. No runtime writes occur outside mounted state/config/workspace paths.
3. Connection isolation guarantees remain intact in multi-client scenarios.

## Deferred topics
1. Network payload-size enforcement.
2. Runtime activation of metadata-only budget override fields.
3. Advanced anomaly detection (mass-delete and high-risk pattern alerting).
