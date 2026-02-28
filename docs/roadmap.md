# Roadmap

This roadmap defines the next packaging and architecture milestones after v1.1.1.

## Guiding principles
1. Keep one core enforcement engine across all deployment channels.
2. Preserve behavior parity for policy decisions, approvals, backup, and audit.
3. Stage architectural refactors before distribution expansion to avoid duplicate migration work.

---

## v1.2 - Reporting Foundation

Goal: add operator-visible reporting without changing enforcement semantics.

### Scope
1. Add `reports.db` in runtime state path, sourced from incremental ingest of `activity.log`.
2. Build Reports GUI section:
- Dashboard tab (cards + rolling 7-day summaries)
- Log tab (auto-refresh feed with filters)
3. Add retention controls for reports storage:
- age-based retention
- size-based cap
- daily prune
4. Add doctor checks for reports DB health and ingest lag.

### Non-goals
1. No major-issue anomaly detection yet (mass-delete alarms deferred).
2. No per-agent isolation changes in v1.2.

### Acceptance gates
1. Reports ingest is stable under log append/rotation/truncation.
2. Dashboard and log views are consistent with source `activity.log`.
3. Unit/API/UI smoke tests pass.
4. `airg-doctor` validates reports DB creation and lag warnings.

---

## v1.3 - Agent Identity and Multi-Agent Policy Model

Goal: refactor runtime identity/session model to support per-agent attribution and policy isolation.

### Scope
1. Introduce explicit agent identity fields:
- `agent_id` (configured identity)
- `agent_session_id` (connection/session scoped)
- transport metadata where applicable
2. Refactor from process-global session assumptions to connection-scoped session context.
3. Support per-agent reporting views in Reports UI and API.
4. Design and implement per-agent policy configuration model:
- per-agent workspace binding
- per-agent policy context or policy overlay model
5. Add migration path for existing single-policy installs.

### Critical architecture requirement
1. Session/identity model must be connection-scoped before enabling multi-client transports (for example SSE), to prevent approval/budget/report cross-talk.

### Acceptance gates
1. Two concurrent agent clients can be distinguished in logs and reports.
2. Per-agent policy/workspace boundaries are enforceable and test-covered.
3. Approval and budget checks are isolated per agent session as designed.
4. Backward-compatibility path for single-agent installs is documented and validated.

---

## v1.4 and later - Distribution Expansion (PyPI + Container)

Goal: expand delivery channels after identity/session architecture stabilizes.

### v1.4 (recommended focus)
1. PyPI publishing hardening:
- packaging metadata finalization
- TestPyPI and clean-install validation
- release publish workflow
2. CLI onboarding polish:
- guided setup reliability
- non-interactive setup path for automation

### v1.5+ (recommended focus)
1. Container channel hardening:
- container path model (`/workspace`, `/config`, `/state`)
- deterministic entrypoint init and runtime checks
- stdio container deployment as first target
2. Optional transport expansion (SSE/HTTP) only after v1.3 session model is proven.

### Acceptance gates
1. Host/PyPI/Container channels preserve core policy behavior parity.
2. Release checklist includes per-channel smoke tests.
3. Docs provide client-specific MCP setup for each supported channel.

---

## Deferred topics
1. Network payload-size enforcement.
2. Runtime activation of metadata-only budget override fields.
3. Advanced anomaly detection (mass-delete or high-risk pattern alerting).

