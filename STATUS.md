# STATUS

Last updated: 2026-03-01

## Current branch
1. Active integration branch: `dev`
2. Release branch: `main`

## Current release state
1. Latest stable release is published from `main`.
2. Ongoing development is on the `1.2-dev` train.
3. Stable release notes are in `CHANGELOG.md`.
4. In-progress development notes are in `docs/CHANGELOG_DEV.md`.

## Current runtime snapshot
1. Setup and runtime
   - `airg-setup` is the primary onboarding command.
   - `airg-service` manages optional GUI service lifecycle.
   - `airg-doctor` validates runtime paths, permissions, UI availability, and reports DB health.
2. Policy and enforcement
   - default profile is accidental-safety-first basic protection.
   - advanced controls include simulation, confirmation, cumulative budgets, network domain controls, and shell workspace containment.
3. Reporting
   - reports ingest from `activity.log` into `reports.db`.
   - UI includes dashboard and log tabs with filtering and drill-down behavior.
4. Approvals
   - approvals are out-of-band via GUI/API.
   - no in-band MCP self-approval tool is exposed.

## Active workstreams
1. Agent identity and connection-scoped session model completion.
2. Per-agent policy/report segmentation refinement.
3. Packaging channel hardening (PyPI and container).
4. Documentation simplification and public-release hygiene.

## Known boundary
1. AIRG enforces actions routed through AIRG MCP tools.
2. Native client tools outside MCP can bypass AIRG policy.
3. Disabling native shell/file tools in clients is a deployment requirement for strict boundary guarantees.

## Historical notes
Detailed historical change logs and completed gate history were moved to:
1. `CHANGELOG.md`
2. `docs/CHANGELOG_DEV.md`
