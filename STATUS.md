# STATUS

Last updated: 2026-05-06 (v2.3.1.dev4)

## Branches
1. Active integration branch: `dev`
2. Stable release branch: `main`

## Release state
1. Current release candidate on `dev`: `v2.3.1.dev4`
2. Latest stable release on `main`: `v2.2.2`
3. Package version in source: `2.3.1.dev4`
4. Stable release notes: `CHANGELOG.md`
5. Development history: `docs/CHANGELOG_DEV.md`

## Runtime snapshot
1. AIRG is a local STDIO MCP policy enforcement server with Web GUI included.
2. Active policy tiers are `blocked`, `requires_confirmation`, and `allowed`.
3. Script Sentinel is active in runtime policy model (write-time detection, execute-time enforcement continuity).
4. Per-agent overrides are supported through `policy.agent_overrides` keyed by `AIRG_AGENT_ID`.
5. Reports ingest from `activity.log` into `reports.db` for dashboard and log views.
6. Setup flow is `airg-setup` plus manual agent onboarding in `Settings -> Agents`.
7. Optional anonymous telemetry now uses an hourly scheduler with parallel generator/uploader workers, outbox spool files, and policy-driven stand-down behavior.
8. Telemetry UI includes payload preview, service status modal, warning banner for stale/failed workers, and restart action.
9. Reports -> Log table now enforces fixed-width truncation for long event/rule/command/path values and provides `Show more` expansion to keep layouts stable across resolutions.
10. Codex integration now supports scope-aware MCP/hardening artifacts, project-only Codex tool approvals, and optional workspace-trust bootstrap for project `.codex/` layers.

## v2.1 highlights
1. Security hardening for command substitution parsing in `execute_command` now covers nested `$(...)`, backticks, and process substitution contexts for network/tier enforcement.
2. Script Sentinel execute-time scanning now evaluates substitution contexts to preserve policy-intent continuity in indirect execution patterns.
3. Cursor hardening support added in `Settings -> Agents`:
   - hook enforcement controls
   - optional read hooks
   - fail-closed behavior
   - sandbox hardening
   - optional `permissions.json` and `.cursorignore` sync.
4. Cursor posture signals/scoring expanded and Cursor scope handling fixed (`Project`/`Global` fallback).
5. Dashboard/UI fixes shipped in `v2.1.1`:
   - truncation for oversized command/path/rule rows
   - stable Network-domain input focus
   - improved delta messaging for long inactivity periods.

## Known boundary
1. AIRG enforces only operations routed through AIRG MCP tools.
2. Native client tools outside MCP can bypass AIRG policy unless client hardening is applied.
3. In STDIO deployments, identity separation is effectively the MCP profile tuple (`AIRG_AGENT_ID` + workspace), not per-instance authenticated identity.

## Next focus areas
1. Agent hardening quality and posture signal accuracy across supported clients.
2. Continued documentation/runtime parity as v2.x features evolve.
3. Future research: authenticated HTTP/SSE transport for stronger per-instance identity.
