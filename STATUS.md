# STATUS

Last updated: 2026-02-24 (merge freeze: self-approval separation-of-duties flaw)

## Current branch
- `refactor` (tracking `origin/refactor`)
- Operator behavior reference: `MANUAL.md`

## What was just changed
- Split monolithic `server.py` into focused modules:
  - `config.py`, `models.py`, `audit.py`, `policy_engine.py`, `approvals.py`, `budget.py`, `backup.py`, `executor.py`
  - `tools/command_tools.py`, `tools/file_tools.py`, `tools/restore_tools.py`
- Kept `server.py` as a thin MCP entrypoint wiring tool registrations.
- Added a refactor-compatible in-repo test suite under `tests/`:
  - `tests/test_attacker_suite.py`
  - `tests/test_retry_clamp.py`
  - `tests/test_helpers.py`
- Updated test execution to `python3 -m unittest discover -s tests -p 'test_*.py'`.
- Moved mutable runtime state ownership out of `config.py` into owning modules:
  - approvals/session state in `approvals.py`
  - retry counters in `policy_engine.py`
  - cumulative budget state in `budget.py`
- Updated policy conflict logging to use shared audit schema construction.
- Removed duplicate blast-radius simulation in `execute_command` by reusing one computed simulation result across policy and budget checks.
- Replaced deprecated UTC helpers with timezone-aware UTC across runtime modules (`datetime.now(datetime.UTC)` / `datetime.fromtimestamp(..., datetime.UTC)`).
- Expanded `policy.json` command-family coverage for lock-down:
  - privilege escalation moved to `blocked` (`sudo`, `su`, `doas`)
  - added confirmation coverage for version-control, email, package-management, process-management, and exfiltration-oriented command families
- Documented merge policy and explicit pre-merge gate in `README.md`.
- Added Phase-1 local policy control-plane skeleton under `ui/` (policy load/validate/apply, command-tier editor tabs, atomic writes, change logging).
- Upgraded UI to v2 policy editor ergonomics:
  - explicit tier column headers
  - `All Commands` view + search filter so non-catalog commands are visible
  - command tooltip descriptions and applied-state status badges (updated after Apply)
  - per-command retry/budget editor fields persisted as `policy.ui_overrides.commands.*`

## Current known issues
- Release blocker: approval separation-of-duties is not enforced. The same AI agent can call `execute_command`, receive a token, call `approve_command`, and complete its own confirmation loop.
- `execute_command` still uses `shell=True` for compatibility; this remains the largest residual command-parsing risk surface.
- Network policy currently focuses on domain-level command checks; payload-size and protocol-depth enforcement are not yet comprehensive.
- Backup target detection for shell commands remains heuristic (`PATH_TOKEN_RE` + existing-path checks) and can miss some shell expansion edge cases.
- Runtime constants are still imported by multiple modules at load time (`WORKSPACE_ROOT`, `MAX_RETRIES`, `LOG_PATH`, `BACKUP_DIR`), so dynamic runtime reconfiguration remains non-centralized and requires careful patching in tests.
- Linux validation checkpoint has not yet been executed in this workspace/session.
- When `requires_confirmation` matches first (for example `rm`), user-facing responses no longer distinguish simulation causes (`bulk_file_threshold` vs `wildcard_unresolved`) even though simulation still runs.
- Cumulative budget limits are currently high enough that practical MVP prompt runs may not trigger budget blocks.
- UI per-command retry/budget overrides are stored as policy metadata for now; runtime does not yet enforce per-command override values.

## Core use cases (from README; do not edit without explicit product decision)
1. Block destructive commands and sensitive path/extension access.
2. Simulation-gate wildcard destructive operations and enforce blast-radius thresholds.
3. Require explicit confirmation handshake for configured risky commands.
4. Create backups before destructive/overwrite actions and validate recovery.

## MVP lock-down sequence (approved order)
1. Branch protection + merge policy: documented in `README.md`; GitHub branch protection settings still need to be applied operationally.
2. UTC deprecation fix: completed.
3. Policy coverage audit and lock-down (`policy.json` only): completed.
4. Linux validation checkpoint: pending.
5. Merge `refactor` -> `main`: frozen pending blocker resolution.

## Merge freeze status
- Current state: `refactor` -> `main` merge is blocked.
- Block reason: confirmation handshake can be self-approved by the same agent, so human-in-the-loop intent is not enforced.
- Unfreeze condition:
  1. `approve_command` must be reachable only via a separate trusted channel (for example UI/operator action, operator-only CLI, or separate non-agent-exposed endpoint), or equivalent actor-authenticated separation.
  2. Runtime must enforce caller identity/role for approvals (policy `allowed_roles` cannot remain declarative-only).
  3. Regression tests must prove an agent cannot self-approve commands it initiated.

## Minimum pre-merge gate (must pass before merge to `main`)
1. Unit test gate: `python3 -m unittest discover -s tests -p 'test_*.py'` passes.
2. Manual integration gate: at least 12 prompts from `tests.md` validated, including destructive block, confirmation handshake, simulation threshold/unresolved wildcard, cumulative-budget anti-bypass, restore dry-run/apply, and network-policy checks.
3. Linux gate: unit suite + reduced integration prompts executed on Linux with outcomes recorded.
4. Approval separation gate: a dedicated regression test and manual scenario confirm the initiating agent cannot complete its own approval loop.

## Post-MVP backlog (grouped workstreams)
### Execution hardening
1. Harden command execution model: reduce dependence on `shell=True` with structured execution where feasible, and isolate a tightly-scoped legacy shell mode for cases that need pipes/redirection.
2. Strengthen network control depth: keep domain controls and add payload/protocol-aware enforcement so `network.max_payload_size_kb` and related policy fields become meaningful.

### Policy/code parity
3. Complete policy-to-code parity for remaining unused/partial keys: `allowed.max_files_per_operation`, `network.max_payload_size_kb`, `audit.log_level`, cumulative budget `counting.mode`, `reset.mode`, `reset_on_server_restart`, `audit.log_budget_state`, `audit.fields`, `on_exceed.decision_tier`, and override metadata fields (`require_confirmation_tool`, `token_ttl_seconds`, `audit_reason_required`, `allowed_roles`).
4. Unify backup policy behavior across tools: enforce `audit.backup_enabled` consistently for `write_file` and `delete_file`, and keep backup access controls consistent between file tools and `execute_command`.
5. Improve backup mutation detection: replace or augment regex path extraction with parser-aware target resolution for shell expansions (`find -exec`, `xargs`, loops, substitutions).
6. Improve restore ergonomics and safety: add restore conflict strategies (`overwrite/skip/fail`) and clearer per-file restore result reporting.

### Release readiness
7. Add CI checks for policy parity regressions and run `python3 -m unittest discover -s tests -p 'test_*.py'` as a required check.
8. Strengthen release hygiene: dependency vulnerability checks (`pip-audit`), reproducible constraints/lock workflow, and branch protection enforcement in GitHub.
9. Formalize long-term two-layer test strategy maintenance for `tests/` and `tests.md` prompt suites.

### Policy validation
10. Validate expanded command sets against real agent workflows to tune false-positive rate (especially for `find`, `xargs`, `sed`, `perl` in simulation tier).
11. Add focused integration tests for multi-command shell constructs (`find -exec`, `xargs`, loops, substitutions) that are represented in policy but only partially modeled by current simulation logic.
12. Restore simulation diagnostics for confirmation-gated commands: include simulation context in logs/responses so operators can distinguish `bulk_file_threshold` from `wildcard_unresolved` even when handshake is required.
13. Tune cumulative budget defaults for MVP operations so anti-bypass behavior is practically testable in manual integration runs without requiring unrealistic operation volume.
14. Add approval separation regression coverage: verify that a command requester cannot approve the same command within the same agent/tool context.
15. Add UI operator warnings:
    - when any command is set to `requires_confirmation`, show a warning that approval increases security but may reduce agent autonomy and introduce operational friction;
    - when command budget configuration is present, show a warning that budget is cumulative and applies per configured session scope (not per-command enforcement unless runtime override support is implemented).
16. Post-MVP hardening review (after packaging + approval workflow rewrite): evaluate restart-based budget bypass risk where MCP process restarts reset in-memory session state, and decide whether to persist budget state across restarts and/or block agent-driven service restart controls.
17. UI guardrails for edit relevance: enable/disable retry and budget inputs based on selected tier so irrelevant fields are visually greyed out (for example `allowed` should not expose retry controls), with clear helper text for why fields are disabled.
