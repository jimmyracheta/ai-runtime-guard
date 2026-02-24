# STATUS

Last updated: 2026-02-24 (MVP lock-down sequencing updates)

## Current branch
- `refactor` (tracking `origin/refactor`)

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

## Current known issues
- `execute_command` still uses `shell=True` for compatibility; this remains the largest residual command-parsing risk surface.
- Network policy currently focuses on domain-level command checks; payload-size and protocol-depth enforcement are not yet comprehensive.
- Backup target detection for shell commands remains heuristic (`PATH_TOKEN_RE` + existing-path checks) and can miss some shell expansion edge cases.
- Runtime constants are still imported by multiple modules at load time (`WORKSPACE_ROOT`, `MAX_RETRIES`, `LOG_PATH`, `BACKUP_DIR`), so dynamic runtime reconfiguration remains non-centralized and requires careful patching in tests.
- Linux validation checkpoint has not yet been executed in this workspace/session.

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
5. Merge `refactor` -> `main`: pending after Linux checkpoint and gate completion.

## Minimum pre-merge gate (must pass before merge to `main`)
1. Unit test gate: `python3 -m unittest discover -s tests -p 'test_*.py'` passes.
2. Manual integration gate: at least 12 prompts from `tests.md` validated, including destructive block, confirmation handshake, simulation threshold/unresolved wildcard, cumulative-budget anti-bypass, restore dry-run/apply, and network-policy checks.
3. Linux gate: unit suite + reduced integration prompts executed on Linux with outcomes recorded.

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
