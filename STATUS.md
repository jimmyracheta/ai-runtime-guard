# STATUS

Last updated: 2026-02-24 (command policy rollout items 10-13 implemented)

## Current branch
- `dev` (tracking `origin/dev`)

## What was just changed
- Added policy schema extensions for cumulative budgets, network enforcement mode, execution limits, approval security, and audit redaction patterns.
- Added startup policy validation/normalization with fail-fast checks for malformed policy structures.
- Added shell-aware command segmentation/tokenization helpers and upgraded command matching/simulation parsing.
- Added cumulative blast-radius budget enforcement (session/request/workspace/tool scope support) and budget telemetry fields in logs.
- Added network policy enforcement hook for command execution (`off`/`monitor`/`enforce` modes).
- Added approval token failure throttling/rate limiting.
- Added output truncation + configurable command timeout handling.
- Added backup manifest file hashing and new `restore_backup` MCP tool with dry-run and hash verification.
- Fixed `list_directory` depth checks to use depth relative to allowed roots.
- Added/expanded tests for cumulative bypass prevention, network enforcement, workspace-relative depth, and restore flow.
- Expanded repo ignore rules for runtime/test artifacts and pinned `mcp` dependency range.
- Activated `requires_confirmation` policy with production command/path coverage and explicitly included `rm`/`mv` to intentionally enable approval-based cumulative-budget override paths.
- Implemented command policy rollout together:
  - Expanded `blocked.commands` hard-deny set (including system/disk-destructive patterns).
  - Expanded `requires_simulation.commands` to cover additional bulk-impact command families.
  - Expanded `network.commands` to Linux/macOS parity command set.
  - Added shell-obfuscation-aware unit tests for chaining, quoting, escaping, and normalization edge cases.

## Current known issues
- `execute_command` still uses `shell=True` for compatibility; this remains the largest residual command-parsing risk surface.
- Network policy currently focuses on domain-level command checks; payload-size and protocol-depth enforcement are not yet comprehensive.
- Backup target detection for shell commands remains heuristic (`PATH_TOKEN_RE` + existing-path checks) and can miss some shell expansion edge cases.
- `test_retry_clamp_pytest.py` requires `pytest`; this environment currently lacks the `pytest` executable.

## Core use cases (from README; do not edit without explicit product decision)
1. Block destructive commands and sensitive path/extension access.
2. Simulation-gate wildcard destructive operations and enforce blast-radius thresholds.
3. Require explicit confirmation handshake for configured risky commands.
4. Create backups before destructive/overwrite actions and validate recovery.

## Recommended next steps and TODO backlog (merged, deduplicated)

### Policy/code audit follow-ups
1. Complete policy-to-code parity: implement or remove currently unused/partially-used policy keys (`allowed.max_files_per_operation`, `network.max_payload_size_kb`, `audit.log_level`, cumulative budget `counting.mode`, `reset.mode`, `reset_on_server_restart`, `audit.log_budget_state`, `audit.fields`, `on_exceed.decision_tier`, override metadata fields).
2. Unify backup policy behavior across tools: enforce `audit.backup_enabled` consistently for `write_file` and `delete_file` (not only `execute_command`), and keep backup access controls consistent between file tools and `execute_command`.
3. Harden command execution model: reduce dependence on `shell=True` with structured execution where feasible, and isolate a tightly-scoped legacy shell mode for cases that need pipes/redirection.
4. Strengthen network control depth: keep domain controls and add payload/protocol-aware enforcement so `network.max_payload_size_kb` and related policy fields become meaningful.
5. Improve backup mutation detection: replace or augment regex path extraction with parser-aware target resolution for shell expansions (`find -exec`, `xargs`, loops, substitutions).
6. Improve restore ergonomics and safety: add restore conflict strategies (`overwrite/skip/fail`) and clearer per-file restore result reporting.
7. Replace deprecated UTC datetime calls with timezone-aware UTC (`datetime.now(datetime.UTC)` / `datetime.fromtimestamp(..., datetime.UTC)`).
8. Consolidate test/runtime tooling: add `pytest` to dev/CI (or migrate remaining pytest tests to unittest), and add CI checks for policy parity regressions.
9. Strengthen release hygiene: dependency vulnerability checks (`pip-audit`), reproducible constraints/lock workflow, and branch protection (`dev` -> `main` with required checks).

### Command policy rollout items (Unix/macOS now, Linux-ready)
10. Validate expanded command sets against real agent workflows to tune false-positive rate (especially for `find`, `xargs`, `sed`, `perl` in simulation tier).
11. Add focused integration tests for multi-command shell constructs (`find -exec`, `xargs`, loops, substitutions) that are now represented in policy but only partially modeled by current simulation logic.
