# STATUS

Last updated: 2026-02-24 (implementation pass: cumulative budgets + reliability + recovery)

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

## Recommended next steps and TODO backlog (aligned to core use cases)
1. Replace `shell=True` with structured execution modes where possible, and isolate an explicit legacy-shell compatibility mode.
2. Harden network enforcement beyond domain matching (payload-size enforcement, protocol constraints, and richer URL/token extraction).
3. Improve backup target discovery for complex shell expansions so backup coverage matches real mutation sets more closely.
4. Add integration tests for blocked destructive patterns (`rm -rf`, `dd`, sensitive paths/extensions) across obfuscated shell forms.
5. Add confirmation-handshake tests for replay, lockout-window reset behavior, and override-consumption behavior under cumulative budgets.
6. Add `pytest` (or migrate remaining pytest-style checks to unittest) so retry-clamp tests run in standard local CI.
7. Add restore conflict strategy options (overwrite/skip/fail) and per-file restore reporting.
8. Add timezone-aware UTC timestamps (`datetime.now(datetime.UTC)`) to remove deprecation warnings.
9. Add dependency vulnerability checks in CI (for example `pip-audit`) and lock dependencies with a reproducible constraints file.
10. Add branch protection/PR gate workflow (`dev` -> `main`) with required checks.
