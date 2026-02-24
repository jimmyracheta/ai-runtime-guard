# STATUS

Last updated: 2026-02-24 (local workspace scan)

## Current branch
- `main`

## What was just changed
- In this session (docs only): added `README.md`, `ARCHITECTURE.md`, `STATUS.md`, `CHANGELOG_DEV.md`.
- Existing local working tree already had uncommitted changes before this pass:
  - modified: `server.py`, `activity.log`
  - untracked: `backups/`, `simtest/`, `test_attacker_suite.py`, `test_retry_clamp_pytest.py`, `tmp_test.txt`, `.DS_Store`
- Most recent commits on branch show security-hardening progression:
  - workspace boundary + whitelist enforcement
  - session/workspace attribution in logs
  - typed `PolicyResult` with tier/rule metadata
  - command normalization + hash-based session whitelist

## Current known issues
- `network` policy section is a placeholder in `policy.json` and is not enforced in `server.py`.
- `execute_command` still runs via `shell=True`; policy checks reduce risk but shell parsing remains a high-risk surface.
- Backup detection for shell commands is heuristic (`PATH_TOKEN_RE` + pre-existence checks) and may miss some shell-expanded destructive targets.
- Repository currently contains generated/runtime artifacts (`.DS_Store`, `backups/`, `simtest/`, `tmp_test.txt`) that can create noise in status and reviews.

## Next 3 tasks
1. Add explicit network/egress enforcement hooks (or remove placeholder) so policy and implementation are aligned.
2. Expand adversarial tests for shell edge cases (quoting, escaped separators, glob edge cases, symlink traversal attempts).
3. Separate fixture/runtime artifacts from repo state (`tests/fixtures`, tighter ignore rules, cleanup script) to keep dev diffs clean.
