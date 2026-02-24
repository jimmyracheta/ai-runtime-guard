# CHANGELOG_DEV

## 2026-02-24 (release freeze: approval separation flaw)
- Identified a release-blocking security gap during MVP gate testing: the same agent can request a confirmation-gated command and then call `approve_command` to approve itself.
- Declared merge freeze for `refactor` -> `main` until separation-of-duties is enforced for approvals.
- Added explicit unfreeze requirements in `STATUS.md`:
  - approvals must come from a separate trusted channel
  - runtime must enforce caller identity/role for approval
  - regression coverage must prove no self-approval path exists
- Added explicit approval-separation checkpoint requirements to `README.md` and `tests.md`.
- Added a Phase-1 local control-plane UI skeleton (`ui/`) for policy management (catalog tabs, tier toggles, validation, atomic apply, and change log), intended as the base for a future out-of-band approval interface.

## 2026-02-24 (MVP lock-down prep)
- Added explicit merge/branch policy and pre-merge gate to `README.md` (unit tests + minimum manual integration prompts + Linux checkpoint).
- Replaced deprecated UTC datetime helpers with timezone-aware UTC usage across runtime modules.
- Expanded `policy.json` command-family coverage for lock-down without adding new runtime features:
  - blocked privilege-escalation commands (`sudo`, `su`, `doas`)
  - requires-confirmation coverage for version control, email, package-management, process-management, and exfiltration-oriented command families.
- Updated `ARCHITECTURE.md` with MVP command-coverage rationale and corrected network enforcement status.
- Reorganized `STATUS.md` into approved lock-down sequence (done vs pending), explicit minimum merge gate, and grouped post-MVP workstreams.
- Confirmed via 12-prompt MVP gate run that handshake controls now consistently gate risky command families (`rm`, `curl`, etc.) and that `restore_backup` dry-run now issues a restore token bound to the live apply step.

## 2026-02-24 (module split + test rewrite)
- Refactored runtime from monolithic `server.py` into focused modules (`config`, `policy_engine`, `approvals`, `budget`, `backup`, `audit`, `executor`, `tools/*`) with a thin `server.py` entrypoint.
- Preserved existing tool behavior and policy semantics while improving code isolation for future changes.
- Added modular regression tests in `tests/` (`test_attacker_suite.py`, `test_retry_clamp.py`, `test_helpers.py`) aligned to the new architecture.
- Replaced references to external test-workspace conventions with repo-local test execution guidance.
- Confirmed unittest discovery passes for refactored tests: `python3 -m unittest discover -s tests -p 'test_*.py'`.

## 2026-02-24 (documentation + repo analysis session)
- Audited all source and policy files to produce operator-facing docs tied to actual implementation behavior.
- Added `README.md` with concise project purpose, startup steps, and test workflow for disposable-workspace destructive scenarios.
- Added `ARCHITECTURE.md` covering tier precedence, retry enforcement, blast-radius simulation, audit schema, backup model, and tool/action mapping.
- Added `STATUS.md` as high-churn snapshot of branch, live workspace state, known issues, and immediate next tasks.
- Added `CHANGELOG_DEV.md` to standardize per-session change capture for faster handoff and historical context.
- Highlighted policy/implementation mismatch risk: `network` policy exists in config but has no runtime enforcement.
- Highlighted residual risk surface: shell execution uses `shell=True`; current mitigations reduce but do not eliminate parser-level attack complexity.
- Captured repo hygiene gap: runtime artifacts and local test data are present in workspace and should be managed explicitly.

## 2026-02-23 (recent hardening sequence from commit history)
- Enforced workspace and optional whitelist roots for file/path operations to reduce path-escape risk.
- Added session/workspace identifiers and centralized `build_log_entry` to make audit records consistent and correlatable.
- Added typed policy result (`PolicyResult`) with decision tier and matched rule metadata to improve explainability.
- Introduced command normalization and hash-based session whitelist so semantically identical commands share approval state.
- Refined destructive-operation handling: simulation checks, retry limits, and final-block behavior.
- Added/expanded file tools (`read_file`, `write_file`, `delete_file`, `list_directory`) with policy-first checks and backup support.
- Backed destructive operations with timestamped backups and manifests to improve recovery.
- Added attacker-focused tests and retry clamp checks to validate high-risk control paths.
