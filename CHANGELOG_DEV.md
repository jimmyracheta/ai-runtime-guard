# CHANGELOG_DEV

## 2026-02-24 (documentation + repo analysis session)
- Audited all source and policy files to produce operator-facing docs tied to actual implementation behavior.
- Added `README.md` with concise project purpose, startup steps, and test workflow aligned to using `~/Documents/ai-runtime-guard-test` for destructive scenarios.
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
