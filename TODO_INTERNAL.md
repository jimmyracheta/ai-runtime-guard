# AIRG Internal Implementation Plan

Last refreshed: 2026-05-20  
Source reconciliation: `CHANGELOG.md`, `docs/CHANGELOG_DEV.md`, `STATUS.md`, current local tests.

## Pass tracking

1. Pass 1 (P0-1 + P0-3): completed
2. Pass 2 (P0-2): completed
3. Pass 3 (P1-1 + P1-2): completed
4. Pass 4 (P1-3 + P1-4, plus selected P2 quick wins): completed
5. v2.3.2.dev0 follow-up (cwd-aware shell containment + P2-5/P2-docs): completed

## Planning assumptions

1. AIRG is a local guardrail and policy-enforcement layer for MCP-routed actions.
2. AIRG is not positioned as full malicious-local-actor containment.
3. Priority is "enforcement correctness for routed actions" before "localhost hardening depth."

## Completed baseline (through v2.3.2.dev0 development)

1. v2.3.1 release active with pass-1..pass-4 hardening, telemetry scheduler, Codex scope/trust support, and documentation alignment.
2. Telemetry reliability and UX follow-up shipped:
   - telemetry section persistence now backfills missing defaults (`enabled`, `endpoint`) when writing `last_sent_date`
   - UI backend now runs daily telemetry eligibility checks in background with wake-resilient bounded ticker intervals
   - approvals refresh path no longer collapses expanded pending sections or forces unnecessary rerenders when payloads are unchanged.
3. v2.2.2 telemetry reliability fix shipped (`User-Agent`/`Accept` headers + debug diagnostics).
4. v2.2.1 docs/install/readme polish shipped.
5. v2.2.0 telemetry model + GUI payload preview shipped.
6. v2.1.0 substitution parsing hardening and Cursor posture/hardening expansion shipped.
7. v2.0.0 Script Sentinel and `edit_file` flow shipped.
8. Shell workspace containment now tracks `cd` state across chained shell segments before resolving later relative path tokens.
9. Default blocked paths now include common cloud/developer credential stores.
10. CI now includes local documentation link/version checks.

## Phase 1 (P0): Core enforcement correctness

### P0-1 Path protection correctness (`blocked.paths`)

Goal:
1. Move from substring matching to resolved-path enforcement.
2. Protect AIRG runtime artifacts with a non-overridable hard denylist.

Implementation:
1. Update `src/policy_engine.py` path checks to canonical absolute-path comparisons.
2. Add hard denylist for internal files (`policy`, approvals DB/HMAC key, activity/report DB/log paths, backup root controls).
3. Ensure equivalent logic is used consistently for command and file tools.

Validation:
1. Add adversarial path tests to `tests/test_attacker_suite.py`.
2. Add quoted/split/path-construction bypass regression cases.

Exit criteria:
1. Known quoting/splitting path bypass variants are denied deterministically.
2. Internal state file protections cannot be weakened via policy JSON.
3. Status: complete in Pass 1.

### P0-2 Restore integrity + Script Sentinel continuity

Goal:
1. Prevent restore-based integrity bypass and Sentinel continuity gaps.

Implementation:
1. Sign backup manifest entries (HMAC) and verify on restore.
2. Require `sha256` for every restored entry.
3. Route restore writes through Sentinel tagging/retag path.
4. Bind restore apply tokens to intended actor/session semantics.

Validation:
1. Add tamper tests for missing hash, invalid signature, mismatched source path.
2. Add restore->execute Sentinel continuity regression tests.

Exit criteria:
1. Crafted/unsigned manifests fail closed.
2. Restored executable artifacts participate in Sentinel continuity checks.
3. Status: complete in Pass 2.

### P0-3 Shell inner payload coverage

Goal:
1. Close policy gaps for nested/indirect command bodies.

Implementation:
1. Recursively evaluate payloads for `-c`, `-e`, `--eval` (known shells/interpreters).
2. Fail closed on tokenizer parse failures where enforcement cannot be determined.
3. Cover heredoc/herestring, ANSI-C quoting, and env-assignment prefixes.

Validation:
1. Extend `tests/test_command_substitution_policy.py` for each parser edge class.
2. Add parser fuzz/property test harness for policy engine command analysis. Status: deferred follow-up; deterministic regression coverage is in place for known bypass classes.

Exit criteria:
1. Inner payload commands are tier-evaluated, not implicitly trusted by outer wrapper.
2. Parse ambiguities no longer skip enforcement.
3. Status: complete in Pass 1.

## Phase 2 (P1): Local hardening and identity reliability

### P1-1 Local GUI API hardening

Goal:
1. Reduce localhost process/browser abuse risk.

Implementation:
1. Add bearer auth middleware for mutating endpoints (preferably all API endpoints except static assets/health).
2. Enforce strict Host allowlist (`127.0.0.1`/`localhost` + configured port).
3. Tighten CORS to exact origin match.
4. Keep `X-Actor` informational only after auth.

Validation:
1. Flask tests for auth-required routes and Host/CORS rejection cases.
2. Manual curl checks for unauthenticated state-changing requests -> deny.

Exit criteria:
1. Unauthenticated localhost API writes are blocked.
2. Status: complete in Pass 3.

### P1-2 Agent override safety / identity caveat enforcement

Goal:
1. Prevent accidental weakening through env-spoofable profile identity.

Implementation:
1. Enforce "agent overrides may only tighten baseline policy."
2. Add UI warning when override attempts to loosen baseline (with migration guidance).
3. Clarify docs: `AIRG_AGENT_ID` is attribution key, not strong identity proof.

Validation:
1. Unit tests for override validation (loosen attempts rejected).
2. UI policy-apply tests for warning/error behavior.
3. Status: complete in Pass 3.

### P1-3 `airg-server` command resolution hardening

Goal:
1. Eliminate PATH ambiguity in generated MCP configs.

Implementation:
1. Prefer `sys.executable -m airg_cli server` output for generated config by default.
2. Validate trusted location when absolute binary path is emitted.

Validation:
1. Tests across setup/configurator/manager code paths for deterministic command emission.
2. Status: complete in Pass 4.

### P1-4 Executor env hardening

Goal:
1. Reduce subprocess behavior manipulation via inherited env.

Implementation:
1. Shift to env allowlist in `src/executor.py`.
2. Add conservative resource limits where portable.
3. Gate suspicious assignment-prefix patterns.

Validation:
1. Unit tests for env propagation allowlist.
2. Regression tests for blocked dangerous assignment prefixes.
3. Status: complete in Pass 4.

## Phase 3 (P2): Follow-on resilience and operator clarity

Completed:
1. Expand default sensitive-path blocklist for common cloud/dev credential stores. Status: complete on 2026-05-20.
2. Add docs CI checks for local Markdown link drift and versioned references. Status: complete on 2026-05-20.

Remaining:
1. Fail closed or loudly degrade when approval HMAC key persistence fails.
2. Decide telemetry endpoint policy model:
   - pin endpoint in runtime, or
   - strict allowlist for custom endpoint.
3. Convert side-effect GET endpoints to authenticated POST.
4. Strengthen audit-log tamper evidence (MAC/signature strategy).
5. Add parser fuzz/property test harness for policy engine command analysis.

## Documentation and release hygiene (cross-cutting)

1. Keep README/MANUAL/STATUS/CHANGELOG aligned every release.
2. Add docs CI checks for link drift and versioned references. Status: complete on 2026-05-20.
3. Keep agent-context handoff synced with active phase and risks.

## Execution workflow

1. Deliver each P0/P1 item in small PR slices with test-first regressions.
2. For each item: include threat scenario, fix, tests, and rollout notes in PR body.
3. Gate release bumps on passing targeted attacker/parser/restore test sets.
