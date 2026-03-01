# Contributing

Thanks for your interest in contributing to `ai-runtime-guard`.

## Branch and PR Workflow
1. `dev` is the active integration branch
2. `main` is release-only
3. Open feature/fix branches from `dev`
4. Merge back into `dev` through PR
5. Promote releases from `dev` to `main` through PR and tag

Do not push directly to protected release branches.

## Development Setup
1. Create and activate a Python virtual environment
2. Install dependencies from `requirements.txt`
3. If working on GUI, install frontend dependencies in `ui_v3`

Typical checks before PR:
1. `python3 -m unittest discover -s tests -p 'test_*.py'`
2. `cd ui_v3 && npm run build`

## Code Standards
1. Keep policy behavior deterministic and explicit
2. Preserve backward compatibility unless a deliberate breaking change is documented
3. Add focused tests for behavior changes
4. Update docs when behavior or policy schema changes
5. Avoid introducing unrelated changes in the same PR

## Security-Sensitive Areas
Changes in these modules need extra care and test coverage:
1. `policy_engine.py`
2. `approvals.py`
3. `budget.py`
4. `backup.py`
5. `executor.py`
6. `tools/command_tools.py` and `tools/file_tools.py`

For security-relevant PRs, include:
1. Risk statement
2. Threat model impact
3. Test evidence
4. Rollback notes if applicable

## Documentation Requirements
If your change affects behavior, update relevant docs such as:
1. `README.md`
2. `docs/MANUAL.md`
3. `docs/ARCHITECTURE.md`
4. `docs/INSTALL.md`
5. `CHANGELOG.md` and `docs/CHANGELOG_DEV.md` when appropriate

## Commit and PR Guidance
1. Use clear commit messages with intent
2. Keep commits scoped and reviewable
3. In PR description, explain:
- what changed
- why it changed
- how it was tested
- any policy migration impact

## Legal
By submitting a contribution, you agree your contribution may be distributed under the project MIT license.
