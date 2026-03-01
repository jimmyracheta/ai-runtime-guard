# Release Guide

This document defines the release workflow for `ai-runtime-guard`.

## Current state
1. Stable releases are published from `main`.
2. Ongoing integration work happens on `dev` (`1.2-dev` train).
3. Stable release notes are in `CHANGELOG.md`.
4. In-progress development notes are in `docs/CHANGELOG_DEV.md`.

## Branch model
1. `dev` is the active integration branch.
2. `main` is release-only.
3. Release flow is `dev` -> `main` -> tag.

## Versioning
Use semantic versions:
1. `vX.Y.Z` for release tags on `main`.
2. Patch tags for stabilization updates.
3. Minor/major bumps for feature and compatibility changes.

## Pre-release checklist (run on `dev`)
1. Confirm clean working tree.
2. Run tests:
   - `python3 -m unittest discover -s tests -p 'test_*.py'`
3. Build UI assets:
   - `cd ui_v3 && npm install && npm run build`
4. Build package artifacts:
   - `python3 -m pip install --upgrade build`
   - `python3 -m build`
5. Validate setup-first packaged behavior:
   - `airg-setup --defaults --yes`
   - `airg-doctor`
6. Optional low-level bootstrap check:
   - `airg-init`
7. Verify docs accuracy:
   - `README.md`, `docs/INSTALL.md`, `docs/MANUAL.md`, `docs/AGENT_MCP_CONFIGS.md`
8. Verify CI workflow green:
   - `.github/workflows/ci-package.yml`

## Release steps
1. Merge `dev` into `main`.
2. Create annotated tag:
   - `git tag -a vX.Y.Z -m "vX.Y.Z"`
3. Push `main` and tag:
   - `git push origin main`
   - `git push origin vX.Y.Z`
4. Create GitHub Release from tag and include:
   - highlights
   - breaking changes (if any)
   - upgrade notes
   - known limitations
5. Attach CI artifacts as needed (`python-dist`, `ui-dist`).

## Packaging validation
Use a fresh virtual environment:
1. `python3 -m venv .venv-release`
2. `source .venv-release/bin/activate`
3. `python -m pip install --upgrade pip build`
4. `python -m build`
5. `python -m pip install dist/*.whl`
6. Smoke-test entrypoints:
   - `airg-setup --defaults --yes`
   - `airg-doctor`
   - `airg-server` (startup smoke, Ctrl+C)
   - `airg-ui` (startup smoke, Ctrl+C)
   - `airg-up` (startup smoke, Ctrl+C)

## Post-release tasks
1. Update `STATUS.md` current snapshot if needed.
2. Open next milestone work on `dev`.
3. Track regressions and hotfix candidates.

## Public-ready criteria
1. CI passes on `dev` and `main`.
2. Setup-first smoke checks pass on clean macOS and Linux environments.
3. UI is served from Flask backend without requiring Vite dev server.
4. Runtime state files are not committed and use secure defaults.
5. Public docs match current setup and boundary behavior.
