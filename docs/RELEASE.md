# Release Guide

This document defines the release workflow for `ai-runtime-guard`.

## Current state
1. Stable releases are published from `main`.
2. Ongoing integration work happens on `dev` (next release train after latest stable tag).
3. Stable release notes are in `CHANGELOG.md`.
4. In-progress development notes are in `docs/CHANGELOG_DEV.md`.

## Branch model
1. `dev` is the active integration branch.
2. `main` is release-only.
3. Release flow is `dev` -> `main` -> tag.

## Versioning
Use semantic versions:
1. `vX.Y.Z` for release tags on `main`.
2. `vX.Y-dev` for integration snapshots from `dev` (pre-release; not public stable).
3. Patch tags for stabilization updates.
4. Minor/major bumps for feature and compatibility changes.

## Pre-release checklist (run on `dev`)
1. Confirm clean working tree.
2. Run tests:
   - `python3 -m unittest discover -s tests -p 'test_*.py'`
3. Build UI assets:
   - `cd ui_v3 && npm install && npm run build`
4. Build package artifacts:
   - `python3 -m pip install --upgrade build`
   - `python3 -m build`
   - `python3 -m pip install --upgrade twine`
   - `twine check dist/*`
5. Validate setup-first packaged behavior:
   - `airg-setup --defaults --yes`
   - `airg-doctor`
6. Optional low-level bootstrap check:
   - `airg-init`
7. Verify docs accuracy:
   - `README.md`, `docs/INSTALL.md`, `docs/MANUAL.md`, `docs/AGENT_MCP_CONFIGS.md`
8. Verify CI workflow green:
   - `.github/workflows/ci-package.yml`
   - `.github/workflows/publish-pypi.yml` (build job on dispatch/tag runs)

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

## Trusted Publishing setup (one-time)
1. In PyPI and TestPyPI, configure Trusted Publisher for this GitHub repository/workflow:
   - repository: `jimmyracheta/ai-runtime-guard`
   - workflow: `.github/workflows/publish-pypi.yml`
2. In GitHub, create environments:
   - `testpypi`
   - `pypi`
3. Keep publish approvals scoped to maintainers as needed by environment protection rules.

## Integration-tag steps (`dev`)
1. Confirm `dev` branch changelog/docs are reconciled.
2. Create annotated integration tag:
   - `git tag -a vX.Y-dev -m "vX.Y-dev"`
3. Push `dev` and tag:
   - `git push origin dev`
   - `git push origin vX.Y-dev`
4. Keep public stable version unchanged until the next `vX.Y.Z` tag is cut on `main`.

## TestPyPI dry-run flow
1. Run workflow manually:
   - `Publish Package` -> `target=testpypi`
2. Validate install in a clean environment:
   - `python3 -m venv .venv-testpypi`
   - `source .venv-testpypi/bin/activate`
   - `python -m pip install --index-url https://test.pypi.org/simple --extra-index-url https://pypi.org/simple ai-runtime-guard`
3. Run smoke checks:
   - `airg-setup --defaults --yes`
   - `airg-doctor`
   - `airg-server` (startup smoke, Ctrl+C)
   - `airg-ui` (startup smoke, Ctrl+C)

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
4. If a bad artifact is published, yank on PyPI and issue a patched release tag.

## Public-ready criteria
1. CI passes on `dev` and `main`.
2. Setup-first smoke checks pass on clean macOS and Linux environments.
3. UI is served from Flask backend without requiring Vite dev server.
4. Runtime state files are not committed and use secure defaults.
5. Public docs match current setup and boundary behavior.
