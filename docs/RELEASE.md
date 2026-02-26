# Release Guide

This document defines a practical release workflow for `ai-runtime-guard`.

## Branch model
1. `dev` is the active integration branch.
2. `main` is release-only.
3. Release flow is `dev` -> `main` -> tag.

## Versioning
Use semantic versions:
1. `v0.9.x` for MVP stabilization patches.
2. `v1.0.0` for first public packaged release.
3. `v1.x.y` for subsequent minor/patch updates.

## Pre-release checklist (run on `dev`)
1. Confirm clean working tree (or intentionally staged changes only).
2. Verify runtime prerequisites are documented:
   - Python `>=3.10` required (`3.12+` recommended on macOS).
   - `AIRG_WORKSPACE` must be configured as a separate sandbox path from install directory.
3. Run unit tests:
   - `python3 -m unittest discover -s tests -p 'test_*.py'`
4. Run UI build:
   - `cd ui_v3 && npm install && npm run build`
5. Validate runtime path bootstrap:
   - `source scripts/setup_runtime_env.sh`
6. Validate packaged CLI behavior:
   - `python3 airg_cli.py init`
   - `python3 airg_cli.py --help`
   - verify generated `policy.json` includes `audit.backup_root` under user-local runtime state path (not repo path)
7. Review docs for release accuracy:
   - `README.md`, `MANUAL.md`, `STATUS.md`
8. Verify CI workflow green:
   - `.github/workflows/ci-package.yml`
   - validates tests, UI build, and Python package build.

## Packaging validation
Use a virtual environment:
1. `python3 -m venv .venv-release`
2. `source .venv-release/bin/activate`
3. `python -m pip install --upgrade pip build`
4. `python -m build`
5. Install generated wheel:
   - `python -m pip install dist/*.whl`
6. Smoke-test entrypoints:
   - `airg-init`
   - `airg-server` (Ctrl+C after startup check)
   - `airg-ui` (Ctrl+C after startup check)
   - `airg-up` (verify sidecar UI starts, then Ctrl+C)
   - `airg-doctor` (verify no hard errors)

## Release steps
1. Merge `dev` into `main`.
2. Create annotated tag:
   - `git tag -a vX.Y.Z -m "vX.Y.Z"`
3. Push `main` and tag:
   - `git push origin main`
   - `git push origin vX.Y.Z`
4. Create GitHub Release from tag with notes:
   - highlights
   - breaking changes
   - upgrade steps
   - known limitations
5. Attach CI artifacts from the tag workflow run:
   - `python-dist` (wheel/sdist)
   - `ui-dist` (built frontend)

## Optional publish channels
### GitHub release artifacts (recommended first)
1. Attach:
   - source archive (`.zip` / `.tar.gz`)
   - wheel/sdist from `dist/`
2. Include install snippets:
   - `pip install ai-runtime-guard-X.Y.Z-py3-none-any.whl`
   - `airg-init && airg-server`

### PyPI (after initial release hardening)
1. Configure project metadata for public publishing.
2. Upload from CI or trusted local environment:
   - `python -m pip install twine`
   - `python -m twine upload dist/*`
3. Verify:
   - `pip install ai-runtime-guard`
   - `airg-init`, `airg-server`, `airg-ui`

## Post-release tasks
1. Update `STATUS.md` with release completion and next milestone.
2. Open next milestone branch/work items on `dev`.
3. Track any regressions from first external users.

## Public-ready packaging completion criteria
1. CI workflow passes on `dev` and `main` (tests + UI build + package build).
2. `airg-init`, `airg-server`, `airg-ui`, `airg-up`, `airg-doctor` all run successfully on clean macOS and Linux test machines.
3. Built UI is served from Flask backend without requiring Vite dev server.
4. Runtime state files (`approvals.db`, HMAC key, logs, backups) are not committed and are created with secure defaults.
5. README install + MCP config snippets are verified with at least one external agent client.
