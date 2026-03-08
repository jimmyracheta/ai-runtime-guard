# Release Checklist

Use this checklist for every stable release (`vX.Y.Z`).

## 1. Prepare on `dev`
1. Confirm working tree is clean:
```bash
git status --short
```
2. Update release references:
   - `README.md` (current release/tag mention)
   - `CHANGELOG.md` (new version section with date and highlights)
   - `STATUS.md` (if needed)
3. Run tests:
```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```
4. Build UI assets:
```bash
cd ui_v3
npm install
npm run build
cd ..
```
5. Build Python package artifacts:
```bash
python3 -m pip install --upgrade build
python3 -m build
python3 -m pip install --upgrade twine
twine check dist/*
```
6. Push `dev`:
```bash
git push origin dev
```

## 2. Open and merge PR (`dev` -> `main`)
1. Create PR from `dev` into `main`.
2. Wait for required checks to pass.
3. Get required approval(s) per branch protection.
4. Merge using **Create a merge commit**.

## 3. Tag release from merged `main`
1. Sync local `main`:
```bash
git checkout main
git pull origin main
```
2. Create annotated stable tag:
```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
```
3. Push tag:
```bash
git push origin vX.Y.Z
```

## 3b. Optional TestPyPI preflight (recommended)
1. Trigger workflow dispatch:
   - workflow: `Publish Package`
   - input: `target=testpypi`
2. Validate install from TestPyPI in clean venv:
```bash
python3 -m venv .venv-testpypi
source .venv-testpypi/bin/activate
python -m pip install --index-url https://test.pypi.org/simple --extra-index-url https://pypi.org/simple ai-runtime-guard
airg-setup --defaults --yes
airg-doctor
```

## 4. Post-release verification
1. Confirm tag points to `main` HEAD:
```bash
git rev-parse main
git rev-parse vX.Y.Z
```
2. Confirm GitHub release/tag is visible.
3. Confirm branch protections are still enabled on `main`.
4. Run packaged CLI smoke checks:
```bash
airg-setup --defaults --yes
airg-doctor
airg-server   # startup smoke (Ctrl+C)
airg-ui       # startup smoke (Ctrl+C)
```
5. Confirm policy baseline reflects current runtime:
   - contains `network.block_unknown_domains`
   - does not rely on removed `network.max_payload_size_kb`
6. Announce release notes from `CHANGELOG.md`.

## 5. If tag was created before PR merge (re-tag fix)
1. Delete local tag:
```bash
git tag -d vX.Y.Z
```
2. Delete remote tag:
```bash
git push origin :refs/tags/vX.Y.Z
```
3. Recreate tag on current `main` HEAD and push again:
```bash
git checkout main
git pull origin main
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```
