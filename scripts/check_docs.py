#!/usr/bin/env python3
"""Validate local documentation links and release-version references."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib
from urllib.parse import unquote, urlparse


ROOT = pathlib.Path(__file__).resolve().parents[1]
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def _project_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data.get("project", {}).get("version", "")).strip()


def _local_markdown_files() -> list[pathlib.Path]:
    excluded = {".git", "ui_v3/dist", "ui_v3/node_modules"}
    files: list[pathlib.Path] = []
    for path in ROOT.rglob("*.md"):
        rel = path.relative_to(ROOT).as_posix()
        if any(rel == item or rel.startswith(f"{item}/") for item in excluded):
            continue
        files.append(path)
    return sorted(files)


def _strip_link_target(raw: str) -> str:
    target = raw.strip()
    if not target:
        return ""
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    if " " in target:
        target = target.split(" ", 1)[0].strip()
    return target


def _is_external_or_special(target: str) -> bool:
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https", "mailto"}:
        return True
    if target.startswith("#"):
        return True
    return False


def _target_exists(source: pathlib.Path, target: str) -> bool:
    target = unquote(target.split("#", 1)[0])
    if not target:
        return True
    candidate = pathlib.Path(target)
    if not candidate.is_absolute():
        candidate = source.parent / candidate
    return candidate.exists()


def check_links() -> list[str]:
    errors: list[str] = []
    for path in _local_markdown_files():
        text = path.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK_RE.finditer(text):
            target = _strip_link_target(match.group(1))
            if not target or _is_external_or_special(target):
                continue
            if not _target_exists(path, target):
                rel = path.relative_to(ROOT)
                errors.append(f"{rel}: broken local link -> {target}")
    return errors


def check_versions() -> list[str]:
    errors: list[str] = []
    version = _project_version()
    if not version:
        return ["pyproject.toml: missing project.version"]
    status = (ROOT / "STATUS.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"Package version in source: `{version}`" not in status:
        errors.append(f"STATUS.md: package version reference does not match pyproject version {version}")
    if "dev" in version:
        if "## [Unreleased]" not in changelog:
            errors.append("CHANGELOG.md: missing Unreleased section for development version")
    elif f"## [{version}]" not in changelog:
        errors.append(f"CHANGELOG.md: no release section for version {version}")
    return errors


def main() -> int:
    errors = check_links() + check_versions()
    if errors:
        print("Documentation checks failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Documentation checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
