import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import uuid

from config import BACKUP_DIR, POLICY, WORKSPACE_ROOT
from policy_engine import is_within_workspace

MODIFYING_COMMAND_RE = re.compile(r"\b(rm|mv)\b|(?<![>])>(?!>)")
PATH_TOKEN_RE = re.compile(
    r"(?<!\S)"
    r"("
    r"/[^\s;|&<>'\"\\]+"
    r"|\.{1,2}/[^\s;|&<>'\"\\]+"
    r"|[A-Za-z0-9_][A-Za-z0-9_.\\-]*/[^\s;|&<>'\"\\]+"
    r"|[A-Za-z0-9_][A-Za-z0-9_.\\-]*\.[A-Za-z0-9]+"
    r")"
)


def extract_paths(command: str) -> list[str]:
    candidates = PATH_TOKEN_RE.findall(command)
    candidates = [c.strip().strip("'\"") for c in candidates]

    resolved: list[str] = []
    for candidate in candidates:
        abs_path = candidate if os.path.isabs(candidate) else os.path.join(WORKSPACE_ROOT, candidate)
        path = str(pathlib.Path(abs_path).resolve())
        if os.path.exists(path):
            resolved.append(path)
    return resolved


def allowed_roots() -> list[pathlib.Path]:
    roots = [pathlib.Path(WORKSPACE_ROOT).resolve()]
    for root in POLICY.get("allowed", {}).get("paths_whitelist", []):
        roots.append(pathlib.Path(root).resolve())
    unique = list({str(r): r for r in roots}.values())
    return sorted(unique, key=lambda p: len(str(p)), reverse=True)


def backup_relative_path(path: pathlib.Path) -> pathlib.Path | None:
    for root in allowed_roots():
        if path.is_relative_to(root):
            return path.relative_to(root)
    return None


def cleanup_old_backups() -> None:
    retention_days = POLICY.get("audit", {}).get("backup_retention_days", 30)
    if retention_days <= 0:
        return
    cutoff = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=retention_days)
    backup_root = pathlib.Path(BACKUP_DIR)
    if not backup_root.exists():
        return
    for child in backup_root.iterdir():
        if not child.is_dir():
            continue
        try:
            mtime = datetime.datetime.fromtimestamp(child.stat().st_mtime, datetime.UTC)
        except OSError:
            continue
        if mtime < cutoff:
            shutil.rmtree(child, ignore_errors=True)


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def backup_entries_for_source(source_path: pathlib.Path) -> list[dict]:
    source = str(source_path.resolve())
    root = pathlib.Path(BACKUP_DIR)
    if not root.exists():
        return []
    entries: list[dict] = []
    for folder in root.iterdir():
        if not folder.is_dir():
            continue
        manifest_path = folder / "manifest.json"
        if not manifest_path.exists():
            continue
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(manifest, list):
            continue
        for item in manifest:
            if not isinstance(item, dict):
                continue
            if item.get("source") != source:
                continue
            backup_path = pathlib.Path(item.get("backup", ""))
            if not backup_path.exists():
                continue
            try:
                order_key = folder.stat().st_mtime
            except OSError:
                order_key = 0
            entries.append(
                {
                    "folder": folder,
                    "manifest_path": manifest_path,
                    "item": item,
                    "order_key": order_key,
                }
            )
    return sorted(entries, key=lambda e: e["order_key"], reverse=True)


def latest_backup_hash_for_source(source_path: pathlib.Path) -> str | None:
    entries = backup_entries_for_source(source_path)
    if not entries:
        return None
    item = entries[0]["item"]
    if item.get("type") != "file":
        return None
    return item.get("sha256")


def enforce_max_versions_per_file() -> None:
    max_versions = int(POLICY.get("audit", {}).get("max_versions_per_file", 5))
    if max_versions <= 0:
        return
    root = pathlib.Path(BACKUP_DIR)
    if not root.exists():
        return

    by_source: dict[str, list[dict]] = {}
    for folder in root.iterdir():
        if not folder.is_dir():
            continue
        manifest_path = folder / "manifest.json"
        if not manifest_path.exists():
            continue
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(manifest, list):
            continue
        try:
            order_key = folder.stat().st_mtime
        except OSError:
            order_key = 0
        for idx, item in enumerate(manifest):
            if not isinstance(item, dict):
                continue
            if item.get("type") != "file":
                continue
            source = item.get("source")
            backup = item.get("backup")
            if not source or not backup:
                continue
            by_source.setdefault(source, []).append(
                {
                    "folder": folder,
                    "manifest_path": manifest_path,
                    "manifest_index": idx,
                    "item": item,
                    "order_key": order_key,
                }
            )

    to_prune: list[dict] = []
    for _source, entries in by_source.items():
        ordered = sorted(entries, key=lambda e: e["order_key"], reverse=True)
        to_prune.extend(ordered[max_versions:])

    by_manifest: dict[str, list[dict]] = {}
    for entry in to_prune:
        key = str(entry["manifest_path"])
        by_manifest.setdefault(key, []).append(entry)

    for _, entries in by_manifest.items():
        manifest_path = pathlib.Path(entries[0]["manifest_path"])
        folder = pathlib.Path(entries[0]["folder"])
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(manifest, list):
            continue

        prune_indices = {e["manifest_index"] for e in entries}
        new_manifest: list[dict] = []
        for idx, item in enumerate(manifest):
            if idx not in prune_indices:
                new_manifest.append(item)
                continue
            backup_path = pathlib.Path(item.get("backup", ""))
            try:
                if backup_path.exists():
                    if backup_path.is_file():
                        backup_path.unlink()
                    elif backup_path.is_dir():
                        shutil.rmtree(backup_path, ignore_errors=True)
            except OSError:
                pass

        try:
            if new_manifest:
                manifest_path.write_text(json.dumps(new_manifest, indent=2))
            else:
                shutil.rmtree(folder, ignore_errors=True)
        except OSError:
            continue


def backup_paths(paths: list[str]) -> str:
    cleanup_old_backups()
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H-%M-%S.%f")
    suffix = uuid.uuid4().hex[:8]
    backup_location = os.path.join(BACKUP_DIR, f"{timestamp}_{suffix}")

    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    os.makedirs(backup_location, mode=0o700, exist_ok=False)
    manifest: list[dict] = []

    for path in paths:
        resolved = pathlib.Path(path).resolve()
        if not is_within_workspace(str(resolved)):
            continue

        rel = backup_relative_path(resolved)
        if rel is None:
            continue
        dest = pathlib.Path(backup_location) / rel

        if resolved.is_file():
            if POLICY.get("audit", {}).get("backup_on_content_change_only", True):
                latest_hash = latest_backup_hash_for_source(resolved)
                current_hash = sha256_file(resolved)
                if latest_hash is not None and latest_hash == current_hash:
                    continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(resolved), str(dest))
            manifest.append(
                {
                    "source": str(resolved),
                    "backup": str(dest),
                    "type": "file",
                    "sha256": sha256_file(dest),
                }
            )
        elif resolved.is_dir():
            shutil.copytree(str(resolved), str(dest))
            manifest.append({"source": str(resolved), "backup": str(dest), "type": "directory"})

    if not manifest:
        shutil.rmtree(backup_location, ignore_errors=True)
        return ""

    with open(os.path.join(backup_location, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    enforce_max_versions_per_file()
    return backup_location
