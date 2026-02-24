import copy
import datetime
import hashlib
import json
import pathlib
import tempfile
from typing import Any

import config

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
POLICY_PATH = BASE_DIR / "policy.json"
CATALOG_PATH = pathlib.Path(__file__).resolve().parent / "catalog.json"
CHANGE_LOG_PATH = pathlib.Path(__file__).resolve().parent / "config_changes.log"


def load_policy(path: pathlib.Path | None = None) -> dict:
    path = path or POLICY_PATH
    return json.loads(path.read_text())


def load_catalog(path: pathlib.Path | None = None) -> dict:
    path = path or CATALOG_PATH
    return json.loads(path.read_text())


def policy_hash(policy: dict) -> str:
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def validate_policy(candidate: dict) -> tuple[bool, dict[str, Any]]:
    try:
        normalized = config._validate_and_normalize_policy(copy.deepcopy(candidate))
        return True, {"normalized": normalized, "errors": []}
    except Exception as exc:
        return False, {"normalized": None, "errors": [str(exc)]}


def command_tier_map(policy: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for cmd in policy.get("requires_simulation", {}).get("commands", []):
        out[str(cmd)] = "requires_simulation"
    for cmd in policy.get("requires_confirmation", {}).get("commands", []):
        out[str(cmd)] = "requires_confirmation"
    for cmd in policy.get("blocked", {}).get("commands", []):
        out[str(cmd)] = "blocked"
    return out


def apply_tier_command(policy: dict, command: str, tier: str) -> dict:
    result = copy.deepcopy(policy)
    lists = {
        "blocked": result.setdefault("blocked", {}).setdefault("commands", []),
        "requires_confirmation": result.setdefault("requires_confirmation", {}).setdefault("commands", []),
        "requires_simulation": result.setdefault("requires_simulation", {}).setdefault("commands", []),
    }
    for name, values in lists.items():
        lists[name] = [x for x in values if x != command]

    result["blocked"]["commands"] = lists["blocked"]
    result["requires_confirmation"]["commands"] = lists["requires_confirmation"]
    result["requires_simulation"]["commands"] = lists["requires_simulation"]

    if tier in lists:
        lists[tier].append(command)
        result[tier]["commands"] = sorted(set(lists[tier]))

    return result


def summarize_diff(before: dict, after: dict) -> dict:
    summary: dict[str, Any] = {"top_level_changed": [], "command_changes": {}}
    for key in sorted(set(before.keys()) | set(after.keys())):
        if before.get(key) != after.get(key):
            summary["top_level_changed"].append(key)

    for section in ["blocked", "requires_confirmation", "requires_simulation"]:
        old = set(before.get(section, {}).get("commands", []))
        new = set(after.get(section, {}).get("commands", []))
        added = sorted(new - old)
        removed = sorted(old - new)
        if added or removed:
            summary["command_changes"][section] = {"added": added, "removed": removed}
    return summary


def atomic_write_policy(policy: dict, path: pathlib.Path | None = None) -> None:
    path = path or POLICY_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=path.parent, prefix=".policy.", suffix=".tmp") as tmp:
        json.dump(policy, tmp, indent=2)
        tmp.write("\n")
        tmp.flush()
        pathlib.Path(tmp.name).chmod(0o600)
        temp_path = pathlib.Path(tmp.name)
    temp_path.replace(path)


def append_change_log(actor: str, before: dict, after: dict, path: pathlib.Path | None = None) -> None:
    path = path or CHANGE_LOG_PATH
    record = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
        "actor": actor,
        "before_hash": policy_hash(before),
        "after_hash": policy_hash(after),
        "diff": summarize_diff(before, after),
    }
    with open(path, "a") as log:
        log.write(json.dumps(record) + "\n")


def validate_and_apply(candidate: dict, actor: str = "local-ui") -> tuple[bool, dict[str, Any]]:
    before = load_policy()
    ok, details = validate_policy(candidate)
    if not ok:
        return False, details
    normalized = details["normalized"]
    atomic_write_policy(normalized)
    append_change_log(actor=actor, before=before, after=normalized)
    return True, {"applied": True, "hash": policy_hash(normalized), "diff": summarize_diff(before, normalized)}
