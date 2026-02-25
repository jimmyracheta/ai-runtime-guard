import copy
import datetime
import hashlib
import json
import pathlib
import tempfile
import re
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


def _slugify_tab_id(label: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(label).strip().lower()).strip("-")
    return slug or "custom"


def _validate_ui_catalog(policy: dict) -> None:
    ui_catalog = policy.get("ui_catalog")
    if ui_catalog is None:
        return
    if not isinstance(ui_catalog, dict):
        raise ValueError("policy.ui_catalog must be an object")
    tabs = ui_catalog.get("tabs", [])
    if not isinstance(tabs, list):
        raise ValueError("policy.ui_catalog.tabs must be an array")
    for tab in tabs:
        if not isinstance(tab, dict):
            raise ValueError("policy.ui_catalog.tabs entries must be objects")
        if "id" not in tab or "label" not in tab:
            raise ValueError("policy.ui_catalog.tabs entries must include 'id' and 'label'")
        if not isinstance(tab["id"], str) or not tab["id"].strip():
            raise ValueError("policy.ui_catalog.tabs[*].id must be a non-empty string")
        if tab["id"] == "all":
            raise ValueError("policy.ui_catalog.tabs cannot redefine reserved id 'all'")
        if not isinstance(tab["label"], str) or not tab["label"].strip():
            raise ValueError("policy.ui_catalog.tabs[*].label must be a non-empty string")
        commands = tab.get("commands", [])
        if not isinstance(commands, list):
            raise ValueError("policy.ui_catalog.tabs[*].commands must be an array")
        for cmd in commands:
            if not isinstance(cmd, str):
                raise ValueError("policy.ui_catalog.tabs[*].commands entries must be strings")
        descriptions = tab.get("descriptions", {})
        if not isinstance(descriptions, dict):
            raise ValueError("policy.ui_catalog.tabs[*].descriptions must be an object")
        for k, v in descriptions.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ValueError("policy.ui_catalog.tabs[*].descriptions keys and values must be strings")


def merged_catalog(policy: dict, catalog: dict) -> dict:
    result = {"tabs": []}
    by_id: dict[str, dict] = {}

    for tab in catalog.get("tabs", []):
        tid = str(tab.get("id", "")).strip()
        if not tid:
            continue
        entry = {
            "id": tid,
            "label": str(tab.get("label", tid)),
            "commands": [str(x) for x in tab.get("commands", []) if str(x).strip()],
            "descriptions": {str(k): str(v) for k, v in (tab.get("descriptions") or {}).items()},
        }
        by_id[tid] = entry

    ui_tabs = ((policy.get("ui_catalog") or {}).get("tabs") or [])
    for tab in ui_tabs:
        tid = str(tab.get("id", "")).strip()
        if not tid:
            tid = _slugify_tab_id(tab.get("label", "custom"))
        label = str(tab.get("label", tid)).strip() or tid
        commands = [str(x) for x in tab.get("commands", []) if str(x).strip()]
        descriptions = {str(k): str(v) for k, v in (tab.get("descriptions") or {}).items()}
        if tid in by_id:
            base = by_id[tid]
            merged_commands = sorted(set(base.get("commands", []) + commands))
            merged_descriptions = {**base.get("descriptions", {}), **descriptions}
            by_id[tid] = {**base, "label": label, "commands": merged_commands, "descriptions": merged_descriptions}
        else:
            by_id[tid] = {"id": tid, "label": label, "commands": sorted(set(commands)), "descriptions": descriptions}

    # Ensure `all` is always first and present for UI.
    if "all" not in by_id:
        by_id["all"] = {"id": "all", "label": "All Commands", "commands": [], "descriptions": {}}
    result["tabs"].append(by_id.pop("all"))
    result["tabs"].extend([by_id[k] for k in sorted(by_id.keys())])
    return result


def command_descriptions(catalog: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for tab in catalog.get("tabs", []):
        for cmd, desc in (tab.get("descriptions") or {}).items():
            out[str(cmd)] = str(desc)
    return out


def policy_hash(policy: dict) -> str:
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def validate_policy(candidate: dict) -> tuple[bool, dict[str, Any]]:
    try:
        _validate_ui_catalog(candidate)
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


def all_known_commands(policy: dict, catalog: dict) -> list[str]:
    commands: set[str] = set()
    for section in ["blocked", "requires_confirmation", "requires_simulation", "network"]:
        commands.update(str(x) for x in policy.get(section, {}).get("commands", []))
    for tab in catalog.get("tabs", []):
        commands.update(str(x) for x in tab.get("commands", []))
    return sorted(commands)


def visible_tabs(catalog: dict) -> list[dict[str, str]]:
    tabs: list[dict[str, str]] = []
    for tab in catalog.get("tabs", []):
        tid = str(tab.get("id", "")).strip()
        if not tid:
            continue
        tabs.append({"id": tid, "label": str(tab.get("label", tid))})
    return tabs


def tab_command_map(catalog: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for tab in catalog.get("tabs", []):
        tid = str(tab.get("id", "")).strip()
        if not tid:
            continue
        out[tid] = sorted(set(str(x) for x in tab.get("commands", []) if str(x).strip()))
    return out


def command_context_map(catalog: dict, commands: list[str]) -> dict[str, list[str]]:
    context_map: dict[str, list[str]] = {cmd: [] for cmd in commands}
    for tab in catalog.get("tabs", []):
        tab_id = str(tab.get("id", ""))
        if tab_id == "all":
            continue
        label = str(tab.get("label", tab_id))
        for cmd in tab.get("commands", []):
            c = str(cmd)
            context_map.setdefault(c, [])
            if label not in context_map[c]:
                context_map[c].append(label)
    return context_map


def get_command_override(policy: dict, command: str) -> dict:
    return (
        policy.get("ui_overrides", {})
        .get("commands", {})
        .get(command, {})
    )


def set_command_override(policy: dict, command: str, retry: int | None, budget: dict | None) -> dict:
    result = copy.deepcopy(policy)
    root = result.setdefault("ui_overrides", {})
    commands = root.setdefault("commands", {})
    if retry is None and not budget:
        commands.pop(command, None)
        return result
    entry: dict[str, Any] = {}
    if retry is not None and int(retry) >= 0:
        entry["retry_override"] = int(retry)
    if budget:
        budget_clean = {k: int(v) for k, v in budget.items() if isinstance(v, int) and v >= 0}
        if budget_clean:
            entry["budget"] = budget_clean
    if not entry:
        commands.pop(command, None)
        return result
    commands[command] = entry
    return result


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
