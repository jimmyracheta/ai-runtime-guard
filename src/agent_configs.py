import json
import os
import pathlib
import shlex
import sys
import uuid
from datetime import UTC, datetime
from typing import Any


AGENT_TYPES = [
    {"id": "claude_code", "label": "Claude Code"},
    {"id": "claude_desktop", "label": "Claude Desktop"},
    {"id": "cursor", "label": "Cursor"},
    {"id": "codex", "label": "Codex"},
    {"id": "custom", "label": "Custom"},
]
_ALLOWED_AGENT_TYPES = {item["id"] for item in AGENT_TYPES}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _safe_slug(value: str) -> str:
    out = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "").strip())
    out = "-".join(filter(None, out.split("-")))
    return out or "agent"


def _shell_single_quote(value: str) -> str:
    # Safe single-quote shell encoding: 'abc' -> 'abc', a'b -> 'a'"'"'b'
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _state_dir(paths: dict[str, pathlib.Path]) -> pathlib.Path:
    return paths["approval_db_path"].expanduser().resolve().parent


def _registry_dir(paths: dict[str, pathlib.Path]) -> pathlib.Path:
    return _state_dir(paths) / "mcp-configs"


def _registry_path(paths: dict[str, pathlib.Path]) -> pathlib.Path:
    return _registry_dir(paths) / "agents.json"


def _ensure_dir(path: pathlib.Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _read_json(path: pathlib.Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text())
    except Exception:
        return fallback


def _write_json(path: pathlib.Path, payload: Any) -> None:
    _ensure_dir(path.parent)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def _normalize_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile_id": str(profile.get("profile_id") or uuid.uuid4()),
        "name": str(profile.get("name") or "").strip(),
        "agent_type": str(profile.get("agent_type") or "claude_code").strip().lower(),
        "workspace": str(profile.get("workspace") or "").strip(),
        "agent_id": str(profile.get("agent_id") or "").strip(),
        "last_generated_at": str(profile.get("last_generated_at") or ""),
        "last_saved_path": str(profile.get("last_saved_path") or ""),
        "last_saved_instructions_path": str(profile.get("last_saved_instructions_path") or ""),
    }


def _validate_profile(profile: dict[str, Any], *, existing: list[dict[str, Any]]) -> tuple[bool, list[str], dict[str, Any]]:
    normalized = _normalize_profile(profile)
    errors: list[str] = []

    if normalized["agent_type"] not in _ALLOWED_AGENT_TYPES:
        errors.append("Unsupported agent type")
    if not normalized["workspace"]:
        errors.append("Workspace is required")
    else:
        ws = pathlib.Path(normalized["workspace"]).expanduser()
        if not ws.is_absolute():
            errors.append("Workspace must be an absolute path")
    if not normalized["agent_id"]:
        errors.append("Agent ID is required")

    this_profile_id = normalized["profile_id"]
    for item in existing:
        other = _normalize_profile(item)
        if other["profile_id"] == this_profile_id:
            continue
        if other["agent_id"] and other["agent_id"] == normalized["agent_id"]:
            errors.append(f"Duplicate agent_id: {normalized['agent_id']}")
            break

    return len(errors) == 0, errors, normalized


def _shared_env(paths: dict[str, pathlib.Path], workspace: str, agent_id: str) -> dict[str, str]:
    return {
        "AIRG_AGENT_ID": agent_id,
        "AIRG_WORKSPACE": workspace,
        "AIRG_POLICY_PATH": str(paths["policy_path"]),
        "AIRG_APPROVAL_DB_PATH": str(paths["approval_db_path"]),
        "AIRG_APPROVAL_HMAC_KEY_PATH": str(paths["approval_hmac_key_path"]),
        "AIRG_LOG_PATH": str(paths["log_path"]),
        "AIRG_REPORTS_DB_PATH": str(paths["reports_db_path"]),
    }


def _server_process() -> tuple[str, list[str]]:
    explicit = str(os.environ.get("AIRG_SERVER_COMMAND", "")).strip()
    if explicit:
        parts = shlex.split(explicit)
        if not parts:
            return "airg-server", []
        return parts[0], parts[1:]

    venv = str(os.environ.get("VIRTUAL_ENV", "")).strip()
    if venv:
        candidate = pathlib.Path(venv) / "bin" / "airg-server"
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate.resolve()), []

    exe_dir = pathlib.Path(sys.executable).resolve().parent
    candidate = exe_dir / "airg-server"
    if candidate.exists() and os.access(candidate, os.X_OK):
        return str(candidate.resolve()), []

    # Fallback to module execution with current Python interpreter so generated
    # configs are runnable even when airg-server is not on PATH.
    return str(pathlib.Path(sys.executable).resolve()), ["-m", "airg_cli", "server"]


def _claude_code_payload(paths: dict[str, pathlib.Path], profile: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    env = _shared_env(paths, profile["workspace"], profile["agent_id"])
    server_command, server_args = _server_process()
    add_json_payload = {
        "type": "stdio",
        "command": server_command,
        "args": server_args,
        "env": env,
    }
    file_payload = {
        "mcpServers": {
            "ai-runtime-guard": {
                "command": server_command,
                "args": server_args,
                "env": env,
            }
        }
    }
    compact = json.dumps(add_json_payload, separators=(",", ":"))
    command = f"claude mcp add-json ai-runtime-guard {_shell_single_quote(compact)}"
    instructions = (
        "Claude Code preferred setup (CLI):\n"
        f"1. Run:\n   {command}\n\n"
        "Alternative file-based setup:\n"
        "1. Open project MCP config scope (for example .claude.json in the project root, depending on your Claude Code setup).\n"
        "2. Insert the JSON from this file under mcpServers.ai-runtime-guard.\n"
        "3. Restart Claude Code."
    )
    return add_json_payload, file_payload, command, instructions


def _placeholder_payload(paths: dict[str, pathlib.Path], profile: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    env = _shared_env(paths, profile["workspace"], profile["agent_id"])
    server_command, server_args = _server_process()
    server_block = {
        "command": server_command,
        "args": server_args,
        "env": env,
    }
    file_payload = {"mcpServers": {"ai-runtime-guard": server_block}}
    command = f"# Placeholder: {profile['agent_type']} CLI command generation is not implemented yet"
    instructions = (
        f"{profile['agent_type']} config guidance (placeholder):\n"
        "1. Use the generated JSON block in the agent's MCP configuration file.\n"
        "2. Insert under mcpServers.ai-runtime-guard.\n"
        "3. Restart the agent client."
    )
    return server_block, file_payload, command, instructions


def _profile_file_paths(paths: dict[str, pathlib.Path], profile: dict[str, Any]) -> tuple[pathlib.Path, pathlib.Path]:
    prefix = _safe_slug(profile["agent_type"])
    agent_slug = _safe_slug(profile["agent_id"])
    base = _registry_dir(paths) / f"{prefix}-{agent_slug}"
    return base.with_suffix(".json"), pathlib.Path(str(base) + ".instructions.txt")


def load_registry(paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    registry_path = _registry_path(paths)
    payload = _read_json(registry_path, {"profiles": []})
    if not isinstance(payload, dict):
        payload = {"profiles": []}
    profiles = payload.get("profiles")
    if not isinstance(profiles, list):
        profiles = []
    payload["profiles"] = [_normalize_profile(p) for p in profiles if isinstance(p, dict)]
    return payload


def save_registry(paths: dict[str, pathlib.Path], payload: dict[str, Any]) -> None:
    registry_path = _registry_path(paths)
    _ensure_dir(registry_path.parent)
    _write_json(registry_path, payload)


def list_profiles(paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    payload = load_registry(paths)
    return {
        "profiles": payload.get("profiles", []),
        "agent_types": AGENT_TYPES,
        "registry_path": str(_registry_path(paths)),
        "configs_dir": str(_registry_dir(paths)),
        "shared_paths": {
            "AIRG_POLICY_PATH": str(paths["policy_path"]),
            "AIRG_APPROVAL_DB_PATH": str(paths["approval_db_path"]),
            "AIRG_APPROVAL_HMAC_KEY_PATH": str(paths["approval_hmac_key_path"]),
            "AIRG_LOG_PATH": str(paths["log_path"]),
            "AIRG_REPORTS_DB_PATH": str(paths["reports_db_path"]),
        },
    }


def upsert_profile(paths: dict[str, pathlib.Path], profile: dict[str, Any]) -> dict[str, Any]:
    registry = load_registry(paths)
    profiles = registry["profiles"]
    ok, errors, normalized = _validate_profile(profile, existing=profiles)
    if not ok:
        return {"ok": False, "errors": errors}

    replaced = False
    next_profiles: list[dict[str, Any]] = []
    for item in profiles:
        cur = _normalize_profile(item)
        if cur["profile_id"] == normalized["profile_id"]:
            next_profiles.append(normalized)
            replaced = True
        else:
            next_profiles.append(cur)
    if not replaced:
        next_profiles.append(normalized)

    registry["profiles"] = next_profiles
    save_registry(paths, registry)
    return {"ok": True, "profile": normalized, "profiles": next_profiles}


def delete_profile(paths: dict[str, pathlib.Path], profile_id: str) -> dict[str, Any]:
    registry = load_registry(paths)
    profiles = [_normalize_profile(p) for p in registry.get("profiles", [])]
    next_profiles = [p for p in profiles if p["profile_id"] != profile_id]
    if len(next_profiles) == len(profiles):
        return {"ok": False, "errors": ["Profile not found"]}
    registry["profiles"] = next_profiles
    save_registry(paths, registry)
    return {"ok": True, "profiles": next_profiles}


def generate_config(paths: dict[str, pathlib.Path], profile_id: str, *, save_to_file: bool = False) -> dict[str, Any]:
    registry = load_registry(paths)
    profiles = [_normalize_profile(p) for p in registry.get("profiles", [])]
    profile = next((p for p in profiles if p["profile_id"] == profile_id), None)
    if not profile:
        return {"ok": False, "errors": ["Profile not found"]}

    ok, errors, normalized = _validate_profile(profile, existing=profiles)
    if not ok:
        return {"ok": False, "errors": errors}

    if normalized["agent_type"] == "claude_code":
        command_json, file_json, command_text, instructions = _claude_code_payload(paths, normalized)
        placeholder = False
    else:
        command_json, file_json, command_text, instructions = _placeholder_payload(paths, normalized)
        placeholder = True

    generated_at = _now_iso()
    normalized["last_generated_at"] = generated_at

    saved_json_path = ""
    saved_instructions_path = ""
    if save_to_file:
        json_path, instructions_path = _profile_file_paths(paths, normalized)
        _write_json(json_path, file_json)
        _ensure_dir(instructions_path.parent)
        instructions_path.write_text(instructions + "\n")
        saved_json_path = str(json_path)
        saved_instructions_path = str(instructions_path)
        normalized["last_saved_path"] = saved_json_path
        normalized["last_saved_instructions_path"] = saved_instructions_path

    next_profiles: list[dict[str, Any]] = []
    for item in profiles:
        if item["profile_id"] == normalized["profile_id"]:
            next_profiles.append(normalized)
        else:
            next_profiles.append(item)
    registry["profiles"] = next_profiles
    save_registry(paths, registry)

    return {
        "ok": True,
        "profile": normalized,
        "profiles": next_profiles,
        "generated": {
            "agent_type": normalized["agent_type"],
            "generated_at": generated_at,
            "placeholder": placeholder,
            "command_json": command_json,
            "command_text": command_text,
            "file_json": file_json,
            "instructions": instructions,
            "saved_json_path": saved_json_path,
            "saved_instructions_path": saved_instructions_path,
        },
    }


def open_saved_file(paths: dict[str, pathlib.Path], profile_id: str) -> dict[str, Any]:
    registry = load_registry(paths)
    profiles = [_normalize_profile(p) for p in registry.get("profiles", [])]
    profile = next((p for p in profiles if p["profile_id"] == profile_id), None)
    if not profile:
        return {"ok": False, "errors": ["Profile not found"]}
    file_path = str(profile.get("last_saved_path", "")).strip()
    instructions_path = str(profile.get("last_saved_instructions_path", "")).strip()
    if not file_path:
        return {"ok": False, "errors": ["No saved config file for this profile yet"]}
    json_file = pathlib.Path(file_path)
    if not json_file.exists() or not json_file.is_file():
        return {"ok": False, "errors": ["Saved config file not found on disk"]}

    instructions_text = ""
    if instructions_path:
        i_file = pathlib.Path(instructions_path)
        if i_file.exists() and i_file.is_file():
            instructions_text = i_file.read_text()

    return {
        "ok": True,
        "file_path": str(json_file),
        "file_content": json_file.read_text(),
        "instructions_path": instructions_path,
        "instructions_content": instructions_text,
    }
