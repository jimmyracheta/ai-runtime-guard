import json
import os
import pathlib
import re
import shlex
import shutil
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
_AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SCOPE_OPTIONS: dict[str, list[dict[str, str]]] = {
    "claude_code": [
        {"id": "local", "label": "Local"},
        {"id": "project", "label": "Project"},
        {"id": "user", "label": "User"},
    ],
    "codex": [
        {"id": "global", "label": "Global"},
        {"id": "project", "label": "Project"},
    ],
}
_DEFAULT_SCOPE_BY_AGENT = {
    "claude_code": "local",
    "codex": "global",
}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _safe_slug(value: str) -> str:
    out = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "").strip())
    out = "-".join(filter(None, out.split("-")))
    return out or "agent"


def _shell_single_quote(value: str) -> str:
    # Safe single-quote shell encoding: 'abc' -> 'abc', a'b -> 'a'"'"'b'
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _shell_join(tokens: list[str]) -> str:
    return " ".join(shlex.quote(str(token)) for token in tokens if str(token))


def _scope_options_for(agent_type: str) -> list[dict[str, str]]:
    key = str(agent_type or "").strip().lower()
    return list(_SCOPE_OPTIONS.get(key, [{"id": "default", "label": "Default"}]))


def _default_scope_for(agent_type: str) -> str:
    key = str(agent_type or "").strip().lower()
    return str(_DEFAULT_SCOPE_BY_AGENT.get(key, "default"))


def _normalize_scope(agent_type: str, raw_scope: Any) -> str:
    options = _scope_options_for(agent_type)
    allowed = {str(item.get("id", "")).strip().lower() for item in options}
    requested = str(raw_scope or "").strip().lower()
    if requested in allowed:
        return requested
    return _default_scope_for(agent_type)


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
    agent_type = str(profile.get("agent_type") or "claude_code").strip().lower()
    return {
        "profile_id": str(profile.get("profile_id") or uuid.uuid4()),
        "name": str(profile.get("name") or "").strip(),
        "agent_type": agent_type,
        "agent_scope": _normalize_scope(agent_type, profile.get("agent_scope")),
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
    elif not _AGENT_ID_PATTERN.fullmatch(normalized["agent_id"]):
        errors.append(
            "Agent ID must be 1-64 chars and use only letters, numbers, '.', '_' or '-' (no spaces)"
        )

    this_profile_id = normalized["profile_id"]
    for item in existing:
        other = _normalize_profile(item)
        if other["profile_id"] == this_profile_id:
            continue
        if other["agent_id"] and other["agent_id"] == normalized["agent_id"]:
            errors.append(f"Duplicate agent_id: {normalized['agent_id']}")
            break

    return len(errors) == 0, errors, normalized


def _shared_env(_paths: dict[str, pathlib.Path], workspace: str, agent_id: str) -> dict[str, str]:
    return {
        "AIRG_AGENT_ID": agent_id,
        "AIRG_WORKSPACE": workspace,
    }


def _server_process() -> tuple[str, list[str]]:
    explicit = str(os.environ.get("AIRG_SERVER_COMMAND", "")).strip()
    if explicit:
        parts = shlex.split(explicit)
        if not parts:
            return "airg-server", []
        cmd = parts[0]
        args = parts[1:]
        if os.path.isabs(cmd):
            return cmd, args
        resolved = shutil.which(cmd)
        if resolved:
            return str(pathlib.Path(resolved).resolve()), args
        # If explicit is just bare airg-server and unresolved, continue to
        # deterministic fallbacks instead of emitting a fragile PATH-only value.
        if cmd != "airg-server":
            return cmd, args

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
    scope = _normalize_scope("claude_code", profile.get("agent_scope"))
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
    env_flags = " ".join(
        [
            f"--env {shlex.quote(f'AIRG_AGENT_ID={profile['agent_id']}')}",
            f"--env {shlex.quote(f'AIRG_WORKSPACE={profile['workspace']}')}",
        ]
    )
    server_cmd = _shell_join([server_command, *server_args])
    command = f"claude mcp add ai-runtime-guard --scope {scope} {env_flags} -- {server_cmd}".strip()
    remove_command = "claude mcp remove ai-runtime-guard"
    instructions = (
        "Claude Code preferred setup (CLI):\n"
        f"1. Remove previous config if this profile changed:\n   {remove_command}\n"
        f"2. Run:\n   {command}\n\n"
        "Alternative file-based setup:\n"
        "1. Open project MCP config scope (for example .claude.json in the project root, depending on your Claude Code setup).\n"
        "2. Insert the JSON from this file under mcpServers.ai-runtime-guard.\n"
        "3. Restart Claude Code."
    )
    return add_json_payload, file_payload, command, instructions, remove_command


def _codex_payload(paths: dict[str, pathlib.Path], profile: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str, str, str]:
    scope = _normalize_scope("codex", profile.get("agent_scope"))
    env = _shared_env(paths, profile["workspace"], profile["agent_id"])
    server_command, server_args = _server_process()
    server_block = {
        "command": server_command,
        "args": server_args,
        "env": env,
    }
    file_payload = {
        "mcpServers": {
            "ai-runtime-guard": server_block,
        }
    }
    env_flags = " ".join(
        [
            f"--env {shlex.quote(f'AIRG_AGENT_ID={profile['agent_id']}')}",
            f"--env {shlex.quote(f'AIRG_WORKSPACE={profile['workspace']}')}",
        ]
    )
    scope_flag = "--scope project " if scope == "project" else ""
    server_cmd = _shell_join([server_command, *server_args])
    command = f"codex mcp add ai-runtime-guard {scope_flag}{env_flags} -- {server_cmd}".strip()
    remove_command = "codex mcp remove ai-runtime-guard"
    instructions = (
        "Codex preferred setup (CLI):\n"
        f"1. Remove previous config if this profile changed:\n   {remove_command}\n"
        f"2. Run:\n   {command}\n\n"
        "Alternative file-based setup:\n"
        "1. Open ~/.codex/config.toml for global scope or .codex/config.toml in your project for project scope.\n"
        "2. Add ai-runtime-guard under mcp_servers.\n"
        "3. Restart Codex."
    )
    return server_block, file_payload, command, instructions, remove_command


def _placeholder_payload(paths: dict[str, pathlib.Path], profile: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str, str, str]:
    env = _shared_env(paths, profile["workspace"], profile["agent_id"])
    server_command, server_args = _server_process()
    server_block = {
        "command": server_command,
        "args": server_args,
        "env": env,
    }
    file_payload = {"mcpServers": {"ai-runtime-guard": server_block}}
    command = f"# Placeholder: {profile['agent_type']} CLI command generation is not implemented yet"
    remove_command = f"# Placeholder: remove command for {profile['agent_type']} is not implemented yet"
    instructions = (
        f"{profile['agent_type']} config guidance (placeholder):\n"
        "1. Use the generated JSON block in the agent's MCP configuration file.\n"
        "2. Insert under mcpServers.ai-runtime-guard.\n"
        "3. Restart the agent client."
    )
    return server_block, file_payload, command, instructions, remove_command


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
        "agent_scopes": {item["id"]: _scope_options_for(item["id"]) for item in AGENT_TYPES},
        "registry_path": str(_registry_path(paths)),
        "configs_dir": str(_registry_dir(paths)),
        "mcp_env_required": ["AIRG_AGENT_ID", "AIRG_WORKSPACE"],
        "mcp_env_note": "Runtime state paths are global defaults and do not need per-agent MCP env entries.",
    }


def upsert_profile(paths: dict[str, pathlib.Path], profile: dict[str, Any], *, create_workspace: bool = False) -> dict[str, Any]:
    registry = load_registry(paths)
    profiles = registry["profiles"]
    ok, errors, normalized = _validate_profile(profile, existing=profiles)
    if not ok:
        return {"ok": False, "errors": errors}

    workspace_path = pathlib.Path(normalized["workspace"]).expanduser()
    if not workspace_path.exists():
        if create_workspace:
            try:
                workspace_path.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                return {
                    "ok": False,
                    "errors": [f"Failed to create workspace directory: {workspace_path} ({exc})"],
                }
        else:
            return {
                "ok": False,
                "workspace_missing": True,
                "workspace": str(workspace_path),
                "errors": [f"Workspace does not exist: {workspace_path}"],
            }
    elif not workspace_path.is_dir():
        return {
            "ok": False,
            "errors": [f"Workspace path is not a directory: {workspace_path}"],
        }
    normalized["workspace"] = str(workspace_path.resolve())

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
        command_json, file_json, command_text, instructions, remove_command = _claude_code_payload(paths, normalized)
        placeholder = False
    elif normalized["agent_type"] == "codex":
        command_json, file_json, command_text, instructions, remove_command = _codex_payload(paths, normalized)
        placeholder = False
    else:
        command_json, file_json, command_text, instructions, remove_command = _placeholder_payload(paths, normalized)
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
            "remove_command": remove_command,
            "file_json": file_json,
            "instructions": instructions,
            "saved_json_path": saved_json_path,
            "saved_instructions_path": saved_instructions_path,
        },
    }


def bootstrap_default_profile(
    paths: dict[str, pathlib.Path],
    *,
    workspace: str,
    agent_id: str,
    agent_type: str = "claude_code",
) -> dict[str, Any]:
    profile = {
        "profile_id": "default-agent",
        "name": "Default Agent",
        "agent_type": agent_type,
        "workspace": workspace,
        "agent_id": agent_id,
    }
    upsert = upsert_profile(paths, profile, create_workspace=True)
    if not upsert.get("ok"):
        return upsert
    return generate_config(paths, "default-agent", save_to_file=True)


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
