import json
import os
import pathlib
import re
import shlex
import shutil
import sys
import tomllib
from datetime import UTC, datetime
from typing import Any

import agent_configs

CLAUDE_SCOPES = {"project", "local", "user"}
CURSOR_SCOPES = {"project", "global"}
CODEX_SCOPES = {"global", "project"}

_CLAUDE_JSON_MISSING = (
    "~/.claude.json not found. Claude Code may not have been initialised for this user. "
    "Please run Claude Code at least once, then retry. If the Claude settings file is saved in "
    "a different location, please manually apply the MCP config using the Copy buttons."
)
_INVALID_JSON_MESSAGE = (
    "The target file contains invalid JSON. Please fix it manually or back it up before AIRG can apply."
)
_INVALID_TOML_MESSAGE = (
    "The target file appears to have unsupported TOML structure for AIRG codex MCP updates. "
    "Please fix it manually or back it up before AIRG can apply."
)
AIRG_MCP_TOOLS = [
    "server_info",
    "restore_backup",
    "execute_command",
    "read_file",
    "write_file",
    "edit_file",
    "delete_file",
    "list_directory",
]
_CODEX_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")
_CODEX_TRUST_LEVEL_RE = re.compile(r'^(\s*trust_level\s*=\s*)".*?"(\s*(?:#.*)?)$')


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _deep_copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _state_dir(paths: dict[str, pathlib.Path]) -> pathlib.Path:
    return paths["approval_db_path"].expanduser().resolve().parent


def _backups_dir(paths: dict[str, pathlib.Path]) -> pathlib.Path:
    out = _state_dir(paths) / "mcp-configs" / "backups"
    out.mkdir(parents=True, exist_ok=True)
    return out


def _safe_slug(value: str) -> str:
    out = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "").strip())
    out = "-".join(filter(None, out.split("-")))
    return out or "agent"


def _backup_file(paths: dict[str, pathlib.Path], target: pathlib.Path, agent_id: str) -> pathlib.Path | None:
    if not target.exists() or not target.is_file():
        return None
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_name = f"{_safe_slug(agent_id)}_{ts}_{target.name}"
    backup_path = _backups_dir(paths) / backup_name
    shutil.copy2(target, backup_path)
    return backup_path


def _home() -> pathlib.Path:
    return pathlib.Path.home().expanduser().resolve()


def _workspace_path(profile: dict[str, Any]) -> pathlib.Path:
    raw = str(profile.get("workspace", "")).strip()
    if not raw:
        raise ValueError("Workspace is required")
    workspace = pathlib.Path(raw).expanduser().resolve()
    if not workspace.exists() or not workspace.is_dir():
        raise ValueError(f"Workspace does not exist or is not a directory: {workspace}")
    return workspace


def _claude_desktop_config_path() -> pathlib.Path:
    system = os.name
    if system == "nt":
        appdata = str(os.environ.get("APPDATA", "")).strip()
        if appdata:
            return pathlib.Path(appdata).expanduser().resolve() / "Claude" / "claude_desktop_config.json"
        return _home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    if sys.platform == "darwin":
        return _home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    return _home() / ".config" / "Claude" / "claude_desktop_config.json"


def _codex_config_path(workspace: pathlib.Path, scope: str) -> pathlib.Path:
    if scope == "project":
        return workspace / ".codex" / "config.toml"
    return _home() / ".codex" / "config.toml"


def _codex_user_config_path() -> pathlib.Path:
    return _home() / ".codex" / "config.toml"


def _cursor_config_path(workspace: pathlib.Path, scope: str) -> pathlib.Path:
    if scope == "global":
        return _home() / ".cursor" / "mcp.json"
    return workspace / ".cursor" / "mcp.json"


def _normalize_scope(agent_type: str, raw_scope: Any) -> str:
    normalized = str(agent_type or "").strip().lower()
    if normalized == "claude_desktop":
        return "desktop"
    if normalized == "cursor":
        requested = str(raw_scope or "").strip().lower()
        if requested in CURSOR_SCOPES:
            return requested
        return "project"
    if normalized == "codex":
        requested = str(raw_scope or "").strip().lower()
        if requested in CODEX_SCOPES:
            return requested
        return "global"
    requested = str(raw_scope or "").strip().lower()
    if requested in CLAUDE_SCOPES:
        return requested
    return "project"


def _server_process() -> tuple[str, list[str]]:
    explicit = str(os.environ.get("AIRG_SERVER_COMMAND", "")).strip()
    if explicit:
        parts = shlex.split(explicit)
        if parts:
            cmd = parts[0]
            args = parts[1:]
            if os.path.isabs(cmd) and os.access(cmd, os.X_OK):
                return cmd, args
    # Deterministic default for generated configs: current interpreter module entrypoint.
    return str(pathlib.Path(sys.executable).resolve()), ["-m", "airg_cli", "server"]


def _server_block(workspace: pathlib.Path, agent_id: str) -> dict[str, Any]:
    command, args = _server_process()
    return {
        "command": command,
        "args": args,
        "env": {
            "AIRG_AGENT_ID": str(agent_id or "").strip() or "default",
            "AIRG_WORKSPACE": str(workspace),
        },
    }


def _target_file_for_scope(agent_type: str, workspace: pathlib.Path, scope: str) -> pathlib.Path:
    normalized = str(agent_type or "").strip().lower()
    if normalized == "claude_desktop":
        return _claude_desktop_config_path()
    if normalized == "cursor":
        return _cursor_config_path(workspace, scope)
    if normalized == "codex":
        return _codex_config_path(workspace, scope)
    if scope == "project":
        return workspace / ".mcp.json"
    return _home() / ".claude.json"


def _settings_local_path(workspace: pathlib.Path) -> pathlib.Path:
    return workspace / ".claude" / "settings.local.json"


def _cleanup_empty_dicts(payload: dict[str, Any], keys: list[str]) -> None:
    cursor: Any = payload
    chain: list[tuple[dict[str, Any], str]] = []
    for key in keys:
        if not isinstance(cursor, dict) or key not in cursor:
            return
        chain.append((cursor, key))
        cursor = cursor[key]
    for parent, key in reversed(chain):
        value = parent.get(key)
        if isinstance(value, dict) and not value:
            parent.pop(key, None)
            continue
        if isinstance(value, list) and not value:
            parent.pop(key, None)
            continue
        break


def _sync_settings_local_allowlist(
    paths: dict[str, pathlib.Path],
    workspace: pathlib.Path,
    *,
    ensure_enabled: bool,
    agent_id: str,
) -> dict[str, Any]:
    target = _settings_local_path(workspace)
    before_exists = target.exists()
    before_payload = _read_json_strict(target) if before_exists else {}
    if not isinstance(before_payload, dict):
        before_payload = {}
    after = _deep_copy(before_payload)

    changed = False
    enabled = after.get("enabledMcpjsonServers")
    if ensure_enabled:
        if not isinstance(enabled, list):
            enabled = []
            after["enabledMcpjsonServers"] = enabled
            changed = True
        if "ai-runtime-guard" not in enabled:
            enabled.append("ai-runtime-guard")
            changed = True
    else:
        if isinstance(enabled, list):
            filtered = [item for item in enabled if str(item).strip() != "ai-runtime-guard"]
            if filtered != enabled:
                changed = True
            if filtered:
                after["enabledMcpjsonServers"] = filtered
            else:
                after.pop("enabledMcpjsonServers", None)

    permissions = after.get("permissions")
    if not isinstance(permissions, dict):
        permissions = {}
        if ensure_enabled:
            after["permissions"] = permissions
            changed = True
    allow = permissions.get("allow")
    if ensure_enabled:
        if not isinstance(allow, list):
            allow = []
            permissions["allow"] = allow
            changed = True
        for tool_name in AIRG_MCP_TOOLS:
            token = f"mcp__ai-runtime-guard__{tool_name}"
            if token not in allow:
                allow.append(token)
                changed = True
    else:
        if isinstance(allow, list):
            filtered_allow = [item for item in allow if not str(item).strip().startswith("mcp__ai-runtime-guard__")]
            if filtered_allow != allow:
                changed = True
            if filtered_allow:
                permissions["allow"] = filtered_allow
            else:
                permissions.pop("allow", None)
        _cleanup_empty_dicts(after, ["permissions"])

    if not changed:
        return {
            "target_path": str(target),
            "changed": False,
            "backup_path": "",
            "created": False,
        }

    target.parent.mkdir(parents=True, exist_ok=True)
    backup = _backup_file(paths, target, agent_id)
    try:
        _write_json_verified(target, after)
    except Exception:
        if before_exists and backup and backup.exists():
            shutil.copy2(backup, target)
        elif not before_exists and target.exists():
            try:
                target.unlink()
            except Exception:
                pass
        raise

    return {
        "target_path": str(target),
        "changed": True,
        "backup_path": str(backup) if backup else "",
        "created": not before_exists,
    }


def _read_json_strict(path: pathlib.Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(_INVALID_JSON_MESSAGE) from exc
    except Exception as exc:  # pragma: no cover - OS-level read failures
        raise RuntimeError(f"Failed to read `{path}`: {exc}. Check file permissions and try again.") from exc
    if not isinstance(payload, dict):
        raise ValueError(_INVALID_JSON_MESSAGE)
    return payload


def _write_json_verified(path: pathlib.Path, payload: dict[str, Any]) -> None:
    text = json.dumps(payload, indent=2) + "\n"
    try:
        path.write_text(text)
    except Exception as exc:  # pragma: no cover - OS-level write failures
        raise RuntimeError(
            f"Failed to write to `{path}`: {exc}. You can apply manually using the Copy buttons."
        ) from exc
    try:
        verify = _read_json_strict(path)
    except Exception as exc:
        raise RuntimeError(f"Write appeared to succeed but verification failed. Please check the file manually at `{path}`.") from exc
    if _canonical(verify) != _canonical(payload):
        raise RuntimeError(f"Write appeared to succeed but verification failed. Please check the file manually at `{path}`.")


def _read_text_strict(path: pathlib.Path) -> str:
    try:
        return path.read_text()
    except Exception as exc:  # pragma: no cover - OS-level read failures
        raise RuntimeError(f"Failed to read `{path}`: {exc}. Check file permissions and try again.") from exc


def _merge_text_parts(before: str, middle: str, after: str) -> str:
    pieces = [part for part in [before.rstrip("\n"), middle.strip("\n"), after.lstrip("\n")] if part]
    return ("\n\n".join(pieces).rstrip() + "\n") if pieces else ""


def _toml_section_records(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    lines = text.splitlines(keepends=True)
    current_name = ""
    current_start = -1
    offset = 0
    for line in lines:
        match = _CODEX_SECTION_RE.match(line)
        if match:
            if current_name:
                records.append({"name": current_name, "start": current_start, "end": offset})
            current_name = str(match.group(1)).strip()
            current_start = offset
        offset += len(line)
    if current_name:
        records.append({"name": current_name, "start": current_start, "end": offset})
    return records


def _replace_or_append_toml_block(
    text: str,
    *,
    managed_sections: list[str],
    replacement: str,
) -> tuple[str, bool]:
    records = _toml_section_records(text)
    managed = [record for record in records if record["name"] in managed_sections]
    if not managed:
        if not replacement.strip():
            return text, False
        if not text.strip():
            return replacement.strip() + "\n", True
        suffix = "" if text.endswith("\n\n") else "\n" if text.endswith("\n") else "\n\n"
        return text + suffix + replacement.strip() + "\n", True
    start = int(managed[0]["start"])
    end = int(managed[-1]["end"])
    updated = _merge_text_parts(text[:start], replacement, text[end:])
    return updated, updated != text


def _codex_project_section_name(workspace: pathlib.Path) -> str:
    escaped = str(workspace).replace("\\", "\\\\").replace('"', '\\"')
    return f'projects."{escaped}"'


def _codex_project_section_state(text: str, workspace: pathlib.Path) -> dict[str, Any]:
    section_name = _codex_project_section_name(workspace)
    for record in _toml_section_records(text):
        if record["name"] != section_name:
            continue
        section_text = text[int(record["start"]):int(record["end"])]
        trust_level = ""
        has_other_settings = False
        for raw_line in section_text.splitlines()[1:]:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("trust_level"):
                parts = stripped.split("=", 1)
                if len(parts) == 2:
                    trust_level = parts[1].strip().strip('"')
                continue
            has_other_settings = True
        return {
            "section_name": section_name,
            "section_exists": True,
            "section_text": section_text,
            "trust_level": trust_level,
            "trusted": trust_level == "trusted",
            "has_other_settings": has_other_settings,
            "start": int(record["start"]),
            "end": int(record["end"]),
        }
    return {
        "section_name": section_name,
        "section_exists": False,
        "section_text": "",
        "trust_level": "",
        "trusted": False,
        "has_other_settings": False,
        "start": -1,
        "end": -1,
    }


def _set_codex_project_trust(text: str, workspace: pathlib.Path) -> tuple[str, bool, dict[str, Any]]:
    state = _codex_project_section_state(text, workspace)
    if state["section_exists"]:
        lines = state["section_text"].splitlines()
        next_lines = [lines[0]]
        trust_written = False
        for line in lines[1:]:
            match = _CODEX_TRUST_LEVEL_RE.match(line)
            if match:
                next_lines.append(f'{match.group(1)}"trusted"{match.group(2)}')
                trust_written = True
            else:
                next_lines.append(line)
        if not trust_written:
            next_lines.append('trust_level = "trusted"')
        replacement = "\n".join(next_lines).rstrip() + "\n"
        updated = _merge_text_parts(text[: int(state["start"])], replacement, text[int(state["end"]):])
        return updated, updated != text, state

    replacement = f'[{state["section_name"]}]\ntrust_level = "trusted"\n'
    if not text.strip():
        updated = replacement
    else:
        suffix = "" if text.endswith("\n\n") else "\n" if text.endswith("\n") else "\n\n"
        updated = text + suffix + replacement
    return updated, updated != text, state


def _restore_codex_project_trust_text(
    text: str,
    workspace: pathlib.Path,
    metadata: dict[str, Any],
) -> tuple[str, bool]:
    state = _codex_project_section_state(text, workspace)
    if bool(metadata.get("section_present", False)):
        replacement = str(metadata.get("section_text") or "").rstrip() + "\n"
        if state["section_exists"]:
            updated = _merge_text_parts(text[: int(state["start"])], replacement, text[int(state["end"]):])
        else:
            if not text.strip():
                updated = replacement
            else:
                suffix = "" if text.endswith("\n\n") else "\n" if text.endswith("\n") else "\n\n"
                updated = text + suffix + replacement
        return updated, updated != text
    if not state["section_exists"]:
        return text, False
    updated = _merge_text_parts(text[: int(state["start"])], "", text[int(state["end"]):])
    return updated, updated != text


def _toml_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _toml_string(value: str) -> str:
    return f'"{_toml_escape(value)}"'


def _toml_list(values: list[str]) -> str:
    return "[" + ", ".join(_toml_string(v) for v in values) + "]"


def _codex_airg_block(server_entry: dict[str, Any]) -> str:
    command = str(server_entry.get("command", "")).strip()
    args = [str(v) for v in (server_entry.get("args") or [])]
    env = server_entry.get("env") if isinstance(server_entry.get("env"), dict) else {}
    lines = [
        "[mcp_servers.ai-runtime-guard]",
        f"command = {_toml_string(command)}",
        f"args = {_toml_list(args)}",
        "",
        "[mcp_servers.ai-runtime-guard.env]",
    ]
    for key in sorted(env.keys()):
        lines.append(f"{key} = {_toml_string(str(env[key]))}")
    return "\n".join(lines).rstrip() + "\n"


def _remove_codex_airg_sections(text: str) -> tuple[str, bool]:
    cleaned, changed = _replace_or_append_toml_block(
        text,
        managed_sections=["mcp_servers.ai-runtime-guard", "mcp_servers.ai-runtime-guard.env"],
        replacement="",
    )
    return cleaned, changed


def _codex_has_airg_section(text: str) -> bool:
    for line in text.splitlines():
        m = _CODEX_SECTION_RE.match(line)
        if not m:
            continue
        section = str(m.group(1)).strip()
        if section == "mcp_servers.ai-runtime-guard":
            return True
    return False


def _write_text_verified(path: pathlib.Path, text: str) -> None:
    try:
        path.write_text(text)
    except Exception as exc:  # pragma: no cover - OS-level write failures
        raise RuntimeError(
            f"Failed to write to `{path}`: {exc}. You can apply manually using the Copy buttons."
        ) from exc
    verify = _read_text_strict(path)
    if verify != text:
        raise RuntimeError(f"Write appeared to succeed but verification failed. Please check the file manually at `{path}`.")


def _write_codex_verified(path: pathlib.Path, text: str) -> None:
    _write_text_verified(path, text)
    try:
        tomllib.loads(text)
    except Exception as exc:
        raise RuntimeError(f"Write produced invalid TOML at `{path}`: {exc}") from exc
    verify = _read_text_strict(path)
    if not _codex_has_airg_section(verify):
        raise RuntimeError(f"Write appeared to succeed but verification failed. Please check the file manually at `{path}`.")


def _ensure_claude_json_exists(path: pathlib.Path) -> None:
    if path.exists() and path.is_file():
        return
    raise FileNotFoundError(_CLAUDE_JSON_MISSING)


def _ensure_mcp_servers(payload: dict[str, Any]) -> dict[str, Any]:
    servers = payload.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
        payload["mcpServers"] = servers
    return servers


def _ensure_project_entry(payload: dict[str, Any], workspace: pathlib.Path) -> dict[str, Any]:
    projects = payload.get("projects")
    if not isinstance(projects, dict):
        projects = {}
        payload["projects"] = projects
    key = str(workspace)
    project_entry = projects.get(key)
    if not isinstance(project_entry, dict):
        project_entry = {}
        projects[key] = project_entry
    return project_entry


def _apply_airg_entry(payload: dict[str, Any], scope: str, workspace: pathlib.Path, block: dict[str, Any]) -> dict[str, Any]:
    after = _deep_copy(payload)
    if scope in {"project", "global", "user", "desktop"}:
        _ensure_mcp_servers(after)["ai-runtime-guard"] = block
        return after
    project_entry = _ensure_project_entry(after, workspace)
    servers = project_entry.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
        project_entry["mcpServers"] = servers
    servers["ai-runtime-guard"] = block
    return after


def _remove_airg_entry(payload: dict[str, Any], scope: str, workspace: pathlib.Path) -> tuple[dict[str, Any], bool]:
    after = _deep_copy(payload)
    if scope in {"project", "global", "user", "desktop"}:
        servers = after.get("mcpServers")
        if not isinstance(servers, dict):
            return after, False
        existed = "ai-runtime-guard" in servers
        servers.pop("ai-runtime-guard", None)
        if not servers:
            after.pop("mcpServers", None)
        return after, existed

    projects = after.get("projects")
    if not isinstance(projects, dict):
        return after, False
    key = str(workspace)
    entry = projects.get(key)
    if not isinstance(entry, dict):
        return after, False
    servers = entry.get("mcpServers")
    if not isinstance(servers, dict):
        return after, False
    existed = "ai-runtime-guard" in servers
    servers.pop("ai-runtime-guard", None)
    if not servers:
        entry.pop("mcpServers", None)
    return after, existed


def _validate_profile(profile: dict[str, Any]) -> tuple[str, pathlib.Path, str, str]:
    agent_type = str(profile.get("agent_type", "")).strip().lower()
    if agent_type not in {"claude_code", "claude_desktop", "cursor", "codex"}:
        raise ValueError("Only Claude Code, Claude Desktop, Cursor, and Codex MCP apply/remove are supported in this pass.")
    workspace = _workspace_path(profile)
    scope = _normalize_scope(agent_type, profile.get("agent_scope"))
    agent_id = str(profile.get("agent_id") or "").strip() or "default"
    return agent_type, workspace, scope, agent_id


def _normalize_last_applied(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    scope = str(raw.get("scope") or "").strip().lower()
    file_path = str(raw.get("file_path") or "").strip()
    timestamp = str(raw.get("timestamp") or "").strip()
    if not (scope and file_path and timestamp):
        return None
    return {
        "scope": scope,
        "file_path": file_path,
        "timestamp": timestamp,
        "workspace": str(raw.get("workspace") or "").strip(),
        "agent_id": str(raw.get("agent_id") or "").strip(),
        "agent_type": str(raw.get("agent_type") or "").strip().lower(),
        "created_by_airg": bool(raw.get("created_by_airg", False)),
        "codex_project_trust": raw.get("codex_project_trust") if isinstance(raw.get("codex_project_trust"), dict) else None,
    }


def _codex_trust_plan(workspace: pathlib.Path, previous: dict[str, Any] | None) -> dict[str, Any] | None:
    trust_path = _codex_user_config_path()
    before_text = trust_path.read_text() if trust_path.exists() else ""
    current = _codex_project_section_state(before_text, workspace)
    previous_trust = previous.get("codex_project_trust") if isinstance(previous, dict) else None
    previous_workspace = str(previous_trust.get("workspace") or "").strip() if isinstance(previous_trust, dict) else ""
    previous_managed = bool(previous_trust.get("managed", False)) if isinstance(previous_trust, dict) else False
    previous_restore_needed = previous_managed and previous_workspace and previous_workspace != str(workspace)
    return {
        "supported": True,
        "config_path": str(trust_path),
        "workspace": str(workspace),
        "trusted": bool(current.get("trusted", False)),
        "manage_choice_required": not bool(current.get("trusted", False)),
        "previous_managed": previous_managed,
        "previous_workspace": previous_workspace,
        "previous_restore_needed": previous_restore_needed,
    }


def _build_plan(profile: dict[str, Any]) -> dict[str, Any]:
    agent_type, workspace, scope, agent_id = _validate_profile(profile)
    target_path = _target_file_for_scope(agent_type, workspace, scope)
    previous = _normalize_last_applied(profile.get("last_applied"))

    scope_changed = False
    workspace_changed = False
    agent_id_changed = False
    target_changed = False
    requires_previous_choice = False
    must_remove_previous = False

    if previous:
        old_scope = str(previous.get("scope") or "").strip().lower()
        old_workspace = str(previous.get("workspace") or "").strip()
        old_agent_id = str(previous.get("agent_id") or "").strip()
        old_target = str(previous.get("file_path") or "").strip()

        scope_changed = old_scope != scope
        workspace_changed = bool(old_workspace) and old_workspace != str(workspace)
        agent_id_changed = bool(old_agent_id) and old_agent_id != agent_id
        target_changed = bool(old_target) and old_target != str(target_path)

        if scope_changed:
            must_remove_previous = True
        elif target_changed and (workspace_changed or agent_id_changed):
            requires_previous_choice = True

    return {
        "agent_type": agent_type,
        "scope": scope,
        "workspace": str(workspace),
        "agent_id": agent_id,
        "target_path": str(target_path),
        "server_entry": _server_block(workspace, agent_id),
        "preview_json": {"mcpServers": {"ai-runtime-guard": _server_block(workspace, agent_id)}},
        "previous": previous,
        "scope_changed": scope_changed,
        "workspace_changed": workspace_changed,
        "agent_id_changed": agent_id_changed,
        "target_changed": target_changed,
        "must_remove_previous": must_remove_previous,
        "requires_previous_choice": requires_previous_choice,
        "codex_project_trust": _codex_trust_plan(workspace, previous) if agent_type == "codex" and scope == "project" else None,
    }


def plan_apply(paths: dict[str, pathlib.Path], profile: dict[str, Any]) -> dict[str, Any]:
    try:
        plan = _build_plan(profile)
        return {"ok": True, "plan": plan}
    except Exception as exc:
        return {"ok": False, "errors": [str(exc)]}


def _apply_for_scope(paths: dict[str, pathlib.Path], plan: dict[str, Any]) -> dict[str, Any]:
    agent_type = str(plan.get("agent_type", "")).strip().lower()
    if agent_type == "codex":
        return _apply_for_scope_codex(paths, plan)

    workspace = pathlib.Path(str(plan["workspace"])).resolve()
    scope = str(plan["scope"])
    target = pathlib.Path(str(plan["target_path"])).expanduser().resolve()
    agent_id = str(plan["agent_id"])
    server_entry = _deep_copy(plan["server_entry"])

    before_exists = target.exists()
    before_payload: dict[str, Any]
    if before_exists:
        before_payload = _read_json_strict(target)
    else:
        if agent_type == "claude_code" and scope in {"local", "user"}:
            _ensure_claude_json_exists(target)
            before_payload = _read_json_strict(target)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            before_payload = {}

    after_payload = _apply_airg_entry(before_payload, scope, workspace, server_entry)
    if _canonical(after_payload) == _canonical(before_payload):
        return {
            "scope": scope,
            "target_path": str(target),
            "changed": False,
            "backup_path": "",
            "created_by_airg": bool(plan["previous"] and plan["previous"].get("created_by_airg", False)),
        }

    backup = _backup_file(paths, target, agent_id)
    try:
        _write_json_verified(target, after_payload)
    except Exception:
        if before_exists and backup and backup.exists():
            shutil.copy2(backup, target)
        elif not before_exists and target.exists():
            try:
                target.unlink()
            except Exception:
                pass
        raise

    verify_payload = _read_json_strict(target)
    verify_removed, has_entry = _remove_airg_entry(verify_payload, scope, workspace)
    # has_entry here means entry existed pre-removal of verification payload.
    if not has_entry:
        raise RuntimeError(f"Write appeared to succeed but verification failed. Please check the file manually at `{target}`.")

    return {
        "scope": scope,
        "target_path": str(target),
        "changed": True,
        "backup_path": str(backup) if backup else "",
        "created_by_airg": scope == "project" and not before_exists,
        "before_missing": not before_exists,
    }


def _apply_for_scope_codex(paths: dict[str, pathlib.Path], plan: dict[str, Any]) -> dict[str, Any]:
    scope = str(plan["scope"]).strip().lower()
    target = pathlib.Path(str(plan["target_path"])).expanduser().resolve()
    agent_id = str(plan["agent_id"])
    server_entry = _deep_copy(plan["server_entry"])

    before_exists = target.exists()
    if before_exists:
        before_text = _read_text_strict(target)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        before_text = ""

    cleaned_before, _ = _remove_codex_airg_sections(before_text)
    block = _codex_airg_block(server_entry)
    after_text, _ = _replace_or_append_toml_block(
        cleaned_before,
        managed_sections=["mcp_servers.ai-runtime-guard", "mcp_servers.ai-runtime-guard.env"],
        replacement=block,
    )

    if after_text == before_text:
        return {
            "scope": scope,
            "target_path": str(target),
            "changed": False,
            "backup_path": "",
            "created_by_airg": bool(plan["previous"] and plan["previous"].get("created_by_airg", False)),
        }

    backup = _backup_file(paths, target, agent_id)
    try:
        _write_codex_verified(target, after_text)
    except Exception:
        if before_exists and backup and backup.exists():
            shutil.copy2(backup, target)
        elif not before_exists and target.exists():
            try:
                target.unlink()
            except Exception:
                pass
        raise

    return {
        "scope": scope,
        "target_path": str(target),
        "changed": True,
        "backup_path": str(backup) if backup else "",
        "created_by_airg": not before_exists,
        "before_missing": not before_exists,
    }


def _remove_from_last_applied(
    paths: dict[str, pathlib.Path],
    previous: dict[str, Any],
    *,
    strict_missing_file: bool,
) -> dict[str, Any]:
    scope = str(previous.get("scope") or "").strip().lower()
    previous_agent_type = str(previous.get("agent_type") or "").strip().lower()
    workspace_raw = str(previous.get("workspace") or "").strip()
    workspace = pathlib.Path(workspace_raw).expanduser().resolve() if workspace_raw else None
    target = pathlib.Path(str(previous.get("file_path") or "")).expanduser().resolve()
    agent_id = str(previous.get("agent_id") or "").strip() or "default"

    if not str(target):
        raise RuntimeError("Missing previous MCP target path")
    if not target.exists():
        if strict_missing_file:
            raise RuntimeError(f"Failed to remove previous MCP config from `{target}`: file not found")
        return {"removed": False, "target_path": str(target), "backup_path": "", "deleted_file": False}

    inferred_codex = target.suffix.lower() == ".toml" and target.name == "config.toml"
    if previous_agent_type == "codex" or inferred_codex:
        before_text = _read_text_strict(target)
        cleaned_text, removed = _remove_codex_airg_sections(before_text)
        if not removed:
            return {"removed": False, "target_path": str(target), "backup_path": "", "deleted_file": False}
        backup = _backup_file(paths, target, agent_id)
        delete_file = bool(previous.get("created_by_airg", False)) and not cleaned_text.strip()
        if delete_file:
            try:
                target.unlink()
            except Exception as exc:
                raise RuntimeError(f"Failed to remove previous MCP config from `{target}`: {exc}") from exc
            return {
                "removed": True,
                "target_path": str(target),
                "backup_path": str(backup) if backup else "",
                "deleted_file": True,
            }
        try:
            if cleaned_text.strip():
                _write_text_verified(target, cleaned_text)
                tomllib.loads(cleaned_text)
            else:
                target.write_text("")
        except Exception as exc:
            raise RuntimeError(f"Failed to write `{target}` after codex MCP cleanup: {exc}") from exc
        return {
            "removed": True,
            "target_path": str(target),
            "backup_path": str(backup) if backup else "",
            "deleted_file": False,
        }

    before_payload = _read_json_strict(target)
    if scope == "local" and workspace is None:
        raise RuntimeError(f"Failed to remove previous MCP config from `{target}`: missing previous workspace metadata")

    cleaned, had_entry = _remove_airg_entry(before_payload, scope, workspace or pathlib.Path("/"))
    if not had_entry:
        return {"removed": False, "target_path": str(target), "backup_path": "", "deleted_file": False}

    backup = _backup_file(paths, target, agent_id)
    delete_project_file = (
        scope == "project"
        and bool(previous.get("created_by_airg", False))
        and not cleaned.get("mcpServers")
    )

    if delete_project_file:
        try:
            target.unlink()
        except Exception as exc:
            raise RuntimeError(f"Failed to remove previous MCP config from `{target}`: {exc}") from exc
        return {
            "removed": True,
            "target_path": str(target),
            "backup_path": str(backup) if backup else "",
            "deleted_file": True,
        }

    _write_json_verified(target, cleaned)
    return {
        "removed": True,
        "target_path": str(target),
        "backup_path": str(backup) if backup else "",
        "deleted_file": False,
    }


def _apply_codex_project_trust(
    paths: dict[str, pathlib.Path],
    workspace: pathlib.Path,
    agent_id: str,
) -> dict[str, Any]:
    target = _codex_user_config_path()
    before_exists = target.exists()
    before_text = _read_text_strict(target) if before_exists else ""
    after_text, changed, state = _set_codex_project_trust(before_text, workspace)
    if not changed:
        return {
            "changed": False,
            "target_path": str(target),
            "backup_path": "",
            "metadata": {
                "managed": False,
                "config_path": str(target),
                "workspace": str(workspace),
                "before_exists": before_exists,
                "section_present": bool(state.get("section_exists", False)),
                "section_text": str(state.get("section_text", "")),
            },
        }

    target.parent.mkdir(parents=True, exist_ok=True)
    backup = _backup_file(paths, target, agent_id)
    try:
        _write_text_verified(target, after_text)
        tomllib.loads(after_text)
    except Exception:
        if before_exists and backup and backup.exists():
            shutil.copy2(backup, target)
        elif not before_exists and target.exists():
            try:
                target.unlink()
            except Exception:
                pass
        raise

    return {
        "changed": True,
        "target_path": str(target),
        "backup_path": str(backup) if backup else "",
        "metadata": {
            "managed": True,
            "config_path": str(target),
            "workspace": str(workspace),
            "before_exists": before_exists,
            "section_present": bool(state.get("section_exists", False)),
            "section_text": str(state.get("section_text", "")),
        },
    }


def _restore_codex_project_trust(
    paths: dict[str, pathlib.Path],
    metadata: dict[str, Any],
    agent_id: str,
) -> dict[str, Any]:
    target = pathlib.Path(str(metadata.get("config_path") or "")).expanduser().resolve()
    workspace_raw = str(metadata.get("workspace") or "").strip()
    if not str(target) or not workspace_raw:
        return {"restored": False, "target_path": str(target), "backup_path": ""}
    workspace = pathlib.Path(workspace_raw).expanduser().resolve()
    before_exists = target.exists()
    before_text = _read_text_strict(target) if before_exists else ""
    after_text, changed = _restore_codex_project_trust_text(before_text, workspace, metadata)
    if not changed:
        return {"restored": False, "target_path": str(target), "backup_path": ""}

    backup = _backup_file(paths, target, agent_id)
    if not after_text.strip():
        try:
            if target.exists():
                target.unlink()
        except Exception as exc:
            raise RuntimeError(f"Failed to remove Codex trust config from `{target}`: {exc}") from exc
        return {"restored": True, "target_path": str(target), "backup_path": str(backup) if backup else "", "deleted_file": True}

    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        _write_text_verified(target, after_text)
        tomllib.loads(after_text)
    except Exception:
        if before_exists and backup and backup.exists():
            shutil.copy2(backup, target)
        elif not before_exists and target.exists():
            try:
                target.unlink()
            except Exception:
                pass
        raise
    return {"restored": True, "target_path": str(target), "backup_path": str(backup) if backup else "", "deleted_file": False}


def apply_mcp_config(
    paths: dict[str, pathlib.Path],
    profile: dict[str, Any],
    *,
    remove_previous: bool | None = None,
    manage_codex_trust: bool | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    planned = plan_apply(paths, profile)
    if not planned.get("ok"):
        return planned

    plan = planned["plan"]
    if dry_run:
        return {"ok": True, "plan": plan, "dry_run": True}

    previous = plan.get("previous")
    must_remove_previous = bool(plan.get("must_remove_previous", False))
    requires_choice = bool(plan.get("requires_previous_choice", False))
    trust_plan = plan.get("codex_project_trust") if isinstance(plan.get("codex_project_trust"), dict) else None

    if requires_choice and remove_previous is None:
        return {
            "ok": False,
            "requires_previous_choice": True,
            "plan": plan,
            "errors": [
                "Previous MCP configuration was found in a different location. Choose whether to remove it before applying the new config."
            ],
        }
    if trust_plan and bool(trust_plan.get("manage_choice_required", False)) and manage_codex_trust is None:
        return {
            "ok": False,
            "requires_trust_choice": True,
            "plan": plan,
            "errors": [
                "Choose whether AIRG should trust the workspace in Codex so the project .codex layer will load."
            ],
        }

    previous_removal: dict[str, Any] | None = None
    settings_local_sync: dict[str, Any] | None = None
    codex_trust_result: dict[str, Any] | None = None
    codex_trust_cleanup: dict[str, Any] | None = None
    try:
        if previous and (must_remove_previous or (requires_choice and bool(remove_previous))):
            previous_removal = _remove_from_last_applied(paths, previous, strict_missing_file=True)

        previous_trust = previous.get("codex_project_trust") if isinstance(previous, dict) else None
        previous_trust_workspace = str(previous_trust.get("workspace") or "").strip() if isinstance(previous_trust, dict) else ""
        if isinstance(previous_trust, dict) and bool(previous_trust.get("managed", False)):
            should_restore_previous_trust = (
                str(plan.get("agent_type", "")).strip().lower() != "codex"
                or str(plan.get("scope", "")).strip().lower() != "project"
                or previous_trust_workspace != str(plan.get("workspace", "")).strip()
            )
            if should_restore_previous_trust:
                codex_trust_cleanup = _restore_codex_project_trust(
                    paths,
                    previous_trust,
                    str(plan.get("agent_id") or "default"),
                )

        applied = _apply_for_scope(paths, plan)
        if trust_plan and bool(manage_codex_trust):
            codex_trust_result = _apply_codex_project_trust(
                paths,
                pathlib.Path(str(plan["workspace"])).resolve(),
                str(plan["agent_id"]),
            )
        if str(plan.get("agent_type", "")).strip().lower() == "claude_code":
            settings_local_sync = _sync_settings_local_allowlist(
                paths,
                pathlib.Path(str(plan["workspace"])).resolve(),
                ensure_enabled=True,
                agent_id=str(plan["agent_id"]),
            )
    except Exception as exc:
        if must_remove_previous and previous_removal is not None:
            return {
                "ok": False,
                "plan": plan,
                "errors": [
                    f"Failed to apply MCP configuration after removing previous config. Manual intervention required: {exc}"
                ],
            }
        return {"ok": False, "plan": plan, "errors": [str(exc)]}

    last_applied = {
        "scope": plan["scope"],
        "file_path": plan["target_path"],
        "timestamp": _now_iso(),
        "workspace": plan["workspace"],
        "agent_id": plan["agent_id"],
        "agent_type": str(plan.get("agent_type") or "").strip().lower(),
        "created_by_airg": bool(applied.get("created_by_airg", False)),
        "codex_project_trust": (codex_trust_result or {}).get("metadata"),
    }
    profile_id = str(profile.get("profile_id") or "").strip()
    if not profile_id:
        return {"ok": False, "errors": ["profile_id is required"]}
    updated = agent_configs.set_last_applied(paths, profile_id, last_applied)
    if not updated.get("ok"):
        return updated

    return {
        "ok": True,
        "plan": plan,
        "applied": applied,
        "settings_local": settings_local_sync,
        "previous_removed": previous_removal,
        "codex_project_trust": codex_trust_result,
        "codex_project_trust_cleanup": codex_trust_cleanup,
        "profile": updated.get("profile"),
        "profiles": updated.get("profiles", []),
    }


def remove_applied_mcp(
    paths: dict[str, pathlib.Path],
    profile: dict[str, Any],
    *,
    remove_codex_trust: bool = False,
) -> dict[str, Any]:
    last_applied = _normalize_last_applied(profile.get("last_applied"))
    workspace_raw = str(profile.get("workspace") or "").strip()
    workspace_path = pathlib.Path(workspace_raw).expanduser().resolve() if workspace_raw else None
    settings_local_cleanup: dict[str, Any] | None = None
    codex_trust_cleanup: dict[str, Any] | None = None

    if last_applied:
        try:
            removal = _remove_from_last_applied(paths, last_applied, strict_missing_file=True)
        except Exception as exc:
            return {"ok": False, "errors": [str(exc)]}
        trust_meta = last_applied.get("codex_project_trust") if isinstance(last_applied, dict) else None
        if remove_codex_trust and isinstance(trust_meta, dict) and bool(trust_meta.get("managed", False)):
            try:
                codex_trust_cleanup = _restore_codex_project_trust(
                    paths,
                    trust_meta,
                    str(last_applied.get("agent_id") or profile.get("agent_id") or "default"),
                )
            except Exception as exc:
                return {"ok": False, "errors": [str(exc)]}
    else:
        removal = {"removed": False, "reason": "no_last_applied"}

    if workspace_path is not None and str(profile.get("agent_type", "")).strip().lower() == "claude_code":
        try:
            settings_local_cleanup = _sync_settings_local_allowlist(
                paths,
                workspace_path,
                ensure_enabled=False,
                agent_id=str(profile.get("agent_id") or "default"),
            )
        except Exception as exc:
            return {"ok": False, "errors": [f"Failed to update Claude settings.local.json: {exc}"]}

    profile_id = str(profile.get("profile_id") or "").strip()
    if not profile_id:
        return {"ok": False, "errors": ["profile_id is required"]}
    updated = agent_configs.set_last_applied(paths, profile_id, None)
    if not updated.get("ok"):
        return updated

    return {
        "ok": True,
        "removed": removal,
        "settings_local": settings_local_cleanup,
        "codex_project_trust_cleanup": codex_trust_cleanup,
        "profile": updated.get("profile"),
        "profiles": updated.get("profiles", []),
    }
