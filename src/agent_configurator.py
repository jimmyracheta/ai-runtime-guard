import json
import os
import platform
import pathlib
import shlex
import shutil
import sys
from datetime import UTC, datetime
from typing import Any


CLAUDE_NATIVE_TOOLS = ["Bash", "Glob", "Grep", "Read", "Write", "Edit", "MultiEdit"]
CLAUDE_SCOPES = {"local", "project", "user"}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _state_dir(paths: dict[str, pathlib.Path]) -> pathlib.Path:
    return paths["approval_db_path"].expanduser().resolve().parent


def _state_path(paths: dict[str, pathlib.Path]) -> pathlib.Path:
    return _state_dir(paths) / "mcp-configs" / "agent-config-state.json"


def _read_json_file(path: pathlib.Path) -> dict[str, Any]:
    try:
        if not path.exists() or not path.is_file():
            return {}
        payload = json.loads(path.read_text())
    except Exception as exc:
        raise ValueError(f"Invalid JSON at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Expected object at {path}, found {type(payload).__name__}")
    return payload


def _read_json_file_optional(path: pathlib.Path) -> dict[str, Any]:
    try:
        return _read_json_file(path)
    except Exception:
        return {}


def _merge_list_union(base: list[Any], overlay: list[Any]) -> list[Any]:
    out: list[Any] = list(base)
    seen = {_canonical(item) for item in out}
    for item in overlay:
        marker = _canonical(item)
        if marker in seen:
            continue
        out.append(item)
        seen.add(marker)
    return out


def _deep_merge_union(base: Any, overlay: Any) -> Any:
    if isinstance(base, dict) and isinstance(overlay, dict):
        out = {k: _deep_copy(v) for k, v in base.items()}
        for key, value in overlay.items():
            if key in out:
                out[key] = _deep_merge_union(out[key], value)
            else:
                out[key] = _deep_copy(value)
        return out
    if isinstance(base, list) and isinstance(overlay, list):
        return _merge_list_union(base, overlay)
    return _deep_copy(overlay)


def _deep_copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _summarize_diff(before: Any, after: Any, *, _path: str = "") -> list[str]:
    path = _path or "root"
    if isinstance(before, dict) and isinstance(after, dict):
        out: list[str] = []
        keys = sorted(set(before.keys()) | set(after.keys()))
        for key in keys:
            child_path = f"{path}.{key}" if _path else key
            if key not in before:
                out.append(f"+ {child_path}")
                continue
            if key not in after:
                out.append(f"- {child_path}")
                continue
            out.extend(_summarize_diff(before[key], after[key], _path=child_path))
        return out
    if isinstance(before, list) and isinstance(after, list):
        if _canonical(before) == _canonical(after):
            return []
        before_set = {_canonical(item): item for item in before}
        after_set = {_canonical(item): item for item in after}
        added = [after_set[k] for k in after_set.keys() - before_set.keys()]
        removed = [before_set[k] for k in before_set.keys() - after_set.keys()]
        out: list[str] = []
        if added:
            out.append(f"+ {path} ({len(added)} added)")
        if removed:
            out.append(f"- {path} ({len(removed)} removed)")
        if not out:
            out.append(f"~ {path} (order/values updated)")
        return out
    if _canonical(before) == _canonical(after):
        return []
    return [f"~ {path}"]


def _server_process() -> tuple[str, list[str]]:
    explicit = str(os.environ.get("AIRG_SERVER_COMMAND", "")).strip()
    if explicit:
        parts = shlex.split(explicit)
        if parts:
            cmd = parts[0]
            args = parts[1:]
            if os.path.isabs(cmd):
                return cmd, args
            resolved = shutil.which(cmd)
            if resolved:
                return str(pathlib.Path(resolved).resolve()), args
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

    return str(pathlib.Path(sys.executable).resolve()), ["-m", "airg_cli", "server"]


def _shared_env(_paths: dict[str, pathlib.Path], workspace: pathlib.Path, agent_id: str) -> dict[str, str]:
    return {
        "AIRG_AGENT_ID": str(agent_id).strip() or "default",
        "AIRG_WORKSPACE": str(workspace),
    }


def _airg_server_block(paths: dict[str, pathlib.Path], workspace: pathlib.Path, agent_id: str) -> dict[str, Any]:
    command, args = _server_process()
    return {
        "command": command,
        "args": args,
        "env": _shared_env(paths, workspace, agent_id),
    }


def _contains_airg_mcp(payload: dict[str, Any]) -> bool:
    servers = payload.get("mcpServers", {})
    return _contains_airg_mcp_servers(servers)


def _contains_airg_mcp_servers(servers: Any) -> bool:
    if not isinstance(servers, dict):
        return False
    if "ai-runtime-guard" in servers:
        return True
    for value in servers.values():
        if not isinstance(value, dict):
            continue
        cmd = str(value.get("command", "")).strip().lower()
        args = [str(v).strip().lower() for v in (value.get("args") or []) if str(v).strip()]
        if "airg" in cmd or any("airg" in item for item in args):
            return True
    return False


def _home() -> pathlib.Path:
    return pathlib.Path.home().expanduser().resolve()


def _workspace_path(profile: dict[str, Any]) -> pathlib.Path:
    raw = str(profile.get("workspace", "")).strip()
    if not raw:
        raise ValueError("Profile workspace is required")
    workspace = pathlib.Path(raw).expanduser().resolve()
    if not workspace.exists() or not workspace.is_dir():
        raise ValueError(f"Workspace does not exist or is not a directory: {workspace}")
    return workspace


def _settings_local_path(workspace: pathlib.Path) -> pathlib.Path:
    return workspace / ".claude" / "settings.local.json"


def _settings_project_path(workspace: pathlib.Path) -> pathlib.Path:
    return workspace / ".claude" / "settings.json"


def _settings_user_path() -> pathlib.Path:
    return _home() / ".claude" / "settings.json"


def _claude_settings_path_for_scope(workspace: pathlib.Path, scope: str) -> pathlib.Path:
    normalized = str(scope or "").strip().lower()
    if normalized == "project":
        return _settings_project_path(workspace)
    if normalized == "user":
        return _settings_user_path()
    return _settings_local_path(workspace)


def _normalize_claude_scope(raw_scope: Any) -> str:
    requested = str(raw_scope or "").strip().lower()
    if requested in CLAUDE_SCOPES:
        return requested
    return "local"


def _normalize_claude_hardening_options(profile: dict[str, Any], options: dict[str, Any] | None) -> dict[str, Any]:
    payload = options if isinstance(options, dict) else {}
    selected_scope = _normalize_claude_scope(payload.get("scope") or profile.get("agent_scope") or "local")

    raw_tools = payload.get("native_tools", CLAUDE_NATIVE_TOOLS)
    if isinstance(raw_tools, dict):
        selected_tools = [tool for tool in CLAUDE_NATIVE_TOOLS if bool(raw_tools.get(tool, False))]
    elif isinstance(raw_tools, list):
        selected_tools = [tool for tool in CLAUDE_NATIVE_TOOLS if tool in {str(t).strip() for t in raw_tools}]
    else:
        selected_tools = list(CLAUDE_NATIVE_TOOLS)

    return {
        "scope": selected_scope,
        "hook_enabled": bool(payload.get("hook_enabled", True)),
        "restrict_native_tools": bool(payload.get("restrict_native_tools", True)),
        "native_tools": selected_tools,
        "sandbox_enabled": bool(payload.get("sandbox_enabled", True)),
        "sandbox_escape_closed": bool(payload.get("sandbox_escape_closed", True)),
    }


def _set_deny_tools(settings: dict[str, Any], *, enabled: bool, tools: list[str]) -> None:
    permissions = settings.get("permissions")
    if not isinstance(permissions, dict):
        permissions = {}
        settings["permissions"] = permissions
    deny = permissions.get("deny")
    deny_list = [str(item).strip() for item in deny if str(item).strip()] if isinstance(deny, list) else []
    managed_set = set(CLAUDE_NATIVE_TOOLS)
    selected = {tool for tool in tools if tool in managed_set}
    if enabled:
        for tool in selected:
            if tool not in deny_list:
                deny_list.append(tool)
    else:
        deny_list = [item for item in deny_list if item not in managed_set]
    if deny_list:
        permissions["deny"] = deny_list
    else:
        permissions.pop("deny", None)
    if not permissions:
        settings.pop("permissions", None)


def _set_airg_hook(settings: dict[str, Any], *, enabled: bool) -> None:
    hooks_payload = settings.get("hooks")
    hooks = hooks_payload if isinstance(hooks_payload, dict) else {}
    pre = hooks.get("PreToolUse")
    pre_list = pre if isinstance(pre, list) else []

    if enabled:
        for matcher in pre_list:
            if not isinstance(matcher, dict):
                continue
            hook_list = matcher.get("hooks")
            if not isinstance(hook_list, list):
                continue
            for hook in hook_list:
                if isinstance(hook, dict) and str(hook.get("command", "")).strip() == "airg-hook":
                    settings["hooks"] = hooks
                    return
        pre_list.append(
            {
                "matcher": "*",
                "hooks": [{"type": "command", "command": "airg-hook"}],
            }
        )
        hooks["PreToolUse"] = pre_list
        settings["hooks"] = hooks
        return

    cleaned_pre: list[dict[str, Any]] = []
    for matcher in pre_list:
        if not isinstance(matcher, dict):
            continue
        hook_list = matcher.get("hooks")
        if not isinstance(hook_list, list):
            continue
        filtered_hooks = [
            hook
            for hook in hook_list
            if not (isinstance(hook, dict) and str(hook.get("command", "")).strip() == "airg-hook")
        ]
        if filtered_hooks:
            next_matcher = dict(matcher)
            next_matcher["hooks"] = filtered_hooks
            cleaned_pre.append(next_matcher)
    if cleaned_pre:
        hooks["PreToolUse"] = cleaned_pre
    else:
        hooks.pop("PreToolUse", None)
    if hooks:
        settings["hooks"] = hooks
    else:
        settings.pop("hooks", None)


def _set_sandbox_flags(
    settings: dict[str, Any],
    *,
    sandbox_enabled: bool,
    sandbox_escape_closed: bool,
) -> None:
    sandbox_payload = settings.get("sandbox")
    sandbox = sandbox_payload if isinstance(sandbox_payload, dict) else {}
    if sandbox_enabled:
        sandbox["enabled"] = True
        sandbox["autoAllowBashIfSandboxed"] = False
    else:
        sandbox.pop("enabled", None)
        sandbox.pop("autoAllowBashIfSandboxed", None)
    if sandbox_escape_closed:
        sandbox["allowUnsandboxedCommands"] = False
    else:
        sandbox.pop("allowUnsandboxedCommands", None)
    if sandbox:
        settings["sandbox"] = sandbox
    else:
        settings.pop("sandbox", None)


def _apply_claude_hardening_to_settings(before: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    after = _deep_copy(before)
    _set_airg_hook(after, enabled=bool(options.get("hook_enabled", True)))
    _set_deny_tools(
        after,
        enabled=bool(options.get("restrict_native_tools", True)),
        tools=list(options.get("native_tools", []) or []),
    )
    _set_sandbox_flags(
        after,
        sandbox_enabled=bool(options.get("sandbox_enabled", True)),
        sandbox_escape_closed=bool(options.get("sandbox_escape_closed", True)),
    )
    return after


def _cursor_mcp_path(workspace: pathlib.Path) -> pathlib.Path:
    return workspace / ".cursor" / "mcp.json"


def _workspace_mcp_path(workspace: pathlib.Path) -> pathlib.Path:
    return workspace / ".mcp.json"


def _mcp_probe_paths(workspace: pathlib.Path) -> list[pathlib.Path]:
    return [
        workspace / ".mcp.json",
        _home() / ".claude.json",
        *_claude_managed_paths(),
    ]


def _claude_managed_paths() -> list[pathlib.Path]:
    system = platform.system().lower()
    if system == "darwin":
        return [pathlib.Path("/Library/Application Support/ClaudeCode/managed-mcp.json")]
    if system == "linux":
        return [pathlib.Path("/etc/claude-code/managed-mcp.json")]
    if system == "windows":
        return [pathlib.Path(r"C:\Program Files\ClaudeCode\managed-mcp.json")]
    return []


def _workspace_key_matches(workspace: pathlib.Path, project_key: Any) -> bool:
    raw = str(project_key or "").strip()
    if not raw:
        return False
    if raw == str(workspace):
        return True
    try:
        candidate = pathlib.Path(raw).expanduser().resolve()
    except Exception:
        return False
    return str(candidate) == str(workspace)


def _detect_claude_mcp_locations(workspace: pathlib.Path) -> list[dict[str, str]]:
    home = _home()
    found: list[dict[str, str]] = []

    workspace_mcp = workspace / ".mcp.json"
    if _contains_airg_mcp(_read_json_file_optional(workspace_mcp)):
        found.append({"scope": "project", "path": str(workspace_mcp)})

    claude_local = home / ".claude.json"
    claude_payload = _read_json_file_optional(claude_local)
    if _contains_airg_mcp_servers(claude_payload.get("mcpServers", {})):
        found.append({"scope": "user", "path": str(claude_local)})

    projects = claude_payload.get("projects", {})
    if isinstance(projects, dict):
        for key, value in projects.items():
            if not _workspace_key_matches(workspace, key):
                continue
            if not isinstance(value, dict):
                continue
            if _contains_airg_mcp_servers(value.get("mcpServers", {})):
                found.append({"scope": "local", "path": str(claude_local)})
                break

    for managed in _claude_managed_paths():
        if _contains_airg_mcp(_read_json_file_optional(managed)):
            found.append({"scope": "managed", "path": str(managed)})

    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in found:
        key = (str(item.get("scope", "")), str(item.get("path", "")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append({"scope": key[0], "path": key[1]})
    return deduped


def _backup_path_for(target: pathlib.Path) -> pathlib.Path:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = target.parent / ".airg-backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    return backup_dir / f"{target.name}.{ts}.bak"


def _write_with_backup(target: pathlib.Path, merged_payload: dict[str, Any]) -> dict[str, Any]:
    target.parent.mkdir(parents=True, exist_ok=True)
    before_exists = target.exists()
    before_payload: dict[str, Any] = _read_json_file(target) if before_exists else {}

    backup_path = _backup_path_for(target)
    if before_exists:
        shutil.copy2(target, backup_path)
    else:
        backup_path.write_text("{}\n")

    target.write_text(json.dumps(merged_payload, indent=2) + "\n")

    verify_payload = _read_json_file(target)
    if _canonical(verify_payload) != _canonical(merged_payload):
        if before_exists:
            shutil.copy2(backup_path, target)
        else:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
        raise RuntimeError(f"Verification failed after writing {target}")

    return {
        "target_path": str(target),
        "backup_path": str(backup_path),
        "original_missing": not before_exists,
        "before": before_payload,
        "after": merged_payload,
        "diff_summary": _summarize_diff(before_payload, merged_payload),
    }


def _load_state(paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    state_file = _state_path(paths)
    payload = {"profiles": {}}
    if not state_file.exists():
        return payload
    try:
        data = json.loads(state_file.read_text())
        if isinstance(data, dict) and isinstance(data.get("profiles"), dict):
            return data
    except Exception:
        pass
    return payload


def _save_state(paths: dict[str, pathlib.Path], payload: dict[str, Any]) -> None:
    state_file = _state_path(paths)
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(payload, indent=2) + "\n")


def _update_profile_state(paths: dict[str, pathlib.Path], profile_id: str, record: dict[str, Any]) -> None:
    state = _load_state(paths)
    profiles = state.setdefault("profiles", {})
    profiles[profile_id] = record
    _save_state(paths, state)


def _clear_profile_state(paths: dict[str, pathlib.Path], profile_id: str) -> None:
    state = _load_state(paths)
    profiles = state.setdefault("profiles", {})
    profiles.pop(profile_id, None)
    _save_state(paths, state)


def _profile_state(paths: dict[str, pathlib.Path], profile_id: str) -> dict[str, Any]:
    state = _load_state(paths)
    profiles = state.get("profiles", {})
    if not isinstance(profiles, dict):
        return {}
    record = profiles.get(profile_id, {})
    return record if isinstance(record, dict) else {}


def undo_available(paths: dict[str, pathlib.Path], profile_id: str) -> bool:
    return bool(_profile_state(paths, profile_id).get("changes"))


def _restore_change(change: dict[str, Any]) -> None:
    target = pathlib.Path(str(change.get("target_path", "")).strip())
    backup = pathlib.Path(str(change.get("backup_path", "")).strip())
    original_missing = bool(change.get("original_missing", False))
    if not str(target):
        return
    if original_missing:
        if target.exists():
            target.unlink()
        return
    if not backup.exists():
        raise FileNotFoundError(f"Backup not found for restore: {backup}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(backup, target)


def _mcp_present_for_claude(workspace: pathlib.Path) -> bool:
    return bool(_detect_claude_mcp_locations(workspace))


def _apply_claude_mcp_for_scope(
    paths: dict[str, pathlib.Path],
    workspace: pathlib.Path,
    agent_id: str,
    scope: str,
) -> dict[str, Any]:
    normalized_scope = _normalize_claude_scope(scope)
    server_block = _airg_server_block(paths, workspace, agent_id)

    if normalized_scope == "project":
        target = _workspace_mcp_path(workspace)
        before = _read_json_file(target) if target.exists() else {}
        after = _deep_merge_union(
            before,
            {"mcpServers": {"ai-runtime-guard": server_block}},
        )
        change = _write_with_backup(target, after)
        change["scope"] = normalized_scope
        return change

    claude_local = _home() / ".claude.json"
    before = _read_json_file(claude_local) if claude_local.exists() else {}
    after = _deep_copy(before)
    if normalized_scope == "user":
        servers = after.get("mcpServers")
        if not isinstance(servers, dict):
            servers = {}
        servers["ai-runtime-guard"] = server_block
        after["mcpServers"] = servers
    else:
        projects = after.get("projects")
        if not isinstance(projects, dict):
            projects = {}
        workspace_key = str(workspace)
        project_entry = projects.get(workspace_key)
        if not isinstance(project_entry, dict):
            project_entry = {}
        servers = project_entry.get("mcpServers")
        if not isinstance(servers, dict):
            servers = {}
        servers["ai-runtime-guard"] = server_block
        project_entry["mcpServers"] = servers
        projects[workspace_key] = project_entry
        after["projects"] = projects
    change = _write_with_backup(claude_local, after)
    change["scope"] = normalized_scope
    return change


def _apply_claude(
    paths: dict[str, pathlib.Path],
    profile: dict[str, Any],
    *,
    options: dict[str, Any] | None,
    auto_add_mcp: bool,
) -> dict[str, Any]:
    workspace = _workspace_path(profile)
    agent_id = str(profile.get("agent_id", "")).strip() or "default"
    profile_id = str(profile.get("profile_id", "")).strip()
    selected_options = _normalize_claude_hardening_options(profile, options)
    selected_scope = selected_options["scope"]

    changes: list[dict[str, Any]] = []
    preflight = {
        "mcp_locations": _detect_claude_mcp_locations(workspace),
        "mcp_probe_paths": [str(p) for p in _mcp_probe_paths(workspace)],
        "selected_scope": selected_scope,
        "settings_target": str(_claude_settings_path_for_scope(workspace, selected_scope)),
    }
    preflight["mcp_present"] = bool(preflight["mcp_locations"])
    preflight["mcp_detected_scopes"] = list(
        dict.fromkeys(
            [
                str(item.get("scope", "")).strip()
                for item in preflight["mcp_locations"]
                if isinstance(item, dict) and str(item.get("scope", "")).strip()
            ]
        )
    )

    try:
        if not preflight["mcp_present"]:
            if not auto_add_mcp:
                return {
                    "ok": False,
                    "requires_mcp": True,
                    "errors": [
                        "AIRG MCP server was not detected in Claude MCP config. Add it first or allow auto-add in this action."
                    ],
                    "preflight": preflight,
                }
            auto_add_scope = selected_scope if selected_scope == "project" else "project"
            mcp_change = _apply_claude_mcp_for_scope(paths, workspace, agent_id, auto_add_scope)
            changes.append(mcp_change)
            preflight["mcp_present"] = True
            preflight["mcp_auto_added"] = True
            preflight["mcp_auto_add_scope"] = auto_add_scope
            preflight["mcp_locations"] = [
                {"scope": str(mcp_change.get("scope", auto_add_scope)), "path": str(mcp_change.get("target_path", ""))}
            ]
            preflight["mcp_detected_scopes"] = [str(mcp_change.get("scope", auto_add_scope))]

        target = _claude_settings_path_for_scope(workspace, selected_scope)
        before = _read_json_file(target) if target.exists() else {}
        after = _apply_claude_hardening_to_settings(before, selected_options)
        changes.append(_write_with_backup(target, after))
    except Exception:
        for change in reversed(changes):
            _restore_change(change)
        raise

    summary: list[str] = []
    for change in changes:
        summary.extend(change.get("diff_summary", []))

    record = {
        "profile_id": profile_id,
        "agent_type": "claude_code",
        "applied_at": _now_iso(),
        "changes": [
            {
                "target_path": c["target_path"],
                "backup_path": c["backup_path"],
                "original_missing": c["original_missing"],
            }
            for c in changes
        ],
        "diff_summary": summary,
        "applied_options": selected_options,
    }
    _update_profile_state(paths, profile_id, record)

    return {
        "ok": True,
        "profile_id": profile_id,
        "agent_type": "claude_code",
        "target_path": str(target),
        "changes": changes,
        "diff_summary": summary,
        "preflight": preflight,
        "applied_options": selected_options,
        "undo_available": True,
    }


def _apply_cursor(paths: dict[str, pathlib.Path], profile: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace_path(profile)
    agent_id = str(profile.get("agent_id", "")).strip() or "default"
    profile_id = str(profile.get("profile_id", "")).strip()

    target = _cursor_mcp_path(workspace)
    overlay = {
        "mcpServers": {
            "ai-runtime-guard": _airg_server_block(paths, workspace, agent_id),
        }
    }

    before = _read_json_file(target) if target.exists() else {}
    after = _deep_merge_union(before, overlay)
    change = _write_with_backup(target, after)
    record = {
        "profile_id": profile_id,
        "agent_type": "cursor",
        "applied_at": _now_iso(),
        "changes": [
            {
                "target_path": change["target_path"],
                "backup_path": change["backup_path"],
                "original_missing": change["original_missing"],
            }
        ],
        "diff_summary": change.get("diff_summary", []),
    }
    _update_profile_state(paths, profile_id, record)

    return {
        "ok": True,
        "profile_id": profile_id,
        "agent_type": "cursor",
        "target_path": str(target),
        "changes": [change],
        "diff_summary": change.get("diff_summary", []),
        "undo_available": True,
    }


def apply_hardening(
    paths: dict[str, pathlib.Path],
    profile: dict[str, Any],
    *,
    options: dict[str, Any] | None = None,
    auto_add_mcp: bool = False,
) -> dict[str, Any]:
    agent_type = str(profile.get("agent_type", "")).strip().lower()
    profile_id = str(profile.get("profile_id", "")).strip()
    if not profile_id:
        return {"ok": False, "errors": ["profile_id is required"]}

    try:
        if agent_type in {"claude_code", "claude_desktop"}:
            return _apply_claude(paths, profile, options=options, auto_add_mcp=auto_add_mcp)
        if agent_type == "cursor":
            return _apply_cursor(paths, profile)
        return {
            "ok": False,
            "errors": [f"Agent type '{agent_type or 'unknown'}' is not supported for config hardening in dev2."],
        }
    except Exception as exc:
        return {"ok": False, "errors": [str(exc)]}


def undo_hardening(paths: dict[str, pathlib.Path], profile: dict[str, Any]) -> dict[str, Any]:
    profile_id = str(profile.get("profile_id", "")).strip()
    if not profile_id:
        return {"ok": False, "errors": ["profile_id is required"]}

    record = _profile_state(paths, profile_id)
    changes = record.get("changes", []) if isinstance(record, dict) else []
    if not isinstance(changes, list) or not changes:
        return {"ok": False, "errors": ["No hardening backup record found for this profile."]}

    try:
        for change in reversed(changes):
            if not isinstance(change, dict):
                continue
            _restore_change(change)
    except Exception as exc:
        return {"ok": False, "errors": [f"Undo failed: {exc}"]}

    _clear_profile_state(paths, profile_id)
    return {
        "ok": True,
        "profile_id": profile_id,
        "undone_changes": len(changes),
        "undo_available": False,
    }
