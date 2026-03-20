import json
import platform
import pathlib
from typing import Any


CLAUDE_SIGNAL_LABELS = {
    "airg_mcp_present": "AIRG MCP configured",
    "native_tools_restricted": "Native tool deny rules enabled",
    "hook_active": "airg-hook PreToolUse hook active",
    "sandbox_enabled": "Sandbox enabled",
    "sandbox_escape_closed": "Sandbox unsandboxed-command escape disabled",
}


def _read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        if not path.exists() or not path.is_file():
            return {}
        payload = json.loads(path.read_text())
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(out.get(key), dict) and isinstance(value, dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _contains_airg_mcp_servers(servers: Any) -> bool:
    if not isinstance(servers, dict):
        return False
    if "ai-runtime-guard" in servers:
        return True
    for value in servers.values():
        if not isinstance(value, dict):
            continue
        cmd = str(value.get("command", "")).strip().lower()
        args = [str(x).strip().lower() for x in (value.get("args", []) or []) if str(x).strip()]
        if "airg" in cmd or any("airg" in a for a in args):
            return True
    return False


def _contains_airg_mcp(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    return _contains_airg_mcp_servers(payload.get("mcpServers", {}))


def _hook_is_active(effective: dict[str, Any]) -> bool:
    hooks = effective.get("hooks", {})
    if not isinstance(hooks, dict):
        return False
    pre = hooks.get("PreToolUse", [])
    if not isinstance(pre, list):
        return False
    for matcher in pre:
        if not isinstance(matcher, dict):
            continue
        for hook in matcher.get("hooks", []) or []:
            if not isinstance(hook, dict):
                continue
            cmd = str(hook.get("command", "")).strip()
            if cmd == "airg-hook":
                return True
    return False


def _native_tools_restricted(effective: dict[str, Any]) -> bool:
    permissions = effective.get("permissions", {})
    if not isinstance(permissions, dict):
        return False
    deny = permissions.get("deny", [])
    if not isinstance(deny, list):
        return False
    denied = {str(x).strip() for x in deny}
    required = {"Bash", "Write", "Edit", "MultiEdit"}
    return required.issubset(denied)


def _sandbox_hardened(effective: dict[str, Any]) -> tuple[bool, bool]:
    sandbox = effective.get("sandbox", {})
    if not isinstance(sandbox, dict):
        return False, False
    enabled = bool(sandbox.get("enabled", False))
    allow_unsandboxed = bool(sandbox.get("allowUnsandboxedCommands", True))
    return enabled, (not allow_unsandboxed)


def _score_claude(*, has_mcp: bool, native_denied: bool, hook_active: bool, sandbox_enabled: bool, escape_closed: bool) -> tuple[str, str]:
    if has_mcp and native_denied and hook_active and sandbox_enabled and escape_closed:
        return "green", "AIRG MCP configured, native tools restricted, hook active, and sandbox hardened."
    if has_mcp or native_denied or hook_active or sandbox_enabled:
        return "yellow", "Partial hardening detected. Review missing controls."
    return "red", "No effective hardening controls detected for Claude Code."


def _score_cursor(*, has_mcp: bool) -> tuple[str, str]:
    if has_mcp:
        return "yellow", "AIRG MCP detected. Cursor client-side permissions/hooks are limited."
    return "red", "No AIRG MCP server configuration detected."


def _missing_controls_from_signals(signals: dict[str, Any], *, labels: dict[str, str]) -> list[str]:
    missing: list[str] = []
    for key, label in labels.items():
        if not bool(signals.get(key, False)):
            missing.append(label)
    return missing


def _claude_recommendations(signals: dict[str, Any]) -> list[str]:
    rec: list[str] = []
    if not bool(signals.get("airg_mcp_present", False)):
        rec.append("Add ai-runtime-guard to your MCP config for this workspace.")
    if not bool(signals.get("hook_active", False)):
        rec.append("Register airg-hook under Claude PreToolUse hooks in settings.local.json.")
    if not bool(signals.get("native_tools_restricted", False)):
        rec.append("Add deny rules for Bash, Write, Edit, and MultiEdit in Claude permissions.")
    if not bool(signals.get("sandbox_enabled", False)):
        rec.append("Enable Claude sandbox mode for this workspace.")
    if bool(signals.get("sandbox_enabled", False)) and not bool(signals.get("sandbox_escape_closed", False)):
        rec.append("Disable allowUnsandboxedCommands to close sandbox escape hatch.")
    return rec


def _cursor_recommendations(signals: dict[str, Any]) -> list[str]:
    if bool(signals.get("airg_mcp_present", False)):
        return ["Cursor is MCP-layer protected; client-native hook/permission hardening is limited."]
    return ["Add ai-runtime-guard MCP server to Cursor mcp.json for this workspace."]


def _home() -> pathlib.Path:
    return pathlib.Path.home().expanduser().resolve()


def _workspace_from_profile(profile: dict[str, Any]) -> pathlib.Path:
    raw = str(profile.get("workspace", "")).strip()
    if not raw:
        return pathlib.Path.cwd().resolve()
    try:
        return pathlib.Path(raw).expanduser().resolve()
    except Exception:
        return pathlib.Path.cwd().resolve()


def _claude_paths(workspace: pathlib.Path) -> list[pathlib.Path]:
    home = _home()
    return [
        home / ".claude" / "settings.json",
        workspace / ".claude" / "settings.json",
        workspace / ".claude" / "settings.local.json",
    ]


def _cursor_paths(workspace: pathlib.Path) -> list[pathlib.Path]:
    home = _home()
    return [
        workspace / ".cursor" / "mcp.json",
        home / ".cursor" / "mcp.json",
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


def _claude_mcp_probe_paths(workspace: pathlib.Path) -> list[pathlib.Path]:
    home = _home()
    return [
        workspace / ".mcp.json",
        home / ".claude.json",
        *_claude_managed_paths(),
    ]


def _detect_claude_mcp_locations(workspace: pathlib.Path) -> list[dict[str, str]]:
    home = _home()
    found: list[dict[str, str]] = []

    project_mcp = workspace / ".mcp.json"
    if _contains_airg_mcp(_read_json(project_mcp)):
        found.append({"scope": "project", "path": str(project_mcp)})

    claude_local = home / ".claude.json"
    claude_payload = _read_json(claude_local)
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
        if _contains_airg_mcp(_read_json(managed)):
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


def _build_claude_posture(profile: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace_from_profile(profile)
    settings_paths = _claude_paths(workspace)
    effective: dict[str, Any] = {}
    for p in settings_paths:
        effective = _deep_merge(effective, _read_json(p))
    mcp_probe_paths = _claude_mcp_probe_paths(workspace)
    mcp_locations = _detect_claude_mcp_locations(workspace)
    mcp_scopes = list(dict.fromkeys([str(item.get("scope", "")) for item in mcp_locations if str(item.get("scope", ""))]))
    has_mcp = bool(mcp_locations)
    native_denied = _native_tools_restricted(effective)
    hook_active = _hook_is_active(effective)
    sandbox_enabled, escape_closed = _sandbox_hardened(effective)
    status, rationale = _score_claude(
        has_mcp=has_mcp,
        native_denied=native_denied,
        hook_active=hook_active,
        sandbox_enabled=sandbox_enabled,
        escape_closed=escape_closed,
    )
    signals = {
        "airg_mcp_present": has_mcp,
        "native_tools_restricted": native_denied,
        "hook_active": hook_active,
        "sandbox_enabled": sandbox_enabled,
        "sandbox_escape_closed": escape_closed,
    }
    return {
        "status": status,
        "rationale": rationale,
        "signals": signals,
        "mcp_detected_scopes": mcp_scopes,
        "mcp_detected_locations": mcp_locations,
        "missing_controls": _missing_controls_from_signals(signals, labels=CLAUDE_SIGNAL_LABELS),
        "recommended_actions": _claude_recommendations(signals),
        "paths_checked": [str(p) for p in settings_paths + mcp_probe_paths],
        "existing_paths": [str(p) for p in settings_paths + mcp_probe_paths if p.exists()],
    }


def _build_cursor_posture(profile: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace_from_profile(profile)
    paths = _cursor_paths(workspace)
    has_mcp = any(_contains_airg_mcp(_read_json(p)) for p in paths)
    status, rationale = _score_cursor(has_mcp=has_mcp)
    signals = {
        "airg_mcp_present": has_mcp,
        "hooks_supported": False,
        "native_tool_permissions_supported": False,
    }
    return {
        "status": status,
        "rationale": rationale,
        "signals": signals,
        "missing_controls": [] if has_mcp else ["AIRG MCP configured"],
        "recommended_actions": _cursor_recommendations(signals),
        "paths_checked": [str(p) for p in paths],
        "existing_paths": [str(p) for p in paths if p.exists()],
    }


def _build_generic_posture(profile: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace_from_profile(profile)
    paths = _claude_mcp_probe_paths(workspace)
    has_mcp = any(_contains_airg_mcp(_read_json(p)) for p in paths)
    status = "yellow" if has_mcp else "red"
    rationale = "AIRG MCP detected." if has_mcp else "No AIRG MCP server configuration detected."
    return {
        "status": status,
        "rationale": rationale,
        "signals": {
            "airg_mcp_present": has_mcp,
        },
        "missing_controls": [] if has_mcp else ["AIRG MCP configured"],
        "recommended_actions": (
            ["Add ai-runtime-guard MCP server for this agent type/workspace."]
            if not has_mcp
            else ["MCP protection detected. Additional native tool restrictions depend on client support."]
        ),
        "paths_checked": [str(p) for p in paths],
        "existing_paths": [str(p) for p in paths if p.exists()],
    }


def build_posture_for_profile(profile: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "profile_id": str(profile.get("profile_id", "")).strip(),
        "name": str(profile.get("name", "")).strip(),
        "agent_type": str(profile.get("agent_type", "")).strip().lower(),
        "agent_id": str(profile.get("agent_id", "")).strip(),
        "workspace": str(profile.get("workspace", "")).strip(),
    }
    agent_type = normalized["agent_type"]
    if agent_type in {"claude_code", "claude_desktop"}:
        posture = _build_claude_posture(profile)
    elif agent_type == "cursor":
        posture = _build_cursor_posture(profile)
    else:
        posture = _build_generic_posture(profile)
    return {**normalized, **posture}


def detect_unregistered_configs(*, known_workspaces: list[pathlib.Path]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    home = _home()
    candidates: list[tuple[str, pathlib.Path, str]] = [
        ("cursor", home / ".cursor" / "mcp.json", "home"),
        ("claude_code", home / ".claude" / "settings.json", "home"),
    ]
    for workspace in known_workspaces:
        candidates.extend(
            [
                ("cursor", workspace / ".cursor" / "mcp.json", "workspace"),
                ("claude_code", workspace / ".claude" / "settings.json", "workspace"),
                ("claude_code", workspace / ".claude" / "settings.local.json", "workspace"),
            ]
        )
    seen: set[str] = set()
    for agent_type, path, scope in candidates:
        key = f"{agent_type}:{path}"
        if key in seen:
            continue
        seen.add(key)
        if path.exists():
            found.append(
                {
                    "agent_type": agent_type,
                    "path": str(path),
                    "scope": scope,
                }
            )
    return found


def build_posture_summary(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    profile_postures = [build_posture_for_profile(profile) for profile in profiles]
    workspaces: list[pathlib.Path] = []
    for p in profiles:
        raw = str((p or {}).get("workspace", "")).strip()
        if not raw:
            continue
        try:
            workspaces.append(pathlib.Path(raw).expanduser().resolve())
        except Exception:
            continue
    discovered = sorted(
        detect_unregistered_configs(known_workspaces=workspaces),
        key=lambda x: (str(x.get("agent_type", "")), str(x.get("scope", "")), str(x.get("path", ""))),
    )
    totals = {"green": 0, "yellow": 0, "red": 0}
    for row in profile_postures:
        status = str(row.get("status", "")).lower()
        if status in totals:
            totals[status] += 1
    return {
        "ok": True,
        "errors": [],
        "profiles": profile_postures,
        "discovered_unregistered": discovered,
        "totals": totals,
    }
