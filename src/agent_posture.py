import json
import os
import platform
import pathlib
import re
import hashlib
import tomllib
from typing import Any


CLAUDE_SIGNAL_LABELS = {
    "airg_mcp_present": "AIRG MCP configured",
    "tier1_hook_active": "Hook coverage active",
    "native_tools_restricted": "Native tools restricted",
    "tier2_hook_active": "Optional Read/Glob/Grep hook active",
    "sandbox_enabled": "Sandbox enabled",
    "sandbox_escape_closed": "Sandbox unsandboxed-command escape disabled",
}
CURSOR_SIGNAL_LABELS = {
    "airg_mcp_present": "AIRG MCP configured",
    "hook_enforcement_active": "AIRG hook enforcement active",
    "hook_fail_closed_active": "Fail-closed hook gates active",
    "sandbox_hardened": "Sandbox hardened",
}
CLAUDE_NATIVE_TOOLS = {"Bash", "Glob", "Grep", "Read", "Write", "Edit", "MultiEdit"}
CLAUDE_TIER1_TOOLS = {"Bash", "Write", "Edit", "MultiEdit"}
CLAUDE_TIER2_TOOLS = {"Read", "Glob", "Grep"}
CURSOR_TIER1_TOOLS = {"Shell", "Write", "Delete"}
CURSOR_TIER2_TOOLS = {"Read", "Grep"}
CODEX_AGENT_DOC_BEGIN = "<!-- AIRG_CODEX_TIER1_BEGIN -->"
CODEX_AGENT_DOC_END = "<!-- AIRG_CODEX_TIER1_END -->"
CODEX_RULES_BEGIN = "# AIRG_CODEX_TIER2_BEGIN"
CODEX_RULES_END = "# AIRG_CODEX_TIER2_END"
CODEX_AIRG_RULES_FILE = "airg.rules"
CURSORIGNORE_MANAGED_BEGIN = "# AIRG_CURSORIGNORE_BEGIN"
CURSORIGNORE_MANAGED_END = "# AIRG_CURSORIGNORE_END"
_CODEX_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def _read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        if not path.exists() or not path.is_file():
            return {}
        payload = json.loads(path.read_text())
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _strip_jsonc_comments(text: str) -> str:
    out: list[str] = []
    in_string = False
    escape = False
    in_line_comment = False
    in_block_comment = False
    idx = 0
    while idx < len(text):
        ch = text[idx]
        nxt = text[idx + 1] if idx + 1 < len(text) else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append(ch)
            idx += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                idx += 2
            else:
                idx += 1
            continue
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            idx += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            idx += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            idx += 2
            continue
        out.append(ch)
        if ch == '"':
            in_string = True
        idx += 1
    return "".join(out)


def _read_jsonc(path: pathlib.Path) -> dict[str, Any]:
    try:
        if not path.exists() or not path.is_file():
            return {}
        raw = path.read_text()
        if not raw.strip():
            return {}
        payload = json.loads(_strip_jsonc_comments(raw))
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


def _hook_active_matchers(effective: dict[str, Any]) -> set[str]:
    hooks = effective.get("hooks", {})
    if not isinstance(hooks, dict):
        return set()
    pre = hooks.get("PreToolUse", [])
    if not isinstance(pre, list):
        return set()
    out: set[str] = set()
    for matcher in pre:
        if not isinstance(matcher, dict):
            continue
        matcher_name = str(matcher.get("matcher", "")).strip()
        for hook in matcher.get("hooks", []) or []:
            if not isinstance(hook, dict):
                continue
            cmd = str(hook.get("command", "")).strip()
            if cmd == "airg-hook" or pathlib.Path(cmd).name == "airg-hook":
                if matcher_name:
                    out.add(matcher_name)
                break
    return out


def _hook_tier_active(effective: dict[str, Any], required_tools: set[str]) -> bool:
    matchers = _hook_active_matchers(effective)
    if not matchers:
        return False
    if "*" in matchers:
        return True
    return required_tools.issubset(matchers)


def _native_tools_restricted(effective: dict[str, Any]) -> bool:
    permissions = effective.get("permissions", {})
    if not isinstance(permissions, dict):
        return False
    deny = permissions.get("deny", [])
    if not isinstance(deny, list):
        return False
    denied = {str(x).strip() for x in deny}
    return CLAUDE_TIER1_TOOLS.issubset(denied)


def _native_tools_denied_set(effective: dict[str, Any]) -> set[str]:
    permissions = effective.get("permissions", {})
    if not isinstance(permissions, dict):
        return set()
    deny = permissions.get("deny", [])
    if not isinstance(deny, list):
        return set()
    denied = {str(x).strip() for x in deny if str(x).strip()}
    return {tool for tool in denied if tool in CLAUDE_NATIVE_TOOLS}


def _sandbox_hardened(effective: dict[str, Any]) -> tuple[bool, bool]:
    sandbox = effective.get("sandbox", {})
    if not isinstance(sandbox, dict):
        return False, False
    enabled = bool(sandbox.get("enabled", False))
    allow_unsandboxed = bool(sandbox.get("allowUnsandboxedCommands", True))
    return enabled, (not allow_unsandboxed)


def _score_claude(
    *,
    has_mcp: bool,
    tier1_hook_active: bool,
    native_denied: bool,
    sandbox_enabled: bool,
    escape_closed: bool,
) -> tuple[str, str]:
    if not has_mcp:
        return "gray", "No AIRG MCP configuration detected for this agent profile."
    if tier1_hook_active and native_denied and sandbox_enabled and escape_closed:
        return "green", "Maximum enforcement detected: MCP + hook + native tool restrictions + sandbox protections."
    if tier1_hook_active:
        return "yellow", "Strict enforcement detected: MCP + hook active."
    return "red", "Standard enforcement detected: AIRG MCP is configured."


def _score_cursor(
    *,
    has_mcp: bool,
    hook_enforcement_active: bool,
    hook_fail_closed_active: bool,
    sandbox_hardened: bool,
) -> tuple[str, str]:
    if not has_mcp:
        return "gray", "No AIRG MCP server configuration detected."
    if hook_enforcement_active and hook_fail_closed_active and sandbox_hardened:
        return "green", "Maximum Cursor hardening detected: MCP + hooks + fail-closed + sandbox."
    if hook_enforcement_active:
        return "yellow", "Strict Cursor hardening detected: MCP + hook enforcement."
    return "red", "Standard Cursor enforcement detected: AIRG MCP configured."


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
    if not bool(signals.get("tier1_hook_active", False)):
        rec.append("Enable hook coverage (Bash/Write/Edit/MultiEdit) for deterministic MCP redirection.")
    if not bool(signals.get("native_tools_restricted", False)):
        rec.append("Restrict native Bash/Write/Edit/MultiEdit tools in Claude permissions.")
    if not bool(signals.get("tier2_hook_active", False)):
        rec.append("Optional: enable Read/Glob/Grep hook coverage for path/extension policy checks and audit.")
    if not bool(signals.get("sandbox_enabled", False)):
        rec.append("Enable Claude sandbox mode for this workspace.")
    if bool(signals.get("sandbox_enabled", False)) and not bool(signals.get("sandbox_escape_closed", False)):
        rec.append("Disable allowUnsandboxedCommands to close sandbox escape hatch.")
    return rec


def _cursor_recommendations(signals: dict[str, Any]) -> list[str]:
    rec: list[str] = []
    if not bool(signals.get("airg_mcp_present", False)):
        rec.append("Add ai-runtime-guard MCP server to Cursor mcp.json for this workspace.")
    if not bool(signals.get("hook_enforcement_active", False)):
        rec.append("Enable Cursor hooks to deny native tools and route actions through AIRG MCP tools.")
    if not bool(signals.get("hook_fail_closed_active", False)):
        rec.append("Enable failClosed on beforeShellExecution and beforeMCPExecution hooks.")
    if not bool(signals.get("sandbox_hardened", False)):
        rec.append("Enable sandbox hardening with deny-by-default network policy and disableTmpWrite.")
    if not bool(signals.get("permissions_airg_allowlist_configured", False)):
        rec.append("Optional: set ~/.cursor/permissions.json mcpAllowlist to ai-runtime-guard:* for safer auto-run behavior.")
    if not bool(signals.get("cursorignore_synced", False)):
        rec.append("Optional: sync AIRG blocked paths/extensions into .cursorignore.")
    return rec


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
    scoped = _claude_paths_by_scope(workspace)
    return [scoped["user"], scoped["project"], scoped["local"]]


def _claude_paths_by_scope(workspace: pathlib.Path) -> dict[str, pathlib.Path]:
    home = _home()
    return {
        "user": home / ".claude" / "settings.json",
        "project": workspace / ".claude" / "settings.json",
        "local": workspace / ".claude" / "settings.local.json",
    }


def _normalize_claude_scope(raw_scope: Any) -> str:
    value = str(raw_scope or "").strip().lower()
    if value in {"project", "local", "user"}:
        return value
    return "local"


def _cursor_paths(workspace: pathlib.Path) -> list[pathlib.Path]:
    home = _home()
    return [
        workspace / ".cursor" / "mcp.json",
        home / ".cursor" / "mcp.json",
    ]


def _cursor_hooks_paths(workspace: pathlib.Path) -> list[tuple[str, pathlib.Path]]:
    home = _home()
    return [
        ("project", workspace / ".cursor" / "hooks.json"),
        ("global", home / ".cursor" / "hooks.json"),
    ]


def _cursor_permissions_path() -> pathlib.Path:
    return _home() / ".cursor" / "permissions.json"


def _cursor_sandbox_paths(workspace: pathlib.Path) -> list[tuple[str, pathlib.Path]]:
    home = _home()
    return [
        ("global", home / ".cursor" / "sandbox.json"),
        ("project", workspace / ".cursor" / "sandbox.json"),
    ]


def _cursorignore_path(workspace: pathlib.Path) -> pathlib.Path:
    return workspace / ".cursorignore"


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


def _claude_desktop_config_path() -> pathlib.Path:
    if platform.system().lower() == "darwin":
        return _home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if platform.system().lower() == "windows":
        appdata = str(os.environ.get("APPDATA", "")).strip()
        if appdata:
            return pathlib.Path(appdata).expanduser().resolve() / "Claude" / "claude_desktop_config.json"
        return _home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    return _home() / ".config" / "Claude" / "claude_desktop_config.json"


def _codex_paths(workspace: pathlib.Path) -> list[pathlib.Path]:
    home = _home()
    return [
        home / ".codex" / "config.toml",
        workspace / ".codex" / "config.toml",
    ]


def _codex_scope_root(workspace: pathlib.Path, scope: str) -> pathlib.Path:
    return workspace / ".codex" if str(scope or "").strip().lower() == "project" else _home() / ".codex"


def _codex_agents_doc_path(workspace: pathlib.Path, scope: str) -> pathlib.Path:
    return _codex_scope_root(workspace, scope) / "AGENTS.md"


def _codex_rules_path(workspace: pathlib.Path, scope: str) -> pathlib.Path:
    return _codex_scope_root(workspace, scope) / "rules" / CODEX_AIRG_RULES_FILE


def _read_text_optional(path: pathlib.Path) -> str:
    try:
        if not path.exists() or not path.is_file():
            return ""
        return path.read_text()
    except Exception:
        return ""


def _find_managed_block(text: str, begin_token: str, end_token: str) -> tuple[int, int]:
    begin_index = text.find(begin_token)
    if begin_index < 0:
        return -1, -1
    end_index = text.find(end_token, begin_index)
    if end_index < 0:
        return -1, -1
    end_index = end_index + len(end_token)
    while end_index < len(text) and text[end_index] in {"\r", "\n"}:
        end_index += 1
    return begin_index, end_index


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _deep_merge_dict(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = json.loads(json.dumps(base))
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge_dict(out[key], value)
        else:
            out[key] = json.loads(json.dumps(value))
    return out


def _effective_policy_for_agent(agent_id: str) -> dict[str, Any]:
    policy_path = pathlib.Path(os.environ.get("AIRG_POLICY_PATH", "")).expanduser()
    if not str(policy_path):
        return {}
    payload = _read_json(policy_path)
    if not isinstance(payload, dict):
        return {}
    overrides = payload.get("agent_overrides")
    if isinstance(overrides, dict):
        override_entry = overrides.get(agent_id, {})
        if isinstance(override_entry, dict):
            overlay = override_entry.get("policy", {})
            if isinstance(overlay, dict) and overlay:
                return _deep_merge_dict(payload, overlay)
    return payload


def _codex_tier1_guidance_present(path: pathlib.Path) -> bool:
    text = _read_text_optional(path)
    if not text:
        return False
    start, end = _find_managed_block(text, CODEX_AGENT_DOC_BEGIN, CODEX_AGENT_DOC_END)
    return start >= 0 and end >= 0


def _parse_codex_rules_metadata(text: str) -> dict[str, Any]:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith(CODEX_RULES_BEGIN):
            continue
        raw = stripped[len(CODEX_RULES_BEGIN) :].strip()
        if not raw:
            return {}
        try:
            payload = json.loads(raw)
        except Exception:
            return {}
        return payload if isinstance(payload, dict) else {}
    return {}


def _extract_codex_rules_body(text: str) -> str:
    start, end = _find_managed_block(text, CODEX_RULES_BEGIN, CODEX_RULES_END)
    if start < 0 or end < 0:
        return ""
    block = text[start:end]
    lines = []
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith(CODEX_RULES_BEGIN):
            continue
        if stripped == CODEX_RULES_END:
            continue
        lines.append(line)
    return ("\n".join(lines).strip() + "\n") if lines else ""


def _codex_rules_state(path: pathlib.Path, agent_id: str) -> dict[str, Any]:
    text = _read_text_optional(path)
    if not text:
        return {
            "present": False,
            "in_sync": False,
            "include_requires_confirmation": False,
            "mirror_approvals_mode": "",
            "policy_hash_match": False,
            "rules_hash_match": False,
            "metadata": {},
        }
    start, end = _find_managed_block(text, CODEX_RULES_BEGIN, CODEX_RULES_END)
    if start < 0 or end < 0:
        return {
            "present": False,
            "in_sync": False,
            "include_requires_confirmation": False,
            "mirror_approvals_mode": "",
            "policy_hash_match": False,
            "rules_hash_match": False,
            "metadata": {},
        }
    metadata = _parse_codex_rules_metadata(text)
    body = _extract_codex_rules_body(text)
    body_hash = _sha256_text(body)
    generated_hash = str(metadata.get("generated_rules_hash", "")).strip()
    rules_hash_match = bool(generated_hash) and generated_hash == body_hash
    include_requires_confirmation = bool(metadata.get("include_requires_confirmation", False))
    mirror_approvals_mode = str(metadata.get("mirror_approvals_mode", "")).strip().lower()
    if mirror_approvals_mode not in {"allow", "approve", "deny"}:
        mirror_approvals_mode = "approve" if include_requires_confirmation else "allow"
    effective_policy = _effective_policy_for_agent(agent_id)
    policy_hash = _sha256_text(json.dumps(effective_policy, sort_keys=True, separators=(",", ":"))) if effective_policy else ""
    policy_hash_match = bool(policy_hash) and str(metadata.get("policy_hash", "")).strip() == policy_hash
    return {
        "present": True,
        "in_sync": bool(rules_hash_match and policy_hash_match),
        "include_requires_confirmation": include_requires_confirmation,
        "mirror_approvals_mode": mirror_approvals_mode,
        "policy_hash_match": policy_hash_match,
        "rules_hash_match": rules_hash_match,
        "metadata": metadata,
    }


def _codex_tier3_state(path: pathlib.Path) -> dict[str, Any]:
    text = _read_text_optional(path)
    if not text.strip():
        return {
            "present": False,
            "sandbox_mode": "",
            "approval_policy": "",
            "network_access": None,
            "exclude_slash_tmp": None,
            "exclude_tmpdir_env_var": None,
            "hardened": False,
        }
    try:
        payload = tomllib.loads(text)
    except Exception:
        return {
            "present": False,
            "sandbox_mode": "",
            "approval_policy": "",
            "network_access": None,
            "exclude_slash_tmp": None,
            "exclude_tmpdir_env_var": None,
            "hardened": False,
        }
    sandbox_mode = str(payload.get("sandbox_mode", "")).strip().lower()
    approval_policy = str(payload.get("approval_policy", "")).strip().lower()
    workspace_cfg = payload.get("sandbox_workspace_write", {})
    network_access = None
    exclude_slash_tmp = None
    exclude_tmpdir_env_var = None
    if isinstance(workspace_cfg, dict) and "network_access" in workspace_cfg:
        network_access = bool(workspace_cfg.get("network_access"))
    if isinstance(workspace_cfg, dict) and "exclude_slash_tmp" in workspace_cfg:
        exclude_slash_tmp = bool(workspace_cfg.get("exclude_slash_tmp"))
    if isinstance(workspace_cfg, dict) and "exclude_tmpdir_env_var" in workspace_cfg:
        exclude_tmpdir_env_var = bool(workspace_cfg.get("exclude_tmpdir_env_var"))
    present = bool(sandbox_mode) and bool(approval_policy)
    hardened = (
        sandbox_mode in {"read-only", "workspace-write"}
        and approval_policy in {"untrusted", "on-request"}
    )
    return {
        "present": present,
        "sandbox_mode": sandbox_mode,
        "approval_policy": approval_policy,
        "network_access": network_access,
        "exclude_slash_tmp": exclude_slash_tmp,
        "exclude_tmpdir_env_var": exclude_tmpdir_env_var,
        "hardened": hardened,
    }


def _codex_has_airg_mcp(path: pathlib.Path) -> bool:
    try:
        if not path.exists() or not path.is_file():
            return False
        for line in path.read_text().splitlines():
            m = _CODEX_SECTION_RE.match(line)
            if not m:
                continue
            if str(m.group(1)).strip() == "mcp_servers.ai-runtime-guard":
                return True
        return False
    except Exception:
        return False


def _build_claude_desktop_posture(profile: dict[str, Any]) -> dict[str, Any]:
    config_path = _claude_desktop_config_path()
    payload = _read_json(config_path)
    has_mcp = _contains_airg_mcp(payload)
    status = "green" if has_mcp else "gray"
    rationale = (
        "AIRG MCP is configured in Claude Desktop. MCP-layer enforcement is active."
        if has_mcp
        else "No AIRG MCP server configuration detected in Claude Desktop config."
    )
    detected_scopes = ["desktop"] if has_mcp else []
    signals = {"airg_mcp_present": has_mcp}
    return {
        "status": status,
        "rationale": rationale,
        "signals": signals,
        "signal_scopes": {"airg_mcp_present": detected_scopes},
        "mcp_detected_scopes": detected_scopes,
        "mcp_detected_locations": ([{"scope": "desktop", "path": str(config_path)}] if has_mcp else []),
        "mcp_expected_scope": "desktop",
        "mcp_scope_match": has_mcp,
        "native_tools_denied": [],
        "missing_controls": [] if has_mcp else ["AIRG MCP configured"],
        "recommended_actions": (
            ["Claude Desktop is MCP-layer protected."]
            if has_mcp
            else ["Add ai-runtime-guard MCP server to Claude Desktop config."]
        ),
        "paths_checked": [str(config_path)],
        "existing_paths": [str(config_path)] if config_path.exists() else [],
    }


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


def _is_airg_hook_command(value: Any) -> bool:
    cmd = str(value or "").strip()
    if not cmd:
        return False
    if cmd == "airg-hook":
        return True
    head = cmd.split()[0]
    return pathlib.Path(head).name == "airg-hook"


def _cursor_matcher_matches_tool(matcher: str, tool: str) -> bool:
    raw = str(matcher or "").strip()
    if not raw:
        return True
    segments = [segment.strip() for segment in raw.split("|") if segment.strip()]
    if segments and tool in segments:
        return True
    try:
        return bool(re.search(raw, tool))
    except Exception:
        return False


def _cursor_hook_signals_for_payload(payload: dict[str, Any]) -> dict[str, Any]:
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return {
            "pretool_tools": set(),
            "before_shell": False,
            "before_shell_fail_closed": False,
            "before_mcp": False,
            "before_mcp_fail_closed": False,
        }

    pretool_tools: set[str] = set()
    pre_tool_use = hooks.get("preToolUse", [])
    if isinstance(pre_tool_use, list):
        for entry in pre_tool_use:
            if not isinstance(entry, dict) or not _is_airg_hook_command(entry.get("command")):
                continue
            matcher = str(entry.get("matcher", "")).strip()
            for tool in (CURSOR_TIER1_TOOLS | CURSOR_TIER2_TOOLS):
                if _cursor_matcher_matches_tool(matcher, tool):
                    pretool_tools.add(tool)

    before_shell = False
    before_shell_fail_closed = False
    before_shell_entries = hooks.get("beforeShellExecution", [])
    if isinstance(before_shell_entries, list):
        for entry in before_shell_entries:
            if not isinstance(entry, dict) or not _is_airg_hook_command(entry.get("command")):
                continue
            before_shell = True
            before_shell_fail_closed = before_shell_fail_closed or bool(entry.get("failClosed", False))

    before_mcp = False
    before_mcp_fail_closed = False
    before_mcp_entries = hooks.get("beforeMCPExecution", [])
    if isinstance(before_mcp_entries, list):
        for entry in before_mcp_entries:
            if not isinstance(entry, dict) or not _is_airg_hook_command(entry.get("command")):
                continue
            before_mcp = True
            before_mcp_fail_closed = before_mcp_fail_closed or bool(entry.get("failClosed", False))

    return {
        "pretool_tools": pretool_tools,
        "before_shell": before_shell,
        "before_shell_fail_closed": before_shell_fail_closed,
        "before_mcp": before_mcp,
        "before_mcp_fail_closed": before_mcp_fail_closed,
    }


def _cursor_permissions_signals(payload: dict[str, Any]) -> dict[str, bool]:
    mcp_allowlist = payload.get("mcpAllowlist", [])
    mcp_entries = [str(item).strip().lower() for item in mcp_allowlist if isinstance(item, str)]
    mcp_allow = any(entry in {"*:*", "ai-runtime-guard:*"} for entry in mcp_entries)
    terminal_allowlist = payload.get("terminalAllowlist", [])
    terminal_entries = [str(item).strip() for item in terminal_allowlist if isinstance(item, str)]
    return {
        "permissions_airg_allowlist_configured": mcp_allow,
        "permissions_terminal_allowlist_locked": isinstance(terminal_allowlist, list) and len(terminal_entries) == 0,
    }


def _cursor_sandbox_effective(workspace: pathlib.Path) -> dict[str, Any]:
    effective: dict[str, Any] = {
        "type": "workspace_readwrite",
        "additionalReadwritePaths": [],
        "additionalReadonlyPaths": [],
        "disableTmpWrite": False,
        "enableSharedBuildCache": False,
        "networkPolicy": {"default": "deny", "allow": [], "deny": []},
    }
    for _, path in _cursor_sandbox_paths(workspace):
        payload = _read_jsonc(path)
        if not isinstance(payload, dict):
            continue
        if str(payload.get("type", "")).strip():
            effective["type"] = str(payload.get("type")).strip()
        rw = payload.get("additionalReadwritePaths", [])
        if isinstance(rw, list):
            current = [str(item).strip() for item in effective.get("additionalReadwritePaths", []) if str(item).strip()]
            additions = [str(item).strip() for item in rw if str(item).strip()]
            effective["additionalReadwritePaths"] = list(dict.fromkeys(current + additions))
        ro = payload.get("additionalReadonlyPaths", [])
        if isinstance(ro, list):
            current = [str(item).strip() for item in effective.get("additionalReadonlyPaths", []) if str(item).strip()]
            additions = [str(item).strip() for item in ro if str(item).strip()]
            effective["additionalReadonlyPaths"] = list(dict.fromkeys(current + additions))
        if bool(payload.get("disableTmpWrite", False)):
            effective["disableTmpWrite"] = True
        if bool(payload.get("enableSharedBuildCache", False)):
            effective["enableSharedBuildCache"] = True

        net = payload.get("networkPolicy", {})
        if isinstance(net, dict):
            net_eff = effective.get("networkPolicy", {})
            if not isinstance(net_eff, dict):
                net_eff = {"default": "deny", "allow": [], "deny": []}
            this_default = str(net.get("default", "")).strip().lower()
            prev_default = str(net_eff.get("default", "deny")).strip().lower()
            if this_default == "deny" or prev_default == "deny":
                net_eff["default"] = "deny"
            elif this_default == "allow":
                net_eff["default"] = "allow"
            allow = net.get("allow", [])
            if isinstance(allow, list):
                merged_allow = [str(item).strip() for item in net_eff.get("allow", []) if str(item).strip()]
                merged_allow.extend([str(item).strip() for item in allow if str(item).strip()])
                net_eff["allow"] = list(dict.fromkeys(merged_allow))
            deny = net.get("deny", [])
            if isinstance(deny, list):
                merged_deny = [str(item).strip() for item in net_eff.get("deny", []) if str(item).strip()]
                merged_deny.extend([str(item).strip() for item in deny if str(item).strip()])
                net_eff["deny"] = list(dict.fromkeys(merged_deny))
            effective["networkPolicy"] = net_eff
    return effective


def _cursor_sandbox_hardened(effective: dict[str, Any]) -> bool:
    sandbox_type = str(effective.get("type", "")).strip().lower()
    if sandbox_type == "insecure_none":
        return False
    if sandbox_type not in {"workspace_readwrite", "workspace_readonly"}:
        return False
    if not bool(effective.get("disableTmpWrite", False)):
        return False
    net = effective.get("networkPolicy", {})
    if not isinstance(net, dict):
        return False
    return str(net.get("default", "deny")).strip().lower() == "deny"


def _cursorignore_synced(path: pathlib.Path) -> bool:
    text = _read_text_optional(path)
    if not text:
        return False
    start, end = _find_managed_block(text, CURSORIGNORE_MANAGED_BEGIN, CURSORIGNORE_MANAGED_END)
    return start >= 0 and end >= 0


def _build_claude_posture(profile: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace_from_profile(profile)
    settings_by_scope = _claude_paths_by_scope(workspace)
    settings_paths = [settings_by_scope["user"], settings_by_scope["project"], settings_by_scope["local"]]
    effective: dict[str, Any] = {}
    for p in settings_paths:
        effective = _deep_merge(effective, _read_json(p))
    payload_by_scope = {scope: _read_json(path) for scope, path in settings_by_scope.items()}
    mcp_probe_paths = _claude_mcp_probe_paths(workspace)
    mcp_locations = _detect_claude_mcp_locations(workspace)
    mcp_scopes = list(dict.fromkeys([str(item.get("scope", "")) for item in mcp_locations if str(item.get("scope", ""))]))
    expected_scope = _normalize_claude_scope(profile.get("agent_scope"))
    has_mcp = bool(mcp_locations)
    native_denied = _native_tools_restricted(effective)
    tier1_hook_active = _hook_tier_active(effective, CLAUDE_TIER1_TOOLS)
    tier2_hook_active = _hook_tier_active(effective, CLAUDE_TIER2_TOOLS)
    sandbox_enabled, escape_closed = _sandbox_hardened(effective)
    native_tool_denied = sorted(list(_native_tools_denied_set(effective)))
    signal_scopes = {
        "tier1_hook_active": [scope for scope, payload in payload_by_scope.items() if _hook_tier_active(payload, CLAUDE_TIER1_TOOLS)],
        "tier2_hook_active": [scope for scope, payload in payload_by_scope.items() if _hook_tier_active(payload, CLAUDE_TIER2_TOOLS)],
        "native_tools_restricted": [scope for scope, payload in payload_by_scope.items() if _native_tools_restricted(payload)],
        "sandbox_enabled": [scope for scope, payload in payload_by_scope.items() if bool((_sandbox_hardened(payload))[0])],
        "sandbox_escape_closed": [scope for scope, payload in payload_by_scope.items() if bool((_sandbox_hardened(payload))[1])],
    }
    status, rationale = _score_claude(
        has_mcp=has_mcp,
        tier1_hook_active=tier1_hook_active,
        native_denied=native_denied,
        sandbox_enabled=sandbox_enabled,
        escape_closed=escape_closed,
    )
    signals = {
        "airg_mcp_present": has_mcp,
        "tier1_hook_active": tier1_hook_active,
        "native_tools_restricted": native_denied,
        "tier2_hook_active": tier2_hook_active,
        "sandbox_enabled": sandbox_enabled,
        "sandbox_escape_closed": escape_closed,
    }
    return {
        "status": status,
        "rationale": rationale,
        "signals": signals,
        "signal_scopes": signal_scopes,
        "mcp_detected_scopes": mcp_scopes,
        "mcp_detected_locations": mcp_locations,
        "mcp_expected_scope": expected_scope,
        "mcp_scope_match": (expected_scope in mcp_scopes) if has_mcp else False,
        "native_tools_denied": native_tool_denied,
        "missing_controls": _missing_controls_from_signals(signals, labels=CLAUDE_SIGNAL_LABELS),
        "recommended_actions": _claude_recommendations(signals),
        "paths_checked": [str(p) for p in settings_paths + mcp_probe_paths],
        "existing_paths": [str(p) for p in settings_paths + mcp_probe_paths if p.exists()],
    }


def _build_cursor_posture(profile: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace_from_profile(profile)
    paths = _cursor_paths(workspace)
    has_project = _contains_airg_mcp(_read_json(paths[0]))
    has_global = _contains_airg_mcp(_read_json(paths[1]))
    has_mcp = has_project or has_global
    detected_scopes: list[str] = []
    locations: list[dict[str, str]] = []
    signal_scopes: dict[str, list[str]] = {}
    if has_project:
        detected_scopes.append("project")
        locations.append({"scope": "project", "path": str(paths[0])})
    if has_global:
        detected_scopes.append("global")
        locations.append({"scope": "global", "path": str(paths[1])})
    if detected_scopes:
        signal_scopes["airg_mcp_present"] = list(detected_scopes)

    pretool_tools: set[str] = set()
    before_shell = False
    before_shell_fail_closed = False
    before_mcp = False
    before_mcp_fail_closed = False
    hook_scopes: dict[str, list[str]] = {
        "hook_enforcement_active": [],
        "hook_fail_closed_active": [],
        "optional_read_hooks_active": [],
    }
    hook_paths = _cursor_hooks_paths(workspace)
    for scope, path in hook_paths:
        payload = _read_jsonc(path)
        if not payload:
            continue
        hook_state = _cursor_hook_signals_for_payload(payload)
        scoped_tools = hook_state.get("pretool_tools", set())
        if isinstance(scoped_tools, set):
            pretool_tools.update(scoped_tools)
            if CURSOR_TIER2_TOOLS.issubset(scoped_tools):
                hook_scopes["optional_read_hooks_active"].append(scope)
        if bool(hook_state.get("before_shell", False)):
            before_shell = True
        if bool(hook_state.get("before_shell_fail_closed", False)):
            before_shell_fail_closed = True
        if bool(hook_state.get("before_mcp", False)):
            before_mcp = True
        if bool(hook_state.get("before_mcp_fail_closed", False)):
            before_mcp_fail_closed = True

        scoped_hook_active = bool(CURSOR_TIER1_TOOLS.issubset(scoped_tools) and hook_state.get("before_shell") and hook_state.get("before_mcp"))
        if scoped_hook_active:
            hook_scopes["hook_enforcement_active"].append(scope)
        scoped_fail_closed = bool(hook_state.get("before_shell_fail_closed") and hook_state.get("before_mcp_fail_closed"))
        if scoped_fail_closed:
            hook_scopes["hook_fail_closed_active"].append(scope)

    hook_enforcement_active = bool(CURSOR_TIER1_TOOLS.issubset(pretool_tools) and before_shell and before_mcp)
    hook_fail_closed_active = bool(before_shell_fail_closed and before_mcp_fail_closed)
    optional_read_hooks_active = bool(CURSOR_TIER2_TOOLS.issubset(pretool_tools))
    if hook_scopes["hook_enforcement_active"]:
        signal_scopes["hook_enforcement_active"] = list(dict.fromkeys(hook_scopes["hook_enforcement_active"]))
    if hook_scopes["hook_fail_closed_active"]:
        signal_scopes["hook_fail_closed_active"] = list(dict.fromkeys(hook_scopes["hook_fail_closed_active"]))
    if hook_scopes["optional_read_hooks_active"]:
        signal_scopes["optional_read_hooks_active"] = list(dict.fromkeys(hook_scopes["optional_read_hooks_active"]))

    permissions_payload = _read_jsonc(_cursor_permissions_path())
    permissions_signals = _cursor_permissions_signals(permissions_payload)
    if bool(permissions_signals.get("permissions_airg_allowlist_configured", False)):
        signal_scopes["permissions_airg_allowlist_configured"] = ["global"]
    if bool(permissions_signals.get("permissions_terminal_allowlist_locked", False)):
        signal_scopes["permissions_terminal_allowlist_locked"] = ["global"]

    sandbox_effective = _cursor_sandbox_effective(workspace)
    sandbox_hardened = _cursor_sandbox_hardened(sandbox_effective)
    if sandbox_hardened:
        signal_scopes["sandbox_hardened"] = [
            scope
            for scope, path in _cursor_sandbox_paths(workspace)
            if path.exists()
        ]

    cursorignore_path = _cursorignore_path(workspace)
    cursorignore_synced = _cursorignore_synced(cursorignore_path)
    if cursorignore_synced:
        signal_scopes["cursorignore_synced"] = ["project"]

    status, rationale = _score_cursor(
        has_mcp=has_mcp,
        hook_enforcement_active=hook_enforcement_active,
        hook_fail_closed_active=hook_fail_closed_active,
        sandbox_hardened=sandbox_hardened,
    )
    expected_scope = str(profile.get("agent_scope", "")).strip().lower() or "project"
    if expected_scope not in {"project", "global"}:
        expected_scope = "project"
    signals = {
        "airg_mcp_present": has_mcp,
        "hook_enforcement_active": hook_enforcement_active,
        "hook_fail_closed_active": hook_fail_closed_active,
        "optional_read_hooks_active": optional_read_hooks_active,
        "permissions_airg_allowlist_configured": bool(permissions_signals.get("permissions_airg_allowlist_configured", False)),
        "permissions_terminal_allowlist_locked": bool(permissions_signals.get("permissions_terminal_allowlist_locked", False)),
        "sandbox_hardened": sandbox_hardened,
        "cursorignore_synced": cursorignore_synced,
    }
    missing_controls = _missing_controls_from_signals(
        {
            "airg_mcp_present": signals["airg_mcp_present"],
            "hook_enforcement_active": signals["hook_enforcement_active"],
            "hook_fail_closed_active": signals["hook_fail_closed_active"],
            "sandbox_hardened": signals["sandbox_hardened"],
        },
        labels=CURSOR_SIGNAL_LABELS,
    )
    return {
        "status": status,
        "rationale": rationale,
        "signals": signals,
        "signal_scopes": signal_scopes,
        "mcp_detected_scopes": detected_scopes,
        "mcp_detected_locations": locations,
        "mcp_expected_scope": expected_scope,
        "mcp_scope_match": (expected_scope in detected_scopes) if has_mcp else False,
        "missing_controls": missing_controls,
        "recommended_actions": _cursor_recommendations(signals),
        "paths_checked": [
            *(str(p) for p in paths),
            *(str(path) for _, path in hook_paths),
            str(_cursor_permissions_path()),
            *(str(path) for _, path in _cursor_sandbox_paths(workspace)),
            str(cursorignore_path),
        ],
        "existing_paths": [
            *(str(p) for p in paths if p.exists()),
            *(str(path) for _, path in hook_paths if path.exists()),
            *([str(_cursor_permissions_path())] if _cursor_permissions_path().exists() else []),
            *(str(path) for _, path in _cursor_sandbox_paths(workspace) if path.exists()),
            *([str(cursorignore_path)] if cursorignore_path.exists() else []),
        ],
        "cursor_sandbox_type": str(sandbox_effective.get("type", "")).strip().lower(),
        "cursor_sandbox_disable_tmp_write": bool(sandbox_effective.get("disableTmpWrite", False)),
        "cursor_sandbox_network_default": str((sandbox_effective.get("networkPolicy", {}) or {}).get("default", "")).strip().lower(),
    }


def _build_codex_posture(profile: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace_from_profile(profile)
    paths = _codex_paths(workspace)
    expected_scope = str(profile.get("agent_scope", "")).strip().lower() or "global"
    scope_index = 1 if expected_scope == "project" else 0
    has_global = _codex_has_airg_mcp(paths[0])
    has_project = _codex_has_airg_mcp(paths[1])
    has_mcp = has_global or has_project
    tier1_path = _codex_agents_doc_path(workspace, expected_scope)
    tier2_path = _codex_rules_path(workspace, expected_scope)
    tier3_path = paths[scope_index]
    tier1_guidance = _codex_tier1_guidance_present(tier1_path)
    tier2_state = _codex_rules_state(tier2_path, str(profile.get("agent_id", "")).strip())
    tier2_present = bool(tier2_state.get("present", False))
    tier2_in_sync = bool(tier2_state.get("in_sync", False))
    tier2_approvals_mode = str(tier2_state.get("mirror_approvals_mode", "")).strip().lower()
    tier2_approvals_configured = tier2_approvals_mode in {"allow", "approve", "deny"}
    tier3_state = _codex_tier3_state(tier3_path)
    tier3_present = bool(tier3_state.get("present", False))
    sandbox_mode = str(tier3_state.get("sandbox_mode", "")).strip().lower()
    approval_policy = str(tier3_state.get("approval_policy", "")).strip().lower()
    sandbox_mode_maximum = sandbox_mode == "read-only"
    approval_policy_maximum = approval_policy == "untrusted"
    network_access = tier3_state.get("network_access")
    exclude_slash_tmp = tier3_state.get("exclude_slash_tmp")
    exclude_tmpdir_env_var = tier3_state.get("exclude_tmpdir_env_var")
    workspace_write_network_blocked = network_access is False
    workspace_write_slash_tmp_blocked = exclude_slash_tmp is True
    workspace_write_tmpdir_blocked = exclude_tmpdir_env_var is True
    strict_ready = bool(has_mcp and tier1_guidance and tier2_in_sync and tier2_approvals_configured)
    maximum_ready = bool(strict_ready and sandbox_mode_maximum and approval_policy_maximum)

    if not has_mcp:
        status = "gray"
        rationale = "No AIRG MCP server configuration detected."
    elif maximum_ready:
        status = "green"
        rationale = "Maximum Codex enforcement detected: Standard + Strict + read-only sandbox + untrusted approvals."
    elif strict_ready:
        status = "yellow"
        rationale = "Strict Codex enforcement detected: MCP + guidance + policy mirror."
    else:
        status = "red"
        rationale = "Standard Codex enforcement detected: AIRG MCP configured."

    detected_scopes: list[str] = []
    if has_global:
        detected_scopes.append("global")
    if has_project:
        detected_scopes.append("project")
    locations = []
    if has_global:
        locations.append({"scope": "global", "path": str(paths[0])})
    if has_project:
        locations.append({"scope": "project", "path": str(paths[1])})
    signals = {
        "airg_mcp_present": has_mcp,
        "tier1_guidance_present": tier1_guidance,
        "tier2_rules_present": tier2_present,
        "tier2_rules_in_sync": tier2_in_sync,
        "tier2_mirror_approvals_configured": tier2_approvals_configured,
        "sandbox_mode_maximum": sandbox_mode_maximum,
        "approval_policy_maximum": approval_policy_maximum,
        "workspace_write_network_blocked": workspace_write_network_blocked,
        "workspace_write_slash_tmp_blocked": workspace_write_slash_tmp_blocked,
        "workspace_write_tmpdir_blocked": workspace_write_tmpdir_blocked,
    }
    missing_controls = []
    if not has_mcp:
        missing_controls.append("AIRG MCP configured")
    if has_mcp and not tier1_guidance:
        missing_controls.append("Guidance configured")
    if has_mcp and not tier2_present:
        missing_controls.append("Policy mirror configured")
    if has_mcp and tier2_present and not tier2_in_sync:
        missing_controls.append("Policy mirror in sync")
    if has_mcp and not tier2_approvals_configured:
        missing_controls.append("Mirror approvals mode configured")
    if has_mcp and strict_ready and not sandbox_mode_maximum:
        missing_controls.append("Sandbox mode read-only")
    if has_mcp and strict_ready and not approval_policy_maximum:
        missing_controls.append("Approval policy untrusted")

    recommendations: list[str] = []
    if not has_mcp:
        recommendations.append("Add ai-runtime-guard MCP server to Codex config.toml (global or project scope).")
    else:
        if not tier1_guidance:
            recommendations.append("Apply Codex guidance in the selected Codex scope AGENTS.md.")
        if not tier2_present:
            recommendations.append("Apply Codex AIRG policy mirror to the selected scope rules/airg.rules.")
        elif not tier2_in_sync:
            recommendations.append("Codex policy mirror drifted from AIRG policy. Reapply enforcement.")
        if strict_ready and not sandbox_mode_maximum:
            recommendations.append("Set Codex sandbox_mode to read-only for maximum posture.")
        if strict_ready and not approval_policy_maximum:
            recommendations.append("Set Codex approval_policy to untrusted for maximum posture.")

    return {
        "status": status,
        "rationale": rationale,
        "signals": signals,
        "signal_scopes": {
            "airg_mcp_present": detected_scopes,
            "tier1_guidance_present": ([expected_scope] if tier1_guidance else []),
            "tier2_rules_present": ([expected_scope] if tier2_present else []),
            "tier2_rules_in_sync": ([expected_scope] if tier2_in_sync else []),
            "tier2_mirror_approvals_configured": ([expected_scope] if tier2_present else []),
            "sandbox_mode_maximum": ([expected_scope] if tier3_present else []),
            "approval_policy_maximum": ([expected_scope] if tier3_present else []),
            "workspace_write_network_blocked": ([expected_scope] if tier3_present else []),
            "workspace_write_slash_tmp_blocked": ([expected_scope] if tier3_present else []),
            "workspace_write_tmpdir_blocked": ([expected_scope] if tier3_present else []),
        },
        "mcp_detected_scopes": detected_scopes,
        "mcp_detected_locations": locations,
        "mcp_expected_scope": expected_scope,
        "mcp_scope_match": (expected_scope in detected_scopes) if has_mcp else False,
        "missing_controls": missing_controls,
        "recommended_actions": recommendations,
        "paths_checked": [str(p) for p in paths + [tier1_path, tier2_path, tier3_path]],
        "existing_paths": [str(p) for p in paths + [tier1_path, tier2_path, tier3_path] if p.exists()],
        "codex_tier2_include_requires_confirmation": bool(tier2_state.get("include_requires_confirmation", False)),
        "codex_tier2_mirror_approvals_mode": tier2_approvals_mode or "allow",
        "codex_tier2_policy_hash_match": bool(tier2_state.get("policy_hash_match", False)),
        "codex_tier2_rules_hash_match": bool(tier2_state.get("rules_hash_match", False)),
        "codex_tier3_sandbox_mode": sandbox_mode,
        "codex_tier3_approval_policy": approval_policy,
        "codex_tier3_network_access": network_access,
        "codex_tier3_exclude_slash_tmp": exclude_slash_tmp,
        "codex_tier3_exclude_tmpdir_env_var": exclude_tmpdir_env_var,
    }


def _build_generic_posture(profile: dict[str, Any]) -> dict[str, Any]:
    workspace = _workspace_from_profile(profile)
    paths = _claude_mcp_probe_paths(workspace)
    has_mcp = any(_contains_airg_mcp(_read_json(p)) for p in paths)
    status = "red" if has_mcp else "gray"
    rationale = (
        "AIRG MCP detected. Advanced client-side hardening depends on agent support."
        if has_mcp
        else "No AIRG MCP server configuration detected."
    )
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
        "agent_scope": str(profile.get("agent_scope", "")).strip().lower(),
        "agent_id": str(profile.get("agent_id", "")).strip(),
        "workspace": str(profile.get("workspace", "")).strip(),
    }
    agent_type = normalized["agent_type"]
    if agent_type == "claude_code":
        posture = _build_claude_posture(profile)
    elif agent_type == "claude_desktop":
        posture = _build_claude_desktop_posture(profile)
    elif agent_type == "codex":
        posture = _build_codex_posture(profile)
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
        ("claude_desktop", _claude_desktop_config_path(), "desktop"),
        ("codex", home / ".codex" / "config.toml", "global"),
    ]
    for workspace in known_workspaces:
        candidates.extend(
            [
                ("cursor", workspace / ".cursor" / "mcp.json", "workspace"),
                ("claude_code", workspace / ".claude" / "settings.json", "workspace"),
                ("claude_code", workspace / ".claude" / "settings.local.json", "workspace"),
                ("codex", workspace / ".codex" / "config.toml", "project"),
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


def _normalize_path(path_value: Any) -> str:
    raw = str(path_value or "").strip()
    if not raw:
        return ""
    try:
        return str(pathlib.Path(raw).expanduser().resolve())
    except Exception:
        return raw


def _filter_registered_discovered(
    profile_postures: list[dict[str, Any]],
    discovered: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    registered: set[tuple[str, str]] = set()
    for row in profile_postures:
        if not isinstance(row, dict):
            continue
        agent_type = str(row.get("agent_type", "")).strip().lower()
        if not agent_type:
            continue
        paths_checked = row.get("paths_checked", [])
        if isinstance(paths_checked, list):
            for path in paths_checked:
                norm = _normalize_path(path)
                if norm:
                    registered.add((agent_type, norm))
        detected_locations = row.get("mcp_detected_locations", [])
        if isinstance(detected_locations, list):
            for item in detected_locations:
                if not isinstance(item, dict):
                    continue
                norm = _normalize_path(item.get("path"))
                if norm:
                    registered.add((agent_type, norm))

    filtered: list[dict[str, Any]] = []
    for item in discovered:
        if not isinstance(item, dict):
            continue
        agent_type = str(item.get("agent_type", "")).strip().lower()
        path_norm = _normalize_path(item.get("path"))
        if not agent_type or not path_norm:
            filtered.append(item)
            continue
        if (agent_type, path_norm) in registered:
            continue
        filtered.append(item)
    return filtered


def _sort_discovered(discovered: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        discovered,
        key=lambda x: (str(x.get("agent_type", "")), str(x.get("scope", "")), str(x.get("path", ""))),
    )


def _known_workspaces_from_profiles(profiles: list[dict[str, Any]]) -> list[pathlib.Path]:
    workspaces: list[pathlib.Path] = []
    for profile in profiles:
        raw = str((profile or {}).get("workspace", "")).strip()
        if not raw:
            continue
        try:
            workspaces.append(pathlib.Path(raw).expanduser().resolve())
        except Exception:
            continue
    return workspaces


def detect_unregistered_for_profiles(profiles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    profile_postures = [build_posture_for_profile(profile) for profile in profiles]
    workspaces = _known_workspaces_from_profiles(profiles)
    discovered_raw = detect_unregistered_configs(known_workspaces=workspaces)
    return _sort_discovered(_filter_registered_discovered(profile_postures, discovered_raw))


def build_posture_summary(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    profile_postures = [build_posture_for_profile(profile) for profile in profiles]
    workspaces = _known_workspaces_from_profiles(profiles)
    discovered_raw = detect_unregistered_configs(known_workspaces=workspaces)
    discovered = _sort_discovered(_filter_registered_discovered(profile_postures, discovered_raw))
    totals = {"gray": 0, "green": 0, "yellow": 0, "red": 0}
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
