import json
import os
import pathlib
import platform
import re
import sys
from datetime import UTC, datetime
from typing import Any


REDIRECTS = {
    "Bash": "mcp__ai-runtime-guard__execute_command",
    "Shell": "mcp__ai-runtime-guard__execute_command",
    "Write": "mcp__ai-runtime-guard__write_file",
    "Edit": "mcp__ai-runtime-guard__edit_file",
    "MultiEdit": "mcp__ai-runtime-guard__edit_file",
    "Delete": "mcp__ai-runtime-guard__delete_file",
}
ALWAYS_ALLOW = {
    "Read",
    "Glob",
    "Grep",
    "LS",
    "Task",
    "WebSearch",
}
SENSITIVE_READ_SUFFIXES = (".env", ".pem", ".key")
HOOK_VERSION = "v2.3.1"
_POLICY_CACHE: dict[str, Any] = {"path": "", "mtime_ns": None, "blocked_paths": [], "blocked_extensions": []}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _default_activity_log_path() -> pathlib.Path:
    explicit = str(os.environ.get("AIRG_LOG_PATH", "")).strip()
    if explicit:
        return pathlib.Path(explicit).expanduser().resolve()
    if os.name == "nt":
        appdata = str(os.environ.get("APPDATA", "")).strip()
        if appdata:
            return (pathlib.Path(appdata).expanduser().resolve() / "ai-runtime-guard" / "activity.log").resolve()
    if platform.system() == "Darwin":
        return (pathlib.Path.home() / "Library" / "Application Support" / "ai-runtime-guard" / "activity.log").resolve()
    xdg = str(os.environ.get("XDG_STATE_HOME", "")).strip()
    if xdg:
        return (pathlib.Path(xdg).expanduser().resolve() / "ai-runtime-guard" / "activity.log").resolve()
    return (pathlib.Path.home() / ".local" / "state" / "ai-runtime-guard" / "activity.log").resolve()


def _extract_session_id(payload: dict[str, Any]) -> str:
    env_session = str(os.environ.get("AIRG_AGENT_SESSION_ID", "")).strip()
    if env_session:
        return env_session
    for key in ("agent_session_id", "session_id"):
        raw = str(payload.get(key, "")).strip()
        if raw:
            return raw
    session = payload.get("session")
    if isinstance(session, dict):
        for key in ("mcp_session_id", "session_id", "id"):
            raw = str(session.get(key, "")).strip()
            if raw:
                return raw
    return "unknown"


def _extract_agent_id(payload: dict[str, Any]) -> str:
    env_agent = str(os.environ.get("AIRG_AGENT_ID", "")).strip()
    if env_agent:
        return env_agent
    raw = str(payload.get("agent_id", "")).strip()
    if raw:
        return raw
    return "unknown"


def _extract_workspace(payload: dict[str, Any]) -> str:
    env_workspace = str(os.environ.get("AIRG_WORKSPACE", "")).strip()
    if env_workspace:
        return env_workspace
    raw = str(payload.get("workspace", "")).strip()
    if raw:
        return raw
    return ""


def _build_activity_entry(
    *,
    payload: dict[str, Any],
    tool_name: str,
    allowed: bool,
    event: str = "hook_pretooluse_checked",
    **extra: Any,
) -> dict[str, Any]:
    session_id = _extract_session_id(payload)
    entry: dict[str, Any] = {
        "timestamp": _utc_now(),
        "source": "airg-hook",
        "agent_id": _extract_agent_id(payload),
        "session_id": session_id,
        "agent_session_id": session_id,
        "tool": tool_name,
        "workspace": _extract_workspace(payload),
        "policy_decision": "allowed" if allowed else "blocked",
        "decision_tier": "allowed" if allowed else "blocked",
        "event": event,
    }
    entry.update(extra)
    entry["hook_version"] = HOOK_VERSION
    return entry


def _append_log(entry: dict[str, Any]) -> None:
    try:
        path = _default_activity_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except Exception:
        pass


def _emit_deny(reason: str, *, hook_event_name: str = "PreToolUse") -> int:
    payload = {
        "permission": "deny",
        "user_message": reason,
        "agent_message": reason,
        "hookSpecificOutput": {
            "hookEventName": hook_event_name,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        # Legacy compatibility fields for older clients that may still read these keys.
        "decision": "deny",
        "reason": reason,
        "message": reason,
    }
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()
    return 0


def _extract_detail(tool_name: str, tool_input: dict[str, Any]) -> str:
    if tool_name in {"Bash", "Shell"}:
        return str(tool_input.get("command", "")).strip()
    if tool_name == "Read":
        return str(tool_input.get("file_path", "")).strip()
    candidates = _extract_path_candidates(tool_input)
    if candidates:
        return ", ".join(candidates[:4])
    return str(tool_input.get("path", "")).strip()


def _is_sensitive_read(tool_input: dict[str, Any]) -> bool:
    path = str(tool_input.get("file_path", "")).strip().lower()
    if not path:
        return False
    if any(path.endswith(suffix) for suffix in SENSITIVE_READ_SUFFIXES):
        return True
    if "/secrets/" in path:
        return True
    return False


def _policy_path() -> pathlib.Path:
    raw = str(os.environ.get("AIRG_POLICY_PATH", "")).strip()
    if raw:
        return pathlib.Path(raw).expanduser().resolve()
    if platform.system() == "Darwin":
        return (pathlib.Path.home() / "Library" / "Application Support" / "ai-runtime-guard" / "policy.json").resolve()
    xdg = str(os.environ.get("XDG_STATE_HOME", "")).strip()
    if xdg:
        return (pathlib.Path(xdg).expanduser().resolve() / "ai-runtime-guard" / "policy.json").resolve()
    return (pathlib.Path.home() / ".local" / "state" / "ai-runtime-guard" / "policy.json").resolve()


def _load_blocked_policy_rules() -> tuple[list[str], list[str]]:
    policy = _policy_path()
    try:
        if not policy.exists() or not policy.is_file():
            return ([], [])
        mtime_ns = policy.stat().st_mtime_ns
        if _POLICY_CACHE["path"] == str(policy) and _POLICY_CACHE["mtime_ns"] == mtime_ns:
            return (
                list(_POLICY_CACHE.get("blocked_paths", [])),
                list(_POLICY_CACHE.get("blocked_extensions", [])),
            )
        payload = json.loads(policy.read_text())
        blocked = payload.get("blocked", {}) if isinstance(payload, dict) else {}
        blocked_paths = [str(v).strip().lower() for v in (blocked.get("paths", []) or []) if str(v).strip()]
        blocked_extensions = [str(v).strip().lower() for v in (blocked.get("extensions", []) or []) if str(v).strip()]
        _POLICY_CACHE.update(
            {
                "path": str(policy),
                "mtime_ns": mtime_ns,
                "blocked_paths": blocked_paths,
                "blocked_extensions": blocked_extensions,
            }
        )
        return (blocked_paths, blocked_extensions)
    except Exception:
        return ([], [])


def _extract_path_candidates(tool_input: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    key_hints = ("path", "file", "dir", "cwd", "root", "include", "exclude", "glob")

    def add(value: str) -> None:
        candidate = str(value or "").strip()
        if not candidate:
            return
        marker = candidate.lower()
        if marker in seen:
            return
        seen.add(marker)
        out.append(candidate)

    def walk(node: Any, key_name: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, str(k).strip().lower())
            return
        if isinstance(node, list):
            for item in node:
                walk(item, key_name)
            return
        if isinstance(node, str):
            text = node.strip()
            if not text:
                return
            hinted = any(hint in key_name for hint in key_hints)
            looks_like_path = (
                text.startswith("/")
                or text.startswith("./")
                or text.startswith("../")
                or text.startswith("~")
                or "/" in text
                or "\\" in text
            )
            if hinted or looks_like_path:
                add(text)

    walk(tool_input)
    return out


def _blocked_by_policy(path_candidate: str) -> str | None:
    blocked_paths, blocked_exts = _load_blocked_policy_rules()
    lower = path_candidate.lower()
    for blocked_path in blocked_paths:
        if blocked_path and blocked_path in lower:
            return f"blocked path pattern '{blocked_path}'"
    for ext in blocked_exts:
        if ext and re.search(rf"{re.escape(ext)}\\b", lower):
            return f"blocked extension '{ext}'"
    return None


def _advanced_tool_violation(tool_name: str, tool_input: dict[str, Any]) -> str | None:
    if tool_name not in {"Read", "Glob", "Grep"}:
        return None
    for candidate in _extract_path_candidates(tool_input):
        violated = _blocked_by_policy(candidate)
        if violated:
            return (
                f"AIRG policy: native '{tool_name}' request matched {violated}. "
                "Use AIRG MCP tools within allowed path policy."
            )
    return None


def _allow() -> int:
    return 0


def _hook_event_name(payload: dict[str, Any]) -> str:
    return str(payload.get("hook_event_name") or payload.get("hookEventName") or "").strip().lower()


def _is_airg_mcp_tool(tool_name: str) -> bool:
    raw = str(tool_name or "").strip().lower()
    if not raw:
        return False
    if raw.startswith("mcp__ai-runtime-guard__"):
        return True
    if raw.startswith("mcp:"):
        return "ai-runtime-guard" in raw
    return raw.startswith("ai-runtime-guard:") or ("ai-runtime-guard" in raw and ":" in raw)


def main() -> int:
    payload: dict[str, Any] = {}
    tool_name = "unknown"
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw else {}
        if not isinstance(payload, dict):
            return _allow()
        hook_event = _hook_event_name(payload)

        if hook_event == "beforeshellexecution":
            command = str(payload.get("command", "")).strip()
            reason = "AIRG policy: native shell execution is restricted. Use mcp__ai-runtime-guard__execute_command instead."
            _append_log(
                _build_activity_entry(
                    payload=payload,
                    tool_name="Shell",
                    allowed=False,
                    event="hook_before_shell_blocked",
                    hook_reason=reason,
                    hook_detail=command,
                )
            )
            return _emit_deny(reason, hook_event_name="beforeShellExecution")

        if hook_event == "beforemcpexecution":
            tool_name = str(payload.get("tool_name", "")).strip()
            if _is_airg_mcp_tool(tool_name):
                _append_log(
                    _build_activity_entry(
                        payload=payload,
                        tool_name=tool_name,
                        allowed=True,
                        event="hook_before_mcp_allowed",
                        hook_reason="airg_mcp_tool",
                    )
                )
                return _allow()
            reason = "AIRG policy: non-AIRG MCP tool is restricted. Use ai-runtime-guard MCP tools only."
            _append_log(
                _build_activity_entry(
                    payload=payload,
                    tool_name=tool_name or "mcp",
                    allowed=False,
                    event="hook_before_mcp_blocked",
                    hook_reason=reason,
                )
            )
            return _emit_deny(reason, hook_event_name="beforeMCPExecution")

        if hook_event == "beforereadfile":
            file_path = str(payload.get("file_path", "")).strip()
            lowered = file_path.lower()
            violated = _blocked_by_policy(file_path) if file_path else None
            if not violated and lowered:
                if any(lowered.endswith(suffix) for suffix in SENSITIVE_READ_SUFFIXES) or "/secrets/" in lowered:
                    violated = "sensitive read target"
            if violated:
                reason = f"AIRG policy: read blocked ({violated}). Use AIRG MCP tools within allowed path policy."
                _append_log(
                    _build_activity_entry(
                        payload=payload,
                        tool_name="Read",
                        allowed=False,
                        event="hook_before_read_blocked",
                        hook_reason=reason,
                        hook_detail=file_path,
                    )
                )
                return _emit_deny(reason, hook_event_name="beforeReadFile")
            _append_log(
                _build_activity_entry(
                    payload=payload,
                    tool_name="Read",
                    allowed=True,
                    event="hook_before_read_allowed",
                    hook_reason="read_allowed",
                    hook_detail=file_path,
                )
            )
            return _allow()

        tool_name = str(payload.get("tool_name", "")).strip()
        tool_input = payload.get("tool_input", {})
        if not isinstance(tool_input, dict):
            tool_input = {}

        # Always allow AIRG MCP tool calls.
        if _is_airg_mcp_tool(tool_name):
            _append_log(
                _build_activity_entry(
                    payload=payload,
                    tool_name=tool_name,
                    allowed=True,
                    hook_reason="airg_mcp_tool",
                )
            )
            return _allow()

        # Allow general read-only tools except sensitive read targets.
        if tool_name in ALWAYS_ALLOW:
            if tool_name == "Read" and _is_sensitive_read(tool_input):
                reason = "AIRG policy: sensitive native Read target restricted. Use mcp__ai-runtime-guard__read_file instead."
                _append_log(
                    _build_activity_entry(
                        payload=payload,
                        tool_name=tool_name,
                        allowed=False,
                        hook_reason=reason,
                        hook_detail=_extract_detail(tool_name, tool_input),
                    )
                )
                return _emit_deny(reason)
            advanced_reason = _advanced_tool_violation(tool_name, tool_input)
            if advanced_reason:
                _append_log(
                    _build_activity_entry(
                        payload=payload,
                        tool_name=tool_name,
                        allowed=False,
                        hook_reason=advanced_reason,
                        hook_detail=_extract_detail(tool_name, tool_input),
                    )
                )
                return _emit_deny(advanced_reason)
            _append_log(
                _build_activity_entry(
                    payload=payload,
                    tool_name=tool_name,
                    allowed=True,
                    hook_reason="read_only_tool",
                    hook_detail=_extract_detail(tool_name, tool_input),
                )
            )
            return _allow()

        if tool_name in REDIRECTS:
            target = REDIRECTS[tool_name]
            detail = _extract_detail(tool_name, tool_input)
            reason = (
                f"AIRG policy: native '{tool_name}' is restricted. "
                f"Use {target} instead."
            )
            if detail:
                reason = f"{reason}\nDetail: '{detail}'"
            _append_log(
                _build_activity_entry(
                    payload=payload,
                    tool_name=tool_name,
                    allowed=False,
                    hook_reason=reason,
                    hook_detail=detail,
                    hook_redirect_tool=target,
                )
            )
            return _emit_deny(reason)

        _append_log(
            _build_activity_entry(
                payload=payload,
                tool_name=tool_name or (hook_event or "hook"),
                allowed=True,
                hook_reason="unmapped_tool",
            )
        )
        return _allow()
    except Exception as exc:
        _append_log(
            _build_activity_entry(
                payload=payload,
                tool_name=tool_name,
                allowed=True,
                event="hook_fail_open",
                hook_reason=f"fail_open:{type(exc).__name__}",
                hook_error_type=type(exc).__name__,
            )
        )
        return _allow()


if __name__ == "__main__":
    raise SystemExit(main())
