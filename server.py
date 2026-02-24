"""
MCP server that exposes tools: server_info, execute_command, approve_command,
read_file, write_file, delete_file, list_directory, and restore_backup.

Policy rules are loaded from policy.json at startup. Every tool call passes
through the policy engine (blocked → requires_confirmation →
requires_simulation → allowed) before any I/O is performed. Blocked calls
are logged and rejected. Allowed file writes are backed up first; allowed
commands are optionally backed up and then executed via subprocess.

Every log entry written to activity.log is produced by build_log_entry() and
carries a session_id (UUID4, stable for the process lifetime) and a workspace
field so audit records from concurrent or sequential server instances can be
correlated and scoped to the correct working directory.
"""

import hashlib
import json
import os
import pathlib
import re
import glob
import shlex
import shutil
import subprocess
import uuid
import datetime
from urllib.parse import urlparse
from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Startup configuration — paths resolved relative to this file so the server
# works correctly regardless of the working directory it is launched from.
# ---------------------------------------------------------------------------

BASE_DIR    = pathlib.Path(__file__).parent
LOG_PATH    = str(BASE_DIR / "activity.log")
BACKUP_DIR  = str(BASE_DIR / "backups")
POLICY_PATH = BASE_DIR / "policy.json"


def _load_policy() -> dict:
    """Read policy.json and return its contents as a dictionary."""
    with open(POLICY_PATH) as f:
        return json.load(f)


def _validate_and_normalize_policy(policy: dict) -> dict:
    """
    Validate and normalize policy structure at startup.

    Fail-fast validation protects the server from silently running with
    malformed safety settings.
    """
    if not isinstance(policy, dict):
        raise ValueError("policy.json root must be an object")

    def _ensure_dict(key: str) -> dict:
        value = policy.get(key, {})
        if not isinstance(value, dict):
            raise ValueError(f"policy.{key} must be an object")
        policy[key] = value
        return value

    def _ensure_list(section: dict, key: str) -> list:
        value = section.get(key, [])
        if not isinstance(value, list):
            raise ValueError(f"policy list '{key}' must be an array")
        section[key] = value
        return value

    blocked = _ensure_dict("blocked")
    _ensure_list(blocked, "commands")
    _ensure_list(blocked, "paths")
    _ensure_list(blocked, "extensions")

    conf = _ensure_dict("requires_confirmation")
    _ensure_list(conf, "commands")
    _ensure_list(conf, "paths")
    conf.setdefault("session_whitelist_enabled", True)
    if not isinstance(conf["session_whitelist_enabled"], bool):
        raise ValueError("requires_confirmation.session_whitelist_enabled must be boolean")
    sec = conf.setdefault("approval_security", {})
    if not isinstance(sec, dict):
        raise ValueError("requires_confirmation.approval_security must be an object")
    sec.setdefault("max_failed_attempts_per_token", 5)
    sec.setdefault("failed_attempt_window_seconds", 600)
    sec.setdefault("token_ttl_seconds", 600)

    sim = _ensure_dict("requires_simulation")
    _ensure_list(sim, "commands")
    sim.setdefault("bulk_file_threshold", 10)
    sim.setdefault("max_retries", 3)
    if int(sim["bulk_file_threshold"]) < 0:
        raise ValueError("requires_simulation.bulk_file_threshold must be >= 0")
    if int(sim["max_retries"]) < 1:
        raise ValueError("requires_simulation.max_retries must be >= 1")
    budget = sim.setdefault("cumulative_budget", {})
    if not isinstance(budget, dict):
        raise ValueError("requires_simulation.cumulative_budget must be an object")
    budget.setdefault("enabled", False)
    budget.setdefault("scope", "session")
    budget.setdefault("limits", {})
    budget.setdefault("counting", {})
    budget.setdefault("reset", {})
    budget.setdefault("on_exceed", {})
    budget.setdefault("overrides", {})
    budget.setdefault("audit", {})
    limits = budget["limits"]
    if not isinstance(limits, dict):
        raise ValueError("requires_simulation.cumulative_budget.limits must be an object")
    limits.setdefault("max_unique_paths", 50)
    limits.setdefault("max_total_operations", 100)
    limits.setdefault("max_total_bytes_estimate", 104857600)
    counting = budget["counting"]
    if not isinstance(counting, dict):
        raise ValueError("requires_simulation.cumulative_budget.counting must be an object")
    counting.setdefault("mode", "affected_paths")
    counting.setdefault("dedupe_paths", True)
    counting.setdefault("include_noop_attempts", False)
    counting.setdefault("commands_included", ["rm", "mv", "write_file", "delete_file"])
    if not isinstance(counting["commands_included"], list):
        raise ValueError("requires_simulation.cumulative_budget.counting.commands_included must be an array")
    reset = budget["reset"]
    if not isinstance(reset, dict):
        raise ValueError("requires_simulation.cumulative_budget.reset must be an object")
    reset.setdefault("mode", "sliding_window")
    reset.setdefault("window_seconds", 3600)
    reset.setdefault("idle_reset_seconds", 900)
    reset.setdefault("reset_on_server_restart", True)
    on_exceed = budget["on_exceed"]
    if not isinstance(on_exceed, dict):
        raise ValueError("requires_simulation.cumulative_budget.on_exceed must be an object")
    on_exceed.setdefault("decision_tier", "blocked")
    on_exceed.setdefault("matched_rule", "requires_simulation.cumulative_budget_exceeded")
    on_exceed.setdefault("message", "Cumulative blast-radius budget exceeded for current scope.")
    overrides = budget["overrides"]
    if not isinstance(overrides, dict):
        raise ValueError("requires_simulation.cumulative_budget.overrides must be an object")
    overrides.setdefault("enabled", True)
    overrides.setdefault("require_confirmation_tool", "approve_command")
    overrides.setdefault("token_ttl_seconds", 300)
    overrides.setdefault("max_override_actions", 1)
    overrides.setdefault("audit_reason_required", True)
    overrides.setdefault("allowed_roles", ["human-operator"])
    audit_cfg = budget["audit"]
    if not isinstance(audit_cfg, dict):
        raise ValueError("requires_simulation.cumulative_budget.audit must be an object")
    audit_cfg.setdefault("log_budget_state", True)
    audit_cfg.setdefault(
        "fields",
        [
            "budget_scope",
            "budget_key",
            "cumulative_unique_paths",
            "cumulative_total_operations",
            "cumulative_total_bytes_estimate",
            "budget_remaining",
        ],
    )

    allowed = _ensure_dict("allowed")
    _ensure_list(allowed, "paths_whitelist")
    allowed.setdefault("max_files_per_operation", 10)
    allowed.setdefault("max_file_size_mb", 10)
    allowed.setdefault("max_directory_depth", 5)

    network = _ensure_dict("network")
    network.setdefault("enforcement_mode", "off")
    _ensure_list(network, "commands")
    _ensure_list(network, "allowed_domains")
    _ensure_list(network, "blocked_domains")
    network.setdefault("max_payload_size_kb", 1024)
    if network["enforcement_mode"] not in {"off", "monitor", "enforce"}:
        raise ValueError("network.enforcement_mode must be one of: off, monitor, enforce")

    execution = _ensure_dict("execution")
    execution.setdefault("max_command_timeout_seconds", 30)
    execution.setdefault("max_output_chars", 200000)
    if int(execution["max_command_timeout_seconds"]) < 1:
        raise ValueError("execution.max_command_timeout_seconds must be >= 1")
    if int(execution["max_output_chars"]) < 1024:
        raise ValueError("execution.max_output_chars must be >= 1024")

    backup_access = _ensure_dict("backup_access")
    backup_access.setdefault("block_agent_tools", True)
    _ensure_list(backup_access, "allowed_tools")
    if not isinstance(backup_access["block_agent_tools"], bool):
        raise ValueError("backup_access.block_agent_tools must be boolean")

    restore = _ensure_dict("restore")
    restore.setdefault("require_dry_run_before_apply", True)
    restore.setdefault("confirmation_ttl_seconds", 300)
    if not isinstance(restore["require_dry_run_before_apply"], bool):
        raise ValueError("restore.require_dry_run_before_apply must be boolean")
    if int(restore["confirmation_ttl_seconds"]) < 30:
        raise ValueError("restore.confirmation_ttl_seconds must be >= 30")

    audit = _ensure_dict("audit")
    audit.setdefault("backup_enabled", True)
    audit.setdefault("backup_on_content_change_only", True)
    audit.setdefault("max_versions_per_file", 5)
    audit.setdefault("backup_root", str(BASE_DIR / "backups"))
    audit.setdefault("backup_retention_days", 30)
    audit.setdefault("log_level", "verbose")
    if int(audit["max_versions_per_file"]) < 1:
        raise ValueError("audit.max_versions_per_file must be >= 1")
    _ensure_list(audit, "redact_patterns")

    return policy


# POLICY is loaded once when the server starts. Restart to pick up edits.
POLICY: dict = _validate_and_normalize_policy(_load_policy())

# Allow backup storage to live outside workspace if configured.
BACKUP_DIR = str(pathlib.Path(POLICY.get("audit", {}).get("backup_root", BACKUP_DIR)).resolve())

# MAX_RETRIES is read from policy so it can be tuned without touching code.
MAX_RETRIES: int = POLICY.get("requires_simulation", {}).get("max_retries", 3)

# Tracks sha256 hashes of normalized commands approved during this session.
# Storing hashes instead of raw strings means whitespace variations of an
# approved command (e.g. "ls  -la" vs "ls -la") are treated as identical.
# When requires_confirmation.session_whitelist_enabled is True in policy,
# a command whose hash is in this set bypasses the confirmation check.
SESSION_WHITELIST: set = set()

# Pending confirmation handshakes keyed by token. Each value contains:
#   command_hash, normalized_command, and expires_at (UTC datetime).
PENDING_APPROVALS: dict[str, dict] = {}

# Server-tracked retries for blocked commands. The client-supplied retry_count
# parameter is accepted for compatibility but is not authoritative.
SERVER_RETRY_COUNTS: dict[str, int] = {}

# Failed approval attempts tracked to throttle token guessing.
APPROVAL_FAILURES: dict[str, list[datetime.datetime]] = {}

# Cumulative blast-radius state keyed by configured scope.
CUMULATIVE_BUDGET_STATE: dict[str, dict] = {}

# Pending restore confirmations keyed by token.
PENDING_RESTORE_CONFIRMATIONS: dict[str, dict] = {}

# Generated once when the server process starts. Every log entry includes
# this ID so related records across tools can be correlated by session.
SESSION_ID: str = str(uuid.uuid4())

# Root directory that this server instance is authorised to work in.
# Override by setting the AIRG_WORKSPACE environment variable before launch.
WORKSPACE_ROOT: str = os.environ.get("AIRG_WORKSPACE", str(BASE_DIR))

# Build marker for quickly verifying the running server version.
SERVER_BUILD = "2026-02-23T22:10Z-simfix-check"

# One-time approval token validity window.
APPROVAL_TTL_SECONDS: int = POLICY.get("requires_confirmation", {}).get(
    "approval_security", {}
).get("token_ttl_seconds", 600)

RESTORE_CONFIRMATION_TTL_SECONDS: int = POLICY.get("restore", {}).get(
    "confirmation_ttl_seconds", 300
)

# Create the MCP server with a descriptive name.
mcp = FastMCP("ai-runtime-guard")


# ---------------------------------------------------------------------------
# Command normalization
# ---------------------------------------------------------------------------

def normalize_command(command: str) -> str:
    """
    Normalize a shell command for policy matching.

    Steps:
      1. Strip leading and trailing whitespace.
      2. Collapse consecutive whitespace characters into a single space.
      3. Lowercase the result.

    The lowercased form is used exclusively for pattern matching inside the
    policy engine. Original casing is never used for matching — only for
    logging via normalize_for_audit().
    """
    return re.sub(r"\s+", " ", command.strip()).lower()


def normalize_for_audit(command: str) -> str:
    """
    Normalize a shell command for audit logging.

    Steps:
      1. Strip leading and trailing whitespace.
      2. Collapse consecutive whitespace characters into a single space.
      3. Preserve original case.

    Used when building log entries so the audit trail shows a clean command
    string while still reflecting the original capitalization the agent used.
    """
    return re.sub(r"\s+", " ", command.strip())


def command_hash(command: str) -> str:
    """
    Return the sha256 hex digest of the normalized command.

    Normalization is applied first so whitespace variations of the same
    command always produce the same hash. Used as the key for SESSION_WHITELIST
    so "ls  -la" and "ls -la" are treated as a single approval.
    """
    return hashlib.sha256(normalize_command(command).encode()).hexdigest()


def _split_shell_segments(command: str) -> list[str]:
    """
    Split a shell command on separators while respecting quotes and escaping.

    This avoids regex-based splitting that can mis-handle separators embedded
    inside quoted literals.
    """
    segments: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    i = 0

    while i < len(command):
        ch = command[i]
        if escaped:
            buf.append(ch)
            escaped = False
            i += 1
            continue

        if ch == "\\":
            escaped = True
            buf.append(ch)
            i += 1
            continue

        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue

        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue

        if not in_single and not in_double and ch in {";", "|", "&"}:
            segment = "".join(buf).strip()
            if segment:
                segments.append(segment)
            buf = []
            # Collapse repeated separators (||, &&, ;;, |&).
            while i + 1 < len(command) and command[i + 1] in {";", "|", "&"}:
                i += 1
            i += 1
            continue

        buf.append(ch)
        i += 1

    final_segment = "".join(buf).strip()
    if final_segment:
        segments.append(final_segment)
    return segments


def _tokenize_shell_segment(segment: str) -> tuple[list[str], bool]:
    """Tokenize a shell segment using shlex. Returns (tokens, parse_error)."""
    try:
        return shlex.split(segment), False
    except ValueError:
        return [], True


def _tokenize_command(command: str) -> tuple[list[str], bool]:
    """
    Tokenize all segments of a shell command.

    Returns (flattened_tokens_lower, parse_error_seen).
    """
    parse_error = False
    all_tokens: list[str] = []
    for segment in _split_shell_segments(command):
        tokens, err = _tokenize_shell_segment(segment)
        parse_error = parse_error or err
        all_tokens.extend(t.lower() for t in tokens)
    return all_tokens, parse_error


def _redact_text_for_audit(value: str) -> str:
    """Redact sensitive token-like values in loggable strings."""
    text = value
    for pattern in POLICY.get("audit", {}).get("redact_patterns", []):
        try:
            text = re.sub(pattern, r"\1<redacted>", text)
        except re.error:
            continue
    return text


def _redact_for_audit(value):
    """Recursively redact log payload values."""
    if isinstance(value, str):
        return _redact_text_for_audit(value)
    if isinstance(value, list):
        return [_redact_for_audit(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact_for_audit(v) for k, v in value.items()}
    return value


def _execution_limits() -> tuple[int, int]:
    """Return configured command timeout and max output chars."""
    execution = POLICY.get("execution", {})
    timeout = int(execution.get("max_command_timeout_seconds", 30))
    max_chars = int(execution.get("max_output_chars", 200000))
    return timeout, max_chars


def _truncate_output(text: str, max_chars: int) -> str:
    """Clamp output strings to configured bounds."""
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return text[:max_chars] + f"\n...[truncated {omitted} chars]"


def _network_policy_check(command: str) -> tuple[bool, str | None]:
    """
    Validate a command against network policy.

    Returns (allowed, reason). In monitor mode this function always allows.
    """
    network = POLICY.get("network", {})
    mode = str(network.get("enforcement_mode", "off")).lower()
    if mode == "off":
        return True, None

    tokens, parse_error = _tokenize_command(command)
    lower_cmd = command.lower()
    network_markers = [m.lower() for m in network.get("commands", [])]
    is_network_intent = any(marker in lower_cmd for marker in network_markers)
    if not is_network_intent:
        return True, None

    blocked = [d.lower() for d in network.get("blocked_domains", [])]
    allowed = [d.lower() for d in network.get("allowed_domains", [])]
    domains: set[str] = set()
    for raw in tokens:
        if "://" in raw:
            parsed = urlparse(raw)
            if parsed.hostname:
                domains.add(parsed.hostname.lower())
        elif raw.startswith("http") and parse_error:
            # Best-effort fallback for malformed quoting.
            parsed = urlparse(raw)
            if parsed.hostname:
                domains.add(parsed.hostname.lower())

    def _domain_matches(domain: str, patterns: list[str]) -> bool:
        for p in patterns:
            if domain == p or domain.endswith("." + p):
                return True
        return False

    for domain in domains:
        if blocked and _domain_matches(domain, blocked):
            reason = f"Network domain '{domain}' is blocked by policy"
            if mode == "monitor":
                return True, reason
            return False, reason

    if allowed:
        for domain in domains:
            if not _domain_matches(domain, allowed):
                reason = f"Network domain '{domain}' is not in allowed_domains policy"
                if mode == "monitor":
                    return True, reason
                return False, reason

    return True, None


def _command_targets_backup_storage(command: str) -> bool:
    """Best-effort check whether command references paths under BACKUP_DIR."""
    if not POLICY.get("backup_access", {}).get("block_agent_tools", True):
        return False

    backup_root = pathlib.Path(BACKUP_DIR).resolve()
    lower = command.lower()
    if str(backup_root).lower() in lower:
        return True

    for segment in _split_shell_segments(command):
        tokens, err = _tokenize_shell_segment(segment)
        if err:
            continue
        for token in tokens:
            candidate = token.strip("'\"")
            if not candidate:
                continue
            if candidate.startswith("-"):
                continue
            if "/" not in candidate and "." not in candidate and "*" not in candidate:
                continue
            try:
                abs_path = candidate if os.path.isabs(candidate) else os.path.join(WORKSPACE_ROOT, candidate)
                resolved = pathlib.Path(abs_path).resolve()
                if resolved.is_relative_to(backup_root):
                    return True
            except Exception:
                continue
    # Extra fallback for symlinked temp paths (/tmp vs /private/tmp).
    tmp_backup_root = str(pathlib.Path(BACKUP_DIR))
    if tmp_backup_root.lower() in lower:
        return True
    return False


def _retry_key(command: str, tier: str, matched_rule: str | None) -> str:
    """
    Build a stable retry key for server-side retry enforcement.

    Retries are scoped to command + blocking tier + matched rule so repeated
    attempts cannot bypass limits by lying about retry_count.
    """
    base = f"{normalize_command(command)}|{tier}|{matched_rule or ''}"
    return hashlib.sha256(base.encode()).hexdigest()


def _register_retry(command: str, tier: str, matched_rule: str | None) -> int:
    """
    Increment and return the server-side retry count for this blocked action.

    Once a key reaches MAX_RETRIES, the stored value is clamped and will not
    increase further. This keeps final-block attempts stable in logs/audit.
    """
    key = _retry_key(command, tier, matched_rule)
    stored_count = SERVER_RETRY_COUNTS.get(key, 0)
    if stored_count >= MAX_RETRIES:
        SERVER_RETRY_COUNTS[key] = MAX_RETRIES
        return MAX_RETRIES

    stored_count += 1
    SERVER_RETRY_COUNTS[key] = stored_count
    return stored_count


def _cumulative_cfg() -> dict:
    """Return cumulative budget configuration."""
    return POLICY.get("requires_simulation", {}).get("cumulative_budget", {})


def _budget_scope_key(tool: str) -> tuple[str, str]:
    """Return (scope, key) for cumulative budget tracking."""
    cfg = _cumulative_cfg()
    scope = str(cfg.get("scope", "session")).lower()
    if scope == "workspace":
        return scope, f"{WORKSPACE_ROOT}"
    if scope == "tool":
        return scope, f"{SESSION_ID}:{tool}"
    if scope == "request":
        # Request scope can be supplied by a client wrapper.
        request_id = os.environ.get("AIRG_REQUEST_ID", SESSION_ID)
        return scope, f"{request_id}:{tool}"
    return "session", SESSION_ID


def _prune_approval_failures() -> None:
    """Drop stale approval-failure records."""
    sec = POLICY.get("requires_confirmation", {}).get("approval_security", {})
    window = int(sec.get("failed_attempt_window_seconds", 600))
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(seconds=window)
    for key in list(APPROVAL_FAILURES.keys()):
        recent = [ts for ts in APPROVAL_FAILURES[key] if ts >= cutoff]
        if recent:
            APPROVAL_FAILURES[key] = recent
        else:
            APPROVAL_FAILURES.pop(key, None)


def _approval_failures_exceeded(key: str) -> bool:
    """Return True if token/key has exceeded failure limit in active window."""
    _prune_approval_failures()
    sec = POLICY.get("requires_confirmation", {}).get("approval_security", {})
    max_failed = int(sec.get("max_failed_attempts_per_token", 5))
    return len(APPROVAL_FAILURES.get(key, [])) >= max_failed


def _record_approval_failure(key: str) -> None:
    """Record one failed approval attempt for a key."""
    _prune_approval_failures()
    APPROVAL_FAILURES.setdefault(key, []).append(datetime.datetime.utcnow())


def _estimate_paths_bytes(paths: list[str]) -> int:
    """Estimate byte impact for a list of file paths."""
    total = 0
    for p in paths:
        try:
            if os.path.isfile(p):
                total += int(os.path.getsize(p))
        except OSError:
            continue
    return total


def _budget_allows_override(scope_key: str, command: str) -> bool:
    """Return True if this action can consume an override slot."""
    cfg = _cumulative_cfg()
    overrides = cfg.get("overrides", {})
    if not overrides.get("enabled", False):
        return False
    cmd_hash = command_hash(command)
    if cmd_hash not in SESSION_WHITELIST:
        return False
    state = CUMULATIVE_BUDGET_STATE.setdefault(
        scope_key,
        {
            "unique_paths": {},
            "total_operations": 0,
            "total_bytes_estimate": 0,
            "last_activity": None,
            "overrides_used": 0,
        },
    )
    max_override = int(overrides.get("max_override_actions", 1))
    if state.get("overrides_used", 0) >= max_override:
        return False
    state["overrides_used"] = state.get("overrides_used", 0) + 1
    return True


def _prune_budget_state(scope_key: str, now: datetime.datetime) -> dict:
    """Prune/reset budget state according to configured policy."""
    cfg = _cumulative_cfg()
    reset_cfg = cfg.get("reset", {})
    window = int(reset_cfg.get("window_seconds", 3600))
    idle = int(reset_cfg.get("idle_reset_seconds", 900))
    state = CUMULATIVE_BUDGET_STATE.setdefault(
        scope_key,
        {
            "unique_paths": {},
            "total_operations": 0,
            "total_bytes_estimate": 0,
            "last_activity": None,
            "overrides_used": 0,
        },
    )
    last = state.get("last_activity")
    if last and idle > 0 and (now - last).total_seconds() > idle:
        state.update(
            {
                "unique_paths": {},
                "total_operations": 0,
                "total_bytes_estimate": 0,
                "last_activity": None,
                "overrides_used": 0,
            }
        )
        return state

    if window > 0:
        cutoff = now - datetime.timedelta(seconds=window)
        state["unique_paths"] = {
            p: seen_at
            for p, seen_at in state.get("unique_paths", {}).items()
            if seen_at >= cutoff
        }
    return state


def _check_and_record_cumulative_budget(
    *,
    tool: str,
    command: str | None,
    affected_paths: list[str],
    operation_count: int = 1,
    bytes_estimate: int | None = None,
) -> tuple[bool, str | None, str | None, dict]:
    """
    Check and record cumulative budget usage.

    Returns:
      (allowed, reason, matched_rule, budget_fields)
    """
    cfg = _cumulative_cfg()
    if not cfg.get("enabled", False):
        return True, None, None, {}

    counting = cfg.get("counting", {})
    included = {str(x).lower() for x in counting.get("commands_included", [])}
    if tool.lower() not in included:
        cmd_tokens, _ = _tokenize_command(command or "")
        if not any(tok in included for tok in cmd_tokens):
            return True, None, None, {}

    scope, scope_key = _budget_scope_key(tool)
    now = datetime.datetime.utcnow()
    state = _prune_budget_state(scope_key, now)
    existing_paths = set(state.get("unique_paths", {}).keys())
    new_paths = {str(pathlib.Path(p).resolve()) for p in affected_paths if is_within_workspace(p)}
    dedupe = bool(counting.get("dedupe_paths", True))
    include_noop = bool(counting.get("include_noop_attempts", False))
    if not new_paths and not include_noop:
        return True, None, None, {}
    prospective_unique = existing_paths | new_paths if dedupe else existing_paths.union(new_paths)
    op_increment = max(int(operation_count), 0)
    bytes_inc = int(bytes_estimate if bytes_estimate is not None else _estimate_paths_bytes(list(new_paths)))

    limits = cfg.get("limits", {})
    max_unique = int(limits.get("max_unique_paths", 50))
    max_ops = int(limits.get("max_total_operations", 100))
    max_bytes = int(limits.get("max_total_bytes_estimate", 104857600))
    next_ops = int(state.get("total_operations", 0)) + op_increment
    next_bytes = int(state.get("total_bytes_estimate", 0)) + bytes_inc

    exceeds = (
        len(prospective_unique) > max_unique
        or next_ops > max_ops
        or next_bytes > max_bytes
    )

    if exceeds and not (command and _budget_allows_override(scope_key, command)):
        on_exceed = cfg.get("on_exceed", {})
        reason = str(
            on_exceed.get(
                "message",
                "Cumulative blast-radius budget exceeded for current scope.",
            )
        )
        matched_rule = str(
            on_exceed.get("matched_rule", "requires_simulation.cumulative_budget_exceeded")
        )
        budget_fields = {
            "budget_scope": scope,
            "budget_key": scope_key,
            "cumulative_unique_paths": len(existing_paths),
            "cumulative_total_operations": int(state.get("total_operations", 0)),
            "cumulative_total_bytes_estimate": int(state.get("total_bytes_estimate", 0)),
            "budget_remaining": {
                "max_unique_paths": max(max_unique - len(existing_paths), 0),
                "max_total_operations": max(max_ops - int(state.get("total_operations", 0)), 0),
                "max_total_bytes_estimate": max(max_bytes - int(state.get("total_bytes_estimate", 0)), 0),
            },
        }
        return False, reason, matched_rule, budget_fields

    for p in new_paths:
        state.setdefault("unique_paths", {})[p] = now
    state["total_operations"] = next_ops
    state["total_bytes_estimate"] = next_bytes
    state["last_activity"] = now

    budget_fields = {
        "budget_scope": scope,
        "budget_key": scope_key,
        "cumulative_unique_paths": len(state.get("unique_paths", {})),
        "cumulative_total_operations": int(state.get("total_operations", 0)),
        "cumulative_total_bytes_estimate": int(state.get("total_bytes_estimate", 0)),
        "budget_remaining": {
            "max_unique_paths": max(max_unique - len(state.get("unique_paths", {})), 0),
            "max_total_operations": max(max_ops - int(state.get("total_operations", 0)), 0),
            "max_total_bytes_estimate": max(max_bytes - int(state.get("total_bytes_estimate", 0)), 0),
        },
    }
    return True, None, None, budget_fields


def _prune_expired_approvals() -> None:
    """Drop expired confirmation tokens from PENDING_APPROVALS."""
    now = datetime.datetime.utcnow()
    expired = [token for token, rec in PENDING_APPROVALS.items() if rec["expires_at"] <= now]
    for token in expired:
        PENDING_APPROVALS.pop(token, None)


def _issue_or_reuse_approval_token(command: str) -> tuple[str, datetime.datetime]:
    """
    Return an active approval token for command, creating one if needed.

    Reusing active tokens avoids generating a new token on every blocked retry.
    """
    _prune_expired_approvals()
    cmd_hash = command_hash(command)
    now = datetime.datetime.utcnow()

    for token, rec in PENDING_APPROVALS.items():
        if rec["command_hash"] == cmd_hash and rec["expires_at"] > now:
            return token, rec["expires_at"]

    token = uuid.uuid4().hex
    expires_at = now + datetime.timedelta(seconds=APPROVAL_TTL_SECONDS)
    PENDING_APPROVALS[token] = {
        "command_hash": cmd_hash,
        "normalized_command": normalize_for_audit(command),
        "expires_at": expires_at,
    }
    return token, expires_at


def _prune_expired_restore_confirmations() -> None:
    """Drop expired restore confirmation tokens."""
    now = datetime.datetime.utcnow()
    expired = [
        token
        for token, rec in PENDING_RESTORE_CONFIRMATIONS.items()
        if rec["expires_at"] <= now
    ]
    for token in expired:
        PENDING_RESTORE_CONFIRMATIONS.pop(token, None)


def _issue_restore_confirmation_token(backup_path: pathlib.Path, planned: int) -> tuple[str, datetime.datetime]:
    """Issue a one-time token authorizing restore apply for a specific backup."""
    _prune_expired_restore_confirmations()
    token = uuid.uuid4().hex
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=RESTORE_CONFIRMATION_TTL_SECONDS)
    PENDING_RESTORE_CONFIRMATIONS[token] = {
        "backup_path": str(backup_path.resolve()),
        "planned": int(planned),
        "expires_at": expires_at,
    }
    return token, expires_at


def _has_shell_unsafe_control_chars(command: str) -> bool:
    """
    Return True when command includes control characters we do not allow.

    Newlines and NUL bytes are blocked server-side to prevent hidden command
    chaining and parser ambiguity with shell=True.
    """
    return any(ch in command for ch in ("\x00", "\n", "\r"))


def _safe_subprocess_env() -> dict:
    """
    Build a constrained environment for shell command execution.

    Start from the parent environment for runtime compatibility, then apply
    targeted constraints and light secret stripping.
    """
    safe = os.environ.copy()
    safe["HOME"] = WORKSPACE_ROOT
    if "LANG" not in safe:
        safe["LANG"] = "C"
    if "LC_ALL" not in safe:
        safe["LC_ALL"] = safe["LANG"]

    # Best-effort removal of obviously sensitive env values before spawning.
    for key in list(safe.keys()):
        lower = key.lower()
        if any(marker in lower for marker in ("api_key", "token", "secret", "password")):
            safe.pop(key, None)

    return safe


# ---------------------------------------------------------------------------
# Policy result type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyResult:
    """
    Immutable result returned by check_policy().

    Fields:
        allowed       — True if the command may proceed, False if it was blocked.
        reason        — Human-readable explanation of the decision.
        decision_tier — Which policy tier made the decision:
                          "blocked" | "requires_confirmation" |
                          "requires_simulation" | "allowed"
        matched_rule  — The specific pattern, path, or extension that triggered
                        the match (e.g. "rm -rf", ".env", ".pem"), or None when
                        the command is allowed and no rule fired.
    """
    allowed:       bool
    reason:        str
    decision_tier: str
    matched_rule:  str | None


# ---------------------------------------------------------------------------
# Policy engine — tier helpers
# ---------------------------------------------------------------------------

def _build_command_matcher(pattern: str):
    """
    Return a callable(command: str) -> bool that tests whether a shell
    command matches *pattern*.

    Matching strategy:
    - Single-word pattern (e.g. "dd", "rm"): word-boundary regex on the
      lowercased command. This prevents "dd" from matching "pwd" or "adduser",
      and "rm" from matching "chmod" — the core reason this helper exists.
    - Multi-word pattern (e.g. "rm -rf"): plain substring match on the
      lowercased command. The extra words already provide enough context that
      word boundaries are not needed.
    """
    words = pattern.strip().split()
    lower_pattern = pattern.lower()
    if len(words) == 1:
        regex = re.compile(rf"\b{re.escape(lower_pattern)}\b")

        def _matches(cmd: str) -> bool:
            if regex.search(cmd.lower()):
                return True
            tokens, _ = _tokenize_command(cmd)
            return lower_pattern in tokens

        return _matches

    def _matches(cmd: str) -> bool:
        if lower_pattern in cmd.lower():
            return True
        tokens, _ = _tokenize_command(cmd)
        rebuilt = " ".join(tokens)
        return lower_pattern in rebuilt

    return _matches


def _check_blocked_tier(command: str) -> tuple[str, str] | None:
    """
    Check *command* against every rule in the 'blocked' policy tier.

    Checks (in order):
      1. blocked.commands   — dangerous commands (word-boundary safe)
      2. blocked.paths      — sensitive file/directory paths
      3. blocked.extensions — sensitive file extensions (.pem, .key, …)

    Returns (reason, matched_rule) if blocked, or None if the command
    passes all checks in this tier. matched_rule is the specific pattern,
    path, or extension string that triggered the match.
    """
    blocked = POLICY.get("blocked", {})
    lower   = command.lower()

    # 1. Blocked command patterns
    for pattern in blocked.get("commands", []):
        if _build_command_matcher(pattern)(command):
            return (
                f"Blocked destructive command '{pattern}': "
                "this operation is prohibited by policy",
                pattern,
            )

    # 2. Blocked file/directory paths (substring match on lowercased command)
    for path in blocked.get("paths", []):
        if path.lower() in lower:
            return (
                f"Sensitive path access not permitted: '{path}' "
                "may contain secrets or critical system configuration",
                path,
            )

    # 3. Blocked file extensions
    # re.escape handles the leading dot; \b prevents partial extension matches
    # (e.g. ".pem" should not match ".pemfile").
    for ext in blocked.get("extensions", []):
        if re.search(rf"{re.escape(ext)}\b", lower):
            return (
                f"Sensitive file extension not permitted: '{ext}' files "
                "may contain private keys or certificates",
                ext,
            )

    return None


def _check_confirmation_tier(command: str) -> tuple[str, str] | None:
    """
    Check *command* against the 'requires_confirmation' policy tier.

    If session_whitelist_enabled is True and the exact command string is
    already in SESSION_WHITELIST, the check is skipped — the user already
    approved it earlier this session.

    Returns (reason, matched_rule) if confirmation is required, or None if
    the command passes (or is whitelisted). matched_rule is the specific
    command pattern or path that triggered the match.
    """
    conf  = POLICY.get("requires_confirmation", {})
    lower = command.lower()

    # Skip the confirmation check if the command was approved earlier this
    # session. Comparison is done by hash so whitespace variants of an
    # approved command don't require a second confirmation.
    whitelist_enabled = conf.get("session_whitelist_enabled", True)
    if whitelist_enabled and command_hash(command) in SESSION_WHITELIST:
        return None

    for pattern in conf.get("commands", []):
        if _build_command_matcher(pattern)(command):
            return (
                f"Command '{pattern}' requires explicit confirmation before execution",
                pattern,
            )

    for path in conf.get("paths", []):
        if path.lower() in lower:
            return (
                f"Access to path '{path}' requires explicit confirmation",
                path,
            )

    return None


def _check_simulation_tier(command: str) -> tuple[str, str] | None:
    """
    Check *command* against the 'requires_simulation' policy tier.

    For configured commands (e.g. rm/mv), wildcard usage is simulated to
    estimate how many workspace paths would be touched. Commands are blocked
    only when simulated blast radius exceeds requires_simulation.bulk_file_threshold.

    Returns (reason, matched_rule) if simulation blocks the command, or None
    otherwise.
    """
    sim          = POLICY.get("requires_simulation", {})
    sim_commands = sim.get("commands", [])
    threshold    = sim.get("bulk_file_threshold", 10)

    if not sim_commands:
        return None

    simulation = _simulate_blast_radius(command, sim_commands)
    affected = simulation["affected"]
    saw_wildcard = simulation["saw_wildcard"]
    parse_error = simulation["parse_error"]

    # If a sensitive command used wildcards but resolved to no concrete targets
    # (or could not be parsed safely), block it and require explicit filenames.
    if saw_wildcard and (parse_error or not affected):
        return (
            "Bulk file operation blocked: wildcard pattern could not be safely "
            "simulated to concrete targets. Please specify exact filenames instead.",
            "requires_simulation.wildcard_unresolved",
        )

    if len(affected) > threshold:
        sample = ", ".join(affected[:3])
        if len(affected) > 3:
            sample += ", ..."
        return (
            f"Bulk file operation blocked: simulated blast radius is {len(affected)} "
            f"path(s), which exceeds the policy threshold of {threshold}. "
            f"Sample targets: {sample}",
            "requires_simulation.bulk_file_threshold",
        )

    return None


def _simulate_blast_radius(command: str, sim_commands: list[str]) -> dict:
    """
    Simulate wildcard expansion for sensitive commands and return simulation data.

    Expansion is constrained to WORKSPACE_ROOT and allowed roots only. Returned
    paths are normalized absolute strings, sorted for deterministic logs/tests.
    """
    affected: set[str] = set()
    lower_ops = {op.lower() for op in sim_commands}
    saw_wildcard = False
    parse_error = False

    # Split command into shell-aware segments before simulation.
    segments = _split_shell_segments(command)
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        tokens, err = _tokenize_shell_segment(segment)
        if err:
            # Tokenization failure makes simulation ambiguous; mark it so the
            # caller can conservatively block wildcard operations.
            parse_error = True
            continue
        if not tokens:
            continue

        op = tokens[0].lower()
        if op not in lower_ops:
            continue

        for token in tokens[1:]:
            if not any(ch in token for ch in ("*", "?", "[")):
                continue
            saw_wildcard = True
            pattern = token if os.path.isabs(token) else os.path.join(WORKSPACE_ROOT, token)
            for match in glob.glob(pattern):
                resolved = str(pathlib.Path(match).resolve())
                if os.path.exists(resolved) and is_within_workspace(resolved):
                    affected.add(resolved)

    return {
        "affected": sorted(affected),
        "saw_wildcard": saw_wildcard,
        "parse_error": parse_error,
    }


def _log_policy_conflict(command: str, normalized: str, matching_tiers: list) -> None:
    """
    Append a warning entry to activity.log when *command* matches more than
    one policy tier. Records which tiers matched and which one won so the
    audit trail explains the resolution.

    matching_tiers is a list of (tier_name, reason, matched_rule) 3-tuples
    in priority order. Both the original command string and the normalized
    form used for matching are included so the log is unambiguous.
    """
    tier_names = [tier for tier, _, _ in matching_tiers]
    winning_tier, _winning_reason, winning_matched_rule = matching_tiers[0]
    warning = {
        "timestamp":          datetime.datetime.utcnow().isoformat() + "Z",
        "event":              "policy_conflict_warning",
        "session_id":         SESSION_ID,
        "workspace":          WORKSPACE_ROOT,
        "command":            command,
        "normalized_command": normalized,
        "matching_tiers":     tier_names,
        "resolved_to":        winning_tier,   # highest-priority tier always wins
        "decision_tier":      winning_tier,
    }
    if winning_matched_rule is not None:
        warning["matched_rule"] = winning_matched_rule
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(warning) + "\n")


def check_policy(command: str) -> PolicyResult:
    """
    Evaluate *command* against all policy tiers in priority order:

        blocked  >  requires_confirmation  >  requires_simulation  >  allowed

    The command is normalized (whitespace-collapsed and lowercased) for
    blocked/confirmation matching so pattern checks are consistent regardless
    of agent formatting. The simulation tier receives the original command so
    wildcard expansion can preserve real path casing.

    Each tier is checked independently so we can detect conflicts. If a
    command matches more than one tier, the highest-priority tier wins and
    a warning is silently logged to activity.log.

    Returns:
        PolicyResult with fields:
          allowed       — True if the command may proceed
          reason        — human-readable explanation of the decision
          decision_tier — which tier made the decision
          matched_rule  — the specific rule that fired, or None
    """
    # Normalize once here; all tier helpers receive the already-normalized
    # string so their internal .lower() calls become harmless no-ops.
    norm = normalize_command(command)

    # Each entry is a (tier_name, reason, matched_rule) 3-tuple.
    matching_tiers: list[tuple[str, str, str]] = []

    blocked_result = _check_blocked_tier(norm)
    if blocked_result:
        reason, matched_rule = blocked_result
        matching_tiers.append(("blocked", reason, matched_rule))

    confirmation_result = _check_confirmation_tier(norm)
    if confirmation_result:
        reason, matched_rule = confirmation_result
        matching_tiers.append(("requires_confirmation", reason, matched_rule))

    # Simulation uses the original command to preserve path case for globbing.
    simulation_result = _check_simulation_tier(command)
    if simulation_result:
        reason, matched_rule = simulation_result
        matching_tiers.append(("requires_simulation", reason, matched_rule))

    # Log a warning whenever a command lands in more than one tier.
    # Pass both forms so the conflict entry shows what was matched against.
    if len(matching_tiers) > 1:
        _log_policy_conflict(command, norm, matching_tiers)

    if not matching_tiers:
        return PolicyResult(
            allowed=True, reason="allowed",
            decision_tier="allowed", matched_rule=None,
        )

    # Return a PolicyResult for the highest-priority (first) matching tier.
    top_tier, reason, matched_rule = matching_tiers[0]
    return PolicyResult(
        allowed=False, reason=reason,
        decision_tier=top_tier, matched_rule=matched_rule,
    )


def is_within_workspace(path: str) -> bool:
    """
    Return True if *path* falls within WORKSPACE_ROOT or any root listed in
    allowed.paths_whitelist, False otherwise.

    Both the requested path and each root are resolved to absolute paths
    before comparison so symlinks and relative components (e.g. "../") cannot
    be used to escape the workspace boundary.

    WORKSPACE_ROOT is always an implicit allowed root; paths_whitelist entries
    extend it with additional roots. An empty paths_whitelist means only
    WORKSPACE_ROOT is checked.

    Args:
        path: The file or directory path to test (absolute or relative).

    Returns:
        True if the resolved path is a descendant of WORKSPACE_ROOT or of any
        root in allowed.paths_whitelist; False otherwise.
    """
    resolved = pathlib.Path(path).resolve()

    # WORKSPACE_ROOT is always an implicit allowed root.
    if resolved.is_relative_to(pathlib.Path(WORKSPACE_ROOT).resolve()):
        return True

    # Check each additional root declared in the policy whitelist.
    for root in POLICY.get("allowed", {}).get("paths_whitelist", []):
        if resolved.is_relative_to(pathlib.Path(root).resolve()):
            return True

    return False


def _deepest_allowed_root(path: str) -> pathlib.Path | None:
    """Return the deepest allowed root containing path, or None."""
    resolved = pathlib.Path(path).resolve()
    roots = [pathlib.Path(WORKSPACE_ROOT).resolve()]
    roots.extend(pathlib.Path(root).resolve() for root in POLICY.get("allowed", {}).get("paths_whitelist", []))
    containing = [root for root in roots if resolved.is_relative_to(root)]
    if not containing:
        return None
    return sorted(containing, key=lambda p: len(str(p)), reverse=True)[0]


def _relative_depth(path: str) -> int:
    """Return directory depth relative to the matched allowed root."""
    resolved = pathlib.Path(path).resolve()
    root = _deepest_allowed_root(path)
    if root is None:
        return len(resolved.parts)
    rel = resolved.relative_to(root)
    # root itself => depth 0, root/child => 1, etc.
    return len(rel.parts)


def _is_backup_path(path: str) -> bool:
    """Return True when path resolves under BACKUP_DIR."""
    try:
        resolved = pathlib.Path(path).resolve()
        return resolved.is_relative_to(pathlib.Path(BACKUP_DIR).resolve())
    except Exception:
        return False


def _check_path_policy(path: str, tool: str | None = None) -> tuple[str, str] | None:
    """
    Check a file path against the blocked path and extension rules in policy.json.

    Called by read_file, write_file, delete_file, and list_directory before
    any I/O is performed.

    Checks (in order):
      1. blocked.paths      — block if any entry appears as a substring of path
      2. blocked.extensions — block if the path ends with a blocked extension
      3. workspace boundary — always block paths outside WORKSPACE_ROOT; the
                              optional allowed.paths_whitelist entries extend the
                              boundary with additional roots but never remove it

    Returns (reason, matched_rule) if the path is blocked, or None if it
    passes every check. matched_rule is the specific blocked path substring,
    extension, or policy key that triggered the match.
    """
    blocked = POLICY.get("blocked", {})
    lower   = path.lower()

    # 1. Blocked path substrings
    for blocked_path in blocked.get("paths", []):
        if blocked_path.lower() in lower:
            return (
                f"Sensitive path access not permitted: '{blocked_path}' "
                "may contain secrets or critical system configuration",
                blocked_path,
            )

    # 2. Blocked file extensions
    for ext in blocked.get("extensions", []):
        if re.search(rf"{re.escape(ext)}\b", lower):
            return (
                f"Sensitive file extension not permitted: '{ext}' files "
                "may contain private keys or certificates",
                ext,
            )

    # 3. Workspace boundary — always enforced regardless of whether
    # allowed.paths_whitelist is populated. WORKSPACE_ROOT is the implicit
    # minimum boundary; paths_whitelist entries extend it with additional roots.
    # An empty whitelist does NOT disable the boundary check — WORKSPACE_ROOT
    # is always the floor.
    if not is_within_workspace(path):
        return (
            f"Path '{path}' is outside the allowed workspace",
            "workspace_boundary",
        )

    # 4. Backup storage protection for regular file tools.
    backup_access = POLICY.get("backup_access", {})
    if backup_access.get("block_agent_tools", True) and _is_backup_path(path):
        allowed_tools = {
            str(t).lower() for t in backup_access.get("allowed_tools", ["restore_backup"])
        }
        tool_name = (tool or "").lower()
        if tool_name not in allowed_tools:
            return (
                f"Path '{path}' is inside protected backup storage and is not accessible via {tool or 'this tool'}",
                "backup_storage_protected",
            )

    return None


# ---------------------------------------------------------------------------
# Log entry builder
# ---------------------------------------------------------------------------

def build_log_entry(tool: str, result: PolicyResult, **kwargs) -> dict:
    """
    Build the standard log-entry dictionary for a tool invocation.

    Every entry written to activity.log is produced by this function so the
    schema is consistent across all tools.

    Standard fields (always present):
        timestamp       — UTC ISO-8601 string of when the entry was built.
        source          — "ai-agent" (constant; identifies the log producer).
        session_id      — SESSION_ID UUID4, stable for the lifetime of this
                          server process; correlates records across tools.
        tool            — The MCP tool that triggered this log write.
        workspace       — WORKSPACE_ROOT for the current server instance.
        policy_decision — "allowed" or "blocked".
        decision_tier   — Which policy tier made the decision.

    Conditional fields (omitted when not applicable):
        matched_rule    — The specific rule that fired (omitted if None).
        block_reason    — Human-readable explanation (omitted when allowed).

    Additional fields:
        Any keyword arguments (command, path, normalized_command, retry_count,
        error, backup_location, final_block, event, …) are merged in after
        the standard fields via dict.update() in the order they are passed.

    Args:
        tool:     Name of the calling MCP tool.
        result:   PolicyResult returned by check_policy() or synthesised
                  inline by a file tool from _check_path_policy().
        **kwargs: Extra fields to include verbatim in the log entry.

    Returns:
        A plain dict ready to be serialised with json.dumps().
    """
    entry: dict = {
        "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
        "source":          "ai-agent",
        "session_id":      SESSION_ID,
        "tool":            tool,
        "workspace":       WORKSPACE_ROOT,
        "policy_decision": "allowed" if result.allowed else "blocked",
        "decision_tier":   result.decision_tier,
    }
    # Omit matched_rule entirely when no rule fired (cleaner logs for allowed ops).
    if result.matched_rule is not None:
        entry["matched_rule"] = result.matched_rule
    # Omit block_reason for allowed decisions to keep the happy-path log terse.
    if not result.allowed:
        entry["block_reason"] = _redact_for_audit(result.reason)
    # Caller-supplied fields (command, path, retry_count, error, …) are appended
    # last so standard fields are always the first keys in every log line.
    entry.update(_redact_for_audit(kwargs))
    return entry


# ---------------------------------------------------------------------------
# Backup layer
# ---------------------------------------------------------------------------

# Detects commands that modify or delete files and therefore need a backup.
# Matches: rm, mv, or a single > redirect (overwrite). The negative look-
# behind/ahead on > prevents matching >> (append), which is non-destructive.
MODIFYING_COMMAND_RE = re.compile(r"\b(rm|mv)\b|(?<![>])>(?!>)")

# Extracts candidate file/directory paths from a shell command string.
# Matches four token shapes (tried in order via alternation):
#   1. Absolute paths           — /foo/bar/baz.txt
#   2. Explicit relative paths  — ./foo or ../foo/bar
#   3. Multi-segment bare paths — foo/bar/baz  (contains at least one /)
#   4. Bare filenames with an extension — report.txt, config.json
# Flags, operators ($VAR, &&, >>, ;) are excluded by the character classes.
PATH_TOKEN_RE = re.compile(
    r"(?<!\S)"                          # must be preceded by whitespace or start
    r"("
    r"/[^\s;|&<>'\"\\]+"               # 1. absolute path
    r"|\.{1,2}/[^\s;|&<>'\"\\]+"       # 2. ./relative or ../relative
    r"|[A-Za-z0-9_][A-Za-z0-9_.\\-]*/[^\s;|&<>'\"\\]+"  # 3. bare multi-segment
    r"|[A-Za-z0-9_][A-Za-z0-9_.\\-]*\.[A-Za-z0-9]+"     # 4. bare name.ext
    r")"
)


def extract_paths(command: str) -> list:
    """
    Extract file and directory paths mentioned in a shell command.

    Uses PATH_TOKEN_RE to find candidate tokens, then filters the list down
    to only paths that actually exist on the filesystem so we don't try to
    back up non-existent targets.

    Args:
        command: The shell command string to scan.

    Returns:
        A list of existing path strings found in the command.
    """
    candidates = PATH_TOKEN_RE.findall(command)

    # Strip surrounding quotes that the shell would normally remove.
    candidates = [c.strip().strip("'\"") for c in candidates]

    resolved: list[str] = []
    for candidate in candidates:
        # Relative command paths are interpreted from WORKSPACE_ROOT, matching
        # execute_command's subprocess cwd.
        abs_path = candidate if os.path.isabs(candidate) else os.path.join(WORKSPACE_ROOT, candidate)
        path = str(pathlib.Path(abs_path).resolve())
        if os.path.exists(path):
            resolved.append(path)
    return resolved


def _allowed_roots() -> list[pathlib.Path]:
    """Return resolved allowed roots sorted longest-first for stable matching."""
    roots = [pathlib.Path(WORKSPACE_ROOT).resolve()]
    for root in POLICY.get("allowed", {}).get("paths_whitelist", []):
        roots.append(pathlib.Path(root).resolve())
    unique = list({str(r): r for r in roots}.values())
    return sorted(unique, key=lambda p: len(str(p)), reverse=True)


def _backup_relative_path(path: pathlib.Path) -> pathlib.Path | None:
    """
    Map an absolute path into a stable backup-relative path.

    The relative form preserves directory structure and avoids basename
    collisions (e.g. dir1/a.txt and dir2/a.txt).
    """
    for root in _allowed_roots():
        if path.is_relative_to(root):
            return path.relative_to(root)
    return None


def _cleanup_old_backups() -> None:
    """Remove backup folders older than audit.backup_retention_days."""
    retention_days = POLICY.get("audit", {}).get("backup_retention_days", 30)
    if retention_days <= 0:
        return
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=retention_days)
    backup_root = pathlib.Path(BACKUP_DIR)
    if not backup_root.exists():
        return
    for child in backup_root.iterdir():
        if not child.is_dir():
            continue
        try:
            mtime = datetime.datetime.utcfromtimestamp(child.stat().st_mtime)
        except OSError:
            continue
        if mtime < cutoff:
            shutil.rmtree(child, ignore_errors=True)


def _sha256_file(path: pathlib.Path) -> str:
    """Return sha256 hex digest for a file path."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _backup_entries_for_source(source_path: pathlib.Path) -> list[dict]:
    """
    Return backup entries for a specific source file, newest first.
    """
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


def _latest_backup_hash_for_source(source_path: pathlib.Path) -> str | None:
    """Return latest backed-up sha256 for a source file, if available."""
    entries = _backup_entries_for_source(source_path)
    if not entries:
        return None
    item = entries[0]["item"]
    if item.get("type") != "file":
        return None
    return item.get("sha256")


def _enforce_max_versions_per_file() -> None:
    """
    Enforce audit.max_versions_per_file by pruning old per-file backups.

    Prunes file entries from manifests. If a backup folder becomes empty after
    pruning, the folder is removed.
    """
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

    # Determine which specific file entries to prune.
    to_prune: list[dict] = []
    for _source, entries in by_source.items():
        ordered = sorted(entries, key=lambda e: e["order_key"], reverse=True)
        to_prune.extend(ordered[max_versions:])

    # Apply prune grouped by manifest.
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


def backup_paths(paths: list) -> str:
    """
    Copy a list of files/directories to a timestamped backup folder.

    Each call creates a unique subfolder under BACKUP_DIR named after the
    current UTC time (colons replaced with hyphens for filesystem safety),
    e.g. backups/2026-02-23T16-30-00/. Files are copied with metadata
    preserved; directories are copied recursively.

    Args:
        paths: List of existing file or directory path strings to back up.

    Returns:
        The path to the newly created backup folder.
    """
    _cleanup_old_backups()
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S.%f")
    suffix = uuid.uuid4().hex[:8]
    backup_location = os.path.join(BACKUP_DIR, f"{timestamp}_{suffix}")

    # Create folders with owner-only defaults where supported.
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    os.makedirs(backup_location, mode=0o700, exist_ok=False)
    manifest: list[dict] = []

    for path in paths:
        resolved = pathlib.Path(path).resolve()
        # Guard against backing up system paths that extract_paths() might
        # surface from agent-supplied commands (e.g. "rm /etc/hosts"). Only
        # paths inside the workspace boundary are ever copied.
        if not is_within_workspace(str(resolved)):
            continue

        rel = _backup_relative_path(resolved)
        if rel is None:
            continue
        dest = pathlib.Path(backup_location) / rel

        if resolved.is_file():
            if POLICY.get("audit", {}).get("backup_on_content_change_only", True):
                latest_hash = _latest_backup_hash_for_source(resolved)
                current_hash = _sha256_file(resolved)
                if latest_hash is not None and latest_hash == current_hash:
                    # Skip duplicate content snapshots for this file.
                    continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            # copy2 preserves file metadata (timestamps, permissions).
            shutil.copy2(str(resolved), str(dest))
            manifest.append(
                {
                    "source": str(resolved),
                    "backup": str(dest),
                    "type": "file",
                    "sha256": _sha256_file(dest),
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

    _enforce_max_versions_per_file()
    return backup_location


# ---------------------------------------------------------------------------
# MCP tool
# ---------------------------------------------------------------------------

@mcp.tool()
def server_info() -> str:
    return f"ai-runtime-guard build={SERVER_BUILD} workspace={WORKSPACE_ROOT} base_dir={BASE_DIR}"


@mcp.tool()
def restore_backup(backup_location: str, dry_run: bool = True, restore_token: str = "") -> str:
    """
    Restore files/directories from a backup manifest.

    Args:
        backup_location: Absolute path or backup folder name under BACKUP_DIR.
        dry_run: If True, return restore plan without writing files.
        restore_token: Required when dry_run=False if restore.require_dry_run_before_apply is enabled.
    """
    backup_path = (
        pathlib.Path(backup_location)
        if os.path.isabs(backup_location)
        else pathlib.Path(BACKUP_DIR) / backup_location
    ).resolve()
    backup_root = pathlib.Path(BACKUP_DIR).resolve()
    if not backup_path.is_relative_to(backup_root):
        result = PolicyResult(
            allowed=False,
            reason="Backup restore path must be inside BACKUP_DIR",
            decision_tier="blocked",
            matched_rule="backup_boundary",
        )
        log_entry = build_log_entry(
            "restore_backup",
            result,
            backup_location=str(backup_path),
            dry_run=dry_run,
        )
        with open(LOG_PATH, "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
        return "[POLICY BLOCK] Backup restore path must be inside BACKUP_DIR"

    manifest_path = backup_path / "manifest.json"
    if not manifest_path.exists():
        return f"Error: manifest.json not found in backup: {backup_path}"

    try:
        manifest = json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return f"Error reading backup manifest: {e}"

    if not isinstance(manifest, list):
        return "Error: backup manifest is invalid (expected array)"

    eligible_entries: list[dict] = []
    for item in manifest:
        if not isinstance(item, dict):
            continue
        source = item.get("source")
        backup = item.get("backup")
        item_type = item.get("type")
        expected_hash = item.get("sha256")
        if not source or not backup or not item_type:
            continue
        source_path = pathlib.Path(source).resolve()
        backup_item = pathlib.Path(backup).resolve()
        if not is_within_workspace(str(source_path)):
            continue
        if not backup_item.exists():
            continue

        eligible_entries.append(
            {
                "source_path": source_path,
                "backup_item": backup_item,
                "item_type": item_type,
                "expected_hash": expected_hash,
            }
        )

    planned = len(eligible_entries)

    require_confirm = bool(POLICY.get("restore", {}).get("require_dry_run_before_apply", True))
    if dry_run:
        response_extra = {}
        if require_confirm:
            token, expires_at = _issue_restore_confirmation_token(backup_path, planned)
            response_extra = {
                "restore_token_issued": token,
                "restore_token_expires_at": expires_at.isoformat() + "Z",
            }
        result = PolicyResult(
            allowed=True,
            reason="allowed",
            decision_tier="allowed",
            matched_rule=None,
        )
        log_entry = build_log_entry(
            "restore_backup",
            result,
            backup_location=str(backup_path),
            dry_run=True,
            planned=planned,
            restored=0,
            hash_failures=0,
            **response_extra,
        )
        with open(LOG_PATH, "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")

        msg = f"Restore dry run complete: {planned} item(s) eligible from {backup_path}"
        if require_confirm:
            msg += (
                f"\nrestore_token={response_extra['restore_token_issued']}"
                f"\nrestore_token_expires_at={response_extra['restore_token_expires_at']}"
            )
        return msg

    if require_confirm:
        _prune_expired_restore_confirmations()
        rec = PENDING_RESTORE_CONFIRMATIONS.get(restore_token)
        if not rec:
            result = PolicyResult(
                allowed=False,
                reason="Invalid or expired restore token",
                decision_tier="blocked",
                matched_rule="restore_token",
            )
            log_entry = build_log_entry(
                "restore_backup",
                result,
                backup_location=str(backup_path),
                dry_run=False,
                restore_token=restore_token,
            )
            with open(LOG_PATH, "a") as log_file:
                log_file.write(json.dumps(log_entry) + "\n")
            return "[POLICY BLOCK] Invalid or expired restore token"

        if rec["backup_path"] != str(backup_path.resolve()):
            result = PolicyResult(
                allowed=False,
                reason="Restore token does not match the requested backup location",
                decision_tier="blocked",
                matched_rule="restore_token_mismatch",
            )
            log_entry = build_log_entry(
                "restore_backup",
                result,
                backup_location=str(backup_path),
                dry_run=False,
                restore_token=restore_token,
            )
            with open(LOG_PATH, "a") as log_file:
                log_file.write(json.dumps(log_entry) + "\n")
            return "[POLICY BLOCK] Restore token does not match the requested backup location"

        PENDING_RESTORE_CONFIRMATIONS.pop(restore_token, None)

    restored = 0
    hash_failures = 0
    for entry in eligible_entries:
        source_path = entry["source_path"]
        backup_item = entry["backup_item"]
        item_type = entry["item_type"]
        expected_hash = entry["expected_hash"]
        try:
            if item_type == "file":
                if expected_hash:
                    actual_hash = _sha256_file(backup_item)
                    if actual_hash != expected_hash:
                        hash_failures += 1
                        continue
                source_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(backup_item), str(source_path))
                restored += 1
            elif item_type == "directory":
                source_path.mkdir(parents=True, exist_ok=True)
                shutil.copytree(str(backup_item), str(source_path), dirs_exist_ok=True)
                restored += 1
        except OSError:
            continue

    result = PolicyResult(
        allowed=True,
        reason="allowed",
        decision_tier="allowed",
        matched_rule=None,
    )
    log_entry = build_log_entry(
        "restore_backup",
        result,
        backup_location=str(backup_path),
        dry_run=dry_run,
        planned=planned,
        restored=restored,
        hash_failures=hash_failures,
    )
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    if dry_run:
        return f"Restore dry run complete: {planned} item(s) eligible from {backup_path}"
    return (
        f"Restore complete from {backup_path}: restored={restored}, "
        f"planned={planned}, hash_failures={hash_failures}"
    )


@mcp.tool()
def execute_command(command: str, retry_count: int = 0) -> str:
    """
    Execute a shell command and return its output.

    The command is checked against the policy engine before execution.
    Blocked commands are logged and rejected without running. The agent
    may retry with a safer alternative up to MAX_RETRIES times total.

    Args:
        command:     The shell command to run (e.g. "ls -la" or "echo hello").
        retry_count: How many times this command has already been retried
                     after a policy block (default 0, max MAX_RETRIES).

    Returns:
        stdout from the command, stderr/exit-code on failure, or a structured
        policy block message (with retry guidance) if the command was blocked.
    """

    network_warning = None
    budget_fields: dict = {}

    # --- 1. Hard-fail commands with unsafe control characters ---
    if _has_shell_unsafe_control_chars(command):
        result = PolicyResult(
            allowed=False,
            reason="Command contains disallowed control characters (newline, carriage return, or NUL)",
            decision_tier="blocked",
            matched_rule="command_control_characters",
        )
    elif _command_targets_backup_storage(command):
        result = PolicyResult(
            allowed=False,
            reason="Command targets protected backup storage; use restore_backup for controlled recovery operations",
            decision_tier="blocked",
            matched_rule="backup_storage_protected",
        )
    else:
        # --- 2. Network policy gate ---
        net_allowed, net_reason = _network_policy_check(command)
        mode = str(POLICY.get("network", {}).get("enforcement_mode", "off")).lower()
        if not net_allowed:
            result = PolicyResult(
                allowed=False,
                reason=net_reason or "Network command blocked by policy",
                decision_tier="blocked",
                matched_rule="network_policy",
            )
        else:
            if mode == "monitor" and net_reason:
                network_warning = net_reason
            # --- 3. Run policy tier evaluation ---
            result = check_policy(command)

    # --- 4. Cumulative budget gate (only after command-level policy allows) ---
    affected_for_budget: list[str] = []
    if result.allowed:
        sim_commands = {c.lower() for c in POLICY.get("requires_simulation", {}).get("commands", [])}
        simulation = _simulate_blast_radius(command, list(sim_commands))
        if simulation["affected"]:
            affected_for_budget = simulation["affected"]
        else:
            affected_for_budget = extract_paths(command)

        budget_allowed, budget_reason, budget_rule, budget_fields = _check_and_record_cumulative_budget(
            tool="execute_command",
            command=command,
            affected_paths=affected_for_budget,
            operation_count=1,
        )
        if not budget_allowed:
            result = PolicyResult(
                allowed=False,
                reason=budget_reason or "Cumulative blast-radius budget exceeded for current scope.",
                decision_tier="blocked",
                matched_rule=budget_rule or "requires_simulation.cumulative_budget_exceeded",
            )

    # --- 5. Server-side retry tracking ---
    server_retry_count = 0
    final_block = False
    if not result.allowed and result.decision_tier != "requires_confirmation":
        server_retry_count = _register_retry(command, result.decision_tier, result.matched_rule)
        final_block = server_retry_count >= MAX_RETRIES

    # --- 6. Build + write log entry ---
    log_entry = build_log_entry(
        "execute_command",
        result,
        command=command,
        normalized_command=normalize_for_audit(command),
        retry_count=retry_count,
        server_retry_count=server_retry_count,
        affected_paths_count=len(affected_for_budget),
        **({"network_warning": network_warning} if network_warning else {}),
        **budget_fields,
        **({"final_block": True} if final_block else {}),
    )
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # --- 7. Blocked response path ---
    if not result.allowed:
        if result.decision_tier == "requires_confirmation":
            token, expires_at = _issue_or_reuse_approval_token(command)
            return (
                f"[POLICY BLOCK] {result.reason}\n\n"
                "This command requires an explicit confirmation handshake.\n"
                f"Call approve_command with this exact command and token:\n"
                f"approval_token={token}\n"
                f"token_expires_at={expires_at.isoformat()}Z"
            )

        if final_block:
            return (
                f"[POLICY BLOCK] {result.reason}\n\n"
                f"Maximum retries reached ({MAX_RETRIES}/{MAX_RETRIES}). "
                "This action is permanently blocked for the current request. "
                "No further attempts will be accepted."
            )

        attempts_remaining = MAX_RETRIES - server_retry_count
        return (
            f"[POLICY BLOCK] {result.reason}\n\n"
            f"You have {attempts_remaining} attempt(s) remaining. "
            "Please retry execute_command with a safer alternative command "
            f"(server attempt {server_retry_count}/{MAX_RETRIES})."
        )

    # --- 8. Backup potentially destructive targets ---
    if MODIFYING_COMMAND_RE.search(command):
        affected = extract_paths(command)
        if affected and POLICY.get("audit", {}).get("backup_enabled", True):
            backup_location = backup_paths(affected)
            if backup_location:
                with open(LOG_PATH, "a") as log_file:
                    log_file.write(
                        json.dumps(
                            {
                                **log_entry,
                                "backup_location": backup_location,
                                "event": "backup_created",
                            }
                        )
                        + "\n"
                    )

    # --- 9. Execute the command with hardened shell settings ---
    timeout_seconds, max_output_chars = _execution_limits()
    try:
        proc = subprocess.run(
            command,
            shell=True,  # Allows pipes/redirects for MCP command compatibility.
            executable="/bin/bash",
            cwd=WORKSPACE_ROOT,
            env=_safe_subprocess_env(),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout_seconds} seconds"

    stdout = _truncate_output(proc.stdout or "", max_output_chars)
    stderr = _truncate_output(proc.stderr or "", max_output_chars)

    # --- 10. Return output or error ---
    if proc.returncode != 0:
        return stderr or f"Command exited with code {proc.returncode}"
    return stdout


@mcp.tool()
def approve_command(command: str, approval_token: str) -> str:
    """
    Approve a previously blocked command for this server session.

    The command and token must match an active handshake issued by
    execute_command when requires_confirmation rules fired.
    """
    _prune_expired_approvals()
    if _approval_failures_exceeded(approval_token):
        result = PolicyResult(
            allowed=False,
            reason="Approval token temporarily locked due to repeated failed attempts",
            decision_tier="blocked",
            matched_rule="approval_rate_limit",
        )
        log_entry = build_log_entry(
            "approve_command",
            result,
            command=command,
            approval_token=approval_token,
        )
        with open(LOG_PATH, "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
        return "[POLICY BLOCK] Approval token temporarily locked due to repeated failed attempts"

    rec = PENDING_APPROVALS.get(approval_token)
    expected_hash = command_hash(command)

    if not rec:
        _record_approval_failure(approval_token)
        result = PolicyResult(
            allowed=False,
            reason="Invalid or expired approval token",
            decision_tier="blocked",
            matched_rule="approval_token",
        )
        log_entry = build_log_entry(
            "approve_command", result,
            command=command, approval_token=approval_token,
        )
        with open(LOG_PATH, "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
        return "[POLICY BLOCK] Invalid or expired approval token"

    if rec["command_hash"] != expected_hash:
        _record_approval_failure(approval_token)
        result = PolicyResult(
            allowed=False,
            reason="Approval token does not match the provided command",
            decision_tier="blocked",
            matched_rule="approval_mismatch",
        )
        log_entry = build_log_entry(
            "approve_command", result,
            command=command, approval_token=approval_token,
        )
        with open(LOG_PATH, "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
        return "[POLICY BLOCK] Approval token does not match the provided command"

    SESSION_WHITELIST.add(expected_hash)
    PENDING_APPROVALS.pop(approval_token, None)
    APPROVAL_FAILURES.pop(approval_token, None)

    result = PolicyResult(
        allowed=True,
        reason="approved",
        decision_tier="allowed",
        matched_rule=None,
    )
    log_entry = build_log_entry(
        "approve_command", result,
        command=command, approval_token=approval_token, event="command_approved",
    )
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")
    return "Command approved for this session. Re-run execute_command with the same command."


@mcp.tool()
def read_file(path: str) -> str:
    """
    Read a file from the filesystem and return its contents as a string.

    The path is checked against policy before any data is read:
      - blocked.paths and blocked.extensions are rejected outright
      - Files larger than allowed.max_file_size_mb are rejected

    Args:
        path: Absolute or relative path to the file to read.

    Returns:
        The file contents as a string, or a [POLICY BLOCK] / error message.
    """

    # --- 0. Resolve relative paths against WORKSPACE_ROOT ---
    # Mirrors execute_command behaviour: relative paths are interpreted as
    # relative to WORKSPACE_ROOT, not the process cwd, so callers get
    # consistent results regardless of where the server was launched from.
    path = str(pathlib.Path(WORKSPACE_ROOT) / path) if not os.path.isabs(path) else path

    # --- 1. Check path against policy ---
    path_check = _check_path_policy(path, tool="read_file")
    if path_check:
        result = PolicyResult(allowed=False, reason=path_check[0],
                              decision_tier="blocked", matched_rule=path_check[1])
    else:
        result = PolicyResult(allowed=True, reason="allowed",
                              decision_tier="allowed", matched_rule=None)

    # --- 2. File-size check (only when policy allows) ---
    if result.allowed:
        max_mb = POLICY.get("allowed", {}).get("max_file_size_mb", 10)
        try:
            size_mb = os.path.getsize(path) / (1024 * 1024)
            if size_mb > max_mb:
                result = PolicyResult(
                    allowed=False,
                    reason=(
                        f"File size {size_mb:.1f} MB exceeds the policy limit "
                        f"of {max_mb} MB (allowed.max_file_size_mb)"
                    ),
                    decision_tier="blocked",
                    matched_rule="allowed.max_file_size_mb",
                )
        except (FileNotFoundError, OSError):
            pass  # Surface the error during the read in step 6.

    # --- 3. Build the log entry ---
    log_entry = build_log_entry("read_file", result, path=path)

    # --- 4. Write the log entry (always, before any I/O) ---
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # --- 5. Reject blocked requests without touching the file ---
    if not result.allowed:
        return f"[POLICY BLOCK] {result.reason}"

    # --- 6. Read and return the file contents ---
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return f"Error: file not found: {path}"
    except OSError as e:
        return f"Error reading file: {e}"


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """
    Write content to a file, creating it if it does not exist.

    The path is checked against policy before any data is written. If the
    file already exists a timestamped backup is created first using the
    same backup_paths() function as execute_command.

    Args:
        path:    Absolute or relative path to the file to write.
        content: The string content to write.

    Returns:
        A success message with the byte count, a backup note if applicable,
        or a [POLICY BLOCK] / error message.
    """

    # --- 0. Resolve relative paths against WORKSPACE_ROOT ---
    # Mirrors execute_command behaviour: relative paths are interpreted as
    # relative to WORKSPACE_ROOT, not the process cwd, so callers get
    # consistent results regardless of where the server was launched from.
    path = str(pathlib.Path(WORKSPACE_ROOT) / path) if not os.path.isabs(path) else path

    # --- 1. Check path against policy ---
    path_check = _check_path_policy(path, tool="write_file")
    if path_check:
        result = PolicyResult(allowed=False, reason=path_check[0],
                              decision_tier="blocked", matched_rule=path_check[1])
    else:
        result = PolicyResult(allowed=True, reason="allowed",
                              decision_tier="allowed", matched_rule=None)

    budget_fields: dict = {}
    if result.allowed:
        budget_allowed, budget_reason, budget_rule, budget_fields = _check_and_record_cumulative_budget(
            tool="write_file",
            command=None,
            affected_paths=[path],
            operation_count=1,
            bytes_estimate=len(content.encode()),
        )
        if not budget_allowed:
            result = PolicyResult(
                allowed=False,
                reason=budget_reason or "Cumulative blast-radius budget exceeded for current scope.",
                decision_tier="blocked",
                matched_rule=budget_rule or "requires_simulation.cumulative_budget_exceeded",
            )

    # --- 2. Build the log entry ---
    log_entry = build_log_entry("write_file", result, path=path, **budget_fields)

    # --- 3. Write the log entry (always, before any I/O) ---
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # --- 4. Reject blocked requests without touching the file ---
    if not result.allowed:
        return f"[POLICY BLOCK] {result.reason}"

    # --- 5. Back up the existing file before overwriting it ---
    backup_location = None
    if os.path.exists(path):
        backup_location = backup_paths([path])
        if backup_location:
            # Record the backup location in a second log line so the audit trail
            # shows where the pre-write snapshot is stored.
            with open(LOG_PATH, "a") as log_file:
                log_file.write(
                    json.dumps({**log_entry, "backup_location": backup_location,
                                "event": "backup_created"}) + "\n"
                )

    # --- 6. Write the file ---
    try:
        with open(path, "w") as f:
            f.write(content)
    except OSError as e:
        return f"Error writing file: {e}"

    # --- 7. Return a success message ---
    msg = f"Successfully wrote {len(content)} characters to {path}"
    if backup_location:
        msg += f" (previous version backed up to {backup_location})"
    else:
        msg += " (no content-change backup needed)"
    return msg


@mcp.tool()
def delete_file(path: str) -> str:
    """
    Delete a single file after creating a backup, subject to policy checks.

    Sequence:
      1. Path is checked against policy (blocked paths, extensions).
      2. If the path does not exist, a clear error is returned — this is not
         a policy block, the operation simply cannot proceed.
      3. If the path is a directory, the request is blocked — use
         execute_command for directory operations.
      4. A timestamped backup is created with backup_paths() before any
         destructive action is taken.
      5. The file is deleted with os.remove().

    Every call is logged to activity.log regardless of outcome. Successful
    deletions include backup_location in the log so the file is always
    recoverable.

    Args:
        path: Absolute or relative path to the file to delete.

    Returns:
        A success message with the backup location, or a [POLICY BLOCK] /
        error message.
    """

    # --- 0. Resolve relative paths against WORKSPACE_ROOT ---
    # Mirrors execute_command behaviour: relative paths are interpreted as
    # relative to WORKSPACE_ROOT, not the process cwd, so callers get
    # consistent results regardless of where the server was launched from.
    path = str(pathlib.Path(WORKSPACE_ROOT) / path) if not os.path.isabs(path) else path

    # --- 1. Check path against policy (blocked paths, extensions) ---
    path_check = _check_path_policy(path, tool="delete_file")
    if path_check:
        result = PolicyResult(allowed=False, reason=path_check[0],
                              decision_tier="blocked", matched_rule=path_check[1])
    else:
        result = PolicyResult(allowed=True, reason="allowed",
                              decision_tier="allowed", matched_rule=None)

    # --- 2. Pre-flight checks on the target (only when policy allows) ---
    if result.allowed:
        if not os.path.exists(path):
            # Not a policy block — the file simply isn't there.
            # Log the attempt and return a clear error without blocking.
            log_entry = build_log_entry("delete_file", result,
                                        path=path, error="file not found")
            with open(LOG_PATH, "a") as log_file:
                log_file.write(json.dumps(log_entry) + "\n")
            return f"Error: file not found: {path}"

        if os.path.isdir(path):
            # Directories need recursive operations that carry higher risk.
            # Direct the agent to execute_command for those cases.
            # This is a type-safety block, not a policy-rule match.
            result = PolicyResult(
                allowed=False,
                reason=(
                    f"'{path}' is a directory — delete_file only removes individual "
                    "files. Use execute_command for directory operations "
                    "(note: bulk/recursive deletions are also subject to policy)."
                ),
                decision_tier="blocked",
                matched_rule=None,
            )

    budget_fields: dict = {}
    if result.allowed:
        bytes_est = 0
        try:
            if os.path.isfile(path):
                bytes_est = int(os.path.getsize(path))
        except OSError:
            bytes_est = 0
        budget_allowed, budget_reason, budget_rule, budget_fields = _check_and_record_cumulative_budget(
            tool="delete_file",
            command=None,
            affected_paths=[path],
            operation_count=1,
            bytes_estimate=bytes_est,
        )
        if not budget_allowed:
            result = PolicyResult(
                allowed=False,
                reason=budget_reason or "Cumulative blast-radius budget exceeded for current scope.",
                decision_tier="blocked",
                matched_rule=budget_rule or "requires_simulation.cumulative_budget_exceeded",
            )

    # --- 3. Build the log entry with the final policy decision ---
    log_entry = build_log_entry("delete_file", result, path=path, **budget_fields)

    # --- 4. If blocked, write log and return without touching the filesystem ---
    if not result.allowed:
        with open(LOG_PATH, "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
        return f"[POLICY BLOCK] {result.reason}"

    # --- 5. Create a backup before any destructive action ---
    # backup_paths() is called unconditionally here — existence was confirmed
    # in step 2, so the file is guaranteed to be present at this point.
    backup_location = backup_paths([path])
    if backup_location:
        log_entry["backup_location"] = backup_location

    # --- 6. Write the log entry (includes backup_location) ---
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # --- 7. Delete the file ---
    try:
        os.remove(path)
    except OSError as e:
        return f"Error deleting file: {e}"

    # --- 8. Return success with the backup location so the file is recoverable ---
    return (
        f"Successfully deleted {path}. "
        + (
            f"Backup saved to {backup_location} — the file can be recovered from there."
            if backup_location
            else "No content-change backup was needed."
        )
    )


@mcp.tool()
def list_directory(path: str) -> str:
    """
    List the contents of a directory and return a formatted summary.

    Checks (in order before any I/O):
      1. Path is validated against policy (blocked paths, extensions).
      2. The path must exist and be a directory — a clear error is returned
         for missing paths or plain files.
      3. Directory depth (relative to the allowed workspace root) is
         checked against allowed.max_directory_depth in policy.json.

    Each entry in the listing includes:
      - name
      - type  (file | directory)
      - size  (bytes, files only)
      - last modified timestamp (UTC ISO-8601)

    Args:
        path: Absolute or relative path to the directory to list.

    Returns:
        A formatted multi-line string with one entry per line, or a
        [POLICY BLOCK] / error message.
    """

    # --- 0. Resolve relative paths against WORKSPACE_ROOT ---
    # Mirrors execute_command behaviour: relative paths are interpreted as
    # relative to WORKSPACE_ROOT, not the process cwd, so callers get
    # consistent results regardless of where the server was launched from.
    path = str(pathlib.Path(WORKSPACE_ROOT) / path) if not os.path.isabs(path) else path

    # --- 1. Check path against policy (blocked paths, extensions) ---
    path_check = _check_path_policy(path, tool="list_directory")
    if path_check:
        result = PolicyResult(allowed=False, reason=path_check[0],
                              decision_tier="blocked", matched_rule=path_check[1])
    else:
        result = PolicyResult(allowed=True, reason="allowed",
                              decision_tier="allowed", matched_rule=None)

    # --- 2. Existence and type checks (only when policy allows) ---
    if result.allowed:
        if not os.path.exists(path):
            # Not a policy block — the path simply doesn't exist.
            log_entry = build_log_entry("list_directory", result,
                                        path=path, error="path not found")
            with open(LOG_PATH, "a") as log_file:
                log_file.write(json.dumps(log_entry) + "\n")
            return f"Error: path not found: {path}"

        if not os.path.isdir(path):
            # The path exists but is a file — log and return a clear error.
            log_entry = build_log_entry("list_directory", result,
                                        path=path, error="not a directory")
            with open(LOG_PATH, "a") as log_file:
                log_file.write(json.dumps(log_entry) + "\n")
            return f"Error: '{path}' is a file, not a directory"

        # --- 3. Depth check ---
        # Measure relative to the deepest allowed root, not filesystem root.
        depth     = _relative_depth(path)
        max_depth = POLICY.get("allowed", {}).get("max_directory_depth", 5)
        if depth > max_depth:
            result = PolicyResult(
                allowed=False,
                reason=(
                    f"Directory depth {depth} exceeds the policy limit of "
                    f"{max_depth} (allowed.max_directory_depth): '{path}'"
                ),
                decision_tier="blocked",
                matched_rule="allowed.max_directory_depth",
            )

    # --- 4. Build the log entry with the final policy decision ---
    log_entry = build_log_entry("list_directory", result, path=path)

    # --- 5. Write the log entry (always, before any I/O) ---
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # --- 6. Return block message without touching the filesystem ---
    if not result.allowed:
        return f"[POLICY BLOCK] {result.reason}"

    # --- 7. Scan the directory and build the listing ---
    lines = [f"Contents of {path}:"]
    try:
        entries = sorted(os.scandir(path), key=lambda e: (e.is_file(), e.name))
    except OSError as e:
        return f"Error reading directory: {e}"

    for entry in entries:
        try:
            stat   = entry.stat(follow_symlinks=False)
            mtime  = datetime.datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z"
            kind   = "file" if entry.is_file(follow_symlinks=False) else "directory"
            # Size is only meaningful for files; directories show a dash.
            size   = f"{stat.st_size} bytes" if kind == "file" else "-"
            lines.append(f"  {entry.name}  [{kind}]  size={size}  modified={mtime}")
        except OSError:
            # If a single entry can't be stat-ed (e.g. broken symlink), skip it
            # gracefully rather than aborting the whole listing.
            lines.append(f"  {entry.name}  [unreadable]")

    if len(lines) == 1:
        lines.append("  (empty)")

    return "\n".join(lines)


if __name__ == "__main__":
    # Run over stdio — the standard transport for MCP servers.
    mcp.run()
