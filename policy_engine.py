import datetime
import glob
import hashlib
import os
import pathlib
import re
import shlex
from urllib.parse import urlparse

from approvals import consume_approved_command
from audit import append_log_entry, build_log_entry
from config import (
    BASE_DIR,
    BACKUP_DIR,
    LOG_PATH,
    MAX_RETRIES,
    POLICY,
    SESSION_ID,
    WORKSPACE_ROOT,
)
from models import PolicyResult

SERVER_RETRY_COUNTS: dict[str, int] = {}

def normalize_command(command: str) -> str:
    return re.sub(r"\s+", " ", command.strip()).lower()


def normalize_for_audit(command: str) -> str:
    return re.sub(r"\s+", " ", command.strip())


def command_hash(command: str) -> str:
    return hashlib.sha256(normalize_command(command).encode()).hexdigest()


def split_shell_segments(command: str) -> list[str]:
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


def tokenize_shell_segment(segment: str) -> tuple[list[str], bool]:
    try:
        return shlex.split(segment), False
    except ValueError:
        return [], True


def tokenize_command(command: str) -> tuple[list[str], bool]:
    parse_error = False
    all_tokens: list[str] = []
    for segment in split_shell_segments(command):
        tokens, err = tokenize_shell_segment(segment)
        parse_error = parse_error or err
        all_tokens.extend(t.lower() for t in tokens)
    return all_tokens, parse_error


def execution_limits() -> tuple[int, int]:
    execution = POLICY.get("execution", {})
    timeout = int(execution.get("max_command_timeout_seconds", 30))
    max_chars = int(execution.get("max_output_chars", 200000))
    return timeout, max_chars


def truncate_output(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return text[:max_chars] + f"\n...[truncated {omitted} chars]"


def network_policy_check(command: str) -> tuple[bool, str | None]:
    network = POLICY.get("network", {})
    mode = str(network.get("enforcement_mode", "off")).lower()
    if mode == "off":
        return True, None

    tokens, parse_error = tokenize_command(command)
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


def command_targets_backup_storage(command: str) -> bool:
    if not POLICY.get("backup_access", {}).get("block_agent_tools", True):
        return False

    backup_root = pathlib.Path(BACKUP_DIR).resolve()
    lower = command.lower()
    if str(backup_root).lower() in lower:
        return True

    for segment in split_shell_segments(command):
        tokens, err = tokenize_shell_segment(segment)
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
    tmp_backup_root = str(pathlib.Path(BACKUP_DIR))
    if tmp_backup_root.lower() in lower:
        return True
    return False


def retry_key(command: str, tier: str, matched_rule: str | None) -> str:
    base = f"{normalize_command(command)}|{tier}|{matched_rule or ''}"
    return hashlib.sha256(base.encode()).hexdigest()


def register_retry(command: str, tier: str, matched_rule: str | None) -> int:
    key = retry_key(command, tier, matched_rule)
    stored_count = SERVER_RETRY_COUNTS.get(key, 0)
    if stored_count >= MAX_RETRIES:
        SERVER_RETRY_COUNTS[key] = MAX_RETRIES
        return MAX_RETRIES
    stored_count += 1
    SERVER_RETRY_COUNTS[key] = stored_count
    return stored_count


def has_shell_unsafe_control_chars(command: str) -> bool:
    return any(ch in command for ch in ("\x00", "\n", "\r"))


def build_command_matcher(pattern: str):
    words = pattern.strip().split()
    lower_pattern = pattern.lower()
    if len(words) == 1:
        regex = re.compile(rf"\b{re.escape(lower_pattern)}\b")

        def _matches(cmd: str) -> bool:
            if regex.search(cmd.lower()):
                return True
            tokens, _ = tokenize_command(cmd)
            return lower_pattern in tokens

        return _matches

    def _matches(cmd: str) -> bool:
        if lower_pattern in cmd.lower():
            return True
        tokens, _ = tokenize_command(cmd)
        rebuilt = " ".join(tokens)
        return lower_pattern in rebuilt

    return _matches


def check_blocked_tier(command: str) -> tuple[str, str] | None:
    blocked = POLICY.get("blocked", {})
    lower = command.lower()

    for pattern in blocked.get("commands", []):
        if build_command_matcher(pattern)(command):
            return (
                f"Blocked destructive command '{pattern}': this operation is prohibited by policy",
                pattern,
            )

    for path in blocked.get("paths", []):
        if path.lower() in lower:
            return (
                f"Sensitive path access not permitted: '{path}' may contain secrets or critical system configuration",
                path,
            )

    for ext in blocked.get("extensions", []):
        if re.search(rf"{re.escape(ext)}\b", lower):
            return (
                f"Sensitive file extension not permitted: '{ext}' files may contain private keys or certificates",
                ext,
            )

    return None


def check_confirmation_tier(command: str) -> tuple[str, str] | None:
    conf = POLICY.get("requires_confirmation", {})
    lower = command.lower()

    for pattern in conf.get("commands", []):
        if build_command_matcher(pattern)(command):
            whitelist_enabled = conf.get("session_whitelist_enabled", True)
            if whitelist_enabled and consume_approved_command(SESSION_ID, command):
                return None
            return (f"Command '{pattern}' requires explicit confirmation before execution", pattern)

    for path in conf.get("paths", []):
        if path.lower() in lower:
            whitelist_enabled = conf.get("session_whitelist_enabled", True)
            if whitelist_enabled and consume_approved_command(SESSION_ID, command):
                return None
            return (f"Access to path '{path}' requires explicit confirmation", path)

    return None


def simulate_blast_radius(command: str, sim_commands: list[str]) -> dict:
    affected: set[str] = set()
    lower_ops = {op.lower() for op in sim_commands}
    saw_wildcard = False
    parse_error = False

    segments = split_shell_segments(command)
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        tokens, err = tokenize_shell_segment(segment)
        if err:
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

    return {"affected": sorted(affected), "saw_wildcard": saw_wildcard, "parse_error": parse_error}


def check_simulation_tier(command: str, simulation: dict | None = None) -> tuple[str, str] | None:
    sim = POLICY.get("requires_simulation", {})
    sim_commands = sim.get("commands", [])
    threshold = sim.get("bulk_file_threshold", 10)

    if not sim_commands:
        return None

    if simulation is None:
        simulation = simulate_blast_radius(command, sim_commands)
    affected = simulation["affected"]
    saw_wildcard = simulation["saw_wildcard"]
    parse_error = simulation["parse_error"]

    if saw_wildcard and (parse_error or not affected):
        return (
            "Bulk file operation blocked: wildcard pattern could not be safely simulated to concrete targets. Please specify exact filenames instead.",
            "requires_simulation.wildcard_unresolved",
        )

    if len(affected) > threshold:
        sample = ", ".join(affected[:3])
        if len(affected) > 3:
            sample += ", ..."
        return (
            f"Bulk file operation blocked: simulated blast radius is {len(affected)} path(s), which exceeds the policy threshold of {threshold}. Sample targets: {sample}",
            "requires_simulation.bulk_file_threshold",
        )

    return None


def log_policy_conflict(command: str, normalized: str, matching_tiers: list) -> None:
    tier_names = [tier for tier, _, _ in matching_tiers]
    winning_tier, _winning_reason, winning_matched_rule = matching_tiers[0]
    warning_result = PolicyResult(
        allowed=False,
        reason="Command matched multiple policy tiers; resolved by policy precedence.",
        decision_tier=winning_tier,
        matched_rule=winning_matched_rule,
    )
    warning = build_log_entry(
        "policy_engine",
        warning_result,
        source="mcp-server",
        event="policy_conflict_warning",
        command=command,
        normalized_command=normalized,
        matching_tiers=tier_names,
        resolved_to=winning_tier,
        session_id=SESSION_ID,
        workspace=WORKSPACE_ROOT,
    )
    append_log_entry(warning)


def check_policy(command: str, simulation: dict | None = None) -> PolicyResult:
    norm = normalize_command(command)
    matching_tiers: list[tuple[str, str, str]] = []

    blocked_result = check_blocked_tier(norm)
    if blocked_result:
        reason, matched_rule = blocked_result
        matching_tiers.append(("blocked", reason, matched_rule))

    confirmation_result = check_confirmation_tier(norm)
    if confirmation_result:
        reason, matched_rule = confirmation_result
        matching_tiers.append(("requires_confirmation", reason, matched_rule))

    simulation_result = check_simulation_tier(command, simulation=simulation)
    if simulation_result:
        reason, matched_rule = simulation_result
        matching_tiers.append(("requires_simulation", reason, matched_rule))

    if len(matching_tiers) > 1:
        log_policy_conflict(command, norm, matching_tiers)

    if not matching_tiers:
        return PolicyResult(allowed=True, reason="allowed", decision_tier="allowed", matched_rule=None)

    top_tier, reason, matched_rule = matching_tiers[0]
    return PolicyResult(allowed=False, reason=reason, decision_tier=top_tier, matched_rule=matched_rule)


def is_within_workspace(path: str) -> bool:
    resolved = pathlib.Path(path).resolve()

    if resolved.is_relative_to(pathlib.Path(WORKSPACE_ROOT).resolve()):
        return True

    for root in POLICY.get("allowed", {}).get("paths_whitelist", []):
        if resolved.is_relative_to(pathlib.Path(root).resolve()):
            return True

    return False


def deepest_allowed_root(path: str) -> pathlib.Path | None:
    resolved = pathlib.Path(path).resolve()
    roots = [pathlib.Path(WORKSPACE_ROOT).resolve()]
    roots.extend(pathlib.Path(root).resolve() for root in POLICY.get("allowed", {}).get("paths_whitelist", []))
    containing = [root for root in roots if resolved.is_relative_to(root)]
    if not containing:
        return None
    return sorted(containing, key=lambda p: len(str(p)), reverse=True)[0]


def relative_depth(path: str) -> int:
    resolved = pathlib.Path(path).resolve()
    root = deepest_allowed_root(path)
    if root is None:
        return len(resolved.parts)
    rel = resolved.relative_to(root)
    return len(rel.parts)


def is_backup_path(path: str) -> bool:
    try:
        resolved = pathlib.Path(path).resolve()
        return resolved.is_relative_to(pathlib.Path(BACKUP_DIR).resolve())
    except Exception:
        return False


def is_protected_runtime_path(path: str) -> bool:
    try:
        resolved = pathlib.Path(path).resolve()
    except Exception:
        return False

    approval_db = pathlib.Path(
        os.environ.get("AIRG_APPROVAL_DB_PATH", str(BASE_DIR / "approvals.db"))
    ).resolve()
    approval_key = pathlib.Path(
        os.environ.get("AIRG_APPROVAL_HMAC_KEY_PATH", f"{approval_db}.hmac.key")
    ).resolve()
    protected = {
        pathlib.Path(LOG_PATH).resolve(),
        approval_db,
        approval_key,
    }
    return resolved in protected


def check_path_policy(path: str, tool: str | None = None) -> tuple[str, str] | None:
    blocked = POLICY.get("blocked", {})
    lower = path.lower()

    for blocked_path in blocked.get("paths", []):
        if blocked_path.lower() in lower:
            return (
                f"Sensitive path access not permitted: '{blocked_path}' may contain secrets or critical system configuration",
                blocked_path,
            )

    for ext in blocked.get("extensions", []):
        if re.search(rf"{re.escape(ext)}\b", lower):
            return (
                f"Sensitive file extension not permitted: '{ext}' files may contain private keys or certificates",
                ext,
            )

    if is_protected_runtime_path(path):
        return (
            f"Path '{path}' is protected runtime state and is not accessible via {tool or 'this tool'}",
            "runtime_protected_path",
        )

    if not is_within_workspace(path):
        return (f"Path '{path}' is outside the allowed workspace", "workspace_boundary")

    backup_access = POLICY.get("backup_access", {})
    if backup_access.get("block_agent_tools", True) and is_backup_path(path):
        allowed_tools = {str(t).lower() for t in backup_access.get("allowed_tools", ["restore_backup"])}
        tool_name = (tool or "").lower()
        if tool_name not in allowed_tools:
            return (
                f"Path '{path}' is inside protected backup storage and is not accessible via {tool or 'this tool'}",
                "backup_storage_protected",
            )

    return None
