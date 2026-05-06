import datetime
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
    POLICY_PATH,
    REPORTS_DB_PATH,
    WORKSPACE_ROOT,
)
from models import PolicyResult
from runtime_context import current_agent_session_id

SERVER_RETRY_COUNTS: dict[str, int] = {}


def _capture_parenthesized(text: str, start_index: int) -> tuple[str | None, int]:
    """Capture a balanced parenthesized payload starting immediately after '('.

    Returns (payload_without_outer_parens, index_after_closing_paren). If no
    matching closing parenthesis is found, returns (None, start_index).
    """
    depth = 1
    in_single = False
    in_double = False
    escaped = False
    buf: list[str] = []
    i = start_index

    while i < len(text):
        ch = text[i]
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

        if not in_single and not in_double:
            if ch == "(":
                depth += 1
                buf.append(ch)
                i += 1
                continue
            if ch == ")":
                depth -= 1
                if depth == 0:
                    return "".join(buf).strip(), i + 1
                buf.append(ch)
                i += 1
                continue

        buf.append(ch)
        i += 1

    return None, start_index


def _capture_backticks(text: str, start_index: int) -> tuple[str | None, int]:
    """Capture payload between backticks starting immediately after opening `."""
    escaped = False
    buf: list[str] = []
    i = start_index

    while i < len(text):
        ch = text[i]
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
        if ch == "`":
            return "".join(buf).strip(), i + 1
        buf.append(ch)
        i += 1

    return None, start_index


def _extract_substitution_commands(command: str, *, depth: int = 0, max_depth: int = 8) -> list[str]:
    """Best-effort static extraction of shell substitution command payloads.

    Covers common forms:
    - $(...)
    - `...`
    - <(...) and >(...)
    - nested substitutions (recursively)

    Known limitation: this is intentionally not a full shell parser/interpreter.
    """
    if depth >= max_depth:
        return []

    found: list[str] = []
    i = 0
    in_single = False
    in_double = False
    escaped = False

    while i < len(command):
        ch = command[i]
        if escaped:
            escaped = False
            i += 1
            continue

        if ch == "\\":
            escaped = True
            i += 1
            continue

        if ch == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue

        if ch == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue

        if in_single:
            i += 1
            continue

        # POSIX command substitution: $(...)
        if ch == "$" and i + 1 < len(command) and command[i + 1] == "(":
            payload, end_i = _capture_parenthesized(command, i + 2)
            if payload is not None and payload:
                found.append(payload)
                found.extend(_extract_substitution_commands(payload, depth=depth + 1, max_depth=max_depth))
                i = end_i
                continue

        # Process substitution: <(...) or >(...)
        if ch in {"<", ">"} and i + 1 < len(command) and command[i + 1] == "(":
            payload, end_i = _capture_parenthesized(command, i + 2)
            if payload is not None and payload:
                found.append(payload)
                found.extend(_extract_substitution_commands(payload, depth=depth + 1, max_depth=max_depth))
                i = end_i
                continue

        # Backtick substitution.
        if ch == "`":
            payload, end_i = _capture_backticks(command, i + 1)
            if payload is not None and payload:
                found.append(payload)
                found.extend(_extract_substitution_commands(payload, depth=depth + 1, max_depth=max_depth))
                i = end_i
                continue

        i += 1

    return found


def _is_env_assignment_token(token: str) -> bool:
    if "=" not in token:
        return False
    key = token.split("=", 1)[0]
    if not key:
        return False
    return all(ch.isalnum() or ch == "_" for ch in key)


def _primary_command_token(tokens: list[str]) -> tuple[str | None, int]:
    idx = 0
    while idx < len(tokens) and _is_env_assignment_token(tokens[idx]):
        idx += 1
    if idx < len(tokens) and tokens[idx] == "env":
        idx += 1
        while idx < len(tokens) and (_is_env_assignment_token(tokens[idx]) or tokens[idx].startswith("-")):
            idx += 1
    if idx >= len(tokens):
        return None, -1
    return tokens[idx], idx


def _extract_eval_payload_commands(command: str, *, depth: int = 0, max_depth: int = 8) -> list[str]:
    if depth >= max_depth:
        return []

    shell_flags = {"-c", "--command"}
    eval_flags = {"-c", "-e", "--eval"}
    shell_commands = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
    eval_commands = {"python", "python3", "python3.12", "python3.13", "python3.14", "perl", "ruby", "node"}
    found: list[str] = []

    for segment in split_shell_segments(command):
        tokens, err = tokenize_shell_segment(segment)
        if err or not tokens:
            continue
        command_token, command_index = _primary_command_token(tokens)
        if command_token is None:
            continue
        cmd = os.path.basename(command_token).lower()
        flags = shell_flags if cmd in shell_commands else eval_flags if cmd in eval_commands else set()
        if not flags:
            continue
        i = command_index + 1
        while i < len(tokens):
            token = tokens[i]
            payload: str | None = None
            if token in flags and i + 1 < len(tokens):
                payload = tokens[i + 1]
                i += 2
            elif any(token.startswith(f"{flag}=") for flag in flags):
                payload = token.split("=", 1)[1]
                i += 1
            else:
                i += 1
            if payload:
                normalized = str(payload).strip()
                if not normalized:
                    continue
                found.append(normalized)
                found.extend(_extract_substitution_commands(normalized, depth=depth + 1, max_depth=max_depth))
                found.extend(_extract_eval_payload_commands(normalized, depth=depth + 1, max_depth=max_depth))

    return found


def shell_command_contexts(command: str) -> list[str]:
    """Return top-level command plus nested substitution command contexts."""
    contexts: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        contexts.append(normalized)

    _add(command)
    for inner in _extract_substitution_commands(command):
        _add(inner)
    for inner in _extract_eval_payload_commands(command):
        _add(inner)
    return contexts

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
    for ctx_command in shell_command_contexts(command):
        for segment in split_shell_segments(ctx_command):
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
    block_unknown = bool(network.get("block_unknown_domains", False))
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

    if block_unknown:
        for domain in domains:
            if not _domain_matches(domain, allowed):
                reason = f"Network domain '{domain}' is not in allowed_domains policy (block_unknown_domains=true)"
                if mode == "monitor":
                    return True, reason
                return False, reason

    return True, None


def _shell_containment_mode() -> str:
    cfg = POLICY.get("execution", {}).get("shell_workspace_containment", {})
    return str(cfg.get("mode", "off")).lower()


def _shell_containment_exempt_commands() -> set[str]:
    cfg = POLICY.get("execution", {}).get("shell_workspace_containment", {})
    return {
        str(value).strip().lower()
        for value in cfg.get("exempt_commands", [])
        if str(value).strip()
    }


def _looks_like_path_token(token: str) -> bool:
    if not token:
        return False
    if token.startswith("-"):
        return False
    # Skip env var assignment tokens (e.g. FOO=bar cmd).
    if "=" in token and "/" not in token and not token.startswith((".", "~")):
        key = token.split("=", 1)[0]
        if key and all(ch.isalnum() or ch == "_" for ch in key):
            return False
    if token.startswith(("/", "./", "../", "~/")):
        return True
    if "/" in token:
        return True
    if token.startswith("."):
        return True
    # File-like tokens are treated as path candidates for containment checks.
    if "." in token:
        return True
    return False


def _resolve_candidate_path(token: str) -> pathlib.Path:
    expanded = os.path.expanduser(token)
    if os.path.isabs(expanded):
        return pathlib.Path(expanded).resolve()
    return (pathlib.Path(WORKSPACE_ROOT) / expanded).resolve()


def _runtime_protected_paths() -> set[pathlib.Path]:
    approval_db = pathlib.Path(
        os.environ.get("AIRG_APPROVAL_DB_PATH", str(BASE_DIR / "approvals.db"))
    ).resolve()
    approval_key = pathlib.Path(
        os.environ.get("AIRG_APPROVAL_HMAC_KEY_PATH", f"{approval_db}.hmac.key")
    ).resolve()
    reports_db = pathlib.Path(
        os.environ.get("AIRG_REPORTS_DB_PATH", str(REPORTS_DB_PATH))
    ).resolve()
    policy_path = pathlib.Path(
        os.environ.get("AIRG_POLICY_PATH", str(POLICY_PATH))
    ).resolve()
    return {
        pathlib.Path(LOG_PATH).resolve(),
        approval_db,
        approval_key,
        reports_db,
        policy_path,
    }


def _blocked_path_matches(candidate: pathlib.Path, blocked_path: str) -> bool:
    raw = str(blocked_path or "").strip()
    if not raw:
        return False
    normalized = raw.replace("\\", "/")
    lowered = normalized.lower()
    candidate_lower = str(candidate).lower()

    # Absolute policy paths are exact-match checked post-resolution.
    if os.path.isabs(normalized) or normalized.startswith("~"):
        try:
            blocked_resolved = pathlib.Path(os.path.expanduser(normalized)).resolve()
            return candidate == blocked_resolved
        except Exception:
            return False

    # Dotfile/filename protections match path segments explicitly.
    parts = [p.lower() for p in candidate.parts]
    if "/" not in normalized:
        return lowered in parts

    # Relative fragments are matched on normalized suffix.
    return candidate_lower.endswith(lowered)


def _command_path_candidates(command: str) -> list[pathlib.Path]:
    resolved: list[pathlib.Path] = []
    seen: set[str] = set()

    for ctx_command in shell_command_contexts(command):
        for segment in split_shell_segments(ctx_command):
            tokens, err = tokenize_shell_segment(segment)
            if err:
                continue
            candidates: list[str] = []
            if tokens:
                cmd_name = str(tokens[0]).lower()
                if cmd_name == "cd" and len(tokens) >= 2:
                    candidates.append(tokens[1])
                candidates.extend(t for t in tokens[1:] if _looks_like_path_token(t))
            candidates.extend(_extract_redirection_targets(segment))

            for candidate in candidates:
                try:
                    path = _resolve_candidate_path(candidate.strip("'\""))
                except Exception:
                    continue
                key = str(path)
                if key in seen:
                    continue
                seen.add(key)
                resolved.append(path)

    return resolved


def _has_dangerous_env_assignment(command: str) -> tuple[bool, str | None]:
    dangerous = {
        "IFS",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PYTHONPATH",
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "GIT_SSH_COMMAND",
    }
    for segment in split_shell_segments(command):
        tokens, err = tokenize_shell_segment(segment)
        if err or not tokens:
            continue
        idx = 0
        while idx < len(tokens) and _is_env_assignment_token(tokens[idx]):
            key = tokens[idx].split("=", 1)[0].upper()
            if key in dangerous:
                return True, key
            idx += 1
    return False, None


def _extract_redirection_targets(segment: str) -> list[str]:
    # Capture basic shell redirection operands (`>`, `>>`, `<`, `<<`).
    matches = re.findall(r"(?:^|\s)(?:>>|>|<<|<)\s*([^\s;|&]+)", segment)
    return [m.strip().strip("'\"") for m in matches if m.strip()]


def shell_workspace_containment_check(command: str) -> tuple[bool, str | None, list[str]]:
    mode = _shell_containment_mode()
    if mode == "off":
        return True, None, []

    exempt = _shell_containment_exempt_commands()
    offending_paths: list[str] = []
    seen: set[str] = set()

    for segment in split_shell_segments(command):
        tokens, err = tokenize_shell_segment(segment)
        if err:
            reason = "Shell workspace containment blocked command: shell tokenization failed."
            if mode == "monitor":
                return True, reason, []
            return False, reason, []
        if not tokens:
            continue
        cmd_name = str(tokens[0]).lower()
        if cmd_name in exempt:
            continue

        candidates: list[str] = []
        if cmd_name == "cd" and len(tokens) >= 2:
            candidates.append(tokens[1])
        candidates.extend(t for t in tokens[1:] if _looks_like_path_token(t))
        candidates.extend(_extract_redirection_targets(segment))

        for candidate in candidates:
            try:
                resolved = _resolve_candidate_path(candidate)
            except Exception:
                continue
            resolved_str = str(resolved)
            if resolved_str in seen:
                continue
            seen.add(resolved_str)
            if not is_within_workspace(resolved_str):
                offending_paths.append(resolved_str)

    if not offending_paths:
        return True, None, []

    reason = (
        "Shell workspace containment blocked command: one or more referenced paths are "
        "outside AIRG_WORKSPACE/allowed whitelist roots"
    )
    if mode == "monitor":
        return True, reason, offending_paths
    return False, reason, offending_paths


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
        if lower_pattern in rebuilt:
            return True
        pattern_tokens = lower_pattern.split()
        if not pattern_tokens:
            return False
        i = 0
        for tok in tokens:
            if tok == pattern_tokens[i]:
                i += 1
                if i == len(pattern_tokens):
                    return True
        return False

    return _matches


def check_blocked_tier(command: str) -> tuple[str, str] | None:
    blocked = POLICY.get("blocked", {})
    lower = command.lower()
    has_dangerous_assignment, assignment_key = _has_dangerous_env_assignment(command)
    if has_dangerous_assignment:
        return (
            f"Dangerous environment assignment '{assignment_key}' is not permitted in execute_command",
            "dangerous_env_assignment",
        )

    for pattern in blocked.get("commands", []):
        if build_command_matcher(pattern)(command):
            return (
                f"Blocked destructive command '{pattern}': this operation is prohibited by policy",
                pattern,
            )

    candidates = _command_path_candidates(command)
    protected = _runtime_protected_paths()
    for candidate in candidates:
        if candidate in protected:
            return (
                f"Path '{candidate}' is protected runtime state and is not accessible via execute_command",
                "runtime_protected_path",
            )
        for path in blocked.get("paths", []):
            if _blocked_path_matches(candidate, str(path)):
                return (
                    f"Sensitive path access not permitted: '{path}' may contain secrets or critical system configuration",
                    str(path),
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
    agent_session_id = current_agent_session_id()

    for pattern in conf.get("commands", []):
        if build_command_matcher(pattern)(command):
            whitelist_enabled = conf.get("session_whitelist_enabled", True)
            if whitelist_enabled and consume_approved_command(agent_session_id, command):
                return None
            return (f"Command '{pattern}' requires explicit confirmation before execution", pattern)

    for candidate in _command_path_candidates(command):
        for path in conf.get("paths", []):
            if _blocked_path_matches(candidate, str(path)):
                whitelist_enabled = conf.get("session_whitelist_enabled", True)
                if whitelist_enabled and consume_approved_command(agent_session_id, command):
                    return None
                return (f"Access to path '{path}' requires explicit confirmation", str(path))

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
    )
    append_log_entry(warning)


def check_policy(command: str) -> PolicyResult:
    norm = normalize_command(command)
    _tokens, parse_error = tokenize_command(command)
    if parse_error:
        return PolicyResult(
            allowed=False,
            reason="Shell command parsing failed; command blocked to preserve policy enforcement.",
            decision_tier="blocked",
            matched_rule="command_parse_error",
        )
    matching_tiers: list[tuple[str, str, str]] = []

    blocked_result = check_blocked_tier(command)
    if blocked_result:
        reason, matched_rule = blocked_result
        matching_tiers.append(("blocked", reason, matched_rule))

    confirmation_result = check_confirmation_tier(command)
    if confirmation_result:
        reason, matched_rule = confirmation_result
        matching_tiers.append(("requires_confirmation", reason, matched_rule))

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
    return resolved in _runtime_protected_paths()


def check_path_policy(path: str, tool: str | None = None) -> tuple[str, str] | None:
    blocked = POLICY.get("blocked", {})
    lower_path = str(path).lower()
    try:
        resolved = pathlib.Path(path).resolve()
    except Exception:
        resolved = pathlib.Path(path)

    for blocked_path in blocked.get("paths", []):
        if _blocked_path_matches(resolved, str(blocked_path)):
            return (
                f"Sensitive path access not permitted: '{blocked_path}' may contain secrets or critical system configuration",
                blocked_path,
            )

    for ext in blocked.get("extensions", []):
        if re.search(rf"{re.escape(ext)}\b", lower_path):
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
        tool_name = (tool or "").lower()
        if tool_name != "restore_backup":
            return (
                f"Path '{path}' is inside protected backup storage and is not accessible via {tool or 'this tool'}",
                "backup_storage_protected",
            )

    return None
