"""
MCP server that exposes six tools: execute_command, approve_command, read_file,
write_file, delete_file, and list_directory.

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


# POLICY is loaded once when the server starts. Restart to pick up edits.
POLICY: dict = _load_policy()

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

# Generated once when the server process starts. Every log entry includes
# this ID so related records across tools can be correlated by session.
SESSION_ID: str = str(uuid.uuid4())

# Root directory that this server instance is authorised to work in.
# Override by setting the AIRG_WORKSPACE environment variable before launch.
WORKSPACE_ROOT: str = os.environ.get("AIRG_WORKSPACE", str(BASE_DIR))

# Build marker for quickly verifying the running server version.
SERVER_BUILD = "2026-02-23T22:10Z-simfix-check"

# One-time approval token validity window.
APPROVAL_TTL_SECONDS: int = 600

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

    Only a minimal set of variables is inherited to reduce accidental secret
    exposure from the host process environment.
    """
    safe = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "HOME": WORKSPACE_ROOT,
    }
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
    if len(words) == 1:
        # Compile once; search the lowercased command at call time.
        regex = re.compile(rf"\b{re.escape(pattern.lower())}\b")
        return lambda cmd: bool(regex.search(cmd.lower()))
    else:
        lower_pat = pattern.lower()
        return lambda cmd: lower_pat in cmd.lower()


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

    # Split on shell command separators; each segment is evaluated independently.
    segments = re.split(r"[|;&]+", command)
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        try:
            tokens = shlex.split(segment)
        except ValueError:
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


def _check_path_policy(path: str) -> tuple[str, str] | None:
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
        entry["block_reason"] = result.reason
    # Caller-supplied fields (command, path, retry_count, error, …) are appended
    # last so standard fields are always the first keys in every log line.
    entry.update(kwargs)
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

    # Keep only paths that exist so we never attempt to back up a ghost target.
    return [c for c in candidates if os.path.exists(c)]


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
            dest.parent.mkdir(parents=True, exist_ok=True)
            # copy2 preserves file metadata (timestamps, permissions).
            shutil.copy2(str(resolved), str(dest))
            manifest.append({"source": str(resolved), "backup": str(dest), "type": "file"})
        elif resolved.is_dir():
            shutil.copytree(str(resolved), str(dest))
            manifest.append({"source": str(resolved), "backup": str(dest), "type": "directory"})

    with open(os.path.join(backup_location, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    return backup_location


# ---------------------------------------------------------------------------
# MCP tool
# ---------------------------------------------------------------------------

@mcp.tool()
def server_info() -> str:
    return f"ai-runtime-guard build={SERVER_BUILD} workspace={WORKSPACE_ROOT} base_dir={BASE_DIR}"


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

    # --- 1. Hard-fail commands with unsafe control characters ---
    if _has_shell_unsafe_control_chars(command):
        result = PolicyResult(
            allowed=False,
            reason="Command contains disallowed control characters (newline, carriage return, or NUL)",
            decision_tier="blocked",
            matched_rule="command_control_characters",
        )
    else:
        # --- 2. Run the policy check ---
        result = check_policy(command)

    # --- 3. Server-side retry tracking ---
    # retry_count is accepted from clients for compatibility, but enforcement
    # is performed server-side using SERVER_RETRY_COUNTS.
    server_retry_count = 0
    final_block = False
    if not result.allowed and result.decision_tier != "requires_confirmation":
        server_retry_count = _register_retry(command, result.decision_tier, result.matched_rule)
        final_block = server_retry_count >= MAX_RETRIES

    # --- 4. Build the log entry via the standard builder ---
    log_entry = build_log_entry(
        "execute_command", result,
        command=command,
        # normalized_command is the whitespace-collapsed, case-preserved form
        # used as the base for policy matching (lowercased internally).
        normalized_command=normalize_for_audit(command),
        retry_count=retry_count,
        server_retry_count=server_retry_count,
        **({"final_block": True} if final_block else {}),
    )

    # --- 5. Write the log entry (always, regardless of allow/block) ---
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # --- 6. If blocked, return a structured message without executing anything ---
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
            # The agent has used all of its attempts — refuse permanently.
            return (
                f"[POLICY BLOCK] {result.reason}\n\n"
                f"Maximum retries reached ({MAX_RETRIES}/{MAX_RETRIES}). "
                "This action is permanently blocked for the current request. "
                "No further attempts will be accepted."
            )

        # Tell the agent what went wrong, how many attempts remain, and ask
        # it to call execute_command again with a safer command.
        attempts_remaining = MAX_RETRIES - server_retry_count
        return (
            f"[POLICY BLOCK] {result.reason}\n\n"
            f"You have {attempts_remaining} attempt(s) remaining. "
            "Please retry execute_command with a safer alternative command "
            f"(server attempt {server_retry_count}/{MAX_RETRIES})."
        )

    # --- 7. Back up any files that the command might modify or delete ---
    # Only triggered for commands that contain rm, mv, or a > overwrite redirect.
    if MODIFYING_COMMAND_RE.search(command):
        affected = extract_paths(command)
        if affected:
            backup_location = backup_paths(affected)
            # Record the backup location so the audit trail shows exactly where
            # the pre-execution snapshot was saved.
            log_entry["backup_location"] = backup_location
            # Append an updated log line tagged "backup_created" so the final
            # record on disk reflects the backup that was made.
            with open(LOG_PATH, "a") as log_file:
                log_file.write(json.dumps({**log_entry, "event": "backup_created"}) + "\n")

    # --- 8. Execute the command with hardened shell settings ---
    try:
        proc = subprocess.run(
            command,
            shell=True,          # Allows pipes, redirects, etc.
            executable="/bin/bash",
            cwd=WORKSPACE_ROOT,
            env=_safe_subprocess_env(),
            capture_output=True, # Captures both stdout and stderr.
            text=True,           # Decodes bytes to str automatically.
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return "Command timed out after 30 seconds"

    # --- 9. Return output or error ---
    if proc.returncode != 0:
        # Non-zero exit code means the command failed.
        return proc.stderr or f"Command exited with code {proc.returncode}"

    # Success: return standard output (may be an empty string).
    return proc.stdout


@mcp.tool()
def approve_command(command: str, approval_token: str) -> str:
    """
    Approve a previously blocked command for this server session.

    The command and token must match an active handshake issued by
    execute_command when requires_confirmation rules fired.
    """
    _prune_expired_approvals()
    rec = PENDING_APPROVALS.get(approval_token)
    expected_hash = command_hash(command)

    if not rec:
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
    path_check = _check_path_policy(path)
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
    path_check = _check_path_policy(path)
    if path_check:
        result = PolicyResult(allowed=False, reason=path_check[0],
                              decision_tier="blocked", matched_rule=path_check[1])
    else:
        result = PolicyResult(allowed=True, reason="allowed",
                              decision_tier="allowed", matched_rule=None)

    # --- 2. Build the log entry ---
    log_entry = build_log_entry("write_file", result, path=path)

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
    path_check = _check_path_policy(path)
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

    # --- 3. Build the log entry with the final policy decision ---
    log_entry = build_log_entry("delete_file", result, path=path)

    # --- 4. If blocked, write log and return without touching the filesystem ---
    if not result.allowed:
        with open(LOG_PATH, "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
        return f"[POLICY BLOCK] {result.reason}"

    # --- 5. Create a backup before any destructive action ---
    # backup_paths() is called unconditionally here — existence was confirmed
    # in step 2, so the file is guaranteed to be present at this point.
    backup_location = backup_paths([path])
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
        f"Backup saved to {backup_location} — the file can be recovered from there."
    )


@mcp.tool()
def list_directory(path: str) -> str:
    """
    List the contents of a directory and return a formatted summary.

    Checks (in order before any I/O):
      1. Path is validated against policy (blocked paths, extensions).
      2. The path must exist and be a directory — a clear error is returned
         for missing paths or plain files.
      3. Directory depth (number of segments from the filesystem root) is
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
    path_check = _check_path_policy(path)
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
        # Resolve to an absolute path first so relative paths (e.g. ".") are
        # measured consistently against the filesystem root.
        resolved  = pathlib.Path(path).resolve()
        # len(resolved.parts) counts every segment including the root ("/"),
        # so "/" has depth 1, "/home" has depth 2, "/home/user" depth 3, etc.
        depth     = len(resolved.parts)
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
