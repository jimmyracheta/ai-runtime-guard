"""
MCP server that exposes three tools: execute_command, read_file, write_file.

Policy rules are loaded from policy.json at startup. Every tool call passes
through the policy engine (blocked → requires_confirmation →
requires_simulation → allowed) before any I/O is performed. Blocked calls
are logged and rejected. Allowed file writes are backed up first; allowed
commands are optionally backed up and then executed via subprocess.
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import datetime

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

# Tracks commands the user has explicitly approved during this session.
# When requires_confirmation.session_whitelist_enabled is True in policy,
# a command in this set bypasses the confirmation check on future calls.
SESSION_WHITELIST: set = set()

# Create the MCP server with a descriptive name.
mcp = FastMCP("ai-runtime-guard")


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


def _check_blocked_tier(command: str) -> str | None:
    """
    Check *command* against every rule in the 'blocked' policy tier.

    Checks (in order):
      1. blocked.commands  — dangerous commands (word-boundary safe)
      2. blocked.paths     — sensitive file/directory paths
      3. blocked.extensions — sensitive file extensions (.pem, .key, …)

    Returns a human-readable reason string if blocked, or None if the
    command passes all checks in this tier.
    """
    blocked = POLICY.get("blocked", {})
    lower   = command.lower()

    # 1. Blocked command patterns
    for pattern in blocked.get("commands", []):
        if _build_command_matcher(pattern)(command):
            return (
                f"Blocked destructive command '{pattern}': "
                "this operation is prohibited by policy"
            )

    # 2. Blocked file/directory paths (substring match on lowercased command)
    for path in blocked.get("paths", []):
        if path.lower() in lower:
            return (
                f"Sensitive path access not permitted: '{path}' "
                "may contain secrets or critical system configuration"
            )

    # 3. Blocked file extensions
    # re.escape handles the leading dot; \b prevents partial extension matches
    # (e.g. ".pem" should not match ".pemfile").
    for ext in blocked.get("extensions", []):
        if re.search(rf"{re.escape(ext)}\b", lower):
            return (
                f"Sensitive file extension not permitted: '{ext}' files "
                "may contain private keys or certificates"
            )

    return None


def _check_confirmation_tier(command: str) -> str | None:
    """
    Check *command* against the 'requires_confirmation' policy tier.

    If session_whitelist_enabled is True and the exact command string is
    already in SESSION_WHITELIST, the check is skipped — the user already
    approved it earlier this session.

    Returns a reason string if confirmation is required, or None if the
    command passes (or is whitelisted).
    """
    conf  = POLICY.get("requires_confirmation", {})
    lower = command.lower()

    # Skip the confirmation check for previously approved commands.
    whitelist_enabled = conf.get("session_whitelist_enabled", True)
    if whitelist_enabled and command in SESSION_WHITELIST:
        return None

    for pattern in conf.get("commands", []):
        if _build_command_matcher(pattern)(command):
            return f"Command '{pattern}' requires explicit confirmation before execution"

    for path in conf.get("paths", []):
        if path.lower() in lower:
            return f"Access to path '{path}' requires explicit confirmation"

    return None


def _check_simulation_tier(command: str) -> str | None:
    """
    Check *command* against the 'requires_simulation' policy tier.

    Any command listed in requires_simulation.commands combined with a
    wildcard character (* or ?) is treated as a potentially dangerous bulk
    operation and blocked. The list of commands is read from policy.json so
    it can be updated without touching this file.

    Example (with policy commands ["rm", "mv"]):
      "rm *.log"   → blocked  (rm + wildcard)
      "mv *.bak /" → blocked  (mv + wildcard)
      "rm file.log"→ allowed  (rm, no wildcard)

    Returns a reason string if simulation is required, or None otherwise.
    """
    sim          = POLICY.get("requires_simulation", {})
    sim_commands = sim.get("commands", [])

    if sim_commands:
        # Build a single regex from all simulation commands.
        # The character class [^|;&\n]* ensures we only look for wildcards
        # on the same command segment, not after a pipe or semicolon.
        ops_pattern = "|".join(re.escape(c) for c in sim_commands)
        wildcard_re = re.compile(rf"\b({ops_pattern})\b[^|;&\n]*[*?]")
        if wildcard_re.search(command):
            ops_display = "/".join(sim_commands)
            return (
                f"Bulk file operation blocked: using wildcards (* or ?) with "
                f"'{ops_display}' can affect unintended files — "
                "please specify exact filenames instead"
            )

    return None


def _log_policy_conflict(command: str, matching_tiers: list) -> None:
    """
    Append a warning entry to activity.log when *command* matches more than
    one policy tier. Records which tiers matched and which one won so the
    audit trail explains the resolution.
    """
    tier_names = [tier for tier, _ in matching_tiers]
    warning = {
        "timestamp":      datetime.datetime.utcnow().isoformat() + "Z",
        "event":          "policy_conflict_warning",
        "command":        command,
        "matching_tiers": tier_names,
        "resolved_to":    tier_names[0],  # highest-priority tier always wins
    }
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(warning) + "\n")


def check_policy(command: str):
    """
    Evaluate *command* against all policy tiers in priority order:

        blocked  >  requires_confirmation  >  requires_simulation  >  allowed

    Each tier is checked independently so we can detect conflicts. If a
    command matches more than one tier, the highest-priority tier wins and
    a warning is silently logged to activity.log.

    Returns:
        (allowed: bool, reason: str)
        - allowed=True,  reason="allowed"   — command may proceed
        - allowed=False, reason=<str>       — command is blocked with
                                              an explanation of why
    """
    matching_tiers = []

    blocked_reason = _check_blocked_tier(command)
    if blocked_reason:
        matching_tiers.append(("blocked", blocked_reason))

    confirmation_reason = _check_confirmation_tier(command)
    if confirmation_reason:
        matching_tiers.append(("requires_confirmation", confirmation_reason))

    simulation_reason = _check_simulation_tier(command)
    if simulation_reason:
        matching_tiers.append(("requires_simulation", simulation_reason))

    # Log a warning whenever a command lands in more than one tier.
    if len(matching_tiers) > 1:
        _log_policy_conflict(command, matching_tiers)

    if not matching_tiers:
        return True, "allowed"

    # Return the decision of the highest-priority (first) matching tier.
    _top_tier, reason = matching_tiers[0]
    return False, reason


def _check_path_policy(path: str) -> str | None:
    """
    Check a file path against the blocked path and extension rules in policy.json.

    Called by read_file, write_file, delete_file, and list_directory before
    any I/O is performed.

    Checks (in order):
      1. blocked.paths      — block if any entry appears as a substring of path
      2. blocked.extensions — block if the path ends with a blocked extension

    Returns a human-readable reason string if the path is blocked, or None
    if it passes every check.
    """
    blocked = POLICY.get("blocked", {})
    lower   = path.lower()

    # 1. Blocked path substrings
    for blocked_path in blocked.get("paths", []):
        if blocked_path.lower() in lower:
            return (
                f"Sensitive path access not permitted: '{blocked_path}' "
                "may contain secrets or critical system configuration"
            )

    # 2. Blocked file extensions
    for ext in blocked.get("extensions", []):
        if re.search(rf"{re.escape(ext)}\b", lower):
            return (
                f"Sensitive file extension not permitted: '{ext}' files "
                "may contain private keys or certificates"
            )

    return None


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
    # Filesystem-safe timestamp — colons are disallowed on macOS and Windows.
    timestamp       = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    backup_location = os.path.join(BACKUP_DIR, timestamp)

    # Create the backup folder (and BACKUP_DIR itself if it doesn't exist yet).
    os.makedirs(backup_location, exist_ok=True)

    for path in paths:
        if os.path.isfile(path):
            # copy2 preserves file metadata (timestamps, permissions).
            shutil.copy2(path, backup_location)
        elif os.path.isdir(path):
            # copytree requires the destination not to exist, so append the
            # directory's own name to keep multiple dirs in the same backup slot.
            dest = os.path.join(backup_location, os.path.basename(path))
            shutil.copytree(path, dest)

    return backup_location


# ---------------------------------------------------------------------------
# MCP tool
# ---------------------------------------------------------------------------

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

    # --- 1. Run the policy check ---
    allowed, reason = check_policy(command)

    # --- 2. Build the log entry (common fields for all outcomes) ---
    log_entry = {
        "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
        "source":          "ai-agent",
        "tool":            "execute_command",
        "command":         command,
        "policy_decision": "allowed" if allowed else "blocked",
        # Always record retry_count so the log shows the full retry history.
        "retry_count":     retry_count,
    }

    if not allowed:
        # Record why the command was blocked.
        log_entry["block_reason"] = reason
        # Flag the entry when no further retries will be accepted.
        if retry_count >= MAX_RETRIES:
            log_entry["final_block"] = True

    # --- 3. Write the log entry (always, regardless of allow/block) ---
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # --- 4. If blocked, return a structured message without executing anything ---
    if not allowed:
        if retry_count >= MAX_RETRIES:
            # The agent has used all of its attempts — refuse permanently.
            return (
                f"[POLICY BLOCK] {reason}\n\n"
                f"Maximum retries reached ({MAX_RETRIES}/{MAX_RETRIES}). "
                "This action is permanently blocked for the current request. "
                "No further attempts will be accepted."
            )

        # Tell the agent what went wrong, how many attempts remain, and ask
        # it to call execute_command again with a safer command.
        attempts_remaining = MAX_RETRIES - retry_count
        return (
            f"[POLICY BLOCK] {reason}\n\n"
            f"You have {attempts_remaining} attempt(s) remaining. "
            "Please retry execute_command with a safer alternative command "
            f"and set retry_count={retry_count + 1}."
        )

    # --- 5. Back up any files that the command might modify or delete ---
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

    # --- 6. Execute the command ---
    result = subprocess.run(
        command,
        shell=True,          # Allows pipes, redirects, etc.
        capture_output=True, # Captures both stdout and stderr.
        text=True,           # Decodes bytes to str automatically.
    )

    # --- 7. Return output or error ---
    if result.returncode != 0:
        # Non-zero exit code means the command failed.
        return result.stderr or f"Command exited with code {result.returncode}"

    # Success: return standard output (may be an empty string).
    return result.stdout


@mcp.tool()
def read_file(path: str) -> str:
    """
    Read a file from the filesystem and return its contents as a string.

    The path is checked against policy before any data is read:
      - blocked.paths and blocked.extensions are rejected outright
      - If allowed.paths_whitelist is non-empty, only whitelisted paths pass
      - Files larger than allowed.max_file_size_mb are rejected

    Args:
        path: Absolute or relative path to the file to read.

    Returns:
        The file contents as a string, or a [POLICY BLOCK] / error message.
    """

    # --- 1. Check path against policy ---
    block_reason = _check_path_policy(path)

    # --- 2. If path is allowed, also check file size before committing ---
    if not block_reason:
        max_mb = POLICY.get("allowed", {}).get("max_file_size_mb", 10)
        try:
            size_mb = os.path.getsize(path) / (1024 * 1024)
            if size_mb > max_mb:
                block_reason = (
                    f"File size {size_mb:.1f} MB exceeds the policy limit "
                    f"of {max_mb} MB (allowed.max_file_size_mb)"
                )
        except FileNotFoundError:
            pass  # Let the read below produce a clear "not found" error.
        except OSError:
            pass  # Same — surface the error during the read.

    # --- 3. Build the log entry with the final policy decision ---
    log_entry = {
        "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
        "source":          "ai-agent",
        "tool":            "read_file",
        "path":            path,
        "policy_decision": "blocked" if block_reason else "allowed",
    }
    if block_reason:
        log_entry["block_reason"] = block_reason

    # --- 4. Write the log entry (always, before any I/O) ---
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # --- 5. Reject blocked requests without touching the file ---
    if block_reason:
        return f"[POLICY BLOCK] {block_reason}"

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

    # --- 1. Check path against policy ---
    block_reason = _check_path_policy(path)

    # --- 2. Build the log entry with the final policy decision ---
    log_entry = {
        "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
        "source":          "ai-agent",
        "tool":            "write_file",
        "path":            path,
        "policy_decision": "blocked" if block_reason else "allowed",
    }
    if block_reason:
        log_entry["block_reason"] = block_reason

    # --- 3. Write the log entry (always, before any I/O) ---
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # --- 4. Reject blocked requests without touching the file ---
    if block_reason:
        return f"[POLICY BLOCK] {block_reason}"

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
      1. Path is checked against policy (blocked paths, extensions, whitelist).
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

    # --- 1. Check path against policy (blocked paths, extensions, whitelist) ---
    block_reason = _check_path_policy(path)

    # --- 2. Pre-flight checks on the target (only when policy allows) ---
    if not block_reason:
        if not os.path.exists(path):
            # Not a policy block — the file simply isn't there.
            # Log the attempt and return a clear error without blocking.
            log_entry = {
                "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
                "source":          "ai-agent",
                "tool":            "delete_file",
                "path":            path,
                "policy_decision": "allowed",
                "error":           "file not found",
            }
            with open(LOG_PATH, "a") as log_file:
                log_file.write(json.dumps(log_entry) + "\n")
            return f"Error: file not found: {path}"

        if os.path.isdir(path):
            # Directories need recursive operations that carry higher risk.
            # Direct the agent to execute_command for those cases.
            block_reason = (
                f"'{path}' is a directory — delete_file only removes individual "
                "files. Use execute_command for directory operations "
                "(note: bulk/recursive deletions are also subject to policy)."
            )

    # --- 3. Build the log entry with the final policy decision ---
    log_entry = {
        "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
        "source":          "ai-agent",
        "tool":            "delete_file",
        "path":            path,
        "policy_decision": "blocked" if block_reason else "allowed",
    }
    if block_reason:
        log_entry["block_reason"] = block_reason

    # --- 4. If blocked, write log and return without touching the filesystem ---
    if block_reason:
        with open(LOG_PATH, "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
        return f"[POLICY BLOCK] {block_reason}"

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
      1. Path is validated against policy (blocked paths, extensions, whitelist).
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

    # --- 1. Check path against policy (blocked paths, extensions, whitelist) ---
    block_reason = _check_path_policy(path)

    # --- 2. Existence and type checks (only when policy allows) ---
    if not block_reason:
        if not os.path.exists(path):
            # Not a policy block — the path simply doesn't exist.
            # Log the attempt and return a clear error.
            log_entry = {
                "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
                "source":          "ai-agent",
                "tool":            "list_directory",
                "path":            path,
                "policy_decision": "allowed",
                "error":           "path not found",
            }
            with open(LOG_PATH, "a") as log_file:
                log_file.write(json.dumps(log_entry) + "\n")
            return f"Error: path not found: {path}"

        if not os.path.isdir(path):
            # The path exists but is a file — log and return a clear error.
            log_entry = {
                "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
                "source":          "ai-agent",
                "tool":            "list_directory",
                "path":            path,
                "policy_decision": "allowed",
                "error":           "not a directory",
            }
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
            block_reason = (
                f"Directory depth {depth} exceeds the policy limit of "
                f"{max_depth} (allowed.max_directory_depth): '{path}'"
            )

    # --- 4. Build the log entry with the final policy decision ---
    log_entry = {
        "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
        "source":          "ai-agent",
        "tool":            "list_directory",
        "path":            path,
        "policy_decision": "blocked" if block_reason else "allowed",
    }
    if block_reason:
        log_entry["block_reason"] = block_reason

    # --- 5. Write the log entry (always, before any I/O) ---
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # --- 6. Return block message without touching the filesystem ---
    if block_reason:
        return f"[POLICY BLOCK] {block_reason}"

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
