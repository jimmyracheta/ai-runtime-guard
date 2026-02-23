"""
MCP server that exposes a single tool: execute_command.

The tool runs every command through a policy engine first. Blocked commands
are logged and rejected without execution. Allowed commands are logged and
then executed via subprocess, returning stdout or stderr.
"""

import json
import os
import re
import shutil
import subprocess
import datetime

from mcp.server.fastmcp import FastMCP

# Create the MCP server with a descriptive name
mcp = FastMCP("ai-runtime-guard")

# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------

# Rule 1 — Destructive commands that should never run.
# Each entry is (pattern_to_search_for, human_readable_reason).
# Note: "dd" is intentionally absent here — it requires a regex check (see below)
# because "dd" as a substring would incorrectly match words like "pwd" or "add".
BLOCKED_COMMANDS = [
    ("rm -rf",   "rm -rf recursively deletes files with no confirmation and cannot be undone"),
    ("mkfs",     "mkfs formats a filesystem, erasing all data on the target device"),
    ("shutdown", "shutdown powers off or reboots the system, disrupting all running services"),
    ("reboot",   "reboot restarts the system, disrupting all running services"),
    ("format",   "format erases a disk or partition and cannot be undone"),
]

# "dd" needs its own regex so it only matches as a standalone command at the
# start of the string (e.g. "dd if=..." is blocked, but "pwd" or "add" are not).
# ^\s*  — optional leading whitespace
# dd    — the literal command name
# \b    — word boundary, so "dd2" or "adduser" won't match
DD_COMMAND_RE = re.compile(r"^\s*dd\b")

# Rule 2 — Sensitive paths that must not be read or written.
# Checked as substrings; the .pem / .key extensions are checked separately.
SENSITIVE_PATHS = [".env", ".ssh", "/etc/passwd"]

# Rule 3 — Wildcard pattern combined with destructive operations.
# Matches commands that use * or ? alongside rm or mv.
WILDCARD_DESTRUCTIVE_RE = re.compile(r"\b(rm|mv)\b[^|;&\n]*[*?]")

# ---------------------------------------------------------------------------
# Backup layer
# ---------------------------------------------------------------------------

# Root folder where all timestamped backups are stored.
BACKUP_DIR = "/Users/liviu/Documents/ai-runtime-guard/backups"

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


def check_policy(command: str):
    """
    Evaluate *command* against all policy rules.

    Returns:
        (allowed: bool, reason: str)
        - If allowed is True,  reason is "allowed".
        - If allowed is False, reason explains why the command was blocked.
    """

    lower = command.lower()

    # --- Rule 1: blocked destructive commands ---
    for pattern, danger in BLOCKED_COMMANDS:
        if pattern in lower:
            return False, f"Blocked destructive command '{pattern}': {danger}"

    # "dd" is checked separately with a regex to avoid false positives on
    # commands like "pwd" or "add" that contain "dd" as part of a longer word.
    if DD_COMMAND_RE.match(command):
        return False, "Blocked destructive command 'dd': dd can overwrite entire disks or devices with no safeguards"

    # --- Rule 2: sensitive path protection ---
    for path in SENSITIVE_PATHS:
        if path in lower:
            return False, (
                f"Sensitive path access not permitted: '{path}' "
                "may contain secrets or critical system configuration"
            )
    # Also block any file ending in .pem or .key
    if re.search(r"\.pem\b", lower) or re.search(r"\.key\b", lower):
        return False, (
            "Sensitive path access not permitted: "
            ".pem and .key files may contain private keys or certificates"
        )

    # --- Rule 3: wildcard + destructive operation ---
    if WILDCARD_DESTRUCTIVE_RE.search(command):
        return False, (
            "Bulk file operation blocked: using wildcards (* or ?) with 'rm' or 'mv' "
            "can affect unintended files — please specify exact filenames instead"
        )

    return True, "allowed"


# ---------------------------------------------------------------------------
# Backup helpers
# ---------------------------------------------------------------------------

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

    # Strip surrounding quotes that the shell would normally remove
    candidates = [c.strip().strip("'\"") for c in candidates]

    # Keep only paths that exist so we never back up a phantom target
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
    # Build a filesystem-safe timestamp (no colons — macOS/Windows disallow them)
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    backup_location = os.path.join(BACKUP_DIR, timestamp)

    # Create the backup folder (and BACKUP_DIR itself if it doesn't exist yet)
    os.makedirs(backup_location, exist_ok=True)

    for path in paths:
        if os.path.isfile(path):
            # copy2 preserves file metadata (timestamps, permissions)
            shutil.copy2(path, backup_location)
        elif os.path.isdir(path):
            # copytree requires the destination not to exist, so append the
            # directory's own name to keep multiple dirs in the same backup slot
            dest = os.path.join(backup_location, os.path.basename(path))
            shutil.copytree(path, dest)

    return backup_location


# ---------------------------------------------------------------------------
# MCP tool
# ---------------------------------------------------------------------------

# Maximum number of blocked attempts allowed before the action is permanently
# refused for this request. The agent may retry up to this many times total.
MAX_RETRIES = 3


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
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "source": "ai-agent",
        "tool": "execute_command",
        "command": command,
        "policy_decision": "allowed" if allowed else "blocked",
        # Always record the retry count so the log shows the full retry history
        "retry_count": retry_count,
    }

    if not allowed:
        # Add the block reason so the log explains exactly why
        log_entry["block_reason"] = reason

        # If this is the final attempt, mark it permanently blocked in the log
        if retry_count >= MAX_RETRIES:
            log_entry["final_block"] = True

    # --- 3. Write the log entry (always, regardless of allow/block) ---
    with open("/Users/liviu/Documents/ai-runtime-guard/activity.log", "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # --- 4. If blocked, return a structured message without executing anything ---
    if not allowed:
        if retry_count >= MAX_RETRIES:
            # The agent has used all of its attempts — refuse permanently.
            return (
                f"[POLICY BLOCK] {reason}\n\n"
                "Maximum retries reached (3/3). This action is permanently "
                "blocked for the current request. No further attempts will be accepted."
            )

        # Calculate how many attempts the agent still has left.
        attempts_remaining = MAX_RETRIES - retry_count

        # Return a structured message that tells the agent what went wrong,
        # how many attempts remain, and asks it to try a safer alternative.
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
            # Record the backup location in the log so the audit trail shows
            # exactly where the pre-execution snapshot was saved.
            log_entry["backup_location"] = backup_location
            # Re-write the log entry now that we have the backup location.
            # (The entry was already written above; append an updated copy so
            # the final record on disk reflects the backup that was made.)
            with open("/Users/liviu/Documents/ai-runtime-guard/activity.log", "a") as log_file:
                log_file.write(json.dumps({**log_entry, "event": "backup_created"}) + "\n")

    # --- 6. Execute the command ---
    result = subprocess.run(
        command,
        shell=True,          # Allows pipes, redirects, etc.
        capture_output=True, # Captures both stdout and stderr
        text=True,           # Decodes bytes to str automatically
    )

    # --- 7. Return output or error ---
    if result.returncode != 0:
        # Non-zero exit code means the command failed
        return result.stderr or f"Command exited with code {result.returncode}"

    # Success: return standard output (may be an empty string)
    return result.stdout


if __name__ == "__main__":
    # Run over stdio — the standard transport for MCP servers
    mcp.run()
