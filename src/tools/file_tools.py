import datetime
import os
import pathlib

from audit import append_log_entry, build_log_entry
from backup import backup_paths
from budget import check_and_record_cumulative_budget
from config import POLICY, WORKSPACE_ROOT
from models import PolicyResult
from policy_engine import check_path_policy, relative_depth


def read_file(path: str) -> str:
    path = str(pathlib.Path(WORKSPACE_ROOT) / path) if not os.path.isabs(path) else path

    path_check = check_path_policy(path, tool="read_file")
    if path_check:
        result = PolicyResult(allowed=False, reason=path_check[0], decision_tier="blocked", matched_rule=path_check[1])
    else:
        result = PolicyResult(allowed=True, reason="allowed", decision_tier="allowed", matched_rule=None)

    if result.allowed:
        max_mb = POLICY.get("allowed", {}).get("max_file_size_mb", 10)
        try:
            size_mb = os.path.getsize(path) / (1024 * 1024)
            if size_mb > max_mb:
                result = PolicyResult(
                    allowed=False,
                    reason=f"File size {size_mb:.1f} MB exceeds the policy limit of {max_mb} MB (allowed.max_file_size_mb)",
                    decision_tier="blocked",
                    matched_rule="allowed.max_file_size_mb",
                )
        except (FileNotFoundError, OSError):
            pass

    append_log_entry(build_log_entry("read_file", result, path=path))
    if not result.allowed:
        return f"[POLICY BLOCK] {result.reason}"

    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return f"Error: file not found: {path}"
    except OSError as e:
        return f"Error reading file: {e}"


def write_file(path: str, content: str) -> str:
    path = str(pathlib.Path(WORKSPACE_ROOT) / path) if not os.path.isabs(path) else path

    path_check = check_path_policy(path, tool="write_file")
    if path_check:
        result = PolicyResult(allowed=False, reason=path_check[0], decision_tier="blocked", matched_rule=path_check[1])
    else:
        result = PolicyResult(allowed=True, reason="allowed", decision_tier="allowed", matched_rule=None)

    budget_fields: dict = {}
    if result.allowed:
        budget_allowed, budget_reason, budget_rule, budget_fields = check_and_record_cumulative_budget(
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

    log_entry = build_log_entry("write_file", result, path=path, **budget_fields)
    append_log_entry(log_entry)
    if not result.allowed:
        return f"[POLICY BLOCK] {result.reason}"

    backup_location = None
    if os.path.exists(path):
        backup_location = backup_paths([path])
        if backup_location:
            append_log_entry(
                {
                    **log_entry,
                    "source": "mcp-server",
                    "backup_location": backup_location,
                    "event": "backup_created",
                }
            )

    try:
        with open(path, "w") as f:
            f.write(content)
    except OSError as e:
        return f"Error writing file: {e}"

    msg = f"Successfully wrote {len(content)} characters to {path}"
    if backup_location:
        msg += f" (previous version backed up to {backup_location})"
    else:
        msg += " (no content-change backup needed)"
    return msg


def delete_file(path: str) -> str:
    path = str(pathlib.Path(WORKSPACE_ROOT) / path) if not os.path.isabs(path) else path

    path_check = check_path_policy(path, tool="delete_file")
    if path_check:
        result = PolicyResult(allowed=False, reason=path_check[0], decision_tier="blocked", matched_rule=path_check[1])
    else:
        result = PolicyResult(allowed=True, reason="allowed", decision_tier="allowed", matched_rule=None)

    if result.allowed:
        if not os.path.exists(path):
            append_log_entry(build_log_entry("delete_file", result, path=path, error="file not found"))
            return f"Error: file not found: {path}"

        if os.path.isdir(path):
            result = PolicyResult(
                allowed=False,
                reason=f"'{path}' is a directory  -  delete_file only removes individual files. Use execute_command for directory operations (note: bulk/recursive deletions are also subject to policy).",
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
        budget_allowed, budget_reason, budget_rule, budget_fields = check_and_record_cumulative_budget(
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

    log_entry = build_log_entry("delete_file", result, path=path, **budget_fields)
    if not result.allowed:
        append_log_entry(log_entry)
        return f"[POLICY BLOCK] {result.reason}"

    backup_location = backup_paths([path])
    if backup_location:
        log_entry["backup_location"] = backup_location

    append_log_entry(log_entry)

    try:
        os.remove(path)
    except OSError as e:
        return f"Error deleting file: {e}"

    return f"Successfully deleted {path}. " + (
        f"Backup saved to {backup_location}  -  the file can be recovered from there."
        if backup_location
        else "No content-change backup was needed."
    )


def list_directory(path: str) -> str:
    path = str(pathlib.Path(WORKSPACE_ROOT) / path) if not os.path.isabs(path) else path

    path_check = check_path_policy(path, tool="list_directory")
    if path_check:
        result = PolicyResult(allowed=False, reason=path_check[0], decision_tier="blocked", matched_rule=path_check[1])
    else:
        result = PolicyResult(allowed=True, reason="allowed", decision_tier="allowed", matched_rule=None)

    if result.allowed:
        if not os.path.exists(path):
            append_log_entry(build_log_entry("list_directory", result, path=path, error="path not found"))
            return f"Error: path not found: {path}"

        if not os.path.isdir(path):
            append_log_entry(build_log_entry("list_directory", result, path=path, error="not a directory"))
            return f"Error: '{path}' is a file, not a directory"

        depth = relative_depth(path)
        max_depth = POLICY.get("allowed", {}).get("max_directory_depth", 5)
        if depth > max_depth:
            result = PolicyResult(
                allowed=False,
                reason=f"Directory depth {depth} exceeds the policy limit of {max_depth} (allowed.max_directory_depth): '{path}'",
                decision_tier="blocked",
                matched_rule="allowed.max_directory_depth",
            )

    append_log_entry(build_log_entry("list_directory", result, path=path))
    if not result.allowed:
        return f"[POLICY BLOCK] {result.reason}"

    lines = [f"Contents of {path}:"]
    try:
        entries = sorted(os.scandir(path), key=lambda e: (e.is_file(), e.name))
    except OSError as e:
        return f"Error reading directory: {e}"

    for entry in entries:
        try:
            stat = entry.stat(follow_symlinks=False)
            mtime = datetime.datetime.fromtimestamp(stat.st_mtime, datetime.UTC).isoformat().replace("+00:00", "Z")
            kind = "file" if entry.is_file(follow_symlinks=False) else "directory"
            size = f"{stat.st_size} bytes" if kind == "file" else "-"
            lines.append(f"  {entry.name}  [{kind}]  size={size}  modified={mtime}")
        except OSError:
            lines.append(f"  {entry.name}  [unreadable]")

    if len(lines) == 1:
        lines.append("  (empty)")

    return "\n".join(lines)
