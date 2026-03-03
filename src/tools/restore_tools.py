import json
import os
import pathlib
import shutil
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import Context
else:
    Context = Any

from approvals import consume_restore_confirmation_token, issue_restore_confirmation_token
from audit import append_log_entry, build_log_entry
from backup import sha256_file
from config import BACKUP_DIR, POLICY
from models import PolicyResult
from policy_engine import is_within_workspace
from runtime_context import activate_runtime_context, reset_runtime_context


def restore_backup(
    backup_location: str,
    dry_run: bool = True,
    restore_token: str = "",
    ctx: Context | None = None,
) -> str:
    context_tokens = activate_runtime_context(ctx)
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
        append_log_entry(
            build_log_entry(
                "restore_backup",
                result,
                backup_location=str(backup_path),
                dry_run=dry_run,
            )
        )
        return "[POLICY BLOCK] Backup restore path must be inside BACKUP_DIR"

    try:
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
                token, expires_at = issue_restore_confirmation_token(backup_path, planned)
                response_extra = {
                    "restore_token_issued": token,
                    "restore_token_expires_at": expires_at.isoformat() + "Z",
                }
            append_log_entry(
                build_log_entry(
                    "restore_backup",
                    PolicyResult(allowed=True, reason="allowed", decision_tier="allowed", matched_rule=None),
                    backup_location=str(backup_path),
                    dry_run=True,
                    planned=planned,
                    restored=0,
                    hash_failures=0,
                    **response_extra,
                )
            )

            msg = f"Restore dry run complete: {planned} item(s) eligible from {backup_path}"
            if require_confirm:
                msg += (
                    f"\nrestore_token={response_extra['restore_token_issued']}"
                    f"\nrestore_token_expires_at={response_extra['restore_token_expires_at']}"
                )
            return msg

        if require_confirm:
            ok, reason, matched_rule = consume_restore_confirmation_token(backup_path, restore_token)
            if not ok:
                append_log_entry(
                    build_log_entry(
                        "restore_backup",
                        PolicyResult(
                            allowed=False,
                            reason=reason or "Invalid restore token",
                            decision_tier="blocked",
                            matched_rule=matched_rule,
                        ),
                        backup_location=str(backup_path),
                        dry_run=False,
                        restore_token=restore_token,
                    )
                )
                return f"[POLICY BLOCK] {reason}"

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
                        actual_hash = sha256_file(backup_item)
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

        append_log_entry(
            build_log_entry(
                "restore_backup",
                PolicyResult(allowed=True, reason="allowed", decision_tier="allowed", matched_rule=None),
                backup_location=str(backup_path),
                dry_run=dry_run,
                planned=planned,
                restored=restored,
                hash_failures=hash_failures,
            )
        )

        return f"Restore complete from {backup_path}: restored={restored}, planned={planned}, hash_failures={hash_failures}"
    finally:
        reset_runtime_context(context_tokens)
