import copy
import pathlib
from contextlib import ExitStack
from unittest.mock import patch

import approvals
import audit
import backup
import budget
import config
import executor
import policy_engine
from tools import command_tools, file_tools, restore_tools


DEFAULT_TEST_POLICY = {
    "blocked": {"commands": [], "paths": [], "extensions": []},
    "requires_confirmation": {
        "commands": [],
        "paths": [],
        "session_whitelist_enabled": True,
        "approval_security": {
            "max_failed_attempts_per_token": 5,
            "failed_attempt_window_seconds": 600,
            "token_ttl_seconds": 600,
        },
    },
    "requires_simulation": {
        "commands": ["rm", "mv"],
        "bulk_file_threshold": 2,
        "max_retries": 2,
        "cumulative_budget": {
            "enabled": False,
            "scope": "session",
            "limits": {
                "max_unique_paths": 50,
                "max_total_operations": 100,
                "max_total_bytes_estimate": 104857600,
            },
            "counting": {
                "mode": "affected_paths",
                "dedupe_paths": True,
                "include_noop_attempts": False,
                "commands_included": ["rm", "mv", "write_file", "delete_file"],
            },
            "reset": {
                "mode": "sliding_window",
                "window_seconds": 3600,
                "idle_reset_seconds": 900,
                "reset_on_server_restart": True,
            },
            "on_exceed": {
                "decision_tier": "blocked",
                "matched_rule": "requires_simulation.cumulative_budget_exceeded",
                "message": "Cumulative blast-radius budget exceeded for current scope.",
            },
            "overrides": {
                "enabled": True,
                "require_confirmation_tool": "out_of_band_operator_approval",
                "token_ttl_seconds": 300,
                "max_override_actions": 1,
                "audit_reason_required": True,
                "allowed_roles": ["human-operator"],
            },
            "audit": {
                "log_budget_state": True,
                "fields": [
                    "budget_scope",
                    "budget_key",
                    "cumulative_unique_paths",
                    "cumulative_total_operations",
                    "cumulative_total_bytes_estimate",
                    "budget_remaining",
                ],
            },
        },
    },
    "allowed": {
        "paths_whitelist": [],
        "max_files_per_operation": 10,
        "max_file_size_mb": 10,
        "max_directory_depth": 20,
    },
    "network": {
        "enforcement_mode": "off",
        "commands": [],
        "allowed_domains": [],
        "blocked_domains": [],
        "max_payload_size_kb": 1024,
    },
    "execution": {"max_command_timeout_seconds": 30, "max_output_chars": 200000},
    "backup_access": {"block_agent_tools": True, "allowed_tools": ["restore_backup"]},
    "restore": {"require_dry_run_before_apply": True, "confirmation_ttl_seconds": 300},
    "audit": {
        "backup_enabled": True,
        "backup_on_content_change_only": True,
        "max_versions_per_file": 5,
        "backup_root": "backups",
        "backup_retention_days": 30,
        "log_level": "verbose",
        "redact_patterns": [],
    },
}


def apply_test_environment(workspace: pathlib.Path, max_retries: int = 2) -> ExitStack:
    ws = str(workspace.resolve())
    log_path = str((workspace / "activity.log").resolve())
    backup_dir = str((workspace / "backups").resolve())
    approval_db = pathlib.Path(workspace / "approvals.db").resolve()
    stack = ExitStack()

    for module in [config, audit, policy_engine, backup, budget, executor, command_tools, file_tools]:
        if hasattr(module, "WORKSPACE_ROOT"):
            stack.enter_context(patch.object(module, "WORKSPACE_ROOT", ws))
    for module in [config, audit]:
        if hasattr(module, "LOG_PATH"):
            stack.enter_context(patch.object(module, "LOG_PATH", log_path))
    if hasattr(policy_engine, "LOG_PATH"):
        stack.enter_context(patch.object(policy_engine, "LOG_PATH", log_path))
    for module in [config, backup, policy_engine, restore_tools]:
        if hasattr(module, "BACKUP_DIR"):
            stack.enter_context(patch.object(module, "BACKUP_DIR", backup_dir))
    if hasattr(policy_engine, "BASE_DIR"):
        stack.enter_context(patch.object(policy_engine, "BASE_DIR", pathlib.Path(ws)))
    for module in [config, policy_engine, command_tools]:
        if hasattr(module, "MAX_RETRIES"):
            stack.enter_context(patch.object(module, "MAX_RETRIES", max_retries))
    stack.enter_context(patch.object(approvals, "APPROVAL_DB_PATH", approval_db))
    stack.enter_context(patch.dict("os.environ", {"AIRG_APPROVAL_DB_PATH": str(approval_db)}, clear=False))

    return stack


def install_test_policy(policy: dict | None = None) -> dict:
    original = copy.deepcopy(config.POLICY)
    config.POLICY.clear()
    config.POLICY.update(copy.deepcopy(policy or DEFAULT_TEST_POLICY))
    return original


def restore_policy(original: dict) -> None:
    config.POLICY.clear()
    config.POLICY.update(original)


def reset_runtime_state() -> None:
    approvals.reset_approval_state_for_tests()
    approvals.PENDING_RESTORE_CONFIRMATIONS.clear()
    policy_engine.SERVER_RETRY_COUNTS.clear()
    budget.CUMULATIVE_BUDGET_STATE.clear()
