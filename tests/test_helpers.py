import copy
import pathlib
from contextlib import ExitStack
from unittest.mock import patch

import approvals
import audit
import backup
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
    "allowed": {
        "paths_whitelist": [],
        "max_directory_depth": 20,
    },
    "network": {
        "enforcement_mode": "off",
        "commands": [],
        "allowed_domains": [],
        "blocked_domains": [],
        "block_unknown_domains": False,
    },
    "execution": {
        "max_command_timeout_seconds": 30,
        "max_output_chars": 200000,
        "shell_workspace_containment": {
            "mode": "off",
            "exempt_commands": [],
            "log_paths": True,
        },
    },
    "backup_access": {"block_agent_tools": True},
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
    "telemetry": {
        "enabled": True,
        "endpoint": "https://telemetry.runtime-guard.ai/v1/telemetry",
        "last_payload_generated_date": "",
        "last_payload_uploaded_at": "",
        "last_sent_date": "",
    },
    "script_sentinel": {
        "enabled": False,
        "mode": "match_original",
        "scan_mode": "exec_context",
        "max_scan_bytes": 1048576,
        "include_wrappers": True,
    },
}


def apply_test_environment(workspace: pathlib.Path, max_retries: int = 2) -> ExitStack:
    ws = str(workspace.resolve())
    log_path = str((workspace / "activity.log").resolve())
    backup_dir = str((workspace / "backups").resolve())
    reports_db = str((workspace / "reports.db").resolve())
    approval_db = pathlib.Path(workspace / "approvals.db").resolve()
    stack = ExitStack()

    for module in [config, audit, policy_engine, backup, executor, command_tools, file_tools]:
        if hasattr(module, "WORKSPACE_ROOT"):
            stack.enter_context(patch.object(module, "WORKSPACE_ROOT", ws))
    for module in [config, audit]:
        if hasattr(module, "LOG_PATH"):
            stack.enter_context(patch.object(module, "LOG_PATH", log_path))
    if hasattr(config, "REPORTS_DB_PATH"):
        stack.enter_context(patch.object(config, "REPORTS_DB_PATH", reports_db))
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
