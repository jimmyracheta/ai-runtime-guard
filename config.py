import datetime
import json
import os
import pathlib
import uuid

# Startup configuration
BASE_DIR = pathlib.Path(__file__).parent
LOG_PATH = str(BASE_DIR / "activity.log")
BACKUP_DIR = str(BASE_DIR / "backups")
POLICY_PATH = BASE_DIR / "policy.json"


def _load_policy() -> dict:
    with open(POLICY_PATH) as f:
        return json.load(f)


def _validate_and_normalize_policy(policy: dict) -> dict:
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
    overrides.setdefault("require_confirmation_tool", "out_of_band_operator_approval")
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


POLICY: dict = _validate_and_normalize_policy(_load_policy())
BACKUP_DIR = str(pathlib.Path(POLICY.get("audit", {}).get("backup_root", BACKUP_DIR)).resolve())
MAX_RETRIES: int = POLICY.get("requires_simulation", {}).get("max_retries", 3)

SESSION_ID: str = str(uuid.uuid4())
WORKSPACE_ROOT: str = os.environ.get("AIRG_WORKSPACE", str(BASE_DIR))
SERVER_BUILD = "2026-02-23T22:10Z-simfix-check"

APPROVAL_TTL_SECONDS: int = POLICY.get("requires_confirmation", {}).get(
    "approval_security", {}
).get("token_ttl_seconds", 600)

RESTORE_CONFIRMATION_TTL_SECONDS: int = POLICY.get("restore", {}).get(
    "confirmation_ttl_seconds", 300
)
