import datetime
import json
import os
import pathlib
import platform
import uuid


def _module_base_dir() -> pathlib.Path:
    here = pathlib.Path(__file__).resolve().parent
    # In editable source layout modules live under ./src.
    if here.name == "src" and (here.parent / "pyproject.toml").exists():
        return here.parent
    return here


def _default_base_state_dir() -> pathlib.Path:
    if os.name == "nt":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            return pathlib.Path(appdata) / "ai-runtime-guard"
    if platform.system() == "Darwin":
        return pathlib.Path.home() / "Library" / "Application Support" / "ai-runtime-guard"
    xdg = os.environ.get("XDG_STATE_HOME", "")
    if xdg:
        return pathlib.Path(xdg) / "ai-runtime-guard"
    return pathlib.Path.home() / ".local" / "state" / "ai-runtime-guard"


def _default_base_config_dir() -> pathlib.Path:
    if os.name == "nt":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            return pathlib.Path(appdata) / "ai-runtime-guard"
    if platform.system() == "Darwin":
        return pathlib.Path.home() / "Library" / "Application Support" / "ai-runtime-guard"
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    if xdg:
        return pathlib.Path(xdg) / "ai-runtime-guard"
    return pathlib.Path.home() / ".config" / "ai-runtime-guard"


# Startup configuration
BASE_DIR = _module_base_dir()
LOG_PATH = str(pathlib.Path(os.environ.get("AIRG_LOG_PATH", str(_default_base_state_dir() / "activity.log"))).expanduser().resolve())
REPORTS_DB_PATH = str(
    pathlib.Path(
        os.environ.get(
            "AIRG_REPORTS_DB_PATH",
            str(pathlib.Path(os.environ.get("AIRG_APPROVAL_DB_PATH", str(_default_base_state_dir() / "approvals.db"))).expanduser().resolve().with_name("reports.db")),
        )
    ).expanduser().resolve()
)
def _default_backup_root() -> pathlib.Path:
    env_override = os.environ.get("AIRG_BACKUP_ROOT", "").strip()
    if env_override:
        return pathlib.Path(env_override).expanduser().resolve()
    return (_default_base_state_dir() / "backups").resolve()


BACKUP_DIR = str(_default_backup_root())
POLICY_PATH = pathlib.Path(
    os.environ.get("AIRG_POLICY_PATH", str(_default_base_config_dir() / "policy.json"))
).expanduser().resolve()


def _load_policy() -> dict:
    path = POLICY_PATH
    if not path.exists():
        fallback = BASE_DIR / "policy.json"
        if fallback.exists():
            path = fallback
    with open(path) as f:
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
    allowed.setdefault("max_directory_depth", 100)

    network = _ensure_dict("network")
    network.setdefault("enforcement_mode", "off")
    _ensure_list(network, "commands")
    _ensure_list(network, "allowed_domains")
    _ensure_list(network, "blocked_domains")
    network.setdefault("block_unknown_domains", False)
    if network["enforcement_mode"] not in {"off", "monitor", "enforce"}:
        raise ValueError("network.enforcement_mode must be one of: off, monitor, enforce")
    if not isinstance(network["block_unknown_domains"], bool):
        raise ValueError("network.block_unknown_domains must be boolean")

    execution = _ensure_dict("execution")
    execution.setdefault("max_command_timeout_seconds", 30)
    execution.setdefault("max_output_chars", 200000)
    shell_containment = execution.setdefault("shell_workspace_containment", {})
    if not isinstance(shell_containment, dict):
        raise ValueError("execution.shell_workspace_containment must be an object")
    shell_containment.setdefault("mode", "off")
    shell_containment.setdefault("exempt_commands", [])
    shell_containment.setdefault("log_paths", True)
    if int(execution["max_command_timeout_seconds"]) < 1:
        raise ValueError("execution.max_command_timeout_seconds must be >= 1")
    if int(execution["max_output_chars"]) < 1024:
        raise ValueError("execution.max_output_chars must be >= 1024")
    if shell_containment["mode"] not in {"off", "monitor", "enforce"}:
        raise ValueError("execution.shell_workspace_containment.mode must be one of: off, monitor, enforce")
    if not isinstance(shell_containment["exempt_commands"], list):
        raise ValueError("execution.shell_workspace_containment.exempt_commands must be an array")
    if not isinstance(shell_containment["log_paths"], bool):
        raise ValueError("execution.shell_workspace_containment.log_paths must be boolean")

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
    audit.setdefault("backup_root", str(_default_backup_root()))
    audit.setdefault("backup_retention_days", 30)
    audit.setdefault("log_level", "verbose")
    if int(audit["max_versions_per_file"]) < 1:
        raise ValueError("audit.max_versions_per_file must be >= 1")
    _ensure_list(audit, "redact_patterns")

    reports = _ensure_dict("reports")
    reports.setdefault("enabled", True)
    reports.setdefault("ingest_poll_interval_seconds", 5)
    reports.setdefault("reconcile_interval_seconds", 3600)
    reports.setdefault("retention_days", 30)
    reports.setdefault("max_db_size_mb", 200)
    reports.setdefault("prune_interval_seconds", 86400)
    if not isinstance(reports["enabled"], bool):
        raise ValueError("reports.enabled must be boolean")
    if int(reports["ingest_poll_interval_seconds"]) < 1:
        raise ValueError("reports.ingest_poll_interval_seconds must be >= 1")
    if int(reports["reconcile_interval_seconds"]) < 60:
        raise ValueError("reports.reconcile_interval_seconds must be >= 60")
    if int(reports["retention_days"]) < 1:
        raise ValueError("reports.retention_days must be >= 1")
    if int(reports["max_db_size_mb"]) < 10:
        raise ValueError("reports.max_db_size_mb must be >= 10")
    if int(reports["prune_interval_seconds"]) < 300:
        raise ValueError("reports.prune_interval_seconds must be >= 300")

    return policy


POLICY: dict = _validate_and_normalize_policy(_load_policy())
BACKUP_DIR = str(
    pathlib.Path(POLICY.get("audit", {}).get("backup_root", str(_default_backup_root())))
    .expanduser()
    .resolve()
)
MAX_RETRIES: int = POLICY.get("requires_simulation", {}).get("max_retries", 3)

SESSION_ID: str = str(uuid.uuid4())
AGENT_ID: str = (os.environ.get("AIRG_AGENT_ID", "").strip() or "Unknown")
WORKSPACE_ROOT: str = os.environ.get("AIRG_WORKSPACE", str(BASE_DIR))
SERVER_BUILD = "2026-02-23T22:10Z-simfix-check"

APPROVAL_TTL_SECONDS: int = POLICY.get("requires_confirmation", {}).get(
    "approval_security", {}
).get("token_ttl_seconds", 600)

RESTORE_CONFIRMATION_TTL_SECONDS: int = POLICY.get("restore", {}).get(
    "confirmation_ttl_seconds", 300
)
