import datetime
import copy
import json
import os
import pathlib
import platform
import threading
import uuid
from importlib.metadata import PackageNotFoundError, version

DEFAULT_MAX_RETRIES = 3


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


def _default_workspace_root() -> pathlib.Path:
    return (pathlib.Path.home() / "airg-workspace").resolve()


# Startup configuration
BASE_DIR = _module_base_dir()
AGENT_ID: str = (os.environ.get("AIRG_AGENT_ID", "").strip() or "Unknown")
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
    path = _policy_source_path()
    with open(path) as f:
        return json.load(f)


def _policy_source_path() -> pathlib.Path:
    path = POLICY_PATH
    if not path.exists():
        fallback = BASE_DIR / "policy.json"
        if fallback.exists():
            path = fallback
    return path


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

    legacy_sim = policy.pop("requires_simulation", None)
    legacy_sim_commands: list[str] = []
    if isinstance(legacy_sim, dict):
        raw_sim_commands = legacy_sim.get("commands", [])
        if isinstance(raw_sim_commands, list):
            legacy_sim_commands = [str(cmd).strip() for cmd in raw_sim_commands if str(cmd).strip()]

    blocked = _ensure_dict("blocked")
    _ensure_list(blocked, "commands")
    _ensure_list(blocked, "paths")
    _ensure_list(blocked, "extensions")

    conf = _ensure_dict("requires_confirmation")
    _ensure_list(conf, "commands")
    _ensure_list(conf, "paths")
    if legacy_sim_commands:
        conf["commands"] = sorted(set(list(conf["commands"]) + legacy_sim_commands))
    conf.setdefault("session_whitelist_enabled", True)
    if not isinstance(conf["session_whitelist_enabled"], bool):
        raise ValueError("requires_confirmation.session_whitelist_enabled must be boolean")
    sec = conf.setdefault("approval_security", {})
    if not isinstance(sec, dict):
        raise ValueError("requires_confirmation.approval_security must be an object")
    sec.setdefault("max_failed_attempts_per_token", 5)
    sec.setdefault("failed_attempt_window_seconds", 600)
    sec.setdefault("token_ttl_seconds", 600)

    allowed = _ensure_dict("allowed")
    _ensure_list(allowed, "paths_whitelist")
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

    telemetry = _ensure_dict("telemetry")
    telemetry.setdefault("enabled", True)
    telemetry.setdefault("endpoint", "https://telemetry.runtime-guard.ai/v1/telemetry")
    telemetry.setdefault("last_payload_generated_date", "")
    telemetry.setdefault("last_payload_uploaded_at", "")
    telemetry.setdefault("last_sent_date", "")
    if not isinstance(telemetry["enabled"], bool):
        raise ValueError("telemetry.enabled must be boolean")
    if not isinstance(telemetry["endpoint"], str):
        raise ValueError("telemetry.endpoint must be string")
    if not isinstance(telemetry["last_payload_generated_date"], str):
        raise ValueError("telemetry.last_payload_generated_date must be string")
    if not isinstance(telemetry["last_payload_uploaded_at"], str):
        raise ValueError("telemetry.last_payload_uploaded_at must be string")
    if not isinstance(telemetry["last_sent_date"], str):
        raise ValueError("telemetry.last_sent_date must be string")

    script_sentinel = _ensure_dict("script_sentinel")
    script_sentinel.setdefault("enabled", True)
    script_sentinel.setdefault("mode", "match_original")
    script_sentinel.setdefault("scan_mode", "exec_context_plus_mentions")
    script_sentinel.setdefault("max_scan_bytes", 1048576)
    script_sentinel.setdefault("include_wrappers", True)
    if not isinstance(script_sentinel["enabled"], bool):
        raise ValueError("script_sentinel.enabled must be boolean")
    if str(script_sentinel["mode"]).strip() not in {"match_original", "block", "requires_confirmation"}:
        raise ValueError("script_sentinel.mode must be one of: match_original, block, requires_confirmation")
    if str(script_sentinel["scan_mode"]).strip() not in {"exec_context", "exec_context_plus_mentions"}:
        raise ValueError("script_sentinel.scan_mode must be one of: exec_context, exec_context_plus_mentions")
    if int(script_sentinel["max_scan_bytes"]) < 1024:
        raise ValueError("script_sentinel.max_scan_bytes must be >= 1024")
    if not isinstance(script_sentinel["include_wrappers"], bool):
        raise ValueError("script_sentinel.include_wrappers must be boolean")

    agent_overrides = policy.get("agent_overrides", {})
    if agent_overrides is None:
        agent_overrides = {}
    if not isinstance(agent_overrides, dict):
        raise ValueError("policy.agent_overrides must be an object")
    allowed_override_sections = {
        "blocked",
        "requires_confirmation",
        "allowed",
        "network",
        "execution",
    }
    normalized_overrides: dict[str, dict] = {}
    tier_rank = {"off": 0, "monitor": 1, "enforce": 2}

    def _as_str_set(values: object) -> set[str]:
        if not isinstance(values, list):
            return set()
        return {str(v).strip() for v in values if str(v).strip()}

    def _validate_tightening_override(agent_key: str, overlay: dict) -> None:
        blocked_base = policy.get("blocked", {}) if isinstance(policy.get("blocked"), dict) else {}
        blocked_overlay = overlay.get("blocked", {}) if isinstance(overlay.get("blocked"), dict) else {}
        for key in ("commands", "paths", "extensions"):
            if key in blocked_overlay:
                base_set = _as_str_set(blocked_base.get(key, []))
                overlay_set = _as_str_set(blocked_overlay.get(key, []))
                if not base_set.issubset(overlay_set):
                    raise ValueError(
                        f"policy.agent_overrides['{agent_key}'].policy.blocked.{key} cannot be less restrictive than baseline"
                    )

        conf_base = policy.get("requires_confirmation", {}) if isinstance(policy.get("requires_confirmation"), dict) else {}
        conf_overlay = overlay.get("requires_confirmation", {}) if isinstance(overlay.get("requires_confirmation"), dict) else {}
        for key in ("commands", "paths"):
            if key in conf_overlay:
                base_set = _as_str_set(conf_base.get(key, []))
                overlay_set = _as_str_set(conf_overlay.get(key, []))
                if not base_set.issubset(overlay_set):
                    raise ValueError(
                        f"policy.agent_overrides['{agent_key}'].policy.requires_confirmation.{key} cannot be less restrictive than baseline"
                    )

        allowed_base = policy.get("allowed", {}) if isinstance(policy.get("allowed"), dict) else {}
        allowed_overlay = overlay.get("allowed", {}) if isinstance(overlay.get("allowed"), dict) else {}
        for key in ("max_directory_depth", "max_file_size_mb", "max_files_per_operation"):
            if key in allowed_overlay:
                try:
                    base_val = int(allowed_base.get(key))
                    override_val = int(allowed_overlay.get(key))
                except Exception:
                    continue
                if override_val > base_val:
                    raise ValueError(
                        f"policy.agent_overrides['{agent_key}'].policy.allowed.{key} cannot be less restrictive than baseline"
                    )

        network_base = policy.get("network", {}) if isinstance(policy.get("network"), dict) else {}
        network_overlay = overlay.get("network", {}) if isinstance(overlay.get("network"), dict) else {}
        if "enforcement_mode" in network_overlay:
            base_mode = str(network_base.get("enforcement_mode", "off")).lower()
            override_mode = str(network_overlay.get("enforcement_mode", "off")).lower()
            if tier_rank.get(override_mode, -1) < tier_rank.get(base_mode, -1):
                raise ValueError(
                    f"policy.agent_overrides['{agent_key}'].policy.network.enforcement_mode cannot be less restrictive than baseline"
                )
        if bool(network_base.get("block_unknown_domains", False)) and "block_unknown_domains" in network_overlay:
            if not bool(network_overlay.get("block_unknown_domains")):
                raise ValueError(
                    f"policy.agent_overrides['{agent_key}'].policy.network.block_unknown_domains cannot disable baseline true setting"
                )

        execution_base = policy.get("execution", {}) if isinstance(policy.get("execution"), dict) else {}
        execution_overlay = overlay.get("execution", {}) if isinstance(overlay.get("execution"), dict) else {}
        shell_base = execution_base.get("shell_workspace_containment", {}) if isinstance(execution_base.get("shell_workspace_containment"), dict) else {}
        shell_overlay = execution_overlay.get("shell_workspace_containment", {}) if isinstance(execution_overlay.get("shell_workspace_containment"), dict) else {}
        if "mode" in shell_overlay:
            base_mode = str(shell_base.get("mode", "off")).lower()
            override_mode = str(shell_overlay.get("mode", "off")).lower()
            if tier_rank.get(override_mode, -1) < tier_rank.get(base_mode, -1):
                raise ValueError(
                    f"policy.agent_overrides['{agent_key}'].policy.execution.shell_workspace_containment.mode cannot be less restrictive than baseline"
                )

    for agent_key, override in agent_overrides.items():
        if isinstance(agent_key, str) and agent_key.startswith("_"):
            continue
        if not isinstance(agent_key, str) or not agent_key.strip():
            raise ValueError("policy.agent_overrides keys must be non-empty strings")
        if not isinstance(override, dict):
            raise ValueError(f"policy.agent_overrides['{agent_key}'] must be an object")
        overlay = override.get("policy", {})
        if overlay is None:
            overlay = {}
        if not isinstance(overlay, dict):
            raise ValueError(f"policy.agent_overrides['{agent_key}'].policy must be an object")
        filtered_overlay = {
            key: value
            for key, value in overlay.items()
            if key in allowed_override_sections
        }
        _validate_tightening_override(agent_key.strip(), filtered_overlay)
        normalized_overrides[agent_key.strip()] = {
            "policy": filtered_overlay,
        }
    policy["agent_overrides"] = normalized_overrides

    return policy


def _deep_merge_dict(base: dict, overlay: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge_dict(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _resolve_effective_policy(base_policy: dict, agent_id: str) -> dict:
    overrides = base_policy.get("agent_overrides", {})
    if not isinstance(overrides, dict):
        return base_policy
    selected = overrides.get(agent_id, {})
    if not isinstance(selected, dict):
        return base_policy
    overlay = selected.get("policy", {})
    if not isinstance(overlay, dict) or not overlay:
        return base_policy
    merged = _deep_merge_dict(base_policy, overlay)
    return merged


_POLICY_LOCK = threading.RLock()
_POLICY_SOURCE_PATH: pathlib.Path = _policy_source_path()
try:
    _POLICY_SOURCE_MTIME_NS = _POLICY_SOURCE_PATH.stat().st_mtime_ns
except OSError:
    _POLICY_SOURCE_MTIME_NS = -1

_BASE_POLICY: dict = _validate_and_normalize_policy(_load_policy())
_EFFECTIVE_POLICY_DOC = _resolve_effective_policy(_BASE_POLICY, AGENT_ID)
POLICY: dict = _validate_and_normalize_policy(_EFFECTIVE_POLICY_DOC)
BACKUP_DIR = str(
    pathlib.Path(POLICY.get("audit", {}).get("backup_root", str(_default_backup_root())))
    .expanduser()
    .resolve()
)
MAX_RETRIES: int = DEFAULT_MAX_RETRIES

SESSION_ID: str = str(uuid.uuid4())
_workspace_from_env = str(os.environ.get("AIRG_WORKSPACE", "") or "").strip()
_workspace_selected = _workspace_from_env or str(_default_workspace_root())
WORKSPACE_ROOT: str = str(pathlib.Path(_workspace_selected).expanduser().resolve())


def _resolve_server_build() -> str:
    env_override = str(os.environ.get("AIRG_SERVER_BUILD", "")).strip()
    if env_override:
        return env_override
    try:
        return f"v{version('ai-runtime-guard')}"
    except PackageNotFoundError:
        return "dev"


SERVER_BUILD = _resolve_server_build()

APPROVAL_TTL_SECONDS: int = POLICY.get("requires_confirmation", {}).get(
    "approval_security", {}
).get("token_ttl_seconds", 600)

RESTORE_CONFIRMATION_TTL_SECONDS: int = POLICY.get("restore", {}).get(
    "confirmation_ttl_seconds", 300
)


def _apply_runtime_policy(effective_policy: dict) -> None:
    global BACKUP_DIR, MAX_RETRIES, APPROVAL_TTL_SECONDS, RESTORE_CONFIRMATION_TTL_SECONDS
    normalized = _validate_and_normalize_policy(copy.deepcopy(effective_policy))
    POLICY.clear()
    POLICY.update(normalized)
    BACKUP_DIR = str(
        pathlib.Path(POLICY.get("audit", {}).get("backup_root", str(_default_backup_root())))
        .expanduser()
        .resolve()
    )
    MAX_RETRIES = DEFAULT_MAX_RETRIES
    APPROVAL_TTL_SECONDS = int(
        POLICY.get("requires_confirmation", {}).get("approval_security", {}).get("token_ttl_seconds", 600)
    )
    RESTORE_CONFIRMATION_TTL_SECONDS = int(
        POLICY.get("restore", {}).get("confirmation_ttl_seconds", 300)
    )


def refresh_policy_if_changed(*, force: bool = False) -> bool:
    global _POLICY_SOURCE_PATH, _POLICY_SOURCE_MTIME_NS
    with _POLICY_LOCK:
        source = _policy_source_path()
        try:
            mtime_ns = source.stat().st_mtime_ns
        except OSError:
            return False
        unchanged = (
            source == _POLICY_SOURCE_PATH
            and int(mtime_ns) == int(_POLICY_SOURCE_MTIME_NS)
        )
        if unchanged and not force:
            return False

        loaded = _validate_and_normalize_policy(_load_policy())
        effective = _resolve_effective_policy(loaded, AGENT_ID)
        _apply_runtime_policy(effective)
        _POLICY_SOURCE_PATH = source
        _POLICY_SOURCE_MTIME_NS = int(mtime_ns)
        return True
