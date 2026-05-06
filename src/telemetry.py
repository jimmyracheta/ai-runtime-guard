import datetime
import json
import os
import pathlib
import re
import sqlite3
import sys
import threading
import urllib.error
import urllib.request
from contextlib import closing
from importlib.metadata import PackageNotFoundError, version as package_version
from typing import Any

import agent_configs
import reports

DEFAULT_ENDPOINT = "https://telemetry.runtime-guard.ai/v1/telemetry"
REQUEST_TIMEOUT_SECONDS = 5
OUTBOX_DIR_NAME = "telemetry"
SCHEDULER_INTERVAL_SECONDS = 3600
_VERSION_ALLOWED_RE = re.compile(r"[^0-9A-Za-z.\-+]+")
_VERSION_VALIDATE_RE = re.compile(r"^[0-9A-Za-z.\-+]+$")
_BUCKET_VALUES = {"0", "1", "2-5", "6-10", "11-50", "51-100", "101-1000", "1000+"}
_AGENT_TYPES_ALLOWED = {"claude_code", "cursor", "codex", "windsurf", "cline", "aider", "other"}
_INSTALL_METHOD_ALLOWED = {"pip", "pipx", "editable", "docker", "unknown"}
_PLATFORM_ALLOWED = {"linux", "macos", "windows", "unknown"}

_STATUS_LOCK = threading.Lock()
_SERVICE_STATUS: dict[str, dict[str, str]] = {
    "generator": {"status": "starting", "last_run": ""},
    "uploader": {"status": "starting", "last_run": ""},
}


def _debug(message: str) -> None:
    if os.environ.get("AIRG_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}:
        print(f"[airg][telemetry][debug] {message}", file=sys.stderr)


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _utc_today(now: datetime.datetime | None = None) -> str:
    current = now or _utc_now()
    return current.strftime("%Y-%m-%d")


def _utc_iso(now: datetime.datetime | None = None) -> str:
    current = now or _utc_now()
    return current.isoformat().replace("+00:00", "Z")


def _set_service_status(service: str, status: str, *, now: datetime.datetime | None = None) -> None:
    with _STATUS_LOCK:
        _SERVICE_STATUS[service] = {
            "status": status,
            "last_run": _utc_iso(now),
        }


def service_status() -> dict[str, dict[str, str]]:
    with _STATUS_LOCK:
        return {
            "generator": dict(_SERVICE_STATUS.get("generator", {"status": "unknown", "last_run": ""})),
            "uploader": dict(_SERVICE_STATUS.get("uploader", {"status": "unknown", "last_run": ""})),
        }


def _append_info_log(log_path: pathlib.Path, event: str, **fields: Any) -> None:
    entry = {
        "timestamp": _utc_iso(),
        "source": "mcp-server",
        "tool": "telemetry",
        "event": event,
        "policy_decision": "allowed",
        "decision_tier": "allowed",
    }
    entry.update(fields)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        _debug(f"failed to append telemetry info log: {exc}")


def bucket(value: int) -> str:
    n = max(0, int(value))
    if n == 0:
        return "0"
    if n == 1:
        return "1"
    if n <= 5:
        return "2-5"
    if n <= 10:
        return "6-10"
    if n <= 50:
        return "11-50"
    if n <= 100:
        return "51-100"
    if n <= 1000:
        return "101-1000"
    return "1000+"


def _sanitize_version(raw: str, *, max_len: int) -> str:
    cleaned = _VERSION_ALLOWED_RE.sub("", str(raw or ""))[:max_len]
    if cleaned and _VERSION_VALIDATE_RE.fullmatch(cleaned):
        return cleaned
    return "unknown"


def _airg_version() -> str:
    try:
        raw = package_version("ai-runtime-guard")
    except PackageNotFoundError:
        raw = "unknown"
    return _sanitize_version(raw, max_len=32)


def _platform_string(system_name: str | None = None) -> str:
    if system_name is None:
        import platform as _platform

        system = _platform.system().lower()
    else:
        system = str(system_name).lower()
    if system == "darwin":
        return "macos"
    if system == "linux":
        return "linux"
    if system == "windows":
        return "windows"
    return "unknown"


def _python_version() -> str:
    raw = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"[:16]
    if raw and _VERSION_VALIDATE_RE.fullmatch(raw):
        return raw
    return "unknown"


def _normalize_agent_type(agent_type: str) -> str:
    normalized = str(agent_type or "").strip().lower()
    mapped = {
        "claude_code": "claude_code",
        "claude_desktop": "claude_code",
        "cursor": "cursor",
        "codex": "codex",
        "windsurf": "windsurf",
        "cline": "cline",
        "aider": "aider",
        "custom": "other",
    }.get(normalized, "other")
    return mapped if mapped in _AGENT_TYPES_ALLOWED else "other"


def normalize_agent_types(agent_types: list[str]) -> list[str]:
    values = sorted({_normalize_agent_type(item) for item in (agent_types or [])})
    return values[:16]


def _load_policy(policy_path: pathlib.Path) -> dict[str, Any]:
    try:
        payload = json.loads(policy_path.read_text())
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _save_policy(policy_path: pathlib.Path, policy: dict[str, Any]) -> None:
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = policy_path.with_suffix(f"{policy_path.suffix}.tmp")
    tmp.write_text(json.dumps(policy, indent=2) + "\n")
    tmp.replace(policy_path)


def _telemetry_section(policy: dict[str, Any]) -> dict[str, Any]:
    section = policy.get("telemetry")
    if not isinstance(section, dict):
        section = {}
    return section


def _telemetry_enabled(policy: dict[str, Any]) -> bool:
    return bool(_telemetry_section(policy).get("enabled", True))


def _telemetry_endpoint(policy: dict[str, Any]) -> str:
    configured = str(_telemetry_section(policy).get("endpoint", "")).strip()
    return configured or DEFAULT_ENDPOINT


def _last_payload_generated_date(policy: dict[str, Any]) -> str:
    return str(_telemetry_section(policy).get("last_payload_generated_date", "")).strip()


def _ensure_telemetry_defaults(policy: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    section = _telemetry_section(policy)
    updated = dict(section)
    changed = False

    if "enabled" not in updated:
        updated["enabled"] = True
        changed = True

    endpoint = str(updated.get("endpoint", "")).strip()
    if not endpoint:
        updated["endpoint"] = DEFAULT_ENDPOINT
        changed = True

    for key in ["last_payload_generated_date", "last_payload_uploaded_at", "last_sent_date"]:
        value = updated.get(key, "")
        if not isinstance(value, str):
            updated[key] = str(value).strip()
            changed = True
        elif key not in updated:
            updated[key] = ""
            changed = True

    if changed:
        normalized = dict(policy)
        normalized["telemetry"] = updated
        return normalized, True
    return policy, False


def _update_telemetry_fields(policy_path: pathlib.Path, **updates: str) -> None:
    policy = _load_policy(policy_path)
    policy, _ = _ensure_telemetry_defaults(policy)
    telemetry = dict(_telemetry_section(policy))
    for key, value in updates.items():
        telemetry[key] = str(value or "")
    policy = dict(policy)
    policy["telemetry"] = telemetry
    _save_policy(policy_path, policy)


def _ensure_telemetry_defaults(policy: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    section = _telemetry_section(policy)
    updated = dict(section)
    changed = False

    if "enabled" not in updated:
        updated["enabled"] = True
        changed = True

    endpoint = str(updated.get("endpoint", "")).strip()
    if not endpoint:
        updated["endpoint"] = DEFAULT_ENDPOINT
        changed = True

    last_sent = updated.get("last_sent_date", "")
    if not isinstance(last_sent, str):
        updated["last_sent_date"] = str(last_sent).strip()
        changed = True
    elif "last_sent_date" not in updated:
        updated["last_sent_date"] = ""
        changed = True

    if changed:
        normalized = dict(policy)
        normalized["telemetry"] = updated
        return normalized, True
    return policy, False


def _load_profiles(approval_db_path: pathlib.Path) -> list[dict[str, Any]]:
    try:
        registry = agent_configs.load_registry({"approval_db_path": approval_db_path})
    except Exception:
        return []
    profiles = registry.get("profiles") if isinstance(registry, dict) else []
    return [row for row in profiles if isinstance(row, dict)] if isinstance(profiles, list) else []


def _sync_reports(policy: dict[str, Any], reports_db_path: pathlib.Path, log_path: pathlib.Path) -> None:
    try:
        reports.sync_from_log(
            db_path=reports_db_path,
            log_path=log_path,
            policy_reports=policy.get("reports", {}) if isinstance(policy, dict) else {},
        )
    except Exception as exc:
        _debug(f"reports sync failed: {exc}")


def _window_counts(reports_db_path: pathlib.Path, now: datetime.datetime | None = None) -> dict[str, int]:
    cutoff = (now or _utc_now()) - datetime.timedelta(days=1)
    cutoff_iso = cutoff.isoformat().replace("+00:00", "Z")

    with closing(sqlite3.connect(reports_db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT
              COUNT(*) AS total_events,
              SUM(CASE WHEN policy_decision='blocked' THEN 1 ELSE 0 END) AS blocked_events,
              SUM(CASE WHEN tool='approve_command' AND event='command_approved' THEN 1 ELSE 0 END) AS approvals_approved,
              SUM(CASE WHEN event='script_sentinel_execute_checked' THEN 1 ELSE 0 END) AS sentinel_flagged,
              SUM(CASE WHEN event='script_sentinel_blocked' THEN 1 ELSE 0 END) AS sentinel_blocked
            FROM events
            WHERE timestamp >= ?
            """,
            (cutoff_iso,),
        ).fetchone()

    if row is None:
        return {
            "total_events": 0,
            "blocked_events": 0,
            "approvals_approved": 0,
            "sentinel_flagged": 0,
            "sentinel_blocked": 0,
        }
    return {
        "total_events": int(row["total_events"] or 0),
        "blocked_events": int(row["blocked_events"] or 0),
        "approvals_approved": int(row["approvals_approved"] or 0),
        "sentinel_flagged": int(row["sentinel_flagged"] or 0),
        "sentinel_blocked": int(row["sentinel_blocked"] or 0),
    }


def build_payload(
    *,
    policy: dict[str, Any],
    reports_db_path: pathlib.Path,
    approval_db_path: pathlib.Path,
    log_path: pathlib.Path,
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    _sync_reports(policy, reports_db_path, log_path)
    counts = _window_counts(reports_db_path, now=now)
    profiles = _load_profiles(approval_db_path)
    agent_types = normalize_agent_types([str(row.get("agent_type", "")) for row in profiles])

    sentinel_policy = policy.get("script_sentinel") if isinstance(policy.get("script_sentinel"), dict) else {}
    payload = {
        "airg_version": _airg_version(),
        "platform": _platform_string(),
        "python_version": _python_version(),
        "install_method": "unknown",
        "agents_bucket": bucket(len(profiles)),
        "agent_types": agent_types,
        "events_bucket": bucket(counts["total_events"]),
        "blocked_bucket": bucket(counts["blocked_events"]),
        "approvals_bucket": bucket(counts["approvals_approved"]),
        "sentinel_enabled": bool(sentinel_policy.get("enabled", False)),
        "sentinel_flagged_bucket": bucket(counts["sentinel_flagged"]),
        "sentinel_blocked_bucket": bucket(counts["sentinel_blocked"]),
        "period_days": 1,
    }
    validate_payload(payload)
    return payload


def validate_payload(payload: dict[str, Any]) -> None:
    required_string_keys = [
        "airg_version",
        "platform",
        "python_version",
        "install_method",
        "agents_bucket",
        "events_bucket",
        "blocked_bucket",
        "approvals_bucket",
        "sentinel_flagged_bucket",
        "sentinel_blocked_bucket",
    ]
    for key in required_string_keys:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"telemetry payload field '{key}' must be a non-empty string")

    if payload["platform"] not in _PLATFORM_ALLOWED:
        raise ValueError("telemetry payload field 'platform' is invalid")
    if payload["install_method"] not in _INSTALL_METHOD_ALLOWED:
        raise ValueError("telemetry payload field 'install_method' is invalid")

    for key in ["agents_bucket", "events_bucket", "blocked_bucket", "approvals_bucket", "sentinel_flagged_bucket", "sentinel_blocked_bucket"]:
        if payload.get(key) not in _BUCKET_VALUES:
            raise ValueError(f"telemetry payload field '{key}' is invalid")

    agent_types = payload.get("agent_types")
    if not isinstance(agent_types, list) or len(agent_types) > 16:
        raise ValueError("telemetry payload field 'agent_types' is invalid")
    if any((not isinstance(item, str) or item not in _AGENT_TYPES_ALLOWED) for item in agent_types):
        raise ValueError("telemetry payload field 'agent_types' contains invalid entries")

    sentinel_enabled = payload.get("sentinel_enabled")
    if not isinstance(sentinel_enabled, bool):
        raise ValueError("telemetry payload field 'sentinel_enabled' must be bool")

    period_days = payload.get("period_days")
    if not isinstance(period_days, int) or period_days < 1 or period_days > 30:
        raise ValueError("telemetry payload field 'period_days' must be int in [1,30]")

    airg_version = str(payload.get("airg_version", ""))
    python_version = str(payload.get("python_version", ""))
    if len(airg_version) > 32 or not _VERSION_VALIDATE_RE.fullmatch(airg_version):
        raise ValueError("telemetry payload field 'airg_version' is invalid")
    if len(python_version) > 16 or not _VERSION_VALIDATE_RE.fullmatch(python_version):
        raise ValueError("telemetry payload field 'python_version' is invalid")


def build_payload_from_paths(
    *,
    policy_path: pathlib.Path,
    reports_db_path: pathlib.Path,
    approval_db_path: pathlib.Path,
    log_path: pathlib.Path,
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    policy = _load_policy(policy_path)
    return build_payload(
        policy=policy,
        reports_db_path=reports_db_path,
        approval_db_path=approval_db_path,
        log_path=log_path,
        now=now,
    )


def _outbox_dir(approval_db_path: pathlib.Path) -> pathlib.Path:
    return approval_db_path.expanduser().resolve().parent / OUTBOX_DIR_NAME


def _payload_file_path(approval_db_path: pathlib.Path, day: str) -> pathlib.Path:
    return _outbox_dir(approval_db_path) / f"telemetry-{day}.json"


def _send_once(endpoint: str, payload: dict[str, Any], timeout_seconds: int) -> int | None:
    body = json.dumps(payload).encode("utf-8")
    user_agent = f"ai-runtime-guard/{payload.get('airg_version', 'unknown')}"
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": user_agent,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status = int(getattr(response, "status", 0))
            if status != 204:
                _debug(f"telemetry send returned status={status}")
            return status
    except urllib.error.HTTPError as exc:
        _debug(f"telemetry send failed with HTTP {exc.code}")
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        _debug(f"telemetry send failed: {exc}")
        return None


def run_generator_once(
    *,
    policy_path: pathlib.Path,
    reports_db_path: pathlib.Path,
    approval_db_path: pathlib.Path,
    log_path: pathlib.Path,
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    current = now or _utc_now()
    _set_service_status("generator", "running", now=current)

    policy = _load_policy(policy_path)
    policy, changed = _ensure_telemetry_defaults(policy)
    if changed:
        _save_policy(policy_path, policy)

    if not _telemetry_enabled(policy):
        _set_service_status("generator", "stand_down_disabled", now=current)
        _append_info_log(log_path, "telemetry_generator_stand_down", reason="disabled")
        return {"status": "stand_down_disabled"}

    today = _utc_today(current)
    if _last_payload_generated_date(policy) == today:
        _set_service_status("generator", "stand_down_same_day", now=current)
        _append_info_log(log_path, "telemetry_generator_stand_down", reason="same_day", day=today)
        return {"status": "stand_down_same_day", "day": today}

    payload = build_payload(
        policy=policy,
        reports_db_path=reports_db_path,
        approval_db_path=approval_db_path,
        log_path=log_path,
        now=current,
    )
    out_path = _payload_file_path(approval_db_path, today)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    _update_telemetry_fields(policy_path, last_payload_generated_date=today)
    _set_service_status("generator", "generated", now=current)
    _append_info_log(log_path, "telemetry_payload_generated", path=str(out_path), day=today)
    return {"status": "generated", "day": today, "path": str(out_path)}


def run_uploader_once(
    *,
    policy_path: pathlib.Path,
    approval_db_path: pathlib.Path,
    log_path: pathlib.Path,
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    current = now or _utc_now()
    _set_service_status("uploader", "running", now=current)

    policy = _load_policy(policy_path)
    policy, changed = _ensure_telemetry_defaults(policy)
    if changed:
        _save_policy(policy_path, policy)

    if not _telemetry_enabled(policy):
        _set_service_status("uploader", "stand_down_disabled", now=current)
        _append_info_log(log_path, "telemetry_uploader_stand_down", reason="disabled")
        return {"status": "stand_down_disabled"}

    endpoint = _telemetry_endpoint(policy)
    out_dir = _outbox_dir(approval_db_path)
    payload_files = sorted(out_dir.glob("telemetry-*.json")) if out_dir.exists() else []

    if not payload_files:
        _set_service_status("uploader", "stand_down_empty", now=current)
        _append_info_log(log_path, "telemetry_uploader_stand_down", reason="empty_outbox")
        return {"status": "stand_down_empty", "uploaded": 0}

    uploaded = 0
    failures = 0
    for payload_path in payload_files:
        try:
            payload = json.loads(payload_path.read_text(encoding="utf-8"))
            _append_info_log(log_path, "telemetry_upload_attempted", path=str(payload_path), endpoint=endpoint)
            status = _send_once(endpoint, payload, REQUEST_TIMEOUT_SECONDS)
            if status == 204:
                uploaded += 1
                _append_info_log(log_path, "telemetry_upload_succeeded", path=str(payload_path), http_status=204)
                payload_path.unlink(missing_ok=True)
                _update_telemetry_fields(
                    policy_path,
                    last_payload_uploaded_at=_utc_iso(current),
                    last_sent_date=_utc_today(current),
                )
            else:
                failures += 1
                _append_info_log(
                    log_path,
                    "telemetry_upload_failed",
                    path=str(payload_path),
                    http_status=int(status or 0),
                )
        except Exception as exc:
            failures += 1
            _append_info_log(log_path, "telemetry_upload_failed", path=str(payload_path), error=str(exc))

    if failures:
        _set_service_status("uploader", "failed", now=current)
        return {"status": "failed", "uploaded": uploaded, "failed": failures}

    _set_service_status("uploader", "uploaded", now=current)
    return {"status": "uploaded", "uploaded": uploaded, "failed": 0}


def maybe_send_daily(
    *,
    policy_path: pathlib.Path,
    reports_db_path: pathlib.Path,
    approval_db_path: pathlib.Path,
    log_path: pathlib.Path,
    now: datetime.datetime | None = None,
) -> bool:
    # Backward-compatible wrapper for callers/tests expecting a bool.
    generated = run_generator_once(
        policy_path=policy_path,
        reports_db_path=reports_db_path,
        approval_db_path=approval_db_path,
        log_path=log_path,
        now=now,
    )
    run_uploader_once(
        policy_path=policy_path,
        approval_db_path=approval_db_path,
        log_path=log_path,
        now=now,
    )
    return generated.get("status") == "generated"
