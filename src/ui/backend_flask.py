import json
import os
import pathlib
import stat
import sys
import secrets
import threading
import time
from urllib.parse import urlparse
from datetime import datetime, UTC, timedelta

from flask import Flask, jsonify, request, send_from_directory

import approvals
import agent_configs
import agent_configurator
import agent_posture
import config
import mcp_config_manager
import reports
import script_sentinel
import telemetry
from audit import append_log_entry, build_operator_log_entry
from ui import service

# Shared paths used by MCP server and control-plane backend.
BASE_DIR = pathlib.Path(config.BASE_DIR)
POLICY_PATH = pathlib.Path(os.environ.get("AIRG_POLICY_PATH", str(BASE_DIR / "policy.json")))
APPROVAL_DB_PATH = pathlib.Path(os.environ.get("AIRG_APPROVAL_DB_PATH", str(BASE_DIR / "approvals.db")))
REPORTS_DB_PATH = pathlib.Path(
    os.environ.get(
        "AIRG_REPORTS_DB_PATH",
        str(APPROVAL_DB_PATH.with_name("reports.db")),
    )
).expanduser().resolve()
CATALOG_PATH = pathlib.Path(os.environ.get("AIRG_CATALOG_PATH", str(pathlib.Path(__file__).resolve().parent / "catalog.json")))
WORKSPACE_PATH = pathlib.Path(os.environ.get("AIRG_WORKSPACE", str(config.WORKSPACE_ROOT)))


def _candidate_ui_dist_paths() -> list[pathlib.Path]:
    env_ui_dist = os.environ.get("AIRG_UI_DIST_PATH", "").strip()
    candidates: list[pathlib.Path] = []
    if env_ui_dist:
        candidates.append(pathlib.Path(env_ui_dist).expanduser())
    candidates.extend(
        [
            BASE_DIR / "ui_v3" / "dist",
            pathlib.Path(sys.prefix) / "ui_v3" / "dist",
            pathlib.Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages" / "ui_v3" / "dist",
        ]
    )
    return candidates


def _resolve_ui_dist_path() -> pathlib.Path:
    for candidate in _candidate_ui_dist_paths():
        resolved = candidate.expanduser()
        if (resolved / "index.html").exists():
            return resolved.resolve()
    return (BASE_DIR / "ui_v3" / "dist").resolve()


UI_DIST_PATH = _resolve_ui_dist_path()

service.POLICY_PATH = POLICY_PATH
service.CATALOG_PATH = CATALOG_PATH
approvals.APPROVAL_DB_PATH = APPROVAL_DB_PATH
approvals.init_approval_store()
reports.init_reports_store(REPORTS_DB_PATH)

app = Flask(__name__)
UI_API_TOKEN_PATH = POLICY_PATH.parent / "ui_api_token"
UI_API_TOKEN_HEADER = "X-AIRG-UI-TOKEN"


def _load_or_create_ui_api_token() -> str:
    UI_API_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    if UI_API_TOKEN_PATH.exists():
        token = UI_API_TOKEN_PATH.read_text(encoding="utf-8").strip()
        if token:
            return token
    token = secrets.token_hex(24)
    UI_API_TOKEN_PATH.write_text(token, encoding="utf-8")
    try:
        os.chmod(UI_API_TOKEN_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return token


UI_API_TOKEN = _load_or_create_ui_api_token()
_TELEMETRY_TICKER_LOCK = threading.Lock()
_TELEMETRY_TICKER_STARTED = False
_TELEMETRY_INTERVAL_SECONDS = telemetry.SCHEDULER_INTERVAL_SECONDS
_TELEMETRY_ACTIVE_RUN_LOCK = threading.Lock()


def _telemetry_log_path() -> pathlib.Path:
    return pathlib.Path(os.environ.get("AIRG_LOG_PATH", config.LOG_PATH)).expanduser().resolve()


def _run_telemetry_workers_once() -> None:
    if not _TELEMETRY_ACTIVE_RUN_LOCK.acquire(blocking=False):
        return
    try:
        now = datetime.now(UTC)

        def _run_generator() -> None:
            telemetry.run_generator_once(
                policy_path=POLICY_PATH,
                reports_db_path=REPORTS_DB_PATH,
                approval_db_path=APPROVAL_DB_PATH,
                log_path=_telemetry_log_path(),
                now=now,
            )

        def _run_uploader() -> None:
            telemetry.run_uploader_once(
                policy_path=POLICY_PATH,
                approval_db_path=APPROVAL_DB_PATH,
                log_path=_telemetry_log_path(),
                now=now,
            )

        generator_thread = threading.Thread(target=_run_generator, daemon=True, name="airg-telemetry-generator")
        uploader_thread = threading.Thread(target=_run_uploader, daemon=True, name="airg-telemetry-uploader")
        generator_thread.start()
        uploader_thread.start()
        generator_thread.join()
        uploader_thread.join()
    finally:
        _TELEMETRY_ACTIVE_RUN_LOCK.release()


def _start_telemetry_scheduler() -> None:
    global _TELEMETRY_TICKER_STARTED
    with _TELEMETRY_TICKER_LOCK:
        if _TELEMETRY_TICKER_STARTED:
            return
        _TELEMETRY_TICKER_STARTED = True

    def _worker() -> None:
        while True:
            _run_telemetry_workers_once()
            time.sleep(_TELEMETRY_INTERVAL_SECONDS)

    threading.Thread(target=_worker, daemon=True, name="airg-telemetry-scheduler").start()


_run_telemetry_workers_once()
_start_telemetry_scheduler()


def _agent_paths() -> dict[str, pathlib.Path]:
    return {
        "policy_path": POLICY_PATH,
        "approval_db_path": APPROVAL_DB_PATH,
        "approval_hmac_key_path": pathlib.Path(
            os.environ.get("AIRG_APPROVAL_HMAC_KEY_PATH", f"{APPROVAL_DB_PATH}.hmac.key")
        ).expanduser().resolve(),
        "log_path": pathlib.Path(os.environ.get("AIRG_LOG_PATH", config.LOG_PATH)).expanduser().resolve(),
        "reports_db_path": REPORTS_DB_PATH,
    }


def _agent_profiles(paths: dict[str, pathlib.Path]) -> list[dict[str, object]]:
    registry = agent_configs.load_registry(paths)
    profiles = registry.get("profiles", []) if isinstance(registry, dict) else []
    return profiles if isinstance(profiles, list) else []


def _profile_by_id(profiles: list[dict[str, object]], profile_id: str) -> dict[str, object] | None:
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        if str(profile.get("profile_id", "")).strip() == profile_id:
            return profile
    return None


def _posture_summary_with_state(profiles: list[dict[str, object]], paths: dict[str, pathlib.Path]) -> dict[str, object]:
    summary = agent_posture.build_posture_summary(profiles if isinstance(profiles, list) else [])
    rows = summary.get("profiles", []) if isinstance(summary, dict) else []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            profile_id = str(row.get("profile_id", "")).strip()
            row["undo_available"] = bool(profile_id) and agent_configurator.undo_available(paths, profile_id)
    return summary


def _runtime_env_file_path() -> pathlib.Path:
    return POLICY_PATH.parent / "runtime.env"


def _write_runtime_env_for_profile(profile: dict[str, object]) -> pathlib.Path:
    workspace = str(profile.get("workspace", "")).strip()
    agent_id = str(profile.get("agent_id", "")).strip() or "default"
    env = {
        "AIRG_AGENT_ID": agent_id,
        "AIRG_WORKSPACE": workspace,
        "AIRG_POLICY_PATH": str(POLICY_PATH),
        "AIRG_APPROVAL_DB_PATH": str(APPROVAL_DB_PATH),
        "AIRG_APPROVAL_HMAC_KEY_PATH": str(
            pathlib.Path(os.environ.get("AIRG_APPROVAL_HMAC_KEY_PATH", f"{APPROVAL_DB_PATH}.hmac.key")).expanduser().resolve()
        ),
        "AIRG_LOG_PATH": str(pathlib.Path(os.environ.get("AIRG_LOG_PATH", config.LOG_PATH)).expanduser().resolve()),
        "AIRG_REPORTS_DB_PATH": str(REPORTS_DB_PATH),
        "AIRG_UI_DIST_PATH": str(UI_DIST_PATH),
        "AIRG_SERVER_COMMAND": str(os.environ.get("AIRG_SERVER_COMMAND", "")).strip(),
    }
    out = _runtime_env_file_path()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(f'{k}="{v}"\n' for k, v in sorted(env.items())))
    try:
        os.chmod(out, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return out


def _is_local_host(host: str) -> bool:
    host_name = str(host or "").split(":", 1)[0].lower()
    return host_name in {"localhost", "127.0.0.1"}


def _is_local_origin(origin: str) -> bool:
    if not origin:
        return False
    parsed = urlparse(origin)
    if parsed.scheme != "http":
        return False
    return _is_local_host(parsed.netloc)


def _origin_matches_host(origin_or_referer: str, request_host: str) -> bool:
    if not origin_or_referer:
        return False
    parsed = urlparse(origin_or_referer)
    if parsed.scheme != "http":
        return False
    return parsed.netloc == request_host and _is_local_host(parsed.netloc)


@app.before_request
def request_security_guard():
    if not _is_local_host(request.host):
        return jsonify({"error": "Host not allowed"}), 403

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        token = str(request.headers.get(UI_API_TOKEN_HEADER, "")).strip()
        auth = str(request.headers.get("Authorization", "")).strip()
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        if token and secrets.compare_digest(token, UI_API_TOKEN):
            return None

        origin = str(request.headers.get("Origin", "")).strip()
        referer = str(request.headers.get("Referer", "")).strip()
        if _origin_matches_host(origin, request.host) or _origin_matches_host(referer, request.host):
            return None
        return jsonify({"error": "Authentication required for mutating API call"}), 401


@app.after_request
def add_cors_headers(resp):
    # Restrict dev CORS to localhost origins so local frontend can call API.
    origin = request.headers.get("Origin", "")
    if origin and _is_local_origin(origin) and _origin_matches_host(origin, request.host):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Headers"] = f"Content-Type, X-Actor, {UI_API_TOKEN_HEADER}, Authorization"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    else:
        resp.headers.pop("Access-Control-Allow-Origin", None)
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/policy", methods=["GET", "OPTIONS"])
def get_policy():
    if request.method == "OPTIONS":
        return ("", 204)
    if not POLICY_PATH.exists():
        return jsonify({"error": "policy.json not found"}), 404
    try:
        policy = service.load_policy()
        base_catalog = service.load_catalog()
        catalog = service.merged_catalog(policy, base_catalog)
    except json.JSONDecodeError:
        return jsonify({"error": "policy.json contains invalid JSON"}), 400
    all_commands = service.all_known_commands(policy, catalog)
    return jsonify(
        {
            "policy": policy,
            "hash": service.policy_hash(policy),
            "valid": service.validate_policy(policy)[0],
            "has_revert_snapshot": service.has_last_applied_snapshot(POLICY_PATH),
            "has_default_snapshot": service.has_default_snapshot(POLICY_PATH),
            "tier_map": service.command_tier_map(policy),
            "all_commands": all_commands,
            "descriptions": service.command_descriptions(catalog),
            "contexts": service.command_context_map(catalog, all_commands),
            "tabs": service.visible_tabs(catalog),
            "tab_commands": service.tab_command_map(catalog),
            "runtime_paths": {
                "AIRG_WORKSPACE": str(WORKSPACE_PATH),
                "AIRG_AGENT_ID": str(os.environ.get("AIRG_AGENT_ID", "default")),
                "AIRG_POLICY_PATH": str(POLICY_PATH),
                "AIRG_APPROVAL_DB_PATH": str(APPROVAL_DB_PATH),
                "AIRG_APPROVAL_HMAC_KEY_PATH": str(
                    pathlib.Path(os.environ.get("AIRG_APPROVAL_HMAC_KEY_PATH", f"{APPROVAL_DB_PATH}.hmac.key"))
                ),
                "AIRG_LOG_PATH": str(pathlib.Path(os.environ.get("AIRG_LOG_PATH", config.LOG_PATH))),
                "AIRG_REPORTS_DB_PATH": str(REPORTS_DB_PATH),
                "AIRG_UI_DIST_PATH": str(UI_DIST_PATH),
            },
            "ui_auth": {
                "token_header": UI_API_TOKEN_HEADER,
                "auth_mode": "token_or_same_origin",
            },
        }
    )


def _reports_sync() -> dict:
    policy = service.load_policy()
    return reports.sync_from_log(
        db_path=REPORTS_DB_PATH,
        log_path=pathlib.Path(os.environ.get("AIRG_LOG_PATH", config.LOG_PATH)).expanduser().resolve(),
        policy_reports=policy.get("reports", {}),
    )


def _report_filters() -> dict[str, str]:
    out: dict[str, str] = {}
    for key in [
        "agent_id",
        "agent_session_id",
        "source",
        "tool",
        "policy_decision",
        "decision_tier",
        "matched_rule",
        "command",
        "path",
        "event",
        "from",
        "to",
    ]:
        val = request.args.get(key, "").strip()
        if val:
            out[key] = val
    return out


def _should_sync_reports() -> bool:
    raw = request.args.get("sync", "").strip().lower()
    return raw in {"1", "true", "yes"}


@app.route("/reports/status", methods=["GET", "OPTIONS"])
def reports_status():
    if request.method == "OPTIONS":
        return ("", 204)
    sync = _reports_sync() if _should_sync_reports() else {"enabled": True, "ingested": 0, "skipped": True}
    status = reports.get_status(REPORTS_DB_PATH)
    status["sync"] = sync
    status["enabled"] = bool(service.load_policy().get("reports", {}).get("enabled", True))
    return jsonify(status)


@app.route("/reports/overview", methods=["GET", "OPTIONS"])
def reports_overview():
    if request.method == "OPTIONS":
        return ("", 204)
    if _should_sync_reports():
        _reports_sync()
    data = reports.get_overview(REPORTS_DB_PATH, filters=_report_filters())
    return jsonify(data)


@app.route("/reports/events", methods=["GET", "OPTIONS"])
def reports_events():
    if request.method == "OPTIONS":
        return ("", 204)
    if _should_sync_reports():
        _reports_sync()
    limit = int(request.args.get("limit", "100"))
    offset = int(request.args.get("offset", "0"))
    data = reports.list_events(
        REPORTS_DB_PATH,
        filters=_report_filters(),
        limit=limit,
        offset=offset,
    )
    return jsonify(data)


@app.route("/reports/top-commands", methods=["GET", "OPTIONS"])
def reports_top_commands():
    if request.method == "OPTIONS":
        return ("", 204)
    if _should_sync_reports():
        _reports_sync()
    data = reports.get_overview(REPORTS_DB_PATH, filters=_report_filters())
    return jsonify({"top_commands": data.get("top_commands", [])})


@app.route("/reports/top-paths", methods=["GET", "OPTIONS"])
def reports_top_paths():
    if request.method == "OPTIONS":
        return ("", 204)
    if _should_sync_reports():
        _reports_sync()
    data = reports.get_overview(REPORTS_DB_PATH, filters=_report_filters())
    return jsonify({"top_paths": data.get("top_paths", [])})


@app.route("/reports/blocked-by-rule", methods=["GET", "OPTIONS"])
def reports_blocked_by_rule():
    if request.method == "OPTIONS":
        return ("", 204)
    if _should_sync_reports():
        _reports_sync()
    data = reports.get_overview(REPORTS_DB_PATH, filters=_report_filters())
    return jsonify({"blocked_by_rule": data.get("blocked_by_rule", [])})


@app.route("/reports/confirmations", methods=["GET", "OPTIONS"])
def reports_confirmations():
    if request.method == "OPTIONS":
        return ("", 204)
    if _should_sync_reports():
        _reports_sync()
    data = reports.get_overview(REPORTS_DB_PATH, filters=_report_filters())
    totals = data.get("totals", {})
    return jsonify(
        {
            "confirmations": {
                "approved": totals.get("approvals_approved", 0),
                "denied": totals.get("approvals_denied", 0),
            }
        }
    )


@app.route("/policy/validate", methods=["POST", "OPTIONS"])
def validate_policy():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    candidate = payload.get("policy")
    if not isinstance(candidate, dict):
        return jsonify({"valid": False, "error": "Expected JSON payload with 'policy' object"}), 400
    ok, details = service.validate_policy(candidate)
    if not ok:
        return jsonify({"valid": False, "error": details["errors"][0]}), 400
    return jsonify({"valid": True})


@app.route("/policy/apply", methods=["POST", "OPTIONS"])
def apply_policy():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    candidate = payload.get("policy")
    if not isinstance(candidate, dict):
        return jsonify({"error": "Expected JSON payload with 'policy' object"}), 400
    actor = request.headers.get("X-Actor", "flask-ui")
    ok, details = service.validate_and_apply(candidate, actor=actor)
    if not ok:
        return jsonify({"error": details["errors"][0]}), 400
    return jsonify({"applied": True, "hash": details["hash"], "diff": details["diff"]})


@app.route("/policy/revert-last", methods=["POST", "OPTIONS"])
def revert_last_policy():
    if request.method == "OPTIONS":
        return ("", 204)
    actor = request.headers.get("X-Actor", "flask-ui")
    ok, details = service.revert_last_applied(actor=actor)
    if not ok:
        error = details.get("errors", ["Revert failed"])[0]
        status = 404 if "not found" in error.lower() else 400
        return jsonify({"error": error}), status
    return jsonify({"applied": True, "hash": details["hash"], "diff": details["diff"]})


@app.route("/policy/reset-defaults", methods=["POST", "OPTIONS"])
def reset_policy_defaults():
    if request.method == "OPTIONS":
        return ("", 204)
    actor = request.headers.get("X-Actor", "flask-ui")
    ok, details = service.reset_to_defaults(actor=actor)
    if not ok:
        error = details.get("errors", ["Reset failed"])[0]
        status = 404 if "not found" in error.lower() else 400
        return jsonify({"error": error}), status
    return jsonify({"applied": True, "hash": details["hash"], "diff": details["diff"]})


@app.route("/approvals/pending", methods=["GET", "OPTIONS"])
def pending_approvals():
    if request.method == "OPTIONS":
        return ("", 204)
    items = approvals.list_pending_approvals()
    now = datetime.now(UTC)
    # Precompute countdown in API response to keep UI rendering simple.
    for item in items:
        try:
            expires = datetime.fromisoformat(item["expires_at"].replace("Z", "+00:00"))
            item["seconds_remaining"] = max(int((expires - now).total_seconds()), 0)
        except Exception:
            item["seconds_remaining"] = 0
    return jsonify({"pending": items, "count": len(items)})


@app.route("/approvals/history", methods=["GET", "OPTIONS"])
def approvals_history():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        limit = int(str(request.args.get("limit", "200")))
    except Exception:
        limit = 200
    items = approvals.list_approval_history(limit=limit)
    return jsonify({"history": items, "count": len(items)})


@app.route("/approvals/approve", methods=["POST", "OPTIONS"])
def approve_pending():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    token = str(payload.get("token", "")).strip()
    command = str(payload.get("command", "")).strip()
    approver = str(payload.get("approver") or request.headers.get("X-Actor") or "User").strip() or "User"
    approved_via = str(payload.get("approved_via") or "gui").strip() or "gui"
    if not token or not command:
        return jsonify({"error": "Expected {token, command}"}), 400
    pending = next((item for item in approvals.list_pending_approvals() if item["token"] == token), None)
    ok, reason, matched_rule = approvals.consume_command_approval(
        command,
        token,
        source="flask.approvals",
        approver=approver,
        approved_via=approved_via,
    )
    if not ok:
        status = 410 if matched_rule == "approval_token" else 403
        return jsonify({"approved": False, "error": reason, "matched_rule": matched_rule}), status
    append_log_entry(
        build_operator_log_entry(
            tool="approve_command",
            event="command_approved",
            session_id=(pending or {}).get("session_id", ""),
            policy_decision="allowed",
            decision_tier="allowed",
            command=command,
            approval_token=token,
            approved_via=approved_via,
            approver=approver,
        )
    )
    return jsonify({"approved": True, "message": "Approval accepted"})


@app.route("/approvals/deny", methods=["POST", "OPTIONS"])
def deny_pending():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    token = str(payload.get("token", "")).strip()
    approver = str(payload.get("approver") or request.headers.get("X-Actor") or "User").strip() or "User"
    approved_via = str(payload.get("approved_via") or "gui").strip() or "gui"
    if not token:
        return jsonify({"error": "Expected {token}"}), 400
    pending = next((item for item in approvals.list_pending_approvals() if item["token"] == token), None)
    ok, message = approvals.deny_command_approval(
        token,
        approver=approver,
        approved_via=approved_via,
        source="flask.approvals",
    )
    if not ok:
        return jsonify({"denied": False, "error": message}), 404
    append_log_entry(
        build_operator_log_entry(
            tool="approve_command",
            event="command_denied",
            session_id=(pending or {}).get("session_id", ""),
            policy_decision="blocked",
            decision_tier="blocked",
            command=(pending or {}).get("command", ""),
            approval_token=token,
            approved_via=approved_via,
            approver=approver,
        )
    )
    return jsonify({"denied": True, "message": message})


@app.route("/telemetry/payload-preview", methods=["GET", "OPTIONS"])
def telemetry_payload_preview():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        payload = telemetry.build_payload_from_paths(
            policy_path=POLICY_PATH,
            reports_db_path=REPORTS_DB_PATH,
            approval_db_path=APPROVAL_DB_PATH,
            log_path=pathlib.Path(os.environ.get("AIRG_LOG_PATH", config.LOG_PATH)).expanduser().resolve(),
        )
        return jsonify({"ok": True, "payload": payload})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/telemetry/service-status", methods=["GET", "OPTIONS"])
def telemetry_service_status():
    if request.method == "OPTIONS":
        return ("", 204)
    status = telemetry.service_status()
    now = datetime.now(UTC)
    generator_last_run = str(status.get("generator", {}).get("last_run", "")).strip()
    uploader_status = str(status.get("uploader", {}).get("status", "")).strip()

    generator_stale = False
    if generator_last_run:
        try:
            ts = datetime.fromisoformat(generator_last_run.replace("Z", "+00:00"))
            generator_stale = (now - ts) > timedelta(days=1)
        except ValueError:
            generator_stale = True

    warning = {
        "generator_stale": generator_stale,
        "uploader_failed": uploader_status == "failed",
    }
    warning["active"] = bool(warning["generator_stale"] or warning["uploader_failed"])
    return jsonify({"ok": True, "services": status, "warning": warning})


@app.route("/telemetry/service-restart", methods=["POST", "OPTIONS"])
def telemetry_service_restart():
    if request.method == "OPTIONS":
        return ("", 204)
    _run_telemetry_workers_once()
    status = telemetry.service_status()
    return jsonify({"ok": True, "services": status})


@app.route("/api/os-sandbox/status", methods=["GET", "OPTIONS"])
def api_os_sandbox_status():
    """Read-only GET: return AIRG OS-sandbox capability + posture summary.

    Side-effect-free. Protected by the existing localhost host-guard and CORS
    guards from request_security_guard / add_cors_headers.  Does NOT expose
    secrets or filesystem paths beyond what other status routes expose.
    """
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        posture = agent_posture.build_os_sandbox_posture()
        return jsonify({"ok": True, **posture})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/settings/agents", methods=["GET", "OPTIONS"])
def settings_agents():
    if request.method == "OPTIONS":
        return ("", 204)
    paths = _agent_paths()
    payload = agent_configs.list_profiles(paths)
    return jsonify(payload)


@app.route("/settings/agents/detect", methods=["GET", "OPTIONS"])
def settings_agents_detect():
    if request.method == "OPTIONS":
        return ("", 204)
    paths = _agent_paths()
    registry = agent_configs.load_registry(paths)
    profiles = registry.get("profiles", []) if isinstance(registry, dict) else []
    discovered = agent_posture.detect_unregistered_for_profiles(profiles if isinstance(profiles, list) else [])
    return jsonify(
        {
            "ok": True,
            "errors": [],
            "known_profiles": profiles,
            "discovered_unregistered": discovered,
        }
    )


@app.route("/settings/agents/posture", methods=["GET", "OPTIONS"])
def settings_agents_posture():
    if request.method == "OPTIONS":
        return ("", 204)
    paths = _agent_paths()
    try:
        profiles = _agent_profiles(paths)
        summary = _posture_summary_with_state(profiles, paths)
        return jsonify(summary)
    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": f"Failed to build agent posture: {exc}",
                "errors": [str(exc)],
                "profiles": [],
                "discovered_unregistered": [],
                "totals": {"green": 0, "yellow": 0, "red": 0},
            }
        ), 500


@app.route("/settings/agents/upsert", methods=["POST", "OPTIONS"])
def settings_agents_upsert():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    profile = payload.get("profile")
    create_workspace = bool(payload.get("create_workspace", False))
    if not isinstance(profile, dict):
        return jsonify({"ok": False, "errors": ["Expected JSON payload with 'profile' object"]}), 400
    paths = _agent_paths()
    result = agent_configs.upsert_profile(paths, profile, create_workspace=create_workspace)
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


@app.route("/settings/agents/delete", methods=["POST", "OPTIONS"])
def settings_agents_delete():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    profile_id = str(payload.get("profile_id", "")).strip()
    remove_mode = str(payload.get("remove_mode", "agent_only") or "agent_only").strip().lower()
    remove_codex_trust = bool(payload.get("remove_codex_trust", False))
    if not profile_id:
        return jsonify({"ok": False, "errors": ["profile_id is required"]}), 400
    paths = _agent_paths()
    profiles = _agent_profiles(paths)
    profile = _profile_by_id(profiles, profile_id)
    if not isinstance(profile, dict):
        return jsonify({"ok": False, "errors": ["Profile not found"]}), 404
    if remove_mode == "everything":
        removed = mcp_config_manager.remove_applied_mcp(paths, profile, remove_codex_trust=remove_codex_trust)
        if not removed.get("ok"):
            return jsonify(removed), 400
    elif remove_mode not in {"agent_only", "everything"}:
        return jsonify({"ok": False, "errors": ["Invalid remove_mode"]}), 400

    result = agent_configs.delete_profile(paths, profile_id)
    if not result.get("ok"):
        return jsonify(result), 404
    if remove_mode == "everything":
        result["cleanup"] = removed
    return jsonify(result)


@app.route("/settings/agents/generate", methods=["POST", "OPTIONS"])
def settings_agents_generate():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    profile_id = str(payload.get("profile_id", "")).strip()
    save_to_file = bool(payload.get("save_to_file", False))
    if not profile_id:
        return jsonify({"ok": False, "errors": ["profile_id is required"]}), 400
    paths = _agent_paths()
    result = agent_configs.generate_config(paths, profile_id, save_to_file=save_to_file)
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


@app.route("/settings/agents/open-file", methods=["GET", "OPTIONS"])
def settings_agents_open_file():
    if request.method == "OPTIONS":
        return ("", 204)
    profile_id = str(request.args.get("profile_id", "")).strip()
    if not profile_id:
        return jsonify({"ok": False, "errors": ["profile_id is required"]}), 400
    paths = _agent_paths()
    result = agent_configs.open_saved_file(paths, profile_id)
    if not result.get("ok"):
        return jsonify(result), 404
    return jsonify(result)


@app.route("/settings/agents/reconfigure-runtime", methods=["POST", "OPTIONS"])
def settings_agents_reconfigure_runtime():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    profile_id = str(payload.get("profile_id", "")).strip()
    if not profile_id:
        return jsonify({"ok": False, "errors": ["profile_id is required"]}), 400
    paths = _agent_paths()
    profiles = _agent_profiles(paths)
    profile = _profile_by_id(profiles, profile_id)
    if not isinstance(profile, dict):
        return jsonify({"ok": False, "errors": ["Profile not found"]}), 404
    if profile_id != "default-agent":
        return jsonify(
            {
                "ok": True,
                "runtime_env_updated": False,
                "restart_required": False,
                "message": "Runtime reconfigure applies only to default-agent profile.",
            }
        )
    runtime_env = _write_runtime_env_for_profile(profile)
    return jsonify(
        {
            "ok": True,
            "runtime_env_updated": True,
            "runtime_env_path": str(runtime_env),
            "restart_required": True,
            "message": "Runtime env updated. Restart airg-ui service to apply changes.",
        }
    )


@app.route("/settings/agents/mcp-apply", methods=["POST", "OPTIONS"])
def settings_agents_mcp_apply():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    profile_id = str(payload.get("profile_id", "")).strip()
    dry_run = bool(payload.get("dry_run", False))
    remove_previous = payload.get("remove_previous", None)
    manage_codex_trust = payload.get("manage_codex_trust", None)
    if remove_previous is not None:
        remove_previous = bool(remove_previous)
    if manage_codex_trust is not None:
        manage_codex_trust = bool(manage_codex_trust)
    if not profile_id:
        return jsonify({"ok": False, "errors": ["profile_id is required"]}), 400

    paths = _agent_paths()
    profiles = _agent_profiles(paths)
    profile = _profile_by_id(profiles, profile_id)
    if not isinstance(profile, dict):
        return jsonify({"ok": False, "errors": ["Profile not found"]}), 404

    result = mcp_config_manager.apply_mcp_config(
        paths,
        profile,
        remove_previous=remove_previous,
        manage_codex_trust=manage_codex_trust,
        dry_run=dry_run,
    )
    if not result.get("ok"):
        status = 409 if result.get("requires_previous_choice") or result.get("requires_trust_choice") else 400
        return jsonify(result), status

    current_profiles = result.get("profiles", profiles)
    result["posture"] = _posture_summary_with_state(current_profiles, paths)
    return jsonify(result)


@app.route("/settings/agents/config-apply", methods=["POST", "OPTIONS"])
def settings_agents_config_apply():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    profile_id = str(payload.get("profile_id", "")).strip()
    auto_add_mcp = bool(payload.get("auto_add_mcp", False))
    options = payload.get("options", {})
    if not profile_id:
        return jsonify({"ok": False, "errors": ["profile_id is required"]}), 400
    paths = _agent_paths()
    profiles = _agent_profiles(paths)
    profile = _profile_by_id(profiles, profile_id)
    if not isinstance(profile, dict):
        return jsonify({"ok": False, "errors": ["Profile not found"]}), 404
    result = agent_configurator.apply_hardening(
        paths,
        profile,
        options=options if isinstance(options, dict) else None,
        auto_add_mcp=auto_add_mcp,
    )
    if not result.get("ok"):
        status = 409 if result.get("requires_mcp") else 400
        return jsonify(result), status
    result["posture"] = _posture_summary_with_state(profiles, paths)
    return jsonify(result)


@app.route("/settings/agents/config-undo", methods=["POST", "OPTIONS"])
def settings_agents_config_undo():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    profile_id = str(payload.get("profile_id", "")).strip()
    if not profile_id:
        return jsonify({"ok": False, "errors": ["profile_id is required"]}), 400
    paths = _agent_paths()
    profiles = _agent_profiles(paths)
    profile = _profile_by_id(profiles, profile_id)
    if not isinstance(profile, dict):
        return jsonify({"ok": False, "errors": ["Profile not found"]}), 404
    result = agent_configurator.undo_hardening(paths, profile)
    if not result.get("ok"):
        return jsonify(result), 400
    result["posture"] = _posture_summary_with_state(profiles, paths)
    return jsonify(result)


@app.route("/settings/agents/script-sentinel", methods=["GET", "OPTIONS"])
def settings_agents_script_sentinel():
    if request.method == "OPTIONS":
        return ("", 204)
    limit = int(request.args.get("limit", "200") or "200")
    offset = int(request.args.get("offset", "0") or "0")
    hours = int(request.args.get("hours", "24") or "24")
    artifacts = script_sentinel.list_flagged_artifacts(limit=limit, offset=offset)
    summary = script_sentinel.execution_summary(hours=hours)
    return jsonify({"ok": True, "artifacts": artifacts, "summary": summary})


@app.route("/settings/agents/script-sentinel/dismiss-once", methods=["POST", "OPTIONS"])
def settings_agents_script_sentinel_dismiss_once():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    content_hash = str(payload.get("content_hash", "")).strip().lower()
    reason = str(payload.get("reason", "")).strip()
    ttl_seconds = int(payload.get("ttl_seconds", 600) or 600)
    target_agent = str(payload.get("agent_id", "")).strip() or str(config.AGENT_ID or "Unknown")
    if not content_hash:
        return jsonify({"ok": False, "errors": ["content_hash is required"]}), 400
    if not reason:
        return jsonify({"ok": False, "errors": ["reason is required"]}), 400
    try:
        created = script_sentinel.create_allowance(
            agent_id=target_agent,
            content_hash=content_hash,
            allowance_type="once",
            reason=reason,
            created_by="gui-operator",
            ttl_seconds=ttl_seconds,
        )
    except Exception as exc:
        return jsonify({"ok": False, "errors": [str(exc)]}), 400
    return jsonify({"ok": True, "allowance": created})


@app.route("/settings/agents/script-sentinel/trust", methods=["POST", "OPTIONS"])
def settings_agents_script_sentinel_trust():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    content_hash = str(payload.get("content_hash", "")).strip().lower()
    reason = str(payload.get("reason", "")).strip()
    target_agent = str(payload.get("agent_id", "")).strip() or str(config.AGENT_ID or "Unknown")
    if not content_hash:
        return jsonify({"ok": False, "errors": ["content_hash is required"]}), 400
    if not reason:
        return jsonify({"ok": False, "errors": ["reason is required"]}), 400
    try:
        created = script_sentinel.create_allowance(
            agent_id=target_agent,
            content_hash=content_hash,
            allowance_type="persistent",
            reason=reason,
            created_by="gui-operator",
        )
    except Exception as exc:
        return jsonify({"ok": False, "errors": [str(exc)]}), 400
    return jsonify({"ok": True, "allowance": created})


def _ui_dist_ready() -> bool:
    return UI_DIST_PATH.exists() and (UI_DIST_PATH / "index.html").exists()


@app.route("/", methods=["GET"])
def ui_index():
    if not _ui_dist_ready():
        return (
            jsonify(
                {
                    "error": "UI build not found",
                    "hint": "Build frontend with `cd ui_v3 && npm install && npm run build` or set AIRG_UI_DIST_PATH",
                }
            ),
            404,
        )
    return send_from_directory(UI_DIST_PATH, "index.html")


@app.route("/assets/<path:asset_path>", methods=["GET"])
def ui_assets(asset_path: str):
    if not _ui_dist_ready():
        return jsonify({"error": "UI build not found"}), 404
    return send_from_directory(UI_DIST_PATH / "assets", asset_path)


@app.route("/<path:path>", methods=["GET"])
def ui_spa(path: str):
    # Keep REST endpoints authoritative; this fallback serves built UI files.
    if path.startswith("policy") or path.startswith("approvals") or path.startswith("telemetry"):
        return jsonify({"error": "Not found"}), 404
    if not _ui_dist_ready():
        return jsonify({"error": "UI build not found"}), 404
    file_path = UI_DIST_PATH / path
    if file_path.exists() and file_path.is_file():
        return send_from_directory(UI_DIST_PATH, path)
    return send_from_directory(UI_DIST_PATH, "index.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("AIRG_FLASK_PORT", "5001")), debug=False)
