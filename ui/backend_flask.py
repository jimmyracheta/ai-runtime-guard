import json
import os
import pathlib
import sys
from datetime import datetime, UTC

from flask import Flask, jsonify, request

# Ensure project-root modules (approvals, config, etc.) are importable when
# this file is run directly via `python3 ui/backend_flask.py`.
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import approvals
from audit import append_log_entry, build_operator_log_entry
from ui import service

# Shared paths used by MCP server and control-plane backend.
POLICY_PATH = pathlib.Path(os.environ.get("AIRG_POLICY_PATH", str(BASE_DIR / "policy.json")))
APPROVAL_DB_PATH = pathlib.Path(os.environ.get("AIRG_APPROVAL_DB_PATH", str(BASE_DIR / "approvals.db")))
CATALOG_PATH = pathlib.Path(os.environ.get("AIRG_CATALOG_PATH", str(pathlib.Path(__file__).resolve().parent / "catalog.json")))

service.POLICY_PATH = POLICY_PATH
service.CATALOG_PATH = CATALOG_PATH
approvals.APPROVAL_DB_PATH = APPROVAL_DB_PATH
approvals.init_approval_store()

app = Flask(__name__)


def _is_local_origin(origin: str) -> bool:
    return origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1")


@app.after_request
def add_cors_headers(resp):
    # Restrict dev CORS to localhost origins so local frontend can call API.
    origin = request.headers.get("Origin", "")
    if origin and _is_local_origin(origin):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Actor"
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
            "tier_map": service.command_tier_map(policy),
            "all_commands": all_commands,
            "descriptions": service.command_descriptions(catalog),
            "contexts": service.command_context_map(catalog, all_commands),
            "tabs": service.visible_tabs(catalog),
            "tab_commands": service.tab_command_map(catalog),
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


@app.route("/approvals/approve", methods=["POST", "OPTIONS"])
def approve_pending():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    token = str(payload.get("token", "")).strip()
    command = str(payload.get("command", "")).strip()
    if not token or not command:
        return jsonify({"error": "Expected {token, command}"}), 400
    pending = next((item for item in approvals.list_pending_approvals() if item["token"] == token), None)
    ok, reason, matched_rule = approvals.consume_command_approval(command, token, source="flask.approvals")
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
            approved_via="gui",
        )
    )
    return jsonify({"approved": True, "message": "Approval accepted"})


@app.route("/approvals/deny", methods=["POST", "OPTIONS"])
def deny_pending():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    token = str(payload.get("token", "")).strip()
    if not token:
        return jsonify({"error": "Expected {token}"}), 400
    pending = next((item for item in approvals.list_pending_approvals() if item["token"] == token), None)
    ok, message = approvals.deny_command_approval(token)
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
            approved_via="gui",
        )
    )
    return jsonify({"denied": True, "message": message})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("AIRG_FLASK_PORT", "5001")), debug=False)
