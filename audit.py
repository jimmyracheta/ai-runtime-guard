import datetime
import json
import re

from config import LOG_PATH, POLICY, SESSION_ID, WORKSPACE_ROOT
from models import PolicyResult


def _redact_text_for_audit(value: str) -> str:
    text = value
    for pattern in POLICY.get("audit", {}).get("redact_patterns", []):
        try:
            text = re.sub(pattern, r"\1<redacted>", text)
        except re.error:
            continue
    return text


def redact_for_audit(value):
    if isinstance(value, str):
        return _redact_text_for_audit(value)
    if isinstance(value, list):
        return [redact_for_audit(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_for_audit(v) for k, v in value.items()}
    return value


def build_log_entry(tool: str, result: PolicyResult, source: str = "ai-agent", **kwargs) -> dict:
    timestamp = datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
    entry: dict = {
        "timestamp": timestamp,
        "source": source,
        "session_id": SESSION_ID,
        "tool": tool,
        "workspace": WORKSPACE_ROOT,
        "policy_decision": "allowed" if result.allowed else "blocked",
        "decision_tier": result.decision_tier,
    }
    if result.matched_rule is not None:
        entry["matched_rule"] = result.matched_rule
    if not result.allowed:
        entry["block_reason"] = redact_for_audit(result.reason)
    entry.update(redact_for_audit(kwargs))
    return entry


def append_log_entry(entry: dict) -> None:
    with open(LOG_PATH, "a") as log_file:
        log_file.write(json.dumps(entry) + "\n")


def build_operator_log_entry(
    *,
    tool: str,
    event: str,
    session_id: str,
    policy_decision: str,
    decision_tier: str,
    **kwargs,
) -> dict:
    """
    Build an audit event for explicit human operator actions (e.g. GUI approvals).
    """
    timestamp = datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
    entry: dict = {
        "timestamp": timestamp,
        "source": "human-operator",
        "session_id": session_id,
        "tool": tool,
        "event": event,
        "workspace": WORKSPACE_ROOT,
        "policy_decision": policy_decision,
        "decision_tier": decision_tier,
    }
    entry.update(redact_for_audit(kwargs))
    return entry
