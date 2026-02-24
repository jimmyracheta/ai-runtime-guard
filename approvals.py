import datetime
import hashlib
import pathlib
import re
import uuid

from config import APPROVAL_TTL_SECONDS, POLICY, RESTORE_CONFIRMATION_TTL_SECONDS

SESSION_WHITELIST: set = set()
PENDING_APPROVALS: dict[str, dict] = {}
APPROVAL_FAILURES: dict[str, list[datetime.datetime]] = {}
PENDING_RESTORE_CONFIRMATIONS: dict[str, dict] = {}


def _normalize_command(command: str) -> str:
    return re.sub(r"\s+", " ", command.strip()).lower()


def _normalize_for_audit(command: str) -> str:
    return re.sub(r"\s+", " ", command.strip())


def _command_hash(command: str) -> str:
    return hashlib.sha256(_normalize_command(command).encode()).hexdigest()


def prune_approval_failures() -> None:
    sec = POLICY.get("requires_confirmation", {}).get("approval_security", {})
    window = int(sec.get("failed_attempt_window_seconds", 600))
    cutoff = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=window)
    for key in list(APPROVAL_FAILURES.keys()):
        recent = [ts for ts in APPROVAL_FAILURES[key] if ts >= cutoff]
        if recent:
            APPROVAL_FAILURES[key] = recent
        else:
            APPROVAL_FAILURES.pop(key, None)


def approval_failures_exceeded(key: str) -> bool:
    prune_approval_failures()
    sec = POLICY.get("requires_confirmation", {}).get("approval_security", {})
    max_failed = int(sec.get("max_failed_attempts_per_token", 5))
    return len(APPROVAL_FAILURES.get(key, [])) >= max_failed


def record_approval_failure(key: str) -> None:
    prune_approval_failures()
    APPROVAL_FAILURES.setdefault(key, []).append(datetime.datetime.now(datetime.UTC))


def prune_expired_approvals() -> None:
    now = datetime.datetime.now(datetime.UTC)
    expired = [token for token, rec in PENDING_APPROVALS.items() if rec["expires_at"] <= now]
    for token in expired:
        PENDING_APPROVALS.pop(token, None)


def issue_or_reuse_approval_token(command: str) -> tuple[str, datetime.datetime]:
    prune_expired_approvals()
    cmd_hash = _command_hash(command)
    now = datetime.datetime.now(datetime.UTC)

    for token, rec in PENDING_APPROVALS.items():
        if rec["command_hash"] == cmd_hash and rec["expires_at"] > now:
            return token, rec["expires_at"]

    token = uuid.uuid4().hex
    expires_at = now + datetime.timedelta(seconds=APPROVAL_TTL_SECONDS)
    PENDING_APPROVALS[token] = {
        "command_hash": cmd_hash,
        "normalized_command": _normalize_for_audit(command),
        "expires_at": expires_at,
    }
    return token, expires_at


def consume_command_approval(command: str, approval_token: str) -> tuple[bool, str | None, str | None]:
    prune_expired_approvals()
    if approval_failures_exceeded(approval_token):
        return False, "Approval token temporarily locked due to repeated failed attempts", "approval_rate_limit"

    rec = PENDING_APPROVALS.get(approval_token)
    expected_hash = _command_hash(command)

    if not rec:
        record_approval_failure(approval_token)
        return False, "Invalid or expired approval token", "approval_token"

    if rec["command_hash"] != expected_hash:
        record_approval_failure(approval_token)
        return False, "Approval token does not match the provided command", "approval_mismatch"

    SESSION_WHITELIST.add(expected_hash)
    PENDING_APPROVALS.pop(approval_token, None)
    APPROVAL_FAILURES.pop(approval_token, None)
    return True, None, None


def prune_expired_restore_confirmations() -> None:
    now = datetime.datetime.now(datetime.UTC)
    expired = [
        token
        for token, rec in PENDING_RESTORE_CONFIRMATIONS.items()
        if rec["expires_at"] <= now
    ]
    for token in expired:
        PENDING_RESTORE_CONFIRMATIONS.pop(token, None)


def issue_restore_confirmation_token(backup_path: pathlib.Path, planned: int) -> tuple[str, datetime.datetime]:
    prune_expired_restore_confirmations()
    token = uuid.uuid4().hex
    expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=RESTORE_CONFIRMATION_TTL_SECONDS)
    PENDING_RESTORE_CONFIRMATIONS[token] = {
        "backup_path": str(backup_path.resolve()),
        "planned": int(planned),
        "expires_at": expires_at,
    }
    return token, expires_at


def consume_restore_confirmation_token(backup_path: pathlib.Path, restore_token: str) -> tuple[bool, str | None, str | None]:
    prune_expired_restore_confirmations()
    rec = PENDING_RESTORE_CONFIRMATIONS.get(restore_token)
    if not rec:
        return False, "Invalid or expired restore token", "restore_token"

    if rec["backup_path"] != str(backup_path.resolve()):
        return False, "Restore token does not match the requested backup location", "restore_token_mismatch"

    PENDING_RESTORE_CONFIRMATIONS.pop(restore_token, None)
    return True, None, None
