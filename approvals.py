import datetime
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import uuid

from config import APPROVAL_TTL_SECONDS, BASE_DIR, POLICY, RESTORE_CONFIRMATION_TTL_SECONDS

APPROVAL_FAILURES: dict[str, list[datetime.datetime]] = {}
PENDING_RESTORE_CONFIRMATIONS: dict[str, dict] = {}
APPROVAL_DB_PATH = pathlib.Path(os.environ.get("AIRG_APPROVAL_DB_PATH", str(BASE_DIR / "approvals.db")))


def _normalize_command(command: str) -> str:
    return re.sub(r"\s+", " ", command.strip()).lower()


def _normalize_for_audit(command: str) -> str:
    return re.sub(r"\s+", " ", command.strip())


def _command_hash(command: str) -> str:
    return hashlib.sha256(_normalize_command(command).encode()).hexdigest()


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _to_z(dt: datetime.datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _from_z(raw: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))


def _conn() -> sqlite3.Connection:
    APPROVAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(APPROVAL_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_approval_store() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_approvals (
                token TEXT PRIMARY KEY,
                command_hash TEXT NOT NULL,
                normalized_command TEXT NOT NULL,
                session_id TEXT,
                requested_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                affected_paths TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pending_approvals_expires_at ON pending_approvals(expires_at)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS approved_commands (
                session_id TEXT NOT NULL,
                command_hash TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                source TEXT,
                PRIMARY KEY(session_id, command_hash)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_approved_commands_expires_at ON approved_commands(expires_at)"
        )
        conn.commit()


def prune_approval_failures() -> None:
    sec = POLICY.get("requires_confirmation", {}).get("approval_security", {})
    window = int(sec.get("failed_attempt_window_seconds", 600))
    cutoff = _now_utc() - datetime.timedelta(seconds=window)
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
    APPROVAL_FAILURES.setdefault(key, []).append(_now_utc())


def prune_expired_approvals() -> None:
    init_approval_store()
    now = _to_z(_now_utc())
    with _conn() as conn:
        conn.execute("DELETE FROM pending_approvals WHERE expires_at <= ?", (now,))
        conn.execute("DELETE FROM approved_commands WHERE expires_at <= ?", (now,))
        conn.commit()


def issue_or_reuse_approval_token(
    command: str,
    *,
    session_id: str = "",
    affected_paths: list[str] | None = None,
) -> tuple[str, datetime.datetime]:
    prune_expired_approvals()
    cmd_hash = _command_hash(command)
    now = _now_utc()
    init_approval_store()

    with _conn() as conn:
        row = conn.execute(
            """
            SELECT token, expires_at
            FROM pending_approvals
            WHERE command_hash = ? AND session_id = ? AND expires_at > ?
            ORDER BY expires_at DESC
            LIMIT 1
            """,
            (cmd_hash, session_id, _to_z(now)),
        ).fetchone()
        if row:
            return str(row["token"]), _from_z(str(row["expires_at"]))

    token = uuid.uuid4().hex
    expires_at = now + datetime.timedelta(seconds=APPROVAL_TTL_SECONDS)
    payload = json.dumps(affected_paths or [])
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO pending_approvals
              (token, command_hash, normalized_command, session_id, requested_at, expires_at, affected_paths)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token,
                cmd_hash,
                _normalize_for_audit(command),
                session_id,
                _to_z(now),
                _to_z(expires_at),
                payload,
            ),
        )
        conn.commit()
    return token, expires_at


def consume_command_approval(
    command: str,
    approval_token: str,
    *,
    source: str = "approve_command",
) -> tuple[bool, str | None, str | None]:
    prune_expired_approvals()
    if approval_failures_exceeded(approval_token):
        return False, "Approval token temporarily locked due to repeated failed attempts", "approval_rate_limit"

    init_approval_store()
    with _conn() as conn:
        rec = conn.execute(
            """
            SELECT command_hash, expires_at, session_id
            FROM pending_approvals
            WHERE token = ?
            LIMIT 1
            """,
            (approval_token,),
        ).fetchone()
    expected_hash = _command_hash(command)

    if not rec:
        record_approval_failure(approval_token)
        return False, "Invalid or expired approval token", "approval_token"

    if _from_z(str(rec["expires_at"])) <= _now_utc():
        with _conn() as conn:
            conn.execute("DELETE FROM pending_approvals WHERE token = ?", (approval_token,))
            conn.commit()
        record_approval_failure(approval_token)
        return False, "Invalid or expired approval token", "approval_token"

    if str(rec["command_hash"]) != expected_hash:
        record_approval_failure(approval_token)
        return False, "Approval token does not match the provided command", "approval_mismatch"

    session_id = str(rec["session_id"] or "")
    with _conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO approved_commands
              (session_id, command_hash, approved_at, expires_at, source)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session_id,
                expected_hash,
                _to_z(_now_utc()),
                _to_z(_now_utc() + datetime.timedelta(seconds=APPROVAL_TTL_SECONDS)),
                source,
            ),
        )
        conn.execute("DELETE FROM pending_approvals WHERE token = ?", (approval_token,))
        conn.commit()
    APPROVAL_FAILURES.pop(approval_token, None)
    return True, None, None


def consume_approved_command(session_id: str, command: str) -> bool:
    """
    Return True and consume one approved command grant for this session+command.

    Grants are one-time use and time-bounded. This enforces separation across
    processes because state is stored in shared SQLite.
    """
    prune_expired_approvals()
    init_approval_store()
    cmd_hash = _command_hash(command)
    with _conn() as conn:
        row = conn.execute(
            """
            SELECT session_id, command_hash
            FROM approved_commands
            WHERE session_id = ? AND command_hash = ?
            LIMIT 1
            """,
            (session_id, cmd_hash),
        ).fetchone()
        if not row:
            return False
        conn.execute(
            "DELETE FROM approved_commands WHERE session_id = ? AND command_hash = ?",
            (session_id, cmd_hash),
        )
        conn.commit()
    return True


def list_pending_approvals() -> list[dict]:
    prune_expired_approvals()
    init_approval_store()
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT token, normalized_command, session_id, requested_at, expires_at, affected_paths
            FROM pending_approvals
            ORDER BY requested_at ASC
            """
        ).fetchall()
    out: list[dict] = []
    for row in rows:
        try:
            affected = json.loads(str(row["affected_paths"]) or "[]")
            if not isinstance(affected, list):
                affected = []
        except Exception:
            affected = []
        out.append(
            {
                "token": str(row["token"]),
                "command": str(row["normalized_command"]),
                "session_id": str(row["session_id"] or ""),
                "requested_at": str(row["requested_at"]),
                "expires_at": str(row["expires_at"]),
                "affected_paths": affected,
            }
        )
    return out


def deny_command_approval(approval_token: str) -> tuple[bool, str]:
    init_approval_store()
    with _conn() as conn:
        cur = conn.execute("DELETE FROM pending_approvals WHERE token = ?", (approval_token,))
        conn.commit()
        if cur.rowcount == 0:
            return False, "Approval token not found"
    APPROVAL_FAILURES.pop(approval_token, None)
    return True, "Approval denied and token removed"


def prune_expired_restore_confirmations() -> None:
    now = _now_utc()
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
    expires_at = _now_utc() + datetime.timedelta(seconds=RESTORE_CONFIRMATION_TTL_SECONDS)
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


def reset_approval_state_for_tests() -> None:
    APPROVAL_FAILURES.clear()
    if APPROVAL_DB_PATH.exists():
        APPROVAL_DB_PATH.unlink()
