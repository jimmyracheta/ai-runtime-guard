import datetime
import hmac
import hashlib
import json
import os
import pathlib
import re
import secrets
import sqlite3
import stat
import uuid

from audit import append_log_entry
from config import (
    APPROVAL_TTL_SECONDS,
    BASE_DIR,
    POLICY,
    RESTORE_CONFIRMATION_TTL_SECONDS,
    SESSION_ID,
    WORKSPACE_ROOT,
)

APPROVAL_FAILURES: dict[str, list[datetime.datetime]] = {}
PENDING_RESTORE_CONFIRMATIONS: dict[str, dict] = {}
APPROVAL_DB_PATH = pathlib.Path(os.environ.get("AIRG_APPROVAL_DB_PATH", str(BASE_DIR / "approvals.db")))
_APPROVAL_HMAC_CACHE: tuple[str, bytes] | None = None
_SECURITY_WARNINGS_EMITTED: set[str] = set()


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
    _warn_if_world_accessible(APPROVAL_DB_PATH.parent)
    _warn_if_store_inside_workspace()
    conn = sqlite3.connect(APPROVAL_DB_PATH)
    conn.row_factory = sqlite3.Row
    _enforce_db_file_permissions()
    return conn


def _log_security_warning(event: str, reason: str, **kwargs) -> None:
    key = json.dumps({"event": event, "reason": reason, **kwargs}, sort_keys=True, default=str)
    if key in _SECURITY_WARNINGS_EMITTED:
        return
    _SECURITY_WARNINGS_EMITTED.add(key)
    append_log_entry(
        {
            "timestamp": _to_z(_now_utc()),
            "source": "mcp-server",
            "session_id": SESSION_ID,
            "tool": "approval_store",
            "event": event,
            "workspace": WORKSPACE_ROOT,
            "policy_decision": "blocked",
            "decision_tier": "blocked",
            "block_reason": reason,
            **kwargs,
        }
    )


def _warn_if_world_accessible(path: pathlib.Path) -> None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        _log_security_warning(
            "approval_store_permission_check_failed",
            "Failed to inspect approval-store directory permissions",
            path=str(path),
            error=str(exc),
        )
        return
    if mode & 0o007:
        _log_security_warning(
            "approval_store_directory_too_open",
            "Approval-store directory is world-accessible; tighten directory permissions",
            path=str(path),
            mode=oct(mode),
        )


def _warn_if_store_inside_workspace() -> None:
    try:
        db_resolved = APPROVAL_DB_PATH.resolve()
        ws_resolved = pathlib.Path(WORKSPACE_ROOT).resolve()
        if db_resolved.is_relative_to(ws_resolved):
            _log_security_warning(
                "approval_store_inside_workspace",
                "Approval store path is inside agent workspace; move AIRG_APPROVAL_DB_PATH outside workspace",
                approval_db_path=str(db_resolved),
                workspace=str(ws_resolved),
            )
        key_resolved = _approval_hmac_key_path().resolve()
        if key_resolved.is_relative_to(ws_resolved):
            _log_security_warning(
                "approval_hmac_key_inside_workspace",
                "Approval HMAC key path is inside agent workspace; move AIRG_APPROVAL_HMAC_KEY_PATH outside workspace",
                approval_hmac_key_path=str(key_resolved),
                workspace=str(ws_resolved),
            )
    except Exception:
        # Path resolution failures are non-fatal for runtime operation.
        return


def _enforce_db_file_permissions() -> None:
    if not APPROVAL_DB_PATH.exists():
        return
    try:
        os.chmod(APPROVAL_DB_PATH, 0o600)
    except OSError as exc:
        _log_security_warning(
            "approval_db_permission_enforce_failed",
            "Failed to enforce 0600 permissions on approvals.db",
            path=str(APPROVAL_DB_PATH),
            error=str(exc),
        )
        return

    try:
        mode = stat.S_IMODE(APPROVAL_DB_PATH.stat().st_mode)
    except OSError as exc:
        _log_security_warning(
            "approval_db_permission_check_failed",
            "Failed to verify approvals.db permissions",
            path=str(APPROVAL_DB_PATH),
            error=str(exc),
        )
        return

    if mode != 0o600:
        _log_security_warning(
            "approval_db_permissions_weak",
            "approvals.db permissions are weaker than expected after chmod",
            path=str(APPROVAL_DB_PATH),
            mode=oct(mode),
        )


def _approval_hmac_key_path() -> pathlib.Path:
    override = os.environ.get("AIRG_APPROVAL_HMAC_KEY_PATH")
    if override:
        return pathlib.Path(override).expanduser().resolve()
    return pathlib.Path(f"{APPROVAL_DB_PATH}.hmac.key")


def _approval_signing_key() -> bytes:
    global _APPROVAL_HMAC_CACHE
    env_secret = os.environ.get("AIRG_APPROVAL_HMAC_SECRET", "").strip()
    if env_secret:
        return env_secret.encode()

    key_path = _approval_hmac_key_path()
    cache_key = str(key_path)
    if _APPROVAL_HMAC_CACHE and _APPROVAL_HMAC_CACHE[0] == cache_key:
        return _APPROVAL_HMAC_CACHE[1]

    try:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        _warn_if_world_accessible(key_path.parent)
        if key_path.exists():
            key = key_path.read_bytes().strip()
        else:
            key = secrets.token_hex(32).encode()
            key_path.write_bytes(key + b"\n")
        os.chmod(key_path, 0o600)
        mode = stat.S_IMODE(key_path.stat().st_mode)
        if mode != 0o600:
            _log_security_warning(
                "approval_hmac_key_permissions_weak",
                "Approval HMAC key file permissions are weaker than expected",
                path=str(key_path),
                mode=oct(mode),
            )
        if not key:
            raise ValueError("Approval HMAC key is empty")
        _APPROVAL_HMAC_CACHE = (cache_key, key)
        return key
    except Exception as exc:
        _log_security_warning(
            "approval_hmac_key_fallback",
            "Falling back to ephemeral in-memory approval signing key; configure AIRG_APPROVAL_HMAC_SECRET or writable key path",
            path=str(key_path),
            error=str(exc),
        )
        fallback = f"ephemeral::{os.getpid()}::{uuid.uuid4().hex}".encode()
        _APPROVAL_HMAC_CACHE = (cache_key, fallback)
        return fallback


def _approval_grant_signature(session_id: str, command_hash: str, expires_at: str) -> str:
    payload = f"{session_id}|{command_hash}|{expires_at}".encode()
    return hmac.new(_approval_signing_key(), payload, hashlib.sha256).hexdigest()


def _check_approval_store_health(conn: sqlite3.Connection) -> tuple[bool, str]:
    try:
        row = conn.execute("PRAGMA integrity_check").fetchone()
        if not row or str(row[0]).lower() != "ok":
            return False, f"sqlite integrity check failed: {row[0] if row else 'no result'}"

        tables = {
            str(r["name"])
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('pending_approvals','approved_commands')"
            ).fetchall()
        }
        required_tables = {"pending_approvals", "approved_commands"}
        if tables != required_tables:
            return False, f"missing required approval tables: expected={sorted(required_tables)} found={sorted(tables)}"

        approved_cols = {
            str(r["name"])
            for r in conn.execute("PRAGMA table_info(approved_commands)").fetchall()
        }
        required_cols = {"session_id", "command_hash", "approved_at", "expires_at", "source", "signature"}
        if not required_cols.issubset(approved_cols):
            return (
                False,
                f"approved_commands schema missing required columns: {sorted(required_cols - approved_cols)}",
            )
    except sqlite3.DatabaseError as exc:
        return False, f"approval-store health check failed with sqlite error: {exc}"

    return True, "ok"


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
                signature TEXT,
                source TEXT,
                PRIMARY KEY(session_id, command_hash)
            )
            """
        )
        cols = {
            str(row["name"])
            for row in conn.execute("PRAGMA table_info(approved_commands)").fetchall()
        }
        if "signature" not in cols:
            conn.execute("ALTER TABLE approved_commands ADD COLUMN signature TEXT")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_approved_commands_expires_at ON approved_commands(expires_at)"
        )
        conn.commit()
        healthy, reason = _check_approval_store_health(conn)
        if not healthy:
            _log_security_warning(
                "approval_store_health_check_failed",
                "Approval store failed health check; refusing approvals until repaired",
                approval_db_path=str(APPROVAL_DB_PATH),
                error=reason,
            )
            raise RuntimeError(f"Approval store failed health check: {reason}")


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

    try:
        rec_expires_at = _from_z(str(rec["expires_at"]))
    except Exception:
        with _conn() as conn:
            conn.execute("DELETE FROM pending_approvals WHERE token = ?", (approval_token,))
            conn.commit()
        _log_security_warning(
            "approval_store_malformed_row",
            "Pending approval row has invalid expires_at and was discarded",
            approval_token=approval_token,
            expires_at=str(rec["expires_at"]),
        )
        record_approval_failure(approval_token)
        return False, "Invalid or expired approval token", "approval_token"

    if rec_expires_at <= _now_utc():
        with _conn() as conn:
            conn.execute("DELETE FROM pending_approvals WHERE token = ?", (approval_token,))
            conn.commit()
        record_approval_failure(approval_token)
        return False, "Invalid or expired approval token", "approval_token"

    if str(rec["command_hash"]) != expected_hash:
        record_approval_failure(approval_token)
        return False, "Approval token does not match the provided command", "approval_mismatch"

    session_id = str(rec["session_id"] or "")
    if not session_id:
        with _conn() as conn:
            conn.execute("DELETE FROM pending_approvals WHERE token = ?", (approval_token,))
            conn.commit()
        _log_security_warning(
            "approval_store_malformed_row",
            "Pending approval row missing session_id and was discarded",
            approval_token=approval_token,
        )
        record_approval_failure(approval_token)
        return False, "Invalid or expired approval token", "approval_token"

    approved_at = _to_z(_now_utc())
    grant_expires_at = _to_z(_now_utc() + datetime.timedelta(seconds=APPROVAL_TTL_SECONDS))
    signature = _approval_grant_signature(session_id, expected_hash, grant_expires_at)
    with _conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO approved_commands
              (session_id, command_hash, approved_at, expires_at, signature, source)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                expected_hash,
                approved_at,
                grant_expires_at,
                signature,
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
            SELECT session_id, command_hash, expires_at, signature
            FROM approved_commands
            WHERE session_id = ? AND command_hash = ?
            LIMIT 1
            """,
            (session_id, cmd_hash),
        ).fetchone()
        if not row:
            return False
        grant_expires_at = str(row["expires_at"] or "")
        signature = str(row["signature"] or "")
        expected_signature = _approval_grant_signature(session_id, cmd_hash, grant_expires_at)
        if not signature or not hmac.compare_digest(signature, expected_signature):
            _log_security_warning(
                "approval_store_tamper_detected",
                "Rejected approval grant due to signature mismatch",
                session_id=session_id,
                command_hash=cmd_hash,
            )
            conn.execute(
                "DELETE FROM approved_commands WHERE session_id = ? AND command_hash = ?",
                (session_id, cmd_hash),
            )
            conn.commit()
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
                _log_security_warning(
                    "approval_store_malformed_row",
                    "Pending approval row has non-list affected_paths; coercing to empty list",
                    approval_token=str(row["token"]),
                )
                affected = []
        except Exception as exc:
            _log_security_warning(
                "approval_store_malformed_row",
                "Pending approval row has invalid affected_paths JSON; coercing to empty list",
                approval_token=str(row["token"]),
                error=str(exc),
            )
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
    global _APPROVAL_HMAC_CACHE
    APPROVAL_FAILURES.clear()
    _SECURITY_WARNINGS_EMITTED.clear()
    _APPROVAL_HMAC_CACHE = None
    if APPROVAL_DB_PATH.exists():
        APPROVAL_DB_PATH.unlink()
    key_path = _approval_hmac_key_path()
    if key_path.exists():
        key_path.unlink()
