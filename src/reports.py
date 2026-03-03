import datetime
import hashlib
import json
import pathlib
import sqlite3
from contextlib import closing
from typing import Any

from audit import append_log_entry
from config import AGENT_ID, LOG_PATH
from runtime_context import current_agent_session_id

SCHEMA_VERSION = "2"
STATE_KEY = "default"


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _iso_now() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def _conn(db_path: pathlib.Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _settings(policy: dict[str, Any] | None) -> dict[str, Any]:
    src = (policy or {})
    return {
        "enabled": bool(src.get("enabled", True)),
        "ingest_poll_interval_seconds": max(1, int(src.get("ingest_poll_interval_seconds", 5))),
        "reconcile_interval_seconds": max(60, int(src.get("reconcile_interval_seconds", 3600))),
        "retention_days": max(1, int(src.get("retention_days", 30))),
        "max_db_size_mb": max(10, int(src.get("max_db_size_mb", 200))),
        "prune_interval_seconds": max(300, int(src.get("prune_interval_seconds", 86400))),
    }


def init_reports_store(db_path: pathlib.Path) -> None:
    with closing(_conn(db_path)) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_key TEXT NOT NULL UNIQUE,
              timestamp TEXT NOT NULL,
              source TEXT,
              agent_id TEXT,
              session_id TEXT,
              agent_session_id TEXT,
              tool TEXT,
              event TEXT,
              workspace TEXT,
              policy_decision TEXT,
              decision_tier TEXT,
              matched_rule TEXT,
              block_reason TEXT,
              command TEXT,
              normalized_command TEXT,
              path TEXT,
              approval_token TEXT,
              approved_via TEXT,
              error TEXT,
              raw_json TEXT NOT NULL,
              ingested_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_tier ON events(decision_tier);
            CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
            CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool);
            CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events(agent_id);
            CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_matched_rule ON events(matched_rule);

            CREATE TABLE IF NOT EXISTS ingest_state (
              state_key TEXT PRIMARY KEY,
              last_offset INTEGER NOT NULL,
              log_mtime_ns INTEGER NOT NULL,
              log_size INTEGER NOT NULL,
              last_ingested_at TEXT,
              last_reconciled_at TEXT,
              last_pruned_at TEXT,
              last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            """
        )
        conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)", (SCHEMA_VERSION,))
        conn.execute(
            """
            INSERT OR IGNORE INTO ingest_state(
              state_key, last_offset, log_mtime_ns, log_size, last_ingested_at, last_reconciled_at, last_pruned_at, last_error
            ) VALUES(?, 0, 0, 0, NULL, NULL, NULL, NULL)
            """,
            (STATE_KEY,),
        )
        cols = {
            str(row["name"]): True
            for row in conn.execute("PRAGMA table_info(events)").fetchall()
        }
        if "agent_session_id" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN agent_session_id TEXT DEFAULT ''")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_agent_session_id ON events(agent_session_id)")
        conn.execute(
            """
            UPDATE events
            SET agent_session_id = CASE
              WHEN agent_session_id IS NULL OR agent_session_id = '' THEN COALESCE(NULLIF(session_id, ''), '')
              ELSE agent_session_id
            END
            """
        )
        conn.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", (SCHEMA_VERSION,))
        conn.commit()


def _load_state(conn: sqlite3.Connection) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM ingest_state WHERE state_key = ?", (STATE_KEY,)).fetchone()
    if row:
        return row
    conn.execute(
        """
        INSERT INTO ingest_state(
          state_key, last_offset, log_mtime_ns, log_size, last_ingested_at, last_reconciled_at, last_pruned_at, last_error
        ) VALUES(?, 0, 0, 0, NULL, NULL, NULL, NULL)
        """,
        (STATE_KEY,),
    )
    return conn.execute("SELECT * FROM ingest_state WHERE state_key = ?", (STATE_KEY,)).fetchone()


def _event_key(raw_line: str) -> str:
    return hashlib.sha256(raw_line.encode("utf-8")).hexdigest()


def _normalize_event(raw: dict[str, Any], raw_line: str) -> dict[str, Any]:
    agent_session_id = str(raw.get("agent_session_id") or raw.get("session_id") or "")
    return {
        "event_key": _event_key(raw_line),
        "timestamp": str(raw.get("timestamp") or _iso_now()),
        "source": str(raw.get("source", "")),
        "agent_id": str(raw.get("agent_id", "Unknown")),
        "session_id": agent_session_id,
        "agent_session_id": agent_session_id,
        "tool": str(raw.get("tool", "")),
        "event": str(raw.get("event", "")),
        "workspace": str(raw.get("workspace", "")),
        "policy_decision": str(raw.get("policy_decision", "")),
        "decision_tier": str(raw.get("decision_tier", "")),
        "matched_rule": str(raw.get("matched_rule", "")),
        "block_reason": str(raw.get("block_reason", "")),
        "command": str(raw.get("command", "")),
        "normalized_command": str(raw.get("normalized_command", "")),
        "path": str(raw.get("path", "")),
        "approval_token": str(raw.get("approval_token", "")),
        "approved_via": str(raw.get("approved_via", "")),
        "error": str(raw.get("error", "")),
        "raw_json": raw_line,
        "ingested_at": _iso_now(),
    }


def _mark_error(conn: sqlite3.Connection, error_text: str) -> None:
    conn.execute("UPDATE ingest_state SET last_error = ? WHERE state_key = ?", (error_text[:500], STATE_KEY))


def _record_warning(event: str, reason: str, **extra: Any) -> None:
    entry: dict[str, Any] = {
        "timestamp": _iso_now(),
        "source": "mcp-server",
        "agent_id": AGENT_ID,
        "session_id": current_agent_session_id(),
        "agent_session_id": current_agent_session_id(),
        "tool": "reports_ingest",
        "event": event,
        "workspace": "",
        "policy_decision": "allowed",
        "decision_tier": "allowed",
        "reason": reason,
    }
    entry.update(extra)
    append_log_entry(entry)


def _prune(conn: sqlite3.Connection, db_path: pathlib.Path, cfg: dict[str, Any], now: datetime.datetime) -> None:
    cutoff = (now - datetime.timedelta(days=int(cfg["retention_days"]))).isoformat().replace("+00:00", "Z")
    conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
    conn.execute("UPDATE ingest_state SET last_pruned_at = ?, last_error = NULL WHERE state_key = ?", (_iso_now(), STATE_KEY))
    conn.commit()

    max_bytes = int(cfg["max_db_size_mb"]) * 1024 * 1024
    if not db_path.exists():
        return
    warned = False
    while db_path.stat().st_size > max_bytes:
        warned = True
        conn.execute(
            "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY timestamp ASC LIMIT 1000)"
        )
        conn.commit()
        conn.execute("VACUUM")
        conn.commit()
        if conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"] == 0:
            break
    if warned:
        _record_warning(
            event="reports_db_size_threshold_reached",
            reason="reports.db exceeded size cap and oldest events were pruned",
            reports_db_path=str(db_path),
            max_db_size_mb=cfg["max_db_size_mb"],
        )


def sync_from_log(
    *,
    db_path: pathlib.Path,
    log_path: pathlib.Path | None = None,
    policy_reports: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cfg = _settings(policy_reports)
    init_reports_store(db_path)
    if not cfg["enabled"]:
        return {"enabled": False, "ingested": 0}

    log_path = (log_path or pathlib.Path(LOG_PATH)).expanduser().resolve()
    if not log_path.exists():
        return {"enabled": True, "ingested": 0, "log_exists": False}

    ingested = 0
    parse_errors = 0
    now = _utc_now()

    with closing(_conn(db_path)) as conn:
        st = _load_state(conn)
        offset = int(st["last_offset"])
        prev_size = int(st["log_size"])
        prev_mtime = int(st["log_mtime_ns"])
        stat_now = log_path.stat()
        size_now = int(stat_now.st_size)
        mtime_now = int(stat_now.st_mtime_ns)

        # Rotation/truncation: restart from beginning when file shrinks, or when
        # content is replaced without growth (mtime changed and size did not grow).
        if size_now < offset or (mtime_now != prev_mtime and size_now <= offset):
            offset = 0

        with open(log_path, "r", encoding="utf-8") as fh:
            fh.seek(offset)
            for line in fh:
                raw_line = line.strip()
                if not raw_line:
                    continue
                try:
                    raw_event = json.loads(raw_line)
                    event = _normalize_event(raw_event, raw_line)
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO events(
                          event_key, timestamp, source, agent_id, session_id, agent_session_id, tool, event, workspace,
                          policy_decision, decision_tier, matched_rule, block_reason, command,
                          normalized_command, path, approval_token, approved_via, error, raw_json, ingested_at
                        ) VALUES(
                          :event_key, :timestamp, :source, :agent_id, :session_id, :agent_session_id, :tool, :event, :workspace,
                          :policy_decision, :decision_tier, :matched_rule, :block_reason, :command,
                          :normalized_command, :path, :approval_token, :approved_via, :error, :raw_json, :ingested_at
                        )
                        """,
                        event,
                    )
                    ingested += 1
                except json.JSONDecodeError:
                    parse_errors += 1
            new_offset = int(fh.tell())

        # Periodic reconcile marker.
        should_reconcile = (
            not st["last_reconciled_at"]
            or (now - datetime.datetime.fromisoformat(str(st["last_reconciled_at"]).replace("Z", "+00:00"))).total_seconds()
            >= int(cfg["reconcile_interval_seconds"])
        )

        # Periodic prune marker.
        should_prune = (
            not st["last_pruned_at"]
            or (now - datetime.datetime.fromisoformat(str(st["last_pruned_at"]).replace("Z", "+00:00"))).total_seconds()
            >= int(cfg["prune_interval_seconds"])
        )

        conn.execute(
            """
            UPDATE ingest_state
            SET last_offset = ?,
                log_mtime_ns = ?,
                log_size = ?,
                last_ingested_at = ?,
                last_reconciled_at = CASE WHEN ? THEN ? ELSE last_reconciled_at END,
                last_error = ?
            WHERE state_key = ?
            """,
            (
                new_offset,
                mtime_now,
                size_now,
                _iso_now(),
                1 if should_reconcile else 0,
                _iso_now(),
                None if parse_errors == 0 else f"parse_errors={parse_errors}",
                STATE_KEY,
            ),
        )
        conn.commit()

        if should_prune:
            _prune(conn, db_path, cfg, now)

        # Reconcile fallback: if file changed unexpectedly with no new offset growth.
        if should_reconcile and mtime_now != prev_mtime and size_now == prev_size and offset == new_offset:
            conn.execute("UPDATE ingest_state SET last_offset = 0 WHERE state_key = ?", (STATE_KEY,))
            conn.commit()

    return {
        "enabled": True,
        "ingested": ingested,
        "parse_errors": parse_errors,
        "log_exists": True,
    }


def _query_rows(
    db_path: pathlib.Path,
    sql: str,
    params: tuple[Any, ...] = (),
) -> list[dict[str, Any]]:
    with closing(_conn(db_path)) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def _events_where(filters: dict[str, str]) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
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
    ]:
        val = str(filters.get(key, "")).strip()
        if val:
            clauses.append(f"LOWER({key}) LIKE ?")
            params.append(f"%{val.lower()}%")
    if filters.get("from"):
        clauses.append("timestamp >= ?")
        params.append(filters["from"])
    if filters.get("to"):
        clauses.append("timestamp <= ?")
        params.append(filters["to"])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def get_status(db_path: pathlib.Path) -> dict[str, Any]:
    init_reports_store(db_path)
    with closing(_conn(db_path)) as conn:
        st = _load_state(conn)
        total = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
    return {
        "schema_version": SCHEMA_VERSION,
        "reports_db_path": str(db_path),
        "reports_db_size_bytes": db_path.stat().st_size if db_path.exists() else 0,
        "last_ingested_at": st["last_ingested_at"],
        "last_reconciled_at": st["last_reconciled_at"],
        "last_pruned_at": st["last_pruned_at"],
        "last_error": st["last_error"],
        "last_offset": int(st["last_offset"]),
        "log_size": int(st["log_size"]),
        "row_count": int(total),
    }


def get_overview(db_path: pathlib.Path, filters: dict[str, str] | None = None) -> dict[str, Any]:
    filters = filters or {}
    where, params = _events_where(filters)
    with closing(_conn(db_path)) as conn:
        by_day = conn.execute(
            f"""
            SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS count
            FROM events
            {where}
            GROUP BY day
            ORDER BY day DESC
            LIMIT 7
            """,
            tuple(params),
        ).fetchall()
        blocked_day = conn.execute(
            f"""
            SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS count
            FROM events
            {where} {"AND" if where else "WHERE"} policy_decision = 'blocked'
            GROUP BY day
            ORDER BY day DESC
            LIMIT 7
            """,
            tuple(params),
        ).fetchall()
        totals = conn.execute(
            f"""
            SELECT
              COUNT(*) AS total_events,
              SUM(CASE WHEN policy_decision='blocked' THEN 1 ELSE 0 END) AS blocked_events,
              SUM(CASE WHEN event='backup_created' THEN 1 ELSE 0 END) AS backup_events,
              SUM(CASE WHEN tool='approve_command' AND event='command_approved' THEN 1 ELSE 0 END) AS approvals_approved,
              SUM(CASE WHEN tool='approve_command' AND event='command_denied' THEN 1 ELSE 0 END) AS approvals_denied
            FROM events
            {where}
            """,
            tuple(params),
        ).fetchone()
        top_commands = conn.execute(
            f"""
            SELECT
              command,
              COUNT(*) AS count,
              SUM(CASE WHEN policy_decision='allowed' THEN 1 ELSE 0 END) AS allowed_count,
              SUM(CASE WHEN policy_decision='blocked' THEN 1 ELSE 0 END) AS blocked_count
            FROM events
            {where} {"AND" if where else "WHERE"} command != ''
            GROUP BY command
            ORDER BY count DESC
            LIMIT 10
            """,
            tuple(params),
        ).fetchall()
        top_paths = conn.execute(
            f"""
            SELECT path, COUNT(*) AS count
            FROM events
            {where} {"AND" if where else "WHERE"} path != ''
            GROUP BY path
            ORDER BY count DESC
            LIMIT 10
            """,
            tuple(params),
        ).fetchall()
        blocked_rules = conn.execute(
            f"""
            SELECT matched_rule, COUNT(*) AS count
            FROM events
            {where} {"AND" if where else "WHERE"} policy_decision='blocked' AND matched_rule != ''
            GROUP BY matched_rule
            ORDER BY count DESC
            LIMIT 10
            """,
            tuple(params),
        ).fetchall()
    return {
        "events_per_day_7d": [dict(r) for r in by_day],
        "blocked_per_day_7d": [dict(r) for r in blocked_day],
        "totals": dict(totals) if totals else {},
        "top_commands": [dict(r) for r in top_commands],
        "top_paths": [dict(r) for r in top_paths],
        "blocked_by_rule": [dict(r) for r in blocked_rules],
    }


def list_events(
    db_path: pathlib.Path,
    *,
    filters: dict[str, str] | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    filters = filters or {}
    where, params = _events_where(filters)
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    with closing(_conn(db_path)) as conn:
        total = conn.execute(f"SELECT COUNT(*) AS c FROM events {where}", tuple(params)).fetchone()["c"]
        rows = conn.execute(
            f"""
            SELECT *
            FROM events
            {where}
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [limit, offset]),
        ).fetchall()
    return {"total": int(total), "limit": limit, "offset": offset, "events": [dict(r) for r in rows]}
