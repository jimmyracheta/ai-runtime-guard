import datetime
import hashlib
import json
import os
import pathlib
import re
import sqlite3
from contextlib import closing
from typing import Any

import config
from policy_engine import split_shell_segments, tokenize_shell_segment

WRAPPER_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("os_system", r"\bos\.system\s*\("),
    ("subprocess", r"\bsubprocess(?:\.[A-Za-z_][A-Za-z0-9_]*)?\s*\("),
    ("shutil_rmtree", r"\bshutil\.rmtree\s*\("),
    ("os_remove", r"\bos\.(?:remove|unlink)\s*\("),
    ("exec_call", r"\bexec\s*\("),
    ("eval_call", r"\beval\s*\("),
)

INTERPRETER_COMMANDS = {"python", "python3", "node", "bash", "sh", "ruby", "perl"}
SOURCE_COMMANDS = {"source", "."}

_SCAN_MATCHER_CACHE: dict[str, dict[str, Any]] = {}


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _iso_now() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _reports_db_path() -> pathlib.Path:
    return pathlib.Path(config.REPORTS_DB_PATH).expanduser().resolve()


def _conn() -> sqlite3.Connection:
    db_path = _reports_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS script_sentinel_artifacts (
          content_hash TEXT PRIMARY KEY,
          matched_signatures_json TEXT NOT NULL,
          first_seen_ts TEXT NOT NULL,
          last_seen_ts TEXT NOT NULL,
          first_writer_agent_id TEXT NOT NULL,
          last_writer_agent_id TEXT NOT NULL,
          first_path TEXT NOT NULL,
          last_path TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS script_sentinel_paths (
          path TEXT PRIMARY KEY,
          content_hash TEXT NOT NULL,
          last_seen_ts TEXT NOT NULL,
          last_writer_agent_id TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_script_sentinel_paths_hash
        ON script_sentinel_paths(content_hash);

        CREATE TABLE IF NOT EXISTS script_sentinel_exec_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT NOT NULL,
          agent_id TEXT NOT NULL,
          session_id TEXT NOT NULL,
          command TEXT NOT NULL,
          script_path TEXT NOT NULL,
          content_hash TEXT NOT NULL,
          decision TEXT NOT NULL,
          decision_mode TEXT NOT NULL,
          detection_method TEXT NOT NULL,
          matched_signatures_json TEXT NOT NULL,
          resolved_tiers_json TEXT NOT NULL,
          allowance_applied TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_script_sentinel_exec_events_ts
        ON script_sentinel_exec_events(ts);
        CREATE INDEX IF NOT EXISTS idx_script_sentinel_exec_events_agent
        ON script_sentinel_exec_events(agent_id);
        CREATE INDEX IF NOT EXISTS idx_script_sentinel_exec_events_hash
        ON script_sentinel_exec_events(content_hash);

        CREATE TABLE IF NOT EXISTS script_sentinel_allowlist (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          agent_id TEXT NOT NULL,
          content_hash TEXT NOT NULL,
          allowance_type TEXT NOT NULL,
          reason TEXT NOT NULL,
          created_by TEXT NOT NULL,
          created_ts TEXT NOT NULL,
          expires_ts TEXT,
          consumed_ts TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_script_sentinel_allowlist_lookup
        ON script_sentinel_allowlist(agent_id, content_hash, allowance_type, consumed_ts);
        """
    )
    conn.commit()


def _config() -> dict[str, Any]:
    sentinel = config.POLICY.get("script_sentinel", {})
    if not isinstance(sentinel, dict):
        sentinel = {}
    return {
        "enabled": bool(sentinel.get("enabled", False)),
        "mode": str(sentinel.get("mode", "match_original")).strip().lower(),
        "max_scan_bytes": max(1024, int(sentinel.get("max_scan_bytes", 1_048_576))),
        "include_wrappers": bool(sentinel.get("include_wrappers", True)),
    }


def enabled() -> bool:
    return bool(_config()["enabled"])


def _norm(value: str) -> str:
    return re.sub(r"\s+", " ", str(value).strip()).lower()


def _collect_policy_patterns(policy_doc: dict[str, Any]) -> dict[str, dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}

    def _add(pattern: str, tier: str) -> None:
        raw = str(pattern).strip()
        if not raw:
            return
        key = _norm(raw)
        if not key:
            return
        existing = merged.get(key)
        if existing and existing.get("tier") == "blocked":
            return
        if existing and existing.get("tier") == "requires_confirmation" and tier == "requires_confirmation":
            return
        merged[key] = {"pattern": raw, "tier": tier}

    blocked = ((policy_doc.get("blocked") or {}).get("commands") or [])
    for cmd in blocked:
        _add(str(cmd), "blocked")

    requires_confirmation = ((policy_doc.get("requires_confirmation") or {}).get("commands") or [])
    for cmd in requires_confirmation:
        _add(str(cmd), "requires_confirmation")

    overrides = policy_doc.get("agent_overrides", {})
    if isinstance(overrides, dict):
        for entry in overrides.values():
            if not isinstance(entry, dict):
                continue
            overlay = entry.get("policy", {})
            if not isinstance(overlay, dict):
                continue
            for cmd in ((overlay.get("blocked") or {}).get("commands") or []):
                _add(str(cmd), "blocked")
            for cmd in ((overlay.get("requires_confirmation") or {}).get("commands") or []):
                _add(str(cmd), "requires_confirmation")
    return merged


def _pattern_regex(pattern: str) -> re.Pattern[str]:
    pieces = [re.escape(part) for part in str(pattern).strip().split() if part.strip()]
    if not pieces:
        return re.compile(r"$^")
    if len(pieces) == 1:
        return re.compile(rf"(?<![A-Za-z0-9_\-]){pieces[0]}(?![A-Za-z0-9_\-])", re.IGNORECASE)
    return re.compile(rf"{r'\s+'.join(pieces)}", re.IGNORECASE)


def _scan_matchers() -> dict[str, Any]:
    policy_patterns = _collect_policy_patterns(config.POLICY)
    cfg = _config()
    cache_key = json.dumps(
        {
            "patterns": sorted((k, v["tier"]) for k, v in policy_patterns.items()),
            "include_wrappers": bool(cfg["include_wrappers"]),
        },
        sort_keys=True,
    )
    cached = _SCAN_MATCHER_CACHE.get(cache_key)
    if cached:
        return cached

    wrappers = []
    if cfg["include_wrappers"]:
        wrappers = [
            {"name": name, "regex": re.compile(regex, re.IGNORECASE)}
            for name, regex in WRAPPER_SIGNATURES
        ]

    matcher = {
        "policy": [
            {
                "normalized": key,
                "pattern": item["pattern"],
                "tier": item["tier"],
                "regex": _pattern_regex(item["pattern"]),
            }
            for key, item in policy_patterns.items()
        ],
        "wrappers": wrappers,
    }
    _SCAN_MATCHER_CACHE.clear()
    _SCAN_MATCHER_CACHE[cache_key] = matcher
    return matcher


def _hash_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _hash_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _upsert_path_map(
    conn: sqlite3.Connection,
    *,
    path: str,
    content_hash: str,
    agent_id: str,
    now_iso: str,
) -> None:
    conn.execute(
        """
        INSERT INTO script_sentinel_paths(path, content_hash, last_seen_ts, last_writer_agent_id)
        VALUES(?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
          content_hash = excluded.content_hash,
          last_seen_ts = excluded.last_seen_ts,
          last_writer_agent_id = excluded.last_writer_agent_id
        """,
        (path, content_hash, now_iso, agent_id),
    )


def scan_and_record_write(path: str, content: str, *, writer_agent_id: str | None = None) -> dict[str, Any]:
    cfg = _config()
    if not cfg["enabled"]:
        return {"enabled": False, "flagged": False}

    agent_id = str(writer_agent_id or config.AGENT_ID or "Unknown").strip() or "Unknown"
    resolved_path = str(pathlib.Path(path).expanduser().resolve())
    encoded = content.encode("utf-8", errors="replace")
    if len(encoded) > int(cfg["max_scan_bytes"]):
        return {
            "enabled": True,
            "flagged": False,
            "scan_skipped": True,
            "skip_reason": "max_scan_bytes_exceeded",
            "path": resolved_path,
            "bytes": len(encoded),
        }

    matchers = _scan_matchers()
    matches: list[dict[str, Any]] = []

    for item in matchers["policy"]:
        if item["regex"].search(content):
            matches.append(
                {
                    "type": "policy_command",
                    "pattern": item["pattern"],
                    "normalized_pattern": item["normalized"],
                    "source_tier": item["tier"],
                }
            )
    for item in matchers["wrappers"]:
        if item["regex"].search(content):
            matches.append(
                {
                    "type": "wrapper_signature",
                    "pattern": item["name"],
                    "normalized_pattern": item["name"],
                    "source_tier": "n/a",
                }
            )

    if not matches:
        return {"enabled": True, "flagged": False, "path": resolved_path}

    content_hash = _hash_text(content)
    now_iso = _iso_now()
    with closing(_conn()) as conn:
        _ensure_schema(conn)
        conn.execute(
            """
            INSERT INTO script_sentinel_artifacts(
              content_hash, matched_signatures_json, first_seen_ts, last_seen_ts,
              first_writer_agent_id, last_writer_agent_id, first_path, last_path
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(content_hash) DO UPDATE SET
              matched_signatures_json = excluded.matched_signatures_json,
              last_seen_ts = excluded.last_seen_ts,
              last_writer_agent_id = excluded.last_writer_agent_id,
              last_path = excluded.last_path
            """,
            (
                content_hash,
                json.dumps(matches, separators=(",", ":"), sort_keys=True),
                now_iso,
                now_iso,
                agent_id,
                agent_id,
                resolved_path,
                resolved_path,
            ),
        )
        _upsert_path_map(conn, path=resolved_path, content_hash=content_hash, agent_id=agent_id, now_iso=now_iso)
        conn.commit()

    return {
        "enabled": True,
        "flagged": True,
        "content_hash": content_hash,
        "path": resolved_path,
        "matched_signatures": matches,
    }


def _resolve_path_token(token: str) -> pathlib.Path:
    raw = token.strip().strip("'\"")
    expanded = os.path.expanduser(raw)
    if os.path.isabs(expanded):
        return pathlib.Path(expanded).resolve()
    return (pathlib.Path(config.WORKSPACE_ROOT) / expanded).resolve()


def _is_exec_path(token: str) -> bool:
    if not token:
        return False
    value = token.strip()
    if value.startswith("./") or value.startswith("../") or value.startswith("~/"):
        return True
    if os.path.isabs(value):
        return True
    return "/" in value


def _first_script_arg(tokens: list[str]) -> str:
    for idx, token in enumerate(tokens[1:], start=1):
        if token == "-c":
            return ""
        if token.startswith("-"):
            continue
        if idx > 1 and tokens[idx - 1] in {"-m"}:
            continue
        return token
    return ""


def _python_import_targets(tokens: list[str]) -> list[pathlib.Path]:
    try:
        c_index = tokens.index("-c")
    except ValueError:
        return []
    if c_index + 1 >= len(tokens):
        return []
    code = tokens[c_index + 1]
    candidates: list[pathlib.Path] = []
    imports = re.findall(r"(?:from|import)\s+([A-Za-z_][A-Za-z0-9_\.]*)", code)
    for module_name in imports:
        module_path = module_name.replace(".", "/")
        base = pathlib.Path(config.WORKSPACE_ROOT)
        file_candidate = (base / f"{module_path}.py").resolve()
        init_candidate = (base / module_path / "__init__.py").resolve()
        if file_candidate.exists():
            candidates.append(file_candidate)
        if init_candidate.exists():
            candidates.append(init_candidate)
    return candidates


def extract_script_targets(command: str) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    seen_paths: set[str] = set()

    def _add(path_obj: pathlib.Path, method: str) -> None:
        resolved = str(path_obj.resolve())
        if resolved in seen_paths:
            return
        seen_paths.add(resolved)
        targets.append({"path": resolved, "detection_method": method})

    for segment in split_shell_segments(command):
        tokens, err = tokenize_shell_segment(segment)
        if err or not tokens:
            continue
        cmd = tokens[0]
        cmd_lower = cmd.lower()

        if cmd_lower in INTERPRETER_COMMANDS:
            script_arg = _first_script_arg(tokens)
            if script_arg:
                try:
                    _add(_resolve_path_token(script_arg), "interpreter_file")
                except Exception:
                    pass
            if cmd_lower in {"python", "python3"}:
                for candidate in _python_import_targets(tokens):
                    _add(candidate, "import_hint")

        if cmd_lower in SOURCE_COMMANDS and len(tokens) >= 2:
            try:
                _add(_resolve_path_token(tokens[1]), "source_file")
            except Exception:
                pass

        if _is_exec_path(cmd):
            try:
                _add(_resolve_path_token(cmd), "direct_exec")
            except Exception:
                pass

    pipe_pattern = re.compile(
        r"\bcat\s+([^\s|;]+)\s*\|\s*(python3?|node|bash|sh|ruby|perl)\b",
        re.IGNORECASE,
    )
    for match in pipe_pattern.finditer(command):
        token = match.group(1)
        try:
            _add(_resolve_path_token(token), "pipe_stream")
        except Exception:
            continue

    return targets


def _artifact_for_hash(conn: sqlite3.Connection, content_hash: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM script_sentinel_artifacts WHERE content_hash = ?",
        (content_hash,),
    ).fetchone()


def _executor_tier(pattern_normalized: str) -> str | None:
    blocked = {_norm(cmd) for cmd in ((config.POLICY.get("blocked") or {}).get("commands") or [])}
    if pattern_normalized in blocked:
        return "blocked"
    requires_confirmation = {
        _norm(cmd)
        for cmd in ((config.POLICY.get("requires_confirmation") or {}).get("commands") or [])
    }
    if pattern_normalized in requires_confirmation:
        return "requires_confirmation"
    return None


def _mode_decision(signatures: list[dict[str, Any]], mode: str) -> tuple[str, list[dict[str, str]]]:
    resolved_tiers: list[dict[str, str]] = []
    has_blocked = False
    has_confirmation = False
    for item in signatures:
        sig_type = str(item.get("type", ""))
        normalized_pattern = str(item.get("normalized_pattern", ""))
        if sig_type == "policy_command":
            tier = _executor_tier(normalized_pattern)
            if tier:
                resolved_tiers.append({"pattern": normalized_pattern, "tier": tier})
                if tier == "blocked":
                    has_blocked = True
                elif tier == "requires_confirmation":
                    has_confirmation = True

    if mode == "block":
        return "blocked", resolved_tiers
    if mode == "requires_confirmation":
        return "requires_confirmation", resolved_tiers
    if has_blocked:
        return "blocked", resolved_tiers
    if has_confirmation:
        return "requires_confirmation", resolved_tiers
    return "allowed", resolved_tiers


def _resolve_allowance(
    conn: sqlite3.Connection,
    *,
    agent_id: str,
    content_hash: str,
) -> dict[str, Any] | None:
    now_iso = _iso_now()
    rows = conn.execute(
        """
        SELECT *
        FROM script_sentinel_allowlist
        WHERE agent_id = ?
          AND content_hash = ?
          AND consumed_ts IS NULL
          AND (expires_ts IS NULL OR expires_ts >= ?)
        ORDER BY
          CASE allowance_type WHEN 'persistent' THEN 0 ELSE 1 END ASC,
          created_ts DESC
        LIMIT 1
        """,
        (agent_id, content_hash, now_iso),
    ).fetchall()
    if not rows:
        return None
    row = rows[0]
    allowance = dict(row)
    if str(row["allowance_type"]) == "once":
        conn.execute(
            "UPDATE script_sentinel_allowlist SET consumed_ts = ? WHERE id = ?",
            (now_iso, int(row["id"])),
        )
    return allowance


def evaluate_command_execution(
    command: str,
    *,
    agent_id: str | None = None,
    session_id: str = "",
) -> dict[str, Any]:
    cfg = _config()
    if not cfg["enabled"]:
        return {"enabled": False, "has_hits": False, "decision": "allowed", "hits": [], "mode": cfg["mode"]}

    executor_agent_id = str(agent_id or config.AGENT_ID or "Unknown").strip() or "Unknown"
    targets = extract_script_targets(command)
    if not targets:
        return {"enabled": True, "has_hits": False, "decision": "allowed", "hits": [], "mode": cfg["mode"]}

    mode = str(cfg["mode"])
    if mode not in {"match_original", "block", "requires_confirmation"}:
        mode = "match_original"

    now_iso = _iso_now()
    hits: list[dict[str, Any]] = []

    with closing(_conn()) as conn:
        _ensure_schema(conn)
        for target in targets:
            path_str = target["path"]
            detection_method = target["detection_method"]
            path_obj = pathlib.Path(path_str)
            if not path_obj.exists() or not path_obj.is_file():
                continue

            try:
                content_hash = _hash_file(path_obj)
            except OSError:
                continue

            _upsert_path_map(
                conn,
                path=path_str,
                content_hash=content_hash,
                agent_id=executor_agent_id,
                now_iso=now_iso,
            )

            artifact = _artifact_for_hash(conn, content_hash)
            if not artifact:
                continue

            signatures = json.loads(str(artifact["matched_signatures_json"]) or "[]")
            decision, resolved_tiers = _mode_decision(signatures, mode)
            allowance_applied = ""

            if decision in {"blocked", "requires_confirmation"}:
                allowance = _resolve_allowance(
                    conn,
                    agent_id=executor_agent_id,
                    content_hash=content_hash,
                )
                if allowance:
                    allowance_applied = str(allowance.get("allowance_type", ""))
                    decision = "allowed"

            hit = {
                "path": path_str,
                "content_hash": content_hash,
                "decision": decision,
                "detection_method": detection_method,
                "matched_signatures": signatures,
                "resolved_tiers": resolved_tiers,
                "allowance_applied": allowance_applied,
            }
            hits.append(hit)
            conn.execute(
                """
                INSERT INTO script_sentinel_exec_events(
                  ts, agent_id, session_id, command, script_path, content_hash, decision,
                  decision_mode, detection_method, matched_signatures_json, resolved_tiers_json, allowance_applied
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now_iso,
                    executor_agent_id,
                    session_id,
                    command,
                    path_str,
                    content_hash,
                    decision,
                    mode,
                    detection_method,
                    json.dumps(signatures, separators=(",", ":"), sort_keys=True),
                    json.dumps(resolved_tiers, separators=(",", ":"), sort_keys=True),
                    allowance_applied,
                ),
            )
        conn.commit()

    unresolved = [h for h in hits if h["decision"] in {"blocked", "requires_confirmation"}]
    final_decision = "allowed"
    if any(h["decision"] == "blocked" for h in unresolved):
        final_decision = "blocked"
    elif any(h["decision"] == "requires_confirmation" for h in unresolved):
        final_decision = "requires_confirmation"

    return {
        "enabled": True,
        "has_hits": bool(hits),
        "decision": final_decision,
        "mode": mode,
        "hits": hits,
    }


def list_flagged_artifacts(*, limit: int = 200, offset: int = 0) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 1000))
    safe_offset = max(0, int(offset))
    with closing(_conn()) as conn:
        _ensure_schema(conn)
        total = int(
            conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM script_sentinel_paths p
                INNER JOIN script_sentinel_artifacts a
                  ON a.content_hash = p.content_hash
                """
            ).fetchone()["c"]
        )
        rows = conn.execute(
            """
            SELECT
              p.path,
              p.content_hash,
              p.last_seen_ts AS path_last_seen_ts,
              p.last_writer_agent_id AS path_last_writer_agent_id,
              a.matched_signatures_json,
              a.first_seen_ts,
              a.last_seen_ts,
              a.first_writer_agent_id,
              a.last_writer_agent_id,
              a.first_path,
              a.last_path
            FROM script_sentinel_paths p
            INNER JOIN script_sentinel_artifacts a
              ON a.content_hash = p.content_hash
            ORDER BY p.last_seen_ts DESC
            LIMIT ? OFFSET ?
            """,
            (safe_limit, safe_offset),
        ).fetchall()

    artifacts = []
    for row in rows:
        item = dict(row)
        item["matched_signatures"] = json.loads(item.pop("matched_signatures_json") or "[]")
        artifacts.append(item)
    return {"total": total, "items": artifacts}


def execution_summary(*, hours: int = 24) -> dict[str, Any]:
    window_hours = max(1, min(int(hours), 24 * 365))
    since = (_utc_now() - datetime.timedelta(hours=window_hours)).isoformat().replace("+00:00", "Z")
    with closing(_conn()) as conn:
        _ensure_schema(conn)
        row = conn.execute(
            """
            SELECT
              COUNT(*) AS total_checks,
              SUM(CASE WHEN decision='blocked' THEN 1 ELSE 0 END) AS blocked,
              SUM(CASE WHEN decision='requires_confirmation' THEN 1 ELSE 0 END) AS requires_confirmation,
              SUM(CASE WHEN decision='allowed' THEN 1 ELSE 0 END) AS allowed,
              SUM(CASE WHEN allowance_applied='persistent' THEN 1 ELSE 0 END) AS trusted_allowances,
              SUM(CASE WHEN allowance_applied='once' THEN 1 ELSE 0 END) AS one_time_allowances
            FROM script_sentinel_exec_events
            WHERE ts >= ?
            """,
            (since,),
        ).fetchone()
        flagged_total = int(
            conn.execute("SELECT COUNT(*) AS c FROM script_sentinel_artifacts").fetchone()["c"]
        )
    return {
        "window_hours": window_hours,
        "since": since,
        "flagged_artifacts": flagged_total,
        "total_checks": int(row["total_checks"] or 0),
        "blocked": int(row["blocked"] or 0),
        "requires_confirmation": int(row["requires_confirmation"] or 0),
        "allowed": int(row["allowed"] or 0),
        "trusted_allowances": int(row["trusted_allowances"] or 0),
        "one_time_allowances": int(row["one_time_allowances"] or 0),
    }


def create_allowance(
    *,
    agent_id: str,
    content_hash: str,
    allowance_type: str,
    reason: str,
    created_by: str,
    ttl_seconds: int = 600,
) -> dict[str, Any]:
    a_type = str(allowance_type).strip().lower()
    if a_type not in {"once", "persistent"}:
        raise ValueError("allowance_type must be 'once' or 'persistent'")
    normalized_agent = str(agent_id or "").strip()
    if not normalized_agent:
        raise ValueError("agent_id is required")
    normalized_hash = str(content_hash or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}", normalized_hash):
        raise ValueError("content_hash must be a 64-char sha256 hex string")
    normalized_reason = str(reason or "").strip()
    if not normalized_reason:
        raise ValueError("reason is required")
    creator = str(created_by or "").strip() or "operator"
    now_iso = _iso_now()
    expires = None
    if a_type == "once":
        ttl = max(30, min(int(ttl_seconds), 86_400))
        expires = (_utc_now() + datetime.timedelta(seconds=ttl)).isoformat().replace("+00:00", "Z")

    with closing(_conn()) as conn:
        _ensure_schema(conn)
        conn.execute(
            """
            INSERT INTO script_sentinel_allowlist(
              agent_id, content_hash, allowance_type, reason, created_by, created_ts, expires_ts, consumed_ts
            ) VALUES(?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (normalized_agent, normalized_hash, a_type, normalized_reason, creator, now_iso, expires),
        )
        row_id = int(conn.execute("SELECT last_insert_rowid() AS rid").fetchone()["rid"])
        conn.commit()

    return {
        "id": row_id,
        "agent_id": normalized_agent,
        "content_hash": normalized_hash,
        "allowance_type": a_type,
        "reason": normalized_reason,
        "created_by": creator,
        "created_ts": now_iso,
        "expires_ts": expires,
    }
