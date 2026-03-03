import contextlib
import contextvars
import os
from typing import Any

from config import SESSION_ID

_AGENT_SESSION_ID_VAR: contextvars.ContextVar[str] = contextvars.ContextVar(
    "airg_agent_session_id",
    default=SESSION_ID,
)
_REQUEST_ID_VAR: contextvars.ContextVar[str] = contextvars.ContextVar(
    "airg_request_id",
    default="",
)


def _ctx_attr(obj: Any, name: str) -> Any:
    try:
        return getattr(obj, name)
    except Exception:
        return None


def _resolve_agent_session_id(ctx: Any | None = None) -> str:
    env_override = os.environ.get("AIRG_AGENT_SESSION_ID", "").strip()
    if env_override:
        return env_override
    if ctx is None:
        return SESSION_ID

    session = _ctx_attr(ctx, "session")
    if session is None:
        return SESSION_ID

    # Prefer explicit IDs when present on transport/session internals.
    for attr in ("mcp_session_id", "session_id", "id"):
        raw = _ctx_attr(session, attr)
        if raw:
            return str(raw)

    # Fallback to process-local stable object identity for the connection.
    return f"conn-{id(session):x}"


def _resolve_request_id(ctx: Any | None = None) -> str:
    if ctx is None:
        return ""
    raw = _ctx_attr(ctx, "request_id")
    if raw is None:
        return ""
    return str(raw)


def activate_runtime_context(ctx: Any | None = None) -> tuple[contextvars.Token, contextvars.Token]:
    sid = _resolve_agent_session_id(ctx)
    rid = _resolve_request_id(ctx)
    sid_token = _AGENT_SESSION_ID_VAR.set(sid)
    rid_token = _REQUEST_ID_VAR.set(rid)
    return sid_token, rid_token


def reset_runtime_context(tokens: tuple[contextvars.Token, contextvars.Token]) -> None:
    sid_token, rid_token = tokens
    _AGENT_SESSION_ID_VAR.reset(sid_token)
    _REQUEST_ID_VAR.reset(rid_token)


@contextlib.contextmanager
def runtime_context(ctx: Any | None = None):
    tokens = activate_runtime_context(ctx)
    try:
        yield
    finally:
        reset_runtime_context(tokens)


def current_agent_session_id() -> str:
    return _AGENT_SESSION_ID_VAR.get()


def current_request_id() -> str:
    return _REQUEST_ID_VAR.get()
