import datetime
import os
import pathlib

from config import POLICY, SESSION_ID, WORKSPACE_ROOT
from policy_engine import command_hash, is_within_workspace, tokenize_command

CUMULATIVE_BUDGET_STATE: dict[str, dict] = {}


def cumulative_cfg() -> dict:
    return POLICY.get("requires_simulation", {}).get("cumulative_budget", {})


def budget_scope_key(tool: str) -> tuple[str, str]:
    cfg = cumulative_cfg()
    scope = str(cfg.get("scope", "session")).lower()
    if scope == "workspace":
        return scope, f"{WORKSPACE_ROOT}"
    if scope == "tool":
        return scope, f"{SESSION_ID}:{tool}"
    if scope == "request":
        request_id = os.environ.get("AIRG_REQUEST_ID", SESSION_ID)
        return scope, f"{request_id}:{tool}"
    return "session", SESSION_ID


def estimate_paths_bytes(paths: list[str]) -> int:
    total = 0
    for p in paths:
        try:
            if os.path.isfile(p):
                total += int(os.path.getsize(p))
        except OSError:
            continue
    return total


def budget_allows_override(scope_key: str, command: str) -> bool:
    cfg = cumulative_cfg()
    overrides = cfg.get("overrides", {})
    if not overrides.get("enabled", False):
        return False
    # Disabled during approval-store migration: command approvals are now
    # consumed through durable session+command grants in policy tier checks.
    # Revisit budget override semantics once override policy is explicitly
    # defined for cross-process approval state.
    _ = (scope_key, command_hash(command), overrides)
    return False


def prune_budget_state(scope_key: str, now: datetime.datetime) -> dict:
    cfg = cumulative_cfg()
    reset_cfg = cfg.get("reset", {})
    window = int(reset_cfg.get("window_seconds", 3600))
    idle = int(reset_cfg.get("idle_reset_seconds", 900))
    state = CUMULATIVE_BUDGET_STATE.setdefault(
        scope_key,
        {
            "unique_paths": {},
            "total_operations": 0,
            "total_bytes_estimate": 0,
            "last_activity": None,
            "overrides_used": 0,
        },
    )
    last = state.get("last_activity")
    if last and idle > 0 and (now - last).total_seconds() > idle:
        state.update(
            {
                "unique_paths": {},
                "total_operations": 0,
                "total_bytes_estimate": 0,
                "last_activity": None,
                "overrides_used": 0,
            }
        )
        return state

    if window > 0:
        cutoff = now - datetime.timedelta(seconds=window)
        state["unique_paths"] = {
            p: seen_at
            for p, seen_at in state.get("unique_paths", {}).items()
            if seen_at >= cutoff
        }
    return state


def check_and_record_cumulative_budget(
    *,
    tool: str,
    command: str | None,
    affected_paths: list[str],
    operation_count: int = 1,
    bytes_estimate: int | None = None,
) -> tuple[bool, str | None, str | None, dict]:
    cfg = cumulative_cfg()
    if not cfg.get("enabled", False):
        return True, None, None, {}

    counting = cfg.get("counting", {})
    included = {str(x).lower() for x in counting.get("commands_included", [])}
    if tool.lower() not in included:
        cmd_tokens, _ = tokenize_command(command or "")
        if not any(tok in included for tok in cmd_tokens):
            return True, None, None, {}

    scope, scope_key = budget_scope_key(tool)
    now = datetime.datetime.now(datetime.UTC)
    state = prune_budget_state(scope_key, now)
    existing_paths = set(state.get("unique_paths", {}).keys())
    new_paths = {str(pathlib.Path(p).resolve()) for p in affected_paths if is_within_workspace(p)}
    dedupe = bool(counting.get("dedupe_paths", True))
    include_noop = bool(counting.get("include_noop_attempts", False))
    if not new_paths and not include_noop:
        return True, None, None, {}
    prospective_unique = existing_paths | new_paths if dedupe else existing_paths.union(new_paths)
    op_increment = max(int(operation_count), 0)
    bytes_inc = int(bytes_estimate if bytes_estimate is not None else estimate_paths_bytes(list(new_paths)))

    limits = cfg.get("limits", {})
    max_unique = int(limits.get("max_unique_paths", 50))
    max_ops = int(limits.get("max_total_operations", 100))
    max_bytes = int(limits.get("max_total_bytes_estimate", 104857600))
    next_ops = int(state.get("total_operations", 0)) + op_increment
    next_bytes = int(state.get("total_bytes_estimate", 0)) + bytes_inc

    exceeds = len(prospective_unique) > max_unique or next_ops > max_ops or next_bytes > max_bytes

    if exceeds and not (command and budget_allows_override(scope_key, command)):
        on_exceed = cfg.get("on_exceed", {})
        reason = str(on_exceed.get("message", "Cumulative blast-radius budget exceeded for current scope."))
        matched_rule = str(on_exceed.get("matched_rule", "requires_simulation.cumulative_budget_exceeded"))
        budget_fields = {
            "budget_scope": scope,
            "budget_key": scope_key,
            "cumulative_unique_paths": len(existing_paths),
            "cumulative_total_operations": int(state.get("total_operations", 0)),
            "cumulative_total_bytes_estimate": int(state.get("total_bytes_estimate", 0)),
            "budget_remaining": {
                "max_unique_paths": max(max_unique - len(existing_paths), 0),
                "max_total_operations": max(max_ops - int(state.get("total_operations", 0)), 0),
                "max_total_bytes_estimate": max(max_bytes - int(state.get("total_bytes_estimate", 0)), 0),
            },
        }
        return False, reason, matched_rule, budget_fields

    for p in new_paths:
        state.setdefault("unique_paths", {})[p] = now
    state["total_operations"] = next_ops
    state["total_bytes_estimate"] = next_bytes
    state["last_activity"] = now

    budget_fields = {
        "budget_scope": scope,
        "budget_key": scope_key,
        "cumulative_unique_paths": len(state.get("unique_paths", {})),
        "cumulative_total_operations": int(state.get("total_operations", 0)),
        "cumulative_total_bytes_estimate": int(state.get("total_bytes_estimate", 0)),
        "budget_remaining": {
            "max_unique_paths": max(max_unique - len(state.get("unique_paths", {})), 0),
            "max_total_operations": max(max_ops - int(state.get("total_operations", 0)), 0),
            "max_total_bytes_estimate": max(max_bytes - int(state.get("total_bytes_estimate", 0)), 0),
        },
    }
    return True, None, None, budget_fields
