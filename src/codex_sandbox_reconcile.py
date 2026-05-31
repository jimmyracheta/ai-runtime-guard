"""
codex_sandbox_reconcile.py — Codex no-double-sandbox reconciliation (P1-c, T7).

When AIRG establishes its own OS-level outer wall (os_sandbox.mode == enforce),
Codex's own inner sandbox must be relaxed to ``danger-full-access`` to avoid a
broken nested double-sandbox — but ONLY after AIRG's outer wall is confirmed up.
This module implements:

  * detect_codex_sandbox_mode(home, workspace) -> dict
      Read the EFFECTIVE Codex sandbox_mode/approval_policy using Codex's
      precedence (project config overrides global when the project is trusted).
      Read-only. Reuses agent_posture._codex_tier3_state for parsing.

  * reconcile_decision(codex_mode, os_sandbox_mode, outer_wall_confirmed)
      Pure decision function implementing the T7 decision table.

  * apply_and_restore(...)  (context manager)
      Edit <config>.toml to set danger-full-access and restore the original on
      exit. It ONLY writes danger-full-access when outer_wall_confirmed=True.

SECURITY: never weaken Codex's sandbox before AIRG's wall is confirmed. The
context manager refuses to write a weakening value when outer_wall_confirmed is
False. Tests must run against TEMP config files, never the real ~/.codex.

Design source: docs/os-enforcement/codex-sandbox-integration.md (§2-§4).
"""

from __future__ import annotations

import os
import pathlib
import re
from contextlib import contextmanager
from typing import Any, Iterator, Optional

import agent_posture  # reuse _codex_tier3_state (do not duplicate divergently)

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    tomllib = None  # type: ignore


CODEX_SANDBOX_MODES = {"read-only", "workspace-write", "danger-full-access"}
DANGER_FULL_ACCESS = "danger-full-access"

# Codex's built-in default when sandbox_mode is absent from both configs.
# Per codex-sandbox-integration.md §2.2: treat absence as "workspace-write".
CODEX_BUILTIN_DEFAULT = "workspace-write"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _global_config_path(home: pathlib.Path) -> pathlib.Path:
    return home / ".codex" / "config.toml"


def _project_config_path(workspace: pathlib.Path) -> pathlib.Path:
    return workspace / ".codex" / "config.toml"


def _project_is_trusted(global_path: pathlib.Path, workspace: pathlib.Path) -> bool:
    """Return True iff the global config marks <workspace> as trusted.

    Codex only loads the project config when the project is trusted via a
    [projects."<abs path>"] trust_level = "trusted" entry in the GLOBAL config.
    """
    try:
        text = global_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if not text.strip() or tomllib is None:
        return False
    try:
        payload = tomllib.loads(text)
    except Exception:
        return False
    projects = payload.get("projects", {})
    if not isinstance(projects, dict):
        return False
    target = str(pathlib.Path(workspace))
    # Match by resolved path string and by raw key (Codex keys by absolute path).
    candidates = {target}
    try:
        candidates.add(str(pathlib.Path(workspace).resolve()))
    except OSError:
        pass
    for key, value in projects.items():
        if str(key) not in candidates:
            continue
        if isinstance(value, dict) and str(value.get("trust_level", "")).strip() == "trusted":
            return True
    return False


def detect_codex_sandbox_mode(home: Any, workspace: Any) -> dict[str, Any]:
    """Detect the EFFECTIVE Codex sandbox state at launch (read-only).

    Returns a dict:
      {
        "effective_sandbox_mode": "read-only"|"workspace-write"|"danger-full-access",
        "effective_approval_policy": str,
        "source": "project"|"global"|"builtin_default"|"unknown",
        "global_present": bool, "project_present": bool, "project_trusted": bool,
        "global_path": str, "project_path": str,
        "readable": bool,   # False => could not read/parse (fail-closed signal)
      }

    Precedence (codex-sandbox-integration.md §2.2): project config overrides
    global config when the project is trusted; else global; else Codex built-in
    default ("workspace-write").
    """
    home_path = pathlib.Path(home)
    workspace_path = pathlib.Path(workspace)
    global_path = _global_config_path(home_path)
    project_path = _project_config_path(workspace_path)

    global_state = agent_posture._codex_tier3_state(global_path)
    project_state = agent_posture._codex_tier3_state(project_path)

    global_mode = str(global_state.get("sandbox_mode", "")).strip()
    project_mode = str(project_state.get("sandbox_mode", "")).strip()
    global_present = global_path.exists()
    project_present = project_path.exists()
    project_trusted = _project_is_trusted(global_path, workspace_path)

    # Detect unreadable/parse-error: file exists but parsing yielded nothing.
    def _unreadable(path: pathlib.Path, mode: str) -> bool:
        if not path.exists():
            return False
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return True
        if not text.strip():
            return False  # empty file is readable (just no config)
        if tomllib is None:
            return False
        try:
            tomllib.loads(text)
        except Exception:
            return True
        return False

    readable = not (_unreadable(global_path, global_mode) or _unreadable(project_path, project_mode))

    if project_mode and project_trusted:
        effective_mode = project_mode
        effective_approval = str(project_state.get("approval_policy", "")).strip()
        source = "project"
    elif global_mode:
        effective_mode = global_mode
        effective_approval = str(global_state.get("approval_policy", "")).strip()
        source = "global"
    else:
        effective_mode = CODEX_BUILTIN_DEFAULT
        effective_approval = ""
        source = "builtin_default"

    return {
        "effective_sandbox_mode": effective_mode,
        "effective_approval_policy": effective_approval,
        "source": source,
        "global_present": global_present,
        "project_present": project_present,
        "project_trusted": project_trusted,
        "global_path": str(global_path),
        "project_path": str(project_path),
        "readable": readable,
    }


def effective_config_path_for_write(detection: dict[str, Any]) -> pathlib.Path:
    """Return the config file whose sandbox_mode is effective, so the launcher
    writes danger-full-access to the right scope. Project (when trusted+present)
    wins; else global."""
    if detection.get("source") == "project":
        return pathlib.Path(detection["project_path"])
    return pathlib.Path(detection["global_path"])


# ---------------------------------------------------------------------------
# Reconciliation decision (pure)
# ---------------------------------------------------------------------------


# Action constants.
ACTION_NOOP = "noop"                              # do not modify Codex config
ACTION_SET_DANGER_FULL_ACCESS = "set_danger_full_access"  # write danger-full-access
ACTION_LEAVE_INTACT = "leave_intact"             # wall not confirmed: do NOT weaken
ACTION_FAIL_CLOSED = "fail_closed"               # cannot determine: refuse


def reconcile_decision(
    codex_mode: Optional[str],
    os_sandbox_mode: str,
    outer_wall_confirmed: bool,
) -> dict[str, Any]:
    """Pure decision per the T7 table (codex-sandbox-integration.md §3.1).

    Returns {"action": <ACTION_*>, "write_value": str|None, "reason": str}.

    Key rules:
      * os_sandbox=enforce AND outer wall confirmed AND Codex sandbox active
        -> set danger-full-access (avoid nested double-sandbox).
      * outer wall NOT confirmed -> leave Codex intact (NEVER weaken first).
      * Codex already danger-full-access (or mode off/monitor) -> no-op.
      * codex_mode unknown AND enforce -> fail closed.
    """
    mode = str(os_sandbox_mode or "off").strip()
    cm = (codex_mode or "").strip().lower()
    codex_active = cm in {"read-only", "workspace-write"}
    codex_unknown = cm not in CODEX_SANDBOX_MODES

    if mode == "enforce":
        if codex_unknown:
            return {
                "action": ACTION_FAIL_CLOSED,
                "write_value": None,
                "reason": (
                    "os_sandbox=enforce but Codex sandbox_mode is unknown/"
                    "unreadable; cannot guarantee a sane stack. Fail closed."
                ),
            }
        if not outer_wall_confirmed:
            # NEVER weaken before the outer wall is up.
            return {
                "action": ACTION_LEAVE_INTACT,
                "write_value": None,
                "reason": (
                    "Outer wall not confirmed; leaving Codex sandbox intact "
                    "(must not weaken before AIRG's wall is established)."
                ),
            }
        if codex_active:
            return {
                "action": ACTION_SET_DANGER_FULL_ACCESS,
                "write_value": DANGER_FULL_ACCESS,
                "reason": (
                    "os_sandbox=enforce and outer wall confirmed; disabling "
                    "Codex inner sandbox to avoid nested double-sandbox."
                ),
            }
        # Codex already danger-full-access: ideal outer-wall state.
        return {
            "action": ACTION_NOOP,
            "write_value": None,
            "reason": "Codex inner sandbox already disabled; nothing to change.",
        }

    # mode == "off" or "monitor": never modify Codex's config.
    return {
        "action": ACTION_NOOP,
        "write_value": None,
        "reason": f"os_sandbox.mode={mode!r}: leaving Codex config unchanged.",
    }


# ---------------------------------------------------------------------------
# Apply + restore (context manager) — TEMP configs only in tests.
# ---------------------------------------------------------------------------

_SANDBOX_MODE_LINE_RE = re.compile(
    r'^(?P<indent>\s*)sandbox_mode\s*=\s*.*$'
)


def _read_sandbox_mode_line(text: str) -> Optional[str]:
    """Return the current top-level sandbox_mode value, or None if absent.

    Only matches a top-level (pre-table) ``sandbox_mode = "..."`` line —
    stops at the first ``[section]`` header so a key inside a sub-table is not
    mistaken for the top-level one.
    """
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            break
        m = _SANDBOX_MODE_LINE_RE.match(raw)
        if m:
            parts = stripped.split("=", 1)
            if len(parts) == 2:
                return parts[1].strip().strip('"').strip("'")
    return None


def _write_sandbox_mode(text: str, value: str) -> str:
    """Return ``text`` with the top-level sandbox_mode set to ``value`` (added
    at the top if absent). Preserves everything else."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    replaced = False
    in_top = True
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_top = False
        if in_top and not replaced and _SANDBOX_MODE_LINE_RE.match(raw):
            newline = "\n" if raw.endswith("\n") else ""
            out.append(f'sandbox_mode = "{value}"{newline}')
            replaced = True
            continue
        out.append(raw)
    if not replaced:
        prefix = f'sandbox_mode = "{value}"\n'
        return prefix + "".join(out)
    return "".join(out)


@contextmanager
def apply_and_restore(
    config_path: Any,
    write_value: str,
    *,
    outer_wall_confirmed: bool,
    logger: Any = None,
) -> Iterator[bool]:
    """Temporarily set Codex's top-level sandbox_mode to ``write_value`` and
    restore the original on exit (even on exception).

    Yields True if a write was performed, False otherwise.

    HARD GUARD: refuses to write a weakening value unless outer_wall_confirmed
    is True. If outer_wall_confirmed is False, this is a no-op (yields False)
    and the config is left completely untouched.
    """
    path = pathlib.Path(config_path)

    def _log(msg: str) -> None:
        if logger is not None:
            try:
                logger(msg)
            except Exception:
                pass

    if not outer_wall_confirmed:
        _log(
            "[GUARD] apply_and_restore refused: outer_wall_confirmed=False; "
            "Codex sandbox left intact (will not weaken before wall is up)."
        )
        yield False
        return

    if write_value not in CODEX_SANDBOX_MODES:
        raise ValueError(f"refusing to write invalid sandbox_mode: {write_value!r}")

    try:
        original_text = path.read_text(encoding="utf-8")
        existed = True
    except FileNotFoundError:
        original_text = ""
        existed = False
    except OSError as exc:
        raise OSError(f"cannot read Codex config {path}: {exc}") from exc

    original_value = _read_sandbox_mode_line(original_text)

    new_text = _write_sandbox_mode(original_text, write_value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new_text, encoding="utf-8")
    _log(f"[apply] set Codex sandbox_mode={write_value!r} in {path}.")

    try:
        yield True
    finally:
        # Restore exactly the prior state.
        if not existed:
            try:
                path.unlink()
                _log(f"[restore] removed launcher-created Codex config {path}.")
            except OSError:
                pass
        elif original_value is None:
            # sandbox_mode key did not exist before — remove it again.
            restored = _remove_top_level_sandbox_mode(original_text)
            path.write_text(restored, encoding="utf-8")
            _log(f"[restore] removed launcher-added sandbox_mode from {path}.")
        else:
            path.write_text(original_text, encoding="utf-8")
            _log(f"[restore] restored Codex sandbox_mode={original_value!r} in {path}.")


def _remove_top_level_sandbox_mode(text: str) -> str:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    in_top = True
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_top = False
        if in_top and _SANDBOX_MODE_LINE_RE.match(raw):
            continue
        out.append(raw)
    return "".join(out)
