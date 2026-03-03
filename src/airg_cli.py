import argparse
import datetime
import json
import importlib.util
import os
import pathlib
import platform
import runpy
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Any


def _project_root() -> pathlib.Path:
    here = pathlib.Path(__file__).resolve().parent
    # In editable source layout modules live under ./src.
    if here.name == "src" and (here.parent / "pyproject.toml").exists():
        return here.parent
    return here


def _is_macos() -> bool:
    return platform.system() == "Darwin"


def _candidate_ui_dist_paths() -> list[pathlib.Path]:
    # Search both source-tree and installed-package style locations.
    here = _project_root()
    cwd = pathlib.Path.cwd().resolve()
    env_ui_dist = os.environ.get("AIRG_UI_DIST_PATH", "").strip()
    candidates: list[pathlib.Path] = []
    if env_ui_dist:
        candidates.append(pathlib.Path(env_ui_dist).expanduser())
    return [
        *candidates,
        cwd / "ui_v3" / "dist",
        here / "ui_v3" / "dist",
        pathlib.Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages" / "ui_v3" / "dist",
    ]


def _resolve_ui_dist_path() -> pathlib.Path:
    for candidate in _candidate_ui_dist_paths():
        resolved = candidate.expanduser()
        if (resolved / "index.html").exists():
            return resolved.resolve()
    # Keep first source-tree path as deterministic fallback for warnings.
    return (_project_root() / "ui_v3" / "dist").resolve()


def _default_base_config_dir() -> pathlib.Path:
    if _is_macos():
        return pathlib.Path.home() / "Library" / "Application Support" / "ai-runtime-guard"
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    if xdg:
        return pathlib.Path(xdg) / "ai-runtime-guard"
    return pathlib.Path.home() / ".config" / "ai-runtime-guard"


def _default_base_state_dir() -> pathlib.Path:
    if _is_macos():
        return pathlib.Path.home() / "Library" / "Application Support" / "ai-runtime-guard"
    xdg = os.environ.get("XDG_STATE_HOME", "")
    if xdg:
        return pathlib.Path(xdg) / "ai-runtime-guard"
    return pathlib.Path.home() / ".local" / "state" / "ai-runtime-guard"


def _default_workspace_path() -> pathlib.Path:
    env_ws = os.environ.get("AIRG_WORKSPACE", "").strip()
    if env_ws:
        return pathlib.Path(env_ws).expanduser().resolve()

    cwd = pathlib.Path.cwd().resolve()
    # If user runs setup from a cloned repo root, place workspace beside repo.
    if (cwd / "pyproject.toml").exists() and (cwd / "src").exists():
        return (cwd.parent / "airg-workspace").resolve()

    return (pathlib.Path.home() / "airg-workspace").resolve()


def _policy_template() -> dict[str, Any]:
    candidates: list[pathlib.Path] = []
    cwd = pathlib.Path.cwd().resolve()
    # Prefer repository template when setup is launched from a cloned repo root.
    if (cwd / "pyproject.toml").exists() and (cwd / "src").exists() and (cwd / "policy.json").exists():
        candidates.append(cwd / "policy.json")
    candidates.append(_project_root() / "policy.json")
    for source in candidates:
        if source.exists():
            return json.loads(source.read_text())
    return {
        "blocked": {
            "commands": [
                "rm -rf",
                "mkfs",
                "shutdown",
                "reboot",
                "format",
                "dd",
                "find -delete",
                "find -exec rm",
                "xargs rm",
                "xargs -0 rm",
                "do rm",
            ],
            "paths": [".env", ".ssh", "/etc/passwd"],
            "extensions": [".pem", ".key"],
        },
        "requires_confirmation": {"commands": [], "paths": [], "session_whitelist_enabled": True, "approval_security": {"max_failed_attempts_per_token": 5, "failed_attempt_window_seconds": 600, "token_ttl_seconds": 600}},
        "requires_simulation": {"commands": [], "bulk_file_threshold": 10, "max_retries": 3, "cumulative_budget": {"enabled": False}},
        "allowed": {"paths_whitelist": [], "max_files_per_operation": 10, "max_file_size_mb": 10, "max_directory_depth": 100},
        "network": {
            "enforcement_mode": "off",
            "commands": [],
            "allowed_domains": [],
            "blocked_domains": [],
            "block_unknown_domains": False,
        },
        "execution": {
            "max_command_timeout_seconds": 30,
            "max_output_chars": 200000,
            "shell_workspace_containment": {
                "mode": "off",
                "exempt_commands": [],
                "log_paths": True,
            },
        },
        "backup_access": {"block_agent_tools": True, "allowed_tools": ["restore_backup"]},
        "restore": {"require_dry_run_before_apply": True, "confirmation_ttl_seconds": 300},
        "audit": {"backup_enabled": True, "backup_on_content_change_only": True, "max_versions_per_file": 5, "backup_retention_days": 30, "log_level": "verbose", "redact_patterns": []},
        "reports": {
            "enabled": True,
            "ingest_poll_interval_seconds": 5,
            "reconcile_interval_seconds": 3600,
            "retention_days": 30,
            "max_db_size_mb": 200,
            "prune_interval_seconds": 86400,
        },
    }


def _resolve_paths() -> dict[str, pathlib.Path]:
    return _resolve_paths_with_overrides()


def _resolve_paths_with_overrides(
    *,
    policy_path: str = "",
    approval_db_path: str = "",
    approval_hmac_key_path: str = "",
) -> dict[str, pathlib.Path]:
    policy_override = os.environ.get("AIRG_POLICY_PATH", "")
    db_override = os.environ.get("AIRG_APPROVAL_DB_PATH", "")
    key_override = os.environ.get("AIRG_APPROVAL_HMAC_KEY_PATH", "")
    log_override = os.environ.get("AIRG_LOG_PATH", "")
    reports_override = os.environ.get("AIRG_REPORTS_DB_PATH", "")
    policy_selected = policy_path or policy_override
    db_selected = approval_db_path or db_override
    key_selected = approval_hmac_key_path or key_override

    cfg_dir = pathlib.Path(policy_selected).expanduser().resolve().parent if policy_selected else _default_base_config_dir()
    state_dir = pathlib.Path(db_selected).expanduser().resolve().parent if db_selected else _default_base_state_dir()
    log_path = pathlib.Path(log_override).expanduser().resolve() if log_override else (state_dir / "activity.log").resolve()
    return {
        "config_dir": cfg_dir,
        "state_dir": state_dir,
        "policy_path": pathlib.Path(policy_selected if policy_selected else str(cfg_dir / "policy.json")).expanduser().resolve(),
        "approval_db_path": pathlib.Path(db_selected if db_selected else str(state_dir / "approvals.db")).expanduser().resolve(),
        "approval_hmac_key_path": pathlib.Path(key_selected if key_selected else str(state_dir / "approvals.db.hmac.key")).expanduser().resolve(),
        "log_path": log_path,
        "reports_db_path": pathlib.Path(reports_override).expanduser().resolve() if reports_override else (state_dir / "reports.db").resolve(),
    }


def _apply_runtime_env(paths: dict[str, pathlib.Path], *, force: bool = False) -> None:
    if force:
        os.environ["AIRG_POLICY_PATH"] = str(paths["policy_path"])
        os.environ["AIRG_APPROVAL_DB_PATH"] = str(paths["approval_db_path"])
        os.environ["AIRG_APPROVAL_HMAC_KEY_PATH"] = str(paths["approval_hmac_key_path"])
        os.environ["AIRG_LOG_PATH"] = str(paths["log_path"])
        os.environ["AIRG_REPORTS_DB_PATH"] = str(paths["reports_db_path"])
        return
    os.environ.setdefault("AIRG_POLICY_PATH", str(paths["policy_path"]))
    os.environ.setdefault("AIRG_APPROVAL_DB_PATH", str(paths["approval_db_path"]))
    os.environ.setdefault("AIRG_APPROVAL_HMAC_KEY_PATH", str(paths["approval_hmac_key_path"]))
    os.environ.setdefault("AIRG_LOG_PATH", str(paths["log_path"]))
    os.environ.setdefault("AIRG_REPORTS_DB_PATH", str(paths["reports_db_path"]))


def _ensure_hmac_key_file(path: pathlib.Path) -> None:
    if not path.exists() or path.stat().st_size == 0:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(secrets.token_hex(32) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _secure_permissions(paths: dict[str, pathlib.Path]) -> None:
    reports_db_path = paths.get("reports_db_path", paths["approval_db_path"].with_name("reports.db"))
    for directory in [
        paths["config_dir"],
        paths["state_dir"],
        paths["approval_db_path"].parent,
        paths["approval_hmac_key_path"].parent,
        paths["log_path"].parent,
        reports_db_path.parent,
    ]:
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
    if not paths["approval_db_path"].exists():
        paths["approval_db_path"].touch()
    _ensure_hmac_key_file(paths["approval_hmac_key_path"])
    if not paths["log_path"].exists():
        paths["log_path"].touch()
    if not reports_db_path.exists():
        reports_db_path.touch()
    for file_path in [paths["approval_db_path"], paths["log_path"], reports_db_path]:
        try:
            os.chmod(file_path, 0o600)
        except OSError:
            pass


def _ensure_policy_file(paths: dict[str, pathlib.Path], force: bool = False) -> None:
    policy_path = paths["policy_path"]
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    if policy_path.exists() and not force:
        return
    policy = _policy_template()
    # Ensure generated policy does not inherit machine-specific backup roots
    # from the repository template. Runtime state should stay user-local.
    audit = policy.get("audit")
    if not isinstance(audit, dict):
        audit = {}
        policy["audit"] = audit
    backup_root = (paths["state_dir"] / "backups").resolve()
    audit["backup_root"] = str(backup_root)
    policy_path.write_text(json.dumps(policy, indent=2) + "\n")
    try:
        os.chmod(policy_path, 0o600)
    except OSError:
        pass


def _init_runtime(
    force_policy: bool = False,
    *,
    policy_path: str = "",
    approval_db_path: str = "",
    approval_hmac_key_path: str = "",
    force_env: bool = False,
) -> dict[str, pathlib.Path]:
    paths = _resolve_paths_with_overrides(
        policy_path=policy_path,
        approval_db_path=approval_db_path,
        approval_hmac_key_path=approval_hmac_key_path,
    )
    _apply_runtime_env(paths, force=force_env)
    _secure_permissions(paths)
    _ensure_policy_file(paths, force=force_policy)

    print(f"[airg] config_dir={paths['config_dir']}")
    print(f"[airg] state_dir={paths['state_dir']}")
    print(f"[airg] AIRG_POLICY_PATH={paths['policy_path']}")
    print(f"[airg] AIRG_APPROVAL_DB_PATH={paths['approval_db_path']}")
    print(f"[airg] AIRG_APPROVAL_HMAC_KEY_PATH={paths['approval_hmac_key_path']}")
    print(f"[airg] AIRG_LOG_PATH={paths['log_path']}")
    print(f"[airg] AIRG_REPORTS_DB_PATH={paths['reports_db_path']}")
    print("[airg] Suggested MCP env block (copy into your client config):")
    print(
        json.dumps(
            {
                "command": "airg-server",
                "args": [],
                "env": {
                    "AIRG_AGENT_ID": os.environ.get("AIRG_AGENT_ID", "unknown-agent"),
                    "AIRG_WORKSPACE": "/absolute/path/to/agent-workspace",
                    "AIRG_POLICY_PATH": str(paths["policy_path"]),
                    "AIRG_APPROVAL_DB_PATH": str(paths["approval_db_path"]),
                    "AIRG_APPROVAL_HMAC_KEY_PATH": str(paths["approval_hmac_key_path"]),
                    "AIRG_LOG_PATH": str(paths["log_path"]),
                    "AIRG_REPORTS_DB_PATH": str(paths["reports_db_path"]),
                },
            },
            indent=2,
        )
    )
    print("[airg] Initialization complete.")
    return paths


def _looks_executable(command: str) -> bool:
    return shutil.which(command) is not None


def _preflight_checks() -> tuple[list[str], list[str]]:
    issues: list[str] = []
    warnings: list[str] = []
    major, minor = sys.version_info.major, sys.version_info.minor
    if (major, minor) < (3, 10):
        issues.append("Python >= 3.10 is required.")
    elif platform.system() == "Darwin" and (major, minor) < (3, 12):
        warnings.append("Python 3.12+ is recommended on macOS for smoother dependency installs.")
    if os.environ.get("VIRTUAL_ENV", "").strip() == "":
        warnings.append("No active virtual environment detected.")
    if not _looks_executable("pip") and importlib.util.find_spec("pip") is None:
        issues.append("pip is unavailable (not in PATH and python -m pip not available).")
    return issues, warnings


def _prompt_text(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{prompt}{suffix}: ").strip()
    return raw if raw else default


def _prompt_yes_no(prompt: str, default: bool = True) -> bool:
    marker = "Y/n" if default else "y/N"
    raw = input(f"{prompt} ({marker}): ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes"}


def _load_policy_from_path(path: pathlib.Path) -> dict[str, Any]:
    if not path.exists():
        return _policy_template()
    return json.loads(path.read_text())


def _save_policy_to_path(path: pathlib.Path, policy: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(policy, indent=2) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _merge_additional_workspaces(policy: dict[str, Any], paths: list[str]) -> dict[str, Any]:
    out = dict(policy)
    allowed = dict(out.get("allowed") or {})
    existing = [str(p) for p in (allowed.get("paths_whitelist") or [])]
    merged = sorted(set(existing + paths))
    allowed["paths_whitelist"] = merged
    out["allowed"] = allowed
    return out


def _apply_backup_override(policy: dict[str, Any], backup_root: str) -> dict[str, Any]:
    if not backup_root:
        return policy
    out = dict(policy)
    audit = dict(out.get("audit") or {})
    audit["backup_root"] = backup_root
    out["audit"] = audit
    return out


def _agent_config_payload(agent: str, workspace: str, paths: dict[str, pathlib.Path], agent_id: str) -> dict[str, Any]:
    reports_db_path = paths.get("reports_db_path", paths["approval_db_path"].with_name("reports.db"))
    env_block = {
        "AIRG_AGENT_ID": agent_id.strip() or "Unknown",
        "AIRG_WORKSPACE": workspace,
        "AIRG_POLICY_PATH": str(paths["policy_path"]),
        "AIRG_APPROVAL_DB_PATH": str(paths["approval_db_path"]),
        "AIRG_APPROVAL_HMAC_KEY_PATH": str(paths["approval_hmac_key_path"]),
        "AIRG_LOG_PATH": str(paths["log_path"]),
        "AIRG_REPORTS_DB_PATH": str(reports_db_path),
    }
    if agent in {"claude_desktop", "cursor", "generic"}:
        return {
            "mcpServers": {
                "ai-runtime-guard": {
                    "command": "airg-server",
                    "args": [],
                    "env": env_block,
                }
            }
        }
    return {
        "command": "airg-server",
        "args": [],
        "env": env_block,
    }


def _write_agent_config_outputs(agent: str, payload: dict[str, Any], out_dir: pathlib.Path) -> pathlib.Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{agent}.mcp.json"
    out_file.write_text(json.dumps(payload, indent=2) + "\n")
    return out_file


def _build_ui_assets() -> None:
    ui_dir_candidates = [
        pathlib.Path.cwd().resolve() / "ui_v3",
        _project_root() / "ui_v3",
    ]
    ui_dir = next((p for p in ui_dir_candidates if p.exists()), None)
    if ui_dir is None:
        raise SystemExit(
            "[airg][error] UI source directory not found. "
            "Run setup from the cloned repository root, or set AIRG_UI_DIST_PATH to an existing dist directory."
        )
    if shutil.which("npm") is None:
        raise SystemExit("[airg][error] npm is required to build GUI assets, but was not found in PATH.")

    print(f"[airg] Building GUI assets in {ui_dir} ...")
    try:
        subprocess.run(["npm", "install"], cwd=str(ui_dir), check=True)
        subprocess.run(["npm", "run", "build"], cwd=str(ui_dir), check=True)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"[airg][error] GUI build failed (exit={exc.returncode}).") from exc
    print("[airg] GUI build complete.")


def _runtime_env_for_process(
    *,
    paths: dict[str, pathlib.Path],
    workspace: pathlib.Path,
    agent_id: str,
) -> dict[str, str]:
    return {
        "AIRG_AGENT_ID": agent_id.strip() or "Unknown",
        "AIRG_WORKSPACE": str(workspace.resolve()),
        "AIRG_POLICY_PATH": str(paths["policy_path"]),
        "AIRG_APPROVAL_DB_PATH": str(paths["approval_db_path"]),
        "AIRG_APPROVAL_HMAC_KEY_PATH": str(paths["approval_hmac_key_path"]),
        "AIRG_LOG_PATH": str(paths["log_path"]),
        "AIRG_REPORTS_DB_PATH": str(paths["reports_db_path"]),
        "AIRG_UI_DIST_PATH": str(_resolve_ui_dist_path()),
    }


def _write_runtime_env_file(path: pathlib.Path, env: dict[str, str]) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f'{k}="{v}"' for k, v in sorted(env.items())]
    path.write_text("\n".join(lines) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _launchd_plist_path() -> pathlib.Path:
    return pathlib.Path.home() / "Library" / "LaunchAgents" / "com.ai-runtime-guard.ui.plist"


def _systemd_unit_path() -> pathlib.Path:
    return pathlib.Path.home() / ".config" / "systemd" / "user" / "airg-ui.service"


def _service_env_file(paths: dict[str, pathlib.Path]) -> pathlib.Path:
    return paths["config_dir"] / "runtime.env"


def _service_install(paths: dict[str, pathlib.Path], workspace: pathlib.Path, agent_id: str) -> None:
    env = _runtime_env_for_process(paths=paths, workspace=workspace, agent_id=agent_id)
    env_file = _write_runtime_env_file(_service_env_file(paths), env)
    python_exec = pathlib.Path(sys.executable).resolve()
    label = "com.ai-runtime-guard.ui"

    if _is_macos():
        plist_path = _launchd_plist_path()
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        plist = {
            "Label": label,
            "ProgramArguments": [str(python_exec), "-m", "airg_cli", "ui", "--with-runtime-env"],
            "RunAtLoad": True,
            "KeepAlive": True,
            "WorkingDirectory": str(_project_root()),
            "StandardOutPath": str(paths["state_dir"] / "airg-ui.service.out.log"),
            "StandardErrorPath": str(paths["state_dir"] / "airg-ui.service.err.log"),
            "EnvironmentVariables": env,
        }
        import plistlib
        with open(plist_path, "wb") as f:
            plistlib.dump(plist, f)
        print(f"[airg] launchd service file written: {plist_path}")
        return

    unit_path = _systemd_unit_path()
    unit_path.parent.mkdir(parents=True, exist_ok=True)
    unit = f"""[Unit]
Description=ai-runtime-guard UI service
After=network.target

[Service]
Type=simple
EnvironmentFile={env_file}
WorkingDirectory={_project_root()}
ExecStart={python_exec} -m airg_cli ui --with-runtime-env
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
"""
    unit_path.write_text(unit)
    print(f"[airg] systemd user unit written: {unit_path}")


def _service_start() -> None:
    if _is_macos():
        plist_path = _launchd_plist_path()
        uid = os.getuid()
        label = "com.ai-runtime-guard.ui"
        subprocess.run(["launchctl", "bootout", f"gui/{uid}/{label}"], check=False)
        subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(plist_path)], check=True)
        subprocess.run(["launchctl", "kickstart", "-k", f"gui/{uid}/{label}"], check=True)
        print("[airg] launchd service started.")
        return

    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "--user", "enable", "--now", "airg-ui.service"], check=True)
    print("[airg] systemd user service enabled and started.")


def _service_stop() -> None:
    if _is_macos():
        uid = os.getuid()
        label = "com.ai-runtime-guard.ui"
        subprocess.run(["launchctl", "bootout", f"gui/{uid}/{label}"], check=False)
        print("[airg] launchd service stopped.")
        return

    subprocess.run(["systemctl", "--user", "disable", "--now", "airg-ui.service"], check=False)
    print("[airg] systemd user service stopped.")


def _service_status() -> None:
    if _is_macos():
        uid = os.getuid()
        label = "com.ai-runtime-guard.ui"
        subprocess.run(["launchctl", "print", f"gui/{uid}/{label}"], check=False)
        return

    subprocess.run(["systemctl", "--user", "status", "--no-pager", "airg-ui.service"], check=False)


def _service_uninstall() -> None:
    _service_stop()
    if _is_macos():
        path = _launchd_plist_path()
        if path.exists():
            path.unlink()
        print("[airg] launchd service uninstalled.")
        return

    unit_path = _systemd_unit_path()
    if unit_path.exists():
        unit_path.unlink()
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    print("[airg] systemd user service uninstalled.")


def _run_setup(
    *,
    defaults: bool,
    yes: bool,
    workspace: str,
    policy_path: str,
    approval_db_path: str,
    approval_hmac_key_path: str,
    backup_root: str,
    agent: str,
    agent_id: str,
    force_policy: bool,
    use_gui: bool | None,
    out_dir: str,
) -> None:
    issues, warnings = _preflight_checks()
    for warning in warnings:
        print(f"[airg][warn] {warning}")
    if issues:
        for issue in issues:
            print(f"[airg][error] {issue}")
        raise SystemExit(1)

    selected_agent = (agent or "generic").strip().lower()
    if selected_agent not in {"claude_desktop", "cursor", "generic"}:
        print(f"[airg][warn] Unknown agent '{selected_agent}', falling back to generic.")
        selected_agent = "generic"

    selected_workspace = workspace.strip()
    selected_policy_path = policy_path.strip()
    selected_db_path = approval_db_path.strip()
    selected_key_path = approval_hmac_key_path.strip()
    selected_backup_root = backup_root.strip()
    selected_agent_id = agent_id.strip() or "Unknown"
    default_workspace = _default_workspace_path()
    selected_use_gui = use_gui

    if not yes:
        proceed = _prompt_yes_no("This will install ai-runtime-guard on your system. Continue?", default=True)
        if not proceed:
            raise SystemExit("[airg] Setup cancelled.")

    # Q1: workspace selection
    if defaults:
        selected_workspace = selected_workspace or str(default_workspace)
    else:
        existing = _prompt_yes_no("Do you already have a project workspace?", default=bool(selected_workspace))
        if existing:
            selected_workspace = _prompt_text("Workspace path", selected_workspace or str(default_workspace))
        else:
            create_default = _prompt_yes_no(
                f"Create default workspace at {default_workspace}?",
                default=True,
            )
            if create_default:
                selected_workspace = str(default_workspace)
            else:
                selected_workspace = _prompt_text("Workspace path to create", selected_workspace or str(pathlib.Path.home() / "airg-workspace"))

    workspace_path = pathlib.Path(selected_workspace).expanduser().resolve()
    if workspace_path.exists() and workspace_path.is_file():
        raise SystemExit(f"[airg][error] Workspace path is a file: {workspace_path}")
    if workspace_path.exists() and not defaults and not _prompt_yes_no(f"Reuse existing workspace at {workspace_path}?", default=True):
        alt = _prompt_text("Alternative workspace path", str(pathlib.Path.home() / "airg-workspace"))
        workspace_path = pathlib.Path(alt).expanduser().resolve()
    workspace_path.mkdir(parents=True, exist_ok=True)

    path_overrides = _init_runtime(
        force_policy=force_policy,
        policy_path=selected_policy_path,
        approval_db_path=selected_db_path,
        approval_hmac_key_path=selected_key_path,
        force_env=True,
    )
    os.environ["AIRG_WORKSPACE"] = str(workspace_path)

    # Q2: runtime path defaults vs custom
    if not defaults:
        use_default_runtime_paths = _prompt_yes_no("Use default paths for policy, approval DB/key, log, and backup?", default=not any([selected_policy_path, selected_db_path, selected_key_path, selected_backup_root]))
        if not use_default_runtime_paths:
            selected_policy_path = _prompt_text("Policy file path", str(path_overrides["policy_path"]))
            selected_db_path = _prompt_text("Approval DB path", str(path_overrides["approval_db_path"]))
            selected_key_path = _prompt_text("Approval HMAC key path", str(path_overrides["approval_hmac_key_path"]))
            selected_backup_root = _prompt_text("Backup root path", str(path_overrides["state_dir"] / "backups"))
            path_overrides = _init_runtime(
                force_policy=force_policy,
                policy_path=selected_policy_path,
                approval_db_path=selected_db_path,
                approval_hmac_key_path=selected_key_path,
                force_env=True,
            )
            os.environ["AIRG_WORKSPACE"] = str(workspace_path)

    current_policy = _load_policy_from_path(path_overrides["policy_path"])
    if selected_backup_root:
        backup_override = pathlib.Path(selected_backup_root).expanduser().resolve()
        current_policy = _apply_backup_override(current_policy, str(backup_override))
    _save_policy_to_path(path_overrides["policy_path"], current_policy)
    # Q3: GUI usage (optional)
    if selected_use_gui is None:
        selected_use_gui = _prompt_yes_no("Do you want to use the GUI for approvals, policy config, and reports?", default=False)

    payload = _agent_config_payload(selected_agent, str(workspace_path), path_overrides, selected_agent_id)
    output_root = pathlib.Path(out_dir).expanduser().resolve()
    output_path = _write_agent_config_outputs(selected_agent, payload, output_root)

    print(f"[airg] workspace={workspace_path}")
    print(f"[airg] policy={path_overrides['policy_path']}")
    print(f"[airg] approval_db={path_overrides['approval_db_path']}")
    print(f"[airg] approval_hmac_key={path_overrides['approval_hmac_key_path']}")
    print(f"[airg] log_path={path_overrides['log_path']}")
    print(f"[airg] reports_db={path_overrides['reports_db_path']}")
    print(f"[airg] agent config written: {output_path}")
    print("[airg] MCP config snippet:")
    print(json.dumps(payload, indent=2))
    if selected_use_gui:
        ui_dist = _resolve_ui_dist_path()
        if not (ui_dist / "index.html").exists():
            _build_ui_assets()
        _service_install(path_overrides, workspace_path, selected_agent_id)
        _service_start()
        print("[airg] GUI service installed and started.")
    print("[airg] Running doctor checks...")
    main_doctor()
    print("[airg] Setup complete.")
    if selected_use_gui:
        print("[airg] Web UI: http://127.0.0.1:5001")
    else:
        print("[airg] GUI not enabled. You can run `airg-ui` manually anytime.")


def _warn_if_paths_inside_unsafe_roots(paths: dict[str, pathlib.Path]) -> None:
    workspace = pathlib.Path(os.environ.get("AIRG_WORKSPACE", str(_project_root()))).expanduser().resolve()
    project_root = _project_root()
    checks = [
        ("policy_path", paths["policy_path"]),
        ("approval_db_path", paths["approval_db_path"]),
        ("approval_hmac_key_path", paths["approval_hmac_key_path"]),
        ("log_path", paths["log_path"]),
        ("reports_db_path", paths["reports_db_path"]),
    ]
    for label, target in checks:
        try:
            resolved = target.resolve()
            if resolved.is_relative_to(workspace):
                print(
                    f"[airg][warn] {label} is inside AIRG_WORKSPACE ({workspace}). "
                    "Set explicit AIRG_* env vars in MCP config to keep runtime state outside workspace."
                )
            if resolved.is_relative_to(project_root):
                print(
                    f"[airg][warn] {label} is inside project directory ({project_root}). "
                    "Set explicit AIRG_* env vars in MCP config to avoid repo-local runtime state."
                )
        except Exception:
            # Non-fatal path resolution issues should not block startup.
            pass


def main_init() -> None:
    _init_runtime(force_policy=False)


def main_setup_entrypoint() -> None:
    parser = argparse.ArgumentParser(description="Guided setup for ai-runtime-guard")
    parser.add_argument("--defaults", action="store_true", help="Use defaults and skip interactive path questions.")
    parser.add_argument("--yes", action="store_true", help="Skip install confirmation prompt.")
    parser.add_argument("--workspace", default="", help="Primary workspace path.")
    parser.add_argument("--policy-path", default="", help="Override AIRG_POLICY_PATH.")
    parser.add_argument("--approval-db-path", default="", help="Override AIRG_APPROVAL_DB_PATH.")
    parser.add_argument("--approval-hmac-key-path", default="", help="Override AIRG_APPROVAL_HMAC_KEY_PATH.")
    parser.add_argument("--backup-root", default="", help="Override audit.backup_root.")
    parser.add_argument("--agent", default="generic", help="Agent target: claude_desktop, cursor, generic.")
    parser.add_argument("--agent-id", default="Unknown", help="Agent identifier to include in runtime logs.")
    parser.add_argument("--force-policy", action="store_true", help="Regenerate policy file from template before applying wizard updates.")
    parser.add_argument("--gui", action="store_true", help="Enable GUI service setup (install/start user service).")
    parser.add_argument("--no-gui", action="store_true", help="Disable GUI service setup.")
    parser.add_argument("--out-dir", default="./out/mcp-configs", help="Output directory for generated MCP config snippets.")
    args = parser.parse_args()
    if args.gui and args.no_gui:
        raise SystemExit("[airg][error] --gui and --no-gui are mutually exclusive.")
    use_gui = True if args.gui else (False if args.no_gui else None)
    _run_setup(
        defaults=args.defaults,
        yes=args.yes,
        workspace=args.workspace,
        policy_path=args.policy_path,
        approval_db_path=args.approval_db_path,
        approval_hmac_key_path=args.approval_hmac_key_path,
        backup_root=args.backup_root,
        agent=args.agent,
        agent_id=args.agent_id,
        force_policy=args.force_policy,
        use_gui=use_gui,
        out_dir=args.out_dir,
    )


def main_server() -> None:
    paths = _resolve_paths()
    _apply_runtime_env(paths)
    _secure_permissions(paths)
    _ensure_policy_file(paths, force=False)
    _warn_if_paths_inside_unsafe_roots(paths)
    runpy.run_module("server", run_name="__main__")


def main_ui(with_runtime_env: bool | None = None) -> None:
    if with_runtime_env is None:
        parser = argparse.ArgumentParser(description="Run AIRG local UI backend")
        parser.add_argument(
            "--with-runtime-env",
            action="store_true",
            help="Initialize and print resolved AIRG runtime paths before launching UI.",
        )
        args = parser.parse_args()
        with_runtime_env = bool(args.with_runtime_env)

    if with_runtime_env:
        paths = _init_runtime(force_policy=False, force_env=False)
        print("[airg] UI started with resolved runtime env values.")
    else:
        paths = _resolve_paths()
        _apply_runtime_env(paths)
        _secure_permissions(paths)
        _ensure_policy_file(paths, force=False)
    _warn_if_paths_inside_unsafe_roots(paths)
    os.environ.setdefault("AIRG_UI_DIST_PATH", str(_resolve_ui_dist_path()))
    runpy.run_module("ui.backend_flask", run_name="__main__")


def _port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def main_up() -> None:
    paths = _resolve_paths()
    _apply_runtime_env(paths)
    _secure_permissions(paths)
    _ensure_policy_file(paths, force=False)
    _warn_if_paths_inside_unsafe_roots(paths)

    host = os.environ.get("AIRG_FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("AIRG_FLASK_PORT", "5001"))
    if _port_open(host, port):
        print(f"[airg] UI backend already listening on http://{host}:{port}")
    else:
        def _run_ui() -> None:
            from ui.backend_flask import app

            app.run(host=host, port=port, debug=False, use_reloader=False)

        t = threading.Thread(target=_run_ui, name="airg-ui-sidecar", daemon=True)
        t.start()
        time.sleep(0.15)
        print(f"[airg] UI sidecar started at http://{host}:{port}")

    print("[airg] Starting MCP server (stdio)...")
    runpy.run_module("server", run_name="__main__")


def _fmt_mode(path: pathlib.Path) -> str:
    try:
        return oct(stat.S_IMODE(path.stat().st_mode))
    except OSError:
        return "n/a"


def main_doctor() -> None:
    paths = _resolve_paths()
    _apply_runtime_env(paths)
    issues: list[str] = []
    warnings: list[str] = []
    backup_root = (paths["state_dir"] / "backups").resolve()
    if paths["policy_path"].exists():
        try:
            policy_doc = json.loads(paths["policy_path"].read_text())
            audit_doc = policy_doc.get("audit", {}) if isinstance(policy_doc, dict) else {}
            configured_backup = str(audit_doc.get("backup_root", "")).strip()
            if configured_backup:
                backup_root = pathlib.Path(configured_backup).expanduser().resolve()
        except Exception as exc:
            warnings.append(f"Could not read backup_root from policy: {exc}")

    print("[airg] Doctor checks")
    print(f"[airg] policy_path={paths['policy_path']}")
    print(f"[airg] approval_db_path={paths['approval_db_path']}")
    print(f"[airg] approval_hmac_key_path={paths['approval_hmac_key_path']}")
    print(f"[airg] log_path={paths['log_path']}")
    print(f"[airg] reports_db_path={paths['reports_db_path']}")
    print(f"[airg] backup_root={backup_root}")
    print(f"[airg] workspace={pathlib.Path(os.environ.get('AIRG_WORKSPACE', str(_project_root()))).expanduser().resolve()}")
    print(f"[airg] agent_id={os.environ.get('AIRG_AGENT_ID', 'Unknown')}")

    # Policy file
    if not paths["policy_path"].exists():
        issues.append("Policy file missing. Run `airg-init`.")
    else:
        try:
            json.loads(paths["policy_path"].read_text())
            print("[ok] policy.json is readable and valid JSON")
        except Exception as exc:
            issues.append(f"Policy file is invalid JSON: {exc}")

    # Permission checks
    for d in [paths["approval_db_path"].parent, paths["approval_hmac_key_path"].parent]:
        if d.exists():
            mode = stat.S_IMODE(d.stat().st_mode)
            if mode & 0o077:
                warnings.append(f"Directory too open: {d} mode={oct(mode)} (recommended 0o700)")
    for f in [paths["approval_db_path"], paths["approval_hmac_key_path"], paths["log_path"], paths["reports_db_path"]]:
        if f.exists():
            mode = stat.S_IMODE(f.stat().st_mode)
            if mode != 0o600:
                warnings.append(f"File permissions weak: {f} mode={oct(mode)} (recommended 0o600)")
        else:
            warnings.append(f"File missing (will be created at runtime): {f}")
    if paths["approval_hmac_key_path"].exists() and paths["approval_hmac_key_path"].stat().st_size == 0:
        warnings.append(
            f"HMAC key is empty: {paths['approval_hmac_key_path']} (approval signatures will fail across processes)"
        )

    # Workspace overlap check
    workspace = pathlib.Path(os.environ.get("AIRG_WORKSPACE", str(_project_root()))).expanduser().resolve()
    for p, label in [
        (paths["policy_path"], "policy_path"),
        (paths["approval_db_path"], "approval_db_path"),
        (paths["approval_hmac_key_path"], "approval_hmac_key_path"),
        (paths["log_path"], "log_path"),
        (paths["reports_db_path"], "reports_db_path"),
    ]:
        try:
            if p.resolve().is_relative_to(workspace):
                warnings.append(f"{label} is inside AIRG_WORKSPACE ({workspace}); move it outside for stronger hardening.")
        except Exception:
            pass

    # Project directory overlap check.
    project_root = _project_root()
    for p, label in [
        (paths["policy_path"], "policy_path"),
        (paths["approval_db_path"], "approval_db_path"),
        (paths["approval_hmac_key_path"], "approval_hmac_key_path"),
        (paths["log_path"], "log_path"),
        (paths["reports_db_path"], "reports_db_path"),
    ]:
        try:
            if p.resolve().is_relative_to(project_root):
                warnings.append(f"{label} is inside project directory ({project_root}); move to user-local runtime paths.")
        except Exception:
            pass
    try:
        if backup_root.is_relative_to(project_root):
            warnings.append(f"backup_root is inside project directory ({project_root}); move to user-local runtime paths.")
    except Exception:
        pass
    if "site-packages" in backup_root.parts:
        warnings.append(
            f"backup_root points inside site-packages ({backup_root}); this is unsafe for installed mode. "
            "Set audit.backup_root to a user-local runtime path."
        )

    # UI build check
    ui_dist = _resolve_ui_dist_path()
    print(f"[airg] ui_dist_path={ui_dist}")
    if (ui_dist / "index.html").exists():
        print(f"[ok] UI build detected at {ui_dist}")
    else:
        warnings.append(
            "UI build not found. Build with `cd ui_v3 && npm install && npm run build`, "
            "or set AIRG_UI_DIST_PATH to a directory containing index.html."
        )
    legacy_ui_path = _project_root() / "src" / "ui" / "static" / "index.html"
    if legacy_ui_path.exists() and not (ui_dist / "index.html").exists():
        warnings.append(
            "Legacy UI assets are present but v3 dist is missing. AIRG UI now expects v3 build artifacts."
        )

    # Flask port check
    host = os.environ.get("AIRG_FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("AIRG_FLASK_PORT", "5001"))
    if _port_open(host, port):
        print(f"[ok] UI/backend is listening on http://{host}:{port}")
    else:
        print(f"[info] UI/backend is not currently listening on http://{host}:{port}")

    # Reports DB check
    try:
        import reports as reports_store

        reports_store.init_reports_store(paths["reports_db_path"])
        status = reports_store.get_status(paths["reports_db_path"])
        print(f"[ok] reports db is ready at {paths['reports_db_path']}")
        lag_warn_seconds = 30
        try:
            policy_for_lag = json.loads(paths["policy_path"].read_text())
            lag_warn_seconds = max(30, int(policy_for_lag.get("reports", {}).get("ingest_poll_interval_seconds", 5)) * 4)
        except Exception:
            pass
        last_ingested = status.get("last_ingested_at")
        if last_ingested:
            try:
                last_ts = datetime.datetime.fromisoformat(str(last_ingested).replace("Z", "+00:00"))
                lag = (datetime.datetime.now(datetime.UTC) - last_ts).total_seconds()
                if lag > lag_warn_seconds:
                    warnings.append(
                        f"Reports ingest lag is {int(lag)}s (threshold {lag_warn_seconds}s). "
                        "Start UI backend or trigger reports sync."
                    )
            except Exception:
                warnings.append("Reports db last_ingested_at is present but unreadable.")
    except Exception as exc:
        warnings.append(f"Reports DB check failed: {exc}")

    for w in warnings:
        print(f"[warn] {w}")
    for i in issues:
        print(f"[error] {i}")

    if issues:
        raise SystemExit(1)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "service":
        sys.argv = [sys.argv[0], *sys.argv[2:]]
        main_service()
        return

    parser = argparse.ArgumentParser(description="ai-runtime-guard CLI")
    parser.add_argument("command", choices=["init", "setup", "server", "ui", "up", "doctor"], help="Command to run")
    parser.add_argument("--force-policy", action="store_true", help="Used with 'init': overwrite existing policy template")
    parser.add_argument("--defaults", action="store_true", help="Setup mode: use defaults and skip interactive path questions.")
    parser.add_argument("--yes", action="store_true", help="Setup mode: skip install confirmation prompt.")
    parser.add_argument("--workspace", default="", help="Setup mode: primary workspace path.")
    parser.add_argument("--policy-path", default="", help="Setup mode: override AIRG_POLICY_PATH.")
    parser.add_argument("--approval-db-path", default="", help="Setup mode: override AIRG_APPROVAL_DB_PATH.")
    parser.add_argument("--approval-hmac-key-path", default="", help="Setup mode: override AIRG_APPROVAL_HMAC_KEY_PATH.")
    parser.add_argument("--backup-root", default="", help="Setup mode: override audit.backup_root.")
    parser.add_argument("--agent", default="generic", help="Setup mode: claude_desktop, cursor, generic.")
    parser.add_argument("--agent-id", default="Unknown", help="Setup mode: agent identifier for logs.")
    parser.add_argument("--gui", action="store_true", help="Setup mode: enable GUI service setup.")
    parser.add_argument("--no-gui", action="store_true", help="Setup mode: disable GUI service setup.")
    parser.add_argument("--out-dir", default="./out/mcp-configs", help="Setup mode: output directory for generated MCP config.")
    parser.add_argument(
        "--with-runtime-env",
        action="store_true",
        help="Used with 'ui': initialize and print resolved runtime env values before launching.",
    )
    args = parser.parse_args()

    if args.command == "setup":
        if args.gui and args.no_gui:
            raise SystemExit("[airg][error] --gui and --no-gui are mutually exclusive.")
        use_gui = True if args.gui else (False if args.no_gui else None)
        _run_setup(
            defaults=args.defaults,
            yes=args.yes,
            workspace=args.workspace,
            policy_path=args.policy_path,
            approval_db_path=args.approval_db_path,
            approval_hmac_key_path=args.approval_hmac_key_path,
            backup_root=args.backup_root,
            agent=args.agent,
            agent_id=args.agent_id,
            force_policy=args.force_policy,
            use_gui=use_gui,
            out_dir=args.out_dir,
        )
        return
    if args.command == "init":
        _init_runtime(force_policy=args.force_policy)
        return
    if args.command == "server":
        main_server()
        return
    if args.command == "ui":
        main_ui(with_runtime_env=args.with_runtime_env)
        return
    if args.command == "doctor":
        main_doctor()
        return
    main_up()


def main_up_entrypoint() -> None:
    main_up()


def main_service() -> None:
    parser = argparse.ArgumentParser(description="Manage ai-runtime-guard GUI user service")
    parser.add_argument("action", choices=["install", "start", "stop", "restart", "status", "uninstall"])
    parser.add_argument("--workspace", default=str(_default_workspace_path()), help="Workspace path used by GUI service.")
    parser.add_argument("--agent-id", default=os.environ.get("AIRG_AGENT_ID", "Unknown"), help="Agent identifier used by GUI service.")
    parser.add_argument("--policy-path", default="", help="Override AIRG_POLICY_PATH for service env.")
    parser.add_argument("--approval-db-path", default="", help="Override AIRG_APPROVAL_DB_PATH for service env.")
    parser.add_argument("--approval-hmac-key-path", default="", help="Override AIRG_APPROVAL_HMAC_KEY_PATH for service env.")
    args = parser.parse_args()

    paths = _resolve_paths_with_overrides(
        policy_path=args.policy_path,
        approval_db_path=args.approval_db_path,
        approval_hmac_key_path=args.approval_hmac_key_path,
    )
    _apply_runtime_env(paths, force=True)
    _secure_permissions(paths)
    _ensure_policy_file(paths, force=False)
    workspace = pathlib.Path(args.workspace).expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    if args.action == "install":
        _service_install(paths, workspace, args.agent_id)
        return
    if args.action == "start":
        _service_start()
        return
    if args.action == "stop":
        _service_stop()
        return
    if args.action == "restart":
        _service_stop()
        _service_start()
        return
    if args.action == "status":
        _service_status()
        return
    _service_uninstall()


if __name__ == "__main__":
    main()
