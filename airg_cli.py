import argparse
import json
import importlib.util
import os
import pathlib
import platform
import runpy
import shutil
import socket
import stat
import sys
import threading
import time
from typing import Any


def _is_macos() -> bool:
    return platform.system() == "Darwin"


def _candidate_ui_dist_paths() -> list[pathlib.Path]:
    # Search both source-tree and installed-package style locations.
    here = pathlib.Path(__file__).resolve().parent
    env_ui_dist = os.environ.get("AIRG_UI_DIST_PATH", "").strip()
    candidates: list[pathlib.Path] = []
    if env_ui_dist:
        candidates.append(pathlib.Path(env_ui_dist).expanduser())
    return [
        *candidates,
        here / "ui_v3" / "dist",
        here / "ui" / "static",
        pathlib.Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages" / "ui_v3" / "dist",
        pathlib.Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages" / "ui" / "static",
    ]


def _resolve_ui_dist_path() -> pathlib.Path:
    for candidate in _candidate_ui_dist_paths():
        resolved = candidate.expanduser()
        if (resolved / "index.html").exists():
            return resolved.resolve()
    # Keep first source-tree path as deterministic fallback for warnings.
    return (pathlib.Path(__file__).resolve().parent / "ui_v3" / "dist").resolve()


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


def _policy_template() -> dict[str, Any]:
    source = pathlib.Path(__file__).with_name("policy.json")
    if source.exists():
        return json.loads(source.read_text())
    return {
        "blocked": {"commands": ["rm -rf", "mkfs", "shutdown", "reboot", "format", "dd"], "paths": [".env", ".ssh", "/etc/passwd"], "extensions": [".pem", ".key"]},
        "requires_confirmation": {"commands": [], "paths": [], "session_whitelist_enabled": True, "approval_security": {"max_failed_attempts_per_token": 5, "failed_attempt_window_seconds": 600, "token_ttl_seconds": 600}},
        "requires_simulation": {"commands": [], "bulk_file_threshold": 10, "max_retries": 3, "cumulative_budget": {"enabled": False}},
        "allowed": {"paths_whitelist": [], "max_files_per_operation": 10, "max_file_size_mb": 10, "max_directory_depth": 5},
        "network": {"enforcement_mode": "off", "commands": [], "allowed_domains": [], "blocked_domains": [], "max_payload_size_kb": 1024},
        "execution": {"max_command_timeout_seconds": 30, "max_output_chars": 200000},
        "backup_access": {"block_agent_tools": True, "allowed_tools": ["restore_backup"]},
        "restore": {"require_dry_run_before_apply": True, "confirmation_ttl_seconds": 300},
        "audit": {"backup_enabled": True, "backup_on_content_change_only": True, "max_versions_per_file": 5, "backup_retention_days": 30, "log_level": "verbose", "redact_patterns": []},
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
    policy_selected = policy_path or policy_override
    db_selected = approval_db_path or db_override
    key_selected = approval_hmac_key_path or key_override

    cfg_dir = pathlib.Path(policy_selected).expanduser().resolve().parent if policy_selected else _default_base_config_dir()
    state_dir = pathlib.Path(db_selected).expanduser().resolve().parent if db_selected else _default_base_state_dir()
    return {
        "config_dir": cfg_dir,
        "state_dir": state_dir,
        "policy_path": pathlib.Path(policy_selected if policy_selected else str(cfg_dir / "policy.json")).expanduser().resolve(),
        "approval_db_path": pathlib.Path(db_selected if db_selected else str(state_dir / "approvals.db")).expanduser().resolve(),
        "approval_hmac_key_path": pathlib.Path(key_selected if key_selected else str(state_dir / "approvals.db.hmac.key")).expanduser().resolve(),
    }


def _apply_runtime_env(paths: dict[str, pathlib.Path], *, force: bool = False) -> None:
    if force:
        os.environ["AIRG_POLICY_PATH"] = str(paths["policy_path"])
        os.environ["AIRG_APPROVAL_DB_PATH"] = str(paths["approval_db_path"])
        os.environ["AIRG_APPROVAL_HMAC_KEY_PATH"] = str(paths["approval_hmac_key_path"])
        return
    os.environ.setdefault("AIRG_POLICY_PATH", str(paths["policy_path"]))
    os.environ.setdefault("AIRG_APPROVAL_DB_PATH", str(paths["approval_db_path"]))
    os.environ.setdefault("AIRG_APPROVAL_HMAC_KEY_PATH", str(paths["approval_hmac_key_path"]))


def _secure_permissions(paths: dict[str, pathlib.Path]) -> None:
    for directory in [paths["config_dir"], paths["state_dir"], paths["approval_db_path"].parent, paths["approval_hmac_key_path"].parent]:
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
    for file_path in [paths["approval_db_path"], paths["approval_hmac_key_path"]]:
        if not file_path.exists():
            file_path.touch()
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
    print("[airg] Suggested MCP env block (copy into your client config):")
    print(
        json.dumps(
            {
                "command": "airg-server",
                "args": [],
                "env": {
                    "AIRG_WORKSPACE": "/absolute/path/to/agent-workspace",
                    "AIRG_POLICY_PATH": str(paths["policy_path"]),
                    "AIRG_APPROVAL_DB_PATH": str(paths["approval_db_path"]),
                    "AIRG_APPROVAL_HMAC_KEY_PATH": str(paths["approval_hmac_key_path"]),
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


def _agent_config_payload(agent: str, workspace: str, paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    env_block = {
        "AIRG_WORKSPACE": workspace,
        "AIRG_POLICY_PATH": str(paths["policy_path"]),
        "AIRG_APPROVAL_DB_PATH": str(paths["approval_db_path"]),
        "AIRG_APPROVAL_HMAC_KEY_PATH": str(paths["approval_hmac_key_path"]),
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


def _run_setup(
    *,
    quickstart: bool,
    yes: bool,
    workspace: str,
    policy_path: str,
    approval_db_path: str,
    approval_hmac_key_path: str,
    backup_root: str,
    additional_workspaces: str,
    agent: str,
    force_policy: bool,
    enable_ui: str,
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
    selected_additional = [p.strip() for p in additional_workspaces.split(",") if p.strip()]

    if not yes and not quickstart:
        selected_workspace = _prompt_text("Primary workspace path", selected_workspace or str(pathlib.Path.home() / "airg-workspace"))
        selected_policy_path = _prompt_text("Custom policy path (blank=default)", selected_policy_path)
        selected_db_path = _prompt_text("Custom approval DB path (blank=default)", selected_db_path)
        selected_key_path = _prompt_text("Custom approval HMAC key path (blank=default)", selected_key_path)
        selected_backup_root = _prompt_text("Custom backup root path (blank=default)", selected_backup_root)
        selected_enable_ui = _prompt_yes_no("Do you want to use the Policy GUI?", default=True)
        enable_ui = "yes" if selected_enable_ui else "no"
        if _prompt_yes_no("Add additional workspace paths to whitelist?", default=False):
            raw_extra = _prompt_text("Comma-separated absolute paths", ",".join(selected_additional))
            selected_additional = [p.strip() for p in raw_extra.split(",") if p.strip()]
        selected_agent = _prompt_text("Agent type (claude_desktop/cursor/generic)", selected_agent)
        if selected_agent not in {"claude_desktop", "cursor", "generic"}:
            selected_agent = "generic"

    if not selected_workspace:
        selected_workspace = str(pathlib.Path.home() / "airg-workspace")
    workspace_path = pathlib.Path(selected_workspace).expanduser().resolve()
    workspace_path.mkdir(parents=True, exist_ok=True)

    path_overrides = _init_runtime(
        force_policy=force_policy,
        policy_path=selected_policy_path,
        approval_db_path=selected_db_path,
        approval_hmac_key_path=selected_key_path,
        force_env=True,
    )
    os.environ["AIRG_WORKSPACE"] = str(workspace_path)

    current_policy = _load_policy_from_path(path_overrides["policy_path"])
    current_policy = _merge_additional_workspaces(current_policy, [str(pathlib.Path(p).expanduser().resolve()) for p in selected_additional if pathlib.Path(p).expanduser().is_absolute()])
    if selected_backup_root:
        backup_override = pathlib.Path(selected_backup_root).expanduser().resolve()
        current_policy = _apply_backup_override(current_policy, str(backup_override))
    _save_policy_to_path(path_overrides["policy_path"], current_policy)

    payload = _agent_config_payload(selected_agent, str(workspace_path), path_overrides)
    output_root = pathlib.Path(out_dir).expanduser().resolve()
    output_path = _write_agent_config_outputs(selected_agent, payload, output_root)

    print(f"[airg] workspace={workspace_path}")
    print(f"[airg] policy={path_overrides['policy_path']}")
    print(f"[airg] approval_db={path_overrides['approval_db_path']}")
    print(f"[airg] approval_hmac_key={path_overrides['approval_hmac_key_path']}")
    print(f"[airg] agent config written: {output_path}")
    print("[airg] MCP config snippet:")
    print(json.dumps(payload, indent=2))
    print("[airg] Running doctor checks...")
    main_doctor()
    print("[airg] Setup complete.")
    if enable_ui.lower() in {"yes", "true", "1"}:
        print("[airg] Next: run `airg-ui` for policy management UI.")


def _warn_if_paths_inside_unsafe_roots(paths: dict[str, pathlib.Path]) -> None:
    workspace = pathlib.Path(os.environ.get("AIRG_WORKSPACE", str(pathlib.Path(__file__).resolve().parent))).expanduser().resolve()
    project_root = pathlib.Path(__file__).resolve().parent
    checks = [
        ("policy_path", paths["policy_path"]),
        ("approval_db_path", paths["approval_db_path"]),
        ("approval_hmac_key_path", paths["approval_hmac_key_path"]),
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
    parser.add_argument("--quickstart", action="store_true", help="Use defaults with minimal prompts.")
    parser.add_argument("--yes", action="store_true", help="Non-interactive mode (accept defaults).")
    parser.add_argument("--workspace", default="", help="Primary workspace path.")
    parser.add_argument("--policy-path", default="", help="Override AIRG_POLICY_PATH.")
    parser.add_argument("--approval-db-path", default="", help="Override AIRG_APPROVAL_DB_PATH.")
    parser.add_argument("--approval-hmac-key-path", default="", help="Override AIRG_APPROVAL_HMAC_KEY_PATH.")
    parser.add_argument("--backup-root", default="", help="Override audit.backup_root.")
    parser.add_argument("--additional-workspaces", default="", help="Comma-separated absolute workspace paths to whitelist.")
    parser.add_argument("--agent", default="generic", help="Agent target: claude_desktop, cursor, generic.")
    parser.add_argument("--force-policy", action="store_true", help="Regenerate policy file from template before applying wizard updates.")
    parser.add_argument("--enable-ui", default="yes", choices=["yes", "no"], help="Whether to keep UI management workflow enabled.")
    parser.add_argument("--out-dir", default="./out/mcp-configs", help="Output directory for generated MCP config snippets.")
    args = parser.parse_args()
    _run_setup(
        quickstart=args.quickstart,
        yes=args.yes,
        workspace=args.workspace,
        policy_path=args.policy_path,
        approval_db_path=args.approval_db_path,
        approval_hmac_key_path=args.approval_hmac_key_path,
        backup_root=args.backup_root,
        additional_workspaces=args.additional_workspaces,
        agent=args.agent,
        force_policy=args.force_policy,
        enable_ui=args.enable_ui,
        out_dir=args.out_dir,
    )


def main_server() -> None:
    paths = _resolve_paths()
    _apply_runtime_env(paths)
    _secure_permissions(paths)
    _ensure_policy_file(paths, force=False)
    _warn_if_paths_inside_unsafe_roots(paths)
    runpy.run_module("server", run_name="__main__")


def main_ui() -> None:
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

    print("[airg] Doctor checks")
    print(f"[airg] policy_path={paths['policy_path']}")
    print(f"[airg] approval_db_path={paths['approval_db_path']}")
    print(f"[airg] approval_hmac_key_path={paths['approval_hmac_key_path']}")

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
    for f in [paths["approval_db_path"], paths["approval_hmac_key_path"]]:
        if f.exists():
            mode = stat.S_IMODE(f.stat().st_mode)
            if mode != 0o600:
                warnings.append(f"File permissions weak: {f} mode={oct(mode)} (recommended 0o600)")
        else:
            warnings.append(f"File missing (will be created at runtime): {f}")

    # Workspace overlap check
    workspace = pathlib.Path(os.environ.get("AIRG_WORKSPACE", str(pathlib.Path(__file__).resolve().parent))).expanduser().resolve()
    for p, label in [
        (paths["policy_path"], "policy_path"),
        (paths["approval_db_path"], "approval_db_path"),
        (paths["approval_hmac_key_path"], "approval_hmac_key_path"),
    ]:
        try:
            if p.resolve().is_relative_to(workspace):
                warnings.append(f"{label} is inside AIRG_WORKSPACE ({workspace}); move it outside for stronger hardening.")
        except Exception:
            pass

    # Project directory overlap check.
    project_root = pathlib.Path(__file__).resolve().parent
    for p, label in [
        (paths["policy_path"], "policy_path"),
        (paths["approval_db_path"], "approval_db_path"),
        (paths["approval_hmac_key_path"], "approval_hmac_key_path"),
    ]:
        try:
            if p.resolve().is_relative_to(project_root):
                warnings.append(f"{label} is inside project directory ({project_root}); move to user-local runtime paths.")
        except Exception:
            pass

    # UI build check
    ui_dist = _resolve_ui_dist_path()
    if (ui_dist / "index.html").exists():
        print(f"[ok] UI build detected at {ui_dist}")
    else:
        warnings.append(
            "UI build not found. Build with `cd ui_v3 && npm install && npm run build`, "
            "or set AIRG_UI_DIST_PATH to a directory containing index.html."
        )

    # Flask port check
    host = os.environ.get("AIRG_FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("AIRG_FLASK_PORT", "5001"))
    if _port_open(host, port):
        print(f"[ok] UI/backend is listening on http://{host}:{port}")
    else:
        print(f"[info] UI/backend is not currently listening on http://{host}:{port}")

    for w in warnings:
        print(f"[warn] {w}")
    for i in issues:
        print(f"[error] {i}")

    if issues:
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="ai-runtime-guard CLI")
    parser.add_argument("command", choices=["init", "setup", "server", "ui", "up", "doctor"], help="Command to run")
    parser.add_argument("--force-policy", action="store_true", help="Used with 'init': overwrite existing policy template")
    parser.add_argument("--wizard", action="store_true", help="Used with 'init': run guided setup wizard.")
    parser.add_argument("--quickstart", action="store_true", help="Wizard mode: use defaults with minimal prompts.")
    parser.add_argument("--yes", action="store_true", help="Wizard mode: non-interactive defaults.")
    parser.add_argument("--workspace", default="", help="Wizard mode: primary workspace path.")
    parser.add_argument("--policy-path", default="", help="Wizard mode: override AIRG_POLICY_PATH.")
    parser.add_argument("--approval-db-path", default="", help="Wizard mode: override AIRG_APPROVAL_DB_PATH.")
    parser.add_argument("--approval-hmac-key-path", default="", help="Wizard mode: override AIRG_APPROVAL_HMAC_KEY_PATH.")
    parser.add_argument("--backup-root", default="", help="Wizard mode: override audit.backup_root.")
    parser.add_argument("--additional-workspaces", default="", help="Wizard mode: comma-separated absolute workspace paths.")
    parser.add_argument("--agent", default="generic", help="Wizard mode: claude_desktop, cursor, generic.")
    parser.add_argument("--enable-ui", default="yes", choices=["yes", "no"], help="Wizard mode: UI workflow preference.")
    parser.add_argument("--out-dir", default="./out/mcp-configs", help="Wizard mode: output directory for generated MCP config.")
    args = parser.parse_args()

    if args.command == "setup" or (args.command == "init" and args.wizard):
        _run_setup(
            quickstart=args.quickstart,
            yes=args.yes,
            workspace=args.workspace,
            policy_path=args.policy_path,
            approval_db_path=args.approval_db_path,
            approval_hmac_key_path=args.approval_hmac_key_path,
            backup_root=args.backup_root,
            additional_workspaces=args.additional_workspaces,
            agent=args.agent,
            force_policy=args.force_policy,
            enable_ui=args.enable_ui,
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
        main_ui()
        return
    if args.command == "doctor":
        main_doctor()
        return
    main_up()


def main_up_entrypoint() -> None:
    main_up()


if __name__ == "__main__":
    main()
