import argparse
import json
import os
import pathlib
import platform
import runpy
import socket
import stat
import threading
import time
from typing import Any


def _is_macos() -> bool:
    return platform.system() == "Darwin"


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
    policy_override = os.environ.get("AIRG_POLICY_PATH", "")
    db_override = os.environ.get("AIRG_APPROVAL_DB_PATH", "")
    key_override = os.environ.get("AIRG_APPROVAL_HMAC_KEY_PATH", "")
    cfg_dir = pathlib.Path(policy_override).expanduser().resolve().parent if policy_override else _default_base_config_dir()
    state_dir = pathlib.Path(db_override).expanduser().resolve().parent if db_override else _default_base_state_dir()
    return {
        "config_dir": cfg_dir,
        "state_dir": state_dir,
        "policy_path": pathlib.Path(policy_override if policy_override else str(cfg_dir / "policy.json")).expanduser().resolve(),
        "approval_db_path": pathlib.Path(db_override if db_override else str(state_dir / "approvals.db")).expanduser().resolve(),
        "approval_hmac_key_path": pathlib.Path(key_override if key_override else str(state_dir / "approvals.db.hmac.key")).expanduser().resolve(),
    }


def _apply_runtime_env(paths: dict[str, pathlib.Path]) -> None:
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
    policy_path.write_text(json.dumps(_policy_template(), indent=2) + "\n")
    try:
        os.chmod(policy_path, 0o600)
    except OSError:
        pass


def _init_runtime(force_policy: bool = False) -> None:
    paths = _resolve_paths()
    _apply_runtime_env(paths)
    _secure_permissions(paths)
    _ensure_policy_file(paths, force=force_policy)

    print(f"[airg] config_dir={paths['config_dir']}")
    print(f"[airg] state_dir={paths['state_dir']}")
    print(f"[airg] AIRG_POLICY_PATH={paths['policy_path']}")
    print(f"[airg] AIRG_APPROVAL_DB_PATH={paths['approval_db_path']}")
    print(f"[airg] AIRG_APPROVAL_HMAC_KEY_PATH={paths['approval_hmac_key_path']}")
    print("[airg] Initialization complete.")


def main_init() -> None:
    _init_runtime(force_policy=False)


def main_server() -> None:
    paths = _resolve_paths()
    _apply_runtime_env(paths)
    _secure_permissions(paths)
    _ensure_policy_file(paths, force=False)
    runpy.run_module("server", run_name="__main__")


def main_ui() -> None:
    paths = _resolve_paths()
    _apply_runtime_env(paths)
    _secure_permissions(paths)
    _ensure_policy_file(paths, force=False)
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
        (paths["approval_db_path"], "approval_db_path"),
        (paths["approval_hmac_key_path"], "approval_hmac_key_path"),
    ]:
        try:
            if p.resolve().is_relative_to(workspace):
                warnings.append(f"{label} is inside AIRG_WORKSPACE ({workspace}); move it outside for stronger hardening.")
        except Exception:
            pass

    # UI build check
    ui_dist = pathlib.Path(os.environ.get("AIRG_UI_DIST_PATH", str(pathlib.Path(__file__).resolve().parent / "ui_v3" / "dist")))
    if (ui_dist / "index.html").exists():
        print(f"[ok] UI build detected at {ui_dist}")
    else:
        warnings.append(f"UI build not found at {ui_dist}. Build with `cd ui_v3 && npm install && npm run build`.")

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
    parser.add_argument("command", choices=["init", "server", "ui", "up", "doctor"], help="Command to run")
    parser.add_argument("--force-policy", action="store_true", help="Used with 'init': overwrite existing policy template")
    args = parser.parse_args()

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
