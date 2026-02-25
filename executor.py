import os
import subprocess

from config import WORKSPACE_ROOT


def safe_subprocess_env() -> dict:
    safe = os.environ.copy()
    safe["HOME"] = WORKSPACE_ROOT
    if "LANG" not in safe:
        safe["LANG"] = "C"
    if "LC_ALL" not in safe:
        safe["LC_ALL"] = safe["LANG"]

    for key in list(safe.keys()):
        lower = key.lower()
        if any(marker in lower for marker in ("api_key", "token", "secret", "password")):
            safe.pop(key, None)

    return safe


def run_shell_command(command: str, timeout_seconds: int):
    return subprocess.run(
        command,
        shell=True,
        executable="/bin/bash",
        cwd=WORKSPACE_ROOT,
        env=safe_subprocess_env(),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
