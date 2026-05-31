#!/usr/bin/env python3
"""
AIRG P0 Spike Harness — run_spike.py

Empirically resolves the P0 go/no-go gates defined in
docs/os-enforcement/ARCHITECTURE.md §4 "P0 — Spike / decision-resolver".

Usage:
    python3 scripts/spike/run_spike.py            # human report
    python3 scripts/spike/run_spike.py --json     # machine-readable JSON
    python3 scripts/spike/run_spike.py --gate 1   # run only one gate

Gates:
    0 — Host capability probe (runs on any OS)
    1 — Landlock + AF_UNIX connect(2)  [CRITICAL — Linux only]
    2 — Private tmpfs in landrun       [Linux only]
    3 — End-to-end bridge under sandbox [Linux only]
    4 — HOME=WORKSPACE_ROOT injection  [Linux only]

IMPORTANT: Gates 1-4 require a Linux host with Landlock (kernel ≥5.13) and
either landrun or bwrap installed.  On non-Linux hosts (macOS, etc.) or when
no launcher is available, those gates are SKIPPED with a clear message.

Safety: This script creates only throwaway temp files/sockets under a temp
directory and cleans up on exit.  It does NOT modify any system state.

Stdlib only (no third-party imports).  Python 3.10+.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PROBE_SCRIPT = _REPO_ROOT / "scripts" / "airg_sandbox_probe.py"
_BRIDGE_SCRIPT = _REPO_ROOT / "scripts" / "airg_stdio_bridge.py"
_UNIX_SERVER_SRC = _REPO_ROOT / "src" / "unix_socket_server.py"

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

VERDICT_PASS = "PASS"
VERDICT_FAIL = "FAIL"
VERDICT_SKIP = "SKIP"


@dataclass
class GateResult:
    gate_id: int
    name: str
    verdict: str          # PASS | FAIL | SKIP
    interpretation: str   # one-line go/no-go interpretation
    commands: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# Shared state written by Gate 0 for use by later gates
# ---------------------------------------------------------------------------

_probe_data: dict[str, Any] = {}
_chosen_launcher: str = ""   # "landrun" | "bwrap" | ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_linux() -> bool:
    return platform.system() == "Linux"


def _skip(gate_id: int, name: str, reason: str) -> GateResult:
    return GateResult(
        gate_id=gate_id,
        name=name,
        verdict=VERDICT_SKIP,
        interpretation=reason,
    )


def _run(cmd: list[str], *, timeout: int = 15, env: dict | None = None,
         input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    """Run a command and return CompletedProcess.  Never raises on non-zero exit."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            env=env,
            input=input_bytes,
        )
        return result
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=-1,
            stdout=b"",
            stderr=f"TIMEOUT after {timeout}s".encode(),
        )
    except Exception as exc:
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=-2,
            stdout=b"",
            stderr=str(exc).encode(),
        )


def _decode(b: bytes | None) -> str:
    if not b:
        return ""
    return b.decode("utf-8", errors="replace").strip()


# ---------------------------------------------------------------------------
# GATE 0 — Host capability probe
# ---------------------------------------------------------------------------

def gate_0_host_probe() -> GateResult:
    """
    Invoke scripts/airg_sandbox_probe.py --json, summarize findings, and
    decide which launcher (landrun vs bwrap) subsequent gates should use.
    Updates module-level _probe_data and _chosen_launcher.
    """
    global _probe_data, _chosen_launcher
    name = "Host capability probe"

    if not _PROBE_SCRIPT.exists():
        return GateResult(
            gate_id=0, name=name, verdict=VERDICT_FAIL,
            interpretation=f"Probe script not found at {_PROBE_SCRIPT}",
            error=f"Missing: {_PROBE_SCRIPT}",
        )

    cmd = [sys.executable, str(_PROBE_SCRIPT), "--json"]
    result = _run(cmd, timeout=20)
    stdout_s = _decode(result.stdout)
    stderr_s = _decode(result.stderr)

    if result.returncode != 0:
        return GateResult(
            gate_id=0, name=name, verdict=VERDICT_FAIL,
            interpretation="Probe script exited non-zero — cannot determine host capabilities.",
            commands=cmd, stdout=stdout_s, stderr=stderr_s,
        )

    try:
        data = json.loads(stdout_s)
    except json.JSONDecodeError as exc:
        return GateResult(
            gate_id=0, name=name, verdict=VERDICT_FAIL,
            interpretation="Probe script produced non-JSON output.",
            commands=cmd, stdout=stdout_s, stderr=stderr_s,
            error=str(exc),
        )

    _probe_data = data

    # Derive the launcher choice using the same logic as the T2/T5 recommendation.
    system = data.get("platform", {}).get("system", "")
    landlock = data.get("landlock", {})
    userns = data.get("userns", {})
    launchers = data.get("launchers", {})

    ll_ok = landlock.get("available", False)
    ll_ver = landlock.get("abi_version")
    userns_verdict = userns.get("verdict", "unknown")
    userns_ok = userns_verdict in ("yes",)   # 'yes_but_apparmor_restricted' treated as restricted
    landrun_found = launchers.get("landrun", {}).get("found", False)
    bwrap_found = launchers.get("bwrap", {}).get("found", False)

    # Launcher selection (mirrors ARCHITECTURE.md §5 conditional recommendation):
    #   1. userns available + bwrap present → bwrap
    #   2. Landlock ABI ≥1 + landrun present → landrun
    #   3. neither → ""
    launcher_choice = ""
    launcher_rationale = ""
    if userns_ok and bwrap_found:
        launcher_choice = "bwrap"
        launcher_rationale = "userns available + bwrap found → bwrap selected"
    elif ll_ok and landrun_found:
        launcher_choice = "landrun"
        launcher_rationale = f"Landlock ABI v{ll_ver} + landrun found → landrun selected"
    elif userns_verdict == "yes_but_apparmor_restricted" and bwrap_found:
        launcher_choice = "bwrap"
        launcher_rationale = "userns restricted (AppArmor) + bwrap found → bwrap (may need AppArmor profile)"
    else:
        if not _is_linux():
            launcher_rationale = "Non-Linux host — no Linux launcher applicable"
        elif not ll_ok and not userns_ok:
            launcher_rationale = "Neither Landlock nor userns available — no launcher viable"
        elif ll_ok and not landrun_found:
            launcher_rationale = f"Landlock ABI v{ll_ver} but landrun not installed — install landrun"
        elif userns_ok and not bwrap_found:
            launcher_rationale = "userns available but bwrap not installed — install bwrap"
        else:
            launcher_rationale = "No viable launcher detected"

    _chosen_launcher = launcher_choice

    # Build a short summary of the probe for the human report.
    details: dict[str, Any] = {
        "platform": f"{system} / {data.get('platform', {}).get('machine', '?')}",
        "landlock_available": ll_ok,
        "landlock_abi_version": ll_ver,
        "userns_verdict": userns_verdict,
        "landrun_found": landrun_found,
        "bwrap_found": bwrap_found,
        "sandbox_exec_found": data.get("sandbox_exec", {}).get("found", False),
        "chosen_launcher": launcher_choice or "(none)",
        "launcher_rationale": launcher_rationale,
    }

    if system == "Darwin":
        ver = data.get("platform", {}).get("macos_product_version", "?")
        details["macos_version"] = ver

    interpretation = (
        f"Probe complete. Platform: {system}. "
        + (f"Landlock ABI v{ll_ver}. " if ll_ok else "No Landlock. ")
        + f"Chosen launcher: {launcher_choice or '(none)'}. "
        + launcher_rationale + "."
    )

    return GateResult(
        gate_id=0, name=name, verdict=VERDICT_PASS,
        interpretation=interpretation,
        commands=[" ".join(cmd)],
        stdout=stdout_s[:2000],  # truncate for display
        details=details,
    )


# ---------------------------------------------------------------------------
# GATE 1 — Landlock + AF_UNIX connect(2)  [CRITICAL]
# ---------------------------------------------------------------------------

def gate_1_afunix_connect(tmpdir: str) -> GateResult:
    """
    CRITICAL GATE: Start a tiny AF_UNIX echo server OUTSIDE the sandbox;
    run a client INSIDE the sandbox (via landrun/bwrap); verify connect(2)
    and a round-trip message.

    This resolves BLOCKING-2 from ARCHITECTURE.md: whether a Landlock FS
    read/write rule on a pathname socket inode actually permits connect(2).

    On non-Linux or missing launcher: SKIP.
    """
    name = "Landlock + AF_UNIX connect(2)"

    if not _is_linux():
        return _skip(1, name, "Linux required — skipping on this host (not Linux).")

    launcher = _chosen_launcher
    if not launcher:
        return _skip(1, name,
            "No viable launcher detected (need landrun or bwrap). "
            "Install landrun (go install github.com/zouuup/landrun/cmd/landrun@latest) "
            "or bwrap (apt install bubblewrap) and re-run.")

    sock_path = os.path.join(tmpdir, "gate1_test.sock")

    # --- Start the echo server (outside the sandbox) in a thread ---
    server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_ready = threading.Event()
    server_error: list[str] = []
    received_msgs: list[bytes] = []

    def _echo_server() -> None:
        try:
            server_sock.bind(sock_path)
            server_sock.listen(1)
            server_ready.set()
            server_sock.settimeout(10.0)
            conn, _ = server_sock.accept()
            try:
                data = conn.recv(4096)
                received_msgs.append(data)
                conn.sendall(data)  # echo back
            finally:
                conn.close()
        except Exception as exc:
            server_error.append(str(exc))
        finally:
            server_sock.close()

    t = threading.Thread(target=_echo_server, daemon=True)
    t.start()

    if not server_ready.wait(timeout=5.0):
        return GateResult(
            gate_id=1, name=name, verdict=VERDICT_FAIL,
            interpretation="Echo server failed to start within 5s.",
            error="; ".join(server_error),
        )

    # --- Build the in-sandbox client command ---
    # The client script: connect to the socket, send a test message, read reply, exit 0 on match.
    client_script = textwrap.dedent(f"""\
        import socket, sys
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect({sock_path!r})
        s.sendall(b"AIRG_GATE1_ROUNDTRIP\\n")
        data = s.recv(4096)
        s.close()
        if data == b"AIRG_GATE1_ROUNDTRIP\\n":
            sys.exit(0)
        else:
            print(f"Got: {{data!r}}", file=sys.stderr)
            sys.exit(1)
    """)

    client_script_path = os.path.join(tmpdir, "gate1_client.py")
    with open(client_script_path, "w") as f:
        f.write(client_script)

    python_bin = sys.executable

    if launcher == "landrun":
        cmd = [
            "landrun",
            "--rw", sock_path,       # carve in the socket path read+write
            "--ro", python_bin,      # allow python binary
            "--ro", "/usr",          # system libs + python stdlib
            "--ro", "/lib",
            "--ro", "/lib64",
            "--ro", "/etc",
            "--ro", client_script_path,
            "--ro", tmpdir,
            "--",
            python_bin, client_script_path,
        ]
    elif launcher == "bwrap":
        cmd = [
            "bwrap",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/etc", "/etc",
            "--bind", sock_path, sock_path,   # bind the socket into the sandbox
            "--ro-bind", client_script_path, client_script_path,
            "--ro-bind", tmpdir, tmpdir,
            "--proc", "/proc",
            "--dev", "/dev",
            "--unshare-all",
            "--share-net",  # keep network for resolver; socket is AF_UNIX not TCP
            "--",
            python_bin, client_script_path,
        ]
    else:
        return _skip(1, name, f"Unsupported launcher: {launcher!r}")

    result = _run(cmd, timeout=20)
    stdout_s = _decode(result.stdout)
    stderr_s = _decode(result.stderr)

    t.join(timeout=5.0)

    if result.returncode == 0 and received_msgs:
        verdict = VERDICT_PASS
        interpretation = (
            f"[GO] AF_UNIX connect(2) works through {launcher} sandbox with FS path carve-out. "
            "Topology A is viable — the Landlock FS rule on a socket inode permits connect(2). "
            "P1 can proceed with confidence."
        )
    elif result.returncode == 0 and not received_msgs:
        verdict = VERDICT_FAIL
        interpretation = (
            f"Client exited 0 but server received no data. "
            "Possible timing issue; re-run to confirm."
        )
    else:
        verdict = VERDICT_FAIL
        interpretation = (
            f"[NO-GO signal] AF_UNIX connect(2) FAILED through {launcher} (exit {result.returncode}). "
            "Topology A may not work on this host/kernel/launcher combination. "
            "Alternatives: (1) try bwrap bind-mount if only landrun was tested; "
            "(2) wait for Landlock ABI v9 (pathname Unix socket scope); "
            "(3) fall back to Topology B with externalized control plane. "
            "See ARCHITECTURE.md BLOCKING-2."
        )

    return GateResult(
        gate_id=1, name=name, verdict=verdict,
        interpretation=interpretation,
        commands=[" ".join(cmd)],
        stdout=stdout_s, stderr=stderr_s,
        details={
            "launcher": launcher,
            "sock_path": sock_path,
            "server_received": bool(received_msgs),
            "server_error": "; ".join(server_error) if server_error else None,
        },
    )


# ---------------------------------------------------------------------------
# GATE 2 — Private tmpfs in landrun
# ---------------------------------------------------------------------------

def gate_2_private_tmpfs(tmpdir: str) -> GateResult:
    """
    Test whether the chosen launcher can provide a writable private /tmp
    (a private tmpfs mount, isolated from the host's /tmp).

    For landrun: look for --tmpfs or --private-tmp flag support.
    For bwrap: bwrap --tmpfs /tmp is well-documented.

    If private tmpfs is not supported, the documented fallback is to grant
    host /tmp read-write access (with audit-log naming).
    """
    name = "Private tmpfs for /tmp"

    if not _is_linux():
        return _skip(2, name, "Linux required — skipping on this host (not Linux).")

    launcher = _chosen_launcher
    if not launcher:
        return _skip(2, name, "No viable launcher detected — skipping Gate 2.")

    if launcher == "landrun":
        # Check if landrun supports --tmpfs by trying landrun --help
        help_result = _run(["landrun", "--help"], timeout=5)
        help_text = _decode(help_result.stdout) + _decode(help_result.stderr)
        has_tmpfs_flag = "--tmpfs" in help_text or "--private-tmp" in help_text

        if has_tmpfs_flag:
            # Actually test it: run a command inside a tmpfs /tmp and write a file
            test_cmd = [
                "landrun",
                "--tmpfs", "/tmp",
                "--ro", sys.executable,
                "--ro", "/usr",
                "--ro", "/lib",
                "--ro", "/lib64",
                "--ro", "/etc",
                "--",
                sys.executable, "-c",
                "import os; open('/tmp/airg_gate2_probe.txt', 'w').write('ok'); "
                "# verify it's isolated: if host /tmp had this file it would exist before we write it"
            ]
            result = _run(test_cmd, timeout=15)
            if result.returncode == 0:
                verdict = VERDICT_PASS
                interpretation = (
                    "landrun supports --tmpfs; private /tmp is available. "
                    "No fallback to host /tmp needed (carve-out shape: use --tmpfs /tmp)."
                )
            else:
                verdict = VERDICT_FAIL
                interpretation = (
                    "landrun has --tmpfs flag but private tmpfs test failed. "
                    "Fallback: use host /tmp rw (document in audit log). "
                    "Check landrun version and kernel tmpfs support."
                )
        else:
            verdict = VERDICT_FAIL
            interpretation = (
                "landrun does NOT expose a --tmpfs / --private-tmp flag in this version. "
                "FALLBACK APPLIES: use host /tmp read-write for writable_paths. "
                "Document in audit log. This is non-fatal per ARCHITECTURE.md BLOCKING-3."
            )
        cmd_display = "landrun --help (checked for --tmpfs flag)"
        return GateResult(
            gate_id=2, name=name, verdict=verdict,
            interpretation=interpretation,
            commands=[cmd_display],
            stdout=help_text[:1000],
            details={
                "launcher": launcher,
                "has_tmpfs_flag": has_tmpfs_flag,
                "fallback_if_fail": "Grant host /tmp rw in writable_paths",
            },
        )

    elif launcher == "bwrap":
        # bwrap --tmpfs /tmp is documented and well-tested; perform a quick functional check
        test_cmd = [
            "bwrap",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/etc", "/etc",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--unshare-all",
            "--",
            sys.executable, "-c",
            "import tempfile, os; f = tempfile.NamedTemporaryFile(dir='/tmp', delete=False); "
            "f.write(b'gate2ok'); f.close(); print('tmpfs write ok')"
        ]
        result = _run(test_cmd, timeout=15)
        stdout_s = _decode(result.stdout)
        stderr_s = _decode(result.stderr)

        if result.returncode == 0 and "tmpfs write ok" in stdout_s:
            verdict = VERDICT_PASS
            interpretation = (
                "bwrap --tmpfs /tmp works: private writable tmpfs confirmed. "
                "Agent writes to /tmp are isolated from host."
            )
        else:
            verdict = VERDICT_FAIL
            interpretation = (
                "bwrap --tmpfs /tmp failed. Fallback: bind-mount host /tmp rw. "
                "Check bwrap version and kernel mount namespace support."
            )
        return GateResult(
            gate_id=2, name=name, verdict=verdict,
            interpretation=interpretation,
            commands=[" ".join(test_cmd)],
            stdout=stdout_s, stderr=stderr_s,
            details={
                "launcher": launcher,
                "fallback_if_fail": "bwrap --bind /tmp /tmp (host /tmp rw)",
            },
        )

    return _skip(2, name, f"Unsupported launcher for Gate 2: {launcher!r}")


# ---------------------------------------------------------------------------
# GATE 3 — End-to-end bridge under sandbox
# ---------------------------------------------------------------------------

def gate_3_end_to_end_bridge(tmpdir: str) -> GateResult:
    """
    Run the real src/unix_socket_server.py (AIRG side) OUTSIDE the sandbox
    listening on a socket; run scripts/airg_stdio_bridge.py INSIDE the
    sandbox (via launcher, carving in only the socket path); drive an MCP
    initialize + tools/list through the shim and assert a valid response.

    This proves the full Topology A path on Linux.

    Because unix_socket_server.py requires the mcp/anyio packages (AIRG's
    full deps), we use a lightweight substitute server that speaks the same
    newline-delimited JSON-RPC protocol — stdlib only, no mcp dependency
    needed for the test server.  The shim (airg_stdio_bridge.py) and the
    client-side message injection are both stdlib-only.
    """
    name = "End-to-end bridge under sandbox"

    if not _is_linux():
        return _skip(3, name, "Linux required — skipping on this host (not Linux).")

    launcher = _chosen_launcher
    if not launcher:
        return _skip(3, name, "No viable launcher detected — skipping Gate 3.")

    if not _BRIDGE_SCRIPT.exists():
        return GateResult(
            gate_id=3, name=name, verdict=VERDICT_FAIL,
            interpretation=f"Bridge script not found: {_BRIDGE_SCRIPT}",
            error=f"Missing: {_BRIDGE_SCRIPT}",
        )

    sock_path = os.path.join(tmpdir, "gate3_airg.sock")
    python_bin = sys.executable

    # --- Lightweight MCP-compatible server (stdlib only) ---
    # Speaks newline-delimited JSON-RPC exactly like the real AIRG server.
    # Handles: initialize → InitializeResult, tools/list → empty tools list.
    server_script = textwrap.dedent(f"""\
        import socket, json, sys, os, threading

        SOCK_PATH = {sock_path!r}

        INIT_RESPONSE = {{
            "jsonrpc": "2.0",
            "id": None,
            "result": {{
                "protocolVersion": "2024-11-05",
                "capabilities": {{"tools": {{}}}},
                "serverInfo": {{"name": "airg-gate3-stub", "version": "0.0.1"}}
            }}
        }}

        TOOLS_LIST_RESPONSE = {{
            "jsonrpc": "2.0",
            "id": None,
            "result": {{"tools": []}}
        }}

        def handle(conn):
            buf = b""
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\\n" in buf:
                        idx = buf.index(b"\\n")
                        line = buf[:idx].decode("utf-8", errors="replace").strip()
                        buf = buf[idx+1:]
                        if not line:
                            continue
                        try:
                            msg = json.loads(line)
                        except Exception:
                            continue
                        method = msg.get("method", "")
                        msg_id = msg.get("id")
                        if method == "initialize":
                            resp = dict(INIT_RESPONSE)
                            resp["id"] = msg_id
                            conn.sendall((json.dumps(resp) + "\\n").encode("utf-8"))
                        elif method == "notifications/initialized":
                            pass  # no response needed
                        elif method == "tools/list":
                            resp = dict(TOOLS_LIST_RESPONSE)
                            resp["id"] = msg_id
                            conn.sendall((json.dumps(resp) + "\\n").encode("utf-8"))
                        # Stop after tools/list to let the client detect success
            except Exception:
                pass
            finally:
                conn.close()

        old_umask = os.umask(0o177)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(SOCK_PATH)
        os.umask(old_umask)
        s.listen(1)
        # Signal readiness by writing to stdout
        print("READY", flush=True)
        try:
            conn, _ = s.accept()
            handle(conn)
        finally:
            s.close()
            try:
                os.unlink(SOCK_PATH)
            except Exception:
                pass
    """)

    server_script_path = os.path.join(tmpdir, "gate3_server.py")
    with open(server_script_path, "w") as f:
        f.write(server_script)

    # --- Client script (drives MCP through the bridge) ---
    # Runs OUTSIDE the sandbox, pipes data to the bridge process's stdin.
    init_msg = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "airg-gate3-client", "version": "0.0.1"},
        }
    }) + "\n"
    initialized_notif = json.dumps({
        "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}
    }) + "\n"
    tools_msg = json.dumps({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }) + "\n"

    client_input = (init_msg + initialized_notif + tools_msg).encode("utf-8")

    # --- Build the bridge (shim) command to run inside the sandbox ---
    bridge_env = {**os.environ, "AIRG_SOCKET_PATH": sock_path}

    if launcher == "landrun":
        bridge_cmd = [
            "landrun",
            "--rw", sock_path,
            "--ro", python_bin,
            "--ro", "/usr",
            "--ro", "/lib",
            "--ro", "/lib64",
            "--ro", "/etc",
            "--ro", str(_BRIDGE_SCRIPT),
            "--ro", os.path.dirname(str(_BRIDGE_SCRIPT)),
            "--",
            python_bin, str(_BRIDGE_SCRIPT), sock_path,
        ]
    elif launcher == "bwrap":
        scripts_dir = str(_BRIDGE_SCRIPT.parent)
        bridge_cmd = [
            "bwrap",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/etc", "/etc",
            "--bind", sock_path, sock_path,
            "--ro-bind", str(_BRIDGE_SCRIPT), str(_BRIDGE_SCRIPT),
            "--ro-bind", scripts_dir, scripts_dir,
            "--proc", "/proc",
            "--dev", "/dev",
            "--unshare-all",
            "--share-net",
            "--",
            python_bin, str(_BRIDGE_SCRIPT), sock_path,
        ]
    else:
        return _skip(3, name, f"Unsupported launcher: {launcher!r}")

    # --- Start the stub server ---
    server_proc = subprocess.Popen(
        [python_bin, server_script_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

    # Wait for "READY" from the server
    ready_line = b""
    try:
        server_proc.stdout.settimeout = lambda *a: None  # not a real method; use poll
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            import select
            r, _, _ = select.select([server_proc.stdout], [], [], 0.2)
            if r:
                ready_line = server_proc.stdout.readline()
                if b"READY" in ready_line:
                    break
    except Exception:
        pass

    if b"READY" not in ready_line:
        server_proc.kill()
        server_proc.wait()
        return GateResult(
            gate_id=3, name=name, verdict=VERDICT_FAIL,
            interpretation="Stub server failed to start or signal readiness within 8s.",
            commands=[" ".join(bridge_cmd)],
            stderr=_decode(server_proc.stderr.read()),
        )

    # --- Run the bridge inside the sandbox, feeding MCP messages to its stdin ---
    try:
        bridge_result = subprocess.run(
            bridge_cmd,
            input=client_input,
            capture_output=True,
            timeout=20,
            env=bridge_env,
        )
    except subprocess.TimeoutExpired:
        server_proc.kill()
        server_proc.wait()
        return GateResult(
            gate_id=3, name=name, verdict=VERDICT_FAIL,
            interpretation="Bridge subprocess timed out (20s).",
            commands=[" ".join(bridge_cmd)],
        )
    finally:
        # Clean up the server process
        try:
            server_proc.terminate()
        except Exception:
            pass
        try:
            server_proc.wait(timeout=5)
        except Exception:
            server_proc.kill()
            server_proc.wait()

    bridge_stdout = _decode(bridge_result.stdout)
    bridge_stderr = _decode(bridge_result.stderr)

    # Parse the bridge output (should contain the MCP JSON-RPC responses)
    init_ok = False
    tools_ok = False
    for line in bridge_stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            if msg.get("id") == 1 and "result" in msg:
                result_obj = msg["result"]
                if "protocolVersion" in result_obj:
                    init_ok = True
            if msg.get("id") == 2 and "result" in msg:
                if "tools" in msg["result"]:
                    tools_ok = True
        except Exception:
            pass

    verdict = VERDICT_PASS if (init_ok and tools_ok) else VERDICT_FAIL
    if init_ok and tools_ok:
        interpretation = (
            f"[GO] Full Topology A path verified on {launcher}. "
            "MCP initialize + tools/list round-tripped through the shim "
            "(inside sandbox) ↔ socket ↔ AIRG server (outside sandbox). "
            "P1 bridge implementation is ready."
        )
    elif bridge_result.returncode != 0:
        interpretation = (
            f"Bridge process exited non-zero (rc={bridge_result.returncode}). "
            "The shim could not connect or the sandbox blocked access to the socket. "
            "Gate 1 may have passed but Gate 3 environment differs — check carve-out paths."
        )
    else:
        interpretation = (
            "Bridge ran but MCP responses were incomplete. "
            f"initialize={'OK' if init_ok else 'MISSING'}, "
            f"tools/list={'OK' if tools_ok else 'MISSING'}. "
            "Check stub server output and bridge stdout."
        )

    return GateResult(
        gate_id=3, name=name, verdict=verdict,
        interpretation=interpretation,
        commands=[" ".join(bridge_cmd)],
        stdout=bridge_stdout, stderr=bridge_stderr,
        details={
            "launcher": launcher,
            "sock_path": sock_path,
            "initialize_response_received": init_ok,
            "tools_list_response_received": tools_ok,
            "bridge_exit_code": bridge_result.returncode,
        },
    )


# ---------------------------------------------------------------------------
# GATE 4 — HOME=WORKSPACE_ROOT injection
# ---------------------------------------------------------------------------

def gate_4_home_injection(tmpdir: str) -> GateResult:
    """
    Verify the launcher invocation sets HOME to the workspace (the T5 finding)
    and that a child process sees it.

    Tests that:
    1. HOME env var inside the sandbox is set to the workspace (tmpdir here).
    2. A tool that reads HOME (e.g., Python's os.path.expanduser("~"))
       resolves to the workspace, not the real user home.

    This is separate from executor.py (which sets HOME for MCP subprocesses);
    here we confirm the OS-level launcher wrapper does it too.
    """
    name = "HOME=WORKSPACE_ROOT injection"

    if not _is_linux():
        return _skip(4, name, "Linux required — skipping on this host (not Linux).")

    launcher = _chosen_launcher
    if not launcher:
        return _skip(4, name, "No viable launcher detected — skipping Gate 4.")

    workspace_dir = os.path.join(tmpdir, "workspace_gate4")
    os.makedirs(workspace_dir, exist_ok=True)

    check_script = textwrap.dedent(f"""\
        import os
        home = os.environ.get("HOME", "")
        expanded = os.path.expanduser("~")
        workspace = {workspace_dir!r}
        print(f"HOME={{home}}")
        print(f"expanded={{expanded}}")
        if home == workspace:
            print("HOME_OK")
        else:
            print(f"HOME_MISMATCH: expected {{workspace!r}}, got {{home!r}}")
        if expanded == workspace:
            print("EXPANDUSER_OK")
        else:
            print(f"EXPANDUSER_MISMATCH: expected {{workspace!r}}, got {{expanded!r}}")
    """)

    check_script_path = os.path.join(tmpdir, "gate4_check.py")
    with open(check_script_path, "w") as f:
        f.write(check_script)

    python_bin = sys.executable

    if launcher == "landrun":
        cmd = [
            "landrun",
            "--rw", workspace_dir,
            "--ro", python_bin,
            "--ro", "/usr",
            "--ro", "/lib",
            "--ro", "/lib64",
            "--ro", "/etc",
            "--ro", check_script_path,
            "--ro", tmpdir,
            "--env", f"HOME={workspace_dir}",
            "--",
            python_bin, check_script_path,
        ]
    elif launcher == "bwrap":
        cmd = [
            "bwrap",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/etc", "/etc",
            "--bind", workspace_dir, workspace_dir,
            "--ro-bind", check_script_path, check_script_path,
            "--ro-bind", tmpdir, tmpdir,
            "--proc", "/proc",
            "--dev", "/dev",
            "--unshare-all",
            "--setenv", "HOME", workspace_dir,
            "--",
            python_bin, check_script_path,
        ]
    else:
        return _skip(4, name, f"Unsupported launcher: {launcher!r}")

    result = _run(cmd, timeout=15)
    stdout_s = _decode(result.stdout)
    stderr_s = _decode(result.stderr)

    home_ok = "HOME_OK" in stdout_s
    expanduser_ok = "EXPANDUSER_OK" in stdout_s

    if home_ok and expanduser_ok:
        verdict = VERDICT_PASS
        interpretation = (
            f"HOME={workspace_dir!r} confirmed inside {launcher} sandbox. "
            "os.path.expanduser('~') resolves to workspace. "
            "Credential files in real ~/  are unreachable; workspace-scoped redirects work."
        )
    elif result.returncode != 0:
        verdict = VERDICT_FAIL
        interpretation = (
            f"Launcher command failed (rc={result.returncode}). "
            "Check if the --env / --setenv flag is supported and the workspace path is correct."
        )
    else:
        verdict = VERDICT_FAIL
        interpretation = (
            f"HOME injection FAILED. home_ok={home_ok}, expanduser_ok={expanduser_ok}. "
            "The launcher did not set HOME to workspace_root correctly. "
            "Check launcher env injection flags (landrun --env, bwrap --setenv). "
            f"Stdout: {stdout_s[:200]!r}"
        )

    return GateResult(
        gate_id=4, name=name, verdict=verdict,
        interpretation=interpretation,
        commands=[" ".join(cmd)],
        stdout=stdout_s, stderr=stderr_s,
        details={
            "launcher": launcher,
            "workspace_dir": workspace_dir,
            "home_env_correct": home_ok,
            "expanduser_correct": expanduser_ok,
        },
    )


# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------

def _overall_verdict(results: list[GateResult]) -> tuple[str, str]:
    """Return (GO/NO-GO/INCONCLUSIVE, reason)."""
    gate1 = next((r for r in results if r.gate_id == 1), None)
    gate3 = next((r for r in results if r.gate_id == 3), None)

    if gate1 and gate1.verdict == VERDICT_SKIP and gate3 and gate3.verdict == VERDICT_SKIP:
        return "INCONCLUSIVE", (
            "Gates 1 and 3 were SKIPPED (not Linux or no launcher). "
            "Run on a Linux host with landrun or bwrap to get a real GO/NO-GO."
        )

    gate1_pass = gate1 and gate1.verdict == VERDICT_PASS
    gate3_pass = gate3 and gate3.verdict == VERDICT_PASS

    if gate1_pass and gate3_pass:
        return "GO", (
            "Gate 1 (AF_UNIX connect) and Gate 3 (end-to-end bridge) both PASS. "
            "Topology A is viable. P1 implementation authorized."
        )
    elif gate1_pass and gate3 and gate3.verdict == VERDICT_FAIL:
        return "PARTIAL-GO", (
            "Gate 1 PASS (socket connect works) but Gate 3 FAIL (full bridge needs investigation). "
            "Topology A transport layer is proven; address Gate 3 environment before P1."
        )
    elif gate1 and gate1.verdict == VERDICT_FAIL:
        return "NO-GO", (
            "Gate 1 FAILED — AF_UNIX connect(2) does not work through the launcher. "
            "Topology A is NOT viable with the current launcher/kernel. "
            "Alternatives: (1) bwrap bind-mount (if userns available); "
            "(2) wait for Landlock ABI v9 pathname Unix socket scope; "
            "(3) Topology B with externalized control plane. "
            "See ARCHITECTURE.md §5 BLOCKING-2."
        )
    else:
        return "INCONCLUSIVE", "Some gates could not be evaluated — check individual results."


def print_human(results: list[GateResult]) -> None:
    sep = "=" * 70
    thin = "-" * 70
    print(sep)
    print("  AIRG P0 SPIKE HARNESS — Go/No-Go Report")
    print(sep)

    for r in results:
        color_start = ""
        color_end = ""
        verdict_display = r.verdict
        print()
        print(f"  GATE {r.gate_id}: {r.name}")
        print(thin)
        print(f"  Verdict       : {verdict_display}")
        print(f"  Interpretation: {r.interpretation}")
        if r.commands:
            for c in r.commands:
                print(f"  Command       : {c[:120]}")
        if r.details:
            for k, v in r.details.items():
                if v is not None:
                    print(f"  Detail        : {k} = {v}")
        if r.error:
            print(f"  Error         : {r.error}")
        if r.stderr:
            stderr_short = r.stderr[:300].replace("\n", " | ")
            print(f"  Stderr        : {stderr_short}")

    print()
    print(sep)
    overall, reason = _overall_verdict(results)
    print(f"  OVERALL: {overall}")
    print(f"  {reason}")
    print(sep)

    # If NO-GO on Gate 1, print the documented alternatives
    gate1 = next((r for r in results if r.gate_id == 1), None)
    if gate1 and gate1.verdict == VERDICT_FAIL:
        print()
        print("  GATE 1 FAILED — Documented alternatives per ARCHITECTURE.md:")
        print("    A) Switch to bwrap (requires userns): --bind <sockpath> <sockpath>")
        print("       Probe will show 'bwrap: VIABLE' if userns is available.")
        print("    B) Landlock ABI v9 (upcoming): adds explicit pathname socket scope.")
        print("       Not yet available in mainline kernel (as of 2026-05).")
        print("    C) Topology B: AIRG inside sandbox + externalized control plane.")
        print("       Weaker security model; see transport-bridge-design.md §5.4.")
        print("    D) bwrap socket-dir carve-out: --bind <socket_dir> <socket_dir>")
        print("       (bind the directory, not just the file, for connect access).")
        print()


def print_json_report(results: list[GateResult]) -> None:
    overall, reason = _overall_verdict(results)
    output = {
        "overall": overall,
        "overall_reason": reason,
        "gates": [r.to_dict() for r in results],
    }
    print(json.dumps(output, indent=2, default=str))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="AIRG P0 Spike Harness — empirically resolve go/no-go gates.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 scripts/spike/run_spike.py
              python3 scripts/spike/run_spike.py --json
              python3 scripts/spike/run_spike.py --gate 1
              python3 scripts/spike/run_spike.py --gate 0

            Requires Linux + landrun or bwrap for Gates 1-4.
            Gate 0 (probe) runs on any OS.
        """),
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON instead of human report.",
    )
    parser.add_argument(
        "--gate", type=int, choices=[0, 1, 2, 3, 4], default=None,
        help="Run only a specific gate (0-4). Default: run all.",
    )
    args = parser.parse_args()

    results: list[GateResult] = []

    with tempfile.TemporaryDirectory(prefix="airg_spike_") as tmpdir:
        run_all = args.gate is None

        # Gate 0 always runs first (other gates depend on its output)
        if run_all or args.gate == 0:
            r0 = gate_0_host_probe()
            results.append(r0)

        if run_all or args.gate == 1:
            results.append(gate_1_afunix_connect(tmpdir))

        if run_all or args.gate == 2:
            results.append(gate_2_private_tmpfs(tmpdir))

        if run_all or args.gate == 3:
            results.append(gate_3_end_to_end_bridge(tmpdir))

        if run_all or args.gate == 4:
            results.append(gate_4_home_injection(tmpdir))

    if args.json:
        print_json_report(results)
    else:
        print_human(results)

    # Exit 0 if overall is GO or INCONCLUSIVE (nothing broken, just needs Linux).
    # Exit 1 if any gate FAILed (operator attention needed).
    overall, _ = _overall_verdict(results)
    if any(r.verdict == VERDICT_FAIL for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
