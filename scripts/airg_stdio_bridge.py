#!/usr/bin/env python3
"""
airg-mcp-shim — in-sandbox stdio<->AF_UNIX socket forwarder.

PURPOSE
-------
This script is the in-sandbox half of the AIRG Topology A transport bridge
(see docs/os-enforcement/transport-bridge-design.md).  It runs INSIDE the OS
sandbox (Landlock / bwrap / sandbox-exec) as the MCP server command.  Its
only job is to relay raw bytes between its own stdin/stdout (connected to the
MCP client) and an AF_UNIX socket (connected to the real AIRG server running
OUTSIDE the sandbox).

USAGE
-----
    # Socket path via environment variable (preferred — set by launcher):
    AIRG_SOCKET_PATH=/path/to/agent.sock python3 airg_stdio_bridge.py

    # Socket path via positional argument (fallback):
    python3 airg_stdio_bridge.py /path/to/agent.sock

The shim is framing-agnostic: it forwards raw bytes without any MCP or
JSON-RPC awareness.  This makes it immune to protocol changes.

DEPENDENCY-FREE
---------------
Intentionally uses ONLY Python 3.10+ stdlib.  The ``mcp`` package is NOT
imported and is NOT required.  This is important because the mcp package may
be absent inside a stripped-down sandbox environment.

EOF / HALF-CLOSE HANDLING
--------------------------
- stdin EOF (MCP client exits):  pump A reads 0 bytes → closes socket write
  side → server sees EOF → session ends.
- Socket EOF (AIRG server exits):  pump B reads 0 bytes → closes stdout →
  MCP client sees its server child exit → client terminates or retries.
- Shim killed (SIGKILL):  OS closes all FDs → AIRG session ends.

RETRY
-----
If the socket is not yet ready (ECONNREFUSED / ENOENT), the shim retries up
to MAX_RETRIES times with exponential backoff before exiting non-zero.  This
tolerates slow AIRG startup.
"""

import os
import socket
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CHUNK_SIZE = 4096
MAX_RETRIES = 5          # total attempts
RETRY_BASE_DELAY = 0.5   # seconds; doubles each retry

# ---------------------------------------------------------------------------
# Core pump — exported so tests can exercise it without a subprocess
# ---------------------------------------------------------------------------


def pump(src, dst) -> None:
    """
    Copy bytes from *src* (file-like, binary) to *dst* (file-like, binary)
    until EOF or error.  Closes both *src* and *dst* on exit.

    Designed to run in a daemon thread.  Uses 4 KiB chunks with no extra
    buffering (both file objects should be opened with ``buffering=0``).
    """
    try:
        while True:
            chunk = src.read(CHUNK_SIZE)
            if not chunk:
                break
            dst.write(chunk)
            dst.flush()
    except Exception:
        pass
    finally:
        try:
            src.close()
        except Exception:
            pass
        try:
            dst.close()
        except Exception:
            pass


def _connect_with_retry(sock_path: str) -> socket.socket:
    """
    Attempt to connect to the AF_UNIX socket at *sock_path*.  Retries with
    exponential backoff (up to MAX_RETRIES attempts) to tolerate slow AIRG
    startup.  Raises ``SystemExit(1)`` on failure.
    """
    delay = RETRY_BASE_DELAY
    for attempt in range(1, MAX_RETRIES + 1):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(sock_path)
            return sock
        except (ConnectionRefusedError, FileNotFoundError) as exc:
            sock.close()
            if attempt == MAX_RETRIES:
                print(
                    f"[airg-shim] could not connect to {sock_path!r} after "
                    f"{MAX_RETRIES} attempts: {exc}",
                    file=sys.stderr,
                )
                raise SystemExit(1) from exc
            time.sleep(delay)
            delay = min(delay * 2, 8.0)
        except OSError as exc:
            sock.close()
            print(f"[airg-shim] connection error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
    # Unreachable — kept for type checkers.
    raise SystemExit(1)


def run_bridge(sock_path: str) -> None:
    """
    Connect to the AIRG server socket at *sock_path* and pump bytes
    bidirectionally between stdin/stdout and the socket until either side
    closes.

    This function BLOCKS until both pump threads finish.
    """
    sock = _connect_with_retry(sock_path)

    # Use buffering=0 (unbuffered) for both directions to avoid latency.
    sock_in = sock.makefile("rb", buffering=0)
    sock_out = sock.makefile("wb", buffering=0)

    stdin_b = sys.stdin.buffer
    stdout_b = sys.stdout.buffer

    t1 = threading.Thread(
        target=pump,
        args=(stdin_b, sock_out),
        name="airg-shim-client-to-server",
        daemon=True,
    )
    t2 = threading.Thread(
        target=pump,
        args=(sock_in, stdout_b),
        name="airg-shim-server-to-client",
        daemon=True,
    )

    t1.start()
    t2.start()
    t1.join()
    t2.join()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    # Resolve socket path: env > argv[1] > error.
    sock_path = os.environ.get("AIRG_SOCKET_PATH", "").strip()
    if not sock_path and len(sys.argv) > 1:
        sock_path = sys.argv[1].strip()
    if not sock_path:
        print(
            "usage: airg_stdio_bridge.py <socket-path>\n"
            "  or set AIRG_SOCKET_PATH in the environment",
            file=sys.stderr,
        )
        raise SystemExit(1)

    run_bridge(sock_path)


if __name__ == "__main__":
    main()
