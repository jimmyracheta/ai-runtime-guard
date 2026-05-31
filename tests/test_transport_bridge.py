"""
Tests for the stdio<->AF_UNIX socket bridge (P1-a).

Test 1 — shim byte-faithfulness (test_shim_pump_*)
    Exercises the pump() function from scripts/airg_stdio_bridge.py:
    - bytes round-trip faithfully including a partial / large payload
    - EOF causes clean exit

Test 2 — end-to-end MCP over socket (test_mcp_over_unix_socket_*)
    Starts run_unix_socket_async() against the real FastMCP ``mcp`` server
    (imported from server.py) in a background thread, connects a raw client,
    performs an MCP ``initialize`` handshake, then calls ``tools/list`` to
    verify a well-formed JSON-RPC response is returned.
"""

import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import pathlib

# Ensure src/ is on the path (mirrors tests/__init__.py).
SRC_DIR = pathlib.Path(__file__).resolve().parent.parent / "src"
SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "scripts"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


# ---------------------------------------------------------------------------
# Test 1 — shim pump byte-faithfulness
# ---------------------------------------------------------------------------


class _CollectingWriter:
    """
    A write-only buffer that survives ``close()`` calls so we can inspect
    what was written after pump() finishes.  pump() closes the dst when done,
    so a plain BytesIO becomes unreadable; this wrapper keeps the data.
    """

    def __init__(self):
        self._parts = []
        self.closed = False

    def write(self, data: bytes) -> None:
        if not self.closed:
            self._parts.append(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    def getvalue(self) -> bytes:
        return b"".join(self._parts)


class TestShimPump(unittest.TestCase):
    """Exercises the pump() helper from airg_stdio_bridge without subprocess."""

    def _import_pump(self):
        """Import pump() from scripts/airg_stdio_bridge.py."""
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "airg_stdio_bridge",
            str(SCRIPTS_DIR / "airg_stdio_bridge.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.pump

    def _echo_server(self, sock_path: str, ready_event: threading.Event) -> None:
        """Simple AF_UNIX echo server for testing."""
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            srv.bind(sock_path)
            srv.listen(1)
            ready_event.set()
            conn, _ = srv.accept()
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)
            finally:
                conn.close()
        finally:
            srv.close()
            try:
                os.unlink(sock_path)
            except OSError:
                pass

    def test_pump_small_payload(self):
        """pump() forwards a small payload faithfully."""
        pump = self._import_pump()
        data = b"hello world\n"
        src = io.BytesIO(data)
        dst = _CollectingWriter()
        pump(src, dst)
        self.assertEqual(dst.getvalue(), data)

    def test_pump_large_payload(self):
        """pump() forwards a large payload (> single chunk) faithfully."""
        pump = self._import_pump()
        # 64 KiB — larger than the 4096-byte chunk size
        data = os.urandom(65536)
        src = io.BytesIO(data)
        dst = _CollectingWriter()
        pump(src, dst)
        self.assertEqual(dst.getvalue(), data)

    def test_pump_eof_causes_clean_exit(self):
        """pump() returns (not raises) on empty input (immediate EOF)."""
        pump = self._import_pump()
        src = io.BytesIO(b"")  # immediate EOF
        dst = _CollectingWriter()
        # Should not raise
        pump(src, dst)
        self.assertEqual(dst.getvalue(), b"")

    def test_pump_partial_chunks(self):
        """pump() correctly reassembles data sent in multiple partial chunks."""
        pump = self._import_pump()

        class ChunkyReader:
            """Feeds data in small 3-byte chunks then EOF."""

            def __init__(self, data: bytes):
                self._data = data
                self._pos = 0

            def read(self, n: int) -> bytes:
                chunk = self._data[self._pos : self._pos + 3]
                self._pos += 3
                return chunk

            def close(self) -> None:
                pass

        payload = b"abcdefghijklmnopqrstuvwxyz"
        src = ChunkyReader(payload)
        dst = _CollectingWriter()
        pump(src, dst)
        self.assertEqual(dst.getvalue(), payload)

    def test_echo_roundtrip_via_unix_socket(self):
        """
        Full round-trip: pump() → AF_UNIX socket echo server → pump() back.
        Asserts bytes arrive faithfully at both ends.
        """
        pump = self._import_pump()

        with tempfile.TemporaryDirectory() as tmpdir:
            sock_path = os.path.join(tmpdir, "echo.sock")
            ready = threading.Event()
            srv_thread = threading.Thread(
                target=self._echo_server,
                args=(sock_path, ready),
                daemon=True,
            )
            srv_thread.start()
            ready.wait(timeout=3)

            # Connect client socket.
            client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client_sock.connect(sock_path)
            sock_in = client_sock.makefile("rb", buffering=0)
            sock_out = client_sock.makefile("wb", buffering=0)

            payload = b"test-payload-round-trip\n" * 100

            # Thread 1: send payload to socket (stdin → socket).
            send_buf = io.BytesIO(payload)
            t_send = threading.Thread(
                target=pump, args=(send_buf, sock_out), daemon=True
            )
            # Thread 2: receive echo from socket (socket → recv_buf).
            recv_buf = io.BytesIO()
            t_recv = threading.Thread(
                target=pump, args=(sock_in, recv_buf), daemon=True
            )

            t_send.start()
            t_recv.start()
            t_send.join(timeout=5)
            t_recv.join(timeout=5)

            self.assertEqual(recv_buf.getvalue(), payload)
            client_sock.close()


# ---------------------------------------------------------------------------
# Test 2 — end-to-end MCP over socket
# ---------------------------------------------------------------------------


def _run_server_in_thread(socket_path: str, started: threading.Event,
                           stop: threading.Event) -> None:
    """
    Run run_unix_socket_async() in a background thread using anyio.
    Sets *started* when the socket file exists, and exits when *stop* is set
    (via cancellation scope).
    """
    import anyio
    from unix_socket_server import run_unix_socket_async
    from server import mcp as airg_mcp

    async def _serve():
        async with anyio.create_task_group() as tg:
            async def _wait_and_signal():
                # Wait for socket file to appear.
                for _ in range(50):
                    if os.path.exists(socket_path):
                        started.set()
                        break
                    await anyio.sleep(0.05)
                # Run until stop requested.
                while not stop.is_set():
                    await anyio.sleep(0.1)
                tg.cancel_scope.cancel()

            tg.start_soon(_wait_and_signal)
            tg.start_soon(run_unix_socket_async, airg_mcp, socket_path)

    anyio.run(_serve)


class TestMCPOverUnixSocket(unittest.TestCase):
    """End-to-end test: MCP initialize + tools/list over AF_UNIX socket."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="airg-bridge-test-")
        self._sock_path = os.path.join(self._tmpdir, "test-airg.sock")
        self._started = threading.Event()
        self._stop = threading.Event()
        self._server_thread = threading.Thread(
            target=_run_server_in_thread,
            args=(self._sock_path, self._started, self._stop),
            daemon=True,
        )
        # Set required env vars so the server initializes cleanly.
        os.environ.setdefault("AIRG_AGENT_ID", "test-bridge-agent")
        os.environ.setdefault(
            "AIRG_WORKSPACE", str(pathlib.Path(self._tmpdir).resolve())
        )
        self._server_thread.start()
        # Wait up to 10 seconds for the socket to appear.
        if not self._started.wait(timeout=10):
            self._stop.set()
            raise RuntimeError("Server did not start within 10 seconds")

    def tearDown(self):
        self._stop.set()
        self._server_thread.join(timeout=5)
        # Remove temp dir.
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _send_recv(
        self, conn: socket.socket, request: dict, timeout: float = 10.0
    ) -> dict:
        """
        Send a JSON-RPC request (newline-delimited) and read the response line.
        """
        line = json.dumps(request) + "\n"
        conn.sendall(line.encode("utf-8"))

        # Read until we get a complete newline-terminated response.
        buf = b""
        deadline = time.time() + timeout
        conn.settimeout(1.0)
        while time.time() < deadline:
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                line_bytes, _ = buf.split(b"\n", 1)
                return json.loads(line_bytes.decode("utf-8"))
        raise TimeoutError(f"No response received within {timeout}s; buf={buf!r}")

    def test_initialize_and_tools_list(self):
        """
        Perform MCP initialize handshake then list tools; assert well-formed
        JSON-RPC responses with the expected structure.
        """
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.connect(self._sock_path)
        try:
            # --- initialize ---
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "0.0.1"},
                },
            }
            init_resp = self._send_recv(conn, init_req)
            self.assertEqual(init_resp.get("jsonrpc"), "2.0")
            self.assertEqual(init_resp.get("id"), 1)
            self.assertIn("result", init_resp, f"No 'result' in response: {init_resp}")
            result = init_resp["result"]
            self.assertIn("protocolVersion", result)
            self.assertIn("serverInfo", result)

            # --- initialized notification ---
            init_notif = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }
            line = json.dumps(init_notif) + "\n"
            conn.sendall(line.encode("utf-8"))

            # Give server a moment to process the notification.
            time.sleep(0.05)

            # --- tools/list ---
            tools_req = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            }
            tools_resp = self._send_recv(conn, tools_req)
            self.assertEqual(tools_resp.get("jsonrpc"), "2.0")
            self.assertEqual(tools_resp.get("id"), 2)
            self.assertIn(
                "result", tools_resp, f"No 'result' in tools/list response: {tools_resp}"
            )
            tools_result = tools_resp["result"]
            self.assertIn("tools", tools_result)
            tool_names = [t["name"] for t in tools_result["tools"]]
            # server_info is a known read-only tool registered in server.py.
            self.assertIn(
                "server_info",
                tool_names,
                f"server_info not found in tool list: {tool_names}",
            )
        finally:
            conn.close()

    def test_second_connection_is_served(self):
        """
        A second client can connect and run its own MCP session independently.
        The server handles multiple sequential connections.
        """
        for conn_id in range(2):
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.connect(self._sock_path)
            try:
                init_req = {
                    "jsonrpc": "2.0",
                    "id": conn_id * 10 + 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {
                            "name": f"test-client-{conn_id}",
                            "version": "0.0.1",
                        },
                    },
                }
                resp = self._send_recv(conn, init_req)
                self.assertIn(
                    "result",
                    resp,
                    f"Connection {conn_id}: no 'result' in response: {resp}",
                )
            finally:
                conn.close()
            # Small gap between connections.
            time.sleep(0.05)


# ---------------------------------------------------------------------------
# Test 3 — stale socket cleanup in run_unix_socket_async
# ---------------------------------------------------------------------------


class TestStaleSocketCleanup(unittest.TestCase):
    """Verifies the stale-socket detection / cleanup logic."""

    def test_stale_socket_is_removed_before_bind(self):
        """
        If a stale socket file exists (no listener), it is unlinked so the
        new bind succeeds.
        """
        from unix_socket_server import _cleanup_stale_socket

        with tempfile.TemporaryDirectory() as tmpdir:
            sock_path = os.path.join(tmpdir, "stale.sock")
            # Create a stale socket (bind but never listen/accept).
            stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stale.bind(sock_path)
            stale.close()
            self.assertTrue(os.path.exists(sock_path))

            # Should cleanly remove the stale file.
            _cleanup_stale_socket(sock_path)
            self.assertFalse(os.path.exists(sock_path))

    def test_no_stale_socket_noop(self):
        """_cleanup_stale_socket is a no-op when the path does not exist."""
        from unix_socket_server import _cleanup_stale_socket

        with tempfile.TemporaryDirectory() as tmpdir:
            missing = os.path.join(tmpdir, "nonexistent.sock")
            # Should not raise.
            _cleanup_stale_socket(missing)

    def test_live_socket_raises(self):
        """
        _cleanup_stale_socket raises RuntimeError if something is actively
        listening on the socket.
        """
        from unix_socket_server import _cleanup_stale_socket

        with tempfile.TemporaryDirectory() as tmpdir:
            sock_path = os.path.join(tmpdir, "live.sock")
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
            srv.listen(1)
            try:
                with self.assertRaises(RuntimeError):
                    _cleanup_stale_socket(sock_path)
            finally:
                srv.close()
                try:
                    os.unlink(sock_path)
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()
