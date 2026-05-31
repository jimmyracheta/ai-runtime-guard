"""
AIRG unix-socket transport — Option A from transport-bridge-design.md §3.2

Provides ``run_unix_socket_async(mcp, socket_path)`` which binds an AF_UNIX
SOCK_STREAM socket and serves one MCP session per accepted connection.  The
JSON-RPC encode/decode logic is copied from ``mcp.server.stdio.stdio_server``
(newline-delimited JSON, UTF-8).  No SDK fork; uses the public low-level
``mcp._mcp_server.run(read_stream, write_stream, init_options)`` API.

Usage (normally invoked via ``airg-server --socket PATH``):

    import anyio
    from server import mcp
    from unix_socket_server import run_unix_socket_async

    anyio.run(run_unix_socket_async, mcp, "/tmp/my-agent.sock")
"""

from __future__ import annotations

import logging
import os
import socket as _socket
from contextlib import asynccontextmanager

import anyio
import anyio.lowlevel
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

import mcp.types as types
from mcp.shared.message import SessionMessage

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-connection session context manager (mirrors stdio_server)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _unix_socket_session(sock_stream: anyio.abc.SocketStream):
    """
    Wrap an accepted anyio SocketStream as the two memory-object-streams that
    ``mcp.server.lowlevel.Server.run()`` expects:

        read_stream:  MemoryObjectReceiveStream[SessionMessage | Exception]
        write_stream: MemoryObjectSendStream[SessionMessage]

    Framing: one UTF-8 JSON-RPC object per line, newline-terminated — identical
    to the stdio transport (confirmed from mcp/server/stdio.py inspection).
    """
    read_stream_writer: MemoryObjectSendStream[SessionMessage | Exception]
    read_stream: MemoryObjectReceiveStream[SessionMessage | Exception]
    write_stream: MemoryObjectSendStream[SessionMessage]
    write_stream_reader: MemoryObjectReceiveStream[SessionMessage]

    read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_stream_reader = anyio.create_memory_object_stream(0)

    # We accumulate incoming bytes into a line buffer, then parse JSON per line.
    recv_buf = bytearray()

    async def socket_reader() -> None:
        """Read bytes from socket, split on '\n', parse each line as JSON-RPC."""
        try:
            async with read_stream_writer:
                while True:
                    try:
                        chunk = await sock_stream.receive(4096)
                    except (anyio.EndOfStream, anyio.ClosedResourceError):
                        break
                    recv_buf.extend(chunk)
                    # Drain all complete lines from the buffer.
                    while b"\n" in recv_buf:
                        idx = recv_buf.index(b"\n")
                        line_bytes = bytes(recv_buf[: idx + 1])
                        del recv_buf[: idx + 1]
                        line = line_bytes.decode("utf-8", errors="replace").strip()
                        if not line:
                            continue
                        try:
                            message = types.JSONRPCMessage.model_validate_json(line)
                        except Exception as exc:
                            await read_stream_writer.send(exc)
                            continue
                        await read_stream_writer.send(SessionMessage(message))
        except anyio.ClosedResourceError:
            await anyio.lowlevel.checkpoint()

    async def socket_writer() -> None:
        """Serialize outgoing SessionMessages as newline-delimited JSON to socket."""
        try:
            async with write_stream_reader:
                async for session_message in write_stream_reader:
                    json_line = (
                        session_message.message.model_dump_json(
                            by_alias=True, exclude_none=True
                        )
                        + "\n"
                    )
                    try:
                        await sock_stream.send(json_line.encode("utf-8"))
                    except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                        break
        except anyio.ClosedResourceError:
            await anyio.lowlevel.checkpoint()

    async with anyio.create_task_group() as tg:
        tg.start_soon(socket_reader)
        tg.start_soon(socket_writer)
        yield read_stream, write_stream
        tg.cancel_scope.cancel()


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------


async def _handle_connection(
    mcp_server,  # FastMCP instance
    sock_stream: anyio.abc.SocketStream,
    conn_id: int,
) -> None:
    """Serve one MCP session over an accepted socket connection."""
    logger.debug("[airg-unix] connection %d accepted", conn_id)
    try:
        async with _unix_socket_session(sock_stream) as (read_stream, write_stream):
            await mcp_server._mcp_server.run(
                read_stream,
                write_stream,
                mcp_server._mcp_server.create_initialization_options(),
            )
    except Exception as exc:
        logger.debug("[airg-unix] connection %d closed: %s", conn_id, exc)
    finally:
        await sock_stream.aclose()
        logger.debug("[airg-unix] connection %d cleaned up", conn_id)


# ---------------------------------------------------------------------------
# Stale-socket cleanup helper
# ---------------------------------------------------------------------------


def _cleanup_stale_socket(path: str) -> None:
    """
    If a socket file already exists at *path*, check whether anything is
    listening.  If not (ECONNREFUSED / ENOENT on connect), unlink it so we
    can bind fresh.  If something IS listening, raise an error — don't stomp
    a live server.
    """
    if not os.path.exists(path):
        return
    test_sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    try:
        test_sock.connect(path)
        # Something answered — do NOT remove it.
        test_sock.close()
        raise RuntimeError(
            f"[airg-unix] Socket {path!r} already exists and has an active listener. "
            "Is another AIRG instance running?"
        )
    except (ConnectionRefusedError, FileNotFoundError, OSError):
        # No listener — safe to remove the stale socket file.
        test_sock.close()
    os.unlink(path)
    logger.debug("[airg-unix] removed stale socket file %s", path)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def run_unix_socket_async(mcp_server, socket_path: str) -> None:
    """
    Bind an AF_UNIX socket at *socket_path* (mode 0600) and serve the given
    FastMCP *mcp_server* instance.  Each accepted connection runs in its own
    anyio task and gets a full MCP session.

    The socket file is removed on exit (clean shutdown or cancellation).

    Args:
        mcp_server: A ``FastMCP`` instance (from ``server.py``).
        socket_path: Filesystem path for the AF_UNIX socket.
    """
    socket_path = os.fspath(socket_path)

    # Make sure the parent directory exists.
    parent = os.path.dirname(os.path.abspath(socket_path))
    os.makedirs(parent, mode=0o700, exist_ok=True)

    # Remove stale socket if present (but refuse if something is still listening).
    _cleanup_stale_socket(socket_path)

    # Temporarily set umask to 0177 so the created socket gets mode 0600.
    old_umask = os.umask(0o177)
    try:
        listener = await anyio.create_unix_listener(socket_path)
    finally:
        os.umask(old_umask)

    # Explicitly set permissions (belt-and-suspenders; umask covers it too).
    try:
        os.chmod(socket_path, 0o600)
    except OSError:
        pass

    logger.info("[airg-unix] listening on %s", socket_path)

    conn_counter = 0
    try:
        async with anyio.create_task_group() as tg:
            async with listener:
                while True:
                    sock_stream = await listener.accept()
                    conn_counter += 1
                    tg.start_soon(
                        _handle_connection, mcp_server, sock_stream, conn_counter
                    )
    finally:
        # Clean up socket file on shutdown.
        try:
            os.unlink(socket_path)
            logger.debug("[airg-unix] removed socket file %s", socket_path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.warning("[airg-unix] could not remove socket %s: %s", socket_path, exc)
