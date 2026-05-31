"""Thin MCP entrypoint that wires tool handlers from modular components."""

import os

import anyio
from mcp.server.fastmcp import FastMCP

import approvals
from tools import (
    delete_file,
    edit_file,
    execute_command,
    list_directory,
    read_file,
    restore_backup,
    server_info,
    write_file,
)

approvals.init_approval_store()

mcp = FastMCP("ai-runtime-guard")

for tool in [
    server_info,
    restore_backup,
    execute_command,
    read_file,
    write_file,
    edit_file,
    delete_file,
    list_directory,
]:
    mcp.tool()(tool)


if __name__ == "__main__":
    # Socket path may come from env (set by airg-server --socket or launcher).
    # If set, serve over AF_UNIX socket; otherwise fall back to default stdio.
    _socket_path = os.environ.get("AIRG_SOCKET_PATH", "").strip()
    if _socket_path:
        from unix_socket_server import run_unix_socket_async
        anyio.run(run_unix_socket_async, mcp, _socket_path)
    else:
        mcp.run()
