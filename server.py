"""Thin MCP entrypoint that wires tool handlers from modular components."""

from mcp.server.fastmcp import FastMCP

import approvals
from tools import (
    delete_file,
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
    delete_file,
    list_directory,
]:
    mcp.tool()(tool)


if __name__ == "__main__":
    mcp.run()
