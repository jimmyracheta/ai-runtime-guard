"""
MCP server that exposes a single tool: execute_command.

The tool logs every call to activity.log, runs the shell command, and
returns its stdout (or stderr on failure).
"""

import json
import subprocess
import datetime

from mcp.server.fastmcp import FastMCP

# Create the MCP server with a descriptive name
mcp = FastMCP("ai-runtime-guard")


@mcp.tool()
def execute_command(command: str) -> str:
    """
    Execute a shell command and return its output.

    Args:
        command: The shell command to run (e.g. "ls -la" or "echo hello").

    Returns:
        stdout from the command, or stderr if the command fails.
    """

    # --- 1. Write a log entry before doing anything else ---
    log_entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "source": "ai-agent",
        "tool": "execute_command",
        "command": command,
    }

    # Open in append mode ("a") so previous entries are preserved
    with open("/Users/liviu/Documents/ai-runtime-guard/activity.log", "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # --- 2. Run the command ---
    result = subprocess.run(
        command,
        shell=True,        # Allows pipes, redirects, etc.
        capture_output=True,  # Captures both stdout and stderr
        text=True,         # Decodes bytes to str automatically
    )

    # --- 3. Return output or error ---
    # If there is any stderr output (even alongside stdout), include it.
    if result.returncode != 0:
        # Non-zero exit code means the command failed
        return result.stderr or f"Command exited with code {result.returncode}"

    # Success: return standard output (may be an empty string)
    return result.stdout


if __name__ == "__main__":
    # Run over stdio — the standard transport for MCP servers
    mcp.run()
