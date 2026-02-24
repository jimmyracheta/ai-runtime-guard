import sys
import types

# Minimal stub so tests can import server.py without installing MCP.
if "mcp.server.fastmcp" not in sys.modules:
    mcp_mod = types.ModuleType("mcp")
    mcp_server_mod = types.ModuleType("mcp.server")
    mcp_fastmcp_mod = types.ModuleType("mcp.server.fastmcp")

    class FastMCP:
        def __init__(self, _name):
            pass

        def tool(self):
            def decorator(func):
                return func
            return decorator

        def run(self):
            return None

    mcp_fastmcp_mod.FastMCP = FastMCP
    sys.modules["mcp"] = mcp_mod
    sys.modules["mcp.server"] = mcp_server_mod
    sys.modules["mcp.server.fastmcp"] = mcp_fastmcp_mod

import server


def test_server_retry_counter_clamps_at_max_retries():
    original_max = server.MAX_RETRIES
    try:
        server.MAX_RETRIES = 3
        server.SERVER_RETRY_COUNTS.clear()

        counts = [
            server._register_retry("rm *.tmp", "requires_simulation", "requires_simulation.bulk_file_threshold")
            for _ in range(5)
        ]
        retry_key = server._retry_key("rm *.tmp", "requires_simulation", "requires_simulation.bulk_file_threshold")

        assert counts == [1, 2, 3, 3, 3]
        assert max(counts) == server.MAX_RETRIES
        assert server.SERVER_RETRY_COUNTS[retry_key] == server.MAX_RETRIES
    finally:
        server.MAX_RETRIES = original_max
        server.SERVER_RETRY_COUNTS.clear()
