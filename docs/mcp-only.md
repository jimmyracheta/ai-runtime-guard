# MCP-Only Mode

When this skill is active, you MUST operate exclusively through MCP server tools. The following built-in tools are DISABLED:

- **Bash** — do not use shell or terminal commands via the built-in Bash tool
- **Glob** — do not use the built-in file pattern matching tool
- **Read** — do not use the built-in file reader tool
- **Write** — do not use the built-in file writer tool
- **Edit** — do not use the built-in file editor tool

## Allowed Tools

Use ONLY the tools exposed by connected MCP servers. For the `ai-runtime-guard` server, the available tools are:

- `mcp__ai-runtime-guard__read_file` — read file contents
- `mcp__ai-runtime-guard__write_file` — write or create files
- `mcp__ai-runtime-guard__delete_file` — delete files
- `mcp__ai-runtime-guard__list_directory` — list directory contents
- `mcp__ai-runtime-guard__execute_command` — execute shell commands
- `mcp__ai-runtime-guard__restore_backup` — restore from backup
- `mcp__ai-runtime-guard__server_info` — get MCP server information

## Failure Handling

If an MCP tool call fails:

- **Do not** fall back to built-in tools (Bash, Glob, Read, Write, Edit)
- **Do not** attempt workarounds that bypass MCP constraints
- **Do** report the failure clearly to the user
- **Do** stay within what the MCP server allows and ask the user how to proceed if blocked
