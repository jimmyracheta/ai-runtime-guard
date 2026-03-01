# Linux Validation Summary

This summary replaces older raw Linux validation transcripts.

## Outcome
1. Fresh Linux install flow is validated with `airg-setup` and `airg-doctor`.
2. MCP connectivity and core tool operations were validated from a non-root user context.
3. Approval flow works with correct runtime state and key material.
4. Reports, logging, and UI startup behavior were validated in the current flow.

## Key notes
1. Use `airg-setup` as primary onboarding command.
2. Keep runtime state outside workspace and outside project directory.
3. Use explicit MCP env values for deterministic startup.
4. For strict enforcement boundaries, disable native client shell/file tools outside MCP.

## Historical raw logs
Older detailed Linux validation transcripts and friction logs were moved out of public docs and retained as internal historical material.
