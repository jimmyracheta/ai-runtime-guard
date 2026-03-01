# Test Plan

This is the public manual validation plan for `ai-runtime-guard`.

## 1. Setup validation
1. Install with `airg-setup`.
2. Run `airg-doctor`.
3. Confirm MCP client connects to `airg-server`.

## 2. Core policy checks
1. Allowed command succeeds (example: `ls -la` in workspace).
2. Blocked destructive command is denied (example: `rm -rf /tmp/test`).
3. Path boundary check blocks out-of-workspace access.

## 3. Confirmation flow
1. Configure a command under `requires_confirmation`.
2. Trigger command from agent and confirm token is issued.
3. Approve via GUI/API and retry exact command.
4. Verify command executes only after approval.

## 4. Simulation and budget checks
1. Configure simulation command and threshold.
2. Trigger wildcard command that exceeds threshold and verify block.
3. Trigger command below threshold and verify allow.
4. If budget enabled, verify cumulative limits block as configured.

## 5. Backup and restore checks
1. Overwrite or delete a file in workspace.
2. Confirm backup entry is created.
3. Run restore dry-run and apply path.

## 6. Reporting checks
1. Open reports dashboard and confirm event counts are populated.
2. Open reports log and validate filters/pagination.
3. Confirm manual refresh and scheduled refresh behavior.

## 7. Boundary warning validation
1. Confirm client native tools outside MCP are disabled.
2. Verify all tested operations were routed through AIRG MCP tools.
