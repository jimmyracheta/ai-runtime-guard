# AIRG v2.0 Current Feature Summary (Internal)

This document is an internal, comprehensive snapshot of what AIRG does now.

## 1. Product scope
AIRG is a local-first MCP policy enforcement server plus GUI control plane.
It enforces policy at runtime for AIRG MCP tools and provides centralized agent config and posture management.

Primary goal:
1. Reduce accidental destructive actions and common policy-evasion patterns from AI agents.
2. Preserve policy intent for direct and indirect execution flows.

Not primary goal:
1. Full malicious actor containment.

## 2. Official support
Platforms:
1. macOS
2. Linux

Supported agents (GUI-managed):
1. Claude Code
2. Claude Desktop
3. Codex
4. Cursor

## 3. Runtime architecture
Core runtime behavior:
1. MCP tool request enters AIRG server.
2. Policy/path/network/execution gates are evaluated.
3. Decision is applied (`blocked`, `requires_confirmation`, `allowed`).
4. If allowed, action executes with safety controls (backup where applicable).
5. Structured events are appended to `activity.log`.
6. Reports ingest copies indexed events into `reports.db`.

Runtime state:
1. `policy.json`
2. `approvals.db`
3. `approvals.db.hmac.key`
4. `activity.log`
5. `reports.db`
6. backups directory

## 4. MCP tool surface
Current AIRG MCP tools:
1. `server_info`
2. `execute_command`
3. `read_file`
4. `write_file`
5. `edit_file`
6. `delete_file`
7. `list_directory`
8. `restore_backup`

## 5. Policy model
Active command tiers:
1. `blocked`
2. `requires_confirmation`
3. `allowed`

Removed/deprecated:
1. Simulation tier removed from runtime and GUI logic.
2. Budget controls removed from runtime and GUI logic.

Policy sections in use:
1. `blocked` (commands, paths, extensions)
2. `requires_confirmation` (commands, paths, approval security)
3. `allowed` (whitelist roots, directory depth)
4. `network` (commands, mode, allowlist/denylist)
5. `execution` (timeout/output caps + shell workspace containment)
6. `backup_access`
7. `restore`
8. `audit`
9. `reports`
10. `script_sentinel`
11. `agent_overrides`

## 6. Default policy baseline (v2 state)
Default posture philosophy:
1. Block high-risk destructive commands by default.
2. Allow normal work by default.
3. No default confirmation-gated commands (operator can add).

Examples in blocked defaults:
1. destructive deletion wrappers (`rm -rf`, `find -delete`, `xargs rm`)
2. disk/system destructive commands (`dd`, `mkfs`, `fdisk`, `parted`, `wipefs`, power/reboot variants)
3. privilege escalation (`sudo`, `su`, `doas`)
4. risky git destructive reset/clean patterns

Script Sentinel defaults:
1. `enabled: true`
2. `mode: match_original`
3. `scan_mode: exec_context_plus_mentions`
4. `include_wrappers: true`

## 7. Script Sentinel
Design:
1. Flag at write time (`write_file`, `edit_file`).
2. Enforce at execute time (`execute_command`) if flagged artifacts are invoked.

Decision modes:
1. `match_original`: preserve originating policy tier.
2. `block`: any enforceable hit blocks.
3. `requires_confirmation`: any enforceable hit requires approval.

Scan modes:
1. `exec_context`: executable-context signatures only.
2. `exec_context_plus_mentions`: includes mention-only hits for audit visibility.

Tracking:
1. Content-hash artifact registry in `reports.db`.
2. Path-to-hash mapping persists flags across rename/copy scenarios when hash is unchanged.
3. Allowance controls support one-time dismiss or trust flows.

Boundary:
1. Detection covers files written through AIRG write/edit tools.
2. Out-of-band file writes are outside write-time scan scope.

## 8. Command enforcement details
`execute_command` guard sequence:
1. Reject control characters.
2. Protect backup storage from direct shell targeting.
3. Apply network policy.
4. Apply shell workspace containment policy.
5. Apply command tier matching (`blocked`, `requires_confirmation`, `allowed`).
6. Apply Script Sentinel execute-time checks.
7. Backup destructive targets when needed.
8. Execute command and log telemetry.

Additional behavior:
1. Blocked non-confirmation paths use server-side retry clamp behavior.
2. Confirmation flow produces tokenized approval responses.

## 9. File/path protections
Enforced across file tools:
1. Workspace boundary checks
2. Blocked paths and extensions
3. Optional allowed-path whitelist expansion
4. Directory depth control

Runtime-state hardening:
1. Critical state artifacts are protected from normal agent file access.

## 10. Approvals and approval security
Capabilities:
1. Pending approval queue
2. Approval history with timestamps and approver source
3. Session+command scoped approval consumption

Security controls:
1. HMAC key for approval state integrity
2. token TTL
3. max failed attempts per token
4. failed-attempt inactivity window

## 11. Backup and restore
Backup:
1. Auto-backup on destructive/overwrite operations (policy controlled).
2. Content-change-only dedup behavior.
3. Retention and max versions policy controls.

Restore:
1. Dry-run first (optional required mode).
2. Token-gated apply with TTL.
3. Backup-root constraints prevent arbitrary restore-path abuse.

## 12. Audit and reports
Audit stream:
1. `activity.log` is the canonical structured event stream.
2. AIRG hook events are merged into the same stream format.

Reports:
1. `reports.db` stores indexed analytics from `activity.log`.
2. Retention, DB size limits, and prune/reconcile intervals are policy controlled.
3. UI surfaces include dashboard trends, event log, approvals, and script sentinel reporting.

## 13. GUI capabilities
Major sections:
1. Approvals (`Pending`, `History`)
2. Policy (`Rules`, `Network`, `Script Sentinel`, `Agent Overrides`, `Advanced`)
3. Reports (`Dashboard`, `Log`)
4. Settings (`Agents`)

Policy editor:
1. Validate/apply/revert/reset flow
2. command/path/extension management
3. network controls
4. script sentinel controls + artifact table

Settings -> Agents:
1. Profile CRUD
2. MCP config generation (JSON + CLI command)
3. Single-click MCP apply/remove
4. Security posture scan/refresh
5. Enforcement options per supported agent type

## 14. Agent management and posture model
Common posture labels:
1. Off (gray)
2. Standard (red) - MCP configured
3. Strict (yellow) - stronger controls by agent type
4. Maximum (green) - strongest supported posture for that client

### Claude Code
MCP scopes:
1. Project (`<workspace>/.mcp.json`)
2. Local (`~/.claude.json` project entry)
3. User (`~/.claude.json` global entry)

Enforcement options:
1. Standard: AIRG MCP configured
2. Strict:
   - basic enforcement hooks for `Bash`, `Write`, `Edit`, `MultiEdit`
   - native tool restrictions
3. Maximum:
   - sandbox enabled
   - sandbox escape closed
4. Optional:
   - Read/Glob/Grep hook enforcement

### Claude Desktop
Scope:
1. Desktop config file MCP registration only.

Posture:
1. MCP-only posture model (no hook/sandbox controls exposed).

### Codex
MCP scopes:
1. Global (`~/.codex/config.toml`)
2. Project (`<workspace>/.codex/config.toml`)

Enforcement options:
1. Standard: AIRG MCP
2. Strict:
   - Tier 1 guidance block in the active Codex scope `AGENTS.md`
   - Tier 2 policy mirror in the active Codex scope `rules/airg.rules`
   - mirror approvals mode (`allow`, `approve`, `deny`)
3. Maximum:
   - sandbox mode + approval policy hardening
   - workspace-write sandbox options (network access and tmp restrictions)

### Cursor
Support:
1. MCP configuration and posture detection.
2. MCP-layer controls only (no native hook/sandbox parity exposed).

## 15. Installation and operations
Supported install paths:
1. Recommended operator install: `pipx`
2. Recommended development install: `venv` + pip
3. Source clone install (`pip install .`)

Why isolation:
1. avoid system-package conflicts
2. cleaner upgrades/uninstalls
3. lower permission friction

Known friction points:
1. after `pipx ensurepath`, shell restart/new terminal needed
2. stale MCP/client configs can point to old AIRG binaries
3. mixed install methods on one host can create path ambiguity

## 16. Known boundaries and limitations
1. AIRG enforces only AIRG MCP tool calls.
2. Native client tools outside MCP can bypass AIRG unless client-side restrictions are enabled.
3. Multi-instance same-client same-workspace identity separation is limited in STDIO model.
4. Effective separation is generally `AIRG_AGENT_ID + AIRG_WORKSPACE`.
5. Stronger per-instance identity requires authenticated HTTP/SSE architecture (future path).

## 17. Operational best practices
1. Use guided setup (`airg-setup`) to define workspace and initialize service.
2. Manage agents through GUI `Settings -> Agents`.
3. Confirm active runtime path/build with `server_info`.
4. Keep one install method per host (`pipx` or one managed venv).
5. Re-scan posture after agent config changes.
6. Treat Script Sentinel as policy-intent continuity, not malware detection.
