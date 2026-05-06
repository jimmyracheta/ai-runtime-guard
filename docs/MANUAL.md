# AI Runtime Guard Manual

This manual documents current runtime behavior for v2.3.1.

## 1. Runtime Surface
AIRG MCP tools:
1. `server_info`
2. `execute_command`
3. `read_file`
4. `write_file`
5. `edit_file`
6. `delete_file`
7. `list_directory`
8. `restore_backup`

Policy is enforced before side effects. Events are written to `activity.log` and ingested into `reports.db`.

## 2. Active Policy Tiers
Tier precedence for command policy:
1. `blocked`
2. `requires_confirmation`
3. `allowed`

Notes:
1. Legacy `requires_simulation` is no longer an active runtime tier.
2. Global cumulative budget enforcement is removed from active runtime logic.

## 3. Command Enforcement Flow (`execute_command`)
Order of checks:
1. Reject unsafe control characters (newline/carriage-return/NUL) in command payload.
2. Protect backup storage paths from direct shell targeting.
3. Apply network policy (`off` | `monitor` | `enforce`).
4. Apply shell workspace containment policy (`off` | `monitor` | `enforce`).
5. Evaluate command tier policy (`blocked` / `requires_confirmation` / `allowed`).
6. Apply Script Sentinel execute-time checks.
7. If allowed, optionally back up destructive targets and execute command.
8. Log decision and execution telemetry.

Substitution coverage:
1. Policy tokenization recursively inspects common substitution contexts before execution: `$(...)`, `` `...` ``, `<(...)`, `>(...)`, including nested forms.
2. Commands discovered in those inner contexts are evaluated by the same network and command-tier gates as top-level commands.
3. This remains best-effort static analysis of shell text, not a full shell interpreter.

Retry behavior:
1. Blocked non-confirmation decisions use server-side retry tracking.
2. Confirmation-tier decisions do not consume that retry bucket.

## 4. Script Sentinel
Purpose: preserve policy intent across indirect execution patterns.

Model:
1. Flag at write time (`write_file` and `edit_file`): scan content against blocked and approval-gated policy patterns.
2. Check at execute time (`execute_command`): detect script invocation targets and enforce decision continuity.

Modes:
1. `match_original`: keeps original pattern tier (`blocked` or `requires_confirmation`).
2. `block`: any hit blocks execution.
3. `requires_confirmation`: any hit requires approval.

Scan modes:
1. `exec_context` (default): executable-context signatures only.
2. `exec_context_plus_mentions`: includes mention-only signatures for audit visibility.

Boundary:
1. Coverage is limited to content written through AIRG file-edit/write tools.
2. This feature targets policy-enforcement evasion patterns, not malicious intent classification.

## 5. File and Path Enforcement
1. Path checks apply to all file tools and enforce workspace boundary plus blocked paths/extensions.
2. `allowed.paths_whitelist` can extend permitted roots.
3. `allowed.max_directory_depth` applies to directory listing depth controls.

## 6. Approvals
1. `requires_confirmation` commands return tokenized block responses.
2. Approval is out-of-band through GUI/API.
3. Approved command grants are session + command scoped.
4. Approval state is persisted in `approvals.db` with HMAC-backed safeguards.

## 7. Backup and Restore
1. Backups are created automatically before destructive or overwrite operations when enabled.
2. Backup retention and version count are policy controlled.
3. Restore supports dry-run token workflow and optional apply confirmation TTL.
4. Backup storage can be protected from direct agent tools by policy.

## 8. Reports and Audit
1. `activity.log` is the canonical event stream.
2. `reports.db` is an indexed analytics store built from `activity.log`.
3. Reports retention and DB-size pruning are configurable.
4. Hook events (for supported clients) are written into the same `activity.log` stream.

## 9. Agent Profiles and Posture
`Settings -> Agents` provides:
1. Agent profiles and MCP config generation/apply/remove.
2. Security posture signals by agent type.
3. Enforcement controls (agent-dependent): MCP presence, hooks/rules guidance, native tool restrictions, sandbox posture.

Identity model:
1. Per-agent policy overlays resolve by `AIRG_AGENT_ID`.
2. In STDIO deployments, practical separation is usually the tuple (`AIRG_AGENT_ID`, workspace profile).

## 10. Cursor Hardening (GUI)
Use this flow in `Settings -> Agents` for Cursor profiles:
1. Select a Cursor profile and ensure MCP is configured first with `Apply MCP Config`.
2. Open `Security Posture` and choose `Config scope`:
3. `Project` writes to `<workspace>/.cursor/*.json`.
4. `Global` writes to `~/.cursor/*.json`.

Control groups:
1. `STANDARD`: MCP-only posture (configured via `Apply MCP Config`).
2. `STRICT`: hook enforcement in `hooks.json` (`preToolUse`, `beforeShellExecution`, `beforeMCPExecution`; optional `beforeReadFile`) plus optional fail-closed behavior.
3. `MAXIMUM`: sandbox hardening in `sandbox.json` (`type`, `disableTmpWrite`, network defaults/sync, cache and path options).
4. `OPTIONAL`: `permissions.json` controls (MCP allowlist and terminal allowlist lock) and `.cursorignore` sync.

Scope applicability:
1. `permissions.json` is global-only in Cursor; AIRG applies those options only when scope is `Global`.
2. `.cursorignore` is project-level; AIRG writes `<workspace>/.cursorignore` regardless of selected scope.

Verification:
1. Re-open `Security Posture` and check signals for `hook_enforcement_active`, `hook_fail_closed_active`, and `sandbox_hardened`.
2. Optional signals are `permissions_airg_allowlist_configured`, `permissions_terminal_allowlist_locked`, `optional_read_hooks_active`, and `cursorignore_synced`.

## 11. Codex Hardening (GUI)
Use this flow in `Settings -> Agents` for Codex profiles:
1. Select a Codex profile and configure MCP first with `Apply MCP Config`.
2. Choose `Global` or `Project` scope in the profile.
3. For `Project` scope, trust the workspace in `~/.codex/config.toml` so Codex loads the project `.codex/` layer.

Scope targets:
1. `Global` writes:
   - `~/.codex/config.toml`
   - `~/.codex/AGENTS.md`
   - `~/.codex/rules/airg.rules`
2. `Project` writes:
   - `<workspace>/.codex/config.toml`
   - `<workspace>/.codex/AGENTS.md`
   - `<workspace>/.codex/rules/airg.rules`
3. AIRG writes Codex tool approval entries (`[mcp_servers.ai-runtime-guard.tools.*]`) only in project-scoped `<workspace>/.codex/config.toml`.

Control groups:
1. `STANDARD`: MCP configuration only.
2. `STRICT`: guidance block in `AGENTS.md` plus policy mirror in `rules/airg.rules`.
3. `MAXIMUM`: `sandbox_mode`, `approval_policy`, and `sandbox_workspace_write` settings in `config.toml`.

Notes:
1. AIRG uses a dedicated `airg.rules` file and does not manage `default.rules`.
2. Codex may continue to write user-approved allowlist entries into `~/.codex/rules/default.rules`; this is separate from AIRG-managed policy mirror state.
3. Project `.codex` trust lives in user `~/.codex/config.toml`, but AIRG does not write Codex tool approval entries to that user-layer file.

## 12. Known Boundaries
1. AIRG enforces only AIRG MCP tool calls.
2. Native client tools outside MCP can bypass AIRG unless separately restricted in the client.
3. Client capabilities differ; some hardening controls are unavailable on some agents.

Failure modes and practical limitations:
1. Hook policy is client-dependent; some native tools may remain allowed or unmapped by hook policy depending on client/hardening profile.
2. Command substitution and shell parsing are best-effort static analysis, not full shell interpretation.
3. Network enforcement depends on marker/domain extraction from command text and tokenized URL forms.
4. Shell workspace containment is heuristic path-token analysis and can run in `off` or `monitor` mode.
5. Script Sentinel write-time coverage applies only to content written via AIRG `write_file` / `edit_file`.
6. Mention-only sentinel matches are audit-visible but non-enforcing.
7. In STDIO deployments, practical identity separation is profile/environment based, not authenticated per-instance identity.

## 13. Hardening Checklist (Recommended Baseline)
1. Route all file/shell operations through AIRG MCP tools and disable risky native tools where the client supports it.
2. Enable and verify hook enforcement (`preToolUse`, `beforeShellExecution`, `beforeMCPExecution`; optional `beforeReadFile`) in clients that support hooks.
3. Set `network.enforcement_mode` to `enforce`; use `allowed_domains` and set `block_unknown_domains=true` for default-deny egress control.
4. Set `execution.shell_workspace_containment.mode` to `enforce` and keep `exempt_commands` minimal.
5. Keep `script_sentinel.enabled=true`; use `mode=match_original` or stricter (`block`) based on risk tolerance.
6. Keep backup protections enabled (`backup_access.block_agent_tools=true`, restore via `restore_backup` flow only).
7. Use distinct `AIRG_AGENT_ID` values per agent profile/workspace and avoid shared identities for high-sensitivity workflows.
8. Periodically validate posture and bypass resistance using `tests/test_airg_hook.py`, `tests/test_attacker_suite.py`, and substitution tests.

## 14. Telemetry
1. AIRG supports optional anonymous telemetry with one aggregate payload per UTC day when enabled.
2. Setup/update flow prompts for telemetry opt-in with default Yes.
3. You can change telemetry preference at any time in GUI: `Policy -> Advanced -> Anonymous telemetry` (`Enable/Disable` + `See Payload`).
4. Backend telemetry scheduler runs hourly and starts generator/uploader workers in parallel.
5. Policy telemetry runtime fields:
   - `telemetry.last_payload_generated_date`
   - `telemetry.last_payload_uploaded_at`
   - `telemetry.last_sent_date` (compatibility field, updates on upload success)
6. Endpoint configuration source of truth is policy (`telemetry.endpoint`), which can be set to a custom endpoint.
7. Full schema and examples: [`docs/telemetry.md`](telemetry.md).
