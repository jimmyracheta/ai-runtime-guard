# AI Runtime Guard Manual

This manual explains current runtime behavior as implemented today.

## 1. What the server does
- Exposes MCP tools: `server_info`, `execute_command`, `approve_command`, `read_file`, `write_file`, `delete_file`, `list_directory`, `restore_backup`.
- Applies policy from `policy.json` before side effects.
- Logs all actions to `activity.log`.
- Creates backups for destructive operations in `backups/`.

## 2. Policy tier order (most important)
Command checks run in strict precedence:
1. `blocked`
2. `requires_confirmation`
3. `requires_simulation`
4. `allowed`

If a command matches multiple tiers, the highest tier wins.

## 3. Command matching behavior
- Matching is not strict full-string equality.
- Single-token patterns (example: `rm`) are token-aware.
- Multi-token patterns (example: `rm -rf`) match normalized command sequences.

Examples:
- `rm -rf /tmp/x` matches blocked `rm -rf`.
- `rm *.txt` does not match `rm -rf`; it can still be caught by `requires_confirmation`/`requires_simulation` if `rm` is configured there.

## 4. Confirmation handshake behavior
Current flow:
1. `execute_command` is blocked with a token when `requires_confirmation` matches.
2. `approve_command(command, token)` whitelists that exact normalized command hash for this server session.
3. Re-running the exact command can proceed.

Storage model:
- pending approvals are persisted in `approvals.db` (SQLite) so separate processes can read/update the same queue.
- each pending record includes `token`, `command`, `session_id`, `requested_at`, `expires_at`, and optional `affected_paths`.
- approved commands are persisted as one-time session+command grants in SQLite and consumed by MCP confirmation checks on retry.

Current security status:
- Merge freeze is active because approval separation-of-duties is not enforced yet.
- The same agent/tool context can currently request and approve in-line.
- This is documented as a release blocker in `STATUS.md`.

## 5. Simulation behavior
- Simulation is used for wildcard blast-radius checks (`requires_simulation.commands`).
- Wildcard operations can be blocked if unresolved or above threshold.

Important current nuance:
- If `requires_confirmation` matches first (for example `rm`), user-facing response may show confirmation gating instead of a distinct simulation reason.

## 6. Retry behavior
- Retries are server-side, not client-authoritative.
- Retry key is scoped to `(normalized_command + decision_tier + matched_rule)`.
- Retries are not one global counter for the entire session.

Practical effect:
- Different blocked command/rule combinations maintain independent retry counters.

## 7. Budget behavior
Current enforced budget:
- Global cumulative budget under `requires_simulation.cumulative_budget`.
- Scope is policy-driven (currently typically `session`).
- Aggregates operations/paths/bytes across included commands.

Not currently enforced:
- Per-command budget overrides from UI metadata.
- Budget override tied to confirmation approvals is temporarily disabled during durable approval migration (pending explicit redesign).

## 8. UI retry/budget fields: what they mean today
The local policy UI writes optional per-command metadata:
- `policy.ui_overrides.commands.<command>.retry_override`
- `policy.ui_overrides.commands.<command>.budget.*`

Current status:
- Persisted in `policy.json`.
- Visible in UI status tags.
- Not enforced by runtime yet.

## 9. Backup and restore behavior
- Backup creation occurs before destructive/overwrite actions.
- Backups are timestamped directories with `manifest.json`.
- `restore_backup` supports dry run and apply.

Important improvement already implemented:
- Dry run issues a `restore_token` bound to the apply step.

## 10. Network behavior
- Network policy gate is active via `network.enforcement_mode` and `network.commands`.
- Domain allow/block logic applies when network intent is detected.

Still limited:
- Deep payload/protocol enforcement is not complete.

## 11. Local policy UI behavior (current)
Current recommended UI stack:
- Backend: Flask (`ui/backend_flask.py`)
- Frontend: Vite React + Tailwind (`ui_v3/`)

Behavior:
- Three-layer navigation: rail (`Approvals`, `Commands`, `Reports`, `Settings`) + command tabs + content panel.
- Approvals panel polls backend and supports `approve`/`deny` actions against shared SQLite approval store.
- Commands panel supports search, tier radios, tooltip descriptions, applied-state badges, retry/budget metadata inputs, and advanced JSON editor.
- Status badges reflect applied policy only (post-`Apply`).
- `Apply` performs validation, atomic write, and appends `ui/config_changes.log`.

## 12. What is automatic vs manual in UI command catalog
Automatic:
- Commands added to policy command lists appear in `All Commands`.

Manual:
- Category/tab placement and descriptions are maintained in `ui/catalog.json`.
- New category tabs require editing `ui/catalog.json`.

## 13. Merge and release gates (current)
Before merge to `main`:
1. Unit tests must pass (`python3 -m unittest discover -s tests -p 'test_*.py'`).
2. Manual MCP gate from `tests.md` must pass.
3. Linux validation checkpoint must pass.
4. Approval separation gate must pass (agent cannot self-approve).

## 14. Known high-priority limitations
- Approval separation-of-duties blocker (merge freeze).
- `shell=True` remains in command execution path.
- Simulation diagnostics are partially obscured when confirmation wins tier precedence.
- Cumulative budget defaults may be too high to trigger in typical manual runs.
- Per-command UI override fields are metadata only today.
