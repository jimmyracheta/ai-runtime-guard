# ai-runtime-guard

> Your agent can say anything. It can only do what policy allows.

AI agents with filesystem and shell access can delete files, leak credentials, or execute destructive commands, often without the user realizing until it is too late.

**Runtime Guard** sits between your AI agent and your system, enforcing policy on every file and shell action before it executes. Install once, configure your rules, and your agent operates within the boundaries you set. Works with Claude Code, Claude Desktop, Cursor, Codex, and any MCP-compatible client. No retraining, no prompt engineering, no external account required.

[![runtime-guard MCP server](https://glama.ai/mcp/servers/runtimeguard/runtime-guard/badges/score.svg)](https://glama.ai/mcp/servers/runtimeguard/runtime-guard)

## See it in action

```
agent -> execute_command("rm -rf /tmp/build")
✗ BLOCKED  destructive command pattern: rm -rf
  matched_rule: destructive_command | decision: blocked

agent -> execute_command("git push --force")
⏸ APPROVAL REQUIRED  awaiting operator
  token: a4f2b9 | expires: 10min | check GUI to approve

agent -> write_file("README.md", ...)
✓ ALLOWED  backup created before write
  backup_location: ~/.local/state/airg/backups/2026-03-18
```

## Quick start

```
pipx install ai-runtime-guard
pipx ensurepath          # if airg* commands are not found
# open a new terminal
airg-setup
airg-doctor
```

After setup, open `http://127.0.0.1:5001` and add your first agent from `Settings -> Agents`.

<details>
<summary>Alternative install methods (venv, source, CI)</summary>

Alternative quick start (`venv`):
1. `python3 -m venv .venv-airg && source .venv-airg/bin/activate`
2. `python -m pip install --upgrade pip`
3. `python -m pip install ai-runtime-guard`
4. `airg-setup` (guided, recommended: select/create workspace during setup; includes telemetry opt-in prompt, default Yes)
5. `airg-doctor`
6. Open GUI `Settings -> Agents`, add agents manually, and apply MCP config/hardening from there.

Source-clone path:
1. `git clone --branch main https://github.com/runtimeguard/runtime-guard.git`
2. `cd runtime-guard`
3. `python3 -m venv .venv-airg && source .venv-airg/bin/activate`
4. `python -m pip install --upgrade pip`
5. `python -m pip install .`
6. `airg-setup`
7. `airg-doctor`

Unattended automation-only setup (CI/non-interactive):
1. `airg-setup --defaults --yes --workspace /absolute/path/to/workspace`


</details>

See [docs/INSTALL.md](docs/INSTALL.md) for the full install reference.

## What it does

**Prevention**
- Blocks destructive commands (`rm -rf`, privilege escalation, sensitive file access) before they run
- Auto-backs up any file before destructive or overwrite operations

**Control**
- Gates risky commands behind explicit human approval via local GUI or API
- Enforces workspace and path boundaries keyed to `AIRG_WORKSPACE`
- Supports per-agent policy overlays keyed to `AIRG_AGENT_ID`
- Configurable network policy with allowlists, denylists, and monitor/enforce modes

**Visibility**
- Logs every allowed, blocked, and pending action to `activity.log`
- Indexes events into `reports.db` for a dashboard view of agent behavior

**Hardening**
- Script Sentinel: detects attempts to launder blocked commands through scripts
- Universal agent hardening: GUI-driven posture enforcement including hooks, sandboxing, and native tool restrictions (support varies by client)

## Why MCP

Runtime Guard is built as an MCP server because MCP provides the interception point you need. When your agent issues a tool call, Runtime Guard evaluates it against policy before execution. For clients that support pre-tool hooks (like Claude Code), AIRG can also deny the agent's native file and shell tools, forcing risky operations through the policy layer.

This approach is the closest to kernel-level enforcement without requiring system privileges or modifying your agent, and it works across any MCP-compatible client without per-agent engineering.

## Who it is for

Developers and operators running AI agents who want deterministic guardrails on what an agent can actually do to their system, without giving up agent autonomy or rewriting their workflow.

## Supported platforms and clients

| Platform | Clients                                     |
|----------|---------------------------------------------|
| macOS    | Claude Code, Claude Desktop, Cursor, Codex  |
| Linux    | Claude Code, Claude Desktop, Cursor, Codex  |

Enforcement depth varies by client. MCP policy enforcement is universal; hook-based native tool restriction and sandboxing depend on what each client exposes.

For Codex, AIRG supports both user-scope (`~/.codex/`) and project-scope (`<workspace>/.codex/`) artifacts. Project-scope enforcement requires the workspace to be trusted in the user-layer `~/.codex/config.toml` before Codex will load the project `.codex/` files. AIRG writes Codex tool approval stanzas only in the project-scoped `.codex/config.toml`.

## Scope and boundaries

**What AIRG is designed for**: reducing accidental damage from agent mistakes, hallucinated commands, and policy-evasion patterns.

**What AIRG is not**: a full malicious-actor containment platform.

**Known enforcement boundary**:
- AIRG enforces policy only on actions routed through AIRG MCP tools
- Native client tools outside MCP (e.g. Claude Code's built-in Bash, Glob, Read, Write, Edit) bypass AIRG unless the client is configured to restrict them
- For strict enforcement, use `Settings -> Agents` in the GUI to apply hook-based native tool restrictions where supported

## Configuration essentials

### `AIRG_WORKSPACE`

The default project root for guarded agent operations. `execute_command` runs from this directory, file tools evaluate path policy relative to this root, and traversal outside the root is blocked. Multiple workspaces are supported. Each agent profile should set workspace explicitly in its MCP config.

### `AIRG_AGENT_ID`

The runtime identity key used for activity and report attribution, per-agent policy override resolution, and posture state in `Settings -> Agents`.

## Web GUI

AIRG includes a local web control plane at `http://127.0.0.1:5001` for policy editing, approvals, agent profile management, reports, and telemetry control.

Service commands:

```
airg-service install --workspace /absolute/path/to/airg-workspace
airg-service start | status | stop | restart | uninstall
```

## Telemetry

AIRG supports optional anonymous telemetry to help prioritize improvements. It is opt-in during setup (default: Yes) and can be toggled any time from `Policy -> Advanced -> Anonymous telemetry`.

- No command text, file contents, paths, prompts, usernames, or machine identifiers are collected
- One aggregate payload per UTC day
- Payload preview available in the GUI before enabling
- Full details in [docs/telemetry.md](docs/telemetry.md)

## More

- [Full documentation](https://runtime-guard.ai/docs)
- [Install reference](docs/INSTALL.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
