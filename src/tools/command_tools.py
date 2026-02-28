import pathlib
import subprocess

from approvals import issue_or_reuse_approval_token
from audit import append_log_entry, build_log_entry
from backup import MODIFYING_COMMAND_RE, backup_paths, extract_paths
from budget import check_and_record_cumulative_budget
from config import MAX_RETRIES, POLICY, SERVER_BUILD, SESSION_ID, WORKSPACE_ROOT
from executor import run_shell_command
from models import PolicyResult
from policy_engine import (
    check_policy,
    check_simulation_tier,
    command_targets_backup_storage,
    execution_limits,
    has_shell_unsafe_control_chars,
    network_policy_check,
    normalize_for_audit,
    register_retry,
    shell_workspace_containment_check,
    simulate_blast_radius,
    truncate_output,
    is_within_workspace,
)


def server_info() -> str:
    from config import BASE_DIR

    return f"ai-runtime-guard build={SERVER_BUILD} workspace={WORKSPACE_ROOT} base_dir={BASE_DIR}"


def execute_command(command: str, retry_count: int = 0) -> str:
    network_warning = None
    shell_containment_warning = None
    shell_containment_paths: list[str] = []
    budget_fields: dict = {}
    simulation = None
    simulation_diagnostic: tuple[str, str] | None = None

    if has_shell_unsafe_control_chars(command):
        result = PolicyResult(
            allowed=False,
            reason="Command contains disallowed control characters (newline, carriage return, or NUL)",
            decision_tier="blocked",
            matched_rule="command_control_characters",
        )
    elif command_targets_backup_storage(command):
        result = PolicyResult(
            allowed=False,
            reason="Command targets protected backup storage; use restore_backup for controlled recovery operations",
            decision_tier="blocked",
            matched_rule="backup_storage_protected",
        )
    else:
        net_allowed, net_reason = network_policy_check(command)
        mode = str(POLICY.get("network", {}).get("enforcement_mode", "off")).lower()
        if not net_allowed:
            result = PolicyResult(
                allowed=False,
                reason=net_reason or "Network command blocked by policy",
                decision_tier="blocked",
                matched_rule="network_policy",
            )
        else:
            if mode == "monitor" and net_reason:
                network_warning = net_reason
            containment_allowed, containment_reason, containment_paths = shell_workspace_containment_check(command)
            if not containment_allowed:
                result = PolicyResult(
                    allowed=False,
                    reason=containment_reason or "Shell workspace containment blocked command.",
                    decision_tier="blocked",
                    matched_rule="execution.shell_workspace_containment",
                )
                shell_containment_paths = containment_paths
            else:
                if containment_reason:
                    shell_containment_warning = containment_reason
                    shell_containment_paths = containment_paths
                sim_commands = [c.lower() for c in POLICY.get("requires_simulation", {}).get("commands", [])]
                if sim_commands:
                    simulation = simulate_blast_radius(command, sim_commands)
                result = check_policy(command, simulation=simulation)
                if simulation is not None:
                    simulation_diagnostic = check_simulation_tier(command, simulation=simulation)

    affected_for_budget: list[str] = []
    affected_for_limits: list[str] = []
    if result.allowed:
        if simulation and simulation["affected"]:
            affected_for_budget = simulation["affected"]
            affected_for_limits = simulation["affected"]
        else:
            affected_for_budget = extract_paths(command)
            affected_for_limits = affected_for_budget

        # Allowed-tier safety cap for default-allowed multi-target operations.
        # Keep simulation-specific wildcard logic governed by simulation thresholds.
        is_simulation_wildcard_flow = bool(simulation and simulation.get("saw_wildcard"))
        if not is_simulation_wildcard_flow:
            resolved_unique: list[str] = []
            seen: set[str] = set()
            for candidate in affected_for_limits:
                try:
                    resolved = str(pathlib.Path(candidate).resolve())
                except OSError:
                    continue
                if not is_within_workspace(resolved):
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                resolved_unique.append(resolved)

            max_files = int(POLICY.get("allowed", {}).get("max_files_per_operation", 10))
            if max_files >= 0 and len(resolved_unique) > max_files:
                result = PolicyResult(
                    allowed=False,
                    reason=(
                        f"Operation targets {len(resolved_unique)} file/path entries, "
                        f"which exceeds allowed.max_files_per_operation={max_files}"
                    ),
                    decision_tier="blocked",
                    matched_rule="allowed.max_files_per_operation",
                )

        if result.allowed:
            budget_allowed, budget_reason, budget_rule, budget_fields = check_and_record_cumulative_budget(
                tool="execute_command",
                command=command,
                affected_paths=affected_for_budget,
                operation_count=1,
            )
            if not budget_allowed:
                result = PolicyResult(
                    allowed=False,
                    reason=budget_reason or "Cumulative blast-radius budget exceeded for current scope.",
                    decision_tier="blocked",
                    matched_rule=budget_rule or "requires_simulation.cumulative_budget_exceeded",
                )

    server_retry_count = 0
    final_block = False
    if not result.allowed and result.decision_tier != "requires_confirmation":
        server_retry_count = register_retry(command, result.decision_tier, result.matched_rule)
        final_block = server_retry_count >= MAX_RETRIES

    log_entry = build_log_entry(
        "execute_command",
        result,
        command=command,
        normalized_command=normalize_for_audit(command),
        retry_count=retry_count,
        server_retry_count=server_retry_count,
        affected_paths_count=len(affected_for_budget),
        **({"network_warning": network_warning} if network_warning else {}),
        **({"shell_containment_warning": shell_containment_warning} if shell_containment_warning else {}),
        **({"shell_containment_offending_paths": shell_containment_paths} if shell_containment_paths else {}),
        **(
            {
                "simulation_diagnostic_message": simulation_diagnostic[0],
                "simulation_diagnostic_rule": simulation_diagnostic[1],
            }
            if simulation_diagnostic and result.decision_tier == "requires_confirmation"
            else {}
        ),
        **budget_fields,
        **({"final_block": True} if final_block else {}),
    )
    append_log_entry(log_entry)

    if not result.allowed:
        if result.decision_tier == "requires_confirmation":
            approval_paths = simulation["affected"] if simulation and simulation.get("affected") else extract_paths(command)
            token, expires_at = issue_or_reuse_approval_token(
                command,
                session_id=SESSION_ID,
                affected_paths=approval_paths,
            )
            simulation_context = (
                f"Simulation context: {simulation_diagnostic[0]}\n"
                if simulation_diagnostic
                else ""
            )
            return (
                f"[POLICY BLOCK] {result.reason}\n\n"
                "This command requires an explicit confirmation handshake.\n"
                f"{simulation_context}"
                "Ask a human operator to approve it via the control-plane GUI/API using this exact command and token, then retry execute_command:\n"
                f"approval_token={token}\n"
                f"token_expires_at={expires_at.isoformat()}Z"
            )

        if final_block:
            return (
                f"[POLICY BLOCK] {result.reason}\n\n"
                f"Maximum retries reached ({MAX_RETRIES}/{MAX_RETRIES}). "
                "This action is permanently blocked for the current request. "
                "No further attempts will be accepted."
            )

        attempts_remaining = MAX_RETRIES - server_retry_count
        return (
            f"[POLICY BLOCK] {result.reason}\n\n"
            f"You have {attempts_remaining} attempt(s) remaining. "
            "Please retry execute_command with a safer alternative command "
            f"(server attempt {server_retry_count}/{MAX_RETRIES})."
        )

    if MODIFYING_COMMAND_RE.search(command):
        affected = extract_paths(command)
        if affected and POLICY.get("audit", {}).get("backup_enabled", True):
            backup_location = backup_paths(affected)
            if backup_location:
                append_log_entry(
                    {
                        **log_entry,
                        "source": "mcp-server",
                        "backup_location": backup_location,
                        "event": "backup_created",
                    }
                )

    timeout_seconds, max_output_chars = execution_limits()
    try:
        proc = run_shell_command(command, timeout_seconds)
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout_seconds} seconds"

    stdout = truncate_output(proc.stdout or "", max_output_chars)
    stderr = truncate_output(proc.stderr or "", max_output_chars)

    if proc.returncode != 0:
        return stderr or f"Command exited with code {proc.returncode}"
    return stdout
