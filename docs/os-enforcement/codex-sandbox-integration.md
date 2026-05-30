# Codex Self-Sandbox Detection & No-Double-Sandbox Logic

**Task:** T7 — Codex self-sandbox detection and no-double-sandbox reconciliation.
**Design authority:** `AGENT_CONTEXT.md §13`, especially §13.1 #5, §13.5 #2, §13.9 #3.
**Produced:** 2026-05-30 by general-purpose agent (Claude Sonnet 4.6).

---

## 0. Executive Summary

AGENT_CONTEXT.md §13.1 #5 states that "AIRG already ships with Codex's own sandbox **disabled**."
**This claim is NOT confirmed by the code as written.** AIRG's default `tier3_sandbox_mode` is
`"workspace-write"` — Codex's own sandbox is active (workspace-confined), not disabled.
`"danger-full-access"` is the mode that would disable Codex's sandbox entirely. As of the code
reviewed, AIRG never writes `danger-full-access` (the constant exists in `CODEX_SANDBOX_MODES`
but is not the default and no code path emits it as a default or enforcement output).

This document:
1. Documents the current state accurately.
2. Defines detection logic for Codex's sandbox state at launch.
3. Defines the reconciliation decision table (no-double-sandbox).
4. Resolves the schema-vs-launcher-logic question (§13.9 #3 / T4 open question 5).
5. Spells out the critical ordering guarantee: AIRG's outer wall must be established *before*
   Codex's inner sandbox is disabled.
6. Notes how this pattern generalizes to other self-sandboxing agents.

---

## 1. Current State: What AIRG Reads and What It Writes

### 1.1 What `agent_posture.py` reads — Codex sandbox signals

`src/agent_posture.py` implements `_codex_tier3_state(path)` (line 550) and
`_build_codex_posture(profile)` (line 1054).

**Files read (in order):**

| Priority | Path | Label |
|----------|------|-------|
| 1 (global) | `~/.codex/config.toml` | global user config |
| 2 (project) | `<workspace>/.codex/config.toml` | project config |

The file consulted for tier3 posture is determined by the profile's `agent_scope` field:
`scope_index = 1 if expected_scope == "project" else 0` (line 1058). Only **one** config file is
read for posture purposes — the one matching the expected scope, not both merged.

**Keys read from `config.toml`:**

| TOML key | Posture signal | Meaning |
|----------|---------------|---------|
| `sandbox_mode` | `codex_tier3_sandbox_mode` | Codex built-in sandbox mode |
| `approval_policy` | `codex_tier3_approval_policy` | Codex command approval policy |
| `sandbox_workspace_write.network_access` | `codex_tier3_network_access` | Network allowed in workspace-write mode |
| `sandbox_workspace_write.exclude_slash_tmp` | `codex_tier3_exclude_slash_tmp` | /tmp excluded in workspace-write |
| `sandbox_workspace_write.exclude_tmpdir_env_var` | `codex_tier3_exclude_tmpdir_env_var` | $TMPDIR excluded in workspace-write |

**Posture scoring:**

- `sandbox_mode_maximum` is `True` only when `sandbox_mode == "read-only"` (most restrictive).
- `hardened` (in `_codex_tier3_state`) is `True` when `sandbox_mode in {"read-only", "workspace-write"}` — so both active modes are considered hardened; `"danger-full-access"` is explicitly excluded.
- The "maximum" posture badge (green) requires `read-only` + `untrusted` approval policy.

**What posture does NOT check:** whether AIRG's OS sandbox is active, and whether the Codex sandbox
and AIRG's OS sandbox are stacked (nested). Posture only reports what Codex's own config contains.

### 1.2 What `agent_configurator.py` writes — Codex hardening artifacts

`src/agent_configurator.py` implements `_apply_codex()` (line 1668), called by `apply_hardening()`.

**Files written (per scope):**

| Artifact | Global path | Project path |
|----------|-------------|-------------|
| MCP config | `~/.codex/config.toml` | `<workspace>/.codex/config.toml` |
| Tier 1 guidance | `~/.codex/AGENTS.md` | `<workspace>/.codex/AGENTS.md` |
| Tier 2 rules | `~/.codex/rules/airg.rules` | `<workspace>/.codex/rules/airg.rules` |

The Codex `config.toml` is written by `_render_codex_tier3_config()` (line 788), using a managed
block delimited by `# AIRG_CODEX_TIER3_BEGIN` / `# AIRG_CODEX_TIER3_END`.

**Keys written to `config.toml`:**

| TOML key | Default value written | Source |
|----------|-----------------------|--------|
| `sandbox_mode` | `"workspace-write"` | `_normalize_codex_hardening_options()` line 280 |
| `approval_policy` | `"on-request"` | `_normalize_codex_hardening_options()` line 283 |
| `sandbox_workspace_write.network_access` | `false` | line 303 |
| `sandbox_workspace_write.exclude_slash_tmp` | `true` | line 304 |
| `sandbox_workspace_write.exclude_tmpdir_env_var` | `true` | line 305 |

### 1.3 Verification of the "ships disabled" claim

**Verdict: NOT CONFIRMED.**

The claim in §13.1 #5 that AIRG "ships with Codex's own sandbox disabled" is inaccurate as of the
current code. What the code actually does:

- **Default mode written:** `sandbox_mode = "workspace-write"` — this is Codex's own sandbox in
  **active** mode (workspace-confined write access), not disabled.
- **The disabling mode** is `"danger-full-access"` — Codex's equivalent of "no sandbox". This value
  exists in `CODEX_SANDBOX_MODES = {"read-only", "workspace-write", "danger-full-access"}` (line 24)
  but is **never the default** and **no code path in `_render_codex_tier3_config` or
  `_normalize_codex_hardening_options` emits it as a default**. A caller could explicitly pass
  `tier3_sandbox_mode: "danger-full-access"` in options, but AIRG does not do so automatically.

**What §13.1 #5 probably intended:** AIRG controls the sandbox setting and can enforce whatever
value it writes. The "disabled" characterization may reflect a prior design decision or an intended
direction (AIRG owns the outer wall, so Codex's inner sandbox becomes redundant). The current code
does NOT implement that direction — it writes `workspace-write` (active sandbox), not
`danger-full-access` (disabled sandbox).

This is a significant discrepancy that must be resolved before OS enforcement is implemented.
Section 3 below proposes the reconciliation logic that would implement §13.1 #5's intent.

---

## 2. Detection: How AIRG Determines Codex's Sandbox State at Launch

### 2.1 Config file precedence (as Codex itself applies it)

Codex applies config in this precedence order (lower index = lower priority; higher index wins):

1. Built-in defaults (hardcoded in Codex binary).
2. Global user config: `~/.codex/config.toml` — applies to all Codex sessions.
3. Project config: `<workspace>/.codex/config.toml` — applies only when the project is trusted
   (requires a `[projects."<path>"]` `trust_level = "trusted"` entry in the user config).

Project config overrides global for keys present in both. A `sandbox_mode` in the project config
takes precedence over `sandbox_mode` in the global config.

AIRG posture currently reads only the scope-matched config file (whichever scope the profile
specifies). For detection at launch, AIRG must apply the same precedence Codex uses: read both
files and let the project value override the global value if both are present and the project is
trusted.

### 2.2 Effective sandbox state detection algorithm

At launch time, the launcher (the new `airg-run`/`airg-codex` entrypoint) must execute the
following detection procedure:

```
1. Read global config:   ~/.codex/config.toml        → global_sandbox_mode
2. Read project config:  <workspace>/.codex/config.toml → project_sandbox_mode
3. Check project trust:  ~/.codex/config.toml has [projects."<workspace>"] trust_level = "trusted"
4. Effective sandbox_mode:
     if project_sandbox_mode is set AND project is trusted:
         effective = project_sandbox_mode
     elif global_sandbox_mode is set:
         effective = global_sandbox_mode
     else:
         effective = <codex built-in default>  # as of this writing: "workspace-write"
5. Report effective_sandbox_mode to AIRG's reconciliation logic.
```

**Detection result values:**

| `effective_sandbox_mode` | Meaning |
|--------------------------|---------|
| `"read-only"` | Codex sandbox active, most restrictive |
| `"workspace-write"` | Codex sandbox active, workspace-confined |
| `"danger-full-access"` | Codex sandbox disabled (no confinement) |
| `""` / absent | Codex built-in default applies (treat as `"workspace-write"`) |

### 2.3 Implementation note

This detection logic reuses and extends the existing `_codex_tier3_state()` function in
`agent_posture.py`. The launcher should call a new `effective_codex_sandbox_mode(workspace)` helper
that:
1. Calls `_codex_tier3_state(global_path)` and `_codex_tier3_state(project_path)`.
2. Checks project trust from the global config.
3. Returns the effective mode using the precedence rule above.

---

## 3. Reconciliation: The No-Double-Sandbox Decision Table

This section implements the directive in §13.1 #5: AIRG is the authoritative outer wall. When
AIRG's OS sandbox is active, Codex's inner sandbox must be disabled (set to `danger-full-access`).
When AIRG's OS sandbox is not active, Codex's inner sandbox should remain in place as the sole
confinement layer.

### 3.1 Decision table

| Codex inner sandbox | `os_sandbox.mode` | AIRG action |
|---------------------|-------------------|-------------|
| `danger-full-access` (disabled) | `off` | Launch unconfined. Codex has no sandbox; AIRG has no OS sandbox. MCP policy is the only guard layer. Log a warning. |
| `danger-full-access` (disabled) | `monitor` | Establish AIRG sandbox in monitor (log-only) mode. Proceed. Codex already has no inner sandbox. |
| `danger-full-access` (disabled) | `enforce` | Establish AIRG sandbox in enforce mode. This is the ideal outer-wall state: AIRG owns the boundary, Codex's inner sandbox is already off. |
| `workspace-write` or `read-only` (active) | `off` | Launch unconfined at OS level. Codex's own sandbox is active. Do not modify Codex's config. MCP policy + Codex's own sandbox are the guards. |
| `workspace-write` or `read-only` (active) | `monitor` | Establish AIRG sandbox in monitor mode only. Do not disable Codex's inner sandbox. **Monitor mode is observation, not enforcement** — leaving Codex's sandbox intact adds no harm and the outer wall is not yet authoritative. Log that both are active. |
| `workspace-write` or `read-only` (active) | `enforce` | AIRG must disable Codex's inner sandbox before launch. Write `sandbox_mode = "danger-full-access"` to the effective scope's `config.toml` (after confirming AIRG's outer wall is established — see §4 ordering). Then launch under AIRG's OS sandbox. |
| unknown / cannot read | `enforce` | **Fail closed.** Refuse to launch. AIRG cannot confirm Codex's sandbox state and therefore cannot ensure neither a broken nested stack nor an unconfined agent. Log the failure reason and exit non-zero. |
| unknown / cannot read | `monitor` | Proceed with AIRG monitor mode but log a prominent warning that Codex's inner sandbox state is unknown. Do not attempt to modify Codex's config. |
| unknown / cannot read | `off` | Launch normally. No OS enforcement is in play; Codex's sandbox state is irrelevant to AIRG's OS sandbox logic (though posture will flag it). |

### 3.2 The reconciliation rule (normative)

> When `os_sandbox.mode == "enforce"`, AIRG's launcher MUST:
> 1. **Detect** the effective `sandbox_mode` from Codex's config (§2.2 algorithm).
> 2. If detection fails (config unreadable or parse error): **fail closed** — refuse to launch.
> 3. If `effective_sandbox_mode` is `"workspace-write"` or `"read-only"` (Codex sandbox is active):
>    a. Establish AIRG's OS sandbox first (see §4 ordering guarantee).
>    b. Only after confirming the OS sandbox is established, write `sandbox_mode = "danger-full-access"`
>       to the effective Codex config file.
>    c. If writing Codex's config fails: **fail closed** — tear down the OS sandbox and refuse to launch.
> 4. If `effective_sandbox_mode` is `"danger-full-access"` (Codex sandbox already disabled): proceed
>    to launch under AIRG's OS sandbox without modifying Codex's config.

### 3.3 Reverting the Codex config after session

The Codex config modification in step 3b is a runtime write, not a persistent hardening artifact.
The launcher must restore the previous `sandbox_mode` value (or remove the key if it was absent)
after the agent process exits. This restore must occur even if the agent process crashes or is
killed (use a `try/finally` or atexit handler around the subprocess call).

---

## 4. Critical Ordering Guarantee: Outer Wall Before Inner Wall Is Removed

This is the most security-sensitive invariant in the entire reconciliation logic.

**The danger:** If AIRG writes `danger-full-access` to Codex's config *before* establishing its own
OS sandbox, there is a window — however brief — where the agent launches with **no confinement at
all**: Codex's sandbox is disabled and AIRG's sandbox is not yet active. If the OS sandbox setup
then fails, the agent was left less protected than before AIRG intervened.

**The required order:**

```
Step 1: Probe OS sandbox feasibility (Landlock ABI version, launcher binary present, etc.).
        If probe fails → fail closed immediately. Do not touch Codex's config.

Step 2: Establish the OS sandbox (invoke the launcher, verify the sandbox is active).
        If sandbox establishment fails → fail closed. Do not touch Codex's config.

Step 3: Only after OS sandbox is confirmed active, write danger-full-access to Codex config.

Step 4: Launch the agent process inside the already-established OS sandbox.

Step 5: Agent exits (normally or via signal).

Step 6: Restore Codex's previous sandbox_mode.

Step 7: OS sandbox is torn down (naturally, as it is tied to the process lifecycle).
```

**Implementation consequence:** The launcher must support a "sandbox-first" invocation model where
the OS sandbox is activated as the outer wrapper before the agent process is forked. For `bwrap` and
`landrun`, this means the sandbox is established via `exec()` and the agent is a child process
inside it from birth — there is no "activate sandbox around running process" step; the sandbox and
the agent process start together. In Topology A (AIRG outside, shim inside), the sequence is:

```
AIRG (outside) →
  establishes sandbox (bwrap/landrun exec) →
    shim (inside sandbox, speaks STDIO to Codex) →
      Codex process (inside sandbox)
```

The AIRG process itself is never inside the sandbox. The ordering guarantee means AIRG must verify
that the sandbox launcher successfully exec'd the shim (exit code, OS signal check, or a handshake
message from the shim over the AF_UNIX socket) before writing `danger-full-access`. For practical
purposes, the handshake approach from `transport-bridge-design.md §5` already provides this
confirmation signal.

**If AIRG's OS sandbox cannot be established (any mode):**

```
os_sandbox.on_setup_failure == "fail_closed"  (default):
  → Log structured ERROR with failure reason.
  → Do NOT write danger-full-access to Codex's config (nothing has changed).
  → Exit non-zero. Agent does not run.

os_sandbox.on_setup_failure == "warn_and_run_unconfined":
  → Log prominent WARNING.
  → Do NOT write danger-full-access (Codex's sandbox remains active as the only guard).
  → Launch agent without OS confinement.
  → Codex's own sandbox protects the session; this is the fallback.
```

The `warn_and_run_unconfined` case is actually safer than it might seem: by not writing
`danger-full-access`, AIRG preserves Codex's inner sandbox as the confinement layer when the OS
sandbox is unavailable. The agent is not less protected than it was before AIRG attempted enforcement.

---

## 5. Schema Field vs Launcher Logic: Resolving §13.9 #3 / T4 Open Question 5

T4's `sandbox-policy-schema.md §6 open question 5` asked: should the no-double-sandbox logic be a
schema field (e.g., `os_sandbox.disable_agent_inner_sandbox: true`) or purely launcher behavior?

**Recommendation: Pure launcher logic, not a schema field.**

**Rationale:**

1. **It is the only correct behavior when `mode == "enforce"`.** The no-double-sandbox rule is not
   optional. When AIRG's OS sandbox is authoritative, Codex's inner sandbox MUST be disabled — there
   is no legitimate use case for "AIRG enforces its outer wall AND Codex also enforces its inner
   wall." A schema field implies the behavior is configurable; it is not.

2. **A schema field would create a dangerous false affordance.** If `disable_agent_inner_sandbox`
   defaults to `true` but can be set to `false` by an operator, an operator could configure
   `mode: "enforce"` + `disable_agent_inner_sandbox: false`, which produces the nested sandbox
   problem §13.1 #5 explicitly prohibits. The launcher must enforce the rule unconditionally when
   `mode == "enforce"`.

3. **The schema field is redundant.** The `os_sandbox.mode` field already encodes the intent:
   `"enforce"` means AIRG is the authoritative wall → inner sandbox must be off. Adding a second
   field to express the same intent duplicates state and creates sync hazards.

4. **Agent-type specificity.** The concept of "the agent has its own sandbox that must be disabled"
   is Codex-specific today. Claude Code, Cursor, and future agents may or may not have inner
   sandboxes — and the mechanism for disabling them varies per agent (Codex: write `danger-full-access`
   to config.toml; Claude Code: set `sandbox.enabled: false`; Cursor: set `sandbox.type: insecure_none`).
   Encoding this as a schema field would require either a generic boolean (losing agent-type specificity)
   or a per-agent sub-object (premature generalization). The launcher, which already selects behavior
   per agent type, is the correct place.

5. **GUI and audit needs are satisfied by posture, not schema.** If the GUI needs to show "inner
   sandbox disabled by AIRG OS enforcement," the posture signal `os_sandbox_confined` (from
   `agent_posture.py`) combined with `codex_tier3_sandbox_mode` (already emitted) provides that
   signal without a dedicated schema field. The audit log entry from the launcher (step 3b above)
   provides the write-time record.

**Concrete statement for implementers:**

> When `os_sandbox.mode == "enforce"` and the agent type is `"codex"`:
> The launcher unconditionally disables Codex's inner sandbox (writes `danger-full-access`) as part
> of the launch sequence (after outer wall is established, before agent process starts). This is not
> a user-configurable option; it is the only correct behavior for `"enforce"` mode and is
> implemented in the launcher, not in the schema.

**One narrow exception:** the `on_setup_failure: "warn_and_run_unconfined"` path. In this path,
AIRG's outer wall cannot be established, so the inner sandbox must NOT be disabled (see §4).
The launcher handles this automatically by the ordering guarantee — no schema field is needed to
express it.

---

## 6. Generalization to Other Self-Sandboxing Agents

The detection/reconciliation pattern developed for Codex generalizes to any agent that has its own
built-in OS-level sandbox. The pattern is:

```
detect_agent_inner_sandbox(agent_type, workspace) → effective_mode: str | None
reconcile(effective_mode, os_sandbox_mode) → action: enum
```

**Per-agent inner sandbox details (current knowledge):**

| Agent | Inner sandbox mechanism | Config location | Disable key/value |
|-------|------------------------|----------------|-------------------|
| Codex | Landlock+seccomp (Linux), Seatbelt (macOS) | `~/.codex/config.toml` or `<workspace>/.codex/config.toml` | `sandbox_mode = "danger-full-access"` |
| Claude Code | AIRG-managed sandbox flag (`sandbox.enabled`) | `~/.claude.json` or `.claude.json` | `sandbox.enabled = false` |
| Cursor | Cursor workspace sandbox | `<workspace>/.cursor/sandbox.json` | `type = "insecure_none"` |

**Extension approach for future agents:**

1. Add an `_effective_inner_sandbox_mode(profile)` method to `agent_posture.py` (or a new
   `agent_launcher.py` module) that dispatches by `agent_type`.
2. The reconciliation logic in the launcher is agent-type-agnostic: it receives
   `(inner_sandbox_active: bool, os_sandbox_mode: str)` and produces the same decision table
   regardless of agent type.
3. The "how to disable" action is agent-type-specific and lives in an agent-type dispatch table
   in the launcher.

This keeps the reconciliation rule single and stable while allowing the detection and disable
mechanisms to vary per agent.

**Important note on Claude Code:** `agent_posture.py` already reads Claude Code's `sandbox.enabled`
flag (the existing `_sandbox_hardened()` function). When AIRG's OS enforcement targets a Claude
Code session, the same ordering guarantee (outer wall first) applies, and the disable action is
writing `sandbox.enabled: false` to Claude Code's settings.json. The T4 schema design's warning
about the `sandbox` naming collision (`agent_posture.py` uses `sandbox` to read Claude Code's own
setting) means the reconciliation code must use `os_sandbox.mode` (AIRG's policy) vs `sandbox.enabled`
(Claude Code's built-in) and never conflate the two.

---

## 7. Open Questions Surfaced

1. **Codex built-in default for `sandbox_mode`:** If `sandbox_mode` is absent from both global and
   project config, Codex applies its own built-in default. This document treats the absence as
   equivalent to `"workspace-write"`, but the actual Codex binary default should be confirmed
   empirically (run `codex` without any `sandbox_mode` set and observe behavior). If Codex's built-in
   default is `"danger-full-access"`, the detection algorithm in §2.2 step 4 must be updated.

2. **Atomic config write and process fork:** The requirement in §4 that AIRG establishes the OS
   sandbox before writing `danger-full-access` to Codex's config assumes the sandbox can be
   established *without* first forking the agent process (so AIRG can write the config before
   the agent starts). With `bwrap`/`landrun`, the sandbox is established by exec'ing the launcher
   which immediately spawns the shim and agent. A clean "sandbox confirmed active, now write config,
   now start agent" sequence requires either (a) a handshake from the shim before Codex starts, or
   (b) a two-phase exec where AIRG's launcher sets up the sandbox wrapper but Codex doesn't start
   until a signal from AIRG. The transport-bridge handshake (T3) is the most practical implementation.

3. **Restoring Codex's sandbox after abnormal exit:** If AIRG itself is killed (SIGKILL) while the
   agent is running, the atexit/finally restore of Codex's `sandbox_mode` will not execute. The
   next Codex session would start with `danger-full-access` unexpectedly. Mitigation: write the
   original value to a sidecar file before modifying Codex's config; implement a recovery check at
   AIRG launch that restores the sidecar if a previous session ended uncleanly.

4. **Project trust for project-scoped config:** The detection algorithm checks whether the project
   is trusted before treating the project config as effective. If AIRG is writing hardening to the
   project config (project scope) but the project trust entry is absent in `~/.codex/config.toml`,
   Codex will not load the project config and the `sandbox_mode` written by AIRG will be silently
   ignored. AIRG's hardening apply flow already handles the trust entry (via `_codex_trust_plan` in
   `mcp_config_manager.py`), but the launch-time detection must also check trust to avoid false
   "sandbox confirmed disabled" conclusions.

5. **§13.1 #5 intent vs code state:** The mismatch between the locked decision ("ships disabled")
   and the actual code default (`workspace-write`) must be resolved by the operator before
   implementation begins. Two options: (a) Change the operator decision — AIRG ships with
   `workspace-write` and disables only when OS enforcement is active. (b) Change the code default
   to `danger-full-access` (effectively disabling Codex's inner sandbox today, before OS enforcement
   exists). Option (a) is strongly preferred: disabling Codex's inner sandbox before AIRG's outer
   wall is in place would leave users less protected, not more.
