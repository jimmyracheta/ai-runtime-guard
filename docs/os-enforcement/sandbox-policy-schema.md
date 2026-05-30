# AIRG OS-Sandbox Policy Schema Design

**Task:** T4 — Design (no implementation) the policy schema for AIRG-owned OS sandboxing.
**Design source of truth:** `AGENT_CONTEXT.md §13`, especially §13.5, §13.6, §13.11.
**Produced:** 2026-05-30 by general-purpose agent (Claude Sonnet 4.6).

---

## 1. Name Collision Warning and Section-Name Decision

### 1.1 The Collision

`src/agent_posture.py` already uses the identifier `sandbox` in two ways:

1. **`_sandbox_hardened()` (line 196)** reads `effective.get("sandbox", {})` — consuming the
   `sandbox` key from the *Claude Code client's* settings.json (the client-side `allowUnsandboxedCommands`
   flag), not AIRG's own policy.json.
2. **Signal keys** `sandbox_enabled`, `sandbox_escape_closed`, `sandbox_hardened` appear in posture
   labels and recommendation text.

`AGENT_CONTEXT.md §13.6` explicitly warns: *"Note a partial `sandbox` concept already exists in
`src/agent_posture.py` but it READS the *client's* sandbox config — keep AIRG's own sandbox policy
distinct or namespace it."*

If the new policy section were named `"sandbox"`, a future implementer reading `config.py` and
`agent_posture.py` side-by-side would face constant confusion: the same word meaning two entirely
different things (AIRG's launcher policy vs the client's built-in sandbox state). The GUI catalog
and test fixtures would also collide in naming conventions.

### 1.2 Recommended Name: `os_sandbox`

**Chosen name: `os_sandbox`**

Rationale:

- `os_` prefix unambiguously signals "kernel/OS-level enforcement owned by AIRG", distinguishing
  it from the client's `sandbox` setting that `agent_posture.py` reads.
- It directly echoes §13.6's suggested name "sandbox" while adding the namespace that §13.6 says
  is needed.
- `enclosure` was considered but is novel jargon that a future implementer would not immediately
  associate with OS sandboxing; `os_sandbox` is self-documenting.
- `agent_overrides` already allows per-agent overlays keyed to existing section names, so
  `os_sandbox` slots in cleanly as another top-level key.

Anywhere this document says "the section", it means `policy["os_sandbox"]`.

---

## 2. Schema Specification

### 2.1 Field Table

All fields live under the top-level JSON key `"os_sandbox"`. Each subsection below specifies type,
allowed values, default, and enforcement meaning.

---

#### 2.1.1 `enabled`

| Attribute | Value |
|-----------|-------|
| Type | boolean |
| Default | `false` |
| Allowed values | `true`, `false` |

When `false`, the entire section is inert: AIRG launches the agent with no OS-level confinement,
regardless of all other fields in this section. The MCP policy layer (all other sections) remains
active.

When `true`, AIRG applies the OS sandbox according to `mode` and the rest of the section.

**Normalization rule:** `setdefault("enabled", False)`. Validate `isinstance(bool)`.

---

#### 2.1.2 `mode`

| Attribute | Value |
|-----------|-------|
| Type | string enum |
| Default | `"off"` |
| Allowed values | `"off"` \| `"monitor"` \| `"enforce"` |

Mirrors the tri-state idiom used by `network.enforcement_mode` and
`execution.shell_workspace_containment.mode`.

- `"off"`: sandbox is not activated. Identical to `enabled: false`; provided for consistency with
  the other tri-state fields.
- `"monitor"`: AIRG attempts to establish the sandbox and logs what *would* be denied, but does not
  actually confine the process. Useful for auditing carve-out completeness before enforcement.
- `"enforce"`: sandbox is active. If it cannot be established (see `on_setup_failure`), AIRG applies
  the fail-closed rule.

**Normalization rule:** `setdefault("mode", "off")`. Validate against `{"off", "monitor", "enforce"}`.

**Interaction with `enabled`:** if `enabled` is `false`, `mode` is ignored. If `enabled` is `true`
and `mode` is `"off"`, warn in audit log (contradictory config) but treat as disabled. Implementer
may choose to normalize `enabled: true + mode: "off"` to `enabled: false` with a warning.

---

#### 2.1.3 `launcher`

| Attribute | Value |
|-----------|-------|
| Type | string enum |
| Default | `"auto"` |
| Allowed values | `"auto"` \| `"bwrap"` \| `"landrun"` \| `"sandbox-exec"` |

Controls how AIRG selects the OS sandbox launcher for the agent process.

- `"auto"` (recommended): AIRG runs the probe logic (from `scripts/airg_sandbox_probe.py`) at
  launcher startup to determine the best available launcher. Selection priority:
  1. If `kernel.unprivileged_userns_clone = 1` AND `bwrap` binary is found → `bwrap`.
  2. Else if Landlock ABI ≥ v1 (kernel ≥ 5.13) AND `landrun` binary is found → `landrun`.
  3. Else → fail-closed (see `on_setup_failure`).
  See `docs/os-enforcement/launcher-evaluation.md §5` for the probe-driven selection rationale.
- `"bwrap"`: force bubblewrap. Fails at setup if `bwrap` binary is absent or userns is unavailable.
- `"landrun"`: force landrun. Fails at setup if `landrun` binary is absent or Landlock is unavailable.
- `"sandbox-exec"`: macOS Seatbelt. Fails at setup if not on macOS or `sandbox-exec` is absent.

**Normalization rule:** `setdefault("launcher", "auto")`.
Validate against `{"auto", "bwrap", "landrun", "sandbox-exec"}`.

**Note on Codex double-sandbox:** Per §13.1 item 5, if the active agent profile has Codex's own
sandbox enabled, `airg_sandbox_probe.py` should detect this and AIRG's launcher logic should treat
the Codex sandbox as AIRG-controlled state. The `os_sandbox` section does NOT carry a field for
this; the Codex inner-sandbox disable/coexist logic is launcher-side policy, not a schema field.
(The schema cannot make that decision; see §13.9 open item 3.)

---

#### 2.1.4 `filesystem`

Sub-object. Defines the allow-set of paths the sandboxed agent process may access.

```
"filesystem": {
  "workspace_root":         string  (path, default: AIRG_WORKSPACE env var or "")
  "readable_paths":         array[string]  (default: [])
  "read_exec_paths":        array[string]  (default: [...system defaults...])
  "writable_paths":         array[string]  (default: [])
  "bridge_socket_path":     string  (default: "")
}
```

**`workspace_root`**

| Attribute | Value |
|-----------|-------|
| Type | string (absolute path) |
| Default | `""` (resolved at runtime from `AIRG_WORKSPACE` env var) |

The primary workspace directory. The launcher grants **read+write** access to this path tree. This
is the spatial analog of `execution.shell_workspace_containment` — where that section uses heuristic
path-token analysis to infer workspace bounds, `os_sandbox.filesystem.workspace_root` is the
**kernel-enforced ground truth** that supersedes those heuristics when `os_sandbox.mode = "enforce"`.

When empty string, the launcher resolves the workspace from `AIRG_WORKSPACE` at runtime. An
operator may override here for profiles where the workspace is fixed and known.

**Normalization rule:** `setdefault("workspace_root", "")`. Validate `isinstance(str)`.
At runtime, if empty, read from `os.environ["AIRG_WORKSPACE"]`; if also unset, fail-closed.

**Relationship to `execution.shell_workspace_containment`:**
- When `os_sandbox.mode = "enforce"`, the OS sandbox enforces workspace bounds at the kernel level.
  `execution.shell_workspace_containment` remains active as an additional MCP-layer behavioral check
  (it can detect and block commands accessing out-of-workspace paths before they even reach the
  kernel). The two layers are complementary, not redundant.
- When `os_sandbox.mode = "off"` or `"monitor"`, `execution.shell_workspace_containment` continues
  to operate as the sole workspace guard (heuristic, as today).

**`readable_paths`**

| Attribute | Value |
|-----------|-------|
| Type | array of strings (absolute paths) |
| Default | `[]` |

Additional filesystem paths the agent may open for reading (not execution). Useful for config files
or system resources outside the workspace that the agent legitimately needs to read (e.g.,
`/etc/ssl/certs`). Each entry is a path or directory (recursive).

**Normalization rule:** `_ensure_list(filesystem, "readable_paths")`.
Each element must be a non-empty string.

**`read_exec_paths`**

| Attribute | Value |
|-----------|-------|
| Type | array of strings (absolute paths) |
| Default | See below |

Paths the agent may read AND execute from. Required for interpreters and system libraries. The
baseline default list (applied if the field is absent) is:

```
["/usr", "/lib", "/lib64", "/lib32", "/libx32",
 "/bin", "/sbin", "/usr/bin", "/usr/sbin",
 "/usr/local", "/proc/self", "/dev/null",
 "/dev/urandom", "/dev/random", "/etc/ld.so.cache",
 "/etc/ld.so.conf", "/etc/ld.so.conf.d",
 "/etc/ssl/certs", "/etc/ca-certificates"]
```

Operators shrink this list to tighten confinement. Agents that need `node`, `python`, `git`, etc.
must have their interpreter paths (or virtualenv directories) included.

This field is the schema-level home for the "carve-out tuning" concern flagged in §13.5 #3.

**Normalization rule:** if `"read_exec_paths"` key is absent or `null`, set to the baseline default
list above. If present as an empty list `[]`, treat as "operator explicitly cleared the baseline"
(no read/exec paths outside workspace — very tight confinement). Validate each element is a string.

**`writable_paths`**

| Attribute | Value |
|-----------|-------|
| Type | array of strings (absolute paths) |
| Default | `["/tmp"]` |

Additional filesystem paths (outside `workspace_root`) the agent may write to.  `/tmp` is the only
default because agent processes commonly need a temp scratch area. Operators may clear this for
maximum confinement.

**Normalization rule:** `setdefault("writable_paths", ["/tmp"])`.
Validate list of strings.

**`bridge_socket_path`**

| Attribute | Value |
|-----------|-------|
| Type | string (absolute path) |
| Default | `""` (resolved at runtime from `AIRG_SOCKET_PATH` env var) |

The path to the AF_UNIX socket that the in-sandbox shim uses to communicate with the AIRG server
running outside the sandbox (Topology A, per `docs/os-enforcement/transport-bridge-design.md`).
This is the **one and only carve-out** that crosses the sandbox boundary for MCP communication.

The launcher must grant read+write access to exactly this path (not a directory containing it).

When empty string, the launcher resolves the socket path from `AIRG_SOCKET_PATH` at runtime.

**Normalization rule:** `setdefault("bridge_socket_path", "")`. Validate `isinstance(str)`.

**Why this field is in the schema, not computed silently:**  Making the bridge socket path an
explicit, auditable schema field means operators can inspect `policy.json` and understand exactly
which single path punches through the sandbox wall. Hiding it as an implicit implementation detail
would violate the principle of least surprise and make security review harder.

---

#### 2.1.5 `network_mode`

| Attribute | Value |
|-----------|-------|
| Type | string enum |
| Default | `"none"` |
| Allowed values | `"none"` \| `"loopback_only"` \| `"unrestricted"` |

Controls OS-level network containment for the sandboxed process.

- `"none"`: all outbound TCP connections are blocked at the kernel level. This is the correct default
  for Topology A — the agent communicates with AIRG over an AF_UNIX socket (not TCP), so no TCP
  egress is needed. On bwrap: achieved via `--unshare-net`. On landrun with Landlock ABI v4+:
  achieved by specifying no `--connect-tcp` rules.
- `"loopback_only"`: allow TCP connect/bind on `127.0.0.1` only. Use when the agent needs to
  reach localhost services (e.g., a local dev server). On bwrap: net namespace with loopback kept.
  On landrun: `--connect-tcp 127.0.0.1:<ports>` (requires kernel ≥ 6.4 / Landlock ABI v4).
- `"unrestricted"`: no OS-level network restriction. Use only if the agent legitimately requires
  arbitrary outbound network and MCP-layer `network` policy is sufficient. Strongly discouraged for
  enforcement deployments.

**CRITICAL LIMITATION — Landlock port-only reality (§13.5 #1):**
Landlock's network rules (ABI v4, kernel ≥ 6.4) filter TCP connections **by port only** — not by
domain, IP address, or protocol (UDP is not filterable). Therefore `network_mode` and
`allowed_tcp_ports` provide port-level containment only. **Domain-level filtering, DNS filtering,
and UDP filtering are NOT expressible in this section and MUST remain in the existing `network`
section of AIRG policy.** These two layers are complementary:
- `os_sandbox.network_mode` + `allowed_tcp_ports`: kernel-enforced, port-level, coarse.
- `policy.network`: MCP-layer, domain-level, semantic — catches attempts within the MCP tool path.

**Normalization rule:** `setdefault("network_mode", "none")`.
Validate against `{"none", "loopback_only", "unrestricted"}`.

---

#### 2.1.6 `allowed_tcp_ports`

| Attribute | Value |
|-----------|-------|
| Type | array of integers |
| Default | `[]` |
| Valid range | 1–65535 each |

Specific TCP ports the agent may connect to, when `network_mode` is not `"none"`. Requires
Landlock ABI v4 (kernel ≥ 6.4) or bwrap net-namespace with a userland proxy. Empty by default
(deny all outbound TCP).

Example use: `[443, 80]` allows HTTPS and HTTP egress by port.

**Domain filtering**: even with `allowed_tcp_ports: [443]`, the agent can reach any HTTPS server.
Domain allowlisting remains the responsibility of `policy.network.allowed_domains` /
`policy.network.block_unknown_domains` operating at the MCP layer.

**Normalization rule:** `_ensure_list(os_sandbox, "allowed_tcp_ports")`.
Validate each element is an integer in range 1–65535.

---

#### 2.1.7 `credential_carve_outs`

| Attribute | Value |
|-----------|-------|
| Type | array of objects |
| Default | `[]` |

An explicit, auditable allow-list of specific credential paths the sandboxed agent legitimately
needs to read. Defaults to empty — the sandbox blocks all credential paths by default, making
`policy.blocked.paths` credential entries kernel-enforced rather than heuristic.

Each entry is an object with the following fields:

```json
{
  "path": "<absolute path>",
  "access": "read" | "read_exec",
  "reason": "<human-readable justification string>"
}
```

- `path` (string, required): the specific file or directory to allow. Must be an absolute path.
  Should be as specific as possible (e.g., `"~/.gitconfig"` not `"~/"`).
- `access` (string enum, required): `"read"` for read-only access; `"read_exec"` for credentials
  that are also executable (unusual, but covers credential helper scripts).
- `reason` (string, required): a short human-readable justification. This field is mandatory to
  force operators to be intentional — a silent empty-string reason must fail validation.

**Normalization rule:**

```python
carve_outs = os_sandbox.setdefault("credential_carve_outs", [])
if not isinstance(carve_outs, list):
    raise ValueError("os_sandbox.credential_carve_outs must be an array")
for i, entry in enumerate(carve_outs):
    if not isinstance(entry, dict):
        raise ValueError(f"os_sandbox.credential_carve_outs[{i}] must be an object")
    if not isinstance(entry.get("path"), str) or not entry["path"].strip():
        raise ValueError(f"os_sandbox.credential_carve_outs[{i}].path must be a non-empty string")
    if entry.get("access") not in {"read", "read_exec"}:
        raise ValueError(f"os_sandbox.credential_carve_outs[{i}].access must be 'read' or 'read_exec'")
    if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
        raise ValueError(f"os_sandbox.credential_carve_outs[{i}].reason must be a non-empty string")
```

**Relationship to `policy.blocked.paths`:** The MCP policy layer's `blocked.paths` (e.g., `.ssh`,
`.aws`, `.gitconfig`) remains fully active. A `credential_carve_outs` entry opens the OS-level
sandbox to that path but does NOT remove it from `blocked.paths` — the MCP layer will still block
tool calls attempting to read those paths through AIRG tools. The carve-out only matters for
native (non-AIRG-routed) tool access. If an operator wants to allow a credential path through BOTH
layers, they must update both this section and `blocked.paths`.

---

#### 2.1.8 `on_setup_failure`

| Attribute | Value |
|-----------|-------|
| Type | string enum |
| Default | `"fail_closed"` |
| Allowed values | `"fail_closed"` \| `"warn_and_run_unconfined"` |

Defines what AIRG does if the OS sandbox cannot be established (e.g., no Landlock support, no
userns for bwrap, launcher binary absent).

- `"fail_closed"` (default, REQUIRED for enforcement deployments): AIRG refuses to launch the agent.
  It emits a loud structured error to stderr, logs the failure to `activity.log`, and exits non-zero.
  This is the correct default — a failed sandbox that silently degrades to unconfined violates the
  deployment-hardening goal (§13.5 #5).
- `"warn_and_run_unconfined"`: AIRG logs a prominent warning to stderr and the audit log, then
  launches the agent without any OS-level confinement. The MCP policy layer remains active. This
  mode is intended ONLY for development environments where the developer needs the agent to run on a
  machine that does not support sandboxing (e.g., macOS dev machine without Seatbelt support).
  Using this value in production is an explicit, auditable operator decision.

**Normalization rule:** `setdefault("on_setup_failure", "fail_closed")`.
Validate against `{"fail_closed", "warn_and_run_unconfined"}`.

**Audit requirement:** Regardless of which value is set, any sandbox setup failure MUST produce a
structured audit log entry with severity `ERROR` and the specific failure reason (missing binary,
kernel version, etc.). The audit log entry must be emitted before any agent process is started.

---

### 2.2 What Is Spatial vs What Stays Behavioral

The schema fields above all map to **spatial controls** — kernel-enforced by the OS sandbox:

| Field | Kernel mechanism | Spatial control |
|-------|-----------------|-----------------|
| `filesystem.workspace_root` | Landlock path rules / bwrap bind-mount | WHERE agent can read/write |
| `filesystem.readable_paths` | Landlock path rules / bwrap ro-bind | WHERE agent can read |
| `filesystem.read_exec_paths` | Landlock path rules / bwrap ro-bind | WHERE agent can exec |
| `filesystem.writable_paths` | Landlock path rules / bwrap rw-bind | WHERE agent can write |
| `filesystem.bridge_socket_path` | Landlock path rule / bwrap bind | WHICH socket crosses boundary |
| `network_mode` | bwrap net namespace / Landlock TCP | WHICH networks agent can reach |
| `allowed_tcp_ports` | Landlock TCP connect rules | WHICH TCP ports agent can use |
| `credential_carve_outs` | Landlock path rules / bwrap bind | WHICH credential files agent can open |

The following controls are **behavioral** and remain in the existing MCP policy layer. They are NOT
expressible in this section and MUST NOT be duplicated here:

| Behavioral control | Existing location |
|-------------------|-------------------|
| Destructive command detection (`rm -rf`, etc.) | `policy.blocked.commands` |
| Domain-level network allowlisting | `policy.network.allowed_domains`, `network.block_unknown_domains` |
| Human-in-the-loop approval gating | `policy.requires_confirmation` |
| Backup-before-write | `policy.audit.backup_enabled` |
| Script Sentinel policy-intent continuity | `policy.script_sentinel` |
| Backup access protection | `policy.backup_access` |
| Restore dry-run gating | `policy.restore` |

**Design rationale (§13.11):** Landlock covers the spatial half. Behavioral enforcement that survives
an MCP bypass requires `seccomp-notify` or eBPF LSM — a distinct advanced phase (large complexity
jump, different abstraction level). The `os_sandbox` section deliberately does not anticipate or
pre-define hooks for that future phase; it may be addressed in a separate schema extension.

---

## 3. Composition with `agent_overrides`

### 3.1 Including `os_sandbox` in `agent_overrides`

The existing `agent_overrides` mechanism (see `config.py` lines 250–355) applies per-agent policy
overlays keyed by `AIRG_AGENT_ID`. The implementer must add `"os_sandbox"` to the
`allowed_override_sections` set (currently: `{"blocked", "requires_confirmation", "allowed",
"network", "execution"}`).

Per-agent overlay example (an agent that is allowed to read its project's `.env` file but must stay
in the workspace for everything else):

```json
"agent_overrides": {
  "codex-proj-web": {
    "policy": {
      "os_sandbox": {
        "credential_carve_outs": [
          {
            "path": "/home/user/project/.env",
            "access": "read",
            "reason": "Next.js env file needed for local dev server start"
          }
        ]
      }
    }
  }
}
```

### 3.2 Tightening-Only Override Rule

Consistent with the existing `_validate_tightening_override()` logic, `os_sandbox` overrides
**may only make policy MORE restrictive** than the baseline. The following checks must be
implemented in the tightening validator:

| Field | Tightening rule |
|-------|----------------|
| `mode` | Override rank must be `>=` baseline rank (`tier_rank = {"off": 0, "monitor": 1, "enforce": 2}`). An agent cannot downgrade from `"enforce"` to `"monitor"`. |
| `network_mode` | Per-mode rank: `"unrestricted": 0`, `"loopback_only": 1`, `"none": 2`. Override rank must be `>=` baseline. An agent cannot widen from `"none"` to `"unrestricted"`. |
| `on_setup_failure` | If baseline is `"fail_closed"`, override cannot be `"warn_and_run_unconfined"`. |
| `allowed_tcp_ports` | Override list must be a **subset** of baseline list (cannot add new ports). |
| `credential_carve_outs` | Override list must be a **subset** of baseline list, matched by `path` (cannot add new carve-out paths). |
| `filesystem.*_paths` | Override lists must be **subsets** of baseline lists (cannot add paths not in baseline). |

These rules enforce the invariant: agents cannot loosen their own sandbox via an override.

**Implementation note:** The `_deep_merge_dict` helper in `config.py` merges lists by replacement,
not union. For `os_sandbox` list fields, the tightening validator must run BEFORE the merge and
compare overlay vs base (not after). This is consistent with how `network.enforcement_mode` and
`execution.shell_workspace_containment.mode` are currently validated.

---

## 4. Concrete Annotated JSON Example

```json
"os_sandbox": {
  "_comment": "AIRG-owned OS-level sandboxing. mode: off|monitor|enforce. launcher: auto selects bwrap (if userns available) or landrun (Landlock ABI v1+). All *_paths fields are Landlock/bwrap allow-sets; domain filtering stays in the network section.",

  "enabled": true,
  "mode": "enforce",

  "launcher": "auto",

  "filesystem": {
    "_comment": "workspace_root defaults to AIRG_WORKSPACE env var. read_exec_paths must include any interpreter the agent needs (python, node, git, etc.).",
    "workspace_root": "",
    "readable_paths": [
      "/etc/ssl/certs",
      "/etc/resolv.conf",
      "/etc/hosts",
      "/proc/self/status"
    ],
    "read_exec_paths": [
      "/usr",
      "/lib",
      "/lib64",
      "/lib32",
      "/libx32",
      "/bin",
      "/sbin",
      "/usr/bin",
      "/usr/sbin",
      "/usr/local",
      "/proc/self",
      "/dev/null",
      "/dev/urandom",
      "/dev/random",
      "/etc/ld.so.cache",
      "/etc/ld.so.conf",
      "/etc/ld.so.conf.d",
      "/etc/ssl/certs",
      "/etc/ca-certificates"
    ],
    "writable_paths": [
      "/tmp"
    ],
    "bridge_socket_path": ""
  },

  "network_mode": "none",
  "allowed_tcp_ports": [],

  "credential_carve_outs": [],

  "on_setup_failure": "fail_closed"
}
```

**Notes on this example:**

- `"mode": "enforce"` + `"on_setup_failure": "fail_closed"` is the correct production default
  — if the kernel does not support sandboxing, refuse to start rather than silently degrade.
- `"network_mode": "none"` is the correct default for Topology A (AIRG bridge uses AF_UNIX, not TCP).
- `"credential_carve_outs": []` means the kernel blocks all credential paths — `.ssh`, `.aws`,
  `.gitconfig`, `.npmrc`, etc. are inaccessible to the agent at the OS level, complementing
  `policy.blocked.paths` which blocks them at the MCP layer.
- `"launcher": "auto"` defers launcher selection to the probe-driven logic.
- `"bridge_socket_path": ""` defers socket path resolution to the `AIRG_SOCKET_PATH` env var.

---

## 5. Implementer Checklist — Touch-Points to Update

The following files must be updated when implementing this schema. Each is modeled on the pattern
described in `AGENT_CONTEXT.md §10` ("Common Pitfalls") and matches how existing sections are
wired.

- [ ] **`src/config.py`**
  - Add `_validate_and_normalize_os_sandbox(policy)` function (or inline it in
    `_validate_and_normalize_policy()`).
  - Add `"os_sandbox"` to `allowed_override_sections` set (line ~256).
  - Implement tightening rules for `os_sandbox` fields inside `_validate_tightening_override()`
    (see §3.2 for exact rules per field).
  - Export a `OS_SANDBOX_POLICY: dict` module-level constant (analogous to how `POLICY` is exported)
    or simply ensure `POLICY["os_sandbox"]` is always normalized and accessible.

- [ ] **`policy.json`** (the live example file)
  - Append the annotated JSON block from §4 as a new top-level section, following the style of
    the existing `network` and `execution` sections (with `_comment` field).

- [ ] **`policy.json.defaults`** (if it exists as a separate defaults artifact)
  - Add the same `os_sandbox` block with all values at their safe defaults.

- [ ] **`src/airg_cli.py`**
  - In `_policy_template()` (line ~90), add the `os_sandbox` section with `enabled: false` and
    `mode: "off"` to the fallback in-line template. New installations default to disabled.
  - In `_ensure_policy_file()` (line ~303), verify the written policy passes
    `_validate_and_normalize_policy()` including the new section.

- [ ] **`tests/test_helpers.py`**
  - Add `"os_sandbox"` key to `DEFAULT_TEST_POLICY` with `enabled: false`, `mode: "off"`,
    and all list fields as empty arrays. This ensures tests that use `install_test_policy()` get a
    fully normalized policy without sandbox activation (tests run on arbitrary machines without
    sandbox support).

- [ ] **UI catalog (GUI frontend)**
  - Add `os_sandbox` section to the Settings → Policy UI panel, following the same pattern as
    `network` and `execution.shell_workspace_containment`.
  - Expose `mode` as a tri-state selector (`off` / `monitor` / `enforce`).
  - Expose `launcher` as a dropdown.
  - Expose `on_setup_failure` as a radio button with a prominent warning label for
    `warn_and_run_unconfined`.
  - Expose `credential_carve_outs` as an editable table (path / access / reason).
  - Expose `network_mode` and `allowed_tcp_ports` with the domain-filter disclaimer prominently
    noted in the UI (domain filtering is in the `network` section, not here).
  - Add a `sandbox_confined` posture signal to `src/agent_posture.py` (alongside existing
    `sandbox_enabled`, `sandbox_escape_closed`) that reads from AIRG's own OS-sandbox state,
    NOT from the client's `sandbox` key. Name it `os_sandbox_confined` to avoid the key collision.

- [ ] **`src/agent_posture.py`**
  - Add a new signal `"os_sandbox_confined"` (boolean) that reads `policy["os_sandbox"]["mode"] ==
    "enforce"` for the effective per-agent policy. This signal must be named `os_sandbox_confined`
    (NOT `sandbox_confined` or `sandbox_enabled`) to avoid colliding with the existing
    `sandbox_enabled` signal that reads from the client's Claude Code settings.json.

- [ ] **`docs/os-enforcement/`**
  - Update `launcher-evaluation.md` if the final launcher selection logic deviates from the
    probe-driven priority described there.
  - Update `transport-bridge-design.md §6.5` with the canonical carve-out field name
    (`filesystem.bridge_socket_path`).

---

## 6. Open Questions Surfaced by This Design

1. **`credential_carve_outs` subset-check implementation**: The tightening validator must compare
   overlay carve-out entries to baseline entries by `path`. If an agent override adds a path not in
   the baseline, it must be rejected. This is straightforward but requires a set-of-paths comparison
   rather than the simple list/rank comparisons used for other fields. Confirm that the normalized
   paths (after `expanduser().resolve()`) are used for comparison, not raw strings.

2. **`read_exec_paths` default baseline**: The default list in §2.1.4 is a Linux-centric baseline.
   macOS (`sandbox-exec`) uses a different filesystem layout (`/usr/bin`, `/usr/lib`, etc.) and the
   Seatbelt profile has its own path syntax. A future implementer must determine whether
   `read_exec_paths` is normalized to a platform-specific default at runtime, or whether the schema
   carries separate `linux_read_exec_paths` / `macos_read_exec_paths` fields. The current design
   uses a single field and relies on the launcher to translate to the correct mechanism, which is
   acceptable for the Linux MVP (P1) but may need revisiting for macOS (P3).

3. **`bridge_socket_path` in test fixtures**: In the test environment, Topology A (AIRG outside,
   shim inside) is not active — tests run the AIRG server and tools in-process via mocks. The
   `bridge_socket_path` field will be empty in `DEFAULT_TEST_POLICY`, and the launcher code must
   check whether sandbox mode is active before requiring the socket path. Tests should not need a
   real socket.

4. **`agent_overrides` subset check for `credential_carve_outs`**: If a baseline policy has
   `credential_carve_outs: []` (deny all), can an agent override add carve-outs? By the
   tightening-only rule, no — an agent cannot add carve-outs not present in the baseline. But this
   means the only way to give a specific agent a credential carve-out is to add it to the baseline
   first (even if other agents don't use it). Operators may find this friction counterintuitive.
   Consider whether `credential_carve_outs` should be managed differently (e.g., as an additive
   agent-specific list rather than a tightening overlay) — but this would require a policy exception
   to the tightening-only rule. Left as an open question for the operator to decide.

5. **Codex double-sandbox interaction at the policy layer**: §13.1 item 5 says AIRG should treat
   Codex's own sandbox as AIRG-controlled state. Should `os_sandbox` include a field like
   `"disable_agent_inner_sandbox": true` to codify this? Or is this purely launcher behavior,
   not a policy field? This affects whether the GUI and `agent_overrides` can express the
   double-sandbox suppression. Left open pending resolution of §13.9 open item 3.
