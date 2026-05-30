# AIRG OS-Level Enforcement — Phased Implementation Architecture (T8 Synthesis)

**Status:** Authoritative architecture; design-only. No code written.
**Branch:** `experimental`
**Produced:** 2026-05-30 by general-purpose agent (Claude Opus).
**Inputs synthesized (trust these; this doc integrates, does not re-derive):**
`AGENT_CONTEXT.md §13` (spine) · `launcher-evaluation.md` (T2) ·
`transport-bridge-design.md` (T3) · `sandbox-policy-schema.md` (T4) ·
`carveout-baseline.md` (T5) · `macos-seatbelt.md` (T6) ·
`codex-sandbox-integration.md` (T7) · `scripts/airg_sandbox_probe.py` (T1).

This is the capstone. It tells a future implementer (or the operator) how the seven
research tasks fit together and how to start P0 immediately. Section 5 (consolidated
open questions) is the key output for the operator.

---

## 1. North Star & Scope

**Operator's north star (§13.1 #6, verbatim-ish):** *"Take what we do now with MCP
policy and apply it at the OS level."* Landlock (Linux) / Seatbelt (macOS) is the chosen
tool; the operator is open to alternatives.

**The crucial calibration (§13.11):** AIRG's MCP policy decomposes into two halves, and
the OS sandbox can only carry one of them:

- **Spatial half — WHERE the agent can act.** Workspace containment + credential
  blocked-paths + port-level network. This **translates cleanly to Landlock/Seatbelt and
  becomes kernel-enforced.** It directly closes AIRG's #1 documented weakness: native
  (non-MCP-routed) tools and agent-spawned subprocesses currently bypass AIRG entirely
  (§2, §13.2).
- **Behavioral half — WHAT the agent is doing.** Destructive-pattern blocking, approval
  gating (human-in-the-loop), backup-before-write, Script Sentinel, domain-based network.
  **Not expressible in Landlock.** This stays in the existing MCP/interception layer.

**The honest one-liner (§13.11):** *"Landlock kernel-enforces WHERE the agent can act;
AIRG MCP continues to govern WHAT it does."* Putting the behavioral half at the OS level
would require seccomp user-notification or eBPF-LSM — a distinct, far larger advanced
phase, explicitly out of scope here.

**Threat-model framing (§13.1 #3):** Defense-in-depth. The OS sandbox is a *second layer*
hardening the existing accident/mistake model. **Do not overclaim adversarial
containment.** The "not a full malicious-actor containment platform" disclaimer stays.

### Locked decisions (§13.1, restated)

1. **Platform:** Linux AND macOS are both primary. (Original "Windows" was a mistype;
   Windows is deferred indefinitely and would use AppContainer/Job Objects, not Landlock.)
   macOS path = Seatbelt / `sandbox-exec`.
2. **Implementation:** Wrap an existing launcher. Do NOT hand-roll `landlock_*` syscalls
   in Python.
3. **Threat model:** Defense-in-depth; OS sandbox is a hardening second layer; keep the
   disclaimer.
4. **AIRG placement:** Topology A — AIRG fully OUTSIDE the sandbox, talking to the
   confined agent over a stdio↔AF_UNIX-socket bridge (no new auth work; do NOT gate the
   sandbox on SSE).
5. **Codex double-sandbox:** AIRG treats Codex's built-in sandbox as AIRG-controlled
   state and must NOT stack a second sandbox. AIRG is the authoritative outer wall.
   **⚠ See §5 BLOCKING-1 — the code does not currently match the "ships disabled"
   characterization in this decision.**
6. **North star:** as above, with the §13.11 spatial/behavioral calibration.

---

## 2. Target Architecture — Topology A (ASCII)

Integrates T3 (bridge) + T4 (`os_sandbox` policy) + T2 (launcher) + the agent.
Enforcement points are marked **[S] = spatial (kernel-enforced)** and
**[B] = behavioral (MCP-layer)**.

```
                          policy.json
                          ├── os_sandbox{}   ← T4  [S] drives the wall below
                          └── blocked/network/execution/script_sentinel{}  [B]
                                   │
   ┌───────────────────────────────┼───────────────────────────────────────────┐
   │  OUTSIDE THE SANDBOX (unconfined) — same uid, separate fd space             │
   │                                   │                                          │
   │   ┌───────────────────────────────▼─────────────────────────────────────┐   │
   │   │  airg-run  (T2 entrypoint, generalizes airg-codex)                   │   │
   │   │   1. probe host (T1)  2. pick launcher  3. reconcile Codex (T7)      │   │
   │   │   4. start AIRG socket server  5. exec launcher → wall → shim        │   │
   │   └──────────────┬────────────────────────────────────┬─────────────────┘   │
   │                  │ spawns (unconfined)                 │ exec's (the wall)    │
   │   ┌──────────────▼──────────────────┐                 │                      │
   │   │  AIRG MCP server                │                 │                      │
   │   │  run_unix_socket_async (T3)     │   [B] WHAT:      │                      │
   │   │  • policy engine, approvals,    │   destructive   │                      │
   │   │    backup, audit, Sentinel,     │   detection,    │                      │
   │   │    domain network filtering     │   approvals,    │                      │
   │   │  • OWNS: approvals.db, hmac.key,│   backup,       │                      │
   │   │    activity.log, backups/,      │   domain net    │                      │
   │   │    policy.json, reports.db      │                 │                      │
   │   └──────────────┬──────────────────┘                 │                      │
   │                  │ listens on                          │                      │
   │   $AIRG_STATE_DIR/sockets/<agent_id>.sock  (0600, dir 0700)                   │
   └──────────────────┼──────────────────────────────────────┼───────────────────┘
                      │  THE ONE CARVE-OUT (only path crossing the wall)
═══════════════════════════════════════════════════════════════════════════════════
   ┌──────────────────┼──────────────────────────────────────▼───────────────────┐
   │  SANDBOX BOUNDARY — landrun/bwrap (Linux) | sandbox-exec (macOS)   [S] WHERE  │
   │                  │                                                            │
   │   ┌──────────────▼───────────┐   raw bytes    ┌──────────────────────────┐   │
   │   │  airg-mcp-shim (T3)      │◄── AF_UNIX ───►│  Agent / Codex           │   │
   │   │  ~40 LOC stdlib forwarder│   stdin/stdout  │  MCP client + subprocs   │   │
   │   │  connect(2) one socket   │                 │  (native tools too)      │   │
   │   └──────────────────────────┘                 └──────────────────────────┘   │
   │                                                                                │
   │   [S] kernel-enforced allow-set (T4 os_sandbox + T5 carve-out baseline):       │
   │     workspace_root (rw) · read_exec_paths (rx) · readable_paths (ro)           │
   │     · writable_paths (rw, /tmp) · bridge_socket_path (rw, the carve-out)       │
   │     · credentials DENIED by default · HOME=workspace_root (T5)                 │
   └────────────────────────────────────────────────────────────────────────────┘
```

Key property (T3 §5): everything except the one socket path — approvals.db, hmac.key,
policy.json, activity.log, backups/, reports.db — is **kernel-unreachable** from inside.
The "agent tampers with its own control plane" attack is closed by the kernel, not by
heuristics. This is why Topology A is preferred over Topology B (AIRG inside with
carve-outs), which would leave the control plane reachable.

---

## 3. Component Inventory

| Component | Purpose | Task | Lives in (codebase) | Depends on |
|---|---|---|---|---|
| **Capability probe** | Decide launcher viability at runtime: Landlock ABI, userns/AppArmor verdict, launcher binaries, sandbox-exec presence, seccomp. | T1 | `scripts/airg_sandbox_probe.py` (exists). Callable as library by launcher. | — |
| **`airg-run` entrypoint** | Generalize `airg-codex` → `airg-run -- <agent cmd>`. Orchestrates: probe → launcher pick → Codex reconcile → start socket server → establish wall → run. | T2/§13.6 | NEW dispatch in `src/airg_cli.py` + `pyproject.toml [project.scripts]`; platform dispatch module `src/airg_launcher/__init__.py` (Darwin→macos, Linux→linux). | probe, socket server, launchers, Codex reconciler |
| **Linux launcher wrapper** | Build + exec `landrun`/`bwrap` command with the T4/T5 allow-set; carve in the socket path; inject `HOME=workspace_root`, `TMPDIR`. | T2/T5 | NEW `src/airg_launcher/linux_launcher.py` | probe, `os_sandbox` policy, carve-out baseline |
| **macOS profile generator + launcher** | Render the SBPL `.sb` template from `os_sandbox` fields; invoke `sandbox-exec -f … -D … --`; filter deprecation warning; fail-closed on profile syntax error. | T6 | NEW `src/airg_launcher/macos_launcher.py` + `src/airg_launcher/profiles/airg_base.sb` | `os_sandbox` policy, carve-out baseline (§6) |
| **stdio↔socket shim** | In-sandbox ~40-LOC stdlib forwarder: relays raw bytes between its stdin/stdout (MCP client) and `connect(2)` on the one AF_UNIX socket. No MCP parsing. | T3 | NEW `src/airg_mcp_shim.py` (+ `[project.scripts]` entry) | bridge socket path env (`AIRG_SOCKET_PATH`) |
| **AIRG `run_unix_socket_async`** | Serve MCP over an AF_UNIX socket (wrap accepted conn as anyio streams → `lowlevel Server.run()`). ~80 LOC; no SDK fork. One process per agent profile (identity unchanged). | T3 | NEW method in `src/server.py` (or `src/server_unix.py`); `--socket PATH` flag in `src/airg_cli.py`. | existing `src/server.py`, mcp 1.26.0 low-level API |
| **`os_sandbox` policy section** | Schema for the spatial wall: `enabled`, `mode` (off/monitor/enforce), `launcher`, `filesystem{}`, `network_mode`, `allowed_tcp_ports`, `credential_carve_outs`, `on_setup_failure`. Tightening-only overrides. | T4 | `src/config.py` (normalize + tightening validator + `allowed_override_sections`); `policy.json`; `airg_cli.py` `_policy_template`; `tests/test_helpers.py` `DEFAULT_TEST_POLICY`; UI catalog. | existing config/policy machinery (§6, §10) |
| **Carve-out baseline** | The concrete default allow-set (read_exec/readable/writable paths, credential deny-list, HOME redirect) that populates `os_sandbox.filesystem`. Minimal vs Comfortable tiers. | T5 | Data: ships in `policy.json` template + launcher defaults. References `src/executor.py` (HOME=WORKSPACE_ROOT already set for MCP subprocs). | `os_sandbox` schema |
| **Codex reconciliation logic** | Detect effective Codex `sandbox_mode` (global+project precedence + trust); when `os_sandbox.mode==enforce`, establish wall FIRST then write `danger-full-access`; restore after exit; fail-closed if detection fails. Launcher logic, NOT a schema field. | T7 | NEW in launcher; reuses/extends `src/agent_posture.py::_codex_tier3_state`; writes via `src/agent_configurator.py` config-write path. | probe, wall establishment, `agent_posture.py`, `agent_configurator.py` |
| **Posture signal** | New `os_sandbox_confined` signal (NOT `sandbox_*` — collides with the client-sandbox keys `agent_posture.py` already reads). Surfaced in GUI Settings→Agents. | T4/§13.6 | `src/agent_posture.py` + `ui_v3/src/App.jsx` | `os_sandbox` policy |
| **`airg-doctor` checks** | Detect launcher binaries (apt/dnf/brew guidance), validate SBPL on macOS via dry-run, check Codex sandbox/trust state, verify socket dir is outside workspace. | T2/T6/§13.5 #6 | `src/airg_cli.py` (`airg-doctor`) | probe |

**Unaffected (do NOT duplicate behavioral logic here):** `src/executor.py` inner MCP
`execute_command` path, `src/policy_engine.py`, `src/approvals.py`, `src/backup.py`,
`src/script_sentinel.py`, `src/audit.py`. The MCP layer continues exactly as today; the
sandbox is purely additive (§13.6, T4 §2.2).

---

## 4. Phased Plan (entry/exit criteria per phase)

Anchored on §13.8, refined with T1–T7 findings.

### P0 — Spike / decision-resolver

**Goal:** Empirically settle the convergent unknowns that T2+T3+T5 all flagged, before
committing to P1. This is the go/no-go gate.

**Entry:** A Linux host (or VM/container) with Landlock (kernel ≥5.13) and `landrun`
installable; ideally also a userns-disabled host to settle the launcher pick. Codex CLI
available.

**Must empirically verify (exact list):**

1. **[BLOCKING] Landlock + AF_UNIX `connect(2)`** — Does granting Landlock FS read/write
   on a pathname socket inode (e.g. `landrun --rw /tmp/test.sock`) actually permit
   `connect(2)` to it at ABI v1–v5? This is the load-bearing assumption of Topology A and
   is flagged by **T2 §7.1, T3 §9.1, T5**. Test: `landrun --rw /tmp/t.sock -- socat -
   UNIX-CONNECT:/tmp/t.sock` against a real listener. **If this fails, Topology A on
   landrun is not viable as designed — re-evaluate (bwrap bind-mount, or ABI v9 pathname
   socket scope, or socket-dir carve-out).**
2. **[BLOCKING] private tmpfs in landrun** — Does landrun v0.1.14 support a private
   `/tmp` tmpfs (T5 §4.6 / open Q2)? If not, fall back to host `/tmp` rw and document.
3. **Probe target hosts** — Run `scripts/airg_sandbox_probe.py --json` on representative
   deployment hosts to read userns verdict + Landlock ABI; this *settles the launcher
   choice* (resolved-conditionally, see §5).
4. **HOME injection** — Confirm the launcher wrapper injects `HOME=workspace_root` into
   the agent env (separate code path from `executor.py`, which already does it for MCP
   subprocs — T5 §4.1 / open Q3). Confirm credential deny targets *real* home absolute
   paths, not `~/` (T5 open Q4).
5. **End-to-end bridge** — `airg-run -- codex` with AIRG outside + shim inside +
   `run_unix_socket_async`: a real MCP tool call succeeds through the bridge. Confirm
   abrupt shim kill doesn't leak session state (T3 §9.4).
6. **Codex reconcile ordering** — Prototype the handshake that confirms the wall is up
   before writing `danger-full-access` (T7 §4 / open Q2).
7. **landrun TCP ABI threshold** — minor: confirm whether TCP rules need 6.4 or 6.7 (T2
   §7.3) — only relevant if `network_mode != none`.

**Exit / go-no-go gates:**
- **GO** if (1) and (5) pass on at least one launcher (landrun preferred; bwrap fallback
  acceptable if userns available). Carve-out pain measured and deemed manageable.
- **NO-GO / redesign** if (1) fails on every available launcher (the socket bridge is the
  spine of Topology A; without it, fall back to Topology B with externalized control
  plane, or block on SSE/auth work).

### P1 — Linux MVP

**Entry:** P0 GO. Launcher pick resolved by probe.

**Deliverables (tied to docs):**
- `airg-run`/`airg-codex` entrypoint with platform dispatch (T2, §13.6).
- `os_sandbox` policy section fully wired: `config.py` normalization + tightening
  validator + `allowed_override_sections`; `policy.json` template; `airg_cli`
  `_policy_template`; `tests/test_helpers.py` (T4 §5 checklist).
- Topology A live: `run_unix_socket_async` + `airg-mcp-shim` + per-agent socket path,
  0600/0700 (T3).
- Linux launcher (`landrun` primary, `bwrap` fallback) applying the Comfortable-tier
  carve-out baseline (T5 §7/§9), HOME=workspace_root, credential deny-list on real home.
- `on_setup_failure: fail_closed` default + explicit, loud, logged, policy-gated
  `warn_and_run_unconfined` switch (§13.5 #5, T4 §2.1.8).
- `airg-doctor` launcher detection + install guidance (§13.5 #6).
- `os_sandbox_confined` posture signal + GUI surfacing (T4).
- Codex reconciliation logic with the ordering guarantee + sidecar restore (T7).

**Exit:** A confined Codex dev agent runs a representative workflow (install deps, run
tests, make a commit) through the bridge with `mode: enforce`; control plane is
kernel-unreachable from inside; fail-closed verified; monitor-mode workflow documented.

### P2 — Hardening

**Entry:** P1 shipped.

**Deliverables:**
- Credential carve-out model maturation; resolve the tightening-vs-additive question
  (§5 OQ, T4 open Q4).
- Network filtering proxy pattern for domain-level egress control (§13.5 #1) — sandbox
  blocks all egress except one proxy port; proxy does domain allowlisting.
- Audit tamper-evidence (cryptographic) — makes any Topology-B interim safe (§13.4,
  §13.8) and hardens the inside-topology fallback.
- Codex double-sandbox reconciliation hardening: SIGKILL recovery sidecar (T7 open Q3),
  project-trust edge case (T7 open Q4).
- Optional: nsjail/minijail advanced profile (Kafel seccomp) where userns available (T2).
- Consider systemd-unit deployment mode for server agents (§13.7).

**Exit:** Domain-level egress enforceable; audit log tamper-evident; recovery paths tested.

### P3 — macOS (Seatbelt)

**Entry:** P1 shipped (reuse the launcher abstraction).

**Deliverables (T6):**
- `src/airg_launcher/macos_launcher.py` + `profiles/airg_base.sb` (deny-default SBPL,
  param'd `WORKSPACE_ROOT` + `SOCKET_PATH`, bridge-socket carve-out via `(literal …)` +
  `(allow network-outbound (local unix-socket …))`).
- Deprecation-warning stderr filtering; fatal-on-syntax = fail-closed by construction.
- `airg-doctor` macOS checks (T6 §7.4); macOS path deltas from T5 §6.
- Resolve `read_exec_paths` platform-specificity (T4 open Q2).

**Exit:** Confined agent runs on macOS 12–15 with zero extra install deps; Codex inner
Seatbelt disabled (single-wall invariant); known SIP/TCC caveats documented (T6 §6).

### P4 — Windows (deferred indefinitely)

Separate workstream. AppContainer / Job Objects, NOT Landlock. Out of scope for this
effort (§13.1 #1).

---

## 5. Consolidated OPEN QUESTIONS / DECISIONS-FOR-OPERATOR

One prioritized, de-duplicated list gathering every open item across T1–T7 and §13.9.
`[BLOCKING]` items must be resolved before the dependent phase can proceed.

### BLOCKING

**BLOCKING-1 — Codex default contradicts the locked "ships disabled" decision. (T7)**
The code's actual Codex default is `tier3_sandbox_mode = "workspace-write"` — Codex's own
sandbox is **ACTIVE** (workspace-confined), not disabled. `"danger-full-access"` (the
value that disables Codex's sandbox) exists in `CODEX_SANDBOX_MODES` but is **never
emitted as a default**. This directly **CONTRADICTS** §13.1 #5's "AIRG already ships with
Codex's own sandbox disabled."
*Implication:* The no-double-sandbox reconciliation (T7) is built on this premise. Until
resolved, the launcher cannot assume Codex is unconfined. **Recommended resolution (T7
open Q5, option a):** keep `workspace-write` as the shipped default; AIRG writes
`danger-full-access` ONLY at OS-enforce launch time, AFTER its outer wall is confirmed up
(never before — that would leave users *less* protected). Operator must explicitly
confirm this interpretation; do not change the code default to `danger-full-access`
globally. *Blocks:* P1 (Codex reconciliation), and any honest statement of §13.1 #5.

**BLOCKING-2 — Landlock + AF_UNIX `connect(2)` is unverified. (T2 §7.1, T3 §9.1, T5)**
Does a Landlock FS read/write rule on a pathname socket inode actually permit `connect(2)`
under ABI v1–v5? The entire Topology A transport depends on this. Must be empirically
tested in P0 (gate 1). *Blocks:* P1 on landrun. If it fails on all launchers, Topology A
must be redesigned (bwrap bind-mount may still work; or wait for ABI v9 pathname-socket
scope; or fall back to Topology B + externalized control plane).

**BLOCKING-3 — Private tmpfs support in landrun. (T5 open Q2)**
landrun v0.1.14 may not expose tmpfs creation. Test in P0 (gate 2). Not fatal — fallback
is host `/tmp` rw with audit-log naming — but the decision changes the carve-out shape.
*Blocks:* finalizing P1 `writable_paths` behavior.

**BLOCKING-4 — Scope decision: does this effort advance from design to implementation?**
This session and T1–T7 are explicitly *design-only*. P0 is the first phase that writes
code. The operator must decide whether to authorize P0 implementation now, or hold at the
design tier. *Blocks:* everything past this document.

### NON-BLOCKING (resolved-conditionally or deferrable)

**OQ-5 — Final launcher pick is probe-driven (resolved-conditionally, NOT a blocker). (T2 §5)**
If userns available → `bwrap`; if userns disabled/AppArmor-restricted → `landrun`. Decided
at runtime by `airg_sandbox_probe.py`; fail-closed if neither. No standing decision needed
— P0 gate 3 settles it per target host.

**OQ-6 — Credential carve-out: tightening-only vs additive. (T4 open Q4)**
The tightening-only override rule means an operator must add a carve-out to the *baseline*
before any agent can use it (counterintuitive). Decide whether `credential_carve_outs`
should be an exception (additive per-agent). Default for P1: tightening-only (consistent
with existing override semantics). *Operator decision for P2.*

**OQ-7 — `read_exec_paths` platform-specificity. (T4 open Q2)**
Single field translated by launcher (current design) vs separate
`linux_/macos_read_exec_paths`. Acceptable as-is for P1 Linux; revisit at P3 macOS.

**OQ-8 — Packaging: detect-and-guide vs bundled static helper. (§13.5 #6, T2)**
landrun/bwrap are not pip-installable. `airg-doctor` detect+guide for P1; consider
bundling a static landrun binary (MIT) later. macOS has zero extra dep (T6 §7.1).

**OQ-9 — Shim delivery inside the sandbox. (T3 §9.3)**
pip-installed alongside AIRG (simplest, P0) vs static binary. Pick pip for P0/P1.

**OQ-10 — `run_unix_socket_async` framing duplication. (T3 §9.2)**
Copy the ~20-LOC newline-JSON encode/decode from `mcp.server.stdio`; own it. Low risk.

**OQ-11 — Codex built-in `sandbox_mode` default if absent. (T7 open Q1)**
Assumed `workspace-write`; confirm empirically in P0. If actually `danger-full-access`,
detection algorithm (T7 §2.2) needs updating.

**OQ-12 — Abrupt-exit / SIGKILL recovery of Codex config. (T7 open Q3)**
If AIRG is killed while `danger-full-access` is written, next session starts unconfined.
Mitigation: sidecar restore file + recovery check at launch. P2.

**OQ-13 — sandbox-exec deprecation. (T6 §2, T5 open Q5)**
Deprecated on macOS 15 but actively used by Codex/Gemini/Chromium/Bazel/Nix. Best-effort
second layer under defense-in-depth; monitor Apple containerization for a replacement.
P3 risk, not a blocker.

**OQ-14 — SBPL `(param …)` with special-char paths; Mach IPC completeness; TCC for
workspaces in iCloud. (T6 open Q1–3)** P3 macOS empirical testing.

**OQ-15 — Landlock ABI-v1 `/proc/self` read behavior on kernels 5.13–5.18. (T5 open Q1)**
Verify during P0/P1 if targeting old kernels.

**OQ-16 — T1 probe arch coverage.** Only x86_64/aarch64 Landlock syscall nrs mapped;
other arches return None and need a mapping entry. AppArmor-restricted userns verdict
needs an Ubuntu 23.10+ host to verify end-to-end. (T1)

---

## 6. Risk Register

| Risk | Likelihood | Impact | Mitigation | Residual |
|---|---|---|---|---|
| **Carve-out brittleness** (agent breaks: "can't find node/git/libs", or too loose) — §13.5 #3, the #1 operational risk | High | Med | `mode: monitor` first (logs would-deny); Minimal/Comfortable tiers (T5 §7); symptom→path debug table (T5 §8); whole-dir allows. | Iteration cost remains; per-deployment tuning expected. |
| **Landlock+AF_UNIX connect fails** (BLOCKING-2) | Unknown until P0 | High | P0 gate 1 is exactly this test; bwrap bind-mount fallback; Topology B + externalized control plane as last resort. | If all fail, Topology A blocked; design pivot needed. |
| **userns disabled on target hosts** (bwrap/nsjail break) — §13.3 | High (hardened/CI) | Med | landrun (Landlock-native, no userns); probe-driven selection; fail-closed if neither. | landrun immaturity (single maintainer, no audit). |
| **Disabling Codex's inner sandbox before AIRG's wall is up** — T7 §4 | Low (if ordering honored) | High | Strict ordering: establish + confirm wall, THEN write `danger-full-access`; never on `warn_and_run_unconfined`; handshake confirmation. | SIGKILL-mid-session leaves config disabled (→ sidecar restore, P2). |
| **Fail-closed correctness** (silent degradation to unconfined) — §13.5 #5 | Med | High | `on_setup_failure: fail_closed` default; loud structured audit ERROR before any agent start; `warn_and_run_unconfined` is explicit/logged/policy-gated/tightening-locked. | Operator can still opt into unconfined; auditable. |
| **sandbox-exec deprecation/removal** — T6 §2 | Low (near-term) | Med (macOS only) | Defense-in-depth framing (MCP layer survives); doctor version pinning; monitor Apple containerization. | No drop-in replacement exists today; macOS is P3 best-effort. |
| **Co-located process connects to socket** — T3 §5.5 | Low | Low-Med | 0600 socket + 0700 dir + state-dir placement (outside workspace); same-user attacker already out of threat model. | Optional SO_PEERCRED hardening (deferred). |
| **Testing-matrix burden** (ABI versions × userns × macOS) — §13.5 #7 | High | Med | Probe-gated behavior; tests use `os_sandbox` disabled `DEFAULT_TEST_POLICY`; CI VMs only for spike/integration. | Heavier than today's pure-Python suite. |

---

## 7. Effort / Sequencing Note

Rough relative sizing (no calendar):

| Phase | Relative size | Notes |
|---|---|---|
| P0 spike | **S** | Mostly empirical verification + ~150 LOC throwaway/seed bridge. Gates everything. |
| P1 Linux MVP | **L** | The bulk: schema wiring (touches config/policy/cli/tests/UI per §10), launcher, bridge productionization, Codex reconcile, doctor, posture. |
| P2 hardening | **M** | Network proxy + audit crypto are each non-trivial; carve-out/recovery polish. |
| P3 macOS | **M** | Reuses launcher abstraction; SBPL template + macOS doctor + path deltas; lower deps but Seatbelt finickiness. |
| P4 Windows | — | Deferred indefinitely; separate workstream. |

**Critical path:**
`P0 gate 1 (Landlock+AF_UNIX connect)` → `run_unix_socket_async + shim` → `Linux launcher
+ carve-out baseline` → `os_sandbox schema wiring` → `Codex reconciliation` → P1 ships.
macOS (P3) and hardening (P2) branch off P1 and can proceed in parallel once the launcher
abstraction and schema are stable. **BLOCKING-1 (Codex default) and BLOCKING-4 (scope
authorization) gate the start of P0/P1 and are operator decisions, not engineering work.**

---

## Cross-references

- `AGENT_CONTEXT.md §13` — design spine and locked decisions.
- `docs/os-enforcement/launcher-evaluation.md` — T2, launcher matrix + probe-driven pick.
- `docs/os-enforcement/transport-bridge-design.md` — T3, shim + `run_unix_socket_async`.
- `docs/os-enforcement/sandbox-policy-schema.md` — T4, `os_sandbox` schema + overrides.
- `docs/os-enforcement/carveout-baseline.md` — T5, the concrete allow-set + tiers.
- `docs/os-enforcement/macos-seatbelt.md` — T6, SBPL profile + sandbox-exec.
- `docs/os-enforcement/codex-sandbox-integration.md` — T7, detection + no-double-sandbox.
- `scripts/airg_sandbox_probe.py` — T1, capability probe (JSON output).
