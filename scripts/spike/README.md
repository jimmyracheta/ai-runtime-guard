# AIRG P0 Spike Harness

Empirically resolves the **P0 go/no-go gates** from `docs/os-enforcement/ARCHITECTURE.md §4`.
Run this on a Linux host before committing to P1 implementation.

---

## Prerequisites (Linux host)

| Requirement | Notes |
|---|---|
| **Linux kernel ≥ 5.13** | Landlock ABI v1 (filesystem rules). Check with `uname -r`. |
| **landrun** (preferred) | `go install github.com/zouuup/landrun/cmd/landrun@latest` or download a binary release from https://github.com/Zouuup/landrun/releases |
| **bwrap** (alternative) | `apt install bubblewrap` or `dnf install bubblewrap`. Requires unprivileged user namespaces (`sysctl kernel.unprivileged_userns_clone`). |
| **Python 3.10+** | Standard install; no pip packages required for the spike harness itself. |

At least one of **landrun** or **bwrap** must be installed. Run `scripts/airg_sandbox_probe.py` first to see which is viable on your host.

---

## Quick start

```bash
# On any host (macOS too): just run Gate 0 to see host capabilities
python3 scripts/spike/run_spike.py --gate 0

# On a Linux host: run all gates
python3 scripts/spike/run_spike.py

# Machine-readable JSON output (for CI or programmatic processing)
python3 scripts/spike/run_spike.py --json

# Run a single gate
python3 scripts/spike/run_spike.py --gate 1
```

---

## Gates

### Gate 0 — Host capability probe (runs on any OS)

Invokes `scripts/airg_sandbox_probe.py --json`, summarizes:
- Landlock ABI version (Linux only)
- Unprivileged user-namespace availability (Linux only)
- Which launcher binaries are present
- Which launcher (landrun vs bwrap) subsequent gates will use

**What it proves:** The host is ready for P0 testing. This gate always runs and
always produces output — it is the foundation for launcher selection.

**Unblocks:** All subsequent gates.

---

### Gate 1 — Landlock + AF_UNIX connect(2) [CRITICAL]

**This is the linchpin gate.** The entire Topology A design depends on it.

Starts a tiny AF_UNIX echo server **outside** the sandbox, then runs a Python
client **inside** the sandbox (via landrun or bwrap), verifying that:
1. `connect(2)` to a pathname socket inode succeeds through the Landlock FS path rule.
2. A round-trip message (`AIRG_GATE1_ROUNDTRIP`) is received and echoed correctly.

This resolves **BLOCKING-2** from `ARCHITECTURE.md`: whether a Landlock FS
read/write rule on a socket inode (e.g. `landrun --rw /tmp/test.sock`) actually
permits `connect(2)` at ABI v1–v5.

**What it proves:** Topology A is viable. If this passes, the socket bridge design
works and P1 can proceed.

**What it unblocks:** P1 Linux MVP (the entire bridge implementation).

**If it FAILS:**
- On landrun: try bwrap (bind-mount: `--bind <sockpath> <sockpath>`).
- On all launchers: wait for Landlock ABI v9 (explicit pathname socket scope).
- Last resort: Topology B (AIRG inside sandbox, externalized control plane — weaker).
- Document the failure in `os_enforcement_work.md` and open an architecture revision.

---

### Gate 2 — Private tmpfs in landrun

Tests whether the chosen launcher can provide a writable private `/tmp` (a
`tmpfs` mount isolated from the host).

- **landrun**: checks for a `--tmpfs` or `--private-tmp` flag; tests it if present.
- **bwrap**: tests `--tmpfs /tmp` (well-documented; expected PASS).

**What it proves:** Whether the P1 `writable_paths` carve-out uses a private tmpfs
(preferred) or falls back to host `/tmp` rw.

**What it unblocks:** Finalizing the P1 carve-out baseline shape. Non-fatal: if
private tmpfs is unavailable, the documented fallback is host `/tmp` rw with
audit-log naming (BLOCKING-3 in `ARCHITECTURE.md`).

---

### Gate 3 — End-to-end bridge under sandbox

Runs a lightweight stub MCP server (stdlib-only, speaks newline-delimited JSON-RPC)
**outside** the sandbox, then runs `scripts/airg_stdio_bridge.py` (the real shim)
**inside** the sandbox via the launcher, carving in only the socket path.

Drives a full MCP `initialize` + `tools/list` round-trip through the bridge and
asserts valid responses.

**What it proves:** The complete Topology A path is functional: agent (inside)
→ shim (inside) ↔ socket ↔ AIRG server (outside). The `scripts/airg_stdio_bridge.py`
shim works correctly when confined.

**What it unblocks:** P1 `run_unix_socket_async` productionization and the
`agent_configs.py` shim-as-command wiring.

---

### Gate 4 — HOME=WORKSPACE_ROOT injection

Verifies that the launcher invocation correctly injects `HOME=<workspace_root>` into
the agent's environment, and that `os.path.expanduser("~")` inside the sandbox
resolves to the workspace (not the real user home).

This is a **separate code path** from `src/executor.py` (which already sets HOME
for MCP subprocesses) — here we confirm the OS-level launcher wrapper does it too.

**What it proves:** The T5 finding (HOME redirect redirects `~/` tool caches and
credential lookups into the workspace) works at the launcher level, not just inside
the existing executor.py path.

**What it unblocks:** Confident credential deny-list construction in P1 (real home
`~/.ssh`, `~/.aws`, etc. are unreachable because HOME points elsewhere).

---

## How to read results

Each gate prints:
- `PASS` — criterion met; go/no-go resolved positively.
- `FAIL` — criterion NOT met; see interpretation for alternatives.
- `SKIP` — gate was not applicable (non-Linux host or no launcher installed).

The final summary line is one of:
- **`GO`** — Gates 1 and 3 both PASS. P1 implementation authorized.
- **`NO-GO`** — Gate 1 FAILED. Topology A needs redesign. See alternatives.
- **`PARTIAL-GO`** — Gate 1 PASS, Gate 3 FAIL. Investigate Gate 3 environment.
- **`INCONCLUSIVE`** — Gates 1 and 3 were SKIPPED (non-Linux or no launcher).

---

## P1 decisions each gate unblocks

| Gate | P1 decision unblocked |
|---|---|
| 0 | Launcher choice (landrun vs bwrap) baked into `linux_launcher.py` |
| 1 | Socket bridge carve-out model: confirm `--rw <sockpath>` (landrun) or `--bind` (bwrap) |
| 2 | `writable_paths` shape: private tmpfs vs host `/tmp` rw |
| 3 | `airg_stdio_bridge.py` → `agent_configs.py` wiring; `run_unix_socket_async` is ready |
| 4 | Launcher env injection: confirm `--env HOME=<ws>` (landrun) or `--setenv HOME <ws>` (bwrap) |

---

## Non-Linux note

On macOS (this dev machine), Gates 1–4 are automatically **SKIPPED** with a clear
message. Gate 0 still runs and provides useful macOS host capability information
(Python version, sandbox-exec presence, etc.). This is by design — the harness
detects the OS at startup and skips gates that require Linux.

The harness does NOT crash, error, or leave stale files on non-Linux hosts.

---

## Safety

The harness is non-mutating with respect to the host:
- Creates only throwaway sockets and scripts under `tempfile.TemporaryDirectory`.
- All temp files are cleaned up on exit (normal or crash).
- Does not modify any system configuration or AIRG source files.
- Read-only with respect to the repository.
