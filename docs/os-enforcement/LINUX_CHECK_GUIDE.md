# AIRG OS-Enforcement — Linux Operator Check Guide

**Branch:** `experimental`  
**Audience:** Project owner, running on a Linux host.  
**Purpose:** Validate the OS-enforcement work (implemented and unit-tested on macOS) on real Linux hardware.  
**Written:** 2026-05-31 by general-purpose agent (Sonnet 4.6).  
Grounded in the actual code — every command was read from a source file, not invented.

---

## Prerequisites (Step 1)

### 1a. Check kernel version

```bash
uname -r
```

**Expected:** The version string should be `5.13.0` or higher (e.g. `6.8.0-51-generic`).  
Landlock ABI v1 requires kernel ≥ 5.13. ABI v4 (TCP port rules) requires ≥ 6.7.  
**If it fails / version is below 5.13:** Upgrade the kernel or use a newer distribution.
Ubuntu 22.04+ ships 5.15; Fedora 38+ ships 6.x. Landlock is not usable on older kernels.

### 1b. Check Python version

```bash
python3 --version
```

**Expected:** `Python 3.10.x` or higher (3.11+ recommended).  
**If it fails:** `apt install python3` or use `pyenv` / `deadsnakes` PPA.

### 1c. Check out the `experimental` branch

```bash
git fetch origin
git checkout experimental
git log --oneline -5
```

**Expected:** The branch tip should include commits from the `P1-c` implementation
(you should see something referencing `sandbox_launcher.py` or `codex_sandbox_reconcile`).  
**If it fails:** Confirm you have the correct remote (`git remote -v`).

### 1d. Install a sandbox launcher

You need at least one of `landrun` or `bwrap`.

**Option A — landrun** (preferred; Landlock-native, no user-namespace dependency):

```bash
# Requires Go toolchain (go >= 1.21 recommended).
go install github.com/zouuup/landrun/cmd/landrun@latest
# Ensure $GOPATH/bin (typically ~/go/bin) is on PATH:
export PATH="$HOME/go/bin:$PATH"
landrun --version
```

> Note: The exact Go module path (`github.com/zouuup/landrun/cmd/landrun`) was taken
> from `scripts/spike/README.md` and `scripts/spike/run_spike.py`. Confirm it resolves
> correctly — the module path capitalisation changed at some point and the `@latest` tag
> may resolve to v0.1.14. If the install fails, check the releases page at
> `https://github.com/Zouuup/landrun/releases` for a pre-built binary.

**Option B — bwrap (bubblewrap)** (requires unprivileged user namespaces):

```bash
# Debian / Ubuntu:
apt install bubblewrap

# Fedora / RHEL 9+:
dnf install bubblewrap

bwrap --version
```

> **Distro userns note:** Ubuntu 23.10+ and some hardened kernels restrict unprivileged
> user namespaces via AppArmor (`/proc/sys/kernel/apparmor_restrict_unprivileged_userns`)
> or by setting `unprivileged_userns_clone=0`. The probe (Step 2) will report this.
> On such hosts, `bwrap` may be blocked and `landrun` is the only viable launcher.
> On Debian Bookworm, `bwrap` works by default; on Ubuntu 24.04+, AppArmor may restrict it.

**If neither is available:** The probe will report `NO viable launcher`. Steps 4–7 will
indicate `NO-GO` or fail-closed. Install one of the above before proceeding.

---

## Step 2 — Run the capability probe

```bash
# Human-readable summary:
python3 scripts/airg_sandbox_probe.py

# Machine-readable JSON (save for the report):
python3 scripts/airg_sandbox_probe.py --json | tee /tmp/airg_probe.json
```

**Expected result (Linux with kernel ≥ 5.13):**

- `Landlock → Available: True, ABI version: v4` (or similar v1–v5 depending on kernel)
- `Unprivileged User Namespaces → Verdict: yes` (unless AppArmor-restricted or hardened)
- Whichever launcher you installed shows `FOUND` with a version string
- The `Usable launcher options` section shows `VIABLE` for at least one launcher
- The `chosen_launcher` in JSON is `"landrun"` or `"bwrap"` (not `"(none)"`)

**How to read the launcher selection logic:**

| Probe output | What the code picks |
|---|---|
| `userns: yes` + `bwrap: FOUND` | `bwrap` (first priority in `select_launcher`) |
| `landlock: ABI v1+` + `landrun: FOUND` | `landrun` (fallback when no usable userns) |
| `userns: yes_but_apparmor_restricted` + `bwrap: FOUND` | `bwrap` treated as restricted; `landrun` preferred if available |
| Neither | `(none)` — no confinement possible |

**If it fails:**
- Script exits non-zero: check Python version (`python3 --version`).
- `Landlock: Available: False, ENOSYS`: kernel < 5.13 or `CONFIG_SECURITY_LANDLOCK` not compiled in.
- `Landlock: EOPNOTSUPP`: compiled in but disabled (check `/boot/config-$(uname -r) | grep LANDLOCK`).
- Both launchers `not found`: install per Step 1d.

---

## Step 3 — Run the unit test suite on Linux

```bash
# From the repo root (activate your venv first if you have one):
python3 -m unittest discover -v 2>&1 | tail -30
```

Or, to get a count summary only:

```bash
python3 -m unittest discover 2>&1 | tail -5
```

**Expected result on Linux:**

```
Ran 260 tests in XX.XXXs
OK (failures=0, skipped=5)
```

The two tests that fail on macOS (due to `/tmp` → `/private/tmp` symlink resolution)
**should PASS on Linux** because Linux has no such symlink:

- `test_attacker_suite.TestAttackerSuite.test_shell_workspace_containment_tracks_cd_before_relative_targets`
- `test_mcp_config_manager.TestMcpConfigManager.test_apply_codex_project_config_creates_project_file`

**If other tests fail:** Those are real problems. Note which tests fail, capture the output,
and report them (they do not exist in the macOS-verified baseline and indicate a
Linux-specific regression). Do NOT proceed to Step 4 with unexpected failures.

**If skips increase beyond 5:** Check whether any tests are being skipped due to missing
optional deps. The 5 known skips are pre-existing and not related to OS enforcement.

---

## Step 4 — Run the P0 spike harness

```bash
# Full run (all 5 gates):
python3 scripts/spike/run_spike.py

# Save machine-readable JSON for the report:
python3 scripts/spike/run_spike.py --json | tee /tmp/airg_spike.json

# Run a single gate (useful for re-running after fixes):
python3 scripts/spike/run_spike.py --gate 1
python3 scripts/spike/run_spike.py --gate 3
```

**What each gate proves and why it matters:**

| Gate | Name | CRITICAL? | What it proves |
|---|---|---|---|
| 0 | Host capability probe | No | Launcher selection; foundation for all subsequent gates |
| **1** | **Landlock + AF_UNIX connect(2)** | **YES — linchpin** | Whether `landrun --rw <sockpath>` or `bwrap --bind <sockpath>` actually permits `connect(2)` to the socket — the load-bearing assumption of Topology A |
| 2 | Private tmpfs | No | Whether landrun supports `--tmpfs /tmp`; if not, fallback is host `/tmp` rw (non-fatal) |
| **3** | **End-to-end bridge** | **YES — linchpin** | Full path: agent (inside sandbox) → shim → socket → AIRG server (outside); real MCP `initialize` + `tools/list` round-trip |
| 4 | HOME=WORKSPACE_ROOT injection | No | That the launcher sets `HOME` to the workspace, blocking credential-path lookups |

**Reading the overall verdict:**

- **`GO`** — Gates 1 and 3 both PASS. P1 implementation is verified. Proceed to Steps 5–7.
- **`PARTIAL-GO`** — Gate 1 PASS, Gate 3 FAIL. Transport layer is sound; investigate Gate 3
  environment (check carve-out paths for the bridge script).
- **`NO-GO`** — Gate 1 FAILED. Topology A is not viable with the current launcher/kernel.
  The socket bridge is the spine of the design; this needs to be resolved before P1 can proceed.
- **`INCONCLUSIVE`** — Gates 1 and 3 were SKIPPED (non-Linux host or no launcher installed).

**If Gate 1 is NO-GO:**

The spike harness will print the documented alternatives:
1. Switch to `bwrap` if only `landrun` was tested (or vice versa). Run the probe again
   to confirm which launchers are available.
2. Use a bwrap socket-directory bind: `--bind <socket_dir> <socket_dir>` (bind the parent
   directory of the socket, not just the socket inode).
3. Wait for Landlock ABI v9 (adds explicit pathname Unix-socket scope) — not yet in
   mainline as of 2026-05.
4. Fall back to Topology B (AIRG inside the sandbox, externalized control plane) — weaker
   security model; see `docs/os-enforcement/transport-bridge-design.md §5.4`.

**If Gate 3 fails but Gate 1 passed:** Check that `scripts/airg_stdio_bridge.py` is readable
from the path the harness uses (it looks up `_BRIDGE_SCRIPT = _REPO_ROOT / "scripts" / "airg_stdio_bridge.py"`).
Also verify the launcher's carve-out for the scripts directory is correct.

---

## Step 5 — Verify/correct landrun flag spellings

This is the known soft spot called out by the P1-c implementer.

### 5a. Check what flags your installed landrun actually exposes

```bash
landrun --version
landrun --help 2>&1 | head -60
```

**Expected:** A help page listing flags. Make a note of the exact flag spellings for:
read-only (`--ro`?), read-write (`--rw`?), read+exec (`--rox`?), read+write+exec (`--rwx`?),
TCP connect (`--connect-tcp`?), env injection (`--env`?), and the unrestricted-network flag.

### 5b. Compare against what `sandbox_launcher.py` emits

Open `src/sandbox_launcher.py` and look at `build_landrun_argv()` (line ~336). The flags
currently coded are:

| Use | Flag in code | Verify against `landrun --help` |
|---|---|---|
| Workspace (rw + exec) | `--rwx` | |
| read+exec baseline paths | `--rox` | |
| read-only data paths | `--ro` | |
| writable scratch | `--rw` | |
| Bridge socket (rw) | `--rw` | |
| TCP port allow | `--connect-tcp` | |
| Env variable | `--env KEY=VAL` | |
| Unrestricted network | `--unrestricted-network` | (flagged as unverified by implementer) |

### 5c. Correct if they differ

If any flag spelling differs from what `landrun --help` shows, edit
`src/sandbox_launcher.py` `build_landrun_argv()` to match. This is a pure string
change — no logic changes needed.

```bash
# Example: if landrun uses --rw-exec instead of --rwx:
# Edit src/sandbox_launcher.py line ~354:
#   argv += ["--rwx", spec.workspace_root]
# becomes:
#   argv += ["--rw-exec", spec.workspace_root]
```

After any corrections, re-run the spike (`python3 scripts/spike/run_spike.py`) and the
unit suite (`python3 -m unittest`) to confirm nothing broke.

**Expected:** All flag names match. If any differ, note the exact correction in your
report (Step 9).

**If landrun has no `--rwx` flag:** The workspace needs both write and exec permission.
Check if there is a combined flag or whether you need separate `--rw` + `--rx` flags (or
`--rw` only, if exec is implied by rw in the installed version).

**If `--unrestricted-network` is not a valid flag:** Check the actual flag name in
`landrun --help`; it may be `--allow-all-net`, `--no-net-restrict`, or similar.

---

## Step 6 — Inspect the launcher plan without running it

`airg-run` has a `--dry-run` flag (confirmed at `src/airg_cli.py` line 958) that prints
the resolved sandbox argv and exits without executing anything.

### 6a. Set up a test workspace and policy

```bash
# Create a disposable workspace for the test:
export AIRG_WORKSPACE=/tmp/airg-test-workspace
mkdir -p "$AIRG_WORKSPACE"

# Locate the policy file (airg-run will create one if absent):
export AIRG_POLICY_PATH=/tmp/airg-test-policy.json
```

Before `--dry-run` can show a real sandbox argv, `os_sandbox.mode` must not be `"off"`.
Set it to `"monitor"` (observation only; does not confine) or `"enforce"`:

```bash
python3 - <<'PYEOF'
import json, os

policy_path = os.environ["AIRG_POLICY_PATH"]
try:
    with open(policy_path) as f:
        policy = json.load(f)
except FileNotFoundError:
    # Import the project default template as a starting point
    import sys
    sys.path.insert(0, "src")
    import airg_cli
    policy = airg_cli._policy_template()

policy["os_sandbox"]["enabled"] = True
policy["os_sandbox"]["mode"] = "monitor"   # safe: observation only, no actual confinement
policy["os_sandbox"]["launcher"] = "auto"
policy["os_sandbox"]["filesystem"]["workspace_root"] = os.environ["AIRG_WORKSPACE"]

with open(policy_path, "w") as f:
    json.dump(policy, f, indent=2)
print("Policy written to", policy_path)
PYEOF
```

### 6b. Run the dry-run inspection

```bash
airg-run \
  --workspace "$AIRG_WORKSPACE" \
  --dry-run \
  -- /bin/sh -c 'echo hello'
```

Or, if `airg-run` is not on PATH (installed entrypoint may not be set up yet):

```bash
PYTHONPATH=src python3 -c "
import sys; sys.argv = [
  'airg-run',
  '--workspace', '$AIRG_WORKSPACE',
  '--dry-run',
  '--', '/bin/sh', '-c', 'echo hello'
]
import airg_cli; airg_cli.main_run()
"
```

**Expected output (stderr):**

```
[airg-run] Start the AIRG control plane in a SEPARATE process (outside the sandbox):
           airg-server --socket /home/USER/.local/state/ai-runtime-guard/sockets/default.sock
[airg-run] os_sandbox mode=monitor: launcher 'landrun' would confine ...
[airg-run] codex reconcile: noop (...)
```

Then, on stdout, the `describe_plan` output — a copy-pasteable `shlex.join()` of the
planned argv. For `mode=monitor` it will be the bare agent command (unconfined). To see
the actual sandbox argv, change mode to `"enforce"`:

```bash
# Quick override for just this inspection — change "monitor" to "enforce" in the policy
# then re-run --dry-run.  You will see the full landrun/bwrap argv.
```

**How to read the dry-run argv:**

- Workspace appears as `--rwx /tmp/airg-test-workspace` (landrun) or
  `--bind /tmp/airg-test-workspace /tmp/airg-test-workspace` (bwrap) — confirms rw access.
- The bridge socket appears as `--rw /home/.../.../sockets/default.sock` (landrun) or
  `--bind .../sockets/default.sock ...` (bwrap) — exactly ONE socket path.
- No `~/.ssh`, `~/.aws`, `~/.kube`, `~/.config/gcloud`, etc. appear anywhere — credentials
  are not granted.
- `--env HOME=/tmp/airg-test-workspace` (landrun) or `--setenv HOME /tmp/airg-test-workspace`
  (bwrap) — HOME redirected to workspace.
- `AIRG_SOCKET_PATH=...` is also injected via `--env`/`--setenv`.

**If it fails:**
- `SandboxSetupError: no usable launcher`: the probe found no launcher. Go back to Step 1d.
- Import error: ensure you are running from the repo root with `src/` on `PYTHONPATH`.

---

## Step 7 — End-to-end confinement smoke test

This is the definitive verification: an actual confined process, tested for allow and deny.

### 7a. Set policy to `enforce`

```bash
python3 - <<'PYEOF'
import json, os

policy_path = os.environ.get("AIRG_POLICY_PATH", os.path.expanduser(
    "~/.config/ai-runtime-guard/policy.json"))
workspace = os.environ.get("AIRG_WORKSPACE", os.path.expanduser("~/airg-workspace"))

with open(policy_path) as f:
    policy = json.load(f)

policy["os_sandbox"]["enabled"] = True
policy["os_sandbox"]["mode"] = "enforce"
policy["os_sandbox"]["launcher"] = "auto"          # probe-driven
policy["os_sandbox"]["network_mode"] = "none"      # block all TCP
policy["os_sandbox"]["on_setup_failure"] = "fail_closed"
policy["os_sandbox"]["filesystem"]["workspace_root"] = workspace

with open(policy_path, "w") as f:
    json.dump(policy, f, indent=2)
print("Policy updated: mode=enforce at", policy_path)
PYEOF
```

### 7b. Start the AIRG control plane (socket server) — in a separate terminal

```bash
# Terminal 1 (leave running):
export AIRG_SOCKET_PATH=/tmp/airg-smoke-test.sock
airg-server --socket "$AIRG_SOCKET_PATH"
```

`airg-run --dry-run` (Step 6) also prints the exact `airg-server --socket <path>` command
with the auto-derived per-agent socket path. Use whichever path you prefer; the smoke test
below uses an explicit `AIRG_SOCKET_PATH` override for clarity.

**Expected:** The server starts and listens without error. It prints nothing to stdout
(it serves MCP over the socket, not stdio). Leave this terminal open.

### 7c. Run the confinement tests — in a second terminal

In Terminal 2, set the same socket path and workspace:

```bash
export AIRG_WORKSPACE=/tmp/airg-test-workspace
export AIRG_SOCKET_PATH=/tmp/airg-smoke-test.sock
mkdir -p "$AIRG_WORKSPACE"
```

#### (a) Write inside the workspace — ALLOW expected

```bash
airg-run --workspace "$AIRG_WORKSPACE" \
  -- /bin/sh -c 'echo "sandbox_write_test" > "$HOME/sandbox_test.txt" && echo "WRITE_OK"'
```

**Expected:** `WRITE_OK` printed; file `/tmp/airg-test-workspace/sandbox_test.txt` exists.  
**If denied:** Workspace is not correctly carve-ined as rw. Check the dry-run argv (Step 6)
for the workspace bind.

#### (b) Read inside the workspace — ALLOW expected

```bash
airg-run --workspace "$AIRG_WORKSPACE" \
  -- /bin/sh -c 'cat "$HOME/sandbox_test.txt" && echo "READ_OK"'
```

**Expected:** `sandbox_write_test` printed followed by `READ_OK`.

#### (c) Read a path OUTSIDE the workspace — DENY expected

```bash
airg-run --workspace "$AIRG_WORKSPACE" \
  -- /bin/sh -c 'cat /etc/shadow 2>&1; echo "exit=$?"'
```

**Expected:** Permission denied error (or file not found) from inside the sandbox, and
`exit=1` (or non-zero). The file should be unreachable because `/etc/shadow` is not in the
carve-out baseline's readable_paths list.  
**If it succeeds (reads the file):** The sandbox is not confining. Check that the launcher
was actually selected (look for `[airg-run] confining agent with 'landrun'` or `'bwrap'`
in stderr). Mode may still be `monitor` instead of `enforce`.

#### (d) Read a credential path — DENY expected

```bash
airg-run --workspace "$AIRG_WORKSPACE" \
  -- /bin/sh -c 'ls ~/.ssh 2>&1; echo "exit=$?"'
```

**Expected:** `ls: cannot access '.../.ssh': Permission denied` (or similar) and non-zero
exit. Since `HOME` is redirected to `$AIRG_WORKSPACE`, `~/.ssh` expands to
`/tmp/airg-test-workspace/.ssh`, which does not exist (correct — the real `~/.ssh` is
unreachable and the workspace `.ssh` does not exist either).  

Also test the absolute real home path directly:

```bash
REAL_HOME=$(bash -c 'echo $HOME')   # capture OUTSIDE the sandbox
airg-run --workspace "$AIRG_WORKSPACE" \
  -- /bin/sh -c "ls ${REAL_HOME}/.ssh 2>&1; echo \"exit=\$?\""
```

**Expected:** Permission denied / not accessible. The real home credential paths are not
in the carve-out list and should be kernel-denied.

#### (e) HOME resolves to the workspace — EXPECTED

```bash
airg-run --workspace "$AIRG_WORKSPACE" \
  -- /bin/sh -c 'echo "HOME=$HOME"'
```

**Expected:** `HOME=/tmp/airg-test-workspace` (not the real user home).

#### (f) Bridge socket is reachable from inside — EXPECTED

The MCP socket connection is implicit if `airg-run` itself succeeded (the shim connects
to the socket). For a direct test:

```bash
airg-run --workspace "$AIRG_WORKSPACE" \
  -- python3 -c "
import socket, os
sock_path = os.environ.get('AIRG_SOCKET_PATH', '')
if not sock_path:
    print('AIRG_SOCKET_PATH not set')
    raise SystemExit(1)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(sock_path)
    print('SOCKET_CONNECT_OK')
    s.close()
except Exception as e:
    print(f'SOCKET_CONNECT_FAIL: {e}')
    raise SystemExit(1)
"
```

**Expected:** `SOCKET_CONNECT_OK`. This is Gate 1 replayed with the real AIRG policy.  
**If it fails:** Gate 1 in Step 4 would have also failed. Revisit the landrun flag spellings
(Step 5) and the `--rw <socket_path>` carve-in in the argv.

**After all tests:** Reset policy to `mode=off` or `mode=monitor` if you don't want
all future `airg-run` invocations to enforce confinement:

```bash
python3 - <<'PYEOF'
import json, os
policy_path = os.environ.get("AIRG_POLICY_PATH",
    os.path.expanduser("~/.config/ai-runtime-guard/policy.json"))
with open(policy_path) as f:
    policy = json.load(f)
policy["os_sandbox"]["mode"] = "off"
with open(policy_path, "w") as f:
    json.dump(policy, f, indent=2)
print("Restored mode=off")
PYEOF
```

---

## Step 8 — (Optional) Codex no-double-sandbox check

This step verifies that AIRG does NOT weaken Codex's inner sandbox until AFTER the outer
OS wall is confirmed.

**Safe inspection only — do NOT point this at your real `~/.codex`.**

```bash
# Use a throwaway Codex config directory:
export HOME_SANDBOX_TEST=/tmp/airg-codex-test-home
mkdir -p "$HOME_SANDBOX_TEST/.codex"

# Write a test Codex global config with sandbox active:
cat > "$HOME_SANDBOX_TEST/.codex/config.toml" <<'EOF'
[sandbox]
sandbox_mode = "workspace-write"
EOF

# Run the reconcile detection (read-only) against the test home:
PYTHONPATH=src python3 - <<'PYEOF'
import pathlib
import sys
sys.path.insert(0, "src")
import codex_sandbox_reconcile as rec

test_home = pathlib.Path("/tmp/airg-codex-test-home")
workspace = pathlib.Path("/tmp/airg-test-workspace")

detection = rec.detect_codex_sandbox_mode(home=test_home, workspace=workspace)
print("Detection result:", detection)

# Test with outer_wall_confirmed=False — should not weaken:
decision = rec.reconcile_decision(
    codex_mode=detection.get("effective_sandbox_mode"),
    os_sandbox_mode="enforce",
    outer_wall_confirmed=False,   # wall NOT yet up
)
print("Decision (wall not up):", decision)
assert decision["action"] != rec.ACTION_SET_DANGER_FULL_ACCESS, \
    "FAIL: should not weaken when wall is not confirmed!"
print("PASS: no weakening before wall is confirmed.")

# Test with outer_wall_confirmed=True — now it should write danger-full-access:
decision2 = rec.reconcile_decision(
    codex_mode=detection.get("effective_sandbox_mode"),
    os_sandbox_mode="enforce",
    outer_wall_confirmed=True,    # wall IS up
)
print("Decision (wall up):", decision2)
print("Action:", decision2["action"])
PYEOF
```

**Expected:** The first decision (wall not confirmed) should NOT be `set_danger_full_access`.
The second decision (wall confirmed) should be `set_danger_full_access`.  
**If the first decision is `set_danger_full_access`:** This is a bug — the guard in
`codex_sandbox_reconcile.apply_and_restore` would prevent the actual write, but the
decision logic itself should not recommend weakening before the wall is up.

The actual enforcement in `airg-run` (`src/airg_cli.py` lines 1029–1062) only calls
`apply_and_restore` with `outer_wall_confirmed=plan.confined`, which is `True` only when
`establish_and_launch` successfully built a real sandbox argv.

---

## Step 9 — Report back

Capture and return the following checklist so the results can drive the next implementation step:

```
=== AIRG Linux OS-Enforcement Check Results ===

Date:
Host (distro + kernel version, uname -r):
Architecture (uname -m):
Python version:
Launcher installed: [ ] landrun  [ ] bwrap

--- Step 2: Probe ---
Landlock available: yes / no
Landlock ABI version: v___
userns verdict: yes / no / yes_but_apparmor_restricted / unknown
Chosen launcher: landrun / bwrap / (none)
Probe JSON saved to: /tmp/airg_probe.json (attach)

--- Step 3: Unit suite ---
Tests ran / failed / skipped: ___ / ___ / ___
macOS /tmp-symlink failures now PASS: yes / no
Any unexpected failures: (list test names, or "none")

--- Step 4: Spike harness ---
Spike JSON saved to: /tmp/airg_spike.json (attach)
Gate 0: PASS / FAIL
Gate 1 (CRITICAL): PASS / FAIL / SKIP
Gate 2: PASS / FAIL / SKIP
Gate 3 (CRITICAL): PASS / FAIL / SKIP
Gate 4: PASS / FAIL / SKIP
Overall verdict: GO / PARTIAL-GO / NO-GO / INCONCLUSIVE

--- Step 5: landrun flag corrections ---
Flags match code: yes / no
If no, corrections made:
  - old flag: ___  →  new flag: ___
  (repeat as needed)

--- Step 7: Confinement smoke test ---
(a) Write inside workspace: ALLOW confirmed: yes / no
(b) Read inside workspace: ALLOW confirmed: yes / no
(c) Read outside workspace (/etc/shadow): DENY confirmed: yes / no
(d) Read real ~/.ssh (absolute path): DENY confirmed: yes / no
(e) HOME = workspace inside sandbox: yes / no
(f) Bridge socket connect: ALLOW confirmed: yes / no

--- Notes / issues ---
(any unexpected behavior, error messages, or deviations from expected)
```

---

## Quick reference: key files

| File | What it does |
|---|---|
| `scripts/airg_sandbox_probe.py` | Capability probe; CLI: `python3 scripts/airg_sandbox_probe.py [--json]` |
| `scripts/spike/run_spike.py` | P0 gate harness; CLI: `python3 scripts/spike/run_spike.py [--json] [--gate N]` |
| `scripts/spike/README.md` | Spike harness documentation |
| `scripts/airg_stdio_bridge.py` | In-sandbox MCP shim (runs inside the sandbox) |
| `src/sandbox_launcher.py` | Landrun/bwrap argv builders; `CARVEOUT_BASELINE` constant; `establish_and_launch()` |
| `src/airg_cli.py` | `main_run()` = `airg-run` entrypoint; `main_server()` = `airg-server --socket PATH` |
| `src/codex_sandbox_reconcile.py` | Codex no-double-sandbox detection + reconciliation |
| `src/config.py` | Policy loading; `os_sandbox` normalization |
| `docs/os-enforcement/ARCHITECTURE.md` | P0 gates + go/no-go criteria |
| `docs/os-enforcement/carveout-baseline.md` | Allow-set tiers (Minimal / Comfortable) |
