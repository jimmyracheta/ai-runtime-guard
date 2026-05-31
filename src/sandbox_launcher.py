"""
sandbox_launcher.py — AIRG Linux OS-sandbox launcher (P1-c).

Builds and orchestrates the OS-level sandbox that wraps an AI agent (first
target: Codex) inside a Landlock (landrun) or namespace (bwrap) confinement
limited to the workspace, with AIRG running OUTSIDE the sandbox and reachable
only via the single AF_UNIX bridge socket (Topology A).

SECURITY-CRITICAL invariants (this is a security boundary):
  * The sandbox invocation is ALWAYS built as an argv LIST. There is never a
    shell string, never ``shell=True``, never string interpolation into a
    shell. ``build_landrun_argv`` / ``build_bwrap_argv`` produce ``list[str]``.
  * Deny-by-default: only the carve-out baseline + workspace (rw) + exactly the
    one bridge socket path (rw) are granted.
  * Fail-closed: if no usable launcher is found and mode == "enforce", AIRG
    refuses to launch unless the policy carries an explicit, logged unconfined
    opt-out (``on_setup_failure == "warn_and_run_unconfined"``).
  * The agent's HOME is redirected to the workspace (mirrors executor.py).

Design sources (trusted; do not redesign):
  docs/os-enforcement/launcher-evaluation.md     (probe-driven selection)
  docs/os-enforcement/carveout-baseline.md       (the allow-sets, deny-list)
  docs/os-enforcement/transport-bridge-design.md (the one socket carve-in)
  docs/os-enforcement/sandbox-policy-schema.md    (os_sandbox fields)

Verification note:
  Real Landlock / namespace confinement can only be verified on Linux. On
  macOS this module is unit-tested for COMMAND CONSTRUCTION and DECISION LOGIC
  only. The operator must verify actual confinement on a Linux host.

  Wiring the agent's MCP client to the in-sandbox shim (agent_configs.py
  shim-command) is OUT OF SCOPE for P1-c and handled separately (see
  transport-bridge-design.md §8 and airg_cli.main_run docstring).
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Carve-out baseline — single structured constant (derived from
# docs/os-enforcement/carveout-baseline.md §7). Tunable + testable.
# Keyed by tier: "minimal" (tightest working shell) and "comfortable"
# (productive dev agent). Each tier names its read+exec, read-only, and
# writable path sets. The launcher pulls from here unless the policy's
# os_sandbox.filesystem fields explicitly override them.
# ---------------------------------------------------------------------------

CARVEOUT_BASELINE: dict[str, dict[str, list[str]]] = {
    "minimal": {
        # read + execute (interpreters, shells, shared libs, dynamic linker)
        "read_exec_paths": [
            "/usr/bin",
            "/usr/lib",
            "/usr/lib64",
            "/bin",
            "/lib",
            "/lib64",
            "/usr/share/terminfo",
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d",
        ],
        # read-only data (certs, resolver, locale, timezone, passwd/group)
        "readable_paths": [
            "/etc/ssl/certs",
            "/etc/pki/tls",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/nsswitch.conf",
            "/etc/passwd",
            "/etc/group",
            "/etc/localtime",
            "/usr/share/zoneinfo",
            "/etc/gitconfig",
        ],
        # read + write scratch
        "writable_paths": [
            "/tmp",
        ],
    },
    "comfortable": {
        "read_exec_paths": [
            "/usr/bin",
            "/usr/sbin",
            "/usr/lib",
            "/usr/lib64",
            "/usr/lib32",
            "/usr/libx32",
            "/usr/libexec",
            "/usr/local/bin",
            "/usr/local/lib",
            "/usr/local/lib64",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/lib32",
            "/libx32",
            "/usr/share/terminfo",
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d",
            "/proc/self",
            "/dev/null",
            "/dev/urandom",
            "/dev/random",
            "/dev/stdin",
            "/dev/stdout",
            "/dev/stderr",
            "/dev/tty",
            "/dev/fd",
        ],
        "readable_paths": [
            "/etc/ssl/certs",
            "/etc/pki/tls",
            "/etc/pki/ca-trust",
            "/usr/share/ca-certificates",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/nsswitch.conf",
            "/etc/passwd",
            "/etc/group",
            "/etc/localtime",
            "/usr/share/zoneinfo",
            "/usr/share/locale",
            "/usr/lib/locale",
            "/usr/share/i18n",
            "/etc/locale.gen",
            "/etc/locale.conf",
            "/etc/gitconfig",
            "/etc/alternatives",
            "/proc/version",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/proc/sys/kernel/hostname",
        ],
        "writable_paths": [
            "/tmp",
        ],
    },
}

# Credential paths that must be DENIED by default at the OS layer. These are
# never granted by the launcher; they are listed so that:
#   (1) callers can assert (in tests) the launcher does not grant them, and
#   (2) the audit log can name what is being kept out.
# Per carveout-baseline.md §5.1 these target the REAL user home (resolved at
# runtime), not the redirected workspace HOME.
CREDENTIAL_DENY_BASENAMES: list[str] = [
    ".ssh",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".docker/config.json",
    ".kube",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".config/gh",
    ".config/op",
    ".vault-token",
    ".gnupg",
    ".gitconfig",
]

# Default tier when the policy does not specify one.
DEFAULT_TIER = "comfortable"


# ---------------------------------------------------------------------------
# Launcher spec — the resolved, immutable description of one sandbox launch.
# argv construction takes a LauncherSpec and is pure (no I/O, no spawning),
# which makes it unit-testable on any platform.
# ---------------------------------------------------------------------------


@dataclass
class LauncherSpec:
    """Everything the argv builders need. Pure data; no side effects."""

    workspace_root: str
    bridge_socket_path: str
    agent_argv: list[str]
    read_exec_paths: list[str] = field(default_factory=list)
    readable_paths: list[str] = field(default_factory=list)
    writable_paths: list[str] = field(default_factory=list)
    credential_carve_outs: list[dict[str, Any]] = field(default_factory=list)
    network_mode: str = "none"  # none | loopback_only | unrestricted
    allowed_tcp_ports: list[int] = field(default_factory=list)
    set_home: bool = True


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SandboxSetupError(RuntimeError):
    """Raised when the OS sandbox cannot be established and mode is enforce
    without an explicit unconfined opt-out (fail-closed)."""


# ---------------------------------------------------------------------------
# Launcher selection (probe-driven)
# ---------------------------------------------------------------------------


def select_launcher(
    probe_result: dict[str, Any],
    os_sandbox_cfg: dict[str, Any],
) -> Optional[str]:
    """Choose the OS launcher given a probe result and the os_sandbox policy.

    Returns "landrun" | "bwrap" | None.

    Honors an explicit ``launcher`` preference in the policy:
      * "bwrap"   -> bwrap iff usable (userns available + binary present)
      * "landrun" -> landrun iff usable (Landlock ABI>=1 + binary present)
      * "auto"    -> probe-driven priority per launcher-evaluation.md §5:
                       1. userns available AND bwrap present -> bwrap
                       2. Landlock ABI>=1 AND landrun present -> landrun
                       3. None
    "sandbox-exec" is recognized but returns None here (macOS launcher is a
    separate phase; P1-c targets Linux).
    """
    pref = str((os_sandbox_cfg or {}).get("launcher", "auto")).strip() or "auto"

    landlock = probe_result.get("landlock", {}) if isinstance(probe_result, dict) else {}
    userns = probe_result.get("userns", {}) if isinstance(probe_result, dict) else {}
    launchers = probe_result.get("launchers", {}) if isinstance(probe_result, dict) else {}

    landlock_ok = bool(landlock.get("available")) and int(landlock.get("abi_version") or 0) >= 1
    userns_verdict = str(userns.get("verdict", "unknown"))
    # AppArmor-restricted userns is treated as NOT usable for unprivileged
    # namespace launchers (bwrap) — it requires operator AppArmor profile work.
    userns_ok = userns_verdict == "yes"

    bwrap_present = bool(launchers.get("bwrap", {}).get("found"))
    landrun_present = bool(launchers.get("landrun", {}).get("found"))

    bwrap_usable = userns_ok and bwrap_present
    landrun_usable = landlock_ok and landrun_present

    if pref == "bwrap":
        return "bwrap" if bwrap_usable else None
    if pref == "landrun":
        return "landrun" if landrun_usable else None
    if pref == "sandbox-exec":
        # Linux launcher module does not handle macOS Seatbelt.
        return None

    # "auto" (or any unexpected value falls through to auto behavior)
    if bwrap_usable:
        return "bwrap"
    if landrun_usable:
        return "landrun"
    return None


# ---------------------------------------------------------------------------
# Spec construction from policy
# ---------------------------------------------------------------------------


def _resolve_tier_paths(os_sandbox_cfg: dict[str, Any]) -> dict[str, list[str]]:
    """Pull the path sets from the policy's filesystem fields when present,
    otherwise from the carve-out baseline tier constant.

    Policy filesystem fields (read_exec_paths / readable_paths / writable_paths)
    are explicit operator overrides; if they are absent we fall back to the
    structured CARVEOUT_BASELINE keyed by ``tier``.
    """
    cfg = os_sandbox_cfg or {}
    fs = cfg.get("filesystem", {}) if isinstance(cfg.get("filesystem"), dict) else {}
    tier = str(cfg.get("tier", DEFAULT_TIER)).strip() or DEFAULT_TIER
    if tier not in CARVEOUT_BASELINE:
        tier = DEFAULT_TIER
    baseline = CARVEOUT_BASELINE[tier]

    def pick(field_name: str) -> list[str]:
        val = fs.get(field_name)
        if isinstance(val, list) and val:
            return [str(p) for p in val]
        return list(baseline[field_name])

    return {
        "read_exec_paths": pick("read_exec_paths"),
        "readable_paths": pick("readable_paths"),
        "writable_paths": pick("writable_paths"),
    }


def build_spec(
    os_sandbox_cfg: dict[str, Any],
    workspace_root: str,
    socket_path: str,
    agent_argv: list[str],
) -> LauncherSpec:
    """Resolve a LauncherSpec from policy + runtime values. Pure (no I/O)."""
    cfg = os_sandbox_cfg or {}
    tier_paths = _resolve_tier_paths(cfg)
    return LauncherSpec(
        workspace_root=workspace_root,
        bridge_socket_path=socket_path,
        agent_argv=list(agent_argv),
        read_exec_paths=tier_paths["read_exec_paths"],
        readable_paths=tier_paths["readable_paths"],
        writable_paths=tier_paths["writable_paths"],
        credential_carve_outs=list(cfg.get("credential_carve_outs", []) or []),
        network_mode=str(cfg.get("network_mode", "none")).strip() or "none",
        allowed_tcp_ports=[int(p) for p in (cfg.get("allowed_tcp_ports", []) or [])],
    )


# ---------------------------------------------------------------------------
# argv builders — ARGV LISTS ONLY, never a shell string.
# ---------------------------------------------------------------------------


def _assert_safe_agent_argv(agent_argv: list[str]) -> None:
    """The agent command must already be a tokenized argv. We never accept a
    single shell string to interpolate. (A single-element argv is fine — it is
    one program name with no args.)"""
    if not agent_argv:
        raise ValueError("agent_argv must be a non-empty list of tokens")
    for tok in agent_argv:
        if not isinstance(tok, str):
            raise ValueError("agent_argv tokens must be strings")


def build_landrun_argv(spec: LauncherSpec) -> list[str]:
    """Build the ``landrun`` argv (Landlock LSM, no namespaces).

    Flags: --ro (read), --rox (read+exec), --rw (read+write).
    Confines FS to: workspace (rw), baseline read+exec, baseline read-only,
    baseline writable scratch, credential carve-outs, and EXACTLY the one
    bridge socket path (rw). Sets HOME=workspace via --env. Network per
    network_mode (Landlock ABI v4 TCP port rules).
    """
    _assert_safe_agent_argv(spec.agent_argv)
    if not spec.workspace_root:
        raise ValueError("workspace_root is required")
    if not spec.bridge_socket_path:
        raise ValueError("bridge_socket_path is required")

    argv: list[str] = ["landrun"]

    # Workspace: read + write + exec (agent may run tools from its venv).
    argv += ["--rwx", spec.workspace_root]

    # Read + exec baseline.
    for p in spec.read_exec_paths:
        argv += ["--rox", p]

    # Read-only data baseline.
    for p in spec.readable_paths:
        argv += ["--ro", p]

    # Writable scratch (e.g. /tmp).
    for p in spec.writable_paths:
        argv += ["--rw", p]

    # Credential carve-outs (explicit, auditable; default none).
    for entry in spec.credential_carve_outs:
        path = str(entry.get("path", "")).strip()
        if not path:
            continue
        access = str(entry.get("access", "read")).strip()
        argv += (["--rox", path] if access == "read_exec" else ["--ro", path])

    # The ONE carve-in: the bridge socket path, read+write (for connect).
    argv += ["--rw", spec.bridge_socket_path]

    # Network policy (Landlock ABI v4+, port-only).
    if spec.network_mode == "none":
        pass  # no --connect-tcp rules => all TCP blocked
    elif spec.network_mode == "loopback_only":
        for port in spec.allowed_tcp_ports:
            argv += ["--connect-tcp", str(port)]
    elif spec.network_mode == "unrestricted":
        argv += ["--unrestricted-network"]

    # Env: redirect HOME into the workspace; advertise the socket path.
    if spec.set_home:
        argv += ["--env", f"HOME={spec.workspace_root}"]
    argv += ["--env", f"AIRG_SOCKET_PATH={spec.bridge_socket_path}"]

    # Separator + the agent command (already a tokenized argv).
    argv += ["--"]
    argv += spec.agent_argv
    return argv


def build_bwrap_argv(spec: LauncherSpec) -> list[str]:
    """Build the ``bwrap`` (bubblewrap) argv (mount + user/pid/... namespaces).

    Constructs a new root via bind-mounts: read-only binds for the baseline
    read/exec + read-only data, rw bind for the workspace, a private tmpfs at
    /tmp, and EXACTLY one bind for the bridge socket path (rw). Drops network
    via --unshare-net unless loopback is needed. Sets HOME=workspace.
    """
    _assert_safe_agent_argv(spec.agent_argv)
    if not spec.workspace_root:
        raise ValueError("workspace_root is required")
    if not spec.bridge_socket_path:
        raise ValueError("bridge_socket_path is required")

    argv: list[str] = ["bwrap"]

    # Hardening flags (CVE-2017-5226 mitigation; deny-by-default posture).
    argv += ["--unshare-all", "--die-with-parent", "--new-session"]

    # Read-only binds: read+exec baseline + read-only data baseline.
    for p in spec.read_exec_paths:
        argv += ["--ro-bind-try", p, p]
    for p in spec.readable_paths:
        argv += ["--ro-bind-try", p, p]

    # Workspace: read-write bind.
    argv += ["--bind", spec.workspace_root, spec.workspace_root]

    # Writable scratch: a private tmpfs at /tmp (isolated from host /tmp),
    # plus any other writable paths as rw binds.
    for p in spec.writable_paths:
        if p == "/tmp":
            argv += ["--tmpfs", "/tmp"]
        else:
            argv += ["--bind-try", p, p]

    # Credential carve-outs (explicit, auditable; default none).
    for entry in spec.credential_carve_outs:
        path = str(entry.get("path", "")).strip()
        if not path:
            continue
        argv += ["--ro-bind-try", path, path]

    # The ONE carve-in: bind exactly the bridge socket file (single inode), rw.
    argv += ["--bind", spec.bridge_socket_path, spec.bridge_socket_path]

    # Minimal /dev and /proc for a working process tree.
    argv += ["--dev", "/dev", "--proc", "/proc"]

    # Network: --unshare-all already unshared the net namespace (loopback only).
    # For loopback_only we additionally keep loopback up via --unshare-net
    # being already implied; for unrestricted we re-share the host net ns.
    if spec.network_mode == "unrestricted":
        argv += ["--share-net"]
    elif spec.network_mode == "loopback_only":
        pass  # private net ns with loopback (default after --unshare-all)
    else:  # "none"
        argv += ["--unshare-net"]

    # Env: start from a clean env, redirect HOME, advertise the socket path.
    argv += ["--clearenv"]
    if spec.set_home:
        argv += ["--setenv", "HOME", spec.workspace_root]
    argv += ["--setenv", "AIRG_SOCKET_PATH", spec.bridge_socket_path]

    # Separator + the agent command (already a tokenized argv).
    argv += ["--"]
    argv += spec.agent_argv
    return argv


def build_sandbox_argv(launcher: str, spec: LauncherSpec) -> list[str]:
    """Dispatch to the correct argv builder by launcher name."""
    if launcher == "landrun":
        return build_landrun_argv(spec)
    if launcher == "bwrap":
        return build_bwrap_argv(spec)
    raise ValueError(f"unsupported launcher: {launcher!r}")


# ---------------------------------------------------------------------------
# Env hygiene for the launched agent (mirrors executor.safe_subprocess_env)
# ---------------------------------------------------------------------------

_ENV_ALLOWED_EXACT = {
    "LANG",
    "LC_ALL",
    "TERM",
    "TZ",
    "PATH",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
}
_ENV_ALLOWED_PREFIXES = ("AIRG_",)
_ENV_BLOCKED_EXACT = {
    "PYTHONPATH",
    "IFS",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "GIT_SSH_COMMAND",
}


def build_agent_env(
    workspace: str,
    socket_path: str,
    source_env: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Build the launched agent's environment, mirroring executor.py hygiene.

    * Allowlist a small set of safe vars + the AIRG_ prefix.
    * Drop dangerous vars (LD_PRELOAD, PYTHONPATH, *_SSH_COMMAND, etc.).
    * Drop anything that looks like a secret (api_key/token/secret/password).
    * Set HOME=workspace and AIRG_SOCKET_PATH=socket_path.
    """
    source = dict(source_env if source_env is not None else os.environ)
    safe: dict[str, str] = {}
    for key, value in source.items():
        if key in _ENV_BLOCKED_EXACT:
            continue
        if key in _ENV_ALLOWED_EXACT or any(
            key.startswith(prefix) for prefix in _ENV_ALLOWED_PREFIXES
        ):
            safe[key] = value
            continue
        lower = key.lower()
        if any(marker in lower for marker in ("api_key", "token", "secret", "password")):
            continue

    safe["HOME"] = workspace
    safe["AIRG_SOCKET_PATH"] = socket_path
    if "PATH" not in safe:
        safe["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    if "LANG" not in safe:
        safe["LANG"] = "C"
    if "LC_ALL" not in safe:
        safe["LC_ALL"] = safe["LANG"]
    return safe


# ---------------------------------------------------------------------------
# Orchestration — select + build + fail-closed checks.
# exec is kept thin and separate so argv construction is testable without
# spawning anything.
# ---------------------------------------------------------------------------


@dataclass
class LaunchPlan:
    """The result of orchestrating a launch decision (no process spawned)."""

    mode: str  # off | monitor | enforce
    launcher: Optional[str]  # landrun | bwrap | None
    sandbox_argv: list[str]  # full argv to exec (sandbox-wrapped or bare agent)
    env: dict[str, str]
    confined: bool  # True if a real sandbox wrapper is in place
    unconfined_optout: bool  # True if running unconfined via explicit opt-out
    decision_log: list[str]  # human-readable decision trail


def establish_and_launch(
    os_sandbox_cfg: dict[str, Any],
    probe_result: dict[str, Any],
    workspace_root: str,
    socket_path: str,
    agent_argv: list[str],
    *,
    source_env: Optional[dict[str, str]] = None,
    logger: Any = None,
) -> LaunchPlan:
    """Decide and BUILD the wrapped command (does not spawn).

    Behavior by mode:
      * off       -> run the agent bare (no OS confinement). MCP layer guards.
      * monitor   -> attempt selection; log what would be confined; run bare
                     (observation only — does not actually confine).
      * enforce   -> select launcher; if none:
                       on_setup_failure == fail_closed (default) -> RAISE.
                       on_setup_failure == warn_and_run_unconfined -> log a
                       prominent warning and run bare (explicit opt-out).

    Returns a LaunchPlan. The caller execs ``plan.sandbox_argv`` with
    ``plan.env`` via :func:`exec_plan` (kept thin + separate).
    """
    cfg = os_sandbox_cfg or {}
    mode = str(cfg.get("mode", "off")).strip() or "off"
    on_setup_failure = str(cfg.get("on_setup_failure", "fail_closed")).strip() or "fail_closed"

    log: list[str] = []

    def _log(msg: str) -> None:
        log.append(msg)
        if logger is not None:
            try:
                logger(msg)
            except Exception:
                pass

    env = build_agent_env(workspace_root, socket_path, source_env=source_env)

    if mode == "off":
        _log("os_sandbox mode=off: launching agent without OS confinement.")
        return LaunchPlan(
            mode=mode,
            launcher=None,
            sandbox_argv=list(agent_argv),
            env=env,
            confined=False,
            unconfined_optout=False,
            decision_log=log,
        )

    launcher = select_launcher(probe_result, cfg)

    if mode == "monitor":
        if launcher:
            _log(
                f"os_sandbox mode=monitor: launcher '{launcher}' would confine "
                "the agent; running UNCONFINED for observation."
            )
        else:
            _log(
                "os_sandbox mode=monitor: no usable launcher detected; "
                "running unconfined (observation only)."
            )
        return LaunchPlan(
            mode=mode,
            launcher=launcher,
            sandbox_argv=list(agent_argv),
            env=env,
            confined=False,
            unconfined_optout=False,
            decision_log=log,
        )

    # mode == "enforce" (any other value already rejected by config validation)
    if launcher is None:
        if on_setup_failure == "warn_and_run_unconfined":
            _log(
                "[WARN] os_sandbox mode=enforce but no usable launcher found "
                "(no Landlock/landrun, no userns/bwrap). on_setup_failure="
                "warn_and_run_unconfined: launching UNCONFINED by explicit "
                "operator opt-out. The agent is NOT OS-confined."
            )
            return LaunchPlan(
                mode=mode,
                launcher=None,
                sandbox_argv=list(agent_argv),
                env=env,
                confined=False,
                unconfined_optout=True,
                decision_log=log,
            )
        _log(
            "[ERROR] os_sandbox mode=enforce but no usable launcher found "
            "(no Landlock/landrun, no unprivileged userns/bwrap). "
            "on_setup_failure=fail_closed: refusing to launch."
        )
        raise SandboxSetupError(
            "OS sandbox required (mode=enforce) but no usable launcher is "
            "available on this host (no Landlock+landrun, no userns+bwrap). "
            "Refusing to launch (fail-closed). Set os_sandbox.on_setup_failure "
            "to 'warn_and_run_unconfined' to run without OS confinement."
        )

    spec = build_spec(cfg, workspace_root, socket_path, agent_argv)
    sandbox_argv = build_sandbox_argv(launcher, spec)
    _log(
        f"os_sandbox mode=enforce: confining agent with '{launcher}'. "
        f"workspace(rw)={workspace_root}; socket carve-in(rw)={socket_path}; "
        f"network_mode={spec.network_mode}."
    )
    return LaunchPlan(
        mode=mode,
        launcher=launcher,
        sandbox_argv=sandbox_argv,
        env=env,
        confined=True,
        unconfined_optout=False,
        decision_log=log,
    )


def exec_plan(plan: LaunchPlan) -> None:  # pragma: no cover - process replacement
    """Replace the current process with the planned (sandbox-wrapped) command.

    Kept deliberately thin and separate from argv construction so the latter is
    unit-testable without spawning anything.
    """
    os.execvpe(plan.sandbox_argv[0], plan.sandbox_argv, plan.env)


def describe_plan(plan: LaunchPlan) -> str:
    """Render a copy-pasteable, shell-safe representation of the planned argv
    (for logging / dry-run). NEVER used to actually run the command — exec uses
    the argv list directly."""
    return shlex.join(plan.sandbox_argv)
