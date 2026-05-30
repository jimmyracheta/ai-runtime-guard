"""
airg_sandbox_probe.py — AIRG Sandbox Capability Probe

Usage:
    python3 scripts/airg_sandbox_probe.py          # human-readable summary
    python3 scripts/airg_sandbox_probe.py --json   # machine-readable JSON

Purpose:
    Detect and report facts about the host's sandbox capabilities so that
    AIRG can determine which OS-level launcher (landrun, bwrap, nsjail, etc.)
    is viable on this machine.

IMPORTANT — READ-ONLY / NON-MUTATING:
    This script performs NO enforcement, NO mutations, NO network calls, and
    has NO side effects.  It only reads /proc entries, calls a single
    read-only syscall (landlock_create_ruleset with the VERSION flag), and
    runs --version sub-processes on existing binaries.  It is safe to run
    on any host at any time.

Python: 3.10+  |  stdlib only (no third-party imports required).
Runs cleanly on Linux and macOS.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import errno
import json
import os
import platform
import shutil
import subprocess
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Landlock syscall number is 444 on all asm-generic architectures (x86_64,
# aarch64, riscv64, …).  This covers the two arches AIRG targets on Linux.
_LANDLOCK_SYSCALL_NR: dict[str, int] = {
    "x86_64": 444,
    "aarch64": 444,
    "arm64": 444,  # macOS /uname reports arm64 for Apple Silicon
}

# Flag that tells the kernel to return its supported ABI version rather than
# actually creating a ruleset.
_LANDLOCK_CREATE_RULESET_VERSION: int = 1 << 0  # == 1

# Launcher binaries to probe.
_LAUNCHERS: list[str] = ["bwrap", "nsjail", "landrun", "firejail", "minijail0"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_read(path: str) -> str | None:
    """Read a text file; return None on any error (file absent, permission…)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


def _run_version(binary: str) -> str | None:
    """Run <binary> --version and return stdout+stderr; None on any error."""
    try:
        result = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        out = (result.stdout + result.stderr).strip()
        return out if out else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 1) Platform / OS / architecture
# ---------------------------------------------------------------------------


def probe_platform() -> dict[str, Any]:
    info: dict[str, Any] = {
        "system": platform.system(),          # "Linux" | "Darwin" | …
        "machine": platform.machine(),        # "x86_64" | "arm64" | "aarch64"
        "python_version": platform.python_version(),
    }

    try:
        un = os.uname()
        info["uname"] = {
            "sysname": un.sysname,
            "nodename": un.nodename,
            "release": un.release,
            "version": un.version,
            "machine": un.machine,
        }
    except Exception as exc:
        info["uname_error"] = str(exc)

    if platform.system() == "Darwin":
        # sw_vers is macOS-only; gives ProductName, ProductVersion, BuildVersion.
        for key, flag in [
            ("macos_product_name", "-productName"),
            ("macos_product_version", "-productVersion"),
            ("macos_build_version", "-buildVersion"),
        ]:
            try:
                result = subprocess.run(
                    ["sw_vers", flag],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                info[key] = result.stdout.strip()
            except Exception:
                info[key] = None

    return info


# ---------------------------------------------------------------------------
# 2) Linux — Landlock ABI version
# ---------------------------------------------------------------------------


def probe_landlock() -> dict[str, Any]:
    """Return Landlock ABI version (int ≥ 1) or None/error info."""
    result: dict[str, Any] = {
        "available": False,
        "abi_version": None,
        "note": None,
    }

    if platform.system() != "Linux":
        result["note"] = "Not Linux — Landlock not applicable."
        return result

    arch = platform.machine()
    syscall_nr = _LANDLOCK_SYSCALL_NR.get(arch)
    if syscall_nr is None:
        result["note"] = f"Unknown arch '{arch}' — cannot map Landlock syscall number."
        return result

    # Load libc for the syscall() wrapper.
    libc_name = ctypes.util.find_library("c")
    try:
        libc = ctypes.CDLL(libc_name, use_errno=True)
    except Exception as exc:
        result["note"] = f"Could not load libc: {exc}"
        return result

    # syscall(NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
    # Returns the ABI version integer, or -1 with errno set.
    try:
        ret = libc.syscall(
            ctypes.c_long(syscall_nr),   # syscall number
            ctypes.c_void_p(0),           # attr = NULL
            ctypes.c_size_t(0),           # size = 0
            ctypes.c_uint(
                _LANDLOCK_CREATE_RULESET_VERSION
            ),                            # flags = VERSION flag
        )
    except Exception as exc:
        result["note"] = f"syscall() raised: {exc}"
        return result

    if ret >= 1:
        result["available"] = True
        result["abi_version"] = int(ret)
        # Informational: ABI v1=kernel 5.13, v2=5.19, v3=6.2, v4=6.7 (net rules)
        abi_map = {
            1: "≥5.13 (filesystem rules)",
            2: "≥5.19 (file truncation)",
            3: "≥6.2 (ioctl_dev)",
            4: "≥6.7 (TCP connect/bind by port)",
            5: "≥6.10 (abstract Unix sockets)",
        }
        result["abi_meaning"] = abi_map.get(int(ret), f"ABI v{ret} (newer than known map)")
        result["note"] = f"Landlock ABI v{ret} supported."
    else:
        # errno ENOSYS (38) = syscall not available; EOPNOTSUPP (95) = disabled.
        err = ctypes.get_errno()
        result["errno"] = err
        result["errno_name"] = errno.errorcode.get(err, f"E{err}")
        if err == errno.ENOSYS:
            result["note"] = "ENOSYS — kernel does not support Landlock."
        elif err == 95:  # EOPNOTSUPP
            result["note"] = "EOPNOTSUPP — Landlock compiled out or disabled."
        else:
            result["note"] = f"syscall returned {ret}, errno={err} ({errno.errorcode.get(err, '?')})."

    return result


# ---------------------------------------------------------------------------
# 3) Linux — unprivileged user-namespace availability
# ---------------------------------------------------------------------------


def probe_userns() -> dict[str, Any]:
    """Best-effort read-only check for unprivileged user-namespace availability."""
    result: dict[str, Any] = {
        "verdict": None,   # "yes" | "no" | "unknown"
        "evidence": {},
    }

    if platform.system() != "Linux":
        result["verdict"] = "not_applicable"
        result["evidence"]["note"] = "Not Linux."
        return result

    ev = result["evidence"]

    # /proc/sys/kernel/unprivileged_userns_clone  (Debian/Ubuntu kernel patch)
    v = _safe_read("/proc/sys/kernel/unprivileged_userns_clone")
    ev["unprivileged_userns_clone"] = v
    if v is not None:
        # "1" = allowed, "0" = disabled.
        if v == "0":
            result["verdict"] = "no"
        elif v == "1":
            result["verdict"] = "yes"

    # /proc/sys/user/max_user_namespaces  (standard, all distros)
    m = _safe_read("/proc/sys/user/max_user_namespaces")
    ev["max_user_namespaces"] = m
    if m is not None and result["verdict"] is None:
        try:
            result["verdict"] = "no" if int(m) == 0 else "yes"
        except ValueError:
            pass

    # AppArmor userns restriction (Ubuntu 23.10+, SUSE):
    #   /proc/sys/kernel/apparmor_restrict_unprivileged_userns
    aa = _safe_read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    ev["apparmor_restrict_unprivileged_userns"] = aa
    if aa == "1" and result["verdict"] == "yes":
        result["verdict"] = "yes_but_apparmor_restricted"
        ev["apparmor_note"] = (
            "AppArmor restricts userns — bwrap/nsjail may work only if the "
            "calling process has a permissive AppArmor profile."
        )

    if result["verdict"] is None:
        result["verdict"] = "unknown"
        ev["note"] = (
            "Could not read /proc/sys/kernel/unprivileged_userns_clone or "
            "/proc/sys/user/max_user_namespaces — verdict is unknown."
        )

    return result


# ---------------------------------------------------------------------------
# 4) Launcher binaries
# ---------------------------------------------------------------------------


def probe_launchers() -> dict[str, dict[str, Any]]:
    launchers: dict[str, dict[str, Any]] = {}
    for name in _LAUNCHERS:
        path = shutil.which(name)
        entry: dict[str, Any] = {"found": path is not None, "path": path}
        if path:
            entry["version_output"] = _run_version(path)
        launchers[name] = entry
    return launchers


# ---------------------------------------------------------------------------
# 5) macOS — sandbox-exec presence
# ---------------------------------------------------------------------------


def probe_sandbox_exec() -> dict[str, Any]:
    if platform.system() != "Darwin":
        return {"applicable": False}
    path = shutil.which("sandbox-exec")
    return {
        "applicable": True,
        "found": path is not None,
        "path": path,
        "note": (
            "sandbox-exec uses Seatbelt (macOS kernel); officially deprecated "
            "by Apple but still functional through macOS 15."
        ),
    }


# ---------------------------------------------------------------------------
# 6) seccomp availability (Linux)
# ---------------------------------------------------------------------------


def probe_seccomp() -> dict[str, Any]:
    result: dict[str, Any] = {"available": None, "evidence": {}}

    if platform.system() != "Linux":
        result["available"] = False
        result["evidence"]["note"] = "Not Linux — seccomp not applicable."
        return result

    ev = result["evidence"]

    # /proc/sys/kernel/seccomp  (not universally present, but common)
    v = _safe_read("/proc/sys/kernel/seccomp")
    ev["proc_sys_kernel_seccomp"] = v
    if v is not None:
        # "2" = filter mode available; "1" = strict only; "0" = off
        try:
            result["available"] = int(v) >= 1
        except ValueError:
            pass

    # /proc/self/status contains "Seccomp:" line showing current mode
    status = _safe_read("/proc/self/status")
    if status:
        for line in status.splitlines():
            if line.startswith("Seccomp:"):
                ev["self_seccomp_mode"] = line.split(":", 1)[1].strip()
                break

    if result["available"] is None:
        # Fallback: check if prctl is available (it is on any modern kernel),
        # but we can only report "unknown" without actually calling prctl(SECCOMP).
        result["available"] = "unknown"
        ev["note"] = (
            "/proc/sys/kernel/seccomp not readable; presence inferred from "
            "kernel version only (not checked here)."
        )

    return result


# ---------------------------------------------------------------------------
# Recommendation hint
# ---------------------------------------------------------------------------


def build_recommendation(
    plat: dict,
    landlock: dict,
    userns: dict,
    launchers: dict,
    seccomp: dict,
) -> str:
    lines: list[str] = []
    system = plat.get("system", "")

    if system == "Linux":
        ll_ok = landlock.get("available", False)
        ll_ver = landlock.get("abi_version")
        us = userns.get("verdict", "unknown")
        userns_ok = us in ("yes", "yes_but_apparmor_restricted")
        userns_restricted = us == "yes_but_apparmor_restricted"

        # landrun / Landlock-native path
        if ll_ok:
            landrun_found = launchers.get("landrun", {}).get("found", False)
            if landrun_found:
                lines.append(
                    f"landrun (Landlock ABI v{ll_ver}): VIABLE — binary present and kernel supports Landlock."
                )
            else:
                lines.append(
                    f"landrun: Landlock ABI v{ll_ver} supported but landrun binary not found (install it)."
                )
            if ll_ver and ll_ver >= 4:
                lines.append(
                    "  Landlock v4+ present: TCP port-level network confinement also available."
                )
        else:
            lines.append(
                "landrun/Landlock: NOT viable — kernel does not support Landlock "
                f"({landlock.get('note', 'see landlock section')})."
            )

        # namespace-based launchers (bwrap, nsjail)
        for name in ("bwrap", "nsjail"):
            found = launchers.get(name, {}).get("found", False)
            if userns_ok and not userns_restricted:
                verdict = "VIABLE" if found else f"userns OK but {name} binary not found"
            elif userns_restricted:
                verdict = (
                    f"MAY work if AppArmor profile allows — {name} "
                    + ("binary present" if found else "binary NOT found")
                )
            else:
                verdict = (
                    f"UNLIKELY — unprivileged userns is disabled or unknown "
                    f"(verdict={us})"
                )
            lines.append(f"{name}: {verdict}.")

        # minijail0 (can use Landlock or seccomp, not necessarily userns)
        mj = launchers.get("minijail0", {})
        if mj.get("found"):
            lines.append(
                "minijail0: binary present — can use Landlock rules if available."
            )

        # seccomp
        sc = seccomp.get("available")
        if sc is True:
            lines.append("seccomp: available — seccomp-filter confinement viable.")
        elif sc == "unknown":
            lines.append("seccomp: availability unknown (could not read /proc/sys/kernel/seccomp).")
        else:
            lines.append("seccomp: NOT detected.")

        if not ll_ok and not userns_ok:
            lines.append(
                "WARNING: Neither Landlock nor unprivileged userns detected. "
                "All mainstream sandbox launchers may be unavailable on this host. "
                "AIRG sandbox must fail-closed unless a privileged helper is provided."
            )

    elif system == "Darwin":
        se = launchers  # unused here; check sandbox-exec separately via plat
        lines.append(
            "macOS host: sandbox-exec (Seatbelt) is the primary option. "
            "Check sandbox_exec section for binary presence."
        )
        # bwrap on macOS via homebrew — rare but possible
        bwrap = launchers.get("bwrap", {})
        if bwrap.get("found"):
            lines.append("bwrap: found (unusual on macOS; may work via homebrew).")
        else:
            lines.append("bwrap/nsjail/landrun: not applicable on macOS without Linux kernel.")
    else:
        lines.append(f"Platform '{system}': no launcher recommendation available.")

    return "\n".join(lines) if lines else "No recommendation could be derived."


# ---------------------------------------------------------------------------
# Main probe entry point
# ---------------------------------------------------------------------------


def run_probe() -> dict[str, Any]:
    plat = probe_platform()
    landlock = probe_landlock()
    userns = probe_userns()
    launchers = probe_launchers()
    sandbox_exec = probe_sandbox_exec()
    seccomp = probe_seccomp()
    recommendation = build_recommendation(plat, landlock, userns, launchers, seccomp)

    return {
        "platform": plat,
        "landlock": landlock,
        "userns": userns,
        "launchers": launchers,
        "sandbox_exec": sandbox_exec,
        "seccomp": seccomp,
        "recommendation": recommendation,
    }


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


def print_human(data: dict[str, Any]) -> None:
    sep = "-" * 60

    plat = data["platform"]
    print(sep)
    print("AIRG Sandbox Capability Probe")
    print(sep)
    print(f"System   : {plat.get('system')} / {plat.get('machine')}")
    un = plat.get("uname", {})
    if un:
        print(f"Kernel   : {un.get('release', '?')} {un.get('version', '')[:60]}")
    if "macos_product_version" in plat:
        print(
            f"macOS    : {plat.get('macos_product_name')} "
            f"{plat.get('macos_product_version')} "
            f"(build {plat.get('macos_build_version')})"
        )
    print(f"Python   : {plat.get('python_version')}")

    # Landlock
    print()
    print(sep)
    print("Landlock (Linux only)")
    print(sep)
    ll = data["landlock"]
    print(f"Available  : {ll.get('available')}")
    if ll.get("abi_version") is not None:
        print(f"ABI version: v{ll['abi_version']}  ({ll.get('abi_meaning', '')})")
    print(f"Note       : {ll.get('note', '')}")

    # User namespaces
    print()
    print(sep)
    print("Unprivileged User Namespaces (Linux only)")
    print(sep)
    us = data["userns"]
    print(f"Verdict  : {us.get('verdict')}")
    for k, v in (us.get("evidence") or {}).items():
        print(f"  {k}: {v}")

    # Seccomp
    print()
    print(sep)
    print("seccomp (Linux only)")
    print(sep)
    sc = data["seccomp"]
    print(f"Available : {sc.get('available')}")
    for k, v in (sc.get("evidence") or {}).items():
        print(f"  {k}: {v}")

    # Launchers
    print()
    print(sep)
    print("Launcher binaries")
    print(sep)
    for name, info in data["launchers"].items():
        found_str = "FOUND" if info.get("found") else "not found"
        path_str = f"  ({info.get('path')})" if info.get("path") else ""
        ver = info.get("version_output", "")
        ver_short = (ver or "")[:80].split("\n")[0]
        print(f"  {name:<12} {found_str}{path_str}")
        if ver_short:
            print(f"              version: {ver_short}")

    # sandbox-exec (macOS)
    se = data["sandbox_exec"]
    if se.get("applicable"):
        print()
        print(sep)
        print("sandbox-exec / Seatbelt (macOS only)")
        print(sep)
        found_str = "FOUND" if se.get("found") else "not found"
        print(f"  sandbox-exec : {found_str}  ({se.get('path')})")
        print(f"  Note         : {se.get('note', '')}")

    # Recommendation
    print()
    print(sep)
    print("Usable launcher options given this host")
    print(sep)
    for line in data["recommendation"].splitlines():
        print(f"  {line}")
    print()


def print_json(data: dict[str, Any]) -> None:
    print(json.dumps(data, indent=2, default=str))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AIRG sandbox capability probe — read-only host detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "This tool is non-mutating. It reads /proc entries, probes one\n"
            "read-only syscall, and runs --version on any found binaries."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON instead of human summary.",
    )
    args = parser.parse_args()

    data = run_probe()
    if args.json:
        print_json(data)
    else:
        print_human(data)


if __name__ == "__main__":
    main()
