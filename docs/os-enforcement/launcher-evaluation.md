# Linux Launcher Evaluation Matrix

**Task:** T2 — inform the still-open decision of which existing Linux launcher AIRG should wrap.
**Design source of truth:** `AGENT_CONTEXT.md §13`, especially §13.3, §13.4, §13.5, §13.11.
**Produced:** 2026-05-30 by general-purpose agent (Claude Sonnet 4.6).

---

## 1. Context and Framing

AIRG's OS-enforcement goal (§13.2) is to add a kernel-enforced spatial wall around the agent process
so that even native (non-MCP-routed) tools and agent-spawned subprocesses are contained. The launcher
wraps the agent command; AIRG runs **outside** the sandbox communicating over a single AF\_UNIX socket
(Topology A, §13.4).

Key deployment facts that constrain the choice (§13.3, §13.5):

1. **Target hosts are often hardened server / CI machines** where `kernel.unprivileged_userns_clone=0`
   and/or Ubuntu 23.10+ AppArmor restricts unprivileged user namespaces. This breaks every
   namespace-based launcher operating without root.
2. **No root / no setuid** is the target operating model for pip-distributed software.
3. The sandbox must allow exactly one AF\_UNIX socket path into it (the AIRG bridge socket), and
   deny everything else by default.
4. Network containment is desired but TCP-port-only filtering is acceptable for an MVP; domain
   filtering stays at the AIRG MCP policy layer.

---

## 2. Comparison Matrix

| Criterion | **bubblewrap (bwrap)** | **nsjail** | **landrun** | **minijail (minijail0)** |
|---|---|---|---|---|
| **Primary confinement mechanism** | Mount + user + PID/IPC/UTS/net namespaces; optional seccomp | Mount + user + PID/IPC/net/cgroup/time namespaces; seccomp-BPF (Kafel); rlimits | Landlock LSM (filesystem path rules + TCP port rules); no namespaces | Landlock LSM + all 7 Linux namespaces + seccomp-BPF; chroot/pivot_root |
| **Landlock used?** | No | No | Yes (primary mechanism) | Yes (one of several layers) |
| **Minimum kernel (FS rules)** | ~3.8 (user ns); practically 4.x+ | ~4.x (cgroup v2 ≥4.6) | **5.13** (Landlock ABI v1) | **5.13** (Landlock ABI v1, for LL mode); ns-only mode: ~4.x |
| **Minimum kernel (net rules)** | Any (own net ns) | Any (own net ns) | **6.4** (Landlock ABI v4, TCP) | **6.4** (Landlock ABI v4, TCP, if used) |
| **Requires unprivileged user namespaces?** | **YES — hard requirement** (setuid mode removed as of ~0.8+) | **YES for unprivileged use** (`--disable_clone_newuser` needs root) | **No** — Landlock + `no_new_privs`; no namespaces needed | Namespace features need userns OR root; Landlock-only sub-mode may work with `no_new_privs` only (unverified — see §7) |
| **Requires root?** | No (if userns available) | No (if userns available); yes if userns disabled | **No** | No (if userns or Landlock-only path used) |
| **Works on hardened/CI hosts with userns=0?** | **No** | **No** | **Yes** | Partially (Landlock sub-path; see caveats) |
| **FS confinement model** | Bind-mount whole dirs/files into new mount ns; flexible allow-list via `--bind`, `--ro-bind`, `--tmpfs` | Similar bind-mount model into new mount ns; chroot or pivot_root | Path-allow-list rules: `--ro`, `--rox`, `--rw`, `--rwx` per path/dir | Bind-mount (`-b`) + Landlock path flags (`--fs-path-ro`, `--fs-path-rw`, `--fs-path-advanced-rw`, `--fs-default-paths`) |
| **AF\_UNIX socket carve-out** | Yes — `--bind /path/to/airg.sock /path/to/airg.sock` binds the socket file into the mount ns | Yes — bind-mount of socket path into mount ns | **Unverified** (see §7.1) — filesystem path `--rw /path/to/airg.sock` should expose the inode; Landlock ABI v9 adds explicit pathname Unix socket scope, but not clear landrun implements it | Yes — `-b /path/to/airg.sock` bind-mount if using namespace mode; Landlock path flag if LL mode |
| **Network containment** | Full net namespace isolation (loopback only by default) | Full net namespace isolation; MACVLAN; pasta | TCP bind/connect by port (Landlock ABI v4, kernel ≥6.4); no UDP; no domain filtering | Net namespace (`-e`) OR Landlock TCP rules (ABI v4) |
| **Seccomp support** | Yes (via `--seccomp-fd` / filter files) | Yes — first-class, Kafel DSL | No (Landlock only; no seccomp support in landrun itself) | Yes — first-class (mode 1 basic; mode 13 policy file) |
| **Packaging: apt/dnf** | **apt install bubblewrap** (Ubuntu/Debian); **dnf install bubblewrap** (Fedora/RHEL) — in main repos | **Build from source** (deps: protobuf, libnl-route; no official apt/dnf package; Debian Security Team packaging WIP since 2020) | **go install** or AUR (Arch); **no apt/dnf package** | **Build from source** (ChromeOS/Android origin; no official Debian/Ubuntu/Fedora package; RFP bug open since 2017) |
| **License** | LGPLv2+ | Apache-2.0 | MIT | BSD-3-Clause |
| **Maturity / audit track record** | High — ships in Flatpak; powers Codex CLI sandbox; broad ecosystem exposure; CVE-2017-5226 (TIOCSTI, fixed with `--new-session`) and CVE-2020-5291 (setuid privilege escalation, fixed by removing setuid) | Medium-high — Google-maintained; used in AOSP; no published CVEs found; C++ codebase with complex namespace/proto logic | Low — young project (v0.1.14, Apr 2025); ~2.1k GitHub stars; no formal security audit found | Medium — Google-maintained; used heavily in ChromeOS/Android; no published CVEs found; C codebase; BSD-3 |
| **Maintenance status (as of 2026-05)** | **Active** — v0.11.2 released Apr 2026; 25 releases; containers org | **Active** — v3.6 released Mar 2026; 1,399 commits; ongoing | **Active but early-stage** — v0.1.14 Apr 2025; 8 releases; single primary maintainer | **Actively maintained upstream** (ChromeOS); GitHub releases stalled at v18 (May 2023); upstream commits continue via Chromium Gerrit |
| **AIRG "wrap a launcher" fit (Topology A)** | Good — proven pattern (Codex CLI uses it); ergonomic bind-mount model | Good — feature-rich but complex config (protobuf/config file or long CLI flags) | **Best fit for userns-disabled hosts** — CLI wraps any command, no privileges needed; carve-out model simpler | Good fit if namespaces available; Landlock-only path needs verification; packaging burden |
| **Suitability summary** | Best choice **if** userns available; poor on hardened/CI hosts | Strong **if** userns available + seccomp needed; same userns blocker | **Primary choice when userns disabled**; younger, no seccomp | Viable hybrid; significant packaging burden |

---

## 3. Per-Launcher Prose

### 3.1 bubblewrap (bwrap)

**Mechanism.** bwrap creates a new mount namespace (always) plus optional user, PID, IPC, UTS, and net
namespaces. Filesystem isolation is achieved by constructing a new root via bind-mounts:
`--ro-bind /usr /usr`, `--bind /workspace /workspace`, etc. Seccomp is supported via a passed fd
(`--seccomp 3 3</filter`). There is no Landlock involvement.

**Kernel and privilege requirements.** bwrap requires unprivileged user namespaces
(`CONFIG_USER_NS=y` and `kernel.unprivileged_userns_clone=1`). The historical setuid fallback was
removed (as of ~v0.8). On Ubuntu 23.10+ (`apparmor_restrict_unprivileged_userns=1`) bwrap fails
unless either: (a) an AppArmor profile allowlisting bwrap is installed, or (b) the restriction is
disabled. Hardened kernels (Arch `linux-hardened`, Debian hardened configs) that set
`unprivileged_userns_clone=0` **break bwrap entirely without root**.
[Source: containers/bubblewrap GitHub; Ubuntu 23.10 AppArmor announcement; ArchWiki Bubblewrap]

**FS confinement ergonomics.** Very ergonomic: `--ro-bind /usr /usr --ro-bind /lib /lib
--bind /workspace /workspace --tmpfs /tmp`. Whole directories can be exposed read-only with one flag.
AF\_UNIX socket carve-out is straightforward: `--bind /run/airg/airg.sock /run/airg/airg.sock`
binds the socket file into the sandbox.

**Network.** `--unshare-net` gives a private net namespace with loopback only. Fine-grained
TCP-port rules are not natively supported; block-all is the correct default here.

**Maturity and CVEs.** High maturity — Flatpak, Codex CLI, and Claude Code sandbox all use bwrap.
CVE-2017-5226: TIOCSTI injection attack; mitigated with `--new-session` (now documented as
required). CVE-2020-5291: privilege escalation via setuid mode; resolved by setuid removal.
No known unpatched CVEs as of 2026-05.
[Source: GitHub security advisories; bubblewrap changelog]

**Packaging.** `apt install bubblewrap` (Debian/Ubuntu); `dnf install bubblewrap` (Fedora/RHEL).
LGPLv2+ license.

**AIRG fit.** Excellent — proven "wrap a launcher" pattern. The primary concern is the userns
dependency. An `airg_sandbox_probe.py` check (T1 deliverable) already detects userns availability;
bwrap should only be selected if the probe confirms userns is available and not AppArmor-restricted.

---

### 3.2 nsjail

**Mechanism.** nsjail uses all 7 Linux namespace types (user, mount, PID, IPC, UTS, net, cgroup)
plus optional time namespace (kernel ≥5.3), chroot/pivot\_root, rlimits, and seccomp-BPF via the
Kafel DSL. Configuration is via a protobuf config file or an extensive CLI. There is no Landlock
involvement.
[Source: google/nsjail GitHub; nsjail.dev]

**Kernel and privilege requirements.** Like bwrap, nsjail depends on CLONE\_NEWUSER for
unprivileged use. Running `--disable_clone_newuser` removes that dependency but requires root or
CAP\_SYS\_ADMIN. Therefore nsjail has the **same userns-disabled blocker as bwrap** on hardened
hosts.

**FS confinement ergonomics.** Bind-mount model, similar expressiveness to bwrap. Kafel-based
seccomp policy is a notable advantage for hardening beyond filesystem/network bounds.

**Network.** Excellent: net namespace isolation, MACVLAN, pasta/slirp4netns for userland networking.
For AIRG's use case (block all egress except AIRG socket) this is more than sufficient.
AF\_UNIX socket carve-out: bind-mount of the socket path.

**Maturity.** Used in AOSP build system; Google-maintained. No published CVEs found (as of research
date). The Ubuntu 24.04 AppArmor restriction broke AOSP's use of nsjail in CI (bug 2063976 on
Launchpad), demonstrating exactly the userns-on-hardened-host breakage risk.
[Source: Launchpad bug 2063976; Makson Lee blog; nsjail.dev]

**Packaging.** Must build from source. Build dependencies: `autoconf bison flex gcc g++
libprotobuf-dev libnl-route-3-dev libtool make pkg-config protobuf-compiler`. A Debian Security
Team packaging effort exists on Salsa (6 commits, last active ~2020) but has not produced an
official package. No apt/dnf package. Apache-2.0 license.

**AIRG fit.** The Kafel seccomp DSL is attractive for a later hardening phase, and the tool is
actively maintained. However: (1) same userns blocker as bwrap; (2) no apt package increases
install friction; (3) protobuf config is heavier to drive programmatically from Python. Suitable as
an **optional advanced-hardening profile** for hosts where userns is available and seccomp tightening
is wanted, not as the primary launcher for broad deployment.

---

### 3.3 landrun

**Mechanism.** landrun is a Go CLI tool (v0.1.14, Apr 2025) that invokes the Landlock LSM directly —
no namespaces. It calls `landlock_create_ruleset`, `landlock_add_rule`, and
`landlock_restrict_self` syscalls (with `prctl(PR_SET_NO_NEW_PRIVS,1)` required by the kernel for
unprivileged callers) to confine the target process.
[Source: github.com/Zouuup/landrun; kernel.org Landlock docs]

**Kernel and privilege requirements.**
- Filesystem rules: kernel ≥5.13 (Landlock ABI v1). Progressively richer at v2 (5.19, REFER),
  v3 (6.2, TRUNCATE), v5 (6.10, IOCTL\_DEV).
- TCP port rules: kernel ≥6.4 (ABI v4). Network restriction claims "kernel 6.7+" in landrun README
  but ABI v4 shipped in 6.4; exact minimum should be verified on target kernels.
- **No user namespaces, no root, no setuid.** Works wherever the kernel has Landlock enabled
  (CONFIG\_SECURITY\_LANDLOCK=y), which is the default in mainline since 5.13.
[Source: docs.kernel.org/userspace-api/landlock.html; landrun README]

**FS confinement ergonomics.** CLI flags: `--ro /path`, `--rox /path`, `--rw /path`, `--rwx /path`.
Each flag can be given multiple times. There is no "bind-mount whole /usr ro" shorthand — every
directory to be allowed must be explicitly listed. This makes carve-out configuration more verbose
than bwrap but more precise. The `--fs-default-paths` approach used by minijail is not present in
landrun; AIRG would need to build its own "standard allow-set" (system libs, interpreters, workspace)
as a policy section.

**AF\_UNIX socket carve-out.** A pathname AF\_UNIX socket is a filesystem inode; `--rw
/run/airg/airg.sock` should expose it to the sandboxed process for read+write (connect). However:
  - Landlock filesystem rules control `open()` but not `connect()` on a socket already in scope.
  - Landlock ABI v6 (kernel 6.12) introduced `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` (abstract
    sockets) and ABI v9 (upcoming) adds pathname Unix socket scope. As of ABI v1-v5, pathname
    sockets reachable via the allowed filesystem path **should** be connectable.
  - landrun has not been verified to explicitly test the socket-carve-out use case; see §7.1.

**Network.** TCP only (ABI v4+, kernel ≥6.4). Flags: `--bind-tcp <port>`, `--connect-tcp <port>`.
No UDP. No domain filtering (same limitation as all Landlock-based tools). With no TCP flags, all
TCP is blocked. For AIRG Topology A (AIRG socket is a pathname socket, not TCP), network can be
fully blocked while socket bridge remains accessible via the filesystem path rule.

**Seccomp.** Not provided by landrun itself. If seccomp is wanted, a separate layer (kernel
seccomp-notify or a different launcher) would be needed.

**Maturity and security track record.** Young project: first HN post March 2025; v0.1.14 is the
latest release (April 2025, 8 releases). ~2,156 GitHub stars. No formal security audit found. Single
primary maintainer. The underlying Landlock LSM is kernel-maintained and well-audited; landrun is a
thin Go wrapper around it. The main risk is tool immaturity: edge cases in the Go binding, absence
of CI coverage on diverse kernels, no distro-level security review.

**Packaging.** `go install github.com/zouuup/landrun/cmd/landrun@latest`. Binary releases available
on GitHub. Arch Linux AUR package exists. No apt/dnf package. MIT license.

**AIRG fit.** Best match for the userns-disabled deployment target. `landrun -- codex ...` is the
closest to the "wrap a launcher" model with zero privilege escalation and no namespace dependency.
The immaturity and absence of apt packaging are the primary concerns. Suitability improves if AIRG
ships a pre-built static landrun binary as part of its installer (one binary, permissive MIT
license), bypassing the distro packaging gap.

---

### 3.4 minijail (minijail0)

**Mechanism.** minijail is a multi-layer sandbox tool from Google (ChromeOS/Android origin). It
supports all 7 Linux namespace types, seccomp-BPF with a policy-file DSL, chroot/pivot\_root, rlimits,
capability bounding, AND Landlock filesystem rules. Landlock support was added via `--fs-path-ro`,
`--fs-path-rw`, `--fs-path-advanced-rw`, and `--fs-default-paths` flags.
[Source: google.github.io/minijail/minijail0.1.html; chromium.org sandboxing guide]

**Kernel and privilege requirements.** Minijail's Landlock flags require kernel ≥5.13. The
ChromeOS guide notes that using Landlock requires either `no_new_privs` (set by minijail
automatically with `-n`) or certain namespace conditions. **Critically:** whether minijail's Landlock
path works *without* any namespace (userns disabled, non-root) is not clearly documented in public
sources. The most likely behavior is: with `-n` (no\_new\_privs) and only Landlock flags (no `-v`,
`-p`, `-U`), minijail should be able to sandbox without namespaces — but this has not been verified
externally. When namespace flags are used, userns dependency re-emerges.
[Source: docs.kernel.org Landlock; minijail LWN article; §7.2 open question]

**FS confinement ergonomics.** Two-mode operation:
  - Namespace mode: bind-mount via `-b src:dst[:writable]`, chroot via `-C`, pivot\_root via `-P`.
    Similar ergonomics to bwrap.
  - Landlock mode: `--fs-path-ro /path`, `--fs-path-rw /path`, `--fs-default-paths` (baseline
    system libs). More explicit than bwrap, similar to landrun but with a convenient baseline flag.
AF\_UNIX socket: bind-mount in namespace mode; filesystem path rule in Landlock mode.

**Network.** `-e` flag creates a new net namespace (namespace mode). Landlock TCP rules apply if
using Landlock mode with kernel ≥6.4.

**Seccomp.** First-class: `-s` (strict mode) or `-S policy_file` (DSL, Kafel-compatible).
Strongest seccomp tooling of the four candidates.

**Maturity.** High — deployed in ChromeOS and Android at scale. BSD-3-Clause license (permissive).
No published CVEs found. Last GitHub-tagged release: v18 (May 2023); ongoing commits flow through
the Chromium Gerrit mirror and are reflected in the GitHub main branch. The upstream-only release
cadence means version tracking is awkward for external consumers.

**Packaging.** Not in apt or dnf official repos (Debian RFP open since 2017, bug #860067; no
progress). AUR package exists for Arch. Must build from source on Debian/Ubuntu/Fedora. Build
is straightforward (C + standard make), but adds a compile step to the install workflow.

**AIRG fit.** If the no-namespace Landlock path works without root (§7.2), minijail would offer
the best of both worlds: Landlock-based containment on userns-disabled hosts PLUS seccomp. However,
the packaging gap is a real barrier for pip-installed AIRG, and the "does Landlock-only work without
userns?" question needs an explicit test before relying on it. Suitable as a long-term target for
hardened deployments that build from source; not suitable as the default out-of-box launcher.

---

## 4. Firejail Exclusion Note

Firejail is not evaluated here. As documented in §13.3: firejail's historical setuid-root model
makes it a poor fit for a security product — setuid binaries have historically been a significant
source of local privilege escalation. Firejail has had multiple CVEs stemming from its setuid
design. The replacement spirit of landrun is "firejail-for-Landlock, minus the setuid attack
surface."

---

## 5. Conditional Recommendation

> **The decision is the operator's; the below frames conditions, not a final pick.**

```
IF target hosts have unprivileged user namespaces enabled (userns = 1, no AppArmor restriction):
  → Use bubblewrap (bwrap) as primary launcher.
     Rationale: mature, audited, apt-installable, proven "wrap a launcher" model, broad ecosystem
     support (Flatpak, Codex CLI, Claude Code). Bind-mount AF_UNIX socket for AIRG bridge.
     Add nsjail as an optional profile when Kafel seccomp is wanted.

IF target hosts have userns disabled or AppArmor-restricted (hardened servers, many CI hosts):
  → Use landrun as primary launcher.
     Rationale: only candidate with zero privilege requirement and no namespace dependency.
     Landlock ABI v1+ (kernel ≥5.13) handles filesystem containment; TCP rules available on ≥6.4.
     Package via pre-built static binary bundled with AIRG (MIT license allows it) to bypass apt gap.
     Verify AF_UNIX socket carve-out path (see §7.1) before shipping.

RECOMMENDED RUNTIME SELECTION:
  The probe script (T1, scripts/airg_sandbox_probe.py) already detects:
    - Landlock ABI version (→ what landrun can enforce)
    - unprivileged_userns_clone value
    - AppArmor userns restriction
    - bwrap / landrun presence
  Selection logic should be:
    1. If probe says userns=available AND bwrap present → bwrap
    2. Else if probe says Landlock ABI ≥1 AND landrun present → landrun
    3. Else → refuse to start in enforce mode (fail closed, §13.5.5)
  This drives the §13.8 P0 spike: implement the probe-driven selector in the airg-exec entrypoint.

MINIJAIL: defer — attractive for seccomp depth, but packaging gap and unverified no-namespace
Landlock path make it unsuitable as a default. Revisit for P2/advanced hardening profile.

NSJAIL: defer — same userns blocker as bwrap; heavier config; no apt package. Consider only for
environments that already have nsjail deployed (e.g., AOSP-based CI).
```

---

## 6. Landlock ABI Quick-Reference (for probe-driven feature gating)

| ABI | Kernel | Feature |
|-----|--------|---------|
| 1 | 5.13 | Basic FS rules (read/write/exec/make\_\*) |
| 2 | 5.19 | REFER (cross-dir file reparenting) |
| 3 | 6.2 | TRUNCATE |
| 4 | 6.4 | TCP bind + TCP connect by port |
| 5 | 6.10 | IOCTL\_DEV (device ioctl restriction) |
| 6 | 6.12 | IPC scoping: abstract UNIX socket + signal isolation |
| 7 | TBD (6.15+) | Audit logging control |
| 8 | TBD | RESTRICT\_SELF\_TSYNC (multithreaded enforcement) |
| 9 | TBD | Pathname UNIX socket scope |

AIRG MVP requires at minimum ABI v1 (kernel ≥5.13). TCP port containment requires ABI v4 (≥6.4).
The AF\_UNIX bridge socket does not require ABI v6/v9 — a pathname socket reachable via an allowed
filesystem path should be accessible under ABI v1+ (connect operates on an already-opened fd or
path).

[Sources: docs.kernel.org/userspace-api/landlock.html; man7.org/linux/man-pages/man7/landlock.7.html;
landlock.io/news/5/]

---

## 7. Open Questions / Unverified Claims

### 7.1 landrun AF\_UNIX socket carve-out — UNVERIFIED

**Claim:** `landrun --rw /run/airg/airg.sock -- <agent>` exposes the socket file, and the agent
process can `connect()` to it.

**Why uncertain:** Landlock v1-v5 FS rules govern file `open()` access rights, not `connect()`.
The socket is a special file; Landlock's MAKE\_SOCK right (ABI v1) governs socket *creation*, not
*connection*. A pathname Unix socket connect resolves the path and then calls `connect(2)` on the fd.
Whether an `--rw` rule covering the socket path allows `connect()` without ABI v9's explicit
pathname-socket scope bit has not been confirmed in landrun's documentation or issues.

**How to resolve:** Run `landrun --rw /tmp/test.sock -- socat - UNIX-CONNECT:/tmp/test.sock` on a
kernel with ABI v1–v5 and observe whether the connect succeeds. This should be part of the P0 spike.

### 7.2 minijail Landlock-only mode without user namespaces — UNVERIFIED

**Claim:** `minijail0 -n --fs-path-ro /usr --fs-path-rw /workspace -- <agent>` (no `-v`, `-p`,
`-U`) applies a Landlock policy without entering any namespace, and works as non-root on a host
where `unprivileged_userns_clone=0`.

**Why uncertain:** minijail's man page and ChromeOS docs do not explicitly document this combination.
The kernel requirement for `landlock_restrict_self` is `no_new_privs OR CAP_SYS_ADMIN`; minijail
sets `no_new_privs` with `-n`. But whether minijail internally uses any namespace even when no
namespace flags are passed is not confirmed from public docs.

**How to resolve:** Run `minijail0 -n --fs-path-ro /usr -- ls /etc` on a hardened host with
userns=0 and check for permission errors. Build minijail from source required.

### 7.3 landrun TCP ABI threshold — minor ambiguity

The landrun README states "kernel 6.7 or later for network restrictions" but kernel docs place ABI v4
(TCP rules) at kernel 6.4. The discrepancy may reflect a landrun implementation choice to require
ABI v5 (6.10) or a documentation error. Verify by checking which ABI landrun negotiates at runtime
on a 6.4 kernel.

### 7.4 nsjail on Ubuntu 24.04 without AppArmor profile — documented but worth tracking

Ubuntu 24.04 broke AOSP's nsjail-based build in CI (Launchpad bug 2063976) due to the AppArmor
userns restriction. A workaround exists (add an AppArmor profile for nsjail), but this requires
sysadmin intervention — contrary to the "no-setup-beyond-pip" deployment goal. Track whether
Ubuntu ships a standard AppArmor profile for nsjail in future releases.

### 7.5 bubblewrap license ambiguity

GitHub repository metadata listed license as "Unknown" in fetched content, but the codebase and
canonical references consistently state LGPLv2+. Verify by reading the `COPYING` file in the repo.
This is likely a metadata issue only, not a real ambiguity.

---

## 8. References

- [containers/bubblewrap GitHub](https://github.com/containers/bubblewrap)
- [Zouuup/landrun GitHub](https://github.com/Zouuup/landrun)
- [google/nsjail GitHub](https://github.com/google/nsjail)
- [google/minijail GitHub](https://github.com/google/minijail)
- [Landlock kernel docs — unprivileged access control](https://docs.kernel.org/userspace-api/landlock.html)
- [landlock(7) man page](https://man7.org/linux/man-pages/man7/landlock.7.html)
- [ChromeOS Sandboxing Guide — minijail Landlock flags](https://www.chromium.org/chromium-os/developer-library/guides/development/sandboxing/)
- [minijail0(1) man page](https://google.github.io/minijail/minijail0.1.html)
- [Landrun: Sandbox any Linux process (HN discussion)](https://news.ycombinator.com/item?id=43445662)
- [Ubuntu 23.10 restricted unprivileged user namespaces announcement](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces)
- [Launchpad bug 2063976 — AppArmor breaking nsjail in AOSP on Ubuntu 24.04](https://bugs.launchpad.net/ubuntu/+source/apparmor/+bug/2063976)
- [bubblewrap CVE-2020-5291 advisory](https://github.com/containers/bubblewrap/security/advisories/GHSA-j2qp-rvxj-43vj)
- [Landlock scoping for Unix sockets — Phoronix](https://www.phoronix.com/news/Landlock-Scoping-Unix-Sockets)
- [Debian RFP for minijail — bug #860067](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=860067)
- [nsjail.dev](https://nsjail.dev/)
- [ArchWiki Bubblewrap](https://wiki.archlinux.org/title/Bubblewrap)
