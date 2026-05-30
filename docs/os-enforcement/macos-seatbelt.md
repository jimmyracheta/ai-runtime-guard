# AIRG macOS Seatbelt / sandbox-exec Design

**Task:** T6 — macOS Seatbelt / `sandbox-exec` approach for OS-level spatial confinement.
**Design source of truth:** `AGENT_CONTEXT.md §13`, especially §13.1 #1, §13.5 #8, §13.5 #2,
§13.5 #5, §13.8 (P3 macOS phasing).
**Cross-references:**
- `docs/os-enforcement/sandbox-policy-schema.md` — the `os_sandbox` schema this maps onto.
- `docs/os-enforcement/carveout-baseline.md §6` — macOS path deltas this profile instantiates.
- `docs/os-enforcement/transport-bridge-design.md` — AF_UNIX bridge socket that must be reachable
  from inside the profile.
**Produced:** 2026-05-30 by general-purpose agent (Claude Sonnet 4.6).

---

## 1. Mechanism Overview

### 1.1 What `sandbox-exec` Is

`sandbox-exec(1)` is a macOS userspace command-line tool that applies an Apple Seatbelt policy to
a target process tree. The policy is written in the **Sandbox Profile Language** (SBPL), a Scheme-
like TinyScheme-based DSL that specifies which OS operations the confined process and all its
descendants may perform.

Invocation form:

```sh
sandbox-exec -f /path/to/profile.sb -D WORKSPACE_ROOT=/the/workspace -D SOCKET_PATH=/path/to/airg.sock -- codex
```

- `-f profile.sb` — load the policy from a file.
- `-D KEY=VALUE` — bind a named parameter that the profile can read via `(param "KEY")`.
- `--` — everything after is the confined command, including all its arguments.

The Seatbelt policy is applied **before** the target process's first instruction executes. All child
processes, grandchildren, and threads inherit the same policy. There is no opt-out once the profile
is applied; the confinement is kernel-enforced via macOS's TrustedBSD Mandatory Access Control
(MAC) framework.

### 1.2 Mapping to the "Wrap a Launcher" Shape

This is the exact same pattern used on Linux:

| Layer | Linux | macOS |
|---|---|---|
| Launcher command | `landrun --path-ro /usr … -- codex` | `sandbox-exec -f profile.sb -D … -- codex` |
| Policy expression | Landlock ABI v1–v9 path/network rules | SBPL `(allow ...)` / `(deny ...)` rules |
| Scope of confinement | Agent + all descendants | Agent + all descendants (inherited) |
| Who sits outside | AIRG server process | AIRG server process |
| Communication channel | AF_UNIX socket (one allowed path) | AF_UNIX socket (one `(literal ...)` rule) |
| Packaging | `landrun` binary (external dep) | `sandbox-exec` (preinstalled, zero dep) |

AIRG's launcher logic on macOS:

1. Resolves `AIRG_WORKSPACE` and `AIRG_SOCKET_PATH` from the environment or policy.json.
2. Renders the `.sb` profile template (see §3) by substituting `(param "WORKSPACE_ROOT")` and
   `(param "SOCKET_PATH")` via the `-D` flag.
3. Executes `sandbox-exec -f <rendered_profile> -D WORKSPACE_ROOT=<ws> -D SOCKET_PATH=<sock>
   -- airg-mcp-shim` (or directly the agent if no bridge shim is needed on this topology variant).
4. The AIRG server runs **outside** the sandbox, listening on the AF_UNIX socket, operating on all
   state files (approvals.db, hmac.key, activity.log, policy.json, backups/) that the confined
   agent process cannot reach.

This satisfies **Topology A** (AGENT_CONTEXT.md §13.4) identically to the Linux path.

### 1.3 Profile Compilation: Fatal-on-Error Alignment

SBPL is compiled by the kernel at sandbox-exec time. A syntax error or invalid rule terminates
`sandbox-exec` before the target process starts. This is **fail-closed by construction** — a
malformed profile never produces a silently-unconfined agent. This matches the `on_setup_failure:
"fail_closed"` default in the `os_sandbox` schema (sandbox-policy-schema.md §2.1.8).

---

## 2. Deprecation Reality

### 2.1 Deprecation Status

`sandbox-exec(1)` is officially marked as deprecated in Apple's man page. The macOS 15 (Sequoia)
deprecation warning is emitted to stderr on every invocation:

```
WARNING: sandbox-exec is deprecated and may be removed in a future release.
```

The SBPL language itself carries the same deprecation flag — Apple has not published a specification
and it is undocumented in public developer documentation.

### 2.2 Who Uses It Anyway

Despite the deprecation label, `sandbox-exec` / SBPL are actively used by production-quality
software as of 2026:

| User | Evidence |
|---|---|
| Chromium renderer sandbox | `chromium/src/sandbox/mac/seatbelt_exec.cc`; V2 sandbox design doc updated 2025-01-30; used for all process types except GPU |
| OpenAI Codex CLI | `codex-rs/core/src/seatbelt_base_policy.sbpl` + `restricted_read_only_platform_defaults.sbpl`; actively maintained (Java support fix merged 2026) |
| Google Gemini CLI | `MacOsSandboxManager` with six built-in profiles; Seatbelt sandboxing for subagents added in v0.36.0 (April 2026) |
| Bazel build system | Uses `sandbox-exec` for hermetic build sandboxing on macOS |
| Nix | Uses Seatbelt profiles for derivation sandboxing on macOS |
| agent-seatbelt (community) | Open-source wrapper for Claude Code and Codex using Codex's base `.sbpl` policies |

The pattern is widespread enough that Apple removing it without a replacement would break a large
fraction of macOS developer tooling simultaneously.

### 2.3 The Replacement Gap

Apple's `apple/containerization` framework (announced at WWDC 2025, v0.9.0 as of Feb 2026) runs
OCI-compatible Linux containers via Apple's Virtualization framework. It is **not** a replacement
for `sandbox-exec` for native macOS process sandboxing:

- Requires macOS 15+ and Apple Silicon.
- Creates a full Linux VM (lightweight but still a VM).
- Does not sandbox native macOS Mach-O processes directly.
- Much heavier overhead than `sandbox-exec` for a CLI agent wrapper.

There is no currently available public C API or tool that provides the same deny-by-default
per-operation policy for a native macOS child process without App Sandbox entitlements (which
require code signing and are designed for GUI App Store apps, not headless CLI processes).

An open issue in the apple/containerization repo explicitly requests Apple clarify the replacement
path for non-App-Store process sandboxing — as of May 2026, no response.

### 2.4 Risk Verdict and Mitigation

**Risk:** Apple could remove `sandbox-exec` in a future macOS major release (macOS 26 / 27) without
a direct CLI process sandboxing replacement.

**Mitigation:**

1. **Consistent with the defense-in-depth framing** (AGENT_CONTEXT.md §13.1 #3): the macOS
   Seatbelt layer is a best-effort second wall, not the primary security claim. If it is removed
   by Apple, the MCP policy layer (all existing AIRG policy sections) continues to operate.
2. **Deprecation warning suppression:** the AIRG launcher can redirect stderr from `sandbox-exec`
   or suppress the deprecation line without suppressing actual errors by filtering on the warning
   string — keeping the UX clean.
3. **Monitor Apple containerization** for a native CLI process sandboxing primitive. When a
   supported API appears, the launcher abstraction (single launcher-specific code path) means
   migration is self-contained.
4. **Pin macOS version ranges** in `airg-doctor` output, noting tested-and-known-working macOS
   versions. If a future macOS removes `sandbox-exec`, `airg-doctor` should detect absence and
   fall back per `on_setup_failure`.
5. **Treat macOS as P3** (AGENT_CONTEXT.md §13.8): Linux is P1 (Landlock/bwrap, stable kernel
   API), macOS is P3 (best-effort, higher deprecation risk, worth shipping but not the primary
   delivery gate).

---

## 3. Annotated Profile Skeleton

The following is an annotated `.sb` profile template suitable for a confined Codex/Claude agent on
macOS. Parameters `WORKSPACE_ROOT` and `SOCKET_PATH` are injected at launch time via `-D`.

```scheme
;;; AIRG macOS Seatbelt profile — deny-by-default spatial confinement
;;; Version: 1 (required for all Seatbelt profiles using SBPL)
;;; Rendered at launch time by the AIRG launcher; (param ...) placeholders are
;;; substituted with -D WORKSPACE_ROOT=... -D SOCKET_PATH=... flags to sandbox-exec.
;;;
;;; SBPL key operations used in this file:
;;;   file-read*              — all file read operations (data, metadata, xattrs, ...)
;;;   file-read-data          — read file content (narrower than file-read*)
;;;   file-read-metadata      — stat, lstat, readdir, getxattr (narrower than file-read*)
;;;   file-write*             — all file write operations (data, create, delete, ...)
;;;   file-map-executable     — mmap with PROT_EXEC (required for shared libraries / dylibs)
;;;   process-exec*           — exec() a new process (required to launch subprocesses)
;;;   process-fork            — fork() (required for any child process creation)
;;;   signal (target same-sandbox) — send signals within the sandboxed process group
;;;   network-outbound        — TCP/UDP connect outbound
;;;   ipc-posix-shm*          — POSIX shared memory (required by some Obj-C runtimes)
;;;   mach-*                  — Mach IPC (required for system services, logging, etc.)
;;;
;;; (subpath "/foo")   — matches /foo and any path below it (recursive)
;;; (literal "/foo")   — matches exactly the path /foo (not children)
;;; (regex "^/foo/.*") — matches paths matching the POSIX ERE

(version 1)

;;; ---------------------------------------------------------------------------
;;; STEP 1: Deny everything by default.
;;; This is the foundation of deny-by-default confinement. Without this the
;;; profile would be permissive-by-default (allow unless denied), which is
;;; exactly backwards for security use. All rules below ADD specific allowances.
;;; ---------------------------------------------------------------------------
(deny default)

;;; ---------------------------------------------------------------------------
;;; STEP 2: Process creation — the agent must be able to spawn children.
;;; Without process-exec* and process-fork, no subprocesses run at all.
;;; signal (target same-sandbox) is required for job control (SIGCHLD, SIGTERM)
;;; within the confined process group.
;;; ---------------------------------------------------------------------------
(allow process-exec*)
(allow process-fork)
(allow signal (target same-sandbox))

;;; ---------------------------------------------------------------------------
;;; STEP 3: System toolchain and shared library read + exec.
;;; The macOS dynamic linker (dyld) and all system dylibs must be readable AND
;;; executable (file-map-executable). On macOS, most dylibs are served from the
;;; dyld shared cache at /System/Library/dyld/ — the kernel maps this directly
;;; without a normal vnode permission check, so no explicit rule is needed for
;;; the cache file itself. Individual framework paths below do require rules.
;;; ---------------------------------------------------------------------------

;;; System dylibs — /usr/lib is the canonical user-facing dylib location.
;;; Covers libSystem.dylib, libssl.dylib, libz.dylib, etc.
(allow file-read* file-map-executable
  (subpath "/usr/lib"))

;;; System frameworks (AppKit, Foundation, CoreFoundation, etc.).
;;; file-map-executable is required to dlopen framework dylibs.
(allow file-read* file-map-executable
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks"))

;;; Apple Silicon additional firmware-level frameworks and dylibs.
(allow file-read* file-map-executable
  (subpath "/Library/Apple/System/Library/Frameworks")
  (subpath "/Library/Apple/usr/lib"))

;;; System executables — read-only (not file-map-executable because executables
;;; are loaded via process-exec*, not mmap'd directly in most cases).
;;; /usr/bin: shell, git, python3, curl, make, etc.
;;; /usr/sbin, /usr/libexec: system admin tools and helper binaries.
;;; /bin, /sbin: symlinks to /usr/bin, /usr/sbin on macOS 10.15+; allow for compat.
(allow file-read-data file-read-metadata
  (subpath "/usr/bin")
  (subpath "/usr/sbin")
  (subpath "/usr/libexec")
  (subpath "/bin")
  (subpath "/sbin"))

;;; Homebrew — Apple Silicon installs to /opt/homebrew; Intel to /usr/local.
;;; Homebrew binaries need both read+exec for the dylibs they link against.
(allow file-read* file-map-executable
  (subpath "/opt/homebrew/lib")
  (subpath "/usr/local/lib"))
(allow file-read-data file-read-metadata
  (subpath "/opt/homebrew/bin")
  (subpath "/opt/homebrew/Cellar")
  (subpath "/opt/homebrew/opt")
  (subpath "/opt/homebrew/share")
  (subpath "/usr/local/bin"))

;;; ---------------------------------------------------------------------------
;;; STEP 4: Read-only system data paths (T5 macOS carve-out baseline).
;;; These are paths the toolchain reads at runtime but must not write to.
;;; ---------------------------------------------------------------------------

;;; TLS CA bundle — required for TLS cert verification by curl, git, pip, npm.
;;; macOS CA bundle lives in the Security.framework Keychain, but many CLI tools
;;; fall back to these paths. Allow both canonical and symlink forms.
(allow file-read*
  (subpath "/private/etc/ssl")
  (subpath "/etc/ssl"))

;;; Resolver and hosts — required for any DNS resolution.
(allow file-read*
  (literal "/private/etc/resolv.conf")
  (literal "/etc/resolv.conf")
  (literal "/private/etc/hosts")
  (literal "/etc/hosts"))

;;; User/group database — UID/GID lookups, ls -l, git, Python os.getpwuid().
(allow file-read*
  (literal "/private/etc/passwd")
  (literal "/etc/passwd")
  (literal "/private/etc/master.passwd")
  (literal "/private/etc/group")
  (literal "/etc/group"))

;;; Timezone data — required for correct timestamp handling.
(allow file-read*
  (subpath "/private/var/db/timezone")
  (subpath "/private/etc/localtime")
  (subpath "/usr/share/zoneinfo"))

;;; Locale and character encoding data.
(allow file-read*
  (subpath "/usr/share/locale")
  (subpath "/usr/share/i18n"))

;;; System git config — git reads this on every invocation.
(allow file-read*
  (literal "/private/etc/gitconfig")
  (literal "/etc/gitconfig"))

;;; Library Preferences — some tools (Python, Ruby) read system preferences.
(allow file-read*
  (subpath "/Library/Preferences"))

;;; Seatbelt itself needs to read its own policy compilation artifacts.
;;; Also needed for Obj-C runtime initialization.
(allow file-read*
  (subpath "/usr/share"))

;;; ---------------------------------------------------------------------------
;;; STEP 5: Writable scratch — private temp.
;;; macOS /tmp is a symlink to /private/tmp. Allow both forms.
;;; Compilers (clang, gcc via Homebrew), pip, npm, and language runtimes all
;;; write temp files here. Unlike Linux bwrap --tmpfs, sandbox-exec does not
;;; create a private tmpfs — this grants write access to the host /tmp.
;;; Two mitigation options: (a) accept it, relying on TMPDIR isolation; or
;;; (b) pre-create a per-session temp dir and use TMPDIR env override — see §7.
;;; ---------------------------------------------------------------------------
(allow file-read* file-write*
  (subpath "/private/tmp")
  (subpath "/tmp")
  (subpath "/private/var/tmp")
  (subpath "/var/tmp"))

;;; ---------------------------------------------------------------------------
;;; STEP 6: Workspace root — READ + WRITE.
;;; This is the agent's working area: the only place it can create, modify,
;;; and delete files. (param "WORKSPACE_ROOT") is substituted at launch with the
;;; resolved AIRG_WORKSPACE path (e.g. /Users/user/projects/myproject).
;;; ---------------------------------------------------------------------------
(allow file-read* file-write*
  (subpath (param "WORKSPACE_ROOT")))

;;; ---------------------------------------------------------------------------
;;; STEP 7: AF_UNIX bridge socket — THE critical carve-out.
;;; The in-sandbox shim (airg-mcp-shim) must be able to connect() to the AF_UNIX
;;; socket on which the AIRG server listens outside the sandbox (Topology A,
;;; transport-bridge-design.md). This is the ONLY path that crosses the sandbox
;;; boundary for MCP communication.
;;;
;;; In Seatbelt, AF_UNIX socket access is modeled as a file operation
;;; (the socket inode must be readable/writable). The network-outbound operation
;;; with (local ...) covers the connect(2) syscall itself.
;;;
;;; (param "SOCKET_PATH") is substituted at launch with the resolved path, e.g.:
;;;   /Users/user/.local/share/airg/sockets/codex-proj-web.sock
;;;
;;; Use (literal ...) not (subpath ...) to allow exactly one socket path, not
;;; the entire socket directory.
;;; ---------------------------------------------------------------------------
(allow file-read* file-write*
  (literal (param "SOCKET_PATH")))

;;; The connect(2) syscall for AF_UNIX is represented as network-outbound with
;;; a (local ...) qualifier in SBPL. Without this rule, connect() to the socket
;;; is denied even if the inode is accessible.
(allow network-outbound
  (local unix-socket (path (param "SOCKET_PATH"))))

;;; ---------------------------------------------------------------------------
;;; STEP 8: Mach IPC — required for system services.
;;; Many macOS system services communicate over Mach IPC. These minimal allows
;;; are required for basic operation (logging, shared memory, OS services).
;;; The specific service names below are derived from Codex's seatbelt_base_policy
;;; and are the minimal set needed for a headless CLI agent.
;;; ---------------------------------------------------------------------------
(allow ipc-posix-shm*)
(allow mach-lookup
  (global-name "com.apple.logd")
  (global-name "com.apple.system.logger")
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.cfprefsd.daemon")
  (global-name "com.apple.distributed_notifications@Uv3")
  (global-name "com.apple.lsd.mapdb"))

;;; ---------------------------------------------------------------------------
;;; STEP 9: PTY and device access.
;;; Interactive shells and terminal-aware tools (vim, less, ncurses) need access
;;; to the controlling TTY. Allow access to the agent's own TTY device.
;;; /dev/null, /dev/urandom, /dev/random are used by virtually every process.
;;; ---------------------------------------------------------------------------
(allow file-read* file-write*
  (literal "/dev/null")
  (literal "/dev/zero")
  (literal "/dev/random")
  (literal "/dev/urandom")
  (literal "/dev/stdin")
  (literal "/dev/stdout")
  (literal "/dev/stderr"))
(allow file-read* file-write* file-ioctl*
  (subpath "/dev/pts")
  (subpath "/dev/ttys"))

;;; Pseudo-terminal allocation (required for interactive shells inside sandbox).
(allow pseudo-tty)

;;; ---------------------------------------------------------------------------
;;; END OF PROFILE
;;; Anything not explicitly allowed above is denied by the (deny default) at the
;;; top. If the agent or a tool fails with a Seatbelt denial, the denial is
;;; logged to /var/log/system.log (search for "deny" + process name).
;;; To diagnose: run with AIRG os_sandbox.mode = "monitor" first (see §6 of
;;; carveout-baseline.md §8 for the monitor-mode workflow).
;;; ---------------------------------------------------------------------------
```

### 3.1 Parameter Injection at Launch

The AIRG macOS launcher renders the profile by passing `-D` flags to `sandbox-exec`. Parameters
inside the profile are read with `(param "KEY")`. This is the correct templating mechanism — SBPL
`(param ...)` is evaluated at profile-compile time (inside the kernel), so the resulting compiled
policy is specific to the workspace and socket path for this agent session.

Example launcher invocation (pseudocode):

```python
import subprocess, shutil, os

def launch_with_seatbelt(workspace_root: str, socket_path: str,
                          profile_path: str, agent_argv: list[str]) -> subprocess.Popen:
    if not shutil.which("sandbox-exec"):
        raise RuntimeError("sandbox-exec not found — macOS Seatbelt unavailable")
    cmd = [
        "sandbox-exec",
        "-f", profile_path,
        "-D", f"WORKSPACE_ROOT={workspace_root}",
        "-D", f"SOCKET_PATH={socket_path}",
        "--",
        *agent_argv,          # e.g. ["airg-mcp-shim"] or ["codex", "--model", "..."]
    ]
    env = os.environ.copy()
    env["HOME"] = workspace_root           # redirect ~/  paths into workspace
    env["TMPDIR"] = "/tmp"                 # predictable temp dir (see §7)
    return subprocess.Popen(cmd, env=env)
```

The profile file is either stored as a package resource (e.g.,
`src/airg_launcher/macos/airg_base.sb`) or rendered to a tempfile per session.

---

## 4. Mapping the `os_sandbox` Schema Fields to SBPL Constructs

This section maps each field of the `os_sandbox` schema
(`docs/os-enforcement/sandbox-policy-schema.md §2`) to its SBPL equivalent.

### 4.1 `filesystem.workspace_root` → `(allow file-read* file-write* (subpath (param "WORKSPACE_ROOT")))`

The workspace root is the primary read-write region. Inject via `-D WORKSPACE_ROOT=<path>` and
consume with `(param "WORKSPACE_ROOT")`. Using `(subpath ...)` makes it recursive.

### 4.2 `filesystem.readable_paths` → `(allow file-read* (subpath "..."))`

Each entry in `readable_paths` maps to one `(allow file-read* (subpath "/path"))` rule. For paths
that should match only a specific file (not a directory tree), use `(literal "/exact/path")`.

On macOS, note the private/real-path duality: `/etc/` is a symlink to `/private/etc/`. Allow both
forms unless you are certain the path is resolved before rule application (Seatbelt evaluates rules
against the resolved vnode path, but many tools open via the symlink form). Safer: allow both.

### 4.3 `filesystem.read_exec_paths` → `(allow file-read* file-map-executable (subpath "..."))`

On macOS, "execute" at the OS level means two distinct operations:
- `process-exec*` — for loading a new process image (`execve`). Covered globally by the
  `(allow process-exec*)` rule in §3.
- `file-map-executable` — for `mmap()` with `PROT_EXEC` — i.e., loading shared libraries (dylibs,
  `.so` files). This must be allowed per path for every dylib directory.

So `read_exec_paths` entries become `(allow file-read* file-map-executable (subpath "/path"))`.
The distinction between "executable binary" (needs `process-exec*`) and "shared library"
(needs `file-map-executable`) does not exist in the schema — the launcher must emit both.

### 4.4 `filesystem.writable_paths` → `(allow file-read* file-write* (subpath "..."))`

Each `writable_paths` entry (default: `["/tmp"]`) maps to `(allow file-read* file-write* (subpath
"/path"))`. On macOS `/tmp` → `/private/tmp`; allow both forms.

### 4.5 `filesystem.bridge_socket_path` → `(allow file-read* file-write* (literal ...)) + (allow network-outbound (local unix-socket (path ...)))`

This is the bridge socket carve-out from §3 Step 7. Two rules are required:
1. The inode must be accessible: `(allow file-read* file-write* (literal (param "SOCKET_PATH")))`.
2. The `connect(2)` syscall to an AF_UNIX socket requires: `(allow network-outbound (local
   unix-socket (path (param "SOCKET_PATH"))))`.

Landlock handles this differently: a Landlock `LANDLOCK_ACCESS_FS_READ_FILE | WRITE_FILE` rule on
the socket inode covers the `connect(2)` path. In Seatbelt, the inode rule and the `network-outbound
(local ...)` rule are separate — both are necessary.

### 4.6 `network_mode` → SBPL network rules

| Schema `network_mode` | SBPL equivalent |
|---|---|
| `"none"` | No `(allow network-outbound ...)` rules except the bridge socket `(local unix-socket ...)`. Effectively: outbound TCP/UDP is blocked; only AF_UNIX to the one socket path is allowed. |
| `"loopback_only"` | `(allow network-outbound (remote ip "localhost:*"))` — allows TCP/UDP to 127.0.0.1 on any port. More expressive than Landlock (which is port-only). |
| `"unrestricted"` | `(allow network-outbound)` — no network restriction. |

Note: unlike Landlock, Seatbelt can filter by remote IP address AND port, not just port. This is
**MORE expressive** than Landlock's port-only network rules. AIRG's schema defines port-only
semantics (`allowed_tcp_ports` as an array of integers) because Landlock is the lowest common
denominator. The macOS launcher can implement the same port rules AND optionally add address-level
filtering — both are expressible in SBPL. This is a **macOS advantage** not currently exploited by
the schema.

### 4.7 `allowed_tcp_ports` → `(allow network-outbound (remote tcp "127.0.0.1:<port>"))` per port

Each integer in `allowed_tcp_ports` maps to:
```scheme
(allow network-outbound
  (remote tcp "*:<port>"))
```
Replace `<port>` with the integer. The `"*"` allows the connection to any remote IP on that port.
For loopback-only, use `(remote tcp "127.0.0.1:<port>")`.

### 4.8 `credential_carve_outs` → `(allow file-read* (literal ...))`

Each `credential_carve_outs` entry with `"access": "read"` becomes:
```scheme
(allow file-read* (literal "/the/credential/path"))
```
With `"access": "read_exec"`:
```scheme
(allow file-read* file-map-executable (literal "/the/credential/path"))
```
Use `(literal ...)` not `(subpath ...)` to keep the allow as narrow as possible.

### 4.9 Expressiveness Comparison: Seatbelt vs Landlock

| Capability | Seatbelt (macOS) | Landlock (Linux) |
|---|---|---|
| Filesystem: path-based allow by operation | Yes — per operation type (`file-read*`, `file-write*`, `file-map-executable`, ...) | Yes — per access right (`LANDLOCK_ACCESS_FS_READ_FILE`, `WRITE_FILE`, `EXECUTE`, ...) |
| Filesystem: recursive (subpath) | Yes — `(subpath "/foo")` | Yes — rules apply to directories recursively |
| Filesystem: exact literal path | Yes — `(literal "/foo")` | Yes — can target individual inodes |
| Filesystem: regex patterns | Yes — `(regex "^/foo/.*")` | No |
| Network: by port only | Yes — `(remote tcp "*:<port>")` | Yes — Landlock ABI v4+ (kernel ≥6.4) |
| Network: by remote IP address | Yes — `(remote ip "1.2.3.4:443")` | No |
| Network: AF_UNIX sockets | Yes — `(local unix-socket (path "..."))` | Landlock ABI v1 treats AF_UNIX as FS inode (read/write on socket file); ABI-version-dependent |
| Mach IPC filtering | Yes — `(mach-lookup (global-name "..."))` | No Linux equivalent |
| Signal filtering | Yes — `(signal (target same-sandbox))` | No |
| Operations: `file-map-executable` distinct from read | Yes (important for dylibs) | No distinct exec-map right; EXECUTE covers both |
| Temporal scope | Applied once, inherited; cannot be relaxed | Applied once, inherited; cannot be relaxed |
| Requires kernel support | TrustedBSD MAC (always on in macOS) | Landlock LSM (kernel ≥5.13; may need `CONFIG_LANDLOCK=y`) |
| Stability / API guarantee | Deprecated; no SLA from Apple | Stable kernel ABI (ABIv1–v9 documented in kernel headers) |

**Summary:** Seatbelt is more expressive than Landlock in several dimensions (IP-level network
filtering, Mach IPC control, regex path rules, distinct `file-map-executable` right). Landlock has
a more stable public API guarantee. For AIRG's use case (workspace confinement + bridge socket +
no egress TCP), both are adequate; Seatbelt's extra expressiveness is available but not needed for
the baseline policy.

---

## 5. Codex Prior Art and the No-Double-Sandbox Decision

### 5.1 Codex's macOS Seatbelt Implementation

OpenAI Codex CLI implements macOS Seatbelt sandboxing in
`codex-rs/core/src/seatbelt_base_policy.sbpl` (base policy) and
`codex-rs/core/src/restricted_read_only_platform_defaults.sbpl` (platform path allowlist).

Key structural observations from the T5 research (where both files were fetched and inspected):

- Starts with `(version 1)` and `(deny default)` — the same deny-by-default foundation used in §3.
- Allows `process-exec`, `process-fork`, and `signal (target same-sandbox)` globally.
- Allows `file-map-executable` for system frameworks and `/usr/lib`.
- Allows `file-read*` for `/private/tmp`, `/private/etc`, `/usr/lib`, and Homebrew lib paths.
- Allows `file-read* file-write*` for `/private/tmp`.
- Allows the workspace root via a `(param "...")` substitution (same `-D` mechanism).
- Uses `UnixDomainSocketPolicy` / `(allow network-outbound (local unix-socket ...))` for its own
  internal IPC.
- The `restricted_read_only_platform_defaults.sbpl` adds Homebrew paths:
  `/opt/homebrew/lib` and `/usr/local/lib`.

A recent commit (2026) added Java support: allowing JVM-specific paths in the profile. The profile
is actively maintained for real-world tool compatibility.

**Codex's profile as a baseline:** AIRG's profile (§3 above) is structurally derived from and
compatible with Codex's approach. The key AIRG-specific additions are:
1. The `(param "SOCKET_PATH")` carve-out for the Topology A bridge socket.
2. The `(allow network-outbound (local unix-socket (path (param "SOCKET_PATH"))))` rule.
3. Parameterized workspace root (Codex also uses a param for this — compatible approach).

### 5.2 No-Double-Sandbox Rule (AGENT_CONTEXT.md §13.1 #5, §13.5 #2)

If AIRG applies a Seatbelt profile to a Codex agent process, and Codex **also** applies its own
Seatbelt profile internally, two nested sandbox layers stack:

1. The outer AIRG profile is applied first (at `sandbox-exec` invocation time, before the Codex
   binary runs its first instruction).
2. Codex internally calls `sandbox_init_with_parameters()` (or equivalent SBPL application) to
   apply its own profile to itself.

**Seatbelt nesting behavior:** In macOS's TrustedBSD MAC layer, a process can tighten its own
sandbox at any time (call `sandbox_init()` on top of an existing profile), but cannot loosen it.
The result of two nested profiles is the **intersection** of their allow-sets. In practice, this
means:
- If the outer AIRG profile allows path X and the inner Codex profile denies X, X is denied.
- If the AIRG profile denies path Y and the Codex profile allows Y, Y is still denied.
- There is no conflict in the sense of a crash or error — both profiles are honored, with the
  more-restrictive one winning per operation.

However, nested sandboxes create **operational complexity**: if the agent fails to access a resource,
it is unclear whether the AIRG profile or the Codex profile is responsible. Debugging becomes
harder, and Codex's own profile may be tuned for a different allow-set than AIRG expects.

**Resolution per §13.1 #5:** AIRG treats Codex's own sandbox as AIRG-controlled state. AIRG
already disables Codex's built-in sandbox when hardening is applied (via `src/agent_configurator.py`
writing the Codex config). The macOS launcher MUST:

1. Before invoking `sandbox-exec`, verify that Codex's sandbox mode is set to `"off"` in the
   applicable `~/.codex/config.toml` or `<workspace>/.codex/config.toml`.
2. If Codex's sandbox is not disabled: either (a) disable it by writing the config, or (b) skip
   the AIRG Seatbelt layer and emit an audit log warning, depending on operator policy.
3. The preferred path is (a): AIRG is the authoritative outer wall; Codex's inner sandbox is
   subordinate.

This is consistent with the existing `src/agent_configurator.py` / `src/agent_posture.py` design
where AIRG manages Codex's config state.

---

## 6. SIP/TCC Interplay and Caveats

### 6.1 What Seatbelt Does NOT Protect

`sandbox-exec` + SBPL is a **process sandbox**, not a system security boundary. It operates on
the process's system calls and resource accesses. It does NOT:

- **Override SIP (System Integrity Protection):** SIP protects `/System`, `/usr` (except
  `/usr/local`), and parts of `/Library`. A Seatbelt profile cannot grant access to SIP-protected
  paths that SIP would deny at the kernel level. Conversely, SIP protection is independent of the
  Seatbelt profile — even if the profile allows a path, SIP may still deny writes to it. This is
  additive security, not a conflict.
- **Override TCC (Transparency, Consent, and Control):** Accessing the camera, microphone, location,
  contacts, calendar, full disk access, etc. requires TCC entitlements. A Seatbelt profile cannot
  grant these. If the agent process tries to access a TCC-protected resource, macOS may:
  - Show a dialog to the user requesting permission.
  - Silently deny the access.
  - Kill the process (depending on the resource).
  TCC prompts from a sandboxed process are surfaced to the user and can be confusing. For a headless
  CLI agent, TCC prompts should not occur (the agent should not need camera/mic/location). If a
  TCC prompt appears, it signals an unexpected resource access — treat as a security signal.
- **Contain the AIRG server process:** AIRG itself runs unconfined outside the sandbox. Seatbelt
  confines only the agent process tree. AIRG's own integrity depends on the host OS security model
  and is protected by running with different file ownership/permissions than the agent.
- **Enforce network semantics beyond operation-type:** Seatbelt's network rules are MAC-level
  operation checks, not a firewall. They prevent the `connect()` or `bind()` syscall from
  succeeding, but do not inspect packet contents. Domain-level filtering (blocking specific
  hostnames) remains in the AIRG MCP layer, as on Linux.

### 6.2 Key Operational Gotchas

**Gotcha 1 — Profile syntax errors are fatal (good for fail-closed, bad for UX):**
Any SBPL syntax error causes `sandbox-exec` to exit with a non-zero status and a message like:
```
sandbox-exec: sbpl: <error description>
```
The target process never starts. This is aligned with `on_setup_failure: "fail_closed"` but means
the AIRG launcher must validate the profile template during the `airg-doctor` / setup phase, not
only at launch time. Consider a dry-run validation step: `sandbox-exec -f profile.sb -- true` to
catch syntax errors before the first real launch.

**Gotcha 2 — `(param ...)` values must not contain shell-special characters:**
If `WORKSPACE_ROOT` or `SOCKET_PATH` contains spaces, single quotes, or other SBPL-special
characters, the profile compilation may fail or the parameter may be misinterpreted. The launcher
must validate that paths are safe for SBPL embedding. Paths under `/Users/<username>/...` with
typical filesystem characters are safe; paths with spaces require quoting that SBPL does not
transparently handle. A pragmatic mitigation: if the workspace path contains spaces or special
characters, render the profile with the literal path embedded (not via `(param ...)`), generating
a per-session profile file rather than using `-D` substitution.

**Gotcha 3 — Deprecation warning goes to stderr:**
`sandbox-exec` emits `WARNING: sandbox-exec is deprecated and may be removed in a future release.`
to stderr on macOS 15+. If the AIRG launcher surfaces subprocess stderr to the user, this warning
will appear on every agent launch. The launcher should filter this specific string from
`sandbox-exec`'s stderr (passing through all other stderr lines, especially actual errors and
agent output).

**Gotcha 4 — Profile does not apply to already-running processes:**
`sandbox-exec` confines a new process from birth. It cannot be applied to an existing process.
This means if the agent (Codex) self-updates or re-execs itself, the new exec'd binary inherits
the profile (because `process-exec*` is sandboxed — the new image starts within the same sandbox).
However, if the agent bypasses `execve` via dlopen of a new binary, this may not be caught by the
profile. For a CLI coding agent this is not a realistic concern.

**Gotcha 5 — `(subpath ...)` on symlinks:**
macOS resolves symlinks before applying Seatbelt vnode rules. `/tmp` → `/private/tmp`, `/etc` →
`/private/etc`. A rule `(allow file-read* (subpath "/tmp"))` may or may not match opens via
`/private/tmp` depending on the kernel version and whether the path was resolved before the MAC
check. The safe approach (shown in §3) is to allow both the symlink form and the canonical form
for well-known macOS symlinks.

**Gotcha 6 — Binary signing and hardened runtime:**
`sandbox-exec` itself does not require code signing of the target binary. However, if the target
binary uses the **hardened runtime** (`com.apple.security.cs.hardened-runtime` entitlement), some
dynamic library injection and debugging operations are restricted by the runtime — separate from
Seatbelt. For `codex` (a Rust/CLI binary), this is not typically an issue.

---

## 7. Invocation and Packaging Notes

### 7.1 Packaging Advantage Over Linux

On Linux, spatial confinement requires installing an external binary: `landrun`, `bwrap`, or
`nsjail`. These are not pip-installable; `airg-doctor` must detect and guide installation via
`apt`/`dnf`/`brew` or ship static binaries.

On macOS, `sandbox-exec` is **preinstalled** as part of the base OS at `/usr/bin/sandbox-exec`.
No external dependency is required. The AIRG macOS Seatbelt path adds zero new install-time
dependencies beyond the OS itself. This is a meaningful packaging advantage:

```
Linux: pip install ai-runtime-guard + apt install landrun (or bwrap)
macOS: pip install ai-runtime-guard  (sandbox-exec already present)
```

`airg-doctor` should still verify `sandbox-exec` is present (it could be removed in future macOS)
and that the current macOS version is in the tested-working range.

### 7.2 Profile File Packaging

The base profile template should be shipped as a package data resource:

```
src/airg_launcher/
  __init__.py
  linux_launcher.py       # landrun / bwrap selection
  macos_launcher.py       # sandbox-exec invocation
  profiles/
    airg_base.sb          # the SBPL template from §3
```

The profile path is resolved at runtime via `importlib.resources` (Python 3.9+):

```python
from importlib.resources import files
profile_path = files("airg_launcher.profiles").joinpath("airg_base.sb")
```

For per-session profile rendering (if param substitution is inadequate for special chars — see
Gotcha 2), render to a tempfile:

```python
import tempfile, string
template = profile_path.read_text()
rendered = template  # (param "KEY") substitution is done by sandbox-exec via -D flags;
                     # only fall back to string rendering if -D is insufficient
with tempfile.NamedTemporaryFile(suffix=".sb", delete=False) as f:
    f.write(rendered.encode())
    rendered_profile_path = f.name
```

### 7.3 Per-Session TMPDIR Isolation

Unlike `bwrap --tmpfs /tmp`, `sandbox-exec` grants write access to the host `/tmp` directory.
To prevent temp file leakage between concurrent sandboxed agent sessions, the launcher should:

1. Create a per-session temp directory outside the sandbox before launching:
   ```python
   import tempfile
   session_tmp = tempfile.mkdtemp(prefix=f"airg-{agent_id}-")
   # e.g. /tmp/airg-codex-proj-web-a3f9b1/
   ```
2. Add a specific allow rule for this directory to the profile (or pre-allow `/tmp` subpath and
   set TMPDIR to the session directory):
   ```scheme
   (allow file-read* file-write*
     (subpath (param "SESSION_TMPDIR")))
   ```
   Pass `-D SESSION_TMPDIR=/tmp/airg-<session>/`.
3. Set `TMPDIR=/tmp/airg-<session>/` in the confined process's environment.
4. After the agent exits, `shutil.rmtree(session_tmp)` in the launcher's cleanup path.

This provides logical temp isolation without requiring kernel-level tmpfs creation, which
`sandbox-exec` does not support.

### 7.4 `airg-doctor` Checks for macOS

`airg-doctor` should add the following macOS Seatbelt-specific checks:

1. `which sandbox-exec` — present and executable.
2. macOS version ≥ 12.0 (Monterey) — last confirmed working baseline; note that 13/14/15 are
   all tested-working per Codex and Chromium use; flag 15+ deprecation warning behavior.
3. Profile syntax validation: dry-run `sandbox-exec -f airg_base.sb -- true` and check exit code.
4. Codex sandbox mode: read `~/.codex/config.toml` and `<workspace>/.codex/config.toml`; warn if
   Codex sandbox is not set to `"off"` (double-sandbox risk).
5. AIRG socket path: verify socket directory is not inside the workspace root (would allow the
   agent to access it via workspace allow — the socket must be in a separate state dir).

---

## 8. Summary: macOS Implementation Checklist

This checklist covers the AIRG-side work required to implement the macOS Seatbelt path at P3.

- [ ] **`src/airg_launcher/macos_launcher.py`**: macOS launcher module. Probe `sandbox-exec`
  presence; resolve workspace root and socket path; render profile; invoke `sandbox-exec -f ...
  -D ... -- <agent_argv>`; filter deprecation warning from stderr; handle non-zero exit
  (profile error) as fail-closed.
- [ ] **`src/airg_launcher/profiles/airg_base.sb`**: the base SBPL template from §3. Parameterized
  on `WORKSPACE_ROOT` and `SOCKET_PATH`.
- [ ] **`src/airg_launcher/__init__.py`**: platform dispatch: call `macos_launcher` on Darwin,
  `linux_launcher` on Linux. Used by the `airg-exec`/`airg-run` entrypoint.
- [ ] **`src/airg_cli.py`**: extend `airg-doctor` with the macOS-specific checks from §7.4.
- [ ] **`src/agent_configurator.py`**: before macOS launch, ensure Codex's own sandbox is disabled
  in the applicable config.toml (single-sandbox invariant).
- [ ] **`docs/os-enforcement/macos-seatbelt.md`**: this document (delivered).
- [ ] **Tests**: add a test that renders the profile with sample params and validates syntax via
  `sandbox-exec -f <rendered> -- true` on a macOS CI runner.

---

## 9. Open Questions Surfaced

1. **`(param ...)` with special-character paths:** If workspace paths contain spaces or other SBPL-
   special characters, parameter substitution via `-D` may be insufficient. Needs empirical testing
   with paths like `/Users/user/My Projects/workspace`.

2. **Mach IPC allow list completeness:** The minimal Mach service names in §3 Step 8 are derived
   from Codex's policy. Some tools (Java, Electron-based tools) may require additional Mach
   services. The monitor-mode workflow (§6 of carveout-baseline.md §8) should surface missing
   services via system.log denial entries.

3. **TCC interaction for headless agents:** If a tool the agent invokes triggers a TCC prompt
   (e.g., accessing iCloud Drive, which may be in the workspace for some users), the UX breaks.
   Need to document which TCC-protected path classes might intersect with a developer workspace
   and either add profile rules to avoid triggering TCC or document the prompt as expected behavior.

4. **`file-map-executable` vs `process-exec*` separation:** The profile allows `process-exec*`
   globally (to allow the agent to spawn any binary). This may be too broad — a tighter profile
   would enumerate specific allowed `execve` targets. However, for a coding agent that needs to
   run arbitrary tools (npm, python, git subcommands, make, etc.), globally allowing `process-exec*`
   is the pragmatic choice, relying on the `file-read*` / `file-map-executable` path rules to
   prevent loading binaries from outside the allow-set.

5. **Double-sandbox coexistence vs disable:** Is it acceptable to let both the AIRG Seatbelt
   profile and Codex's inner profile coexist (nested, intersection semantics), or must Codex's
   be definitively disabled? Coexistence is technically safe (more-restrictive wins) but operationally
   complex. The current design recommends disable; this should be confirmed with the operator.
