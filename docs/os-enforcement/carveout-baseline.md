# AIRG OS Sandbox — Carve-out Baseline for a Confined Dev Agent

**Task:** T5 — Minimal filesystem allow-set for a Codex-style agent under OS confinement.
**Design source of truth:** `AGENT_CONTEXT.md §13`, especially §13.5 #3 (carve-out tuning = #1 UX risk) and §13.5 #4 (credentials).
**Produced:** 2026-05-30 by general-purpose agent (Claude Sonnet 4.6).
**Cross-references:** `docs/os-enforcement/sandbox-policy-schema.md` (the `os_sandbox.filesystem` fields this document populates), `src/executor.py` (HOME=WORKSPACE_ROOT, env scrub).

---

## 1. Core Principle: Additive Allow-Rules on a Deny-by-Default Posture

The sandbox starts with **deny everything**. Allow-rules are added additively for exactly the paths
an agent legitimately needs. This document defines those rules.

The governing tiers:

```
workspace_root          → READ + WRITE  (the agent's working area; non-negotiable)
system executables      → READ + EXEC   (interpreters, shells, build tools)
shared libraries        → READ + EXEC   (dynamic linker, libc, language runtimes)
system read-only data   → READ only     (certs, resolver, locale, timezone)
writable scratch        → READ + WRITE  (tmp; ideally private/redirected)
credentials             → DENY by default; explicit carve-outs via policy only
```

Everything else is implicitly denied. The implementation maps directly to the
`os_sandbox.filesystem` sub-object fields defined in `sandbox-policy-schema.md`:

| Allow tier | Schema field | Default |
|---|---|---|
| workspace | `workspace_root` | resolved from `AIRG_WORKSPACE` at runtime |
| extra reads | `readable_paths` | `[]` (populated per this doc) |
| exec + read | `read_exec_paths` | baseline list (see §2) |
| write scratch | `writable_paths` | `["/tmp"]` (see §4) |
| credentials | `credential_carve_outs` | `[]` (deny all) |

---

## 2. Linux: Read + Exec Paths for a Working Dev Shell

### 2.1 Distro Layout: usrmerge vs Split /bin

All major Linux distros have completed the **usrmerge** transition (the unification of `/bin`,
`/sbin`, `/lib`, `/lib64` into `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/lib64` with the old
paths becoming symlinks):

| Distro | usrmerge status (2025/2026) |
|---|---|
| Debian 12+ (bookworm) | Merged-usr only; `/bin` → symlink to `/usr/bin` |
| Ubuntu 22.04+ | Merged-usr only |
| Fedora 37+ | Fully merged; `/usr/sbin` additionally merged into `/usr/bin` |
| RHEL/CentOS 9+ | Merged |
| Arch Linux | Merged |
| openSUSE Tumbleweed | Merged since 2021-05-27 |

**Practical implication for Landlock/bwrap rules:** on a fully-merged system, allowing `/usr`
recursively covers `/usr/bin`, `/usr/lib`, `/usr/lib64`, `/usr/sbin`, and the symlink targets of
`/bin` and `/lib`. However, Landlock path rules on symlinks are resolved at open time, not at
rule-definition time. To be safe across all distros and Landlock ABI versions, **enumerate both
the canonical `/usr/*` paths AND the legacy `/bin`, `/sbin`, `/lib`, `/lib64` paths** — on merged
systems the extra rules cost nothing; on (rare) un-merged systems they are necessary.

### 2.2 Concrete read_exec_paths for Linux

The `read_exec_paths` field in `os_sandbox.filesystem` should contain the following for Linux:

#### Minimal tier (boot a shell, run a basic Python/Node/git workflow)

```json
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
  "/etc/ld.so.conf.d"
]
```

**Why each group matters:**

| Path(s) | Why needed |
|---|---|
| `/usr/bin`, `/usr/sbin` | Shells (`bash`, `sh`), `git`, `python3`, `node`, `npm`, `make`, `gcc`, `curl`, standard POSIX utilities |
| `/usr/lib`, `/usr/lib64` | Shared libraries: libc, libstdc++, libssl, libz, Python stdlib `.so` files, Node addons |
| `/usr/lib32`, `/usr/libx32` | Multilib: 32-bit libs on x86_64 hosts; build tools that emit 32-bit targets |
| `/usr/libexec` | Helper binaries called by tools (e.g., `git-core/` helpers, `gcc` subprocesses) |
| `/usr/local/bin`, `/usr/local/lib` | Site-wide installs (pip-installed CLI tools, manual language version installs) |
| `/bin`, `/sbin`, `/lib`, `/lib64` | Symlinks on merged systems (no cost); real paths on split-/bin systems |
| `/lib32`, `/libx32` | 32-bit library paths on un-merged systems |
| `/usr/share/terminfo` | Terminal capability database — missing this causes broken TTY/cursor in interactive shells and TUI tools (`ncurses`, `less`, `vim`). Symptom: garbled output, `TERM unknown` errors |
| `/etc/ld.so.cache`, `/etc/ld.so.conf*` | Dynamic linker reads these to locate shared libraries. Missing = every dynamically linked binary fails to start with `error while loading shared libraries` |

#### Dynamic linker — explicit carve-out

The dynamic linker itself must be read+exec-able. Its path is architecture-dependent:

| Architecture | Path |
|---|---|
| x86_64 | `/lib64/ld-linux-x86-64.so.2` (covered by `/lib64` above) |
| aarch64 | `/lib/ld-linux-aarch64.so.1` (covered by `/lib` above) |
| armhf | `/lib/ld-linux-armhf.so.3` |
| i686 | `/lib/ld-linux.so.2` |

These are all covered by the directory paths in the minimal list above. No separate entry needed
if the parent directory is included. If you switch to **file-level** (not directory-level) Landlock
rules, enumerate these explicitly.

#### Comfortable tier additions (productive dev agent)

```json
"read_exec_paths_additional": [
  "/usr/local",
  "/opt",
  "/home/linuxbrew/.linuxbrew",
  "/proc/self",
  "/dev/null",
  "/dev/urandom",
  "/dev/random",
  "/dev/stdin",
  "/dev/stdout",
  "/dev/stderr",
  "/dev/tty",
  "/dev/fd",
  "/run/systemd/resolve"
]
```

| Path | Why |
|---|---|
| `/usr/local` | Catch-all for site-local tools; avoids needing to enumerate sub-paths |
| `/opt` | Some distros install language version managers (pyenv, nvm) and non-packaged tools here |
| `/home/linuxbrew/.linuxbrew` | Linuxbrew (Homebrew on Linux) prefix; needed if the agent uses brew-installed tools |
| `/proc/self` | Process reads its own `/proc/self/exe`, `/proc/self/maps`, `/proc/self/fd/*` — needed by Python, Node, Rust, and the dynamic linker for self-inspection |
| `/dev/null`, `/dev/urandom`, etc. | Standard device files used by almost every runtime for discard, entropy, and I/O |
| `/run/systemd/resolve` | `systemd-resolved` stub resolver socket; some DNS resolution paths consult it |

**Note on `/proc/self` vs `/proc`:** Do NOT allow `/proc` broadly — it exposes process table
information for all PIDs. Allow only `/proc/self` (agent's own process). If the agent needs
`/proc/version` or `/proc/cpuinfo` (e.g., for hardware detection), add those specific paths to
`readable_paths`, not `read_exec_paths`.

---

## 3. Linux: Read-Only Data the Toolchain Needs

These paths go in `readable_paths` (read only, not exec):

```json
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
  "/usr/share/terminfo",
  "/etc/gitconfig",
  "/etc/alternatives",
  "/proc/version",
  "/proc/cpuinfo",
  "/proc/meminfo",
  "/proc/sys/kernel/hostname",
  "/sys/kernel/mm/transparent_hugepage"
]
```

**Why each matters:**

| Path(s) | Why needed | Failure symptom if missing |
|---|---|---|
| `/etc/ssl/certs`, `/etc/pki/tls`, `/etc/pki/ca-trust`, `/usr/share/ca-certificates` | TLS CA bundles. `curl`, `git`, `pip`, `npm`, and any HTTPS client consults these to verify server certificates. Distro split: Debian/Ubuntu use `/etc/ssl/certs`; Fedora/RHEL use `/etc/pki/tls` and `/etc/pki/ca-trust`; both should be listed. | `SSL certificate verify failed`, `curl: (60) SSL certificate problem` |
| `/etc/resolv.conf` | DNS resolver configuration (nameserver IPs, search domains). Without this, hostname lookups fail. | `Temporary failure in name resolution`, `Name or service not known` |
| `/etc/hosts` | Static hostname mappings. `localhost` resolution and any `/etc/hosts` overrides. | `localhost` lookup may fail; some tools break |
| `/etc/nsswitch.conf` | Name Service Switch: determines order of resolution (files→dns→mDNS etc.). `getaddrinfo()` reads this. | DNS resolution falls back or fails unexpectedly |
| `/etc/passwd`, `/etc/group` | UID/GID lookups by name. `ls -l`, `git`, Python's `os.getpwuid()`, and many tools call `getpwuid()`/`getgrgid()`. | `I have no name!` in shell prompt; file ownership displayed as raw UIDs; some git operations fail |
| `/etc/localtime`, `/usr/share/zoneinfo` | Timezone data. Without this, timestamps default to UTC and `TZ=` env vars can't resolve named zones. | Log timestamps in UTC regardless of system zone; some apps error on timezone lookup |
| `/usr/share/locale`, `/usr/lib/locale`, `/usr/share/i18n`, `/etc/locale.*` | Locale data for `glibc`. Needed for correct `LC_*` behavior, character encoding, and some Python string ops. | `locale: Cannot set LC_ALL to default locale`; encoding errors in non-ASCII filenames |
| `/usr/share/terminfo` | Also listed in `read_exec_paths`; terminal database for `ncurses`/`terminfo` — keep in both if the linker also needs to map it. | Garbled terminal output; `Error opening terminal: unknown.` |
| `/etc/gitconfig` | System-wide git config. `git` reads this on every invocation. | git missing system-level config (e.g., `safe.directory`, `http.proxy`) — usually non-fatal but may break specific workflows |
| `/etc/alternatives` | Debian/Ubuntu's `update-alternatives` symlink tree. `python3`, `java`, `gcc` may resolve through here. | `python3 not found` even though the binary exists |
| `/proc/version`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/sys/kernel/hostname` | Self-diagnostic reads common in build systems, CI, and tools that detect the host environment. | Usually non-fatal but some build toolchains (CMake, Meson, Bazel) may fail during feature detection |
| `/sys/kernel/mm/transparent_hugepage` | Some JVM and native runtimes read this for memory performance tuning. | Non-fatal warning; some JVM startups log `Unable to determine Transparent Hugepage config` |

---

## 4. Language-Ecosystem Specifics

### 4.1 HOME = WORKSPACE_ROOT (already set by AIRG)

`src/executor.py` line 44 already sets `HOME = WORKSPACE_ROOT` for all subprocesses. This is the
correct strategy: it redirects any tool that uses `~` to look inside the workspace, which means:

- `~/.gitconfig` → `$WORKSPACE/.gitconfig` (inside workspace, writable)
- `~/.npmrc` → `$WORKSPACE/.npmrc` (inside workspace)
- `~/.cache` → `$WORKSPACE/.cache` (inside workspace, writable)

This effectively eliminates the need for most `~/` credential carve-outs. However it only works
for subprocesses launched through `executor.py`. The Codex agent process itself is launched by the
OS-level sandbox wrapper, and its HOME must also be pointed at the workspace (set in the launcher's
`--setenv HOME=$WORKSPACE_ROOT` equivalent). Confirm this is done in the launcher construction
code when implementing.

### 4.2 git

| Resource | Path | Recommended access | Notes |
|---|---|---|---|
| System git config | `/etc/gitconfig` | Read-only | Safe to allow; controls proxy/safe.directory |
| User git config | `~/.gitconfig` → `$WORKSPACE/.gitconfig` | Read-write (inside workspace, already allowed via workspace_root) | HOME redirect handles this; no extra carve-out needed |
| XDG git config | `~/.config/git` → `$WORKSPACE/.config/git` | Read-write (inside workspace) | Same HOME redirect |
| git credential store | `~/.git-credentials` → `$WORKSPACE/.git-credentials` | Read (inside workspace) | Only if operator puts token there explicitly |
| Global git executable helpers | `/usr/lib/git-core/` | Read+exec | Covered by `/usr/lib` in `read_exec_paths` |

**git and SSH:** `git push` over SSH requires `~/.ssh/id_*` and the `ssh-agent` socket. These are
credential paths and must be handled via `credential_carve_outs` (see §5), not via the read_exec
baseline. Default: DENY.

**git HTTPS with token:** A git credential helper (e.g., `git credential-store`) can store a token
in `$WORKSPACE/.git-credentials` — this is inside the workspace and already accessible. Preferred
over SSH for sandboxed agents.

### 4.3 Node.js / npm

| Resource | Path | Recommended access | Notes |
|---|---|---|---|
| npm global cache | `~/.npm` → `$WORKSPACE/.npm` | Read-write (workspace) | HOME redirect; npm respects HOME |
| npm user config | `~/.npmrc` → `$WORKSPACE/.npmrc` | Read (workspace) | npm tokens live here by default — inside workspace if HOME redirected |
| npm/yarn/pnpm cache | `~/.cache/` → `$WORKSPACE/.cache/` | Read-write (workspace) | HOME redirect |
| Node.js binary | `/usr/bin/node`, `/usr/local/bin/node` | Read+exec | Covered by `read_exec_paths` |
| Node.js shared libs | `/usr/lib/node_modules/npm/` | Read+exec | Covered by `/usr/lib` |
| nvm installs | `~/.nvm` → `$WORKSPACE/.nvm` | Read+exec (workspace) | If agent uses nvm, and HOME is redirected |
| Volta | `$VOLTA_HOME` (default `~/.volta`) | Read+exec | Redirect: set `VOLTA_HOME=$WORKSPACE/.volta` in launcher env |

**Token risk:** `~/.npmrc` is a primary npm token store. With HOME redirect, it lands inside the
workspace — the token is effectively workspace-scoped. If the operator provides an `.npmrc` via
the workspace, that is intentional. If the real user's `~/.npmrc` (with registry tokens) must be
accessed, that requires an explicit `credential_carve_outs` entry (see §5). Default: DENY.

### 4.4 Python

| Resource | Path | Recommended access | Notes |
|---|---|---|---|
| pip cache | `~/.cache/pip` → `$WORKSPACE/.cache/pip` | Read-write (workspace) | HOME redirect |
| pip user installs | `~/.local/lib/python*/site-packages` → `$WORKSPACE/.local/...` | Read+exec (workspace) | HOME redirect |
| System site-packages | `/usr/lib/python3/dist-packages`, `/usr/lib/python3.*/` | Read+exec | Covered by `/usr/lib` in `read_exec_paths` |
| Virtual env | `$WORKSPACE/.venv/` or `$WORKSPACE/venv/` | Read+exec (workspace) | Inside workspace; fully covered |
| `.pypirc` | `~/.pypirc` → `$WORKSPACE/.pypirc` | Read (workspace) | PyPI upload tokens; HOME redirect scopes it to workspace |
| Compiled extensions | `/usr/lib/python3.*/lib-dynload/` | Read+exec | Covered by `/usr/lib` |

### 4.5 Java / JVM (optional, comfortable tier)

| Resource | Path | Recommended access |
|---|---|---|
| JDK/JRE | `/usr/lib/jvm/`, `/usr/local/lib/jvm/` | Read+exec |
| Maven local repo | `~/.m2` → `$WORKSPACE/.m2` | Read-write (workspace, HOME redirect) |
| Gradle cache | `~/.gradle` → `$WORKSPACE/.gradle` | Read-write (workspace) |

### 4.6 /tmp and TMPDIR

| Path | Access | Notes |
|---|---|---|
| `/tmp` | Read+write | Default in `writable_paths`. Used by compilers (gcc temp files), pip, npm build steps, language runtimes for IPC sockets |
| `$TMPDIR` | Read+write | Many runtimes honor `$TMPDIR`. On Linux this is often `/tmp`; on macOS it is `/var/folders/...` (a per-user temp). Set `TMPDIR=/tmp` in the launcher env to ensure a predictable, controllable path. |

**Recommendation:** Use `bwrap --tmpfs /tmp` (or landrun's equivalent) to create a **private tmpfs
mount** at `/tmp` inside the sandbox. This gives the agent a writable `/tmp` that is isolated from
the host's `/tmp`, avoiding information leakage between concurrent sandboxed processes and
preventing an agent from leaving behind temp files after exit. This is the preferred approach over
simply bind-mounting the host `/tmp` read-write.

If a private tmpfs is not feasible (landrun may not support tmpfs creation in early versions),
grant read-write on `/tmp` (already the schema default) but name it in the audit log.

---

## 5. Credentials: Deny-by-Default with Controlled Carve-Outs

### 5.1 Paths That Must Be DENIED by Default

The following paths are blocked at BOTH layers:
1. **OS sandbox** (kernel-level, no access to the path inode at all)
2. **MCP policy** (`policy.blocked.paths` — matches the existing AIRG policy.json entries)

Cross-referencing `policy.json` blocked paths (lines 38–53), AIRG already blocks these at the
MCP layer. The OS sandbox makes these blocks kernel-enforced:

| Path | What it contains | policy.json entry |
|---|---|---|
| `~/.ssh/` | SSH private keys, `authorized_keys`, `known_hosts` | `.ssh` |
| `~/.aws/` | AWS credentials, config, session tokens | `.aws` |
| `~/.azure/` | Azure CLI credentials | `.azure` |
| `~/.config/gcloud/` | GCloud application-default credentials | `.config/gcloud` |
| `~/.docker/config.json` | Docker registry auth tokens | `.docker/config.json` |
| `~/.kube/` | Kubernetes service account tokens, kubeconfig | `.kube` |
| `~/.netrc` | FTP/HTTP credentials (including GitHub tokens if configured there) | `.netrc` |
| `~/.npmrc` | npm registry auth tokens | `.npmrc` |
| `~/.pypirc` | PyPI upload credentials | `.pypirc` |
| `~/.config/gh/` | GitHub CLI OAuth token | (add to policy.json) |
| `~/.config/op/` | 1Password CLI session | (add to policy.json) |
| `~/.vault-token` | HashiCorp Vault token | (add to policy.json) |
| `~/.gnupg/` | GPG private keys | (add to policy.json) |
| `~/.gitconfig` | May contain `credential.helper` with tokens; also blocked by context | `.gitconfig` (via `.env`) |
| `.env` | Project-level secrets | `.env` |
| `*.pem`, `*.key` | Certificate/private key files | policy.json extensions |

**With HOME redirect** (HOME=WORKSPACE_ROOT, already in `src/executor.py`), the `~/` paths above
resolve to `$WORKSPACE/.ssh`, `$WORKSPACE/.aws`, etc. These are INSIDE the workspace and therefore
writable by default — the operator MUST ensure the real credential directories do not get copied
into the workspace, and the agent must not be given these paths as part of workspace setup.

**Critical:** the OS sandbox deny-list for credentials must target the **real user home** (e.g.,
`/home/user/`) not `$WORKSPACE`. Because HOME is redirected, `~/.ssh` in shell context resolves
to `$WORKSPACE/.ssh`, but the OS sandbox rules target the actual filesystem path `/home/user/.ssh`.
Both must be denied. The policy should specify absolute paths, not `~`-relative ones.

### 5.2 The Credentials Tension (AGENT_CONTEXT.md §13.5 #4)

The risk is asymmetric:
- Too tight: agent cannot `git push`, cannot download private packages, cannot authenticate to
  any service. Workflow breaks.
- Too loose: agent can exfiltrate SSH keys, AWS credentials, or registry tokens.

The correct answer is **explicit, auditable, per-deployment carve-outs** via the
`credential_carve_outs` schema field. Examples:

```json
"credential_carve_outs": [
  {
    "path": "/home/user/.gitconfig",
    "access": "read",
    "reason": "git needs user name/email for commits; no credential.helper configured"
  },
  {
    "path": "/run/secrets/GIT_TOKEN",
    "access": "read",
    "reason": "CI-injected git token for private repo clone; file is bind-mounted by CI"
  }
]
```

**Recommended pattern for git authentication in sandboxed agents:**
1. Inject a fine-grained GitHub token (repo-scope only) as a file inside the workspace or
   as a bind-mounted secret at a `/run/secrets/` path, with an explicit `credential_carve_outs`
   entry.
2. Configure `git credential-store` pointing at `$WORKSPACE/.git-credentials` (already inside
   workspace, no carve-out needed).
3. Do NOT give the agent access to the real `~/.ssh` directory.

---

## 6. macOS Deltas: Seatbelt Profile Paths

On macOS, the launcher is `sandbox-exec` with a Seatbelt profile (`.sbpl`). Codex's own
`seatbelt_base_policy.sbpl` + `restricted_read_only_platform_defaults.sbpl` serve as prior art.
The following is derived directly from those files (fetched from `openai/codex` repo,
`codex-rs/sandboxing/src/`).

### 6.1 Seatbelt Profile Structure

Seatbelt profiles start with `(deny default)` then add explicit `(allow ...)` rules. This
mirrors the deny-by-default posture on Linux.

### 6.2 macOS-Specific Path Equivalents

#### Shared library / dynamic linker equivalent

On macOS, shared libraries are served from the **dyld shared cache**, not individual `.so` files:

| macOS path | Role | Seatbelt rule |
|---|---|---|
| `/usr/lib/` | User-space dylibs (also in shared cache); `file-read*` + `file-map-executable` | `(allow file-read* file-map-executable (subpath "/usr/lib"))` |
| `/System/Library/Frameworks/` | System frameworks (AppKit, Foundation, etc.) | `file-map-executable` + `file-read*` |
| `/System/Library/PrivateFrameworks/` | Private system frameworks | `file-map-executable` + `file-read*` |
| `/Library/Apple/System/Library/Frameworks/` | Apple Silicon firmware frameworks | `file-map-executable` + `file-read*` |
| `/Library/Apple/usr/lib/` | Additional Apple-provided dylibs | `file-map-executable` + `file-read*` |

The dyld shared cache itself (`/System/Library/dyld/`) does not appear as a path rule in Seatbelt
profiles because the kernel maps it directly without going through the normal vnode permission
check path. No explicit allow needed for the cache itself.

#### Executable paths

| macOS path | Linux equivalent | Notes |
|---|---|---|
| `/usr/bin/` | `/usr/bin/` | `file-read-data` + `file-read-metadata` |
| `/usr/sbin/` | `/usr/sbin/` | Same |
| `/usr/libexec/` | `/usr/libexec/` | Helper binaries |
| `/bin/` | `/bin/` | Symlink to `/usr/bin` on macOS 10.15+ |
| `/sbin/` | `/sbin/` | Symlink |
| `/usr/local/bin/` | `/usr/local/bin/` | Intel Homebrew prefix |
| `/opt/homebrew/bin/` | n/a | Apple Silicon Homebrew prefix |
| `/opt/homebrew/lib/` | n/a | Homebrew shared libs (ARM) |
| `/usr/local/lib/` | `/usr/local/lib/` | Intel Homebrew libs |

Codex's `restricted_read_only_platform_defaults.sbpl` explicitly allows:
```
(allow file-read* (subpath "/opt/homebrew/lib"))
(allow file-read* (subpath "/usr/local/lib"))
```

#### Temp, etc, and devices

| macOS path | Linux equivalent | Access |
|---|---|---|
| `/private/tmp/` | `/tmp/` | Read+write (Codex explicitly allows this) |
| `/tmp/` | `/tmp/` | Symlink to `/private/tmp` on macOS; allow both |
| `/var/tmp/`, `/private/var/tmp/` | `/var/tmp/` | Read+write |
| `/private/etc/` | `/etc/` | Read-only |
| `/etc/` | `/etc/` | Symlink; allow both |
| `/private/etc/resolv.conf` | `/etc/resolv.conf` | Read |
| `/private/etc/hosts` | `/etc/hosts` | Read |
| `/private/etc/passwd`, `/private/etc/master.passwd` | `/etc/passwd` | Read |
| `/private/etc/ssl/certs/`, `/etc/ssl/certs/` | `/etc/ssl/certs/` | Read (TLS CA) |
| `/private/var/db/timezone/`, `/private/etc/localtime` | `/etc/localtime` | Read (timezone) |

#### macOS Homebrew — the distro-level package manager

Homebrew installs to two locations depending on CPU architecture:

| Architecture | Homebrew prefix | Key paths |
|---|---|---|
| Apple Silicon (arm64) | `/opt/homebrew/` | `/opt/homebrew/bin`, `/opt/homebrew/lib`, `/opt/homebrew/Cellar` |
| Intel (x86_64) | `/usr/local/` | `/usr/local/bin`, `/usr/local/lib`, `/usr/local/Cellar` |

For a sandboxed dev agent on macOS, allow:
```
/opt/homebrew/bin      → read+exec
/opt/homebrew/lib      → read+exec
/opt/homebrew/Cellar   → read+exec (individual package binaries)
/opt/homebrew/opt      → read+exec (symlinks to Cellar)
/opt/homebrew/share    → read (docs, terminfo, man pages)
/usr/local/bin         → read+exec (Intel Homebrew + manual installs)
/usr/local/lib         → read+exec
```

### 6.3 Codex macOS Seatbelt as Prior Art

Codex's macOS Seatbelt profile (`codex-rs/sandboxing/src/seatbelt_base_policy.sbpl` +
`restricted_read_only_platform_defaults.sbpl`, fetched from `openai/codex` on GitHub) uses:
- `(deny default)` — deny-by-default posture (same as AIRG's intent)
- `(allow process-exec) (allow process-fork) (allow signal (target same-sandbox))` — child process creation within the sandbox
- `(allow file-map-executable (subpath "/System/Library/..."))` — dyld shared cache equivalent
- `(allow file-read* (subpath "/usr/lib"))` — system dylibs
- `(allow file-read* file-write* (subpath "/private/tmp"))` — temp scratch
- `(allow file-read* (subpath "/private/etc"))` — resolver, hosts, certs
- `(allow file-read* (subpath "/opt/homebrew/lib"))` and `/usr/local/lib` — Homebrew
- Explicit `pseudo-tty` and PTY device rules for interactive shells
- Unix domain socket allowlisting for the AIRG bridge socket (via `UnixDomainSocketPolicy`)

AIRG's macOS Seatbelt profile should be derived from this baseline and extended with the
`bridge_socket_path` allowance for the Topology A stdio↔socket bridge.

---

## 7. Tiered Baseline: Minimal vs Comfortable

### 7.1 Overview

Two named tiers let operators choose their risk/usability point. The schema field
`os_sandbox.filesystem.read_exec_paths` is populated differently per tier.

### 7.2 Tier 1 — Minimal (tightest confinement compatible with a working shell)

**Goal:** Run the agent shell and basic POSIX tools. Sufficient for simple read/edit/write
workflows where the agent does not need to install packages or run language toolchains.

**Linux `read_exec_paths`:**
```json
[
  "/usr/bin",
  "/usr/lib",
  "/usr/lib64",
  "/bin",
  "/lib",
  "/lib64",
  "/usr/share/terminfo",
  "/etc/ld.so.cache",
  "/etc/ld.so.conf",
  "/etc/ld.so.conf.d"
]
```

**Linux `readable_paths`:**
```json
[
  "/etc/ssl/certs",
  "/etc/pki/tls",
  "/etc/resolv.conf",
  "/etc/hosts",
  "/etc/nsswitch.conf",
  "/etc/passwd",
  "/etc/group",
  "/etc/localtime",
  "/usr/share/zoneinfo",
  "/etc/gitconfig"
]
```

**Linux `writable_paths`:**
```json
["/tmp"]
```

**macOS** (minimal Seatbelt additions on top of `seatbelt_base_policy.sbpl`):
```scheme
(allow file-read* file-map-executable (subpath "/usr/lib"))
(allow file-map-executable
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks")
  (subpath "/Library/Apple/System/Library/Frameworks")
  (subpath "/Library/Apple/usr/lib"))
(allow file-read* file-write* (subpath "/private/tmp"))
(allow file-read* (subpath "/private/etc"))
(allow file-read-data file-read-metadata (subpath "/usr/bin"))
(allow file-read-data file-read-metadata (subpath "/bin"))
```

### 7.3 Tier 2 — Comfortable (productive dev agent with language toolchains)

**Goal:** Full Python/Node/git/build-tool workflows including package installs, test runners,
compilers, and debug tools. Adds multilib, libexec, locale, Homebrew, proc self-inspection,
device access, and comfortable `/proc` reads.

**Linux `read_exec_paths`** (the full list from §2.2):
```json
[
  "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64",
  "/usr/lib32", "/usr/libx32", "/usr/libexec",
  "/usr/local/bin", "/usr/local/lib", "/usr/local/lib64",
  "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32",
  "/usr/share/terminfo",
  "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
  "/proc/self",
  "/dev/null", "/dev/urandom", "/dev/random",
  "/dev/stdin", "/dev/stdout", "/dev/stderr",
  "/dev/tty", "/dev/fd"
]
```

**Linux `readable_paths`** (the full list from §3):
```json
[
  "/etc/ssl/certs", "/etc/pki/tls", "/etc/pki/ca-trust",
  "/usr/share/ca-certificates",
  "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
  "/etc/passwd", "/etc/group",
  "/etc/localtime", "/usr/share/zoneinfo",
  "/usr/share/locale", "/usr/lib/locale",
  "/usr/share/i18n", "/etc/locale.gen", "/etc/locale.conf",
  "/usr/share/terminfo",
  "/etc/gitconfig", "/etc/alternatives",
  "/proc/version", "/proc/cpuinfo", "/proc/meminfo",
  "/proc/sys/kernel/hostname"
]
```

**Linux `writable_paths`:**
```json
["/tmp"]
```
(With private tmpfs mount recommended — see §4.6.)

**macOS** (comfortable additions on top of minimal):
```scheme
(allow file-read* file-map-executable (subpath "/usr/local/lib"))
(allow file-read* file-map-executable (subpath "/opt/homebrew/lib"))
(allow file-read-data file-read-metadata
  (subpath "/usr/sbin")
  (subpath "/usr/libexec")
  (subpath "/sbin"))
(allow file-read* (subpath "/Library/Preferences"))
(allow file-read* (subpath "/usr/share"))
(allow file-read* (subpath "/var/db/timezone"))
(allow file-read* (subpath "/private/var/db/timezone"))
```

### 7.4 Tier Summary Table

| Category | Minimal | Comfortable |
|---|---|---|
| Shell + POSIX tools | Yes | Yes |
| Python / pip (system) | Yes (via /usr/lib) | Yes + user site-packages |
| Node.js (system) | Yes (via /usr/bin + /usr/lib) | Yes + nvm/volta |
| git | Yes (basic) | Yes + full toolchain |
| Build tools (gcc, make) | No (needs /usr/lib32, libexec) | Yes |
| Homebrew (macOS) | No | Yes |
| Locale / i18n | No | Yes |
| 32-bit multilib | No | Yes |
| /proc self-inspection | No | Yes |
| Full CA bundle (multi-distro) | Partial (Debian only) | Yes (both Debian+RHEL) |
| Private tmpfs | Recommended | Recommended |

---

## 8. How to Debug a Too-Tight Sandbox

This section addresses the #1 operational pain point (AGENT_CONTEXT.md §13.5 #3).

### 8.1 Diagnosis Approach

Use `os_sandbox.mode = "monitor"` first (logs what would be denied, agent runs unconfined).
Review the deny log before switching to `"enforce"`.

For bwrap: add `--ro-bind / /` plus target overlays and observe stderr for access failures.
For landrun: use strace or audit log.
For macOS: use `codex sandbox macos --log-denials` flag (Seatbelt logs denials to `/var/log/system.log`).

### 8.2 Symptom → Likely Missing Path

| Symptom | Likely missing path | Fix |
|---|---|---|
| `error while loading shared libraries: libXXX.so.N: cannot open shared object file` | `/usr/lib` or `/usr/lib64` (or `/lib`, `/lib64` on split-/bin systems) | Add to `read_exec_paths` |
| `cannot execute binary file: Exec format error` or tool not found at all | Tool's parent directory not in `read_exec_paths` | Add `/usr/bin`, `/usr/local/bin`, or tool-specific path |
| `SSL certificate verify failed` / `curl: (60)` | CA bundle missing: `/etc/ssl/certs` (Debian) or `/etc/pki/tls` (RHEL) | Add both to `readable_paths` |
| `Name or service not known` / `Temporary failure in name resolution` | `/etc/resolv.conf` or `/etc/nsswitch.conf` | Add to `readable_paths` |
| `I have no name!` in shell prompt, UID shown as numbers | `/etc/passwd` or `/etc/group` | Add to `readable_paths` |
| `Error opening terminal: unknown.` / garbled terminal output | `/usr/share/terminfo` | Add to `read_exec_paths` or `readable_paths` |
| `Cannot set LC_ALL to default locale` / encoding errors | `/usr/share/locale`, `/usr/lib/locale` | Add to `readable_paths` |
| `git: 'credential-...' is not a git command` or git helper fails | `/usr/lib/git-core/` | Covered by `/usr/lib`; check if git was installed to `/usr/local` instead |
| Python import fails for C-extension module (`_ssl`, `_hashlib`, etc.) | `/usr/lib/python3.*/lib-dynload/` | Covered by `/usr/lib`; check if custom Python in `/opt` |
| npm fails to start / `Cannot find module` | `/usr/lib/node_modules/npm/` or Node in `/usr/local/bin` | Add `/usr/local` or `/usr/lib/node_modules` |
| `pip: command not found` even though pip is installed | pip may be in `~/.local/bin` which resolves to `$WORKSPACE/.local/bin` — must be in workspace and workspace is already RW | Check pip install location with `pip show pip`; may need `PATH=$WORKSPACE/.local/bin:$PATH` |
| Java/JVM fails to start | `/usr/lib/jvm/` | Add to `read_exec_paths` |
| `/tmp` write fails | `/tmp` not in `writable_paths` | Add `/tmp` (already default) |
| Tool creates socket in `/tmp` and another process can't connect | `/tmp` is a private tmpfs — sockets are isolated | Expected behavior; if IPC across sandbox boundary is needed, use explicit socket path in `credential_carve_outs` or `bridge_socket_path` |
| `sandbox-exec: sbpl: ...` on macOS | Seatbelt profile syntax error | Check `.sbpl` for malformed rules |
| macOS: dylib load fails, `dyld: ...` | Missing `file-map-executable` for `/usr/lib` or a framework | Add framework path to Seatbelt profile |
| macOS: `brew` command not found | Homebrew not in path rules | Add `/opt/homebrew/bin` (ARM) or `/usr/local/bin` (Intel) to exec allows |

### 8.3 Monitor Mode Workflow

1. Set `os_sandbox.mode = "monitor"` in policy.json.
2. Run the agent through a representative workflow (install deps, run tests, make a commit).
3. Collect the AIRG sandbox audit log entries for "would-deny" events.
4. Group by path prefix; add the smallest set of paths that covers all denials.
5. Switch to `os_sandbox.mode = "enforce"` and repeat.
6. Use `airg-doctor` to verify the launcher binary is present before the first enforce run.

---

## 9. Policy.json `os_sandbox.filesystem` Populated Example

The following is the concrete `os_sandbox.filesystem` block for the **comfortable tier** on Linux,
ready to paste into `policy.json` (per the schema in `sandbox-policy-schema.md`):

```json
"os_sandbox": {
  "enabled": true,
  "mode": "enforce",
  "launcher": "auto",
  "filesystem": {
    "workspace_root": "",
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
      "/proc/sys/kernel/hostname"
    ],
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
      "/dev/fd"
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

For macOS, the `launcher` is `"sandbox-exec"` and the `read_exec_paths` list is not used directly
(the Seatbelt profile has its own path syntax). The macOS launcher translates `readable_paths` and
`read_exec_paths` into `(allow file-read* ...)` / `(allow file-map-executable ...)` / `(allow
file-read-data file-read-metadata ...)` rules appended to the base policy.

---

## 10. Open Questions

1. **`/proc/self` — Landlock ABI v1 behavior:** Landlock v1 (kernel 5.13) does not support
   `LANDLOCK_ACCESS_FS_EXECUTE`. The `/proc/self` path rule is about read access to process
   metadata; check whether Landlock v1's `O_PATH` + read rules cover `/proc/self/*` correctly on
   kernels 5.13–5.18 before counting on it.

2. **Private tmpfs support in landrun:** bwrap supports `--tmpfs /tmp` (private tmpfs). landrun
   may not expose a tmpfs-creation flag in early versions (v0.1.14). Until confirmed, the
   recommended writable `/tmp` falls back to bind-mounting the host `/tmp`. Verify during P0 spike.

3. **HOME redirect on the agent launcher vs executor:** `src/executor.py` sets `HOME=WORKSPACE_ROOT`
   for AIRG subprocesses (MCP tool calls). But the Codex agent process itself is launched by the
   OS-level launcher wrapper, not by `executor.py`. The launcher must also inject `HOME=WORKSPACE_ROOT`
   into the agent's environment for the `~/` → workspace redirect to work at the OS level. Confirm
   this is implemented when writing the launcher.

4. **Credential deny-list: real home vs workspace home:** With HOME redirected, the OS sandbox must
   deny the REAL user home directory paths (`/home/user/.ssh`, `/home/user/.aws`) explicitly,
   because the redirected `$WORKSPACE/.ssh` is already inside the workspace (and workspace is
   writable). The sandbox rules must target absolute paths of the real home, not `~/` expansions.
   The launcher needs to resolve the real home at startup time and generate deny rules (or simply
   not grant read access outside the workspace + the allow-list).

5. **macOS SIP and `sandbox-exec` deprecation:** `sandbox-exec` is officially deprecated by Apple
   but continues to work through macOS 15.x. Codex uses it successfully. Watch for removal in
   future macOS versions; the long-term macOS story may need to migrate to App Sandbox entitlements
   or a different confinement mechanism (e.g., Endpoint Security framework).
