# stdio ↔ AF_UNIX Socket Bridge — Design Document

**Status:** Design only, no implementation.  
**Branch:** `experimental`  
**Date:** 2026-05-30  
**Task:** T3 — Transport bridge enabling Topology A (AIRG fully outside sandbox)

---

## 1. Topology Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│  SANDBOX BOUNDARY  (Landlock / bwrap / sandbox-exec)                │
│                                                                     │
│  ┌─────────────────────────┐     raw bytes (MCP frames)            │
│  │  Agent process (Codex)  │ ──── stdin/stdout ────►               │
│  │  MCP client             │                        │              │
│  └─────────────────────────┘                        ▼              │
│                                      ┌──────────────────────────┐  │
│                                      │  in-sandbox shim         │  │
│                                      │  (airg-mcp-shim)         │  │
│                                      │  tiny forwarder process  │  │
│                                      └──────────┬───────────────┘  │
│                                                 │ AF_UNIX socket   │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │ ─ ─ ─ ─ ─ ─ ─ ─ ─│
│  (only carve-out: one socket path r/w)          │                  │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─┘
                                                  │
                          socket path:            │
                          $AIRG_STATE/<agent_id>.sock
                                                  │
┌─────────────────────────────────────────────────▼───────────────────┐
│  OUTSIDE SANDBOX  (unconfined)                                      │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  AIRG server process  (src/server.py + policy engine)        │   │
│  │  • Listens on AF_UNIX socket                                 │   │
│  │  • One MCP session per accepted connection                   │   │
│  │  • Full access to: approvals.db, hmac.key, activity.log,    │   │
│  │    backups/, policy.json, reports.db                         │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  state dir: $AIRG_STATE_DIR/  (e.g. ~/.local/share/airg/)          │
└─────────────────────────────────────────────────────────────────────┘
```

**Process inventory:**

| Process | Location | User | Sandbox |
|---|---|---|---|
| Agent / Codex | Inside | agent user | Landlock / bwrap / sandbox-exec confined |
| `airg-mcp-shim` | Inside | agent user | Confined; reads stdin/stdout, connect(2) one socket path |
| AIRG MCP server | Outside | agent user (same uid, different fd space) | Unconfined; owns all state files |

The shim is spawned by the MCP client as if it were the AIRG server (the config `command` field points to the shim, not to the real AIRG server). From the MCP client's perspective nothing changes: it still has a child process speaking stdio MCP.

---

## 2. In-Sandbox Shim

### 2.1 Role

The shim is a minimal forwarder. It does exactly one thing: relay raw bytes between its own stdin/stdout (connected to the MCP client) and a connected AF_UNIX stream socket (connected to the real AIRG server). No MCP parsing, no policy logic, no state.

### 2.2 MCP Framing — Confirmed

The installed `mcp` package is **version 1.26.0** (Python SDK). Inspection of `mcp/server/stdio.py` confirms:

- Messages are serialized with `model_dump_json(by_alias=True, exclude_none=True)`.
- Each message is written as **a single JSON line followed by `\n`** (newline-delimited JSON, not HTTP Content-Length framing).
- The reader iterates `async for line in stdin` — it reads line by line.

Therefore the framing is: **one JSON-RPC object per line, newline-terminated (`\n`).** There is no Content-Length header or envelope framing in the stdio transport.

**Design consequence:** the shim does NOT need to parse framing at all. It treats the streams as raw byte streams and forwards bytes verbatim in both directions. Newline boundaries are preserved naturally because bytes are passed through intact. This makes the shim transport-agnostic and immune to future MCP framing changes.

### 2.3 Shim Architecture

```
                 stdin (bytes from MCP client)
                         │
                   ┌─────▼──────┐
                   │  pump A    │  asyncio/threads
                   │  stdin →   │──► socket.send()
                   │  socket    │
                   └────────────┘
                         ┌────────────┐
                   ┌─────┤  pump B    │
      socket.recv()◄─── │  socket → │
                   │    │  stdout    │
                   └─────┤           │──► stdout (bytes to MCP client)
                         └────────────┘
```

**Implementation sketch (stdlib only, no deps):**

```python
#!/usr/bin/env python3
"""
airg-mcp-shim  — in-sandbox stdio<->unix-socket forwarder.
Single dependency: Python 3.8+ stdlib only.
"""
import os, socket, sys, threading

SOCK_PATH = os.environ["AIRG_SOCKET_PATH"]   # injected by launcher

def pump(src, dst, label):
    try:
        while True:
            chunk = src.read(4096)
            if not chunk:
                break
            dst.write(chunk)
            dst.flush()
    except Exception:
        pass
    finally:
        try: src.close()
        except Exception: pass
        try: dst.close()
        except Exception: pass

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(SOCK_PATH)
sock_in  = sock.makefile("rb", buffering=0)
sock_out = sock.makefile("wb", buffering=0)

stdin_b  = sys.stdin.buffer
stdout_b = sys.stdout.buffer

t1 = threading.Thread(target=pump, args=(stdin_b,  sock_out, "client→server"), daemon=True)
t2 = threading.Thread(target=pump, args=(sock_in,  stdout_b, "server→client"), daemon=True)
t1.start(); t2.start()
t1.join(); t2.join()
```

Key properties:
- **Stdlib only** — no pip install needed inside the sandbox.
- **Byte-level forwarding** — no JSON parsing, no MCP awareness.
- **Two daemon threads** — one per direction; either can terminate and the other follows.
- **Buffering=0** — no buffering delay; essential for interactive approval prompts.
- **4 KiB chunks** — small enough for low latency, large enough for throughput.

### 2.4 EOF and Half-Close Handling

MCP over stdio uses EOF as the session-end signal (the `stdin_reader` loop in `mcp/server/stdio.py` exits on EOF). The shim must propagate EOF correctly:

| Event | Shim action |
|---|---|
| Agent process exits (stdin EOF to shim) | pump A reads 0 bytes → closes sock_out → server sees EOF on its read side → server closes session |
| AIRG server exits / disconnects (socket EOF to shim) | pump B reads 0 bytes → closes stdout → MCP client sees EOF → client terminates or retries |
| Shim itself killed (e.g. OOM) | Socket closed by OS → server session terminates gracefully |

AF_UNIX `SOCK_STREAM` supports half-close via `socket.shutdown(SHUT_WR)` if bidirectional independence is needed, but for MCP the session is always terminated when either end closes, so full close on first EOF is correct.

### 2.5 Process Lifecycle

**Normal flow:**

1. Launcher starts AIRG server outside sandbox; server creates and listens on the socket.
2. Launcher starts agent inside sandbox, with shim as the MCP server command.
3. MCP client spawns shim as child (stdio pipe).
4. Shim connects to socket. If connection refused (AIRG not yet ready), shim retries with exponential backoff (max 5 s) before exiting non-zero.
5. MCP session proceeds normally through the bridge.
6. Agent exits → shim exits → socket connection closed → AIRG closes that session.

**AIRG restarts (server side):**

- Server closes the socket file and re-creates it on restart.
- Shim's socket connection is broken → pump B gets EOF → shim exits.
- MCP client sees the shim child exit → client may restart the shim (behavior is client-dependent).
- Mitigation: AIRG should not restart mid-session without operator action. If it does, the agent will see its MCP server disconnect and need to re-initialize.

**Agent crashes (client side):**

- OS closes shim stdin → pump A gets EOF → shim exits → socket closes → AIRG session ends.
- AIRG cleans up session state normally.

**Shim crashes:**

- OS closes socket FD → AIRG session ends.
- OS closes stdout FD → MCP client sees child process exit (exit code non-zero if crash).

---

## 3. AIRG Running Outside — Transport Options

Today `src/server.py` calls `mcp.run()` which calls `anyio.run(self.run_stdio_async)`. This reads/writes `sys.stdin`/`sys.stdout`. For socket-based serving, this must change.

### 3.1 Verified SDK Capabilities (mcp 1.26.0)

From inspection of the installed package:

**`FastMCP.run()`** accepts `transport: Literal["stdio", "sse", "streamable-http"]`. There is no `"unix-socket"` transport option.

**`FastMCP.run_stdio_async()`** calls `stdio_server()` which wraps `sys.stdin.buffer` / `sys.stdout.buffer`. It is not socket-aware.

**`lowlevel/server.py` `Server.run()`** signature:
```python
async def run(
    self,
    read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
    write_stream: MemoryObjectSendStream[SessionMessage],
    ...
)
```

The low-level server accepts abstract anyio memory streams — it does NOT depend on stdin/stdout. The stdio binding is only in `stdio_server()` which wraps `sys.stdin`/`sys.stdout` into those stream types.

**Conclusion:** The SDK does not have a built-in unix-socket transport, but the low-level `Server.run()` is stream-agnostic. AIRG can serve over a unix socket by creating custom anyio streams that wrap a socket connection and passing them to `self._mcp_server.run()`.

### 3.2 Option A — Custom `run_unix_socket_async` Method (Recommended)

Add a new method to the AIRG server startup path (not in FastMCP itself, since we don't want to fork the SDK) that:

1. Creates an AF_UNIX `SOCK_STREAM` socket, binds, and listens.
2. On each `accept()`, wraps the connection into anyio byte streams.
3. Wraps those byte streams into MCP `MemoryObjectReceiveStream[SessionMessage]` / `MemoryObjectSendStream[SessionMessage]` using the same logic as `stdio_server()` (newline-delimited JSON encode/decode).
4. Calls `mcp._mcp_server.run(read_stream, write_stream, init_options)` for each connection.
5. Each accepted connection runs in its own anyio task group, allowing concurrent sessions.

The key insight: `stdio_server()` in `mcp/server/stdio.py` is ~60 lines of code. The socket analog replaces the `sys.stdin`/`sys.stdout` wrapping with `anyio.wrap_file(sock.makefile(...))`. The JSON encode/decode logic is identical.

**Skeleton:**

```python
import anyio, anyio.abc, socket as _socket
from contextlib import asynccontextmanager
from mcp.server.stdio import stdio_server  # for reference/copy of encode/decode logic

@asynccontextmanager
async def unix_socket_session(conn_sock):
    """Mirrors stdio_server() but for an accepted AF_UNIX connection."""
    # wrap socket fds as anyio async files
    reader = anyio.wrap_file(conn_sock.makefile("rb", buffering=0))
    writer = anyio.wrap_file(conn_sock.makefile("wb", buffering=0))
    # ... same MemoryObjectStream plumbing as stdio_server ...
    yield read_stream, write_stream

async def run_unix_socket_async(mcp_server, sock_path):
    # create, bind, listen
    server_sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    server_sock.bind(sock_path)
    server_sock.listen(5)
    async with anyio.create_task_group() as tg:
        while True:
            conn, _ = await anyio.to_thread.run_sync(server_sock.accept)
            tg.start_soon(handle_connection, mcp_server, conn)

async def handle_connection(mcp_server, conn):
    async with unix_socket_session(conn) as (read_stream, write_stream):
        await mcp_server.run(read_stream, write_stream, init_options)
```

**Trade-offs:**
- Pro: No SDK fork or patch; uses the public low-level API.
- Pro: Minimal code (~80 lines mirroring `stdio_server`).
- Pro: Preserves all AIRG tool logic unchanged.
- Con: Must duplicate the JSON encode/decode logic from `stdio_server` (or factor it into a shared helper). This is a maintenance surface if the SDK changes its framing (unlikely for newline-JSON).

### 3.3 Option B — Stdio Adapter on AIRG Side (shim-on-both-ends)

Instead of serving directly from a socket, run the existing `mcp.run()` (stdio) and wrap it with a socket-to-stdio adapter process on the AIRG side:

```
socket → socat/adapter → AIRG stdin/stdout
```

**Trade-offs:**
- Pro: Zero changes to `src/server.py`.
- Con: One more process per session; `socat` is an external dependency.
- Con: Lifecycle complexity — three processes per agent session.
- Con: Per-connection env injection (for identity) is harder with a static adapter.
- **Not recommended.** Option A is strictly cleaner.

### 3.4 Option C — Use SSE/Streamable-HTTP Transport

FastMCP supports SSE and streamable-HTTP. AIRG could listen on `localhost:PORT` instead of a unix socket.

**Trade-offs:**
- Pro: No custom stream code needed.
- Con: Introduces a TCP listener — new local attack surface (documented in AGENT_CONTEXT.md §13.10).
- Con: Requires authenticated per-connection identity (the explicitly deferred roadmap item).
- Con: Socket-path-as-identity (Section 4a below) does not apply.
- **Deferred.** Confirmed in §13.10 as the future authenticated-transport track, not the near-term path.

**Recommendation: Option A.** The AIRG side needs approximately 80 lines of new async code to serve over a unix socket. No SDK fork, no external deps, no new listeners.

---

## 4. Identity Preservation

### 4.1 The Problem

Today, each AIRG server process is spawned with `AIRG_AGENT_ID`, `AIRG_WORKSPACE`, and optionally `AIRG_AGENT_SESSION_ID` baked into its environment. These drive:
- Policy overlay selection (`agent_overrides` keyed on `agent_id`).
- Workspace containment paths.
- Audit log attribution.
- Approval token session-binding.

Over a shared unix socket, multiple agents could connect to a single AIRG process. The per-process-env model must be adapted.

### 4.2 Option (a) — One Socket Path Per Agent Profile (Recommended)

Each agent profile gets a unique socket path, e.g.:

```
$AIRG_STATE_DIR/sockets/<agent_id>.sock
```

The AIRG server is launched once per agent profile (not shared across profiles) with the same env vars as today. It listens on exactly one socket path derived from its own `AIRG_AGENT_ID`. The shim receives `AIRG_SOCKET_PATH=$AIRG_STATE_DIR/sockets/<agent_id>.sock` via its environment (injected by the launcher; the socket path is inside the sandbox boundary carve-out).

**Identity flow:**

```
Launcher sets env:
  AIRG_AGENT_ID=codex-proj-123
  AIRG_WORKSPACE=/home/user/myproject
  AIRG_SOCKET_PATH=~/.local/share/airg/sockets/codex-proj-123.sock

AIRG process (outside):
  reads AIRG_AGENT_ID, AIRG_WORKSPACE from its own env
  listens on AIRG_SOCKET_PATH
  → identity is fixed at process start, exactly as today

Shim (inside):
  reads AIRG_SOCKET_PATH from its env
  connects to that socket
  → forwarding begins
  → AIRG's context is already set; no per-connection identity negotiation needed
```

**Why this works:** The AIRG server process retains the exact same per-process identity model. From AIRG's perspective, it behaves identically to the current stdio mode — it has one identity, fixed at startup. The socket is just the transport, not a multiplexer.

**Security implication:** any co-located process with filesystem access to the socket path could connect to it. Mitigations (see Section 5): socket permissions 0600, owner-only; socket path placed outside the agent workspace; sandbox only carves in this one path. The threat is a co-located *malicious* process on the same machine posing as the agent — acceptable risk given the defense-in-depth framing (AIRG is not a full malicious-actor containment platform per §13.1 item 3).

**Evaluation:** This is the correct choice. It maps 1:1 to the existing model and adds zero new protocol complexity.

### 4.3 Option (b) — Identity Passed in MCP Handshake/Init Param

The agent or shim sends `AIRG_AGENT_ID` etc. in the MCP `initialize` params or as a custom header.

**Trade-offs:**
- Pro: Single AIRG process can serve multiple agents.
- Con: AIRG must parse and trust identity claims from the connecting client — this is the authenticated-transport problem in disguise. Without verification, the identity claim is spoofable.
- Con: Requires AIRG to handle per-session env context instead of per-process env, which changes `runtime_context.py` semantics significantly.
- **Not recommended for the near-term bridge.** Appropriate only with the authenticated SSE transport (deferred roadmap).

### 4.4 Option (c) — `SO_PEERCRED` / Unix Socket Credential

On Linux, `getsockopt(SO_PEERCRED)` gives the connecting process's `(pid, uid, gid)`. On macOS, `LOCAL_PEERPID` gives the pid.

**Trade-offs:**
- Pro: Kernel-verified; cannot be spoofed by userspace.
- Con: pid is not sufficient to derive `AIRG_AGENT_ID` or `AIRG_WORKSPACE` without AIRG having a registry mapping `pid → profile`. This registry has race conditions (pid reuse) and requires the launcher to register pids before the shim connects.
- Con: `LOCAL_PEERPID` is macOS-only; `SO_PEERCRED` is Linux-only — cross-platform bridging adds complexity.
- **Not recommended.** The per-socket-path approach (4a) achieves the same isolation with zero complexity.

### 4.5 Recommendation

**Use Option (a): one socket path per agent profile.** No changes to the identity model. No per-connection authentication. Socket path is the identity discriminator. This is both the simplest and the most secure option for the near-term bridge.

---

## 5. Security Analysis

### 5.1 The Socket as the Sole Hole

The sandbox (Landlock / bwrap / sandbox-exec) enforces that the agent and shim can only access:
- The agent workspace (read/write as configured).
- System libraries and interpreters (read/exec).
- The single AF_UNIX socket path.

The socket path is the only channel between inside and outside. Everything else — approvals.db, hmac.key, policy.json, activity.log, backups/, reports.db — is unreachable from inside the sandbox. This is the core security property of Topology A.

### 5.2 Socket File Permissions

```
-rw-------  1 user user  0  <socket path>
```

- **Mode 0600** (owner read/write only). Set immediately after `bind()` before `listen()`.
- **Umask** should be set to 0177 around the `bind()` call to avoid race with permissive umask.
- **Socket directory**: `$AIRG_STATE_DIR/sockets/`, mode 0700, created by AIRG launcher.

On Linux, socket files additionally require execute permission on the directory to connect — directory should be 0700 (owner-only traverse). This prevents other local users from even discovering socket names.

### 5.3 Socket Placement

The socket path must be:
1. **Outside the agent workspace** — a workspace-confined Landlock/bwrap sandbox would not grant the agent direct filesystem access to the socket's directory; the sandbox only carves in the specific socket path.
2. **Inside AIRG's state dir** — `$AIRG_STATE_DIR/sockets/<agent_id>.sock` (e.g. `~/.local/share/airg/sockets/codex-proj-123.sock`). Never inside `/tmp` (world-writable on some systems) or the workspace.
3. **Not world-accessible** — enforced by directory mode 0700 + file mode 0600.

### 5.4 Comparison: Topology A vs Topology B

| Property | Topology A (AIRG outside, socket bridge) | Topology B (AIRG inside, carve-outs) |
|---|---|---|
| approvals.db reachable from agent? | No — kernel-enforced | Yes — inside sandbox boundary |
| hmac.key reachable from agent? | No | Yes |
| policy.json writable by agent? | No | Yes (unless separate carve-out) |
| backups/ accessible to agent? | No | Yes |
| activity.log tamperable? | No | Yes (Landlock has no append-only) |
| "Agent tampers control plane" attack | Closed by kernel | Mitigated only by AIRG logic + planned crypto audit |
| Implementation complexity | Shim + socket server (~150 lines) | Zero (direct spawn) |
| Verdict | Correct | Weaker; acceptable only as interim with externalized control plane |

**Topology A is strictly better.** The complexity cost (the bridge) is small relative to the security gain.

### 5.5 Threat: Co-located Process Connects to Socket

A process running as the same user on the same machine (but outside the sandbox) could connect to `<agent_id>.sock`. The AIRG server would serve it as if it were the legitimate agent.

**Mitigations:**
1. Mode 0600 + directory 0700 → other users cannot reach it.
2. Same-user co-located attacker is already a privileged local attacker (they have ptrace access, can read the agent's memory, etc.) — this is out of scope for AIRG's threat model (defense-in-depth against accidents, not fully adversarial local attacker).
3. For higher assurance: combine with `SO_PEERCRED` check (Option 4c) to verify the connecting pid is the known shim pid. This is an optional hardening layer, not required for the near-term bridge.

---

## 6. Failure and Fallback Modes

### 6.1 Socket Not Available (AIRG Not Started)

Shim connects and gets `ECONNREFUSED` or `ENOENT`. Behavior:
- Shim should retry with backoff (e.g., 3 attempts × 1/2/4 s) to tolerate slow AIRG startup.
- After retries exhausted: shim exits non-zero. MCP client sees child process failure and should surface an error to the agent.
- Fail-closed: the agent cannot proceed without AIRG (no unguarded tool calls possible).

### 6.2 AIRG Server Crash Mid-Session

- Socket connection breaks → shim pump B gets EOF → shim exits.
- MCP client loses its server → session ends.
- No silent degradation: the agent knows its MCP server is gone.

### 6.3 Shim Binary Not Found or Exec Fails

- Launcher must verify the shim is accessible inside the sandbox at the path specified in the MCP config `command` field.
- If shim is not found: MCP client fails to start the server — explicit, not silent.
- Recommended placement: shim installed to a fixed location inside the sandbox's allowed-exec paths (e.g., same virtualenv as the agent's Python, or a dedicated directory that is bind-mounted read-only).

### 6.4 Sandbox Cannot Be Established (Fail-Closed)

Per AGENT_CONTEXT.md §13.5 item 5: if the sandbox cannot be established (no Landlock, no userns for bwrap), AIRG must refuse to start the agent OR degrade explicitly with a loud, logged, policy-gated warning. The bridge design is neutral here — the same fail-closed logic applies at the launcher level before the shim is started.

### 6.5 Launcher Carve-Out Cross-Reference

The sandbox must carve in exactly the socket path for connect access. Cross-referencing `docs/os-enforcement/launcher-evaluation.md`:

**Landlock (via landrun):** `--fs-path-rw $AIRG_SOCKET_PATH` or equivalent. Landlock FS rules cover `open(2)` on the socket path; the connect(2) syscall is covered by Landlock's network rules only for TCP ports (ABI v4+). For AF_UNIX sockets, `connect(2)` uses the filesystem path — granting read/write on the socket inode via Landlock FS rules is sufficient. **This needs empirical verification during the P0 spike** (also flagged as open in T2).

**bwrap:** `--bind $SOCK_DIR $SOCK_DIR` (bind-mount the socket directory read-write) or `--bind $SOCK_PATH $SOCK_PATH` for just the file. The latter is cleaner (minimizes carve-out to a single inode).

**sandbox-exec (macOS):** `(allow file-read* file-write* (path "/path/to/agent_id.sock"))` in the Seatbelt profile. Also needs `(allow network* (local unix-stream))` for the connect call.

The carve-out is deliberately narrow: one socket path, no directory traversal, no other AIRG state.

### 6.6 `AIRG_SOCKET_PATH` Injection Security

`AIRG_SOCKET_PATH` is set in the shim's environment by the launcher (outside the sandbox, before the sandbox is activated). The agent inside the sandbox can read its own environment but cannot modify the shim's environment after launch. The path is therefore launcher-controlled and not agent-spoofable.

---

## 7. Comparison: Bridge vs Authenticated SSE/HTTP

Per AGENT_CONTEXT.md §13.10, SSE transport is explicitly deferred because it requires authenticated per-connection identity. This appendix documents the trade-off.

| Dimension | stdio↔socket bridge (this document) | Authenticated SSE/HTTP (deferred) |
|---|---|---|
| Implementation size | ~150 lines (shim + socket server) | Substantial: OAuth/token auth, per-session identity, CORS hardening, TLS or localhost-only |
| New local listener? | No — socket file, no TCP port | Yes — HTTP port on localhost |
| Identity model | Per-process env (unchanged) | Per-connection token (new work) |
| Multi-agent support | One process per profile (as today) | Single process can serve N agents |
| Sandbox carve-out | One socket path per agent | One TCP port (shared or per-agent) |
| Client config change | Yes — `command` points to shim | Yes — `url` replaces `command` |
| Risk of regressions | Low — identity model unchanged | Higher — session/context threading changes |
| MCP SDK changes needed | Minor (socket server mode) | Minor (SSE is already in FastMCP) |
| Timeline | Near-term (weeks) | Long-term (months, needs auth design) |
| Precedent | Standard Unix IPC pattern | Standard web service pattern |

**Why the bridge is the correct near-term path:**
1. Identity is preserved with zero protocol changes — no auth tokens, no per-connection handshake.
2. No new listening port → no new attack surface for localhost injection.
3. SDK work is minimal (~80 lines to wrap a socket as anyio streams).
4. The shim is < 30 lines of stdlib Python.
5. Unblocks the P0 sandbox spike immediately.

SSE/HTTP remains the right long-term direction for multi-agent/remote deployments where authenticated identity and network transport are appropriate. The bridge does not foreclose SSE — it buys time for the auth design to be done correctly.

---

## 8. Summary of Required Changes

To ship Topology A with the stdio↔socket bridge:

| Component | Change | Size |
|---|---|---|
| `src/server.py` or new `src/server_unix.py` | Add `run_unix_socket_async()` coroutine; add `--socket PATH` CLI mode | ~80 lines |
| `src/airg_cli.py` | Add `airg-server --socket PATH` flag to start socket-mode server | ~20 lines |
| New file: `src/airg_mcp_shim.py` (or `scripts/`) | Tiny forwarder (Section 2.3) | ~40 lines |
| `src/agent_configs.py` | When sandbox mode enabled, emit shim as `command` + `AIRG_SOCKET_PATH` in env | ~30 lines |
| Launcher logic (T4/T5 scope) | Start AIRG outside before sandbox, pass socket path; carve in socket path | Per launcher |
| `docs/os-enforcement/` | This document | Done |

No changes required to: policy engine, approvals, audit, executor, tools, tests (identity model unchanged).

---

## 9. Open Questions

1. **Landlock AF_UNIX socket carve-out** — Does granting Landlock FS read/write on the socket inode (via landrun `--fs-path-rw`) actually allow `connect(2)` to an AF_UNIX socket? Needs empirical test during P0 spike. Also flagged in T2.

2. **`stdio_server()` duplication** — The socket-side server needs the same newline-JSON encode/decode as `stdio_server()`. Options: (a) copy-paste and own it, (b) import internal helpers from `mcp.server.stdio` if they are factored out in a future SDK version. For now, copy-paste is safe (the logic is ~20 lines and the framing is unlikely to change without a major version bump).

3. **Shim binary delivery inside sandbox** — The shim must be on an executable path inside the sandbox. Packaging question: (a) install via pip alongside AIRG (natural), (b) compile to a static binary (no Python dep inside sandbox). For the P0 spike, pip-installed alongside AIRG and included in the sandbox's allowed-exec paths is simplest.

4. **Session cleanup on abrupt shim exit** — If the shim is killed (SIGKILL) and the socket is closed abruptly, AIRG's `anyio` task for that session gets a broken-pipe error. Needs a test to confirm AIRG's existing exception handling covers this gracefully (no leaked session state in approvals.db).

5. **Multiple connections to same socket (edge case)** — With one AIRG process per socket (Option 4a), the listen backlog is 1 (or small). If the MCP client spawns multiple shim processes connecting to the same socket simultaneously, AIRG would serve them all with the same identity — potentially confusing. The launcher should ensure one shim per agent session; the AIRG socket server may enforce `accept` serialization (one active connection at a time) if multi-shim is a concern.
