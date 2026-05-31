# SSE / Streamable-HTTP MCP Transport — Feasibility Exploration

**Status:** Exploration complete. No prototype added (auth wiring is non-trivial; see §5).
**Branch:** `experimental`
**Date:** 2026-05-31
**Task:** W4 — SSE/HTTP transport exploration

---

## 1. SDK Feasibility — What the Installed `mcp` Package Actually Supports

**Installed version:** `mcp 1.26.0` (Python SDK, installed at
`.venv-airg/lib/python3.14/site-packages/mcp/`)

All claims in this section are grounded in code read from the installed package.

### 1.1 FastMCP Transport API

`FastMCP.run()` (`mcp/server/fastmcp/server.py`, line 279–301) accepts:

```python
def run(
    self,
    transport: Literal["stdio", "sse", "streamable-http"] = "stdio",
    mount_path: str | None = None,
) -> None:
```

All three transports are first-class. The default is `"stdio"`. AIRG's `src/server.py`
calls `mcp.run()` with no argument, so it uses the stdio default.

### 1.2 Streamable-HTTP (current MCP-recommended transport)

`FastMCP.streamable_http_app()` (line 950) returns a `starlette.applications.Starlette`
ASGI app. It lazily creates a `StreamableHTTPSessionManager` (from
`mcp.server.streamable_http_manager`) with these constructor parameters:

```python
class StreamableHTTPSessionManager:
    def __init__(
        self,
        app: MCPServer[Any, Any],
        event_store: EventStore | None = None,
        json_response: bool = False,
        stateless: bool = False,
        security_settings: TransportSecuritySettings | None = None,
        retry_interval: int | None = None,
    )
```

The manager handles session tracking (keyed on the `mcp-session-id` HTTP header) and
optional resumability via an `EventStore`. With `stateless=True` it creates a fresh
transport per request (useful for serverless).

`FastMCP.run_streamable_http_async()` (line 777) launches this app with `uvicorn`.

**Default path:** `streamable_http_path: str = "/mcp"` (in `Settings`).

**Stateful vs stateless:** both modes are available. Stateful is the default (maintains
session across requests). Stateless is a one-liner flag.

### 1.3 SSE (legacy — still supported)

`FastMCP.sse_app()` (line 818) and `FastMCP.run_sse_async()` (line 762) are present
and functional. The `SseServerTransport` class in `mcp/server/sse.py` implements the
two-endpoint SSE pattern: a `GET /sse` endpoint for the SSE stream and a `POST /messages/`
endpoint for client messages.

**SSE status in mcp 1.26.0:** supported and not deprecated in this SDK version, but
the MCP protocol spec now designates streamable-HTTP as the preferred HTTP transport.
SSE is described as the "legacy" pattern in the SDK codebase (the streamable-HTTP module
was added to supersede it). Both are usable.

**Default paths:** `sse_path: str = "/sse"`, `message_path: str = "/messages/"`.

### 1.4 DNS Rebinding Protection (built-in)

`FastMCP.__init__()` (line 177) auto-enables `TransportSecuritySettings` when
`host in ("127.0.0.1", "localhost", "::1")`:

```python
if transport_security is None and host in ("127.0.0.1", "localhost", "::1"):
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
        allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
    )
```

This is automatic and free when binding to loopback.

### 1.5 Auth Support (OAuth Bearer)

The SDK ships a full OAuth/bearer-token auth stack:
- `mcp.server.auth.middleware.bearer_auth.BearerAuthBackend` (Starlette auth backend
  that validates `Authorization: Bearer <token>` headers via a `TokenVerifier`)
- `mcp.server.auth.middleware.bearer_auth.RequireAuthMiddleware` (ASGI middleware that
  enforces auth; wraps SSE endpoint and POST handler)
- `mcp.server.auth.middleware.auth_context.AuthContextMiddleware` (contextvar-based
  auth info propagation; stores `AuthenticatedUser` in a contextvar so handlers can
  read it)
- `mcp.server.auth.provider.TokenVerifier` (abstract protocol — AIRG must implement this)

`FastMCP.__init__()` accepts `token_verifier: TokenVerifier | None` and
`auth: AuthSettings | None`. When both are provided, `RequireAuthMiddleware` wraps both
the SSE/streamable-HTTP endpoint and the POST messages handler automatically.

**What the SDK gives for free:**
- DNS rebinding protection on loopback (automatic)
- Bearer token extraction and middleware wiring
- `AuthContextMiddleware` to propagate authenticated identity into a contextvar
- `BearerAuthBackend` (Starlette auth backend)
- `RequireAuthMiddleware` enforcement wrapper

**What AIRG must build:**
- A concrete `TokenVerifier` implementation (the `verify_token(token: str) ->
  AccessToken | None` method) — this is the token store/validation logic
- Token issuance: generating per-agent tokens at registration time, persisting them
  (e.g., alongside the agent socket path), and injecting them into the agent's MCP
  config environment
- Per-connection identity mapping: reading the `AccessToken.client_id` from the
  auth contextvar and resolving it to `AIRG_AGENT_ID` / workspace / policy overlay
- `runtime_context.py` changes: `_resolve_agent_session_id()` currently reads only
  `os.environ.get("AIRG_AGENT_SESSION_ID")` and session-object attributes — it has no
  bearer-token lookup path

---

## 2. The Identity/Auth Gap — The Crux

### 2.1 Why the Current Model Breaks Over a Shared HTTP Listener

Today each AIRG process is spawned with `AIRG_AGENT_ID`, `AIRG_WORKSPACE`, and
`AIRG_AGENT_SESSION_ID` baked into its environment (set in `agent_configs.py`
~L198–290). Policy overlays, workspace containment, approval token session-binding, and
audit attribution all key off these env vars. `src/runtime_context.py` reads them in
`_resolve_agent_session_id()`:

```python
def _resolve_agent_session_id(ctx: Any | None = None) -> str:
    env_override = os.environ.get("AIRG_AGENT_SESSION_ID", "").strip()
    if env_override:
        return env_override
    # ... falls back to session object attributes or SESSION_ID constant
```

Over a shared HTTP listener:
- One AIRG process serves N agents over N concurrent HTTP sessions.
- `os.environ` is process-global — it has exactly one `AIRG_AGENT_ID` value for all
  sessions.
- There is no `ctx.session`-level auth binding. `_resolve_agent_session_id` probes
  `mcp_session_id`/`session_id`/`id` on the session object, which gives a unique ID per
  MCP session, but that ID is not mapped to any agent identity or policy overlay.
- Result: all connected agents share the same identity, workspace, and policy. This
  collapses the per-agent isolation that AIRG is built on.

### 2.2 Restoring Per-Agent Identity — Recommended Design

**Approach: per-agent bearer token mapped server-side to agent identity.**

1. **Token issuance (at agent registration time):**
   When an agent profile is registered (via `agent_configs.upsert_profile()` or the
   `airg-run` launcher), AIRG generates a cryptographically random token
   (`secrets.token_hex(32)`) for that agent. Store it alongside the profile in a
   token-registry file (e.g., `$AIRG_STATE_DIR/agent_tokens.json`, mode 0600), mapping
   `token → {agent_id, workspace, policy_overlay_key, ...}`.

2. **Token injection into the MCP config:**
   The agent's MCP configuration (generated by `agent_configs.generate_config()`) injects
   the token as an environment variable, e.g. `AIRG_MCP_TOKEN`, which the MCP client
   passes to the server connection as `Authorization: Bearer <token>` header (standard
   MCP HTTP client behavior) or as a custom header.

3. **Server-side `TokenVerifier` implementation:**
   AIRG implements `TokenVerifier.verify_token(token)` by looking up the token in the
   registry file and returning an `AccessToken` with `client_id=<agent_id>` and scopes
   `["airg:agent"]`. Expired or unknown tokens return `None`.

4. **Per-connection identity resolution:**
   After `BearerAuthBackend` and `AuthContextMiddleware` run, the authenticated identity
   is available via `auth_context.get_access_token().client_id` (the agent_id). AIRG
   must modify `_resolve_agent_session_id()` to check this contextvar first:

   ```python
   def _resolve_agent_session_id(ctx: Any | None = None) -> str:
       # 1. Check HTTP bearer auth context (SSE/HTTP transport path)
       from mcp.server.auth.middleware.auth_context import get_access_token
       access_token = get_access_token()
       if access_token and access_token.client_id:
           return access_token.client_id
       # 2. Env override (existing stdio/socket path)
       env_override = os.environ.get("AIRG_AGENT_SESSION_ID", "").strip()
       ...
   ```

5. **Policy overlay resolution per connection:**
   Today, `_resolve_agent_session_id` returns the session ID which is then used as an
   audit key but NOT as the policy overlay key (policy overlays use `AIRG_AGENT_ID`, not
   the session ID). For SSE, the `AccessToken.client_id` must carry the `agent_id`, not
   just a session ID, so that `config.load_policy()` can look up `agent_overrides[agent_id]`.
   This means `access_token.client_id = agent_id` (e.g., `"codex-proj-123"`) — the same
   string that today comes from `AIRG_AGENT_ID`. The workspace path must also be stored
   in the token registry and injected into the request context so that executor workspace
   containment (`AIRG_WORKSPACE`) works per-connection.

   The cleanest approach is a `RequestContext` (contextvar) that carries
   `{agent_id, workspace, policy_overlay_key}` alongside the session ID — analogous to
   how `AuthContextMiddleware` stores `AuthenticatedUser` in a contextvar.

6. **Reuse the Pass-3 auth model:**
   `backend_flask.py`'s `_load_or_create_ui_api_token()` / `request_security_guard()`
   pattern (token stored in `$policy_dir/ui_api_token`, mode 0600; checked via
   `secrets.compare_digest`) is the right precedent. The MCP token registry follows the
   same idiom: file-based, mode 0600, `secrets.compare_digest` for constant-time
   comparison. The difference is one token per agent instead of one shared UI token.

### 2.3 Alternative Identity Approaches

**mTLS (mutual TLS):** Each agent gets a client cert; the server verifies the cert to
establish identity. Provides strong cryptographic identity but requires: a local CA,
cert generation per agent, cert injection into the agent's MCP config, and TLS on a
loopback-only listener (unusual; adds openssl/cert-management complexity). Not worth it
for a local-first deployment. Appropriate only if AIRG is deployed over a real network.

**Per-port binding (one HTTP port per agent):** Preserves the per-process identity model
by assigning each agent a dedicated TCP port. Avoids the shared-listener identity problem.
But: N agents = N listening ports (hard to manage, port conflicts, firewall complexity),
and the per-port identity is still only as strong as localhost access control. Essentially
reconstructs the socket-path identity model at the TCP layer, losing the filesystem-perm
advantage of AF_UNIX. Not recommended.

**Recommendation:** Bearer token per agent, mapped server-side to agent identity. This
is the approach the SDK is built for (`BearerAuthBackend` + `TokenVerifier`) and
matches the Pass-3 precedent.

---

## 3. Security Analysis — TCP Listener vs. Socket Bridge

### 3.1 New Attack Surface from a Listening TCP Port

A local TCP listener (even loopback-only) is reachable by any process running as any
user on the local machine — not just the owning user. This is unlike an AF_UNIX socket
(mode 0600 in a directory mode 0700), which is reachable only by the owning user.

**Required mitigations (in priority order):**

1. **Bind to loopback only (`127.0.0.1` or `::1`).**
   Mandatory. The SDK defaults to `host="127.0.0.1"` in `FastMCP.__init__()` (line 163).
   Never bind to `0.0.0.0` for a local-only transport.

2. **Mandatory bearer token authentication even on loopback.**
   Every request must carry a valid `Authorization: Bearer <token>` header. No
   unauthenticated connections accepted. The `RequireAuthMiddleware` from the SDK
   wraps both the SSE/streamable-HTTP endpoints and the POST message handler, returning
   HTTP 401 before any MCP processing occurs. This is non-optional — without it, any
   local process can connect to the MCP server and execute tools with the full policy
   identity of whichever agent's token it guesses or brute-forces.

3. **Host / Origin header validation (DNS rebinding protection).**
   Already automatic when binding to loopback (see §1.4). The `TransportSecuritySettings`
   check enforces that `Host` is `127.0.0.1:*` or `localhost:*` and `Origin` (if present)
   matches. This prevents a malicious web page from sending requests to `localhost:PORT`
   via a browser (the `Origin` header from a cross-origin browser request would fail the
   check). The SDK handles this automatically; AIRG must not disable it.

4. **Rate limiting on connection and authentication.**
   Any process on the machine can send TCP SYNs to the port. Implement a per-IP
   connection rate limit and per-IP authentication failure limit at the ASGI middleware
   level (or via a simple counter in the `TokenVerifier`). This prevents:
   - Token brute-forcing (the token space is `secrets.token_hex(32)` = 2^128; brute
     force is computationally infeasible, but rate limiting is defense-in-depth)
   - Connection exhaustion (many half-open connections from a local attacker)

   The Flask backend currently has no rate limiting either; both transports share this
   gap. Simple token-bucket rate limiting via a middleware is ~30 lines.

5. **No token logging.**
   Bearer tokens must not appear in AIRG's audit log (`activity.log`) or in structured
   log output. Confirm this in the `TokenVerifier` implementation.

### 3.2 Bridge vs. TCP Port — Side-by-Side

| Security property | stdio↔socket bridge | SSE/streamable-HTTP |
|---|---|---|
| Accessible by other local users? | No (socket mode 0600) | Yes (any user on loopback) |
| Requires authentication? | No (kernel + FS perms are the boundary) | Yes (mandatory bearer token) |
| DNS rebinding protection? | N/A (no HTTP) | Yes (SDK auto-enables on loopback) |
| Auth brute-force risk? | None | Low (token_hex(32)) but needs rate limit |
| New port opened? | No | Yes (port on 127.0.0.1) |
| Threat: malicious local process connects? | Must be same-user + have FS access to socket dir | Must have token (harder if rate-limited) |
| Privilege required to connect? | Same UID + know socket path | No special privilege; any local process |
| Sandbox carve-out | One socket path (narrow) | One TCP port (slightly broader) |

**Bottom line:** The bridge provides stronger local isolation with zero new auth work
because the kernel + filesystem perms form the boundary. The TCP listener is reachable
by any local process (not just the owning user) and therefore requires mandatory auth.
Both approaches are workable; the bridge is simpler and safer for the local/sandbox use
case.

---

## 4. Decision Matrix — SSE/HTTP vs. stdio↔socket Bridge

### 4.1 Use Case Analysis

| Dimension | stdio↔socket bridge | SSE/streamable-HTTP |
|---|---|---|
| **(a) Sandbox / Topology A** | **Correct choice, already built.** AIRG outside sandbox, agent inside, bridge is the carve-out. Zero new auth, identity model unchanged. P1-a is complete. | Possible but unnecessary overhead. TCP port is a wider carve-out than one socket path. Adds auth work for no net benefit in this topology. |
| **(b) Remote / multi-agent / containerized** | **Not suitable.** AF_UNIX sockets are host-local. A container boundary breaks the socket. Multi-agent requires one process+socket per agent profile. | **Correct choice.** HTTP works across container, network, and machine boundaries. One AIRG instance can serve N agents over N authenticated sessions. This is where SSE/HTTP earns its complexity cost. |
| **(c) Implementation cost & risk** | **Already implemented** (src/unix_socket_server.py, P1-a, 10 tests, zero new failures). | **Non-trivial.** Requires: token registry, TokenVerifier, identity wiring in runtime_context.py, policy overlay resolution per-connection, rate limiting. Estimate: ~300–400 lines of new code, new test surface. Higher regression risk (identity/context model changes). |

### 4.2 Explicit Clarification on Sequencing

The stdio↔socket bridge (P1-a, already complete) solves the "AIRG fully outside the
sandbox" problem with zero new auth work. SSE/HTTP is **NOT** a prerequisite for
Topology A. The bridge already delivers Topology A.

SSE/HTTP is the right direction for a different set of use cases: remote deployment,
multi-tenant infrastructure, Docker-networked agents, cross-machine monitoring. These
are valid and important but are NOT part of the current P0/P1 scope.

**Recommendation: SSE/HTTP as a separate track, justified by remote/multi-tenant use
cases, not as a replacement for the bridge in the sandbox topology.**

The two transports can coexist in the same codebase: a `--http` / `--sse` flag on
`airg-server` (default: off) adds the HTTP listener alongside the existing stdio/socket
modes. Agents that need the sandbox topology use the socket bridge; agents in containers
or remote deployments use the HTTP transport.

---

## 5. Concrete Implementation Sketch

### 5.1 Minimal Code Changes for a Guarded Streamable-HTTP Transport

The following describes what would be needed — not a prototype to ship yet.

**Why no prototype is included here:** The SDK makes it a few lines to expose a
loopback-only listener, but doing the auth *correctly* (token issuance, per-connection
identity wiring, policy-overlay resolution per connection) is the non-trivial part.
Adding an unauthenticated listener would violate the security requirement that auth is
mandatory even on loopback. Therefore, only the sketch is included here; the prototype
should be built as a dedicated task once the auth design is reviewed.

**New file: `src/http_transport.py`** (~200 lines)

```python
"""
AIRG streamable-HTTP / SSE transport — EXPERIMENTAL, default-OFF.

Start with:  airg-server --http [--http-port 8765]
Requires:    $AIRG_STATE_DIR/agent_tokens.json  (populated at agent registration)
"""
import secrets
import json
import time
from pathlib import Path
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

class AIRGTokenRegistry:
    """File-backed token→agent mapping, reloaded on each request for hot rotation."""
    def __init__(self, registry_path: Path):
        self._path = registry_path

    def issue_token(self, agent_id: str, workspace: str, policy_key: str) -> str:
        token = secrets.token_hex(32)
        registry = self._load()
        registry[token] = {
            "agent_id": agent_id,
            "workspace": workspace,
            "policy_key": policy_key,
            "issued_at": int(time.time()),
        }
        self._save(registry)
        return token

    def revoke_agent(self, agent_id: str) -> None:
        registry = self._load()
        registry = {t: v for t, v in registry.items() if v["agent_id"] != agent_id}
        self._save(registry)

    def _load(self) -> dict:
        if not self._path.exists():
            return {}
        return json.loads(self._path.read_text())

    def _save(self, registry: dict) -> None:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._path.write_text(json.dumps(registry, indent=2))
        import os, stat
        os.chmod(self._path, stat.S_IRUSR | stat.S_IWUSR)

class AIRGTokenVerifier(TokenVerifier):
    def __init__(self, registry: AIRGTokenRegistry):
        self._registry = registry

    async def verify_token(self, token: str) -> AccessToken | None:
        data = self._registry._load().get(token)
        if not data:
            return None
        return AccessToken(
            token=token,
            client_id=data["agent_id"],
            scopes=["airg:agent"],
        )


def build_http_server(
    mcp: FastMCP,
    token_verifier: AIRGTokenVerifier,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> FastMCP:
    """Return a FastMCP instance wired for authenticated loopback streamable-HTTP."""
    # Patch the existing FastMCP instance's auth settings.
    # The token_verifier + auth settings enable RequireAuthMiddleware automatically.
    mcp._token_verifier = token_verifier
    mcp.settings.host = host
    mcp.settings.port = port
    mcp.settings.auth = AuthSettings(
        issuer_url=f"http://{host}:{port}",
        resource_server_url=f"http://{host}:{port}",
    )
    return mcp
```

**Changes to `src/server.py`:** Add a `--http` flag that, when set, calls
`run_streamable_http_async()` instead of `mcp.run()`. Default remains stdio.

**Changes to `src/airg_cli.py` (`main_server`):**

```python
# Existing: --socket PATH
# New:      --http / --http-port N  (default-OFF)
if args.http:
    from http_transport import AIRGTokenRegistry, AIRGTokenVerifier, build_http_server
    registry = AIRGTokenRegistry(Path(state_dir) / "agent_tokens.json")
    verifier = AIRGTokenVerifier(registry)
    http_mcp = build_http_server(mcp, verifier, port=args.http_port)
    anyio.run(http_mcp.run_streamable_http_async)
```

**Changes to `src/runtime_context.py`:** Add a bearer-token identity resolution path
before the env override (see §2.2 design above).

**Changes to `src/agent_configs.py`:** When generating config in HTTP mode, emit the
`url` field (pointing to `http://127.0.0.1:PORT/mcp`) instead of the `command` field,
and inject `AIRG_MCP_TOKEN` into the agent's environment so the MCP client includes it
as a `Bearer` header.

### 5.2 Per-Connection Policy Overlay Resolution

Today, policy overlays (`policy["agent_overrides"][agent_id]`) are merged at policy
load time when the process starts. Over HTTP, the overlay must be merged per-request
using the per-connection `agent_id` from the auth context.

This requires:
- A `get_effective_policy(agent_id: str) -> dict` function that merges the global policy
  with `agent_overrides[agent_id]` (pure function, no I/O beyond the already-loaded
  policy).
- Tool handlers that call `get_effective_policy(current_agent_id())` instead of reading
  a process-global policy.
- `current_agent_id()` reads the `AuthContextMiddleware` contextvar (new) or falls back
  to `os.environ["AIRG_AGENT_ID"]` (existing stdio/socket path).

This is approximately the same refactor regardless of SSE vs streamable-HTTP transport.

### 5.3 Test / CI Implications

New tests needed (not yet written — this is a sketch):
- `test_http_transport.py`: token issuance + verification + revocation; loopback-only
  binding assertion; auth rejection (401 for missing/invalid token); per-connection
  identity isolation (two sessions, different tokens, different agent_ids, verify
  correct overlay applied to each)
- Integration test: `airg-server --http --http-port 9999` + MCP client connecting with
  Bearer token → `tools/list` succeeds; connecting without token → 401.

The existing 312 tests would not be affected (default stdio/socket path unchanged).

### 5.4 Phased Delivery

| Phase | Content | Effort |
|---|---|---|
| **HTTP-1** | Token registry + AIRGTokenVerifier; token issuance in agent_configs; `--http` flag defaulting off; loopback bind + auto-auth via SDK | ~200 lines + tests |
| **HTTP-2** | runtime_context.py per-connection identity; get_effective_policy() refactor; per-connection policy overlay | ~150 lines + tests |
| **HTTP-3** | Rate limiting middleware; token rotation / revocation UI; remote binding option (with TLS requirement gate) | ~200 lines + tests |

HTTP-1 can be started once HTTP-2 is designed (they are tightly coupled — issuing a
token is pointless without the identity resolution that uses it).

---

## 6. Open Questions / Unknowns Not Resolvable from the SDK

1. **MCP client bearer token injection:** The standard MCP Python client (`mcp.client`)
   accepts `StdioServerParameters` or `SseServerParameters`/`streamable_http` params.
   It is unclear (without reading the client SDK) whether the MCP client automatically
   reads `AIRG_MCP_TOKEN` from the agent's env and sends it as `Authorization: Bearer`.
   This needs verification against `mcp.client` — the client-side transport headers may
   need to be explicitly configured rather than relying on env-var convention.

2. **Concurrent policy reload during a long-lived SSE session:** If the operator
   updates `policy.json` mid-session, the in-flight SSE connection holds a reference to
   the old policy object. For the bridge, this is not an issue (one process per agent,
   policy is reloaded on each tool call). For the shared HTTP server, a reload event
   must propagate to all active sessions. The `config.load_policy()` function currently
   reads from disk on each call (no caching); that behavior is correct but should be
   confirmed under load.

3. **uvicorn dependency:** `run_streamable_http_async()` and `run_sse_async()` import
   `uvicorn` at call time. `uvicorn` is not in AIRG's current `requirements.txt`
   (`mcp>=1.0,<2.0` and `flask>=3.0,<4.0` only). It would need to be added as an
   optional or required dependency. Verify that `mcp[http]` extra exists or add
   `uvicorn` directly.

4. **Token file security under multi-user CI:** The `agent_tokens.json` file (mode 0600)
   stores all agent tokens. If AIRG is ever run in a shared CI environment, this file
   is the single point of compromise for all agent identities. Evaluate whether
   per-agent token files (one file per agent, mode 0600) are preferable to a single
   registry file.

5. **HTTP transport and the Topology A sandbox:** If an agent is running inside a
   Landlock/bwrap sandbox, it needs to reach `127.0.0.1:PORT`. The `os_sandbox`
   network mode must be at least `loopback_only` (not `none`) for an HTTP-transport
   agent. This contradicts the current default of `network_mode: none` for sandboxed
   agents and would require a policy change. Document this constraint explicitly before
   allowing HTTP transport in enforce-mode sandboxes.

6. **SSE vs streamable-HTTP choice for the initial implementation:** The SDK ships
   both. Streamable-HTTP is the current MCP recommendation and has better session
   management (resumability via `EventStore`, stateless mode option). SSE is simpler
   to debug (plain `text/event-stream`). Recommend streamable-HTTP for the
   implementation (it is what the MCP spec points to) and treat SSE as available-but-
   secondary for clients that require it.

---

## Summary

**SDK feasibility:** mcp 1.26.0 ships full support for both SSE (`sse_app()`,
`run_sse_async()`) and streamable-HTTP (`streamable_http_app()`, `run_streamable_http_async()`).
The `FastMCP.run()` method accepts `transport: Literal["stdio", "sse", "streamable-http"]`.
Streamable-HTTP is the MCP-recommended transport; SSE is legacy but functional. DNS
rebinding protection is automatic on loopback. The OAuth bearer auth stack
(`BearerAuthBackend`, `RequireAuthMiddleware`, `AuthContextMiddleware`) is present and
wired by `sse_app()` / `streamable_http_app()` when `token_verifier` is provided. **The
SDK gives the transport plumbing for free; AIRG must build the token registry,
`TokenVerifier` implementation, and per-connection identity/policy wiring.**

**Prototype decision:** Not prototyped. The auth wiring (token issuance, per-connection
identity resolution in `runtime_context.py`, per-connection policy overlay resolution)
is non-trivial. Adding a loopback listener without auth would violate the security
requirement. The sketch in §5 is sufficient for the next implementer to proceed without
guessing at API surfaces.
