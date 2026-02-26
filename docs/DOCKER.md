# Docker Guide (Baseline for Listing)

This document provides a minimal Docker packaging baseline for `ai-runtime-guard`, suitable for repository listing/review workflows (including Glama-style MCP catalog checks).

## Scope
1. Containerized runtime for `airg-server` (MCP stdio entrypoint).
2. Optional containerized `airg-ui` (web GUI).
3. Persistent runtime state via mounted host paths.

## Minimal Dockerfile
Create a `Dockerfile` at repo root:

```dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install package
COPY . /app
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Default command runs MCP server (stdio)
CMD ["airg-server"]
```

## Build Image
```bash
docker build -t ai-runtime-guard:latest .
```

## Run MCP Server Container
Use host-mounted runtime files so policy/db/key persist across restarts:

```bash
mkdir -p ~/.config/ai-runtime-guard ~/.local/state/ai-runtime-guard ~/airg-workspace

docker run --rm -i \
  -e AIRG_WORKSPACE=/workspace \
  -e AIRG_POLICY_PATH=/config/policy.json \
  -e AIRG_APPROVAL_DB_PATH=/state/approvals.db \
  -e AIRG_APPROVAL_HMAC_KEY_PATH=/state/approvals.db.hmac.key \
  -v ~/airg-workspace:/workspace \
  -v ~/.config/ai-runtime-guard:/config \
  -v ~/.local/state/ai-runtime-guard:/state \
  ai-runtime-guard:latest
```

Notes:
1. `-i` is required because MCP stdio uses stdin/stdout.
2. Container paths are examples; keep env vars and mounts aligned.
3. Initialize policy/state first (for example with local `airg-setup`) or mount pre-created files.

## MCP Client Config Using Docker
Example stdio MCP config:

```json
{
  "mcpServers": {
    "ai-runtime-guard": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-e", "AIRG_WORKSPACE=/workspace",
        "-e", "AIRG_POLICY_PATH=/config/policy.json",
        "-e", "AIRG_APPROVAL_DB_PATH=/state/approvals.db",
        "-e", "AIRG_APPROVAL_HMAC_KEY_PATH=/state/approvals.db.hmac.key",
        "-v", "/absolute/path/to/airg-workspace:/workspace",
        "-v", "/absolute/path/to/config-dir:/config",
        "-v", "/absolute/path/to/state-dir:/state",
        "ai-runtime-guard:latest"
      ]
    }
  }
}
```

## Optional: Run GUI from Container
If you also want GUI in Docker:

```bash
docker run --rm \
  -p 5001:5001 \
  -e AIRG_WORKSPACE=/workspace \
  -e AIRG_POLICY_PATH=/config/policy.json \
  -e AIRG_APPROVAL_DB_PATH=/state/approvals.db \
  -e AIRG_APPROVAL_HMAC_KEY_PATH=/state/approvals.db.hmac.key \
  -v ~/airg-workspace:/workspace \
  -v ~/.config/ai-runtime-guard:/config \
  -v ~/.local/state/ai-runtime-guard:/state \
  ai-runtime-guard:latest \
  airg-ui
```

Open: `http://127.0.0.1:5001`

## Validation Checklist
1. Image builds successfully.
2. `airg-server` starts and accepts MCP stdio traffic.
3. Policy file is writable through mounted config directory.
4. Approval DB/HMAC key persist in mounted state directory.
5. GUI loads and can read policy/approvals when launched with `airg-ui`.

## Known Limitations
1. Docker packaging does not change AIRG’s core enforcement model: only MCP-routed actions are enforced.
2. If the client can execute native shell/file tools outside MCP, those actions bypass AIRG.
