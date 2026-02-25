#!/usr/bin/env bash
set -euo pipefail

# Source this script to export AIRG_* variables in your current shell:
#   source scripts/setup_runtime_env.sh
#
# If executed directly, it will still create directories/files and print exports,
# but parent-shell env vars will not be updated automatically.

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "[airg] Tip: run with 'source scripts/setup_runtime_env.sh' to export env vars in current shell."
fi

OS_NAME="$(uname -s || true)"
HOME_DIR="${HOME:-}"
if [[ -z "${HOME_DIR}" ]]; then
  echo "[airg] ERROR: HOME is not set."
  exit 1
fi

if [[ "${OS_NAME}" == "Darwin" ]]; then
  BASE_DIR="${HOME_DIR}/Library/Application Support/ai-runtime-guard"
else
  STATE_HOME="${XDG_STATE_HOME:-${HOME_DIR}/.local/state}"
  BASE_DIR="${STATE_HOME}/ai-runtime-guard"
fi

APPROVAL_DB_PATH_DEFAULT="${BASE_DIR}/approvals.db"
APPROVAL_HMAC_KEY_PATH_DEFAULT="${BASE_DIR}/approvals.db.hmac.key"

APPROVAL_DB_PATH="${AIRG_APPROVAL_DB_PATH:-${APPROVAL_DB_PATH_DEFAULT}}"
APPROVAL_HMAC_KEY_PATH="${AIRG_APPROVAL_HMAC_KEY_PATH:-${APPROVAL_HMAC_KEY_PATH_DEFAULT}}"

mkdir -p "$(dirname "${APPROVAL_DB_PATH}")"
mkdir -p "$(dirname "${APPROVAL_HMAC_KEY_PATH}")"

# Tighten directory permissions where secrets/state live.
chmod 700 "$(dirname "${APPROVAL_DB_PATH}")" || true
chmod 700 "$(dirname "${APPROVAL_HMAC_KEY_PATH}")" || true

# Ensure files exist and are not world/group accessible.
touch "${APPROVAL_DB_PATH}" "${APPROVAL_HMAC_KEY_PATH}"
chmod 600 "${APPROVAL_DB_PATH}" "${APPROVAL_HMAC_KEY_PATH}" || true

export AIRG_APPROVAL_DB_PATH="${APPROVAL_DB_PATH}"
export AIRG_APPROVAL_HMAC_KEY_PATH="${APPROVAL_HMAC_KEY_PATH}"

echo "[airg] AIRG_APPROVAL_DB_PATH=${AIRG_APPROVAL_DB_PATH}"
echo "[airg] AIRG_APPROVAL_HMAC_KEY_PATH=${AIRG_APPROVAL_HMAC_KEY_PATH}"
echo "[airg] Permissions tightened: dirs=700, files=600"
