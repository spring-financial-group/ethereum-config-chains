#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "50_merge_check (${SETUP:-})"

need curl

cache_names

_EL_POD="${CURRENT_EL_POD:-$EL_POD}"
_CL_POD="${CURRENT_CL_POD:-$CL_POD}"
_CL_CTN="${CURRENT_CL_CTN:-$CL_CTN}"

if [[ -z "$_CL_POD" ]]; then
  warn "Skipping merge check (CL pod not found)"
  return 0
fi

echo "Merge spec sanity-check…"

# Ensure PFs for EL & CL
EL_PF_PID=""
if ! curl -sSf --max-time 2 "http://127.0.0.1:${EL_HTTP_PORT}" >/dev/null 2>&1; then
  EL_PF_PID=$(pf_bg "svc" "$EL_SVC" "${EL_HTTP_PORT}" "${EL_HTTP_PORT}") || true
  sleep 1
fi
CL_PF_PID=""
if ! curl -sSf --max-time 2 "http://127.0.0.1:${CL_REST_PORT}/eth/v1/config/spec" >/dev/null 2>&1; then
  CL_PF_PID=$(pf_bg "pod" "$_CL_POD" "${CL_REST_PORT}" "${CL_REST_PORT}") || true
  sleep 1
fi
trap 'kill_pf "$EL_PF_PID"; kill_pf "$CL_PF_PID"' EXIT

# Get EL block0 hash
EL_BLOCK0_HASH="$(curl -s -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x0", false],"id":1}' \
  "http://127.0.0.1:${EL_HTTP_PORT}" 2>/dev/null \
  | jq -r '.result.hash // empty')"

if [[ -z "$EL_BLOCK0_HASH" ]]; then
  warn "Could not fetch EL block0 hash from ${EL_SVC}:${EL_HTTP_PORT}"
  return 0
fi
echo "EL block0 hash: $EL_BLOCK0_HASH"

# Check CL config file (if accessible)
FILE_TBH="$(kubectl -n "$NS" exec "$_CL_POD" -c "$_CL_CTN" -- sh -lc \
  "grep -E '^TERMINAL_BLOCK_HASH:' /data/testnet_spec/config.yaml 2>/dev/null | awk '{print \$2}'" 2>/dev/null || true)"
FILE_TBH_EPOCH="$(kubectl -n "$NS" exec "$_CL_POD" -c "$_CL_CTN" -- sh -lc \
  "grep -E '^TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH:' /data/testnet_spec/config.yaml 2>/dev/null | awk '{print \$2}'" 2>/dev/null || true)"

[[ -n "$FILE_TBH" ]] && echo "CL file TBH: $FILE_TBH" || echo "CL file TBH: <not found>"
[[ -n "$FILE_TBH_EPOCH" ]] && echo "CL file TBH_EPOCH: $FILE_TBH_EPOCH" || echo "CL file TBH_EPOCH: <not found>"

# Check CL REST API
SPEC_JSON="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/config/spec" 2>/dev/null || echo '{}')"
REST_TBH="$(echo "$SPEC_JSON" | jq -r '.data.TERMINAL_BLOCK_HASH // empty' 2>/dev/null)"
REST_TBH_EPOCH="$(echo "$SPEC_JSON" | jq -r '.data.TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH // empty' 2>/dev/null)"

echo "CL REST TBH: ${REST_TBH:-<unset>}"
echo "CL REST TBH_EPOCH: ${REST_TBH_EPOCH:-<unset>}"

# Validate
ZERO_HASH="0x0000000000000000000000000000000000000000000000000000000000000000"
MAX_EPOCH="18446744073709551615"

if [[ "$REST_TBH" == "$EL_BLOCK0_HASH" && "${REST_TBH_EPOCH:-}" == "0" ]]; then
  pass "Merge trigger loaded correctly (TBH matches EL genesis, epoch=0)"
elif [[ -n "$FILE_TBH" && "$FILE_TBH" == "$EL_BLOCK0_HASH" && "${FILE_TBH_EPOCH:-}" == "0" && ( -z "$REST_TBH" || "$REST_TBH" == "$ZERO_HASH" ) ]]; then
  warn "Disk config is correct, but runtime spec shows TBH unset. Consider restarting beacon pod."
  echo "  kubectl -n $NS delete pod $_CL_POD"
elif [[ ( -z "$FILE_TBH" || "$FILE_TBH" == "$ZERO_HASH" ) && ( -z "$FILE_TBH_EPOCH" || "$FILE_TBH_EPOCH" == "$MAX_EPOCH" ) ]]; then
  # TBH not set and epoch at max value - this is typical for instant-merge devnets
  pass "Merge config: instant-merge mode (TTD=0, TBH not explicitly set)"
  echo "     → This is the expected configuration for instant-merge devnets"
else
  warn "Merge config inconsistency detected between file and REST API"
  echo "     → If blocks are being produced, this is non-critical"
fi