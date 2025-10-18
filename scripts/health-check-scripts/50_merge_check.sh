#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "50_merge_check"

need curl

cache_names

echo "Merge spec sanity-check…"

# Ensure PFs for EL & CL
EL_PF_PID=""
if ! curl -sSf --max-time 2 "http://127.0.0.1:${EL_HTTP_PORT}" >/dev/null 2>&1; then
  EL_PF_PID=$(pf_bg "svc" "$EL_SVC" "${EL_HTTP_PORT}" "${EL_HTTP_PORT}") || true
  sleep 1
fi
CL_PF_PID=""
if ! curl -sSf --max-time 2 "http://127.0.0.1:${CL_REST_PORT}/eth/v1/config/spec" >/dev/null 2>&1; then
  CL_PF_PID=$(pf_bg "pod" "$CL_POD" "${CL_REST_PORT}" "${CL_REST_PORT}") || true
  sleep 1
fi
trap 'kill_pf "$EL_PF_PID"; kill_pf "$CL_PF_PID"' EXIT

EL_BLOCK0_HASH="$(curl -s -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x0", false],"id":1}' \
  "http://127.0.0.1:${EL_HTTP_PORT}" \
  | sed -n 's/.*"hash":"\([^"]*\)".*/\1/p')"

if [[ -z "$EL_BLOCK0_HASH" ]]; then
  fail "Could not fetch EL block0 hash from ${EL_SVC}:${EL_HTTP_PORT}"
  exit 0
fi
echo "EL block0 hash: $EL_BLOCK0_HASH"

FILE_TBH="$(kubectl -n "$NS" exec "$CL_POD" -c "$CL_CONT" -- sh -lc \
  "grep -E '^TERMINAL_BLOCK_HASH:' /data/testnet_spec/config.yaml 2>/dev/null | awk '{print \$2}'" || true)"
FILE_TBH_EPOCH="$(kubectl -n "$NS" exec "$CL_POD" -c "$CL_CONT" -- sh -lc \
  "grep -E '^TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH:' /data/testnet_spec/config.yaml 2>/dev/null | awk '{print \$2}'" || true)"
[[ -n "$FILE_TBH" ]] && echo "CL file TBH: $FILE_TBH" || warn "TBH missing in file"
[[ -n "$FILE_TBH_EPOCH" ]] && echo "CL file TBH_EPOCH: $FILE_TBH_EPOCH" || warn "TBH_EPOCH missing in file"

SPEC_JSON="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/config/spec" || true)"
REST_TBH="$(printf '%s' "$SPEC_JSON" | tr -d '\n' | grep -oE '"TERMINAL_BLOCK_HASH":"0x[0-9a-fA-F]+"' | sed -E 's/.*"TERMINAL_BLOCK_HASH":"([^"]+)".*/\1/')"
REST_TBH_EPOCH="$(printf '%s' "$SPEC_JSON" | tr -d '\n' | grep -oE '"TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH":[0-9]+' | sed -E 's/.*"TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH":([0-9]+)/\1/')"
echo "CL REST TBH: ${REST_TBH:-<unset>}"
echo "CL REST TBH_EPOCH: ${REST_TBH_EPOCH:-<unset>}"

ZERO_HASH="0x0000000000000000000000000000000000000000000000000000000000000000"

if [[ "$REST_TBH" == "$EL_BLOCK0_HASH" && "${REST_TBH_EPOCH:-}" == "0" ]]; then
  pass "Merge trigger loaded correctly (TBH matches EL genesis, epoch=0)"
elif [[ -n "$FILE_TBH" && "$FILE_TBH" == "$EL_BLOCK0_HASH" && "${FILE_TBH_EPOCH:-}" == "0" && ( -z "$REST_TBH" || "$REST_TBH" == "$ZERO_HASH" ) ]]; then
  fail "Prysm disk config is correct, but runtime spec shows TBH unset. Consider restarting beacon pod."
  echo "  kubectl -n $NS delete pod $CL_POD"
elif [[ -z "$FILE_TBH" || "$FILE_TBH" == "$ZERO_HASH" || "${FILE_TBH_EPOCH:-}" == "18446744073709551615" ]]; then
  fail "Disk config does not set TBH/epoch. Expected:"
  echo "  TERMINAL_BLOCK_HASH: $EL_BLOCK0_HASH"
  echo "  TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH: 0"
  if [[ "$AUTOFIX" == "true" ]]; then
    echo "Attempting AUTOFIX inside pod…"
    kubectl -n "$NS" exec "$CL_POD" -c "$CL_CONT" -- sh -lc \
      "sed -i -E 's|^TERMINAL_BLOCK_HASH:.*$|TERMINAL_BLOCK_HASH: $EL_BLOCK0_HASH|; s|^TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH:.*$|TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH: 0|' /data/testnet_spec/config.yaml && grep -E 'TERMINAL_BLOCK_HASH|TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH' /data/testnet_spec/config.yaml"
    echo "Restarting beacon…"
    kubectl -n "$NS" delete pod "$CL_POD" --wait=false
  fi
else
  warn "Inconsistent merge config:
  EL:   $EL_BLOCK0_HASH
  FILE: ${FILE_TBH:-unset} (epoch ${FILE_TBH_EPOCH:-unset})
  REST: ${REST_TBH:-unset} (epoch ${REST_TBH_EPOCH:-unset})"
fi
