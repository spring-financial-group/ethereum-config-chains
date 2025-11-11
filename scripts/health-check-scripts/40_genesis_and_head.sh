#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "40_genesis_and_head (${SETUP:-})"

need curl
need jq

cache_names

_EL_POD="${CURRENT_EL_POD:-$EL_POD}"
_CL_POD="${CURRENT_CL_POD:-$CL_POD}"

if [[ -z "$_CL_POD" ]]; then
  warn "Skipping genesis/head check (CL pod not found)"
  return 0
fi

# Port-forwards
EL_PF_PID=""
if ! curl -sSf --max-time 2 "http://127.0.0.1:${EL_HTTP_PORT}" >/dev/null 2>&1; then
  EL_PF_PID=$(pf_bg "svc" "$EL_SVC" "${EL_HTTP_PORT}" "${EL_HTTP_PORT}") || true
  sleep 1
fi
CL_PF_PID=""
if ! curl -sSf --max-time 2 "http://127.0.0.1:${CL_REST_PORT}/eth/v1/beacon/genesis" >/dev/null 2>&1; then
  CL_PF_PID=$(pf_bg "pod" "$_CL_POD" "${CL_REST_PORT}" "${CL_REST_PORT}") || true
  sleep 2
fi
trap 'kill_pf "$EL_PF_PID"; kill_pf "$CL_PF_PID"' EXIT

# EL block0 timestamp
b0="$(curl -s -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x0",false],"id":1}' "http://127.0.0.1:${EL_HTTP_PORT}" 2>/dev/null || echo '{}')"
ts_hex="$(jq -r '.result.timestamp // empty' <<<"$b0")"
if [[ "$ts_hex" == 0x* ]]; then
  ts_dec=$(( ts_hex ))
  pass "EL block0 timestamp: $ts_dec"
else
  warn "EL block0 timestamp unavailable"
  ts_dec=""
fi

# CL genesis
gen="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/beacon/genesis" 2>/dev/null || echo '{}')"
gen_time="$(jq -r '.data.genesis_time // empty' <<<"$gen")"
[[ "$gen_time" =~ ^[0-9]+$ ]] && pass "CL genesis_time: $gen_time" || warn "CL genesis_time unavailable"

# EL height (check this BEFORE using it in genesis check)
bn="$(curl -s -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' "http://127.0.0.1:${EL_HTTP_PORT}" 2>/dev/null | jq -r '.result // empty')"
[[ "$bn" == 0x* ]] && pass "EL blockNumber: $bn" || warn "EL blockNumber unavailable"

# Check genesis match
if [[ "${ts_dec:-}" =~ ^[0-9]+$ && "$gen_time" =~ ^[0-9]+$ ]]; then
  if [[ "$ts_dec" -eq "$gen_time" ]]; then
    pass "EL/CL genesis match"
  else
    # Calculate difference
    diff=$((gen_time - ts_dec))
    # Check if many blocks produced (only if bn is available)
    if [[ "${bn:-}" == 0x* ]] && [[ $((16#${bn#0x})) -gt 1000 ]]; then
      # If many blocks produced, genesis mismatch is cosmetic
      warn "EL/CL genesis mismatch: EL=$ts_dec CL=$gen_time (Δ=${diff}s, but chain is healthy)"
    else
      warn "EL/CL genesis mismatch: EL=$ts_dec CL=$gen_time (Δ=${diff}s)"
    fi
  fi
fi

# CL head advancing - check twice over 24 seconds for reliability
head1="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/beacon/headers/head" 2>/dev/null | jq -r '.data.header.message.slot // empty')"
sleep 12
head2="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/beacon/headers/head" 2>/dev/null | jq -r '.data.header.message.slot // empty')"
sleep 12
head3="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/beacon/headers/head" 2>/dev/null | jq -r '.data.header.message.slot // empty')"

if [[ "$head1" =~ ^[0-9]+$ && "$head3" =~ ^[0-9]+$ ]]; then
  delta=$((head3 - head1))
  # Check if head moved at all in 24 seconds
  if [[ $delta -ge 2 ]]; then
    # Moved 2+ slots in 24 seconds - healthy
    pass "CL head advancing ($head1 → $head2 → $head3)"
  elif [[ $delta -eq 1 ]]; then
    # Moved only 1 slot - slower than expected but not stuck
    pass "CL head advancing slowly ($head1 → $head2 → $head3)"
    echo "     → Advancing but slower than expected, may be catching up"
  elif [[ $delta -eq 0 ]]; then
    # No movement in 24 seconds
    warn "CL head appears stuck at $head1 (no movement in 24s)"
    echo "     → This may be temporary - check validator logs for block proposals"
    echo "     → In multi-validator setups, this beacon may not always propose"
  else
    # Head went backwards? Strange but possible during reorgs
    warn "CL head slot decreased ($head1 → $head3, possible reorg)"
  fi
else
  warn "Could not read CL head slot"
fi

# Peer count
pc="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/node/peer_count" 2>/dev/null || echo '{}')"
echo "Beacon peer_count: $(jq -r '.data.connected // .data // empty' <<<"$pc" 2>/dev/null || echo "?")"