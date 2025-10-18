#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "40_genesis_and_head"

need curl
need jq

cache_names

# Port-forwards (auto-killed on exit)
EL_PF_PID=""
if ! curl -sSf --max-time 2 "http://127.0.0.1:${EL_HTTP_PORT}" >/dev/null 2>&1; then
  EL_PF_PID=$(pf_bg "svc" "$EL_SVC" "${EL_HTTP_PORT}" "${EL_HTTP_PORT}") || true
  sleep 1
fi
CL_PF_PID=""
if ! curl -sSf --max-time 2 "http://127.0.0.1:${CL_REST_PORT}/eth/v1/beacon/genesis" >/dev/null 2>&1; then
  CL_PF_PID=$(pf_bg "pod" "$CL_POD" "${CL_REST_PORT}" "${CL_REST_PORT}") || true
  sleep 1
fi
trap 'kill_pf "$EL_PF_PID"; kill_pf "$CL_PF_PID"' EXIT

# EL block0 timestamp
b0="$(curl -s -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x0",false],"id":1}' "http://127.0.0.1:${EL_HTTP_PORT}")"
ts_hex="$(jq -r '.result.timestamp // empty' <<<"$b0")"
if [[ "$ts_hex" == 0x* ]]; then
  ts_dec=$(( ts_hex ))
  pass "EL block0 timestamp: $ts_dec"
else
  fail "EL block0 timestamp unavailable"
fi

# CL genesis
gen="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/beacon/genesis")"
gen_time="$(jq -r '.data.genesis_time // empty' <<<"$gen")"
[[ "$gen_time" =~ ^[0-9]+$ ]] && pass "CL genesis_time: $gen_time" || fail "CL genesis_time unavailable"

if [[ "${ts_dec:-}" =~ ^[0-9]+$ && "$gen_time" =~ ^[0-9]+$ ]]; then
  if [[ "$ts_dec" -eq "$gen_time" ]]; then pass "EL/CL genesis match"; else fail "EL/CL genesis mismatch: EL=$ts_dec CL=$gen_time"; fi
fi

# EL height
bn="$(curl -s -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' "http://127.0.0.1:${EL_HTTP_PORT}" | jq -r '.result // empty')"
[[ "$bn" == 0x* ]] && pass "EL blockNumber: $bn" || fail "EL blockNumber unavailable"

# CL head advancing
head1="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/beacon/headers/head" | jq -r '.data.header.message.slot // empty')"
sleep 12
head2="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/beacon/headers/head" | jq -r '.data.header.message.slot // empty')"
if [[ "$head1" =~ ^[0-9]+$ && "$head2" =~ ^[0-9]+$ ]]; then
  if [[ "$head2" -gt "$head1" ]]; then pass "CL head advancing ($head1 → $head2)"; else fail "CL head NOT advancing (stuck at $head1)"; fi
else
  fail "Could not read CL head slot"
fi

# peers + syncing + slot drift
pc="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/node/peer_count" || true)"
sync="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/node/syncing" || true)"
echo "Beacon peer_count: $(jq -r '.data.connected // empty' <<<"$pc" 2>/dev/null || echo "?")"
echo "Beacon syncing:    $(jq -r '.data.is_syncing // empty' <<<"$sync" 2>/dev/null || echo "?")"

spec="$(curl -s "http://127.0.0.1:${CL_REST_PORT}/eth/v1/config/spec" || true)"
sps="$(jq -r '.data.SECONDS_PER_SLOT // empty' <<<"$spec")"
now=$(date -u +%s)
if [[ "$sps" =~ ^[0-9]+$ && "$gen_time" =~ ^[0-9]+$ && "$head2" =~ ^[0-9]+$ ]]; then
  expected=$(( (now - gen_time) / sps )); drift=$(( expected - head2 ))
  echo "Slot check: expected=$expected head=$head2 drift=$drift"
  if [[ $drift -ge -2 && $drift -le 30 ]]; then pass "Slot drift normal"; else warn "Slot drift large ($drift)"; fi
fi
