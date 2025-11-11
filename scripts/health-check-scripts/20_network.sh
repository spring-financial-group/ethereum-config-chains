#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "20_network (${SETUP:-})"

cache_names

# Use CURRENT_* variables if set
_EL_POD="${CURRENT_EL_POD:-$EL_POD}"
_EL_CTN="${CURRENT_EL_CTN:-$EL_CTN}"
_CL_POD="${CURRENT_CL_POD:-$CL_POD}"
_CL_CTN="${CURRENT_CL_CTN:-$CL_CTN}"
_VC_POD="${CURRENT_VC_POD:-$VC_POD}"
_VC_CTN="${CURRENT_VC_CTN:-$VC_CTN}"

if [[ -z "$_CL_POD" ]]; then
  warn "Skipping network check (CL pod not found)"
  return 0
fi

# Service & endpoints check
local_svc_json="$(kubectl get svc -n "$NS" "$EL_SVC" -o json 2>/dev/null || true)"
if [[ -n "$local_svc_json" ]]; then
  pass "Service $EL_SVC present"
else
  fail "Service $EL_SVC not found"
  return 0
fi

echo "Ports on $EL_SVC:"
echo "$local_svc_json" | jq -r '.spec.ports[] | "  \(.name)//\(.port)/\(.protocol)"'

if echo "$local_svc_json" | jq -e --arg p "$AUTHRPC_PORT" '.spec.ports[] | select(.port==($p|tonumber))' >/dev/null; then
  pass "Service exposes Engine API port $AUTHRPC_PORT"
else
  fail "Service missing Engine API $AUTHRPC_PORT"
fi

eps_json="$(kubectl get endpoints -n "$NS" "$EL_SVC" -o json 2>/dev/null || true)"
if [[ -n "$eps_json" ]]; then
  pass "Endpoints exist for $EL_SVC"
else
  fail "No Endpoints for $EL_SVC"
fi

# TCP probe: Beacon → EL
if [[ -n "$_CL_POD" && -n "$_CL_CTN" ]]; then
  probe_result=$(tcp_probe "$_CL_POD" "$_CL_CTN" "$EL_SVC" "$AUTHRPC_PORT" 2>/dev/null || echo "FAIL")
  case "$probe_result" in
    OK)   pass "Beacon → EL TCP $EL_SVC:$AUTHRPC_PORT OK" ;;
    SKIP) warn "Beacon → EL TCP $EL_SVC:$AUTHRPC_PORT SKIP (no tcp tool)" ;;
    *)    fail "Beacon → EL TCP $EL_SVC:$AUTHRPC_PORT FAIL" ;;
  esac
fi

# TCP probe: Validator → Beacon (only if VC exists)
if [[ -n "$_VC_POD" && -n "$_VC_CTN" && -n "$CL_SVC" ]]; then
  VC_PROBE_PORT="${CL_GRPC_PORT:-4000}"
  [[ "$SETUP" == "LIGHTHOUSE" ]] && VC_PROBE_PORT="${CL_REST_PORT:-5052}"
  
  probe_result=$(tcp_probe "$_VC_POD" "$_VC_CTN" "$CL_SVC" "$VC_PROBE_PORT" 2>/dev/null || echo "FAIL")
  case "$probe_result" in
    OK)   pass "Validator → Beacon TCP $CL_SVC:$VC_PROBE_PORT OK" ;;
    SKIP) warn "Validator → Beacon TCP $CL_SVC:$VC_PROBE_PORT SKIP (no tcp tool)" ;;
    *)    fail "Validator → Beacon TCP $CL_SVC:$VC_PROBE_PORT FAIL" ;;
  esac
fi
