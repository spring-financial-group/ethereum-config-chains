#!/usr/bin/env bash
# 20_network.sh
set -Eeuo pipefail

# shellcheck source=00_lib.sh
. "$(dirname "$0")/00_lib.sh"

banner "20 network"

# Discover names/containers from labels and env defaults
cache_names

# --- Service & endpoints on the EL service ---
local_svc_json="$(kubectl get svc -n "$NS" "$EL_SVC" -o json 2>/dev/null || true)"
if [[ -n "$local_svc_json" ]]; then
  pass "Service $EL_SVC present"
else
  fail "Service $EL_SVC not found"
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

EL_EP_8551="$(echo "$eps_json" \
  | jq -r --arg p "$AUTHRPC_PORT" '
      .subsets[]? as $s
      | ($s.addresses[]?.ip // empty) as $ip
      | $s.ports[]?
      | select(.port==($p|tonumber))
      | "\($ip):\(.port)"
    ' | xargs -r echo)"
if [[ -n "$EL_EP_8551" ]]; then
  pass "Endpoint(s) on $AUTHRPC_PORT: $EL_EP_8551"
else
  fail "No endpoint on $AUTHRPC_PORT"
fi

# --- Beacon flags from the StatefulSet (args/cmd) ---
BEACON_STS="$(kubectl get -n "$NS" sts -l "$CL_LABEL" -o json)"
ARGS="$(echo "$BEACON_STS" \
  | jq -r '.items[0].spec.template.spec.containers[]? | select(.name!=null) | .args // empty' \
  | xargs -r echo)"
CMD="$(echo "$BEACON_STS" \
  | jq -r '.items[0].spec.template.spec.containers[]? | select(.name!=null) | ((.command//[]) + (.args//[])) | join(" ")' \
  | tr '\n' ' ')"

echo "Beacon args: $ARGS"
echo "Beacon cmd:  $CMD"

check_flag() {
  local flag="$1"
  if grep -qi -- "$flag" <<<"$ARGS $CMD"; then
    pass "Beacon flag present: $flag"
  else
    warn "Beacon flag missing: $flag"
  fi
}

check_flag "--execution-endpoint=http://$EL_SVC.default.svc:$AUTHRPC_PORT"
check_flag "--jwt-secret=$CL_JWT_PATH"
check_flag "--min-sync-peers=0"
check_flag "--subscribe-all-subnets"

# --- Robust TCP probes (Beacon→EL, VC→Beacon) ---
# Use tcp_probe from 00_lib.sh if present; otherwise fallback
_have_tcp_probe=0
if declare -F tcp_probe >/dev/null 2>&1; then _have_tcp_probe=1; fi

probe_once() {
  local from_pod="$1" from_ctn="$2" host="$3" port="$4"
  if [[ $_have_tcp_probe -eq 1 ]]; then
    tcp_probe "$from_pod" "$from_ctn" "$host" "$port" | tr -d '\r'
    return
  fi
  # Fallback: try bash /dev/tcp, nc, busybox nc, curl
  kubectl exec -n "$NS" "$from_pod" -c "$from_ctn" -- sh -lc '
    H="'"$host"'"; P="'"$port"'"
    if command -v bash >/dev/null 2>&1; then
      bash -lc "exec 3<>/dev/tcp/${H}/${P}" >/dev/null 2>&1 && echo OK || echo FAIL
    elif command -v nc >/dev/null 2>&1; then
      nc -z -w1 "$H" "$P" >/dev/null 2>&1 && echo OK || echo FAIL
    elif command -v busybox >/dev/null 2>&1; then
      busybox nc -z -w1 "$H" "$P" >/dev/null 2>&1 && echo OK || echo FAIL
    elif command -v curl >/dev/null 2>&1; then
      curl -m2 -s "http://$H:$P" >/dev/null 2>&1 && echo OK || echo FAIL
    else
      echo SKIP
    fi' 2>/dev/null | tr -d '\r'
}

probe_and_print() {
  local from_pod="$1" from_ctn="$2" host="$3" port="$4" label="$5"
  local res
  res="$(probe_once "$from_pod" "$from_ctn" "$host" "$port")"
  case "$res" in
    OK)   pass "$label $host:$port OK" ;;
    SKIP) warn "$label $host:$port SKIP (no tcp tool in container)" ;;
    *)    fail "$label $host:$port FAIL" ;;
  esac
}

# Beacon → EL (service DNS and FQDN)
probe_and_print "$CL_POD" "$CL_CTN" "$EL_SVC"             "$AUTHRPC_PORT" "Beacon → EL TCP"
probe_and_print "$CL_POD" "$CL_CTN" "$EL_SVC.default.svc" "$AUTHRPC_PORT" "Beacon → EL TCP"

# Validator → Beacon (only if VC is present)
if [[ -n "${VC_POD:-}" && -n "${VC_CTN:-}" ]]; then
  probe_and_print "$VC_POD" "$VC_CTN" "$CL_SVC"             "$CL_GRPC_PORT" "Validator → Beacon TCP"
  probe_and_print "$VC_POD" "$VC_CTN" "$CL_SVC.default.svc" "$CL_GRPC_PORT" "Validator → Beacon TCP"
fi

