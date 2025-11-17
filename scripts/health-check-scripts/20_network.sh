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
else
  # Service & endpoints check
  local_svc_json="$(kubectl get svc -n "$NS" "$EL_SVC" -o json 2>/dev/null || true)"
  if [[ -n "$local_svc_json" ]]; then
    pass "Service $EL_SVC present"

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

    # Engine API connectivity check (using logs instead of tcp_probe for reliability)
    if [[ -n "$_CL_POD" && -n "$_CL_CTN" ]]; then
      # Check recent beacon logs for engine connection errors
      engine_errors=$(kubectl logs -n "$NS" "$_CL_POD" -c "$_CL_CTN" --tail=100 --since=3m 2>/dev/null | \
        { grep -iE "execution|engine" || true; } | \
        { grep -iE "connection refused|timeout|dial.*failed|cannot.*connect|unavailable" || true; } | \
        wc -l  | xargs)

      if [[ "$engine_errors" -eq 0 ]]; then
        pass "Beacon → EL Engine API $EL_SVC:$AUTHRPC_PORT OK (log verification)"
      else
        fail "Beacon → EL Engine API $EL_SVC:$AUTHRPC_PORT has connection errors"
        kubectl logs -n "$NS" "$_CL_POD" -c "$_CL_CTN" --tail=50 --since=2m 2>/dev/null | \
          { grep -iE "execution|engine" || true; } | \
          { grep -iE "refused|timeout|failed" || true; } | \
          head -2 | sed 's/^/  /' || true
      fi
    fi

  if [[ -n "$_VC_POD" && -n "$_VC_CTN" && -n "$CL_SVC" ]]; then
    # Check validator logs for beacon connection errors
    vc_errors=$(kubectl logs -n "$NS" "$_VC_POD" -c "$_VC_CTN" --tail=100 --since=3m 2>/dev/null | \
      { grep -iE "beacon|grpc" || true; } | \
      { grep -iE "connection refused|timeout|dial.*failed|cannot.*connect|unavailable" || true; } | \
      wc -l  | xargs)

    VC_PROBE_PORT="${CL_GRPC_PORT:-4000}"
    [[ "$SETUP" == "LIGHTHOUSE" ]] && VC_PROBE_PORT="${CL_REST_PORT:-5052}"

    if [[ "$vc_errors" -eq 0 ]]; then
      pass "Validator → Beacon $CL_SVC:$VC_PROBE_PORT OK (log verification)"
    else
      fail "Validator → Beacon $CL_SVC:$VC_PROBE_PORT has connection errors"
      kubectl logs -n "$NS" "$_VC_POD" -c "$_VC_CTN" --tail=50 --since=2m 2>/dev/null | \
        { grep -iE "beacon|grpc" || true; } | \
        { grep -iE "refused|timeout|failed" || true; } | \
        head -2 | sed 's/^/  /' || true
    fi
  fi


    # ===== PEER INFORMATION =====

    echo ""
    echo "=== Execution Layer Peers ==="
    if [[ -n "$_EL_POD" && -n "$_EL_CTN" ]]; then
      # Use geth attach with proper datadir since curl is not available
      peer_count=$(kubectl exec -n "$NS" "$_EL_POD" -c "$_EL_CTN" -- \
        geth --datadir /data attach --exec 'admin.peers.length' /data/geth.ipc 2>/dev/null | tr -d '\n' || echo "0")

      # Validate it's a number
      if [[ "$peer_count" =~ ^[0-9]+$ ]]; then
        if [[ "$peer_count" -gt 0 ]]; then
          pass "EL has $peer_count peer(s)"

          # Get detailed peer info
          kubectl exec -n "$NS" "$_EL_POD" -c "$_EL_CTN" -- \
            geth --datadir /data attach --exec 'admin.peers.forEach(function(p){console.log("  ["+p.id.substring(0,16)+"...] "+p.name+" via "+p.network.remoteAddress)})' \
            /data/geth.ipc 2>&1 | grep "^\s*\[" || echo "  (peer details unavailable)"
        else
          warn "EL has 0 peers"
        fi
      else
        warn "Could not query EL peer count (got: $peer_count)"
      fi
    fi

    echo ""
    echo "=== Consensus Layer Peers ==="
    if [[ -n "$_CL_POD" && -n "$_CL_CTN" ]]; then
      # Determine API port based on setup
      if [[ "$SETUP" == "PRYSM" ]]; then
        CL_API_PORT="${CL_REST_PORT:-3500}"
      else
        CL_API_PORT="${CL_REST_PORT_LIGHTHOUSE:-5052}"
      fi

      # Use port-forward to query API since curl is not available in containers
      # REMOVED 'local' keyword here
      pf_pid=$(pf_bg pod "$_CL_POD" 18888 "$CL_API_PORT")
      sleep 1  # Give port-forward time to establish

      # Query via localhost port-forward
      peer_info=$(curl -s http://localhost:18888/eth/v1/node/peers 2>/dev/null || echo '{"data":[]}')

      # Kill port-forward
      kill_pf "$pf_pid"

      if echo "$peer_info" | jq -e . >/dev/null 2>&1; then
        peer_count=$(echo "$peer_info" | jq -r '.data | length' 2>/dev/null || echo "0")

        if [[ "$peer_count" -gt 0 ]]; then
          pass "CL has $peer_count peer(s)"
          echo "$peer_info" | jq -r '.data[] | "  \(.peer_id[0:16])... state:\(.state) direction:\(.direction)"' 2>/dev/null || \
            echo "  (peer details unavailable)"
        else
          warn "CL has 0 peers"
        fi
      else
        warn "Could not query CL peers (API not available?)"
      fi
    fi

  else
    fail "Service $EL_SVC not found"
  fi

fi