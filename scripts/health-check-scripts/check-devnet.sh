#!/usr/bin/env bash
set -Eeuo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

export EXIT=0

# Source sections so env vars (EL_POD/CL_POD/.../SVC) persist across sections
run() {
  echo
  echo ">>> $(basename "$1" .sh)"
  set +e
  # shellcheck source=/dev/null
  . "$1"
  local rc=$?
  set -e
  return 0
}

run "$DIR/10_discovery.sh"
run "$DIR/20_network.sh"
run "$DIR/30_jwt.sh"
run "$DIR/40_genesis_and_head.sh"
run "$DIR/50_merge_check.sh"
run "$DIR/60_engine_traffic.sh"
#run "$DIR/90_logs.sh"

# (optional) quick peek at what was discovered—handy if something still seems unset
echo
echo "Discovered vars:"
echo "  K8S_NS=${K8S_NS:-<empty>}  EL_NS=${EL_NS:-<empty>}  EL_POD=${EL_POD:-<empty>}  EL_SVC=${EL_SVC:-<empty>}"
echo "  CL_NS=${CL_NS:-<empty>}  CL_POD=${CL_POD:-<empty>}  CL_SVC=${CL_SVC:-<empty>}  CL_REST=${CL_REST:-<empty>}"
echo "  VC_NS=${VC_NS:-<empty>}  VC_POD=${VC_POD:-<empty>}"


# ===================== 70 images =====================

# Helper: print images for a single pod (spec + resolved imageIDs)
print_pod_images() {
  local ns="$1" pod="$2"
  echo
  echo "Pod: ${ns}/${pod}"

  # Spec (what was requested)
  kubectl -n "$ns" get pod "$pod" -o json \
  | jq -r '
      def rows($kind): (.spec[$kind] // []) | map({name:.name, image:.image});
      (rows("initContainers")[]? | "  init  \(.name): \(.image)"),
      (rows("containers")[]?     | "  run   \(.name): \(.image)")' || true

  # Resolved (what actually ran; includes digests)
  kubectl -n "$ns" get pod "$pod" -o json \
  | jq -r '
      def rows($kind): (.status[$kind] // []) | map({name:.name, imageID:.imageID});
      (rows("initContainerStatuses")[]? | select(.imageID!=null) | "  init  \(.name): \(.imageID)"),
      (rows("containerStatuses")[]?     | select(.imageID!=null) | "  run   \(.name): \(.imageID)")' \
  | sed 's#^docker-pullable://##; s#^containerd://##' || true
}

. "$(dirname "$0")/00_lib.sh"

# ---- safe-inits for control checks (avoid set -u issues) ----
EL_TTD=""; EL_TTD_PASSED=""; EL_GENESIS_DIFFICULTY=""
CL_TBH_SPEC=""; CL_TBH_EPOCH_SPEC=""; CL_SLOT_SECS_SPEC=""
TBH="${TBH:-}"; TBH_EPOCH="${TBH_EPOCH:-}"   # may be set by earlier steps
to_lower(){ printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'; }


# Print EL / CL / VC if the script already discovered them
if [[ -n "${EL_POD:-}" && -n "${EL_NS:-}" ]]; then
  print_pod_images "$EL_NS" "$EL_POD"
fi
if [[ -n "${CL_POD:-}" && -n "${CL_NS:-}" ]]; then
  print_pod_images "$CL_NS" "$CL_POD"
fi
if [[ -n "${VC_POD:-}" && -n "${VC_NS:-}" ]]; then
  print_pod_images "$VC_NS" "$VC_POD"
fi

# Unique list of all images (spec) in the namespace
echo
echo "All images (spec) in namespace ${K8S_NS:-default}:"
kubectl ${K8S_NS:+-n "$K8S_NS"} get pods -o json \
| jq -r '
    [
      .items[]
      | (.spec.initContainers[]?.image),
        (.spec.containers[]?.image)
    ]
    | map(select(.!=null))
    | unique[]' \
| sort

# Unique list of resolved imageIDs/digests (what actually ran)
echo
echo "All resolved imageIDs in namespace ${K8S_NS:-default}:"
kubectl ${K8S_NS:+-n "$K8S_NS"} get pods -o json \
| jq -r '
    [
      .items[]
      | (.status.initContainerStatuses[]?.imageID),
        (.status.containerStatuses[]?.imageID)
    ]
    | map(select(.!=null))
    | map(gsub("^(docker-pullable://|containerd://)"; ""))
    | unique[]' \
| sort



# ===================== 80 control =====================
echo
echo ">>> 80 control"

# ----- CL spec constants (from REST) -----
if [[ -n "${CL_POD:-}" && -n "${CL_SVC:-}" ]]; then
  CL_SPEC_JSON="$(
    kubectl ${CL_NS:+-n "$CL_NS"} exec -i -t "$CL_POD" -- \
      sh -lc "curl -s http://$CL_SVC:${CL_REST:-5052}/eth/v1/config/spec" \
    2>/dev/null || true
  )"
  if [[ -n "${CL_SPEC_JSON:-}" && "${CL_SPEC_JSON:-null}" != "null" ]]; then
    CL_TBH_SPEC="$(echo "$CL_SPEC_JSON" | jq -r '.data.TERMINAL_BLOCK_HASH // .data.terminal_block_hash // empty')"
    CL_TBH_EPOCH_SPEC="$(echo "$CL_SPEC_JSON" | jq -r '.data.TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH // .data.terminal_block_hash_activation_epoch // empty')"
    CL_SLOT_SECS_SPEC="$(echo "$CL_SPEC_JSON" | jq -r '.data.SECONDS_PER_SLOT // .data.seconds_per_slot // empty')"
    echo "CL spec TERMINAL_BLOCK_HASH: ${CL_TBH_SPEC:-<unset>}"
    echo "CL spec TBH_ACTIVATION_EPOCH: ${CL_TBH_EPOCH_SPEC:-<unset>}"
    echo "CL spec SECONDS_PER_SLOT: ${CL_SLOT_SECS_SPEC:-<unset>}"
  else
    warn "CL /eth/v1/config/spec returned empty/null (check CL_REST or readiness)"
  fi
else
  warn "Skipping CL spec dump (CL_POD or CL_SVC unset)"
fi

# ----- EL Merge controls (TTD & Passed) -----
# Try JSON-RPC debug_getChainConfig from inside the CL pod → EL service
EL_CFG_OK=0
if [[ -n "${CL_POD:-}" && -n "${EL_SVC:-}" ]]; then
  DBG_CFG="$(
    kubectl ${CL_NS:+-n "$CL_NS"} exec -i -t "$CL_POD" -- sh -lc \
      "curl -s -H 'Content-Type: application/json' \
         --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"debug_getChainConfig\",\"params\":[]}' \
         http://$EL_SVC:${EL_RPC:-8545}" 2>/dev/null || true
  )"
  if echo "${DBG_CFG:-}" | jq -e '.result' >/dev/null 2>&1; then
    EL_TTD="$(echo "$DBG_CFG" | jq -r '.result.terminalTotalDifficulty // .result.terminal_total_difficulty // empty')"
    EL_TTD_PASSED="$(echo "$DBG_CFG" | jq -r '.result.terminalTotalDifficultyPassed // .result.terminal_total_difficulty_passed // empty')"
    if [[ -n "$EL_TTD" ]]; then
      echo "EL chain config terminalTotalDifficulty: $EL_TTD"
      echo "EL chain config terminalTotalDifficultyPassed: ${EL_TTD_PASSED:-<unset>}"
      EL_CFG_OK=1
    fi
  fi
fi

# Fallback: read genesis.json inside the EL pod (common paths)
if (( EL_CFG_OK != 1 )) && [[ -n "${EL_POD:-}" ]]; then
  for GEN in /config/genesis.json /genesis.json /data/genesis.json /etc/genesis.json; do
    RAW="$(
      kubectl ${EL_NS:+-n "$EL_NS"} exec -i -t "$EL_POD" -- \
        sh -lc "[ -s '$GEN' ] && cat '$GEN' || true" 2>/dev/null
    )"
    if [[ -n "${RAW:-}" ]]; then
      EL_GENESIS_DIFFICULTY="$(echo "$RAW" | jq -r '.difficulty // empty')"
      EL_TTD="$(echo "$RAW" | jq -r '.config.terminalTotalDifficulty // .terminalTotalDifficulty // empty')"
      EL_TTD_PASSED="$(echo "$RAW" | jq -r '.config.terminalTotalDifficultyPassed // .terminalTotalDifficultyPassed // empty')"
      echo "EL genesis ($GEN) difficulty: ${EL_GENESIS_DIFFICULTY:-<unset>}"
      [[ -n "$EL_TTD" ]] && echo "EL genesis ($GEN) terminalTotalDifficulty: $EL_TTD"
      [[ -n "$EL_TTD_PASSED" ]] && echo "EL genesis ($GEN) terminalTotalDifficultyPassed: $EL_TTD_PASSED"
      break
    fi
  done
fi

# ----- Verdicts (soft: allow inference if we can't read directly) -----
if [[ -n "${EL_TTD:-}" ]]; then
  # TTD
  case "$EL_TTD" in
    1|"1"|"0x1"|"\"0x1\"") pass "EL terminalTotalDifficulty is 1 (instant-merge devnet)";;
    *)                      warn "EL terminalTotalDifficulty is ${EL_TTD} (expected 1 for instant-merge devnets)";;
  esac
  # TTD_PASSED
  norm_passed="$(to_lower "${EL_TTD_PASSED:-}")"
  case "$norm_passed" in
    true|1|"\"true\"") pass "EL terminalTotalDifficultyPassed = true";;
    "")                warn "EL terminalTotalDifficultyPassed is unset";;
    *)                 warn "EL terminalTotalDifficultyPassed != true (engine may not start at block 1)";;
  esac
else
  # Inference fallback: compare CL execution payload block number vs EL head
  if [[ -n "${CL_POD:-}" && -n "${CL_SVC:-}" && -n "${EL_SVC:-}" ]]; then
    CL_BN="$(
      kubectl ${CL_NS:+-n "$CL_NS"} exec -i -t "$CL_POD" -- sh -lc \
        "curl -s http://$CL_SVC:${CL_REST:-5052}/eth/v2/beacon/blocks/head" \
      2>/dev/null | jq -r '.data.message.body.execution_payload.block_number // .data.message.body.execution_payload.blockNumber' 2>/dev/null || true
    )"
    EL_BN_HEX="$(
      kubectl ${CL_NS:+-n "$CL_NS"} exec -i -t "$CL_POD" -- sh -lc \
        "curl -s -H 'Content-Type: application/json' \
           --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_blockNumber\",\"params\":[]}' \
           http://$EL_SVC:${EL_RPC:-8545}" \
      2>/dev/null | jq -r '.result' 2>/dev/null || true
    )"
    if [[ "$CL_BN" =~ ^[0-9]+$ && "$EL_BN_HEX" =~ ^0x[0-9a-fA-F]+$ ]]; then
      EL_BN=$((16#${EL_BN_HEX#0x})); DELTA=$(( EL_BN - CL_BN ))
      if (( DELTA >= -1 && DELTA <= 1 )); then
        pass "Merge-by-TTD inferred: CL payload=${CL_BN} ≈ EL head=${EL_BN} (|Δ|≤1)"
      else
        warn "Cannot confirm Merge from heads: CL payload=${CL_BN}, EL head=${EL_BN} (Δ=${DELTA})"
        echo "     → Expose Geth debug API or mount a readable genesis.json for direct TTD read."
      fi
    else
      warn "TTD unknown and inference unavailable (REST/RPC unreachable from CL pod)."
      echo "     → Ensure CL_REST and EL_RPC ports are correct; consider exposing 'debug' in --http.api."
    fi
  else
    warn "TTD unknown and inference skipped (CL_POD/CL_SVC/EL_SVC unset)."
  fi
fi

