#!/usr/bin/env bash
set -euo pipefail

# check-devnet-kind.sh (kind/k8s Kurtosis devnet checker)
# - Uses local port-forwards for JSON-RPC calls (no curl needed in pods)
# - Discovers EL by port 8551 if not pinned
# - Supports Lighthouse/Prysm flag variants

# ===================== Config =====================
K8S_NS="${K8S_NS:-}"           # e.g., kt-devnet-ref
TIMEOUT="${TIMEOUT:-5}"

# Ports inside the cluster
EL_AUTH="${EL_AUTH:-8551}"     # Engine API (JWT)
EL_RPC="${EL_RPC:-8545}"       # Execution JSON-RPC
CL_REST="${CL_REST:-}"         # Will autodetect (5052 or 4000) if empty

# Local ports for port-forward
EL_LOCAL="${EL_LOCAL:-18545}"
CL_LOCAL="${CL_LOCAL:-15052}"

# Slot timing defaults (safe with `set -u`)
SLOT_SECONDS="${SLOT_SECONDS:-12}"
ADVANCE_WAIT="${ADVANCE_WAIT:-$SLOT_SECONDS}"


# Pod/service discovery regexes (used only if you don't pin names)
EL_RE="${EL_RE:-geth|reth|nethermind|erigon}"
CL_RE="${CL_RE:-lighthouse|prysm|teku|nimbus|beacon}"
VC_RE="${VC_RE:-validator|prysm-validator|lighthouse-validator|teku-validator|nimbus-validator}"

CURL=(curl -sS --max-time "$TIMEOUT")
trap 'cleanup' EXIT

# ===================== Pretty =====================
info(){ printf "\n>>> %s\n\n" "$1"; }
pass(){ printf "PASS %s\n" "$1"; }
fail(){ printf "FAIL %s\n" "$1"; }
warn(){ printf "WARN %s\n" "$1"; }

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }; }
need kubectl; need jq; need curl

ns_args=()
[[ -n "$K8S_NS" ]] && ns_args=(-n "$K8S_NS")
kget(){ kubectl "${ns_args[@]}" "$@"; }

# ===================== Helpers =====================
pick_first_running_pod_by_regex() {
  local regex="$1"
  kget get pods -o json \
  | jq -r --arg re "$regex" '
      [.items[]
        | select(.metadata.name|test($re;"i"))
        | select(.status.phase=="Running")]
      | (.[0] // empty)
      | if .==null then "" else "\(.metadata.namespace) \(.metadata.name)" end'
}

pick_first_running_pod_by_port() {
  local port="$1"
  kget get pods -o json \
  | jq -r --argjson p "$port" '
      [.items[]
        | select(any(.spec.containers[]?.ports[]?; .containerPort==$p))
        | select(.status.phase=="Running")]
      | (.[0] // empty)
      | if .==null then "" else "\(.metadata.namespace) \(.metadata.name)" end'
}

find_service_by_port() {
  local port="$1"
  kget get svc -o json \
  | jq -r --argjson p "$port" '
      [.items[] | select(any(.spec.ports[]?; .port==$p))]
      | (.[0] // empty) | .metadata.name' \
  | sed '/^null$/d' | head -n1
}

find_service_by_hint() {
  local hint="$1"
  kget get svc -o json \
  | jq -r --arg h "$hint" '
      [.items[] | select(.metadata.name|test($h;"i"))]
      | (.[0] // empty) | .metadata.name' \
  | sed '/^null$/d' | head -n1
}

svc_ports_pretty(){
  local svc="$1"
  kget get svc "$svc" -o json \
  | jq -r '.spec.ports[] | "  \(.name)//\(.port)/\(.protocol)"'
}

svc_has_port(){
  local svc="$1" port="$2"
  kget get svc "$svc" -o json | jq -e --argjson p "$port" 'any(.spec.ports[]?; .port==$p)' >/dev/null
}

get_endpoints_for_port(){
  local svc="$1" port="$2"
  kget get endpoints "$svc" -o json \
  | jq -r --argjson p "$port" '
      .subsets[]?
      | (.addresses[]?.ip) as $ip
      | .ports[]? | select(.port==$p)
      | "\($ip):\(.port)"' || true
}

pod_cmd(){ local ns="$1" pod="$2"; shift 2; kget exec -i -t -n "$ns" "$pod" -- "$@" 2>/dev/null; }

tcp_check_from_pod(){
  local ns="$1" pod="$2" host="$3" port="$4" label="$5"
  # nc
  if pod_cmd "$ns" "$pod" sh -lc 'command -v nc >/dev/null 2>&1'; then
    if pod_cmd "$ns" "$pod" sh -lc "nc -z -w $TIMEOUT $host $port"; then pass "$label TCP $host:$port OK"; return 0; else fail "$label TCP $host:$port FAILED"; return 1; fi
  fi
  # curl
  if pod_cmd "$ns" "$pod" sh -lc 'command -v curl >/dev/null 2>&1'; then
    if pod_cmd "$ns" "$pod" sh -lc "curl -sS --connect-timeout $TIMEOUT http://$host:$port >/dev/null || true"; then pass "$label TCP $host:$port OK"; return 0; else fail "$label TCP $host:$port FAILED"; return 1; fi
  fi
  # /dev/tcp fallback
  if pod_cmd "$ns" "$pod" sh -lc "timeout $TIMEOUT bash -lc '</dev/tcp/$host/$port' >/dev/null 2>&1"; then
    pass "$label TCP $host:$port OK"; return 0
  else
    fail "$label TCP $host:$port FAILED"; return 1
  fi
}

extract_cmdline(){ kget exec -n "$2" "$3" -- sh -lc 'tr "\0" " " < /proc/1/cmdline' 2>/dev/null || true; } # kept for symmetry; unused

get_cmdline(){
  local ns="$1" pod="$2"
  kget exec -n "$ns" "$pod" -- sh -lc 'tr "\0" " " < /proc/1/cmdline' 2>/dev/null || true
}

try_read_jwt(){
  local ns="$1" pod="$2"
  # common file paths
  for p in /data/jwt.hex /config/jwt.hex /jwt/jwtsecret /jwtsecret/jwt.hex /var/lib/jwt.hex; do
    if pod_cmd "$ns" "$pod" sh -lc "[ -s $p ] && cat $p" >/dev/null; then
      pod_cmd "$ns" "$pod" sh -lc "cat $p" && return 0
    fi
  done
  # parse from flags
  local line path
  line="$(get_cmdline "$ns" "$pod")"
  path="$(printf '%s' "$line" | grep -Eo -- '--jwt-secret(=| )[^\ ]+|--execution-jwt(=| )[^\ ]+|--jwt-secrets(=| )[^\ ]+' | head -n1 | sed -E 's/^--(jwt-secret|execution-jwt|jwt-secrets)(=| )//')"
  if [[ -n "$path" ]]; then pod_cmd "$ns" "$pod" sh -lc "[ -s '$path' ] && cat '$path'" 2>/dev/null && return 0; fi
  return 1
}

hexhash(){ printf "%s" "$1" | sha256sum | awk '{print $1}'; }

# Local JSON-RPC/REST via forwarded ports
el_rpc_local(){
  local method="$1" params="${2:-[]}"
  "${CURL[@]}" -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}" \
    "http://127.0.0.1:${EL_LOCAL}"
}

beacon_get_local(){
  local path="$1" # e.g. /eth/v1/node/health
  "${CURL[@]}" "http://127.0.0.1:${CL_LOCAL}${path}"
}

# Port-forward helpers
EL_PF_PID=""; CL_PF_PID=""
cleanup(){
  [[ -n "$EL_PF_PID" ]] && kill "$EL_PF_PID" 2>/dev/null || true
  [[ -n "$CL_PF_PID" ]] && kill "$CL_PF_PID" 2>/dev/null || true
}

start_pf_svc(){
  local svc="$1" lport="$2" rport="$3" label="$4"
  kubectl "${ns_args[@]}" port-forward "svc/${svc}" "${lport}:${rport}" >/dev/null 2>&1 &
  local pid=$!
  sleep 2
  echo "$pid"
}

# ===================== 10_discovery =====================
info "10_discovery"

# Prefer explicit pins; otherwise discover
if [[ -z "${EL_POD:-}" ]]; then
  read EL_NS EL_POD <<<"$(pick_first_running_pod_by_port "$EL_AUTH" || true)"
  [[ -z "${EL_POD:-}" ]] && read EL_NS EL_POD <<<"$(pick_first_running_pod_by_regex "$EL_RE" || true)"
else
  EL_NS="${K8S_NS:-default}"
fi

if [[ -z "${CL_POD:-}" ]]; then
  read CL_NS CL_POD <<<"$(pick_first_running_pod_by_regex "$CL_RE" || true)"
else
  CL_NS="${K8S_NS:-default}"
fi

if [[ -z "${VC_POD:-}" ]]; then
  read VC_NS VC_POD <<<"$(pick_first_running_pod_by_regex "$VC_RE" || true)"
else
  VC_NS="${K8S_NS:-default}"
fi

[[ -n "${EL_POD:-}" ]] && pass "Found EL pod: $EL_POD" || fail "EL pod not found"
[[ -n "${CL_POD:-}" ]] && pass "Found CL pod: $CL_POD" || fail "CL pod not found"
[[ -n "${VC_POD:-}" ]] && pass "Found VC pod: $VC_POD" || warn "VC pod not found (may be OK)"

# ===================== 20_network =====================
info "20_network"

# EL service (prefer one with 8551)
if [[ -z "${EL_SVC:-}" ]]; then
  EL_SVC="$(find_service_by_port "$EL_AUTH" || true)"
fi
[[ -z "${EL_SVC:-}" && -n "${EL_POD:-}" ]] && EL_SVC="$(find_service_by_hint "$EL_POD" || true)"

if [[ -n "${EL_SVC:-}" ]]; then
  pass "Service $EL_SVC present"
  echo "Ports on $EL_SVC:"
  svc_ports_pretty "$EL_SVC" || true
  if svc_has_port "$EL_SVC" "$EL_AUTH"; then
    pass "Service exposes Engine API port $EL_AUTH"
  else
    fail "Service missing Engine API port $EL_AUTH"
  fi
  if kget get endpoints "$EL_SVC" >/dev/null 2>&1; then
    pass "Endpoints exist for $EL_SVC"
    ep="$(get_endpoints_for_port "$EL_SVC" "$EL_AUTH" | paste -sd, -)"
    echo "Endpoint(s) on $EL_AUTH: ${ep:-None}"
  else
    fail "No Endpoints for $EL_SVC"
  fi
else
  fail "Could not find EL service"
fi

# CL service guess if not pinned
if [[ -z "${CL_SVC:-}" && -n "${CL_POD:-}" ]]; then
  CL_SVC="$(find_service_by_hint "$CL_POD" || true)"
fi

NS="${K8S_NS:-default}"
EL_FQDN="${EL_SVC:-}.${NS}.svc"
CL_FQDN="${CL_SVC:-}.${NS}.svc"

# Beacon flags (supports Lighthouse & Prysm)
if [[ -n "${CL_POD:-}" ]]; then
  echo "Beacon args:"
  cmdline="$(get_cmdline "$CL_NS" "$CL_POD")"
  echo "Beacon cmd:  $cmdline"

  check_flag(){ printf '%s' "$cmdline" | grep -F -q -- "$1"; }

  # --execution-endpoint(s)
  if check_flag "--execution-endpoint=http://${EL_SVC}:${EL_AUTH}"; then
    pass "Beacon flag present: --execution-endpoint=http://${EL_SVC}:${EL_AUTH}"
  elif check_flag "--execution-endpoints=http://${EL_SVC}:${EL_AUTH}"; then
    pass "Beacon flag present: --execution-endpoints=http://${EL_SVC}:${EL_AUTH}"
  elif check_flag "--execution-endpoint=http://${EL_FQDN}:${EL_AUTH}"; then
    pass "Beacon flag present: --execution-endpoint=http://${EL_FQDN}:${EL_AUTH}"
  elif check_flag "--execution-endpoints=http://${EL_FQDN}:${EL_AUTH}"; then
    pass "Beacon flag present: --execution-endpoints=http://${EL_FQDN}:${EL_AUTH}"
  else
    warn "Beacon --execution-endpoint(s) not found"
  fi

  # JWT variants
  if check_flag "--jwt-secret="; then
    pass "Beacon flag present: --jwt-secret"
  elif check_flag "--execution-jwt="; then
    pass "Beacon flag present: --execution-jwt"
  elif check_flag "--jwt-secrets="; then
    pass "Beacon flag present: --jwt-secrets"
  else
    warn "Beacon JWT flag not found (Prysm: --jwt-secret, LH: --execution-jwt/--jwt-secrets)"
  fi

  check_flag "--min-sync-peers=0" && pass "Beacon flag present: --min-sync-peers=0" || true
  check_flag "--subscribe-all-subnets" && pass "Beacon flag present: --subscribe-all-subnets" || true
fi

# In-cluster TCP reachability
[[ -n "${CL_POD:-}" && -n "${EL_SVC:-}" ]] && tcp_check_from_pod "$CL_NS" "$CL_POD" "$EL_SVC" "$EL_AUTH" "Beacon → EL"
[[ -n "${VC_POD:-}" && -n "${CL_SVC:-}" ]] && { 
  # autodetect CL_REST if not set
  if [[ -z "${CL_REST:-}" ]]; then
    maybe="$(kget get svc "$CL_SVC" -o json | jq -r '(.spec.ports[]? | select(.port==5052) | .port), (.spec.ports[]? | select(.port==4000) | .port)' | head -n1)"
    [[ -n "$maybe" ]] && CL_REST="$maybe"
  fi
  tcp_check_from_pod "$VC_NS" "$VC_POD" "$CL_SVC" "$CL_REST" "Validator → Beacon"
}

# ===================== 30_jwt =====================
info "30 jwt"

JWT_EL=""; JWT_CL=""
[[ -n "${EL_POD:-}" ]] && JWT_EL="$(try_read_jwt "$EL_NS" "$EL_POD" 2>/dev/null || true)"
[[ -n "${CL_POD:-}" ]] && JWT_CL="$(try_read_jwt "$CL_NS" "$CL_POD" 2>/dev/null || true)"

if [[ -n "$JWT_EL" && -n "$JWT_CL" ]]; then
  h1="$(hexhash "$JWT_EL")"; h2="$(hexhash "$JWT_CL")"
  if [[ "$h1" == "$h2" ]]; then pass "JWT hashes match ($h1)"; else fail "JWT mismatch: EL $h1 vs CL $h2"; fi
else
  warn "Could not read JWT from one or both pods"
fi

# ===================== Port-forward (for JSON calls) =====================
# Only start PFs if services are known
if [[ -n "${EL_SVC:-}" ]]; then
  EL_PF_PID="$(start_pf_svc "$EL_SVC" "$EL_LOCAL" "$EL_RPC" "EL RPC")"
fi
if [[ -n "${CL_SVC:-}" && -n "${CL_REST:-}" ]]; then
  CL_PF_PID="$(start_pf_svc "$CL_SVC" "$CL_LOCAL" "$CL_REST" "CL REST")"
fi

# ===================== 40_genesis_and_head =====================
info "40 genesis and head"

EL_OK=0; CL_OK=0

# EL block0 timestamp
b0json="$(el_rpc_local "eth_getBlockByNumber" "[\"0x0\", false]" || true)"
genesis_ts_hex="$(echo "$b0json" | jq -r '.result.timestamp' 2>/dev/null || true)"
if [[ -n "$genesis_ts_hex" && "$genesis_ts_hex" != "null" ]]; then
  genesis_ts_dec="$((16#${genesis_ts_hex#0x}))"
  pass "EL block0 timestamp: $genesis_ts_dec"
  EL_OK=1
else
  fail "Could not read EL block0 timestamp"
fi

# CL genesis time
gjson="$(beacon_get_local "/eth/v1/beacon/genesis" || true)"
cl_genesis_time="$(echo "$gjson" | jq -r '.data.genesis_time' 2>/dev/null || echo "")"
if [[ "$cl_genesis_time" =~ ^[0-9]+$ ]]; then
  pass "CL genesis_time: $cl_genesis_time"
  CL_OK=1
else
  fail "Could not read CL genesis_time"
fi

if (( EL_OK==1 && CL_OK==1 )); then
  if [[ "${genesis_ts_dec:-}" == "$cl_genesis_time" ]]; then
    pass "EL/CL genesis match"
  else
    fail "EL/CL genesis mismatch: EL=${genesis_ts_dec:-?} CL=${cl_genesis_time:-?}"
  fi
fi

# EL head number
head_hex="$(el_rpc_local "eth_blockNumber" "[]" | jq -r '.result' 2>/dev/null || true)"
[[ -n "$head_hex" && "$head_hex" != "null" ]] && pass "EL blockNumber: $head_hex" || fail "EL blockNumber unavailable"

# CL head, peers, syncing, slot drift
head_hdr="$(beacon_get_local "/eth/v1/beacon/headers/head" || true)"
head_slot="$(echo "$head_hdr" | jq -r '.data.header.message.slot' 2>/dev/null || echo "")"
if [[ "$head_slot" =~ ^[0-9]+$ ]]; then
# Wait a full slot (or override via ADVANCE_WAIT)
  ADVANCE_WAIT="${ADVANCE_WAIT:-$SLOT_SECONDS}"
  sleep "$ADVANCE_WAIT"

  head_hdr2="$(beacon_get_local "/eth/v1/beacon/headers/head" || true)"
  head_slot2="$(echo "$head_hdr2" | jq -r '.data.header.message.slot' 2>/dev/null || echo "")"
  if [[ "$head_slot2" =~ ^[0-9]+$ ]] && (( head_slot2 > head_slot )); then
    pass "CL head advancing (slot ${head_slot} → ${head_slot2})"
  else
    warn "CL head NOT advancing (stuck at ${head_slot})"
  fi
else
  fail "CL head slot unavailable"
fi

peers_json="$(beacon_get_local "/eth/v1/node/peer_count" || true)"
peers="$(echo "$peers_json" | jq -r '.data.connected' 2>/dev/null || echo "")"
[[ "$peers" =~ ^[0-9]+$ ]] && echo "Beacon peer_count: $peers"

syncing_json="$(beacon_get_local "/eth/v1/node/syncing" || true)"
syncing="$(echo "$syncing_json" | jq -r '.data.is_syncing // .data.syncing // empty')"
echo "Beacon syncing:    ${syncing:-}"

SLOT_SECONDS="${SLOT_SECONDS:-12}"
now="$(date +%s)"
if [[ "${cl_genesis_time:-}" =~ ^[0-9]+$ && "${head_slot:-}" =~ ^[0-9]+$ ]]; then
  expected=$(( (now - cl_genesis_time) / SLOT_SECONDS ))
  drift=$(( expected - head_slot ))
  echo "Slot check: expected=${expected} head=${head_slot} drift=${drift}"
  (( drift > SLOT_SECONDS*10 )) && warn "Slot drift large (${drift})"
fi

# ===================== 50_merge_check =====================
info "50 merge check"

b0hash="$(el_rpc_local "eth_getBlockByNumber" "[\"0x0\", false]" | jq -r '.result.hash' 2>/dev/null || true)"
[[ -n "$b0hash" && "$b0hash" != "null" ]] && echo "EL block0 hash: $b0hash"

# Try reading CL TTD files if present (best-effort)
if [[ -n "${CL_POD:-}" ]]; then
  TBH="$(pod_cmd "$CL_NS" "$CL_POD" sh -lc 'cat /data/testnet_spec/terminal_block_hash.txt 2>/dev/null' || true)"
  TBH_EPOCH="$(pod_cmd "$CL_NS" "$CL_POD" sh -lc 'cat /data/testnet_spec/terminal_block_hash_activation_epoch.txt 2>/dev/null' || true)"
  [[ -z "$TBH" ]] && TBH="0x0000000000000000000000000000000000000000000000000000000000000000"
  [[ -z "$TBH_EPOCH" ]] && TBH_EPOCH="18446744073709551615"
  echo "CL file TBH: $TBH"
  echo "CL file TBH_EPOCH: $TBH_EPOCH"
fi

# ===================== 60_engine_traffic =====================
info "60 engine traffic"

LOG_SINCE="${LOG_SINCE:-15m}"
engine_logs_ok=0

if [[ -n "${EL_POD:-}" ]]; then
  # 1) Plaintext grep
  if kget logs -n "$EL_NS" "$EL_POD" --since="$LOG_SINCE" 2>/dev/null \
     | grep -Eiq 'engine_newPayload|engine_forkchoiceUpdated|NewPayloadV|ForkchoiceUpdatedV|payload|forkchoice|Engine API|engine api'; then
    pass "Recent engine payload/forkchoice seen in EL logs (last $LOG_SINCE)"
    engine_logs_ok=1
  else
    # 2) JSON logs: extract .msg/.message and grep
    if kget logs -n "$EL_NS" "$EL_POD" --since="$LOG_SINCE" 2>/dev/null \
       | jq -r 'select(type=="object") | (.msg // .message // "")' 2>/dev/null \
       | grep -Eiq 'payload|forkchoice|engine'; then
      pass "Recent engine payload/forkchoice seen in EL JSON logs (last $LOG_SINCE)"
      engine_logs_ok=1
    fi
  fi

  if [[ $engine_logs_ok -ne 1 ]]; then
    # 3) Inference fallback: compare CL execution payload block_number vs EL head
    head_exec_bn="$(beacon_get_local "/eth/v2/beacon/blocks/head" \
      | jq -r '.data.message.body.execution_payload.block_number // .data.message.body.execution_payload.blockNumber' 2>/dev/null || true)"
    el_head_hex="$(el_rpc_local "eth_blockNumber" "[]" | jq -r '.result' 2>/dev/null || true)"
    if [[ "$head_exec_bn" =~ ^[0-9]+$ && "$el_head_hex" =~ ^0x[0-9a-fA-F]+$ ]]; then
      el_head_dec=$((16#${el_head_hex#0x}))
      diff=$(( el_head_dec - head_exec_bn ))
      # Accept small skew; in tiny devnets EL can be slightly ahead/behind temporarily
      if (( diff <= 1 && diff >= -1 )); then
        pass "Engine traffic inferred: CL payload block_number=$head_exec_bn ≈ EL head=$el_head_dec"
      else
        fail "No engine log match; CL payload block_number=$head_exec_bn, EL head=$el_head_dec (skew $diff)"
        echo "     → Logs may be JSON or at a different verbosity; see README comment in script."
      fi
    else
      fail "No recent engine payload/forkchoice logs and could not infer from heads."
      echo "     → Try: kubectl -n $EL_NS logs $EL_POD --since=$LOG_SINCE | jq -r '.msg? // .message? // empty' | grep -Ei 'payload|forkchoice|engine'"
    fi
  fi
else
  warn "Skipping engine traffic check (no EL pod)"
fi



# ===================== 70 images =====================
info "70 images"

print_pod_images(){
  local ns="$1" pod="$2"
  echo
  echo "Pod: ${ns}/${pod}"
  # Spec images (what was requested)
  kget get pod "$pod" -n "$ns" -o json \
  | jq -r '
      def row($kind): . as $p
        | ($p.spec[$kind] // [])
        | map({name:.name, image:.image})
        | .[];
      (row("initContainers") | "  init  \(.name): \(.image)"),
      (row("containers")     | "  run   \(.name): \(.image)")
    ' 2>/dev/null || true

  # Resolved images (what actually ran, with digests)
  kget get pod "$pod" -n "$ns" -o json \
  | jq -r '
      def row($kind): . as $p
        | ($p.status[$kind] // [])
        | map({name:.name, imageID:.imageID})
        | .[];
      (row("initContainerStatuses") | select(.imageID!=null) | "  init  \(.name): \(.imageID)"),
      (row("containerStatuses")     | select(.imageID!=null) | "  run   \(.name): \(.imageID)")
    ' 2>/dev/null | sed 's#docker-pullable://##; s#containerd://##' || true
}

# Print for EL / CL / VC specifically (if discovered)
[[ -n "${EL_POD:-}" ]] && print_pod_images "$EL_NS" "$EL_POD"
[[ -n "${CL_POD:-}" ]] && print_pod_images "$CL_NS" "$CL_POD"
[[ -n "${VC_POD:-}" ]] && print_pod_images "$VC_NS" "$VC_POD"

# Unique list of all images in namespace (spec + init) for quick comparison
echo
echo "All images in namespace ${K8S_NS:-default}:"
kget get pods -o json \
| jq -r '
    [
      .items[]
      | (.spec.initContainers[]?.image),
        (.spec.containers[]?.image)
    ] | unique[]' \
| sort

# Unique list of resolved imageIDs/digests (what actually ran)
echo
echo "All resolved imageIDs in namespace ${K8S_NS:-default}:"
kget get pods -o json \
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
info "80 control"

# Show CL spec constants (Lighthouse/Prysm expose these on /eth/v1/config/spec)
spec_json="$(beacon_get_local "/eth/v1/config/spec" 2>/dev/null || true)"
if [[ -n "$spec_json" && "$spec_json" != "null" ]]; then
  TBH_SPEC="$(echo "$spec_json" | jq -r '.data.TERMINAL_BLOCK_HASH // .data.terminal_block_hash // empty')"
  TBH_EPOCH_SPEC="$(echo "$spec_json" | jq -r '.data.TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH // .data.terminal_block_hash_activation_epoch // empty')"
  SLOT_SECS_SPEC="$(echo "$spec_json" | jq -r '.data.SECONDS_PER_SLOT // .data.seconds_per_slot // empty')"
  echo "CL spec TERMINAL_BLOCK_HASH: ${TBH_SPEC:-<unset>}"
  echo "CL spec TBH_ACTIVATION_EPOCH: ${TBH_EPOCH_SPEC:-<unset>}"
  echo "CL spec SECONDS_PER_SLOT: ${SLOT_SECS_SPEC:-<unset>}"
else
  warn "CL /eth/v1/config/spec not available via local port-forward"
fi

# Compare file-based TBH/TBH_EPOCH (if we printed them earlier) vs spec
if [[ -n "${TBH:-}" || -n "${TBH_EPOCH:-}" ]]; then
  echo "CL file TBH (earlier): ${TBH:-<unknown>}"
  echo "CL file TBH_EPOCH (earlier): ${TBH_EPOCH:-<unknown>}"
fi

# Attempt to read EL chain config from Geth (debug_getChainConfig)
el_chain_cfg="$(el_rpc_local "debug_getChainConfig" "[]" 2>/dev/null || true)"
if echo "$el_chain_cfg" | jq -e '.result' >/dev/null 2>&1; then
  TTD="$(echo "$el_chain_cfg" | jq -r '.result.terminalTotalDifficulty // .result.terminal_total_difficulty // empty')"
  TTD_PASSED="$(echo "$el_chain_cfg" | jq -r '.result.terminalTotalDifficultyPassed // .result.terminal_total_difficulty_passed // empty')"
  echo "EL chain config terminalTotalDifficulty: ${TTD:-<unavailable>}"
  echo "EL chain config terminalTotalDifficultyPassed: ${TTD_PASSED:-<unavailable>}"
else
  warn "EL debug_getChainConfig not available (debug RPC likely disabled)."
  warn "If you need TTD here, enable geth debug API on JSON-RPC or inspect genesis.json in the EL pod."
fi

# ===================== 90 logs =====================
info "90 logs"

LOG_TAIL="${LOG_TAIL:-80}"     # how many lines to show per component
LOG_SINCE="${LOG_SINCE:-15m}"  # already used above; keep same default

show_logs_smart(){
  local ns="$1" pod="$2" label="$3"
  echo
  echo "---- ${label} (${ns}/${pod}) last ${LOG_TAIL} lines ----"
  # Try JSON logs: show message field if present, else raw
  raw="$(kget logs -n "$ns" "$pod" --since="$LOG_SINCE" 2>/dev/null || true)"
  if printf '%s' "$raw" | head -n1 | jq -e . >/dev/null 2>&1; then
    # JSON logs; print a compact view with timestamp + msg if available
    printf '%s' "$raw" \
      | jq -r '[.ts, .time, .level, .lvl, .msg, .message]
                | {( (.[0]//.[1]//"" )    ):null} as $t
                | [(.[2]//.[3]//"")] as $lvl
                | (.[4]//.[5]//"") as $m
                | "\($t|keys|.[0]) [\($lvl|.[0])] \($m)"' 2>/dev/null \
      | tail -n "$LOG_TAIL"
  else
    # Plaintext logs
    printf '%s' "$raw" | tail -n "$LOG_TAIL"
  fi
}

[[ -n "${EL_POD:-}" ]] && show_logs_smart "$EL_NS" "$EL_POD" "EL logs"
[[ -n "${CL_POD:-}" ]] && show_logs_smart "$CL_NS" "$CL_POD" "CL logs"
[[ -n "${VC_POD:-}" ]] && show_logs_smart "$VC_NS" "$VC_POD" "VC logs"
