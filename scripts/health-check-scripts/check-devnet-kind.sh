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
# --- init/guards so set -u won't blow up ---

TTD=""; TTD_PASSED=""; DIFF_HEX=""
TBH_SPEC=""; TBH_EPOCH_SPEC=""; SLOT_SECS_SPEC=""
# If earlier file-based TBH vars weren't set, make them safe:
TBH="${TBH:-}"; TBH_EPOCH="${TBH_EPOCH:-}"

to_lower(){ printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'; }


# ----- CL spec constants (from REST) -----
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

# Keep file-based TBH (if earlier block set them)
if [[ -n "${TBH:-}" || -n "${TBH_EPOCH:-}" ]]; then
  echo "CL file TBH (earlier): ${TBH:-<unknown>}"
  echo "CL file TBH_EPOCH (earlier): ${TBH_EPOCH:-<unknown>}"
fi

# ----- EL Merge controls (TTD & Passed) -----
# Try JSON-RPC debug_getChainConfig via local PF first
el_chain_cfg="$(el_rpc_local "debug_getChainConfig" "[]" 2>/dev/null || true)"
EL_CFG_OK=0
if echo "$el_chain_cfg" | jq -e '.result' >/dev/null 2>&1; then
  TTD="$(echo  "$el_chain_cfg" | jq -r '.result.terminalTotalDifficulty // .result.terminal_total_difficulty // empty')"
  TTD_PASSED="$(echo "$el_chain_cfg" | jq -r '.result.terminalTotalDifficultyPassed // .result.terminal_total_difficulty_passed // empty')"
  if [[ -n "$TTD" ]]; then
    echo "EL chain config terminalTotalDifficulty: $TTD"
    echo "EL chain config terminalTotalDifficultyPassed: ${TTD_PASSED:-<unset>}"
    EL_CFG_OK=1
  fi
fi

# Fallback: read genesis.json from EL pod (common paths)
if [[ $EL_CFG_OK -ne 1 && -n "${EL_POD:-}" ]]; then
  for GEN in /config/genesis.json /genesis.json /data/genesis.json /etc/genesis.json; do
    raw="$(pod_cmd "$EL_NS" "$EL_POD" sh -lc "[ -s '$GEN' ] && cat '$GEN' || true")"
    if [[ -n "$raw" ]]; then
      TTD="$(echo "$raw" | jq -r '.config.terminalTotalDifficulty // .terminalTotalDifficulty // empty')"
      TTD_PASSED="$(echo "$raw" | jq -r '.config.terminalTotalDifficultyPassed // .terminalTotalDifficultyPassed // empty')"
      DIFF_HEX="$(echo "$raw" | jq -r '.difficulty // empty')"
      echo "EL genesis ($GEN) difficulty: ${DIFF_HEX:-<unset>}"
      [[ -n "$TTD" ]] && echo "EL genesis ($GEN) terminalTotalDifficulty: $TTD"
      [[ -n "$TTD_PASSED" ]] && echo "EL genesis ($GEN) terminalTotalDifficultyPassed: $TTD_PASSED"
      break
    fi
  done
fi

# Verdicts (soft: allow fallbacks + inference)
to_lower(){ printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'; }

if [[ -n "${TTD:-}" ]]; then
  # normalize "true"/true/"1"
  TTD_PASSED_NORM="$(to_lower "${TTD_PASSED:-}")"

  # TTD value verdict
  case "${TTD}" in
    1|"1"|"0x1"|"\"0x1\"")
      pass "EL terminalTotalDifficulty is 1 (Merge-by-TTD set)"
      ;;
    *)
      warn "EL terminalTotalDifficulty is ${TTD} (expected 1 for instant-merge devnets)"
      ;;
  esac

  # TTD_PASSED verdict
  case "${TTD_PASSED_NORM}" in
    true|1|"\"true\"")
      pass "EL terminalTotalDifficultyPassed = true"
      ;;
    "")
      warn "EL terminalTotalDifficultyPassed is unset"
      ;;
    *)
      warn "EL terminalTotalDifficultyPassed != true (engine may not start at block 1)"
      ;;
  esac

else
  # Couldn't read TTD directly — try to infer from live heads
  head_exec_bn="$(beacon_get_local "/eth/v2/beacon/blocks/head" \
    | jq -r '.data.message.body.execution_payload.block_number // .data.message.body.execution_payload.blockNumber' 2>/dev/null || true)"
  el_head_hex="$(el_rpc_local "eth_blockNumber" "[]" \
    | jq -r '.result' 2>/dev/null || true)"

  if [[ "$head_exec_bn" =~ ^[0-9]+$ && "$el_head_hex" =~ ^0x[0-9a-fA-F]+$ ]]; then
    el_head_dec=$((16#${el_head_hex#0x}))
    diff=$(( el_head_dec - head_exec_bn ))
    if (( diff >= -1 && diff <= 1 )); then
      pass "Merge-by-TTD inferred: CL payload block_number=$head_exec_bn ≈ EL head=$el_head_dec (|Δ|≤1)"
    else
      warn "Unable to confirm Merge-by-TTD from heads: CL payload=$head_exec_bn, EL head=$el_head_dec (Δ=$diff)"
      echo "     → Consider exposing Geth debug API or mounting genesis.json so TTD can be read directly."
    fi
  else
    warn "Could not determine EL terminalTotalDifficulty/Passed directly (no debug API/genesis.json)"
    echo "     → Also could not infer from heads (port-forward down or services unknown)."
    echo "     → To make this PASS: include 'debug' in --http.api or mount a readable genesis.json."
  fi
fi

