#!/usr/bin/env bash
set -Eeuo pipefail

NS=${NS:-default}
EL_LABEL=${EL_LABEL:-app.kubernetes.io/instance=geth-devnet}
CL_LABEL=${CL_LABEL:-app.kubernetes.io/instance=beacon-devnet}
VC_LABEL=${VC_LABEL:-app.kubernetes.io/instance=validator-devnet}
EL_SVC=${EL_SVC:-geth-devnet}
CL_SVC=${CL_SVC:-beacon-devnet-prysm}
AUTHRPC_PORT=${AUTHRPC_PORT:-8551}
EL_HTTP_PORT=${EL_HTTP_PORT:-8545}
CL_REST_PORT=${CL_REST_PORT:-3500}
CL_GRPC_PORT=${CL_GRPC_PORT:-4000}
EL_JWT_PATH=${EL_JWT_PATH:-/data/jwt.hex}
CL_JWT_PATH=${CL_JWT_PATH:-/data/jwt.hex}

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; NC=$'\e[0m'; EXIT=0
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing $1"; exit 2; }; }
need kubectl; need jq; need curl
pass(){ echo "${GRN}PASS${NC} $*"; } ; fail(){ echo "${RED}FAIL${NC} $*"; EXIT=1; } ; warn(){ echo "${YEL}WARN${NC} $*"; }

get_pod(){ kubectl get pod -n "$NS" -l "$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true; }
first_ctn(){ kubectl get pod -n "$NS" "$1" -o jsonpath='{.spec.containers[0].name}'; }
ctn_by(){ kubectl get pod -n "$NS" "$1" -o json | jq -r --arg re "$2" '.spec.containers[] | select(.name|test($re)) | .name' | head -n1; }
tcp(){ kubectl exec -n "$NS" "$1" -c "$2" -- bash -lc "timeout 2 bash -lc '</dev/tcp/$3/$4' >/dev/null 2>&1 && echo OK || echo FAIL" 2>/dev/null || true; }

EL_POD="$(get_pod "$EL_LABEL")"; [ -n "$EL_POD" ] && pass "Found EL pod: $EL_POD" || fail "EL pod not found"
CL_POD="$(get_pod "$CL_LABEL")"; [ -n "$CL_POD" ] && pass "Found CL pod: $CL_POD" || fail "CL pod not found"
VC_POD="$(get_pod "$VC_LABEL")"; [ -n "$VC_POD" ] && pass "Found VC pod: $VC_POD" || warn "VC pod not found"

EL_CTN="$(ctn_by "$EL_POD" 'geth|el|execution')"; [ -z "$EL_CTN" ] && EL_CTN="$(first_ctn "$EL_POD")"
CL_CTN="$(ctn_by "$CL_POD" 'prysm|beacon|cl')"; [ -z "$CL_CTN" ] && CL_CTN="$(first_ctn "$CL_POD")"
if [ -n "$VC_POD" ]; then VC_CTN="$(ctn_by "$VC_POD" 'prysm|validator|vc')"; [ -z "$VC_CTN" ] && VC_CTN="$(first_ctn "$VC_POD")"; fi

# Service + endpoints
svc_json="$(kubectl get svc -n "$NS" "$EL_SVC" -o json 2>/dev/null || true)"
[ -n "$svc_json" ] && pass "Service $EL_SVC present" || fail "Service $EL_SVC not found"
echo "Ports on $EL_SVC:"; echo "$svc_json" | jq -r '.spec.ports[] | "  \(.name)//\(.port)/\(.protocol)"'
echo "$svc_json" | jq -e --arg p "$AUTHRPC_PORT" '.spec.ports[] | select(.port==($p|tonumber))' >/dev/null && \
  pass "Service exposes Engine API port $AUTHRPC_PORT" || fail "Service missing Engine API $AUTHRPC_PORT"
eps_json="$(kubectl get endpoints -n "$NS" "$EL_SVC" -o json 2>/dev/null || true)"
[ -n "$eps_json" ] && pass "Endpoints exist for $EL_SVC" || fail "No Endpoints for $EL_SVC"
EL_EP_8551=$(echo "$eps_json" | jq -r --arg p "$AUTHRPC_PORT" '.subsets[]? as $s | ($s.addresses[]?.ip // empty) as $ip | $s.ports[]? | select(.port==($p|tonumber)) | "\($ip):\(.port)"' | xargs -r echo)
[ -n "$EL_EP_8551" ] && pass "Endpoint(s) on $AUTHRPC_PORT: $EL_EP_8551" || fail "No endpoint on $AUTHRPC_PORT"

# Parse beacon flags from args OR command
BEACON_STS="$(kubectl get -n "$NS" sts -l "$CL_LABEL" -o json)"
ARGS=$(echo "$BEACON_STS" | jq -r '.items[0].spec.template.spec.containers[] | select(.name!=null) | .args // empty' | xargs -r echo)
CMD=$(echo "$BEACON_STS" | jq -r '.items[0].spec.template.spec.containers[] | select(.name!=null) | (.command|join(" ")) + " " + ((.args//[])|join(" "))' | tr '\n' ' ')
echo "Beacon args: $ARGS"
echo "Beacon cmd:  $CMD"

check_flag(){
  local flag="$1" ; shift
  if grep -qi -- "$flag" <<<"$ARGS$CMD"; then pass "Beacon flag present: $flag"; else warn "Beacon flag missing: $flag"; fi
}
check_flag "--execution-endpoint=http://$EL_SVC.default.svc:$AUTHRPC_PORT"
check_flag "--jwt-secret=$CL_JWT_PATH"
check_flag "--min-sync-peers=0"
check_flag "--subscribe-all-subnets"

# JWT hashes
if kubectl exec -n "$NS" "$EL_POD" -c "$EL_CTN" -- sh -c "sha256sum $EL_JWT_PATH" >/dev/null 2>&1 && \
   kubectl exec -n "$NS" "$CL_POD" -c "$CL_CTN" -- sh -c "sha256sum $CL_JWT_PATH" >/dev/null 2>&1; then
  EL_JWT_HASH="$(kubectl exec -n "$NS" "$EL_POD" -c "$EL_CTN" -- sh -c "sha256sum $EL_JWT_PATH" | awk '{print $1}')"
  CL_JWT_HASH="$(kubectl exec -n "$NS" "$CL_POD" -c "$CL_CTN" -- sh -c "sha256sum $CL_JWT_PATH" | awk '{print $1}')"
  [ "$EL_JWT_HASH" = "$CL_JWT_HASH" ] && pass "JWT hashes match ($EL_JWT_HASH)" || fail "JWT hashes differ: EL=$EL_JWT_HASH CL=$CL_JWT_HASH"
else
  warn "Could not read JWT files ($EL_JWT_PATH / $CL_JWT_PATH)"
fi

# TCP tests (both short & FQDN)
for host in "$EL_SVC:8551" "$EL_SVC.default.svc:8551"; do
  H="${host%:*}"; P="${host#*:}"
  [ "$(tcp "$CL_POD" "$CL_CTN" "$H" "$P")" = "OK" ] && pass "Beacon → EL TCP $H:$P OK" || fail "Beacon → EL TCP $H:$P FAIL"
done
if [ -n "${VC_POD:-}" ]; then
  for host in "$CL_SVC:4000" "$CL_SVC.default.svc:4000"; do
    H="${host%:*}"; P="${host#*:}"
    [ "$(tcp "$VC_POD" "$VC_CTN" "$H" "$P")" = "OK" ] && pass "Validator → Beacon TCP $H:$P OK" || fail "Validator → Beacon TCP $H:$P FAIL"
  done
fi

# Port-forwards
pf(){ kubectl -n "$NS" port-forward "pod/$1" "$2" >/dev/null 2>&1 & echo $!; }
PF1=$(pf "$EL_POD" "$EL_HTTP_PORT:$EL_HTTP_PORT"); sleep 0.5
PF2=$(pf "$CL_POD" "$CL_REST_PORT:$CL_REST_PORT"); sleep 0.5
trap 'kill $PF1 $PF2 2>/dev/null || true' EXIT

# EL block0 vs CL genesis
b0="$(curl -s -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x0",false],"id":1}' "http://localhost:$EL_HTTP_PORT")"
ts_hex="$(jq -r '.result.timestamp // empty' <<<"$b0")"
if [[ "$ts_hex" == 0x* ]]; then ts_dec=$(( ts_hex )); pass "EL block0 timestamp: $ts_dec"; else fail "EL block0 timestamp unavailable"; fi
gen="$(curl -s "http://localhost:$CL_REST_PORT/eth/v1/beacon/genesis")"
gen_time="$(jq -r '.data.genesis_time // empty' <<<"$gen")"
[[ "$gen_time" =~ ^[0-9]+$ ]] && pass "CL genesis_time: $gen_time" || fail "CL genesis_time unavailable"
if [[ "${ts_dec:-}" =~ ^[0-9]+$ ]] && [[ "$gen_time" =~ ^[0-9]+$ ]]; then
  [ "$ts_dec" -eq "$gen_time" ] && pass "EL/CL genesis match" || fail "EL/CL genesis mismatch: EL=$ts_dec CL=$gen_time"
fi

# EL height & CL head advance
bn="$(curl -s -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' "http://localhost:$EL_HTTP_PORT" | jq -r '.result // empty')"
[[ "$bn" == 0x* ]] && pass "EL blockNumber: $bn" || fail "EL blockNumber unavailable"
head1="$(curl -s "http://localhost:$CL_REST_PORT/eth/v1/beacon/headers/head" | jq -r '.data.header.message.slot // empty')"
sleep 12
head2="$(curl -s "http://localhost:$CL_REST_PORT/eth/v1/beacon/headers/head" | jq -r '.data.header.message.slot // empty')"
if [[ "$head1" =~ ^[0-9]+$ ]] && [[ "$head2" =~ ^[0-9]+$ ]]; then
  [ "$head2" -gt "$head1" ] && pass "CL head advancing ($head1 → $head2)" || fail "CL head NOT advancing (stuck at $head1)"
else fail "Could not read CL head slot"; fi

# Peer & syncing info (helps explain 'failed to find peers')
id="$(curl -s "http://localhost:$CL_REST_PORT/eth/v1/node/identity" || true)"
pc="$(curl -s "http://localhost:$CL_REST_PORT/eth/v1/node/peer_count" || true)"
sync="$(curl -s "http://localhost:$CL_REST_PORT/eth/v1/node/syncing" || true)"
echo "Beacon peer_count: $(jq -r '.data.connected // empty' <<<"$pc" 2>/dev/null || echo "?")"
echo "Beacon syncing:    $(jq -r '.data.is_syncing // empty' <<<"$sync" 2>/dev/null || echo "?")"

# Slot drift
spec="$(curl -s "http://localhost:$CL_REST_PORT/eth/v1/config/spec" || true)"
sps="$(jq -r '.data.SECONDS_PER_SLOT // empty' <<<"$spec")"
now=$(date -u +%s)
if [[ "$sps" =~ ^[0-9]+$ ]] && [[ "$gen_time" =~ ^[0-9]+$ ]] && [[ "$head2" =~ ^[0-9]+$ ]]; then
  expected=$(( (now - gen_time) / sps )); drift=$(( expected - head2 ))
  echo "Slot check: expected=$expected head=$head2 drift=$drift"
  if [ $drift -ge -2 ] && [ $drift -le 30 ]; then pass "Slot drift normal"; else warn "Slot drift large ($drift)"; fi
fi

spec="$(curl -s "http://localhost:$CL_REST_PORT/eth/v1/config/spec")"
ttd="$(jq -r '.data.TERMINAL_TOTAL_DIFFICULTY // empty' <<<"$spec")"
tbh="$(jq -r '.data.TERMINAL_BLOCK_HASH // empty' <<<"$spec")"
tbh_epoch="$(jq -r '.data.TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH // empty' <<<"$spec")"
echo "Merge spec: TTD=$ttd TBH=$tbh TBH_EPOCH=$tbh_epoch"
if { [ -z "$tbh" ] || [ "$tbh" = "0x0000000000000000000000000000000000000000000000000000000000000000" ]; } && \
   { [ -z "$ttd" ] || [ "$ttd" != "0" ]; }; then
  echo "WARN Merge may never trigger on an isolated devnet (set TTD=0 or TBH)"
fi


#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-default}"
EL_SVC="${EL_SVC:-geth-devnet}"
CL_POD="${CL_POD:-beacon-devnet-prysm-0}"
EL_POD="${EL_POD:-geth-devnet-0}"
EL_CONT="${EL_CONT:-geth}"
CL_CONT="${CL_CONT:-prysm}"

hr() { printf '%s\n' "----------------------------------------"; }

# --- Helper: with a short-lived port-forward (kills itself) ---
pf_bg() {
  local kind="$1" name="$2" lport="$3" rport="$4"
  kubectl -n "$NS" port-forward "$kind/$name" "${lport}:${rport}" >/dev/null 2>&1 &
  echo $!
}

kill_pf() {
  local pid="$1"
  if ps -p "$pid" >/dev/null 2>&1; then kill "$pid" >/dev/null 2>&1 || true; fi
}

# ---------------------------
# MERGE / TBH CONSISTENCY CHECK
# ---------------------------
echo "Merge spec sanity-check…"

# 1) Get EL block0 hash via JSON-RPC
EL_PF_PID=""
if ! curl -sSf --max-time 2 "http://127.0.0.1:8545" >/dev/null 2>&1; then
  EL_PF_PID=$(pf_bg "svc" "$EL_SVC" 8545 8545)
  sleep 1
fi

EL_BLOCK0_HASH="$(curl -s -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x0", false],"id":1}' \
  http://127.0.0.1:8545 \
  | sed -n 's/.*"hash":"\([^"]*\)".*/\1/p')"

if [[ -n "$EL_PF_PID" ]]; then kill_pf "$EL_PF_PID"; fi

if [[ -z "$EL_BLOCK0_HASH" ]]; then
  echo "FAIL Could not fetch EL block0 hash from ${EL_SVC}:8545"
  exit 1
fi
echo "EL block0 hash: $EL_BLOCK0_HASH"

# 2) Read what Prysm will read from disk inside the pod
FILE_TBH="$(kubectl -n "$NS" exec "$CL_POD" -c "$CL_CONT" -- sh -lc \
  "grep -E '^TERMINAL_BLOCK_HASH:' /data/testnet_spec/config.yaml 2>/dev/null | awk '{print \$2}'" || true)"

FILE_TBH_EPOCH="$(kubectl -n "$NS" exec "$CL_POD" -c "$CL_CONT" -- sh -lc \
  "grep -E '^TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH:' /data/testnet_spec/config.yaml 2>/dev/null | awk '{print \$2}'" || true)"

if [[ -z "$FILE_TBH" ]]; then
  echo "WARN Could not read TBH from /data/testnet_spec/config.yaml (file missing or init not finished?)"
else
  echo "CL file TBH: $FILE_TBH"
  echo "CL file TBH_EPOCH: ${FILE_TBH_EPOCH:-<unset>}"
fi

# 3) Prysm REST: what it actually loaded
CL_PF_PID=""
if ! curl -sSf --max-time 2 "http://127.0.0.1:3500/eth/v1/config/spec" >/dev/null 2>&1; then
  CL_PF_PID=$(pf_bg "pod" "$CL_POD" 3500 3500)
  sleep 1
fi

SPEC_JSON="$(curl -s "http://127.0.0.1:3500/eth/v1/config/spec" || true)"
[[ -n "$CL_PF_PID" ]] && kill_pf "$CL_PF_PID"

# Extract values without jq (BSD-friendly)
REST_TBH="$(printf '%s' "$SPEC_JSON" \
  | tr -d '\n' \
  | grep -oE '"TERMINAL_BLOCK_HASH":"0x[0-9a-fA-F]+"' \
  | sed -E 's/.*"TERMINAL_BLOCK_HASH":"([^"]+)".*/\1/')"

REST_TBH_EPOCH="$(printf '%s' "$SPEC_JSON" \
  | tr -d '\n' \
  | grep -oE '"TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH":[0-9]+' \
  | sed -E 's/.*"TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH":([0-9]+)/\1/')"

echo "CL REST TBH: ${REST_TBH:-<unset>}"
echo "CL REST TBH_EPOCH: ${REST_TBH_EPOCH:-<unset>}"


# 4) Evaluate + actionable guidance
ZERO_HASH="0x0000000000000000000000000000000000000000000000000000000000000000"

if [[ "$REST_TBH" == "$EL_BLOCK0_HASH" && "${REST_TBH_EPOCH:-}" == "0" ]]; then
  echo "PASS Merge trigger loaded correctly (TBH matches EL genesis, epoch=0)"
elif [[ -n "$FILE_TBH" && "$FILE_TBH" == "$EL_BLOCK0_HASH" && "${FILE_TBH_EPOCH:-}" == "0" && ( -z "$REST_TBH" || "$REST_TBH" == "$ZERO_HASH" ) ]]; then
  echo "FAIL Prysm disk config is correct, but runtime spec shows TBH unset."
  echo "     => Restart beacon so it re-reads the file:"
  echo "        kubectl -n $NS delete pod $CL_POD"
elif [[ -z "$FILE_TBH" || "$FILE_TBH" == "$ZERO_HASH" || "${FILE_TBH_EPOCH:-}" == "18446744073709551615" ]]; then
  echo "FAIL Disk config does not set TBH/epoch."
  echo "     Fix the source config your init downloads (or patch after download)."
  echo "     Expected:"
  echo "       TERMINAL_BLOCK_HASH: $EL_BLOCK0_HASH"
  echo "       TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH: 0"
else
  echo "WARN Inconsistent merge config:"
  echo "     EL:   $EL_BLOCK0_HASH"
  echo "     FILE: $FILE_TBH (epoch ${FILE_TBH_EPOCH:-?})"
  echo "     REST: ${REST_TBH:-unset} (epoch ${REST_TBH_EPOCH:-unset})"
fi

hr
# ---------------------------
# ENGINE TRAFFIC (EL <-> CL)
# ---------------------------
echo "Engine API traffic check…"
if kubectl -n "$NS" logs "$EL_POD" -c "$EL_CONT" --since=15m 2>/dev/null \
   | grep -Eiq 'engine_.*(newpayload|forkchoice)|forkchoice|newpayload'; then
  echo "PASS Geth engine is receiving payload/forkchoice calls"
else
  echo "FAIL No recent engine_newPayload/forkchoice logs seen in Geth (last 15m)"
  echo "     => Beacon may not be driving the engine yet."
fi

hr



# Log probes
echo "---- EL (engine) tail ----"
kubectl logs -n "$NS" "$EL_POD" -c "$EL_CTN" --tail=120 | egrep -i 'forkchoice|newpayload|engine|payload' || true
echo "---- CL (exec/validator RPC) tail ----"
kubectl logs -n "$NS" "$CL_POD" -c "$CL_CTN" --tail=120 | egrep -i 'execution|engine|endpoint|rpc/validator|deadline|process slots|parent state|error' || true

BLOCK0=$(kubectl exec -n default geth-devnet-0 -c geth -- sh -lc \
 'apk add -q curl jq || true; curl -s -H "Content-Type: application/json" \
 --data '"'"'{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x0", false],"id":1}'"'"' \
 http://localhost:8545 | jq -r .result.hash')
echo "$BLOCK0"



exit $EXIT

