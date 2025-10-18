#!/usr/bin/env bash
set -Eeuo pipefail

# -------- Colors / status ----------
if [ -t 1 ]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; NC=$'\e[0m'
else
  RED=; GRN=; YEL=; NC=
fi
EXIT_STATUS=0
pass(){ echo "${GRN}PASS${NC} $*"; }
fail(){ echo "${RED}FAIL${NC} $*"; EXIT_STATUS=1; }
warn(){ echo "${YEL}WARN${NC} $*"; }
die(){  echo "${RED}ERROR${NC} $*"; exit 2; }
hdr(){  echo; echo ">>> $1"; }

need(){ command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }

# --- Portable banner shim (overrides /usr/bin/banner on macOS) ---
banner() {
  # Replace underscores with spaces for nicer output
  local msg="${*//_/ }"
  printf "\n>>> %s\n" "$msg"
}
export -f banner || true  # ok if exporting functions is not supported

# Cache pod/container names so every module can reuse them
cache_names() {
  # Labels & namespace (already set by env or defaults)
  : "${NS:=default}"
  : "${EL_LABEL:=app.kubernetes.io/instance=geth-devnet}"
  : "${CL_LABEL:=app.kubernetes.io/instance=beacon-devnet}"
  : "${VC_LABEL:=app.kubernetes.io/instance=validator-devnet}"

  # Find pods by label if not already provided
  EL_POD="${EL_POD:-$(kubectl get pod -n "$NS" -l "$EL_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)}"
  CL_POD="${CL_POD:-$(kubectl get pod -n "$NS" -l "$CL_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)}"
  VC_POD="${VC_POD:-$(kubectl get pod -n "$NS" -l "$VC_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)}"

  # Resolve container names (regex first, fall back to first container)
  _first_ctn() { kubectl get pod -n "$NS" "$1" -o jsonpath='{.spec.containers[0].name}' 2>/dev/null; }
  _ctn_by() {
    kubectl get pod -n "$NS" "$1" -o json 2>/dev/null \
      | jq -r --arg re "$2" '.spec.containers[] | select(.name|test($re)) | .name' \
      | head -n1
  }

  if [ -n "$EL_POD" ]; then
    EL_CTN="${EL_CTN:-$(_ctn_by "$EL_POD" 'geth|el|execution')}"
    [ -z "$EL_CTN" ] && EL_CTN="$(_first_ctn "$EL_POD")"
  fi

  if [ -n "$CL_POD" ]; then
    CL_CTN="${CL_CTN:-$(_ctn_by "$CL_POD" 'prysm|beacon|cl')}"
    [ -z "$CL_CTN" ] && CL_CTN="$(_first_ctn "$CL_POD")"
  fi

  if [ -n "$VC_POD" ]; then
    VC_CTN="${VC_CTN:-$(_ctn_by "$VC_POD" 'prysm|validator|vc')}"
    [ -z "$VC_CTN" ] && VC_CTN="$(_first_ctn "$VC_POD")"
  fi

  export EL_POD CL_POD VC_POD EL_CTN CL_CTN VC_CTN
}

tcp_probe() {
  # usage: tcp_probe POD CTN HOST PORT
  local _pod="$1" _ctn="$2" _h="$3" _p="$4"
  kubectl exec -n "$NS" "$_pod" -c "$_ctn" -- sh -lc '
    H="'"$_h"'"; P="'"$_p"'"
    if command -v bash >/dev/null 2>&1; then
      bash -lc "exec 3<>/dev/tcp/${H}/${P}" >/dev/null 2>&1 && echo OK || echo FAIL
    elif command -v nc >/dev/null 2>&1; then
      nc -z -w1 "$H" "$P" >/dev/null 2>&1 && echo OK || echo FAIL
    elif command -v busybox >/dev/null 2>&1; then
      busybox nc -z -w1 "$H" "$P" >/dev/null 2>&1 && echo OK || echo FAIL
    elif command -v curl >/dev/null 2>&1; then
      # last-resort: works if the remote speaks HTTP (e.g. 8551/8545)
      curl -m2 -s "http://$H:$P" >/dev/null 2>&1 && echo OK || echo FAIL
    else
      echo SKIP
    fi'
}

# short-lived port-forward helpers (used in merge/head checks)
pf_bg() { # pf_bg KIND NAME LPORT RPORT
  kubectl -n "$NS" port-forward "$1/$2" "$3:$4" >/dev/null 2>&1 & echo $!
}
kill_pf() { local pid="$1"; { ps -p "$pid" >/dev/null 2>&1 && kill "$pid"; } >/dev/null 2>&1 || true; }



# -------- Load env --------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

need kubectl
need jq
need curl

# -------- k8s helpers --------
get_pod(){
  local label="${1:-}"
  [ -n "$label" ] || { echo ""; return 0; }
  kubectl get pod -n "$NS" -l "$label" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}

first_ctn(){
  local pod="${1:-}"
  [ -n "$pod" ] || { echo ""; return 0; }
  kubectl get pod -n "$NS" "$pod" -o jsonpath='{.spec.containers[0].name}' 2>/dev/null || true
}

ctn_by(){
  local pod="${1:-}"
  local re="${2:-.*}"
  [ -n "$pod" ] || { echo ""; return 0; }
  kubectl get pod -n "$NS" "$pod" -o json 2>/dev/null \
    | jq -r --arg re "$re" '.spec.containers[]? | select(.name|test($re)) | .name' \
    | head -n1
}

# TCP probe using bash's /dev/tcp; tolerate missing args
tcp(){
  local pod="${1:-}"
  local ctn="${2:-}"
  local host="${3:-}"
  local port="${4:-}"
  if [ -z "$pod" ] || [ -z "$ctn" ] || [ -z "$host" ] || [ -z "$port" ]; then
    echo "FAIL"
    return 0
  fi
  kubectl exec -n "$NS" "$pod" -c "$ctn" -- bash -lc \
    "timeout 2 bash -lc '</dev/tcp/$host/$port' >/dev/null 2>&1 && echo OK || echo FAIL" \
    2>/dev/null || echo FAIL
}

# Short-lived port-forward helpers (return PID, safe to call with blanks)
pf_bg(){
  local kind="${1:-}"
  local name="${2:-}"
  local lport="${3:-}"
  local rport="${4:-}"
  [ -n "$kind" ] && [ -n "$name" ] && [ -n "$lport" ] && [ -n "$rport" ] || { echo ""; return 0; }
  kubectl -n "$NS" port-forward "$kind/$name" "${lport}:${rport}" >/dev/null 2>&1 &
  echo $!
}

kill_pf(){
  local pid="${1:-}"
  [ -n "$pid" ] || return 0
  if ps -p "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
  fi
}

export RED GRN YEL NC EXIT_STATUS pass fail warn die hdr need \
  get_pod first_ctn ctn_by tcp pf_bg kill_pf \
  NS EL_LABEL CL_LABEL VC_LABEL EL_SVC CL_SVC AUTHRPC_PORT EL_HTTP_PORT \
  CL_REST_PORT CL_GRPC_PORT EL_JWT_PATH CL_JWT_PATH

