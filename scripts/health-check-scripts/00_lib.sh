#!/usr/bin/env bash
set -Eeuo pipefail

# -------- Colors / status ----------
if [ -t 1 ]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; NC=$'\e[0m'
else
  RED=; GRN=; YEL=; BLU=; NC=
fi
EXIT_STATUS=0
pass(){ echo "${GRN}PASS${NC} $*"; }
fail(){ echo "${RED}FAIL${NC} $*"; EXIT_STATUS=1; }
warn(){ echo "${YEL}WARN${NC} $*"; }
die(){  echo "${RED}ERROR${NC} $*"; exit 2; }
hdr(){  echo; echo ">>> $1"; }
section(){ echo; echo "${BLU}=== $1 ===${NC}"; }

need(){ command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }

# --- Portable banner shim ---
banner() {
  local msg="${*//_/ }"
  printf "\n>>> %s\n" "$msg"
}
export -f banner || true

# Cache pod/container names for both setups
cache_names() {
  : "${NS:=devnet}"
  
  # Prysm labels
  : "${EL_LABEL:=app.kubernetes.io/instance=geth-devnet}"
  : "${CL_LABEL:=app.kubernetes.io/instance=beacon-devnet-prysm}"
  : "${VC_LABEL:=app.kubernetes.io/instance=validator-devnet-prysm}"
  
  # Lighthouse labels
  : "${EL_LABEL_LIGHTHOUSE:=app.kubernetes.io/instance=geth-lighthouse}"
  : "${CL_LABEL_LIGHTHOUSE:=app.kubernetes.io/instance=beacon-devnet-lighthouse}"
  : "${VC_LABEL_LIGHTHOUSE:=app.kubernetes.io/instance=validator-devnet-lighthouse}"

  # Find Prysm pods
  EL_POD="${EL_POD:-$(kubectl get pod -n "$NS" -l "$EL_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)}"
  CL_POD="${CL_POD:-$(kubectl get pod -n "$NS" -l "$CL_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)}"
  VC_POD="${VC_POD:-$(kubectl get pod -n "$NS" -l "$VC_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)}"

  # Find Lighthouse pods
  EL_POD_LH="${EL_POD_LH:-$(kubectl get pod -n "$NS" -l "$EL_LABEL_LIGHTHOUSE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)}"
  CL_POD_LH="${CL_POD_LH:-$(kubectl get pod -n "$NS" -l "$CL_LABEL_LIGHTHOUSE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)}"
  VC_POD_LH="${VC_POD_LH:-$(kubectl get pod -n "$NS" -l "$VC_LABEL_LIGHTHOUSE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)}"

  _first_ctn() { kubectl get pod -n "$NS" "$1" -o jsonpath='{.spec.containers[0].name}' 2>/dev/null; }
  _ctn_by() {
    kubectl get pod -n "$NS" "$1" -o json 2>/dev/null \
      | jq -r --arg re "$2" '.spec.containers[] | select(.name|test($re)) | .name' \
      | head -n1
  }

  # Resolve Prysm containers
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

  # Resolve Lighthouse containers
  if [ -n "$EL_POD_LH" ]; then
    EL_CTN_LH="${EL_CTN_LH:-$(_ctn_by "$EL_POD_LH" 'geth|el|execution')}"
    [ -z "$EL_CTN_LH" ] && EL_CTN_LH="$(_first_ctn "$EL_POD_LH")"
  fi

  if [ -n "$CL_POD_LH" ]; then
    CL_CTN_LH="${CL_CTN_LH:-$(_ctn_by "$CL_POD_LH" 'lighthouse|beacon|cl')}"
    [ -z "$CL_CTN_LH" ] && CL_CTN_LH="$(_first_ctn "$CL_POD_LH")"
  fi

  if [ -n "$VC_POD_LH" ]; then
    VC_CTN_LH="${VC_CTN_LH:-$(_ctn_by "$VC_POD_LH" 'lighthouse|validator|vc')}"
    [ -z "$VC_CTN_LH" ] && VC_CTN_LH="$(_first_ctn "$VC_POD_LH")"
  fi

  export EL_POD CL_POD VC_POD EL_CTN CL_CTN VC_CTN
  export EL_POD_LH CL_POD_LH VC_POD_LH EL_CTN_LH CL_CTN_LH VC_CTN_LH
}

tcp_probe() {
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
      curl -m2 -s "http://$H:$P" >/dev/null 2>&1 && echo OK || echo FAIL
    else
      echo SKIP
    fi'
}

pf_bg() {
  kubectl -n "$NS" port-forward "$1/$2" "$3:$4" >/dev/null 2>&1 & echo $!
}

kill_pf() {
  local pid="$1"
  { ps -p "$pid" >/dev/null 2>&1 && kill "$pid"; } >/dev/null 2>&1 || true
}

# -------- Load env --------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

need kubectl
need jq
need curl

get_pod(){
  local label="${1:-}"
  [ -n "$label" ] || { echo ""; return 0; }
  kubectl get pod -n "$NS" -l "$label" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}

export RED GRN YEL BLU NC EXIT_STATUS pass fail warn die hdr need section \
  get_pod tcp_probe pf_bg kill_pf cache_names \
  NS EL_LABEL CL_LABEL VC_LABEL EL_LABEL_LIGHTHOUSE CL_LABEL_LIGHTHOUSE VC_LABEL_LIGHTHOUSE
