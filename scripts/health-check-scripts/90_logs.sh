#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "90_logs (${SETUP:-})"

cache_names

_EL_POD="${CURRENT_EL_POD:-$EL_POD}"
_EL_CTN="${CURRENT_EL_CTN:-$EL_CTN}"
_CL_POD="${CURRENT_CL_POD:-$CL_POD}"
_CL_CTN="${CURRENT_CL_CTN:-$CL_CTN}"

if [[ -n "$_EL_POD" && -n "$_EL_CTN" ]]; then
  echo "---- EL (engine) tail ----"
  kubectl logs -n "$NS" "$_EL_POD" -c "$_EL_CTN" --tail="${EL_LOG_TAIL}" 2>/dev/null \
    | grep -iE 'forkchoice|newpayload|engine|payload' || echo "(no matching logs)"
fi

if [[ -n "$_CL_POD" && -n "$_CL_CTN" ]]; then
  echo "---- CL (beacon) tail ----"
  kubectl logs -n "$NS" "$_CL_POD" -c "$_CL_CTN" --tail="${CL_LOG_TAIL}" 2>/dev/null \
    | grep -iE 'execution|engine|endpoint|rpc|error|peer' || echo "(no matching logs)"
fi
