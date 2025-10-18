#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "90_logs"

cache_names

echo "---- EL (engine) tail ----"
kubectl logs -n "$NS" "$EL_POD" -c "$EL_CONT" --tail="${EL_LOG_TAIL}" | egrep -i 'forkchoice|newpayload|engine|payload' || true

echo "---- CL (exec/validator RPC) tail ----"
kubectl logs -n "$NS" "$CL_POD" -c "$CL_CONT" --tail="${CL_LOG_TAIL}" | egrep -i 'execution|engine|endpoint|rpc/validator|deadline|process slots|parent state|error|peer' || true
