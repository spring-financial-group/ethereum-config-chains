#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "60_engine_traffic"

cache_names

if kubectl -n "$NS" logs "$EL_POD" -c "$EL_CTN" --since=15m 2>/dev/null \
   | egrep -iq 'engine_.*(newpayload|forkchoice)|forkchoice|newpayload|Starting work on payload|Updated payload|Stopping work on payload'; then
  pass "Geth engine is receiving payload/forkchoice calls"
else
  fail "No recent engine_newPayload/forkchoice logs seen in Geth (last 15m)"
  echo "     → Beacon may not be driving the engine yet."
fi

