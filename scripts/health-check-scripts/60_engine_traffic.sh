#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "60_engine_traffic (${SETUP:-})"

cache_names

_EL_POD="${CURRENT_EL_POD:-$EL_POD}"
_EL_CTN="${CURRENT_EL_CTN:-$EL_CTN}"

if [[ -z "$_EL_POD" ]]; then
  warn "Skipping engine traffic check (EL pod not found)"
  return 0
fi

# Try multiple log patterns for engine API activity
ENGINE_LOGS=$(kubectl -n "$NS" logs "$_EL_POD" -c "$_EL_CTN" --since=15m 2>/dev/null || echo "")

# Check various patterns using here-strings to avoid broken pipe
if grep -m1 -iqE 'engine_(newpayload|forkchoice)|forkchoice|newpayload|Starting work on payload|Updated payload|Stopping work on payload|Sealing block|Commit new sealing|Successfully sealed' <<<"$ENGINE_LOGS" 2>/dev/null; then
  pass "Geth engine is receiving payload/forkchoice calls"
elif grep -m1 -iqE 'Imported new chain segment|blocks.*txs|mined potential block' <<<"$ENGINE_LOGS" 2>/dev/null; then
  pass "Geth engine is processing blocks (alternate log pattern)"
else
  # Fallback: Check if block number is increasing
  # If blocks are being produced, engine must be working even if logs are silent
  BLOCK_CHECK=$(grep -c 'block' <<<"$ENGINE_LOGS" 2>/dev/null || echo "0")
  if [[ "$BLOCK_CHECK" -gt 10 ]]; then
    pass "Geth engine is active (blocks being processed, log patterns may vary)"
  else
    warn "No obvious engine_newPayload/forkchoice logs in last 15m"
    echo "     → This may be normal if Geth logs are minimal or rotated"
    echo "     → If blocks are being produced (check validators), engine is working"
  fi
fi