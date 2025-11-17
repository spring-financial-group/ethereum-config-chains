#!/usr/bin/env bash
set -Eeuo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

export EXIT_STATUS=0

# Source lib to get colors
source "$DIR/00_lib.sh"

echo "${BLU}================================${NC}"
echo "${BLU}  DEVNET HEALTH CHECK${NC}"
echo "${BLU}================================${NC}"

# Run discovery first to cache all pod names
banner "10_discovery"
source "$DIR/10_discovery.sh"

echo
echo "${BLU}╔═══════════════════════════════╗${NC}"
echo "${BLU}║   PRYSM SETUP CHECKS          ║${NC}"
echo "${BLU}╚═══════════════════════════════╝${NC}"

# Check Prysm setup
export SETUP="PRYSM"
export EL_SVC="${EL_SVC:-geth-devnet}"
export CL_SVC="${CL_SVC:-beacon-devnet-prysm}"
export CURRENT_EL_POD="$EL_POD"
export CURRENT_CL_POD="$CL_POD"
export CURRENT_VC_POD="$VC_POD"
export CURRENT_EL_CTN="$EL_CTN"
export CURRENT_CL_CTN="$CL_CTN"
export CURRENT_VC_CTN="$VC_CTN"

if [[ -n "$CURRENT_CL_POD" ]]; then
  source "$DIR/20_network.sh" || true
  source "$DIR/30_jwt.sh" || true
  source "$DIR/40_genesis_and_head.sh" || true
  source "$DIR/50_merge_check.sh" || true
  source "$DIR/60_engine_traffic.sh" || true
else
  warn "Prysm CL pod not found, skipping Prysm checks"
fi

echo
echo "${BLU}╔═══════════════════════════════╗${NC}"
echo "${BLU}║   LIGHTHOUSE SETUP CHECKS     ║${NC}"
echo "${BLU}╚═══════════════════════════════╝${NC}"

# Check Lighthouse setup
export SETUP="LIGHTHOUSE"
export EL_SVC="${EL_SVC_LIGHTHOUSE:-geth-lighthouse}"
export CL_SVC="${CL_SVC_LIGHTHOUSE:-beacon-devnet-lighthouse}"
export CURRENT_EL_POD="$EL_POD_LH"
export CURRENT_CL_POD="$CL_POD_LH"
export CURRENT_VC_POD="$VC_POD_LH"
export CURRENT_EL_CTN="$EL_CTN_LH"
export CURRENT_CL_CTN="$CL_CTN_LH"
export CURRENT_VC_CTN="$VC_CTN_LH"
export CL_REST_PORT="${CL_REST_PORT_LIGHTHOUSE:-5052}"

if [[ -n "$CURRENT_CL_POD" ]]; then
  source "$DIR/20_network.sh" || true
  source "$DIR/30_jwt.sh" || true
  source "$DIR/40_genesis_and_head.sh" || true
  source "$DIR/50_merge_check.sh" || true
  source "$DIR/60_engine_traffic.sh" || true
else
  warn "Lighthouse CL pod not found, skipping Lighthouse checks"
fi

echo
echo "${BLU}╔═══════════════════════════════╗${NC}"
echo "${BLU}║   VALIDATOR BLOCK PROPOSALS   ║${NC}"
echo "${BLU}╚═══════════════════════════════╝${NC}"


echo ""
banner "Block Proposals"

# Get container names first
prysm_vc_container=$(kubectl get pod -n devnet validator-devnet-prysm-0 -o jsonpath='{.spec.containers[0].name}' 2>/dev/null || echo "prysm")
lighthouse_vc_container=$(kubectl get pod -n devnet validator-devnet-lighthouse-0 -o jsonpath='{.spec.containers[0].name}' 2>/dev/null || echo "lighthouse-validator")

# Prysm validator block proposals (search ALL logs)
prysm_blocks=$(kubectl logs -n devnet validator-devnet-prysm-0 -c "$prysm_vc_container" --tail=-1 2>/dev/null | \
  { grep "Submitted new block" || true; } | wc -l)
prysm_blocks=$(echo "$prysm_blocks" | tr -d '\n' | xargs)

echo "Prysm Validator: $prysm_blocks blocks proposed"
if [[ "$prysm_blocks" -gt 0 ]]; then
  pass "Prysm validator is proposing blocks"
else
  warn "Prysm validator has not proposed any blocks yet (may not have been assigned a slot)"
fi

# Lighthouse validator block proposals (search ALL logs)
lighthouse_blocks=$(kubectl logs -n devnet validator-devnet-lighthouse-0 -c "$lighthouse_vc_container" --tail=-1 2>/dev/null | \
  { grep "Successfully published block" || true; } | wc -l)
lighthouse_blocks=$(echo "$lighthouse_blocks" | tr -d '\n' | xargs)

echo "Lighthouse Validator: $lighthouse_blocks blocks proposed"
if [[ "$lighthouse_blocks" -gt 0 ]]; then
  pass "Lighthouse validator is proposing blocks"
else
  warn "Lighthouse validator has not proposed any blocks yet (may not have been assigned a slot)"
fi

# Calculate total (useful for overall health check)
total_blocks=$((prysm_blocks + lighthouse_blocks))

# Check that at least ONE validator is working
if [[ "$total_blocks" -gt 0 ]]; then
  pass "Network is producing blocks (total: $total_blocks)"
else
  warn "No blocks proposed yet by any validator (validators may be active but waiting for slot assignment)"
fi

echo ""
echo "╔═══════════════════════════════╗"
echo "║   FEE RECIPIENT BALANCES      ║"
echo "╚═══════════════════════════════╝"
echo ""

# Fee recipient addresses
PRYSM_FEE="0x1111111111111111111111111111111111111111"
LIGHTHOUSE_FEE="0x2222222222222222222222222222222222222222"

echo ">>> Fee Recipients"

# Get Prysm balance
prysm_balance=$(kubectl exec -n "$NS" geth-devnet-0 -c geth -- sh -c "HOME=/tmp geth attach --exec 'web3.fromWei(eth.getBalance(\"$PRYSM_FEE\"), \"ether\")' /data/geth.ipc" 2>/dev/null | tail -1)
echo "Prysm fee recipient ($PRYSM_FEE): $prysm_balance ETH"

# Get Lighthouse balance
lighthouse_balance=$(kubectl exec -n "$NS" geth-lighthouse-0 -c geth -- sh -c "HOME=/tmp geth attach --exec 'web3.fromWei(eth.getBalance(\"$LIGHTHOUSE_FEE\"), \"ether\")' /data/geth.ipc" 2>/dev/null | tail -1)
echo "Lighthouse fee recipient ($LIGHTHOUSE_FEE): $lighthouse_balance ETH"

# Check if both have earned fees
if [[ $(echo "$prysm_balance > 0" | bc -l) -eq 1 ]] && [[ $(echo "$lighthouse_balance > 0" | bc -l) -eq 1 ]]; then
    echo "PASS Both validators earning fees"
elif [[ $(echo "$prysm_balance > 0" | bc -l) -eq 1 ]] || [[ $(echo "$lighthouse_balance > 0" | bc -l) -eq 1 ]]; then
    echo "WARN Only one validator has earned fees (may need more time)"
else
    echo "INFO No fees earned yet (check fee recipient configuration)"
fi
echo

echo
echo "${BLU}================================${NC}"
if [[ "$EXIT_STATUS" -eq 0 ]]; then
  echo "${GRN}✓ All checks passed!${NC}"
elif [[ "$TOTAL_BLOCKS" -gt 100 ]]; then
  echo "${GRN}✓ Chain is healthy!${NC}"
  echo "  Total blocks produced: $TOTAL_BLOCKS"
  echo "  Some non-critical warnings present (see above)"
else
  echo "${YEL}⚠ Some checks failed (see above)${NC}"
fi
echo "${BLU}================================${NC}"

exit "$EXIT_STATUS"