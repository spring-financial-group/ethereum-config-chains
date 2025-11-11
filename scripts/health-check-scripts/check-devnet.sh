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

# Check block proposals from both validators
banner "Block Proposals"

PRYSM_BLOCKS=0
LH_BLOCKS=0

if [[ -n "$VC_POD" ]]; then
  PRYSM_BLOCKS=$(kubectl logs "$VC_POD" -n "$NS" -c "$VC_CTN" 2>/dev/null | grep -c '"Submitted new block"' || echo "0")
  echo "${GRN}Prysm Validator:${NC} $PRYSM_BLOCKS blocks proposed"
  if [[ "$PRYSM_BLOCKS" -gt 0 ]]; then
    pass "Prysm validator is proposing blocks"
  else
    warn "Prysm validator has not proposed any blocks yet"
  fi
else
  warn "Prysm validator pod not found"
fi

if [[ -n "$VC_POD_LH" ]]; then
  LH_BLOCKS=$(kubectl logs "$VC_POD_LH" -n "$NS" -c "$VC_CTN_LH" 2>/dev/null | grep -c "Successfully published block" || echo "0")
  echo "${GRN}Lighthouse Validator:${NC} $LH_BLOCKS blocks proposed"
  if [[ "$LH_BLOCKS" -gt 0 ]]; then
    pass "Lighthouse validator is proposing blocks"
  else
    warn "Lighthouse validator has not proposed any blocks yet"
  fi
else
  warn "Lighthouse validator pod not found"
fi

TOTAL_BLOCKS=$((PRYSM_BLOCKS + LH_BLOCKS))

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