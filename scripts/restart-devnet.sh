#!/bin/bash
# restart-devnet.sh - Manage devnet stack with multiple scenarios
#
# Usage:
#   ./restart-devnet.sh full             # uninstall + reinstall everything (incl. Blockscout)
#   ./restart-devnet.sh shutdown         # just uninstall everything
#   ./restart-devnet.sh geth-prysm       # Geth (devnet) + Prysm beacon + Prysm validators
#   ./restart-devnet.sh geth-lighthouse  # Geth (lighthouse) + Lighthouse beacon + Lighthouse validators
#   ./restart-devnet.sh no-blockscout    # full EL+CL+validators, skip Blockscout
#   ./restart-devnet.sh blockscout-only  # (re)install Blockscout stack only

set -euo pipefail

MODE="${1:-full}"

BASE_URL="https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs"
NAMESPACE=${NAMESPACE:-default}

#######################################
# Helper functions
#######################################

uninstall_all() {
  echo "🧹 Step 1: Uninstalling everything in namespace '$NAMESPACE'..."
  RELEASES=$(helm list -n "$NAMESPACE" -q || true)

  # Only the releases that actually exist
  for release in \
    validator-devnet-prysm \
    validator-devnet-lighthouse \
    beacon-devnet-prysm \
    beacon-devnet-lighthouse \
    blockscout \
    blockscout-db \
    geth-devnet \
    geth-lighthouse
  do
    if echo "$RELEASES" | grep -q "^${release}$"; then
      echo "  Uninstalling $release..."
      helm uninstall "$release" -n "$NAMESPACE"
    else
      echo "  Skipping $release (not found)"
    fi
  done

  echo "  Deleting Blockscout PVC (if exists)..."
  kubectl delete pvc data-blockscout-db-postgresql-0 -n "$NAMESPACE" 2>/dev/null || true
  echo "  Waiting 30s for resources to terminate..."
  sleep 30
}

uninstall_blockscout_only() {
  echo "🧹 Uninstalling Blockscout stack in namespace '$NAMESPACE'..."
  RELEASES=$(helm list -n "$NAMESPACE" -q || true)

  for release in blockscout blockscout-db; do
    if echo "$RELEASES" | grep -q "^${release}$"; then
      echo "  Uninstalling $release..."
      helm uninstall "$release" -n "$NAMESPACE"
    else
      echo "  Skipping $release (not found)"
    fi
  done

  echo "  Deleting Blockscout PVC (if exists)..."
  kubectl delete pvc data-blockscout-db-postgresql-0 -n "$NAMESPACE" 2>/dev/null || true
  echo "  Waiting 10s for Blockscout resources to terminate..."
  sleep 10
}

install_geth_prysm_side() {
  echo ""
  echo "🔧 Installing Geth node (devnet/prysm)..."
  helm upgrade --install geth-devnet ethpandaops/geth \
    -f "$BASE_URL/geth-execution.yaml" -n "$NAMESPACE" --create-namespace
  echo "  ✓ geth-devnet installed"

  echo ""
  echo "⏳ Waiting for geth-devnet pod to be ready..."
  kubectl wait --for=condition=ready pod/geth-devnet-0 -n "$NAMESPACE" --timeout=120s
  echo "  ✓ geth-devnet ready"
}

install_geth_lighthouse_side() {
  echo ""
  echo "🔧 Installing Geth node (lighthouse side)..."
  helm upgrade --install geth-lighthouse ethpandaops/geth \
    -f "$BASE_URL/geth-execution-lighthouse.yaml" -n "$NAMESPACE"
  echo "  ✓ geth-lighthouse installed"

  echo ""
  echo "⏳ Waiting for geth-lighthouse pod to be ready..."
  kubectl wait --for=condition=ready pod/geth-lighthouse-0 -n "$NAMESPACE" --timeout=120s
  echo "  ✓ geth-lighthouse ready"
}

install_prysm_beacon_and_validators() {
  echo ""
  echo "🔧 Installing Prysm beacon..."
  helm upgrade --install beacon-devnet-prysm ethpandaops/prysm \
    -f "$BASE_URL/beacon-chain.yaml" -n "$NAMESPACE"
  echo "  ✓ beacon-devnet-prysm installed"

  echo ""
  echo "⏳ Waiting for Prysm beacon to sync (90s)..."
  sleep 90

  echo ""
  echo "🔧 Installing Prysm validators..."
  helm upgrade --install validator-devnet-prysm ethpandaops/prysm \
    -f "$BASE_URL/validator.yaml" -n "$NAMESPACE"
  echo "  ✓ validator-devnet-prysm installed"

  echo ""
  echo "⏳ Waiting for Prysm chain to produce blocks (120s)..."
  sleep 120
}

install_lighthouse_beacon_and_validators() {
  echo ""
  echo "🔧 Installing Lighthouse beacon..."
  helm upgrade --install beacon-devnet-lighthouse ethpandaops/lighthouse \
    -f "$BASE_URL/beacon-chain-lighthouse.yaml" -n "$NAMESPACE"
  echo "  ✓ beacon-devnet-lighthouse installed"

  echo ""
  echo "⏳ Waiting for Lighthouse beacon to sync (90s)..."
  sleep 90

  echo ""
  echo "🔧 Installing Lighthouse validators..."
  helm upgrade --install validator-devnet-lighthouse ethpandaops/lighthouse \
    -f "$BASE_URL/validator-lighthouse.yaml" -n "$NAMESPACE"
  echo "  ✓ validator-devnet-lighthouse installed"

  echo ""
  echo "⏳ Waiting for Lighthouse chain to produce blocks (120s)..."
  sleep 120
}

install_blockscout_stack() {
  echo ""
  echo "🔧 Creating the Auth Secret for Blockscout..."
  kubectl apply -f "$BASE_URL/blockscout-db-auth.secret.yaml" --namespace "$NAMESPACE"
  echo "  ✓ Blockscout auth secret applied"

  echo ""
  echo "🔧 Installing PostgreSQL for Blockscout..."
  helm upgrade --install blockscout-db oci://registry-1.docker.io/bitnamicharts/postgresql \
    -n "$NAMESPACE" -f "$BASE_URL/block-postgresql.yaml"
  echo "  ✓ blockscout-db installed"

  echo ""
  echo "⏳ Waiting for PostgreSQL to be ready..."
  kubectl wait --for=condition=ready pod/blockscout-db-postgresql-0 -n "$NAMESPACE" --timeout=180s
  sleep 10
  echo "  ✓ PostgreSQL ready"

  echo ""
  echo "⏳ Creating the Postgres secret for Blockscout..."
  ./postgress-secret-script.sh
  sleep 10
  echo "  ✓ Postgres secret ready"

  echo ""
  echo "📊 Creating Blockscout stats database..."
  ./createStatsDB.sh && echo "  ✓ Stats database created" || echo "  ⚠ Stats DB creation had issues (may already exist)"
  sleep 10

  echo ""
  echo "🔧 Installing Blockscout..."
  helm upgrade --install blockscout blockscout/blockscout-stack \
    -n "$NAMESPACE" -f "$BASE_URL/blockscout-stack.yaml"
  echo "  ✓ blockscout installed"

  echo ""
  echo "📊 Blockscout should start indexing blocks from genesis"
  echo "🔗 Access Blockscout at:  https://mqube-blockscout-frontend.mqube-playground.com/"
}

final_status() {
  echo ""
  echo "🎉 Done! Final status:"
  echo ""
  kubectl get pods -n "$NAMESPACE"
}

#######################################
# Mode dispatcher
#######################################

case "$MODE" in
  full)
    echo "▶ Mode: full (uninstall + reinstall everything, including Blockscout)"
    uninstall_all
    install_geth_prysm_side
    install_geth_lighthouse_side
    install_prysm_beacon_and_validators
    install_lighthouse_beacon_and_validators
    install_blockscout_stack
    final_status
    ;;

  shutdown)
    echo "▶ Mode: shutdown (just uninstall everything and clean Blockscout PVC)"
    uninstall_all
    echo "✅ All devnet components have been uninstalled."
    ;;

  geth-prysm)
    echo "▶ Mode: geth-prysm (Geth devnet + Prysm beacon/validators only)"
    uninstall_all
    install_geth_prysm_side
    install_prysm_beacon_and_validators
    final_status
    ;;

  geth-lighthouse)
    echo "▶ Mode: geth-lighthouse (Geth lighthouse + Lighthouse beacon/validators only)"
    uninstall_all
    install_geth_lighthouse_side
    install_lighthouse_beacon_and_validators
    final_status
    ;;

  no-blockscout)
    echo "▶ Mode: no-blockscout (full EL+CL+validators, skip Blockscout)"
    uninstall_all
    install_geth_prysm_side
    install_geth_lighthouse_side
    install_prysm_beacon_and_validators
    install_lighthouse_beacon_and_validators
    final_status
    ;;

  blockscout-only)
    echo "▶ Mode: blockscout-only (reinstall Blockscout stack only)"
    uninstall_blockscout_only
    install_blockscout_stack
    final_status
    ;;

  *)
    echo "❌ Unknown mode: $MODE"
    echo "Usage: $0 {full|shutdown|geth-prysm|geth-lighthouse|no-blockscout|blockscout-only}"
    exit 1
    ;;
esac

