#!/bin/bash
# restart-devnet.sh - Clean restart of entire devnet

BASE_URL="https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs"
NAMESPACE="devnet"
echo "🧹 Step 1: Uninstalling everything..."
RELEASES=$(helm list -n $NAMESPACE -q)

# Only the releases that actually exist
for release in validator-devnet-prysm validator-devnet-lighthouse beacon-devnet-prysm beacon-devnet-lighthouse blockscout blockscout-db geth-devnet geth-lighthouse; do
  if echo "$RELEASES" | grep -q "^${release}$"; then
    echo "  Uninstalling $release..."
    helm uninstall $release -n $NAMESPACE
  else
    echo "  Skipping $release (not found)"
  fi
done

kubectl delete pvc data-blockscout-db-postgresql-0 -n $NAMESPACE 2>/dev/null || true
sleep 30

echo ""
echo "🔧 Step 4: Installing Geth nodes..."
helm upgrade --install geth-devnet ethpandaops/geth \
  -f $BASE_URL/geth-execution.yaml -n $NAMESPACE --create-namespace
echo "  ✓ geth-devnet installed"

helm upgrade --install geth-lighthouse ethpandaops/geth \
  -f $BASE_URL/geth-execution-lighthouse.yaml -n $NAMESPACE
echo "  ✓ geth-lighthouse installed"

echo ""
echo "⏳ Step 5: Waiting for Geth pods to be ready..."
kubectl wait --for=condition=ready pod/geth-devnet-0 -n $NAMESPACE --timeout=120s
kubectl wait --for=condition=ready pod/geth-lighthouse-0 -n $NAMESPACE --timeout=120s
echo "  ✓ Both Geth pods ready"

echo ""
echo "🔧 Step 6: Installing beacons..."
helm upgrade --install beacon-devnet-prysm ethpandaops/prysm \
  -f $BASE_URL/beacon-chain.yaml -n $NAMESPACE
echo "  ✓ beacon-devnet-prysm installed"

helm upgrade --install beacon-devnet-lighthouse ethpandaops/lighthouse \
  -f $BASE_URL/beacon-chain-lighthouse.yaml -n $NAMESPACE
echo "  ✓ beacon-devnet-lighthouse installed"

echo ""
echo "⏳ Step 7: Waiting for beacons to sync (90s)..."
sleep 90

echo ""
echo "🔧 Step 8: Installing validators..."
helm upgrade --install validator-devnet-prysm ethpandaops/prysm \
  -f $BASE_URL/validator.yaml -n $NAMESPACE
echo "  ✓ validator-devnet-prysm installed"

helm upgrade --install validator-devnet-lighthouse ethpandaops/lighthouse \
  -f $BASE_URL/validator-lighthouse.yaml -n $NAMESPACE
echo "  ✓ validator-devnet-lighthouse installed"

echo ""
echo "⏳ Step 9: Waiting for chain to produce blocks (120s)..."
sleep 120


echo ""
echo "🔧 Step 10: Create the Auth Secret for Block Scout..."
kubectl apply -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/blockscout-db-auth.secret.yaml  --namespace $NAMESPACE
echo "  ✓ blockscout-db installed"

echo ""
echo "🔧 Step 11: Installing PostgreSQL for Blockscout..."
helm upgrade --install blockscout-db oci://registry-1.docker.io/bitnamicharts/postgresql \
  -n $NAMESPACE -f $BASE_URL/block-postgresql.yaml
echo "  ✓ blockscout-db installed"


echo ""
echo "⏳ Step 12: Waiting for PostgreSQL to be ready..."
kubectl wait --for=condition=ready pod/blockscout-db-postgresql-0 -n $NAMESPACE --timeout=180s
sleep 10
echo "  ✓ PostgreSQL ready"

echo ""
echo "⏳ Step 13: Create the Post secret for Block Scout..."
./postgress-secret-script.sh
sleep 10
echo "  ✓ PostgreSQL ready"


echo ""
echo "📊 Step 14: Creating Blockscout stats database..."
./createStatsDB.sh && echo "  ✓ Stats database created" || echo "  ⚠ Stats DB creation had issues (may already exist)"
sleep 10
echo "  ✓ Stats database created"

echo ""
echo "🔧 Step 15: Installing Blockscout..."
helm upgrade --install blockscout blockscout/blockscout-stack \
  -n $NAMESPACE -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/blockscout-stack.yaml
echo "  ✓ blockscout installed"

echo ""
echo "🎉 Done! Final status:"
echo ""
kubectl get pods -n $NAMESPACE

echo ""
echo "📊 Blockscout should start indexing blocks from genesis"
echo "🔗 Access Blockscout at:  https://mqube-blockscout-frontend.mqube-playground.com/"