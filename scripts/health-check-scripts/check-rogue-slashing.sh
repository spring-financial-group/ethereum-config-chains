#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-devnet}"

# Start port-forward in background
kubectl port-forward -n "$NS" beacon-devnet-prysm-0 3500:3500 >/dev/null 2>&1 &
PF_PID=$!
sleep 2

# Cleanup function
cleanup() {
  kill $PF_PID 2>/dev/null || true
}
trap cleanup EXIT

echo "╔═══════════════════════════════════════╗"
echo "║   ROGUE VALIDATOR SLASHING CHECK      ║"
echo "╚═══════════════════════════════════════╝"
echo ""

echo ">>> Checking Rogue Validators (0-4)"
echo ""

slashed_count=0

for idx in 0 1 2 3 4; do
  validator_data=$(curl -s "http://localhost:3500/eth/v1/beacon/states/head/validators/$idx" 2>/dev/null)

  status=$(echo "$validator_data" | jq -r '.data.status // "unknown"')
  slashed=$(echo "$validator_data" | jq -r '.data.validator.slashed // "false"')
  balance=$(echo "$validator_data" | jq -r '.data.balance // "0"')
  effective_balance=$(echo "$validator_data" | jq -r '.data.validator.effective_balance // "0"')

  balance_eth=$(echo "scale=6; $balance / 1000000000" | bc -l)
  effective_eth=$(echo "scale=6; $effective_balance / 1000000000" | bc -l)

  if [ "$slashed" == "true" ]; then
    echo "  Validator $idx: 🔥 SLASHED"
    echo "    Status: $status"
    echo "    Balance: $balance_eth ETH (started at 32 ETH)"
    echo "    Effective Balance: $effective_eth ETH"
    slashed_count=$((slashed_count + 1))
  else
    echo "  Validator $idx: Status=$status, Slashed=$slashed"
    echo "    Balance: $balance_eth ETH"
    echo "    Effective Balance: $effective_eth ETH"
  fi
done

echo ""
echo ">>> Summary"
echo "Slashed validators: $slashed_count / 5"

if [ $slashed_count -eq 5 ]; then
  echo "🔥 ALL ROGUE VALIDATORS HAVE BEEN SLASHED!"
elif [ $slashed_count -gt 0 ]; then
  echo "⚠️  Partial slashing detected"
else
  echo "ℹ️  No validators marked as slashed yet"
  echo "    (Balance loss of ~2.3 ETH could be from attestation penalties)"
fi

echo ""
echo ">>> Rogue Pods Status"
kubectl get pods -n "$NS" | grep rogue-prysm

echo ""
echo ">>> Recent Attestations from Rogue Validators"
echo "Replica 0:"
kubectl logs -n "$NS" validator-devnet-rogue-prysm-0 --tail=5 | grep -i "attestation\|proposal" || echo "  (no recent activity)"
echo ""
echo "Replica 1:"
kubectl logs -n "$NS" validator-devnet-rogue-prysm-1 --tail=5 | grep -i "attestation\|proposal" || echo "  (no recent activity)"

echo ""