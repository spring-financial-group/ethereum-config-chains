#!/usr/bin/env bash
# Quick installation guide for the updated health check scripts

echo "Installing updated dual-setup health check scripts..."

# Make all scripts executable
chmod +x *.sh

echo "✓ Scripts made executable"

# Test if we can find pods
echo ""
echo "Testing pod discovery..."

export NS=devnet

PRYSM_CL=$(kubectl get pod -n $NS -l app.kubernetes.io/instance=beacon-devnet-prysm -o name 2>/dev/null | head -1)
LIGHTHOUSE_CL=$(kubectl get pod -n $NS -l app.kubernetes.io/instance=beacon-devnet-lighthouse -o name 2>/dev/null | head -1)

if [[ -n "$PRYSM_CL" ]]; then
  echo "✓ Found Prysm beacon: $PRYSM_CL"
else
  echo "⚠ Prysm beacon not found"
fi

if [[ -n "$LIGHTHOUSE_CL" ]]; then
  echo "✓ Found Lighthouse beacon: $LIGHTHOUSE_CL"
else
  echo "⚠ Lighthouse beacon not found"
fi

echo ""
echo "Installation complete!"
echo ""
echo "Usage:"
echo "  ./check-devnet.sh              # Run full health check"
echo "  NS=your-namespace ./check-devnet.sh   # Override namespace"
echo ""
echo "See README.md for full documentation"
