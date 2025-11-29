#!/bin/bash
# update-bootnode-config.sh
# Updates bootstrap_nodes.txt and bootstrap_nodes.yaml with current bootnode info

set -e

NAMESPACE="${1:-devnet}"
BOOTNODE_POD="${2:-beacon-bootnode-lighthouse-0}"
OUTPUT_DIR="${3:-.}"

echo "=== Fetching bootnode info from $BOOTNODE_POD in namespace $NAMESPACE ==="

# Get current ENR from logs
CURRENT_ENR=$(kubectl logs "$BOOTNODE_POD" -n "$NAMESPACE" -c lighthouse 2>/dev/null | grep -o 'enr:[^"]*' | tail -1)
if [[ -z "$CURRENT_ENR" ]]; then
  echo "ERROR: Could not find ENR in bootnode logs"
  exit 1
fi
echo "Current ENR: $CURRENT_ENR"

# Get pod IP
POD_IP=$(kubectl get pod "$BOOTNODE_POD" -n "$NAMESPACE" -o jsonpath='{.status.podIP}')
if [[ -z "$POD_IP" ]]; then
  echo "ERROR: Could not get pod IP"
  exit 1
fi
echo "Pod IP: $POD_IP"

# Get peer ID from logs (Identity established line)
echo "Fetching peer ID from logs..."
PEER_ID=$(kubectl logs "$BOOTNODE_POD" -n "$NAMESPACE" -c lighthouse 2>/dev/null | grep "Identity established" | grep -oE '16Uiu[A-Za-z0-9]+' | head -1)

if [[ -z "$PEER_ID" ]]; then
  echo "ERROR: Could not get peer ID from logs"
  exit 1
fi
echo "Peer ID: $PEER_ID"

# Update bootstrap_nodes.yaml
YAML_FILE="$OUTPUT_DIR/bootstrap_nodes.yaml"
echo "Updating $YAML_FILE..."
cat > "$YAML_FILE" << EOF
- "$CURRENT_ENR"
EOF
echo "  Done"

# Update bootstrap_nodes.txt (multiaddr format)
TXT_FILE="$OUTPUT_DIR/bootstrap_nodes.txt"
echo "Updating $TXT_FILE..."
cat > "$TXT_FILE" << EOF
/ip4/$POD_IP/udp/9000/p2p/$PEER_ID
EOF
echo "  Done"

echo ""
echo "=== Updated files ==="
echo "bootstrap_nodes.yaml:"
cat "$YAML_FILE"
echo ""
echo "bootstrap_nodes.txt:"
cat "$TXT_FILE"
echo ""
echo "=== Next steps ==="
echo "1. git add $YAML_FILE $TXT_FILE"
echo "2. git commit -m 'Update bootnode ENR and multiaddr'"
echo "3. git push"
echo "4. kubectl delete pod beacon-devnet-prysm-0 beacon-devnet-lighthouse-0 -n $NAMESPACE"
