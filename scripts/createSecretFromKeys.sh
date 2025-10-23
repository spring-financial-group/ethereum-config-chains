#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# Config
# =========================
: "${NAMESPACE:=devnet}"
: "${SECRET_NAME:=validator-keystores}"

# Paths (from getKurtosisKeys.sh output)
KEYSTORE_TAR="./keystores.tar.gz"
PRYSM_PASSWORD="./prysm-password.txt"
TEKU_SECRETS_DIR="./teku-secrets"

# =========================
# Pre-flight checks
# =========================
echo "=== Pre-flight checks ==="

if [ ! -f "$KEYSTORE_TAR" ]; then
  echo "ERROR: keystores.tar.gz not found. Run ./getKurtosisKeys.sh first." >&2
  exit 1
fi

if [ ! -f "$PRYSM_PASSWORD" ]; then
  echo "ERROR: prysm-password.txt not found. Run ./getKurtosisKeys.sh first." >&2
  exit 1
fi

if [ ! -d "$TEKU_SECRETS_DIR" ] || [ -z "$(ls -A "$TEKU_SECRETS_DIR"/*.txt 2>/dev/null)" ]; then
  echo "ERROR: teku-secrets directory not found or empty. Run ./getKurtosisKeys.sh first." >&2
  exit 1
fi

# Count files
keystore_size=$(ls -lh "$KEYSTORE_TAR" | awk '{print $5}')
password_count=$(ls -1 "$TEKU_SECRETS_DIR"/*.txt 2>/dev/null | wc -l | awk '{print $1}')

echo "✓ Found keystores.tar.gz ($keystore_size)"
echo "✓ Found prysm-password.txt"
echo "✓ Found $password_count per-key password files"
echo

# =========================
# Create Kubernetes Secret
# =========================
echo "=== Creating Kubernetes secret ==="
echo "Namespace: $NAMESPACE"
echo "Secret name: $SECRET_NAME"
echo

# Delete existing secret if it exists
if kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" >/dev/null 2>&1; then
  echo "Deleting existing secret..."
  kubectl -n "$NAMESPACE" delete secret "$SECRET_NAME"
fi

# Build the secret with all files
echo "Creating new secret with:"
echo "  - keystores.tar.gz (Nimbus layout)"
echo "  - prysm-password.txt (fallback password)"
echo "  - $password_count per-key password files (0x*.txt)"
echo

kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
  --from-file=keystores.tar.gz="$KEYSTORE_TAR" \
  --from-file=prysm-password.txt="$PRYSM_PASSWORD" \
  $(for f in "$TEKU_SECRETS_DIR"/0x*.txt; do [ -f "$f" ] && echo --from-file="$(basename "$f")=$f"; done)

echo "✓ Secret created successfully"
echo

# =========================
# Verification
# =========================
echo "=== Verification ==="
echo "Secret contents:"
kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" -o jsonpath='{.data}' | jq -r 'keys[]' | head -20
echo "..."
echo

echo "Total keys in secret:"
kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" -o jsonpath='{.data}' | jq -r 'keys | length'
echo

echo "Secret size:"
kubectl -n "$NAMESPACE" describe secret "$SECRET_NAME" | grep -E '^Data|^===|keystores.tar.gz|prysm-password'
echo

# =========================
# Summary
# =========================
echo "========================================="
echo "✅ Secret created successfully!"
echo "========================================="
echo ""
echo "To use this secret in your validator pod, add to your deployment:"
echo ""
echo "  volumes:"
echo "    - name: validator-keys"
echo "      secret:"
echo "        secretName: $SECRET_NAME"
echo "  containers:"
echo "    - name: validator"
echo "      volumeMounts:"
echo "        - name: validator-keys"
echo "          mountPath: /keys"
echo "          readOnly: true"
echo ""
echo "Keys will be available at:"
echo "  /keys/keystores.tar.gz"
echo "  /keys/prysm-password.txt"
echo "  /keys/0x<PUBKEY>.txt (per-key passwords)"
