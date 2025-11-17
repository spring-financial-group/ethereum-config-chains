#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# Config
# =========================
: "${NAMESPACE:=devnet}"
SECRET_NAME_PRYSM="validator-keystores-prysm"
SECRET_NAME_LIGHTHOUSE="validator-keystores-lighthouse"

# Paths
KEYSTORE_TAR="./keystores.tar.gz"
PRYSM_PASSWORD="./prysm-password.txt"
TEKU_SECRETS_DIR="./teku-secrets"
NIMBUS_KEYS_DIR="./nimbus-keys"

# Working directories
WORK_DIR="./split-keys"
PRYSM_DIR="$WORK_DIR/prysm"
LIGHTHOUSE_DIR="$WORK_DIR/lighthouse"

# =========================
# Pre-flight checks
# =========================
echo "=== Pre-flight checks ==="

if [ ! -f "$KEYSTORE_TAR" ]; then
  echo "ERROR: keystores.tar.gz not found." >&2
  exit 1
fi

if [ ! -f "$PRYSM_PASSWORD" ]; then
  echo "ERROR: prysm-password.txt not found." >&2
  exit 1
fi

if [ ! -d "$NIMBUS_KEYS_DIR" ]; then
  echo "ERROR: nimbus-keys directory not found." >&2
  exit 1
fi

echo "✓ All required files found"
echo

# =========================
# Split keystores
# =========================
echo "=== Splitting keystores ==="
rm -rf "$WORK_DIR"
mkdir -p "$PRYSM_DIR/nimbus-keys" "$LIGHTHOUSE_DIR/nimbus-keys"
mkdir -p "$PRYSM_DIR/teku-secrets" "$LIGHTHOUSE_DIR/teku-secrets"

# Get all validator directories sorted (without trailing slashes)
VALIDATOR_DIRS=($(ls "$NIMBUS_KEYS_DIR" | grep "^0x" | sort))
TOTAL_KEYS=${#VALIDATOR_DIRS[@]}
SPLIT_POINT=$((TOTAL_KEYS / 2))

echo "Total validator keys: $TOTAL_KEYS"
echo "Splitting at: $SPLIT_POINT"
echo "  Prysm:      validators 0-$((SPLIT_POINT-1)) ($SPLIT_POINT keys)"
echo "  Lighthouse: validators $SPLIT_POINT-$((TOTAL_KEYS-1)) ($((TOTAL_KEYS-SPLIT_POINT)) keys)"
echo

# Copy first half to Prysm
echo "Copying to Prysm..."
for ((i=0; i<SPLIT_POINT; i++)); do
  DIR="${VALIDATOR_DIRS[$i]}"
  cp -r "$NIMBUS_KEYS_DIR/$DIR" "$PRYSM_DIR/nimbus-keys/"
done

# Copy second half to Lighthouse
echo "Copying to Lighthouse..."
for ((i=SPLIT_POINT; i<TOTAL_KEYS; i++)); do
  DIR="${VALIDATOR_DIRS[$i]}"
  cp -r "$NIMBUS_KEYS_DIR/$DIR" "$LIGHTHOUSE_DIR/nimbus-keys/"
done

# Copy teku secrets
echo "Copying Teku secrets..."
for dir in "$PRYSM_DIR/nimbus-keys"/*/; do
  pubkey=$(basename "$dir")
  if [ -f "$TEKU_SECRETS_DIR/$pubkey.txt" ]; then
    cp "$TEKU_SECRETS_DIR/$pubkey.txt" "$PRYSM_DIR/teku-secrets/"
  fi
done

for dir in "$LIGHTHOUSE_DIR/nimbus-keys"/*/; do
  pubkey=$(basename "$dir")
  if [ -f "$TEKU_SECRETS_DIR/$pubkey.txt" ]; then
    cp "$TEKU_SECRETS_DIR/$pubkey.txt" "$LIGHTHOUSE_DIR/teku-secrets/"
  fi
done

# =========================
# Create tarballs
# =========================
echo "=== Creating split tarballs ==="
tar -czf "$PRYSM_DIR/keystores.tar.gz" -C "$PRYSM_DIR/nimbus-keys" .
tar -czf "$LIGHTHOUSE_DIR/keystores.tar.gz" -C "$LIGHTHOUSE_DIR/nimbus-keys" .

echo "✓ Created split tarballs"
echo

# =========================
# Verification
# =========================
echo "=== Verification ==="
prysm_count=$(find "$PRYSM_DIR/nimbus-keys" -name "keystore.json" | wc -l | awk '{print $1}')
lighthouse_count=$(find "$LIGHTHOUSE_DIR/nimbus-keys" -name "keystore.json" | wc -l | awk '{print $1}')
prysm_secrets=$(find "$PRYSM_DIR/teku-secrets" -name "*.txt" 2>/dev/null | wc -l | awk '{print $1}')
lighthouse_secrets=$(find "$LIGHTHOUSE_DIR/teku-secrets" -name "*.txt" 2>/dev/null | wc -l | awk '{print $1}')

echo "Prysm:"
echo "  Keystores: $prysm_count"
echo "  Secrets:   $prysm_secrets"
echo "Lighthouse:"
echo "  Keystores: $lighthouse_count"
echo "  Secrets:   $lighthouse_secrets"
echo

if [ "$prysm_count" -ne "$prysm_secrets" ] || [ "$lighthouse_count" -ne "$lighthouse_secrets" ]; then
  echo "ERROR: Keystore/secret count mismatch!" >&2
  exit 1
fi

# =========================
# Create Kubernetes Secrets
# =========================
echo "=== Creating Kubernetes secrets ==="

# Delete existing secrets if they exist
for SECRET in "$SECRET_NAME_PRYSM" "$SECRET_NAME_LIGHTHOUSE"; do
  if kubectl -n "$NAMESPACE" get secret "$SECRET" >/dev/null 2>&1; then
    echo "Deleting existing secret: $SECRET"
    kubectl -n "$NAMESPACE" delete secret "$SECRET"
  fi
done

# Create Prysm secret
echo "Creating Prysm secret with $prysm_count keys..."
kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME_PRYSM" \
  --from-file=keystores.tar.gz="$PRYSM_DIR/keystores.tar.gz" \
  --from-file=prysm-password.txt="$PRYSM_PASSWORD" \
  $(for f in "$PRYSM_DIR/teku-secrets"/*.txt; do [ -f "$f" ] && echo --from-file="$(basename "$f")=$f"; done)

# Create Lighthouse secret
echo "Creating Lighthouse secret with $lighthouse_count keys..."
kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME_LIGHTHOUSE" \
  --from-file=keystores.tar.gz="$LIGHTHOUSE_DIR/keystores.tar.gz" \
  --from-file=prysm-password.txt="$PRYSM_PASSWORD" \
  $(for f in "$LIGHTHOUSE_DIR/teku-secrets"/*.txt; do [ -f "$f" ] && echo --from-file="$(basename "$f")=$f"; done)

echo "✓ Secrets created successfully"
echo

# =========================
# Final verification
# =========================
echo "=== Final Verification ==="
echo "Prysm secret:"
kubectl -n "$NAMESPACE" describe secret "$SECRET_NAME_PRYSM" | grep -E '^Data|keystores.tar.gz'
echo ""
echo "Lighthouse secret:"
kubectl -n "$NAMESPACE" describe secret "$SECRET_NAME_LIGHTHOUSE" | grep -E '^Data|keystores.tar.gz'

# =========================
# Summary
# =========================
echo ""
echo "========================================="
echo "✅ Split complete!"
echo "========================================="
echo ""
echo "Created two secrets:"
echo "  1. $SECRET_NAME_PRYSM ($prysm_count validators)"
echo "  2. $SECRET_NAME_LIGHTHOUSE ($lighthouse_count validators)"
echo ""
echo "Next steps:"
echo "1. Update validator-devnet-prysm deployment to use: $SECRET_NAME_PRYSM"
echo "2. Update validator-devnet-lighthouse deployment to use: $SECRET_NAME_LIGHTHOUSE"
echo "3. Restart both validators"