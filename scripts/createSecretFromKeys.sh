#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# Config
# =========================
: "${NAMESPACE:=devnet}"
: "${RESERVE_FOR_ROGUE:=3}"  # Reserve first N validators for rogue validator
SECRET_NAME_PRYSM="validator-keystores-prysm"
SECRET_NAME_LIGHTHOUSE="validator-keystores-lighthouse"
SECRET_NAME_ROGUE="validator-keystores-rogue"

# Paths
KEYSTORE_TAR="./keystores.tar.gz"
PRYSM_PASSWORD="./prysm-password.txt"
TEKU_SECRETS_DIR="./teku-secrets"
NIMBUS_KEYS_DIR="./nimbus-keys"

# Working directories
WORK_DIR="./split-keys"
PRYSM_DIR="$WORK_DIR/prysm"
LIGHTHOUSE_DIR="$WORK_DIR/lighthouse"
ROGUE_DIR="$WORK_DIR/rogue"

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
echo "=== Splitting keystores with $RESERVE_FOR_ROGUE reserved for rogue validator ==="
rm -rf "$WORK_DIR"
mkdir -p "$PRYSM_DIR/nimbus-keys" "$LIGHTHOUSE_DIR/nimbus-keys" "$ROGUE_DIR/nimbus-keys"
mkdir -p "$PRYSM_DIR/teku-secrets" "$LIGHTHOUSE_DIR/teku-secrets" "$ROGUE_DIR/teku-secrets"

# Get all validator directories sorted (without trailing slashes)
VALIDATOR_DIRS=($(ls "$NIMBUS_KEYS_DIR" | grep "^0x" | sort))
TOTAL_KEYS=${#VALIDATOR_DIRS[@]}

# Calculate split points
# Validators 0 to (RESERVE_FOR_ROGUE-1): Rogue
# Remaining validators split between Prysm and Lighthouse
REMAINING_KEYS=$((TOTAL_KEYS - RESERVE_FOR_ROGUE))
PRYSM_START=$RESERVE_FOR_ROGUE
PRYSM_END=$((PRYSM_START + REMAINING_KEYS / 2))
LIGHTHOUSE_START=$PRYSM_END

echo "Total validator keys: $TOTAL_KEYS"
echo "Distribution:"
echo "  Rogue:      validators 0-$((RESERVE_FOR_ROGUE-1)) ($RESERVE_FOR_ROGUE keys) ⚠️ WILL BE SLASHED"
echo "  Prysm:      validators $PRYSM_START-$((PRYSM_END-1)) ($((PRYSM_END-PRYSM_START)) keys)"
echo "  Lighthouse: validators $LIGHTHOUSE_START-$((TOTAL_KEYS-1)) ($((TOTAL_KEYS-LIGHTHOUSE_START)) keys)"
echo

# Copy first RESERVE_FOR_ROGUE validators to Rogue
echo "Copying to Rogue (for slashing demo)..."
for ((i=0; i<RESERVE_FOR_ROGUE; i++)); do
  DIR="${VALIDATOR_DIRS[$i]}"
  cp -r "$NIMBUS_KEYS_DIR/$DIR" "$ROGUE_DIR/nimbus-keys/"
  echo "  Reserved for slashing: $DIR"
done

# Copy Prysm validators
echo "Copying to Prysm..."
for ((i=PRYSM_START; i<PRYSM_END; i++)); do
  DIR="${VALIDATOR_DIRS[$i]}"
  cp -r "$NIMBUS_KEYS_DIR/$DIR" "$PRYSM_DIR/nimbus-keys/"
done

# Copy Lighthouse validators
echo "Copying to Lighthouse..."
for ((i=LIGHTHOUSE_START; i<TOTAL_KEYS; i++)); do
  DIR="${VALIDATOR_DIRS[$i]}"
  cp -r "$NIMBUS_KEYS_DIR/$DIR" "$LIGHTHOUSE_DIR/nimbus-keys/"
done

# Copy teku secrets for Rogue
echo "Copying Teku secrets for Rogue..."
for dir in "$ROGUE_DIR/nimbus-keys"/*/; do
  pubkey=$(basename "$dir")
  if [ -f "$TEKU_SECRETS_DIR/$pubkey.txt" ]; then
    cp "$TEKU_SECRETS_DIR/$pubkey.txt" "$ROGUE_DIR/teku-secrets/"
  fi
done

# Copy teku secrets for Prysm
echo "Copying Teku secrets for Prysm..."
for dir in "$PRYSM_DIR/nimbus-keys"/*/; do
  pubkey=$(basename "$dir")
  if [ -f "$TEKU_SECRETS_DIR/$pubkey.txt" ]; then
    cp "$TEKU_SECRETS_DIR/$pubkey.txt" "$PRYSM_DIR/teku-secrets/"
  fi
done

# Copy teku secrets for Lighthouse
echo "Copying Teku secrets for Lighthouse..."
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
tar -czf "$ROGUE_DIR/keystores.tar.gz" -C "$ROGUE_DIR/nimbus-keys" .
tar -czf "$PRYSM_DIR/keystores.tar.gz" -C "$PRYSM_DIR/nimbus-keys" .
tar -czf "$LIGHTHOUSE_DIR/keystores.tar.gz" -C "$LIGHTHOUSE_DIR/nimbus-keys" .

echo "✓ Created split tarballs"
echo

# =========================
# Verification
# =========================
echo "=== Verification ==="
rogue_count=$(find "$ROGUE_DIR/nimbus-keys" -name "keystore.json" | wc -l | awk '{print $1}')
prysm_count=$(find "$PRYSM_DIR/nimbus-keys" -name "keystore.json" | wc -l | awk '{print $1}')
lighthouse_count=$(find "$LIGHTHOUSE_DIR/nimbus-keys" -name "keystore.json" | wc -l | awk '{print $1}')
rogue_secrets=$(find "$ROGUE_DIR/teku-secrets" -name "*.txt" 2>/dev/null | wc -l | awk '{print $1}')
prysm_secrets=$(find "$PRYSM_DIR/teku-secrets" -name "*.txt" 2>/dev/null | wc -l | awk '{print $1}')
lighthouse_secrets=$(find "$LIGHTHOUSE_DIR/teku-secrets" -name "*.txt" 2>/dev/null | wc -l | awk '{print $1}')

echo "Rogue:"
echo "  Keystores: $rogue_count"
echo "  Secrets:   $rogue_secrets"
echo "Prysm:"
echo "  Keystores: $prysm_count"
echo "  Secrets:   $prysm_secrets"
echo "Lighthouse:"
echo "  Keystores: $lighthouse_count"
echo "  Secrets:   $lighthouse_secrets"
echo

if [ "$rogue_count" -ne "$rogue_secrets" ] || [ "$prysm_count" -ne "$prysm_secrets" ] || [ "$lighthouse_count" -ne "$lighthouse_secrets" ]; then
  echo "ERROR: Keystore/secret count mismatch!" >&2
  exit 1
fi

# =========================
# Create Kubernetes Secrets
# =========================
echo "=== Creating Kubernetes secrets ==="

# Delete existing secrets if they exist
for SECRET in "$SECRET_NAME_ROGUE" "$SECRET_NAME_PRYSM" "$SECRET_NAME_LIGHTHOUSE"; do
  if kubectl -n "$NAMESPACE" get secret "$SECRET" >/dev/null 2>&1; then
    echo "Deleting existing secret: $SECRET"
    kubectl -n "$NAMESPACE" delete secret "$SECRET"
  fi
done

# Create Rogue secret (for slashing demo - DO NOT START YET)
echo "Creating Rogue secret with $rogue_count keys (⚠️ DO NOT DEPLOY YET)..."
kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME_ROGUE" \
  --from-file=keystores.tar.gz="$ROGUE_DIR/keystores.tar.gz" \
  --from-file=prysm-password.txt="$PRYSM_PASSWORD" \
  $(for f in "$ROGUE_DIR/teku-secrets"/*.txt; do [ -f "$f" ] && echo --from-file="$(basename "$f")=$f"; done)

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
echo "Rogue secret:"
kubectl -n "$NAMESPACE" describe secret "$SECRET_NAME_ROGUE" | grep -E '^Data|keystores.tar.gz'
echo ""
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
echo "Created three secrets:"
echo "  1. $SECRET_NAME_ROGUE ($rogue_count validators) ⚠️ FOR SLASHING DEMO ONLY"
echo "  2. $SECRET_NAME_PRYSM ($prysm_count validators)"
echo "  3. $SECRET_NAME_LIGHTHOUSE ($lighthouse_count validators)"
echo ""
echo "Next steps:"
echo "1. Update validator-devnet-prysm to use: $SECRET_NAME_PRYSM"
echo "2. Update validator-devnet-lighthouse to use: $SECRET_NAME_LIGHTHOUSE"
echo "3. Restart both validators"
echo "4. Wait for them to activate and propose blocks"
echo "5. THEN deploy rogue validator for slashing demo"
echo ""
echo "⚠️  WARNING: Rogue validator will use same keys as itself (duplicate)"
echo "    This will cause slashing of validators 0-$((RESERVE_FOR_ROGUE-1))"
echo "    Your working Prysm/Lighthouse validators will NOT be affected!"