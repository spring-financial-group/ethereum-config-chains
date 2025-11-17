#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${DEBUG:-0}" -eq 1 ]] && set -x

# =========================
# Config
# =========================
: "${ENCLAVE:=my-testnet}"
: "${KURTOSIS_BIN:=/opt/homebrew/bin/kurtosis}"
export PATH="$(dirname "$KURTOSIS_BIN"):$PATH"
: "${KURTOSIS_CLI_LOG_LEVEL:=error}"
export KURTOSIS_CLI_LOG_LEVEL
: "${KEEP_RAW:=0}"
: "${SKIP_KEYGEN:=0}"
: "${SKIP_VC:=0}"
: "${KEYGEN_PATHS:=/node-0-keystores /keystores /keys /validator_keys /validator-keys /deposit-data /output /data/keystores /var/lib/validators}"

NIMBUS_DIR="nimbus-keys"
TEKU_DIR="teku-secrets"
RAW_ROOT=".artifacts/raw"
VC_DIR="$RAW_ROOT/validator_keys/vc"
KEYGEN_DIR="$RAW_ROOT/validator_keys/keygen"

mkdir -p "$RAW_ROOT" "$NIMBUS_DIR" "$TEKU_DIR"

# =========================
# Tar detection
# =========================
detect_tar() {
  if [[ -n "${TAR_BIN:-}" ]]; then echo "$TAR_BIN"; return; fi
  if command -v gtar >/dev/null 2>&1; then echo gtar; else echo tar; fi
}
TAR_BIN="$(detect_tar)"
is_gnu_tar=0
"$TAR_BIN" --version 2>/dev/null | head -1 | grep -qi 'gnu tar' && is_gnu_tar=1
gnu_extract_flags=(--no-same-owner --no-same-permissions --delay-directory-restore --overwrite --recursive-unlink)

echo "SCRIPT kurtosis bin : $(command -v kurtosis || true)"
echo "SCRIPT versions     :"; kurtosis version || true
echo "Kurtosis engine status:"; kurtosis engine status || true
echo "Using tar: $TAR_BIN ($([[ $is_gnu_tar -eq 1 ]] && echo 'GNU' || echo 'non-GNU'))"
echo

# =========================
# Helpers
# =========================
safe_rm_rf() {
  local target="$1"
  if [[ -e "$target" ]]; then
    command -v chflags >/dev/null 2>&1 && chflags -R nouchg "$target" 2>/dev/null || true
    chmod -R u+rwX "$target" 2>/dev/null || true
    rm -rf "$target" || true
  fi
}

list_services() {
  kurtosis enclave inspect "$ENCLAVE" 2>/dev/null \
    | awk 'BEGIN{in_services=0} /^Services:/ {in_services=1; next} /^Enclave/ {in_services=0} in_services && NF>0 {print}' \
    | sed -E 's/^[[:space:]-]+//; s/[[:space:]]+.*$//' \
    | grep -E '^[A-Za-z0-9._:-]+$' || true
}

pick_service() {
  list_services | grep -Ei "$1" || true | head -n1 || true
}

get_service_status() {
  kurtosis service inspect "$ENCLAVE" "$1" 2>/dev/null \
    | awk '/Status:/ {print tolower($2)}' | head -n1 || echo "unknown"
}

svc_exec() {
  local svc="$1"
  shift
  kurtosis --cli-log-level error service exec "$ENCLAVE" "$svc" "$1"
}

fetch_bundle() {
  local svc="$1" outfile="$2" tar_paths_str="$3"
  echo "==> [$svc] checking candidate paths..."
  local cmd_probe="bash -lc 'for p in $tar_paths_str; do [[ -e \"\$p\" ]] && echo \"FOUND: \$p\" || echo \"MISSING: \$p\"; done'"
  svc_exec "$svc" "$cmd_probe" || true

  local raw tmp
  raw="$(mktemp)"
  tmp="$(mktemp)"
  local cmd_tar="bash -lc 'printf \"BASE64-BEGIN\n\"; tar -P --ignore-failed-read -czf - $tar_paths_str 2>/dev/null | base64; printf \"\nBASE64-END\n\"'"
  if ! svc_exec "$svc" "$cmd_tar" 1> "$raw" 2> "${outfile}.exec.log"; then
    echo "ERROR: kurtosis exec failed" >&2
    rm -f "$raw" "$tmp"
    return 1
  fi

  awk '/^BASE64-BEGIN$/ {p=1; next} /^BASE64-END$/ {p=0} p && /^[A-Za-z0-9+\/=]+$/' "$raw" | base64 --decode > "$tmp" || {
    echo "ERROR: base64 decode failed" >&2
    rm -f "$raw" "$tmp"
    return 1
  }

  if ! "$TAR_BIN" tzf "$tmp" >/dev/null 2>&1; then
    echo "ERROR: not a valid .tgz" >&2
    rm -f "$raw" "$tmp"
    return 1
  fi

  local count
  count="$("$TAR_BIN" tzf "$tmp" | wc -l | awk '{print $1}')"
  if [[ "$count" -eq 0 ]]; then
    echo "ERROR: archive is empty" >&2
    rm -f "$raw" "$tmp"
    return 1
  fi

  mv "$tmp" "$outfile"
  rm -f "$raw"
  echo "OK: wrote $outfile ($count entries)"
  return 0
}

extract_bundle() {
  local tgz="$1" dest="$2"
  local tmpdir
  tmpdir="$(mktemp -d)"
  if [[ $is_gnu_tar -eq 1 ]]; then
    "$TAR_BIN" -xzf "$tgz" -C "$tmpdir" "${gnu_extract_flags[@]}"
  else
    "$TAR_BIN" -xzf "$tgz" -C "$tmpdir" || {
      echo "ERROR: tar extraction failed" >&2
      rm -rf "$tmpdir"
      return 1
    }
  fi
  safe_rm_rf "$dest"
  mkdir -p "$(dirname "$dest")"
  mv "$tmpdir" "$dest"
}

# =========================
# Pre-flight
# =========================
if ! (kurtosis enclave ls 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "${ENCLAVE}" || true); then
  echo "ERROR: Enclave '${ENCLAVE}' not found."
  kurtosis enclave ls || true
  exit 1
fi

VC_SERVICE="${VC_SERVICE:-$(pick_service 'vc.*light|light.*vc|lighthouse|vc-.*lighthouse')}"
KEYGEN_SERVICE="${KEYGEN_SERVICE:-$(pick_service 'key(gen|store)|validator.*keystore|keystore')}"
[[ -z "${VC_SERVICE:-}" ]] && VC_SERVICE="vc-1-geth-lighthouse"
[[ -z "${KEYGEN_SERVICE:-}" ]] && KEYGEN_SERVICE="validator-key-generation-cl-validator-keystore"

echo "Detected:"
echo "  ENCLAVE         = '${ENCLAVE}'"
echo "  VC_SERVICE      = '${VC_SERVICE}'"
echo "  KEYGEN_SERVICE  = '${KEYGEN_SERVICE}'"
echo

safe_rm_rf "$VC_DIR"
safe_rm_rf "$KEYGEN_DIR"
mkdir -p "$VC_DIR" "$KEYGEN_DIR"

# =========================
# 1) VC bundle
# =========================
if [[ "${SKIP_VC:-0}" -eq 0 ]]; then
  echo "=== Fetching VC bundle ==="
  # Check if VC service exists
  if kurtosis service inspect "$ENCLAVE" "$VC_SERVICE" >/dev/null 2>&1; then
    vc_tgz="$RAW_ROOT/vc_bundle.tgz"
    if fetch_bundle "$VC_SERVICE" "$vc_tgz" "/root/.lighthouse/custom/validators /root/.lighthouse/custom/slashing_protection.sqlite /validator-keys"; then
      extract_bundle "$vc_tgz" "$VC_DIR"
      echo "✓ VC bundle extracted"
    else
      echo "WARNING: Failed to fetch VC bundle (continuing anyway)" >&2
    fi
  else
    echo "ℹ VC service '$VC_SERVICE' not found, skipping"
  fi
else
  echo "SKIP_VC=1"
fi
echo

# =========================
# 2) Keygen bundle
# =========================
if [[ "${SKIP_KEYGEN:-0}" -eq 0 ]]; then
  echo "=== Fetching keygen bundle ==="
  keygen_tgz="$RAW_ROOT/keygen_bundle.tgz"
  status_keygen="$(get_service_status "$KEYGEN_SERVICE")"
  echo "Keygen service status: $status_keygen"

  if fetch_bundle "$KEYGEN_SERVICE" "$keygen_tgz" "$KEYGEN_PATHS"; then
    extract_bundle "$keygen_tgz" "$KEYGEN_DIR"
    echo "✓ Keygen bundle extracted"
  else
    echo "WARNING: Failed to fetch keygen bundle" >&2
  fi
else
  echo "SKIP_KEYGEN=1"
fi
echo

# =========================
# 3) Nimbus keystores
# =========================
echo "=== Assembling Nimbus keystores ==="
mkdir -p "$NIMBUS_DIR"

if [ -d "$VC_DIR/validator-keys/nimbus-keys" ]; then
  echo "Using pre-built Nimbus layout from VC bundle"
  cp -r "$VC_DIR/validator-keys/nimbus-keys/"* "$NIMBUS_DIR/" 2>/dev/null || true
elif [ -d "$KEYGEN_DIR/node-0-keystores/nimbus-keys" ]; then
  echo "Using Nimbus layout from keygen"
  rsync -a --delete "$KEYGEN_DIR/node-0-keystores/nimbus-keys/" "$NIMBUS_DIR/"
else
  echo "Building from keystores"
  find "$VC_DIR" "$KEYGEN_DIR" -type f \( -name 'keystore.json' -o -name 'keystore-*.json' \) 2>/dev/null | while IFS= read -r ks; do
    [ -f "$ks" ] || continue
    pub=""
    if command -v jq >/dev/null 2>&1; then
      pub="$(jq -r '.pubkey // empty' "$ks" 2>/dev/null || true)"
    fi
    if [ -z "$pub" ]; then
      pub="$(grep -Eo '"pubkey"[[:space:]]*:[[:space:]]*"0x[0-9a-fA-F]+"' "$ks" | head -n1 | sed -E 's/.*"(0x[0-9A-Fa-f]+)".*/\1/')"
    fi
    [ -z "$pub" ] && continue
    case "$pub" in 0x*) ;; *) pub="0x${pub}";; esac
    mkdir -p "$NIMBUS_DIR/$pub"
    cp -f "$ks" "$NIMBUS_DIR/$pub/"
  done
fi

keystore_count=$(find "$NIMBUS_DIR" -type f -name 'keystore*.json' 2>/dev/null | wc -l | awk '{print $1}')
echo "✓ Found $keystore_count keystores"
echo

# =========================
# 4) Teku secrets - FIXED!
# =========================
echo "=== Assembling Teku secrets ==="
mkdir -p "$TEKU_DIR"

# Check VC bundle first
if [ -d "$VC_DIR/validator-keys/teku-secrets" ]; then
  echo "Copying teku-secrets from VC bundle"
  cp -f "$VC_DIR/validator-keys/teku-secrets/"*.txt "$TEKU_DIR/" 2>/dev/null || true
fi

# Check keygen bundle - THIS WAS MISSING!
if [ -d "$KEYGEN_DIR/node-0-keystores/teku-secrets" ]; then
  echo "Copying teku-secrets from keygen bundle"
  cp -f "$KEYGEN_DIR/node-0-keystores/teku-secrets/"*.txt "$TEKU_DIR/" 2>/dev/null || true
fi

teku_count=$(find "$TEKU_DIR" -name "*.txt" -type f 2>/dev/null | wc -l | awk '{print $1}')
echo "✓ Found $teku_count Teku secrets"
echo

# =========================
# 5) Nimbus secrets
# =========================
echo "=== Checking Nimbus secrets ==="
secrets_existing=$(find "$NIMBUS_DIR" -name "secrets.txt" -type f 2>/dev/null | wc -l | awk '{print $1}')

if [ "$secrets_existing" -gt 0 ]; then
  echo "✓ Found $secrets_existing existing secrets"
  secrets_created=$secrets_existing
else
  echo "Creating secrets from Teku passwords"
  secrets_created=0
  for teku_secret in "$TEKU_DIR"/0x*.txt; do
    [ -f "$teku_secret" ] || continue
    pubkey=$(basename "$teku_secret" .txt)

    if [ -d "$NIMBUS_DIR/$pubkey" ]; then
      # Just copy directly, no base64 decode needed
      cp "$teku_secret" "$NIMBUS_DIR/$pubkey/secrets.txt"
      secrets_created=$((secrets_created + 1))
    fi
  done
  echo "✓ Created $secrets_created secrets"
fi
echo

# =========================
# 6) prysm-password.txt
# =========================
echo "=== Creating prysm-password.txt ==="
first_password=""

# Try teku-secrets first
if [ -z "$first_password" ]; then
  first_password=$(ls "$TEKU_DIR"/0x*.txt 2>/dev/null | head -n1)
fi

# Try nimbus secrets as fallback
if [ -z "$first_password" ]; then
  first_password=$(find "$NIMBUS_DIR" -name "secrets.txt" -type f 2>/dev/null | head -n1)
fi

if [ -n "$first_password" ] && [ -f "$first_password" ]; then
  cp -f "$first_password" ./prysm-password.txt
  echo "✓ Created prysm-password.txt"
else
  echo "WARNING: No passwords found" >&2
  touch ./prysm-password.txt
fi
echo

# =========================
# 7) Package
# =========================
echo "=== Packaging ==="
"$TAR_BIN" -czf keystores.tar.gz -C "$NIMBUS_DIR" .
chmod -R u+rwX,go-rwx keystores.tar.gz prysm-password.txt "$TEKU_DIR" "$NIMBUS_DIR" 2>/dev/null || true
echo "✓ Created keystores.tar.gz"
echo

# =========================
# 8) Cleanup
# =========================
if [[ "$KEEP_RAW" -eq 0 ]]; then
  safe_rm_rf "$RAW_ROOT"
else
  echo "KEEP_RAW=1: preserved raw artifacts"
fi

# =========================
# Summary
# =========================
echo "========================================="
echo "✅ Complete!"
echo "========================================="
echo ""
echo "Output files:"
echo "  - keystores.tar.gz"
echo "  - nimbus-keys/ ($keystore_count validators)"
echo "  - prysm-password.txt"
echo "  - teku-secrets/ ($teku_count passwords)"
echo ""
echo "Counts:"
echo "  Keystores:      $keystore_count"
echo "  Nimbus secrets: $secrets_created"
echo "  Teku passwords: $teku_count"
echo ""
if [[ "$keystore_count" -eq "$secrets_created" ]] && [[ "$keystore_count" -eq "$teku_count" ]]; then
  echo "✓ All validators complete"
else
  echo "⚠ Count mismatch - verify setup"
fi