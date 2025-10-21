#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# Config (env overrides supported)
# =========================
: "${ENCLAVE:=devnet-ref}"
: "${KURTOSIS_BIN:=/usr/local/bin/kurtosis}"
export PATH="$(dirname "$KURTOSIS_BIN"):$PATH"
: "${KURTOSIS_CLI_LOG_LEVEL:=error}"   # keep Kurtosis CLI quiet on stdout
export KURTOSIS_CLI_LOG_LEVEL

# Where we’ll drop raw bundles & extracted trees
VC_DIR="validator_keys/vc"
KEYGEN_DIR="validator_keys/keygen"
mkdir -p "$VC_DIR" "$KEYGEN_DIR" scripts/nimbus-keys scripts/teku-secrets

# =========================
# Tar detection (GNU tar preferred)
# =========================
detect_tar() {
  if [[ -n "${TAR_BIN:-}" ]]; then
    echo "$TAR_BIN"
    return
  fi
  if command -v gtar >/dev/null 2>&1; then
    echo "gtar"
  else
    echo "tar"
  fi
}
TAR_BIN="$(detect_tar)"

is_gnu_tar=0
if "$TAR_BIN" --version 2>/dev/null | head -1 | grep -qi 'gnu tar'; then
  is_gnu_tar=1
fi

gnu_extract_flags=(--no-same-owner --no-same-permissions --delay-directory-restore --overwrite --recursive-unlink)

echo "SCRIPT kurtosis bin : $(command -v kurtosis)"
echo "SCRIPT versions     :"
kurtosis version || true
echo "Kurtosis info:"
kurtosis engine status || true
echo "Using tar: $TAR_BIN ($([[ $is_gnu_tar -eq 1 ]] && echo 'GNU' || echo 'non-GNU'))"

# =========================
# Helper: fetch framed base64 -> decode -> write tgz
# =========================
fetch_bundle () {
  local svc="$1"
  local outfile="$2"
  local tar_paths="$3"

  echo "==> [$svc] checking candidate paths..."
  kurtosis --cli-log-level error service exec "$ENCLAVE" "$svc" \
    "bash -lc 'for p in $tar_paths; do [[ -e \"\$p\" ]] && echo \"FOUND: \$p\" || echo \"MISSING: \$p\"; done'" || true

  local raw tmp
  raw="$(mktemp)"; tmp="$(mktemp)"

  # Frame payload inside the container; silence tar stderr; keep absolute names (-P)
  if ! kurtosis --cli-log-level error service exec "$ENCLAVE" "$svc" \
      "bash -lc 'printf \"BASE64-BEGIN\n\"; tar -P --ignore-failed-read -czf - $tar_paths 2>/dev/null | base64; printf \"\nBASE64-END\n\"'" \
      1> "$raw" 2> "${outfile}.exec.log"; then
    echo "ERROR: kurtosis exec failed for $svc (see ${outfile}.exec.log)" >&2
    sed -n '1,20p' "$raw" || true
    rm -f "$raw" "$tmp"
    exit 1
  fi

  # Extract only the base64 payload between markers; filter out any non-base64 lines
  awk '
    /^BASE64-BEGIN$/ {p=1; next}
    /^BASE64-END$/   {p=0}
    p && /^[A-Za-z0-9+\/=]+$/
  ' "$raw" | base64 --decode > "$tmp" || {
    echo "ERROR: base64 decode failed; raw at: $raw (log: ${outfile}.exec.log)" >&2
    rm -f "$raw" "$tmp"
    exit 1
  }

  # Validate the tar and ensure non-empty
  if ! "$TAR_BIN" tzf "$tmp" >/dev/null 2>&1; then
    echo "ERROR: decoded data is not a valid .tgz; raw at: $raw (log: ${outfile}.exec.log)" >&2
    rm -f "$raw" "$tmp"
    exit 1
  fi
  local count; count="$("$TAR_BIN" tzf "$tmp" | wc -l | awk '{print $1}')"
  if [[ "$count" -eq 0 ]]; then
    echo "ERROR: archive is empty — requested paths had no files. Raw at: $raw" >&2
    rm -f "$raw" "$tmp"
    exit 1
  fi

  mv "$tmp" "$outfile"
  rm -f "$raw"
  echo "OK: wrote $outfile ($count entries)"
}

# =========================
# Helper: extract safely to a fresh temp dir, then atomically swap into place
# =========================
extract_bundle () {
  local tgz="$1"
  local dest="$2"

  local tmpdir; tmpdir="$(mktemp -d)"

  if [[ $is_gnu_tar -eq 1 ]]; then
    "$TAR_BIN" -xzf "$tgz" -C "$tmpdir" "${gnu_extract_flags[@]}"
  else
    if ! "$TAR_BIN" -xzf "$tgz" -C "$tmpdir"; then
      echo "ERROR: Non-GNU tar had permission errors. Install GNU tar (gtar) or re-run this extract with sudo." >&2
      echo "Hint: TAR_BIN=gtar $0" >&2
      rm -rf "$tmpdir"
      exit 1
    fi
  fi

  rm -rf "$dest"
  mkdir -p "$(dirname "$dest")"
  mv "$tmpdir" "$dest"
}

# =========================
# 1) Lighthouse VC (usually: keystores + prysm-style per-key passwords + slashing DB)
# =========================
fetch_bundle \
  "vc-1-geth-lighthouse" \
  "$VC_DIR/vc_bundle.tgz" \
  "/root/.lighthouse/custom/validators \
   /root/.lighthouse/custom/slashing_protection.sqlite \
   /validator-keys"

extract_bundle "$VC_DIR/vc_bundle.tgz" "$VC_DIR"

# =========================
# 2) Key-generation service (usually: keystore JSONs + deposit data + password file[s])
# =========================
fetch_bundle \
  "validator-key-generation-cl-validator-keystore" \
  "$KEYGEN_DIR/keygen_bundle.tgz" \
  "/node-0-keystores"

extract_bundle "$KEYGEN_DIR/keygen_bundle.tgz" "$KEYGEN_DIR"

# Tighten perms on whatever we extracted
chmod -R u+rwX,go-rwx validator_keys || true

# =========================
# 3) Assemble Nimbus keystore layout + Teku secrets + prysm-password.txt
# =========================
echo "Assembling Nimbus keystore layout and Teku secrets…"
mkdir -p scripts/nimbus-keys scripts/teku-secrets

# Fast path: if keygen already gave us a Nimbus layout, copy it directly
if [ -d "$KEYGEN_DIR/node-0-keystores/nimbus-keys" ]; then
  echo "Using existing Nimbus layout from keygen output..."
  rsync -a --delete "$KEYGEN_DIR/node-0-keystores/nimbus-keys/" scripts/nimbus-keys/
else
  echo "No prebuilt nimbus-keys tree; building from found keystores..."
  # Match BOTH styles: keystore.json and keystore-*.json
  find "$VC_DIR" "$KEYGEN_DIR" -type f \( -name 'keystore.json' -o -name 'keystore-*.json' \) 2>/dev/null \
  | while IFS= read -r ks; do
      [ -f "$ks" ] || continue
      # pubkey via jq if available; fallback grep
      pub=""
      if command -v jq >/dev/null 2>&1; then
        pub="$(jq -r '.pubkey // empty' "$ks" 2>/dev/null || true)"
      fi
      if [ -z "$pub" ]; then
        pub="$(grep -Eo '"pubkey"[[:space:]]*:[[:space:]]*"0x[0-9a-fA-F]+"' "$ks" | head -n1 | sed -E 's/.*"(0x[0-9A-Fa-f]+)".*/\1/')"
      fi
      if [ -z "$pub" ]; then
        echo "WARN: could not read pubkey from $ks; skipping"
        continue
      fi
      case "$pub" in 0x*) ;; *) pub="0x${pub}";; esac
      mkdir -p "scripts/nimbus-keys/$pub"
      cp -f "$ks" "scripts/nimbus-keys/$pub/"
    done
fi

# Prysm-style per-key passwords from VC -> Teku secrets <0xPUBKEY>.txt
if [ -d "$VC_DIR/validator-keys/secrets" ]; then
  find "$VC_DIR/validator-keys/secrets" -maxdepth 1 -type f 2>/dev/null \
  | while IFS= read -r f; do
      base="$(basename "$f")"
      cp -f "$f" "scripts/teku-secrets/${base}.txt"
    done
fi

# Also copy any *password*.txt from keygen output (some stacks produce one file)
rm -f ./_maybe_single_password.txt 2>/dev/null || true
find "$KEYGEN_DIR" -type f -iname '*password*.txt' 2>/dev/null \
| while IFS= read -r f; do
    bn="$(basename "$f")"
    if echo "$bn" | grep -qiE '^0x[0-9a-f]+(\.txt)?$'; then
      cp -f "$f" "scripts/teku-secrets/${bn%.txt}.txt"
    else
      cp -f "$f" "./_maybe_single_password.txt"
    fi
  done

# Provide prysm-password.txt (fallback to any single password if no per-key files)
if ls scripts/teku-secrets/0x*.txt >/dev/null 2>&1; then
  cp -f "$(ls scripts/teku-secrets/0x*.txt | head -n1)" ./prysm-password.txt
elif [ -f ./_maybe_single_password.txt ]; then
  mv -f ./_maybe_single_password.txt ./prysm-password.txt
else
  echo "NOTE: No password files found; creating empty prysm-password.txt. Fill this if needed." >&2
  : > ./prysm-password.txt
fi

# Package keystores as Nimbus layout tarball
tar -czf keystores.tar.gz -C scripts/nimbus-keys .

# Lock down outputs
chmod -R u+rwX,go-rwx keystores.tar.gz prysm-password.txt scripts/teku-secrets || true

echo "✅ All done."
echo "Produced:"
echo "  - keystores.tar.gz (Nimbus layout)"
echo "  - prysm-password.txt"
echo "  - per-key Teku secrets under scripts/teku-secrets/ (if available)"
echo "Nimbus sample:"
find scripts/nimbus-keys -type f -name 'keystore*.json' | head -n 10 | sed 's/^/  /'


# Package keystores as Nimbus layout tarball
tar -czf keystores.tar.gz -C scripts/nimbus-keys .

# Lock down outputs
chmod -R u+rwX,go-rwx keystores.tar.gz prysm-password.txt scripts/teku-secrets || true

# =========================
# Done + sanity
# =========================
echo "✅ All done."
echo "Produced:"
echo "  - keystores.tar.gz (Nimbus layout)"
echo "  - prysm-password.txt"
echo "  - per-key Teku secrets under scripts/teku-secrets/ (if available)"
echo
echo "Quick sanity:"
echo "  Keystores (Nimbus):"
find scripts/nimbus-keys -type f -name 'keystore-*.json' -ls | head -n 20 || true
echo "  Per-key Teku secrets:"
ls -1 scripts/teku-secrets/0x*.txt 2>/dev/null | head -n 20 || true
echo
echo "If you’re on macOS and extraction ever fails, re-run with GNU tar explicitly:"
echo "  TAR_BIN=/opt/homebrew/bin/gtar $0"

