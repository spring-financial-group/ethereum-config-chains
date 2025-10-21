# 1) Point to your run folder
RUN_DIR="./out/validator-keys"
KEYSTORE_DIR="$RUN_DIR/nimbus-keys"     # folders named 0xPUBKEY/keystore-*.json
TEKU_SECRETS="$RUN_DIR/teku-secrets"    # contains 0xPUBKEY.txt password files

# 2) Create the keystore tarball (Nimbus layout)
tar -czf keystores.tar.gz -C "$KEYSTORE_DIR" .

# 3) Choose your password strategy:

# (A) Single password for all keys -> make prysm-password.txt
#     If all keys share the same password, reuse one of the Teku txt files:
cp "$(ls "$TEKU_SECRETS"/0x*.txt | head -n1)" ./prysm-password.txt

# --OR--

# (B) Per-key passwords -> keep the 0x*.txt files as overrides (preferred if they exist).
#     Still provide a fallback prysm-password.txt (pick any one, or type yours):
cp "$(ls "$TEKU_SECRETS"/0x*.txt | head -n1)" ./prysm-password.txt

# 4) Recreate the Secret in the *devnet* namespace (that’s where your validator reads it)
kubectl -n devnet delete secret validator-keystores --ignore-not-found

# Single password only:
# kubectl -n devnet create secret generic validator-keystores \
#   --from-file=keystores.tar.gz=./keystores.tar.gz \
#   --from-file=prysm-password.txt=./prysm-password.txt

# Single + per-key overrides (adds all 0x*.txt files from teku-secrets):
kubectl -n devnet create secret generic validator-keystores \
  --from-file=keystores.tar.gz=./keystores.tar.gz \
  --from-file=prysm-password.txt=./prysm-password.txt \
  $(for f in "$TEKU_SECRETS"/0x*.txt; do [ -f "$f" ] && echo --from-file="$(basename "$f")=$f"; done)

# 5) Sanity check: you should see keystores.tar.gz, prysm-password.txt, and lots of 0x....txt entries
kubectl -n devnet describe secret validator-keystores | sed -n '1,120p'

