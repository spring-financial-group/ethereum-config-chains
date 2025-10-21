# --- set enclave name
ENCLAVE=my-enclave

# local output dirs
mkdir -p validator_keys/vc validator_keys/keygen

# =========================
# 1) From the validator client
#    (Lighthouse VC usually mounts/imports keys here)
# =========================
kurtosis service exec "$ENCLAVE" vc-1-geth-lighthouse \
  "bash -lc 'tar czf - \
    /root/.lighthouse/validators \
    /root/.lighthouse/slashing_protection \
    /data/validators \
    /opt/keys \
    /validator_keys \
    /shared-data/keys \
    2>/dev/null | base64'" \
| base64 --decode > validator_keys/vc/vc_bundle.tgz

tar xzf validator_keys/vc/vc_bundle.tgz -C validator_keys/vc || true

# =========================
# 2) From the key-generation service
#    (this often holds the original keystores, deposit data, pw files)
# =========================
kurtosis service exec "$ENCLAVE" validator-key-generation-cl-validator-keystore \
  "bash -lc 'tar czf - \
    /validator_keys \
    /keys \
    /output \
    /artifacts \
    /data \
    /shared-data \
    2>/dev/null | base64'" \
| base64 --decode > validator_keys/keygen/keygen_bundle.tgz

tar xzf validator_keys/keygen/keygen_bundle.tgz -C validator_keys/keygen || true

# Permissions (keep secrets secret)
chmod -R go-rwx validator_keys

echo "✅ Done. Check ./validator_keys/{vc,keygen}"

