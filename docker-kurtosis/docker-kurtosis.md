# You can create and downlaod the files like below passing in config files there are some example config files

1. **Ensure EL genesis exists** (creates `out/metadata/genesis.json`):

```bash
docker run --rm -u "$(id -u)"   -v "$PWD/out:/data"   ethpandaops/ethereum-genesis-generator:5.1.0 el
```

---

2. **Build the CL genesis with your 64 validators + fixed config:**

```bash
docker run --rm -u "$(id -u)"   -v "$PWD/out:/data"   -v "$PWD/config/cl-min64.yaml:/config/cl.yaml:ro"   -v "$PWD/config/mnemonics-64.yaml:/config/mnemonics.yaml:ro"   --entrypoint /bin/sh   ethpandaops/ethereum-genesis-generator:5.1.0 -lc '
    set -e
    mkdir -p /data/parsed
    test -s /data/metadata/genesis.json

    /usr/local/bin/eth-genesis-state-generator beaconchain       --config /config/cl.yaml       --eth1-config /data/metadata/genesis.json       --mnemonics /config/mnemonics.yaml       --state-output /data/metadata/genesis.ssz       --json-output /data/parsed/parsedConsensusGenesis.json

    jq -r .genesis_validators_root /data/parsed/parsedConsensusGenesis.json > /data/metadata/genesis_validators_root.txt
    printf "0\n" > /data/metadata/deposit_contract_block.txt
  '
```

---

### ✅ Outputs

After these steps, the following files are created:

- `out/metadata/genesis.json` — Execution Layer genesis  
- `out/metadata/genesis.ssz` — Consensus Layer genesis  
- `out/metadata/genesis_validators_root.txt` — Validators root  
- `out/metadata/deposit_contract_block.txt` — Deposit contract block height  
- `out/parsed/parsedConsensusGenesis.json` — Parsed CL genesis details  

---

### 🧰 Notes

- Requires Docker and `jq`
- Adjust `/config/` paths to your environment
- Both steps are idempotent — re-running safely overwrites outputs

