# Genesis Generation Scripts

Scripts for generating Ethereum testnet genesis configurations.

## Scripts

### generate-preview-config.sh

Main entry point for PR pipeline. Generates a complete config for a preview environment.

```bash
# Basic usage
./generate-preview-config.sh --pr 42

# With custom validators and mnemonic
./generate-preview-config.sh --pr 42 --validators 64 --mnemonic-file /path/to/mnemonic.txt

# Dry run (show what would be done)
./generate-preview-config.sh --pr 42 --dry-run
```

**Output:** Creates `network-configs/preview/PR-{number}-{timestamp}/metadata/` with:
- `genesis.json` - Execution layer genesis
- `genesis.ssz` - Consensus layer genesis state
- `config.yaml` - Beacon chain config
- `config-web3signer.yaml` - Web3Signer compatible config
- `deposit_contract_block.txt` - Deposit contract deployment block
- `preview-info.json` - Metadata about the preview

### generate-accounts.sh

Generates Ethereum accounts for testing:
- Pre-funded accounts (for transactions)
- Fee recipient account (for block rewards)
- Withdrawal account (for validator withdrawals)

```bash
./generate-accounts.sh [num_accounts] [balance_eth]
# Default: 30 accounts with 1000 ETH each
```

### generate-genesis.sh

Generates genesis files using ethpandaops/ethereum-genesis-generator.

```bash
./generate-genesis.sh \
  --validators 128 \
  --chain-id 3151909 \
  --mnemonic-file mnemonic.txt \
  --output-dir ./genesis
```

## Pipeline Integration

The PR pipeline uses these scripts to generate unique configs:

```yaml
# In pipeline step
- name: generate-genesis
  image: docker:latest
  script: |
    # Clone config repo
    git clone https://github.com/spring-financial-group/ethereum-config-chains.git
    cd ethereum-config-chains

    # Generate config for this PR
    CONFIG_OUTPUT=$(./scripts/genesis/generate-preview-config.sh --pr $PULL_NUMBER)
    CONFIG_PATH=$(echo "$CONFIG_OUTPUT" | grep CONFIG_PATH | cut -d= -f2)

    # Commit and push
    git add network-configs/preview/
    git commit -m "Add preview config for PR-$PULL_NUMBER"
    git push

    # Export for helm
    echo "CONFIG_PATH=$CONFIG_PATH" >> $GITHUB_OUTPUT
```

## Directory Structure

```
network-configs/
├── azure-staging/          # Static production config
│   └── metadata/
│       ├── genesis.json
│       ├── genesis.ssz
│       └── config.yaml
└── preview/                # PR-based configs
    ├── PR-42-1738123456/
    │   └── metadata/
    └── PR-43-1738200000/
        └── metadata/
```

## Requirements

- Docker (for running ethereum-genesis-generator and foundry)
- bash
- jq (for JSON processing)
- git (for pipeline commits)
