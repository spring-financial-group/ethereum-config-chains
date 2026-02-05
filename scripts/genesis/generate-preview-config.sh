#!/bin/bash
# generate-preview-config.sh
# Generates a complete Ethereum testnet configuration for a PR preview environment
#
# This script orchestrates the full genesis generation process:
#   1. Creates unique output directory (PR-{number}-{timestamp})
#   2. Generates accounts (pre-funded, fee recipient, withdrawal)
#   3. Generates genesis files (genesis.json, genesis.ssz, config.yaml)
#   4. Outputs the config path for use in helm deployments
#
# Usage: ./generate-preview-config.sh --pr <number> [OPTIONS]
#
# Required:
#   --pr NUM              PR number for unique identification
#
# Optional:
#   --mnemonic "WORDS"    BIP39 mnemonic for validator keys
#   --mnemonic-file FILE  Read mnemonic from file
#   --validators NUM      Number of validators (default: 128)
#   --chain-id ID         Chain ID (default: 3151909)
#   --output-base DIR     Base output directory (default: ./network-configs/preview)
#   --skip-accounts       Skip account generation (use existing)
#   --dry-run             Show what would be done without executing
#
# Output:
#   Creates: {output-base}/PR-{number}-{timestamp}/metadata/
#   Prints CONFIG_PATH to stdout on success
#
# Example:
#   ./generate-preview-config.sh --pr 42 --validators 64
#   # Output: CONFIG_PATH=preview/PR-42-1738123456

set -euo pipefail

# Defaults
PR_NUMBER=""
MNEMONIC=""
MNEMONIC_FILE=""
VALIDATORS=128
CHAIN_ID=3151909
OUTPUT_BASE="./network-configs/preview"
SKIP_ACCOUNTS=false
DRY_RUN=false

# Script directory (for finding other scripts)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --pr)
            PR_NUMBER="$2"
            shift 2
            ;;
        --mnemonic)
            MNEMONIC="$2"
            shift 2
            ;;
        --mnemonic-file)
            MNEMONIC_FILE="$2"
            shift 2
            ;;
        --validators)
            VALIDATORS="$2"
            shift 2
            ;;
        --chain-id)
            CHAIN_ID="$2"
            shift 2
            ;;
        --output-base)
            OUTPUT_BASE="$2"
            shift 2
            ;;
        --skip-accounts)
            SKIP_ACCOUNTS=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            head -40 "$0" | tail -n +2 | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$PR_NUMBER" ]; then
    log_error "PR number is required. Use --pr <number>"
    exit 1
fi

# Generate timestamp and unique directory name
TIMESTAMP=$(date +%s)
CONFIG_DIR_NAME="PR-${PR_NUMBER}-${TIMESTAMP}"
CONFIG_PATH="${OUTPUT_BASE}/${CONFIG_DIR_NAME}"
METADATA_PATH="${CONFIG_PATH}/metadata"

log_info "==========================================="
log_info "Generate Preview Config for PR-${PR_NUMBER}"
log_info "==========================================="
log_info ""
log_info "Configuration:"
log_info "  PR Number:     ${PR_NUMBER}"
log_info "  Timestamp:     ${TIMESTAMP}"
log_info "  Validators:    ${VALIDATORS}"
log_info "  Chain ID:      ${CHAIN_ID}"
log_info "  Output Path:   ${CONFIG_PATH}"
log_info ""

if [ "$DRY_RUN" = true ]; then
    log_warn "DRY RUN - No changes will be made"
    echo "CONFIG_PATH=preview/${CONFIG_DIR_NAME}"
    exit 0
fi

# Create output directories
mkdir -p "${CONFIG_PATH}"
mkdir -p "${METADATA_PATH}"

# Create working directory for intermediate files
WORK_DIR="${CONFIG_PATH}/work"
mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}"

# Resolve mnemonic
if [ -n "$MNEMONIC_FILE" ] && [ -f "$MNEMONIC_FILE" ]; then
    MNEMONIC=$(head -1 "$MNEMONIC_FILE" | xargs)
    log_info "Loaded mnemonic from file: $MNEMONIC_FILE"
elif [ -z "$MNEMONIC" ]; then
    # Generate a new mnemonic for this preview
    log_warn "No mnemonic provided. Generating new one for this preview."
    # Use a deterministic mnemonic based on PR number for reproducibility within same PR
    # In production, you might want to store this securely
    MNEMONIC="test test test test test test test test test test test junk"
    log_warn "Using default test mnemonic. For unique validators, provide --mnemonic or --mnemonic-file"
fi

# Save mnemonic for genesis script
echo "$MNEMONIC" > mnemonic.txt

# Step 1: Generate accounts (if not skipped)
if [ "$SKIP_ACCOUNTS" = false ]; then
    log_info ""
    log_info "Step 1: Generating accounts..."
    log_info "---"

    if [ -f "${SCRIPT_DIR}/generate-accounts.sh" ]; then
        bash "${SCRIPT_DIR}/generate-accounts.sh" 30 1000
    else
        log_error "generate-accounts.sh not found at ${SCRIPT_DIR}"
        exit 1
    fi
else
    log_info "Skipping account generation (--skip-accounts)"
    mkdir -p accounts
fi

# Step 2: Generate genesis files
log_info ""
log_info "Step 2: Generating genesis files..."
log_info "---"

if [ -f "${SCRIPT_DIR}/generate-genesis.sh" ]; then
    bash "${SCRIPT_DIR}/generate-genesis.sh" \
        --validators "$VALIDATORS" \
        --chain-id "$CHAIN_ID" \
        --genesis-delay 120 \
        --output-dir ./genesis \
        --clean
else
    log_error "generate-genesis.sh not found at ${SCRIPT_DIR}"
    exit 1
fi

# Step 3: Copy generated files to metadata directory
log_info ""
log_info "Step 3: Copying files to metadata directory..."
log_info "---"

# Required files for the Helm charts
REQUIRED_FILES=(
    "genesis/genesis.json"
    "genesis/genesis.ssz"
    "genesis/config.yaml"
    "genesis/deposit_contract_block.txt"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        cp "$file" "${METADATA_PATH}/"
        log_info "  Copied: $(basename $file)"
    else
        log_warn "  Missing: $file"
    fi
done

# Copy web3signer-compatible config if exists
if [ -f "genesis/config-web3signer.yaml" ]; then
    cp "genesis/config-web3signer.yaml" "${METADATA_PATH}/"
    log_info "  Copied: config-web3signer.yaml"
fi

# Copy generation info
if [ -f "genesis/generation-info.json" ]; then
    cp "genesis/generation-info.json" "${METADATA_PATH}/"
    log_info "  Copied: generation-info.json"
fi

# Step 4: Create preview metadata
log_info ""
log_info "Step 4: Creating preview metadata..."
log_info "---"

cat > "${METADATA_PATH}/preview-info.json" << EOF
{
    "pr_number": ${PR_NUMBER},
    "timestamp": ${TIMESTAMP},
    "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "validators": ${VALIDATORS},
    "chain_id": ${CHAIN_ID},
    "config_path": "preview/${CONFIG_DIR_NAME}",
    "mnemonic_hint": "$(echo "$MNEMONIC" | awk '{print $1, $2, "...", $(NF-1), $NF}')"
}
EOF
log_info "  Created: preview-info.json"

# Cleanup working directory (optional - keep for debugging)
# rm -rf "${WORK_DIR}"

# Output the config path (this is what the pipeline will capture)
log_info ""
log_info "==========================================="
log_info "Preview config generated successfully!"
log_info "==========================================="
log_info ""
log_info "Config Path: preview/${CONFIG_DIR_NAME}"
log_info "Full URL: https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/network-configs/preview/${CONFIG_DIR_NAME}/metadata"
log_info ""
log_info "Files created:"
ls -la "${METADATA_PATH}/"
log_info ""

# Output for pipeline to capture
echo "CONFIG_PATH=preview/${CONFIG_DIR_NAME}"
