#!/bin/bash
# generate-accounts.sh
# Generate all Ethereum accounts needed for a testnet
#
# Creates:
#   1. Pre-funded accounts (for testing transactions)
#   2. Fee recipient account (for validator block rewards)
#   3. Withdrawal account (for validator withdrawals)
#
# Usage: ./generate-accounts.sh [number_of_prefunded_accounts] [balance_in_eth]

set -e

NUM_ACCOUNTS=${1:-30}
BALANCE_ETH=${2:-1000}

# Convert ETH to Wei (decimal) - 1000 ETH = 1000 * 10^18 wei
# ethereum-genesis-generator expects decimal format, not hex
BALANCE_WEI="1000000000000000000000"

# Output directory and files
OUTPUT_DIR="./accounts"
mkdir -p "$OUTPUT_DIR"

ACCOUNTS_FILE="$OUTPUT_DIR/accounts.txt"
GENESIS_ALLOC_FILE="$OUTPUT_DIR/genesis_alloc.json"
FEE_RECIPIENT_FILE="$OUTPUT_DIR/fee_recipient_account.txt"
WITHDRAWAL_FILE="$OUTPUT_DIR/withdrawal_account.txt"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}          Generate Ethereum Testnet Accounts                   ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Pre-funded accounts: ${BLUE}${NUM_ACCOUNTS}${NC}"
echo -e "  Balance per account: ${BLUE}${BALANCE_ETH} ETH${NC}"
echo ""

# Check Docker is available
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is required but not installed"
    exit 1
fi

# =============================================================================
echo -e "${GREEN}=== Generating Pre-funded Accounts ===${NC}"
# =============================================================================

echo "=== Generated Accounts ===" > "$ACCOUNTS_FILE"
echo "Generated on: $(date)" >> "$ACCOUNTS_FILE"
echo "Number of accounts: $NUM_ACCOUNTS" >> "$ACCOUNTS_FILE"
echo "" >> "$ACCOUNTS_FILE"

echo "{" > "$GENESIS_ALLOC_FILE"

for i in $(seq 1 $NUM_ACCOUNTS); do
  # Generate account using Foundry Docker
  result=$(docker run --rm ghcr.io/foundry-rs/foundry:latest "cast wallet new" 2>/dev/null)

  address=$(echo "$result" | grep "Address:" | awk '{print $2}')
  privkey=$(echo "$result" | grep "Private key:" | awk '{print $3}')

  # Convert address to lowercase for genesis.json
  address_lower=$(echo "$address" | tr '[:upper:]' '[:lower:]')

  # Write to accounts file
  echo "Account $i:" >> "$ACCOUNTS_FILE"
  echo "  Address:     $address" >> "$ACCOUNTS_FILE"
  echo "  Private Key: $privkey" >> "$ACCOUNTS_FILE"
  echo "" >> "$ACCOUNTS_FILE"

  # Write to genesis alloc JSON (with trailing comma - we'll add more)
  echo "  \"$address_lower\": { \"balance\": \"$BALANCE_WEI\" }," >> "$GENESIS_ALLOC_FILE"

  # Progress
  if [ $((i % 10)) -eq 0 ] || [ $i -eq $NUM_ACCOUNTS ]; then
    echo "  Generated $i/$NUM_ACCOUNTS accounts..."
  fi
done

echo ""

# =============================================================================
echo -e "${GREEN}=== Generating Fee Recipient Account ===${NC}"
# =============================================================================

result=$(docker run --rm ghcr.io/foundry-rs/foundry:latest "cast wallet new" 2>/dev/null)
FEE_ADDRESS=$(echo "$result" | grep "Address:" | awk '{print $2}')
FEE_PRIVKEY=$(echo "$result" | grep "Private key:" | awk '{print $3}')
FEE_ADDRESS_LOWER=$(echo "$FEE_ADDRESS" | tr '[:upper:]' '[:lower:]')

echo "=== Fee Recipient Account ===" > "$FEE_RECIPIENT_FILE"
echo "Generated on: $(date)" >> "$FEE_RECIPIENT_FILE"
echo "" >> "$FEE_RECIPIENT_FILE"
echo "Address:     $FEE_ADDRESS" >> "$FEE_RECIPIENT_FILE"
echo "Private Key: $FEE_PRIVKEY" >> "$FEE_RECIPIENT_FILE"
echo "" >> "$FEE_RECIPIENT_FILE"
echo "Use in validator config:" >> "$FEE_RECIPIENT_FILE"
echo "  --suggested-fee-recipient=$FEE_ADDRESS" >> "$FEE_RECIPIENT_FILE"
echo "" >> "$FEE_RECIPIENT_FILE"
echo "Genesis alloc entry (if you want to pre-fund it):" >> "$FEE_RECIPIENT_FILE"
echo "\"$FEE_ADDRESS_LOWER\": { \"balance\": \"0\" }" >> "$FEE_RECIPIENT_FILE"

echo "  Address: $FEE_ADDRESS"

# Add to genesis_alloc with zero balance (optional, just to have it in genesis)
echo "  \"$FEE_ADDRESS_LOWER\": { \"balance\": \"0\" }," >> "$GENESIS_ALLOC_FILE"

echo ""

# =============================================================================
echo -e "${GREEN}=== Generating Withdrawal Account ===${NC}"
# =============================================================================

result=$(docker run --rm ghcr.io/foundry-rs/foundry:latest "cast wallet new" 2>/dev/null)
WITHDRAWAL_ADDRESS=$(echo "$result" | grep "Address:" | awk '{print $2}')
WITHDRAWAL_PRIVKEY=$(echo "$result" | grep "Private key:" | awk '{print $3}')
WITHDRAWAL_ADDRESS_LOWER=$(echo "$WITHDRAWAL_ADDRESS" | tr '[:upper:]' '[:lower:]')

echo "=== Withdrawal Account ===" > "$WITHDRAWAL_FILE"
echo "Generated on: $(date)" >> "$WITHDRAWAL_FILE"
echo "" >> "$WITHDRAWAL_FILE"
echo "Address:     $WITHDRAWAL_ADDRESS" >> "$WITHDRAWAL_FILE"
echo "Private Key: $WITHDRAWAL_PRIVKEY" >> "$WITHDRAWAL_FILE"
echo "" >> "$WITHDRAWAL_FILE"
echo "Use when generating validator keys:" >> "$WITHDRAWAL_FILE"
echo "  --eth1_withdrawal_address=$WITHDRAWAL_ADDRESS" >> "$WITHDRAWAL_FILE"
echo "" >> "$WITHDRAWAL_FILE"
echo "Genesis alloc entry (if you want to pre-fund it):" >> "$WITHDRAWAL_FILE"
echo "\"$WITHDRAWAL_ADDRESS_LOWER\": { \"balance\": \"0\" }" >> "$WITHDRAWAL_FILE"

echo "  Address: $WITHDRAWAL_ADDRESS"

# Add to genesis_alloc with zero balance (last entry, no comma)
echo "  \"$WITHDRAWAL_ADDRESS_LOWER\": { \"balance\": \"0\" }" >> "$GENESIS_ALLOC_FILE"

# Close JSON
echo "}" >> "$GENESIS_ALLOC_FILE"

echo ""

# =============================================================================
echo -e "${GREEN}=== Summary ===${NC}"
# =============================================================================

echo ""
echo "  Files created:"
echo "    - $ACCOUNTS_FILE           (${NUM_ACCOUNTS} pre-funded accounts)"
echo "    - $GENESIS_ALLOC_FILE      (for genesis.json alloc section)"
echo "    - $FEE_RECIPIENT_FILE      (for validator --suggested-fee-recipient)"
echo "    - $WITHDRAWAL_FILE         (for validator key generation)"
echo ""
echo "  Key addresses:"
echo "    Fee Recipient:  $FEE_ADDRESS"
echo "    Withdrawal:     $WITHDRAWAL_ADDRESS"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
