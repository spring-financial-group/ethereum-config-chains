#!/bin/bash

RPC_URL="https://rpc-geth-node.mqube-playground.com"

echo "=== MQube Devnet Info ==="
echo "RPC: $RPC_URL"
echo ""

# Get chain ID
chain_hex=$(curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' | jq -r '.result')

chain_id=$(python3 -c "print(int('$chain_hex', 16))")
echo "Chain ID: $chain_id (hex: $chain_hex)"

# Get block number
block_hex=$(curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq -r '.result')

block_num=$(python3 -c "print(int('$block_hex', 16))")
echo "Current Block: $block_num"
echo ""

# Check first 3 accounts
echo "=== Account Balances ==="
ACCOUNTS=(
  "0x8943545177806ED17B9F23F0a21ee5948eCaa776"
  "0xE25583099BA105D9ec0A67f5Ae86D90e50036425"
  "0x614561D2d143621E126e87831AEF287678B442b8"
)

for i in "${!ACCOUNTS[@]}"; do
  addr="${ACCOUNTS[$i]}"
  
  balance_hex=$(curl -s -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$addr\",\"latest\"],\"id\":1}" | jq -r '.result')
  
  if [ "$balance_hex" != "null" ]; then
    balance_eth=$(python3 -c "print(f'{int(\"$balance_hex\", 16) / 10**18:,.0f}')")
    echo "Account $i: $addr"
    echo "  Balance: $balance_eth ETH"
  fi
done

echo ""
echo "=== MetaMask Setup ==="
echo "Network Name:     MQube Devnet"
echo "RPC URL:          $RPC_URL"
echo "Chain ID:         $chain_id"
echo "Currency Symbol:  ETH"
