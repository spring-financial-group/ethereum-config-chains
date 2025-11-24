jq -r '.alloc | to_entries[] | "\(.key) \(.value.balance)"' ../network-configs/private-net/metadata/genesis.json
