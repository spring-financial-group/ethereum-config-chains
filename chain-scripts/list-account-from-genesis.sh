jq -r '.alloc | to_entries[] | "\(.key) \(.value.balance)"' ../helm-configs/genesis.json
