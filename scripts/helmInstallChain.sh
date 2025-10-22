#!/usr/bin/env bash

NS=${NS:-default}

helm upgrade --install geth-devnet ethpandaops/geth -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/geth-execution.yaml --namespace "$NS" --create-namespace

sleep 5

helm upgrade --install beacon-devnet ethpandaops/prysm -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/beacon-chain.yaml --namespace "$NS" --create-namespace

sleep 5

helm upgrade --install validator-devnet ethpandaops/prysm -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/validator.yaml --namespace "$NS" --create-namespace

