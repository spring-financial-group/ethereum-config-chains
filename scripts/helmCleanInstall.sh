#!/usr/bin/env bash

NS=${NS:-default}

helm uninstall blockscout -n "$NS" 

helm uninstall blockscout-db -n "$NS"

helm uninstall geth-devnet -n "$NS"  

helm uninstall beacon-devnet -n "$NS"

helm uninstall validator-devnet -n "$NS"

kubectl delete pvc data-blockscout-db-postgresql-0 -n "$NS"

helm upgrade --install geth-devnet ethpandaops/geth -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/geth-execution.yaml --namespace "$NS" --create-namespace

sleep 5

helm upgrade --install beacon-devnet ethpandaops/prysm -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/beacon-chain.yaml --namespace "$NS" --create-namespace

sleep 5

helm upgrade --install validator-devnet ethpandaops/prysm -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/validator.yaml --namespace "$NS" --create-namespace


sleep 5


kubectl apply -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/blockscout-db-auth.secret.yaml  --namespace "$NS"

helm upgrade --install blockscout-db oci://registry-1.docker.io/bitnamicharts/postgresql   -n default -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/block-postgresql.yaml -n "$NS"


./createStatsDB.sh


 helm upgrade --install blockscout blockscout/blockscout-stack   -n "$NS" -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/blockscout-stack.yaml
