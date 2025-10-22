#!/usr/bin/env bash

NS=${NS:-default}

kubectl apply -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/blockscout-db-auth.secret.yaml  --namespace "$NS"

helm upgrade --install blockscout-db oci://registry-1.docker.io/bitnamicharts/postgresql   -n "$NS" -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/block-postgresql.yaml -n "$NS"

sleep 120


./createStatsDB.sh


 helm upgrade --install blockscout blockscout/blockscout-stack   -n "$NS" -f https://raw.githubusercontent.com/spring-financial-group/ethereum-config-chains/main/helm-configs/blockscout-stack.yaml
