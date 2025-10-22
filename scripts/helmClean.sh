#!/usr/bin/env bash

NS=${NS:-default}

helm uninstall blockscout -n "$NS" 

helm uninstall blockscout-db -n "$NS"

helm uninstall geth-devnet -n "$NS"  

helm uninstall beacon-devnet -n "$NS"

helm uninstall validator-devnet -n "$NS"

kubectl delete pvc data-blockscout-db-postgresql-0 -n "$NS"

