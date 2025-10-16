#!/usr/bin/env bash
set -euo pipefail

NS=default
REL=blockscout-db

APP_USER=$(kubectl get sts ${REL}-postgresql -n $NS -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="POSTGRES_USER")].value}')
DB_NAME=$(kubectl get sts ${REL}-postgresql -n $NS -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="POSTGRES_DB")].value}')
APP_PASS=$(kubectl get secret ${REL}-auth -n $NS -o jsonpath='{.data.password}' | base64 -d)
PG_HOST=${REL}-postgresql.${NS}.svc.cluster.local
PG_PORT=5432

DB_URL="postgresql://${APP_USER}:${APP_PASS}@${PG_HOST}:${PG_PORT}/${DB_NAME}?sslmode=disable"

# Recreate the env secret atomically with all keys:
kubectl delete secret blockscout-db-env -n $NS --ignore-not-found
kubectl create secret generic blockscout-db-env -n $NS \
  --from-literal=DATABASE_URL="${DB_URL}" \
  --from-literal=ACCOUNT_DATABASE_URL="${DB_URL}" \
  --from-literal=DATABASE_SSL="false" \
  --from-literal=ACCOUNT_DATABASE_SSL="false" \
  --from-literal=PGHOST="${PG_HOST}" \
  --from-literal=PGPORT="${PG_PORT}" \
  --from-literal=PGUSER="${APP_USER}" \
  --from-literal=PGPASSWORD="${APP_PASS}" \
  --from-literal=PGDATABASE="${DB_NAME}"

