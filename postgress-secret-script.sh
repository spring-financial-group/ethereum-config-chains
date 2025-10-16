i#!/usr/bin/env bash
set -euo pipefail

NS=${NS:-default}

# Bitnami Postgres release name (what you used when installing the chart)
REL=${REL:-blockscout-db}

PG_SVC="${REL}-postgresql"
PG_HOST="${PG_SVC}.${NS}.svc.cluster.local"
PG_PORT=5432

echo "==> Discovering Bitnami PostgreSQL settings…"
APP_USER="$(kubectl get sts "${PG_SVC}" -n "$NS" -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="POSTGRES_USER")].value}' 2>/dev/null || true)"
DB_NAME="$(kubectl get sts "${PG_SVC}" -n "$NS" -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="POSTGRES_DB")].value}' 2>/dev/null || true)"

# Fallbacks
APP_USER="${APP_USER:-blockscout}"
DB_NAME="${DB_NAME:-blockscout}"
STATS_DB="${STATS_DB:-${DB_NAME}_stats}"

# App user password is in the Bitnami auth secret under key 'password'
APP_PASS="$(kubectl get secret "${REL}-auth" -n "$NS" -o jsonpath='{.data.password}' | base64 -d)"

echo "   PG host : ${PG_HOST}:${PG_PORT}"
echo "   User    : ${APP_USER}"
echo "   App DB  : ${DB_NAME}"
echo "   StatsDB : ${STATS_DB} (will NOT be created by this script)"

# Build DSNs — include DB name and sslmode
APP_DB_URL="postgresql://${APP_USER}:${APP_PASS}@${PG_HOST}:${PG_PORT}/${DB_NAME}?sslmode=disable"
STATS_DB_URL="postgresql://${APP_USER}:${APP_PASS}@${PG_HOST}:${PG_PORT}/${STATS_DB}?sslmode=disable"

echo "==> Creating/Updating secret 'blockscout-db-env' (backend URLs + legacy flags)…"
kubectl create secret generic blockscout-db-env -n "$NS" \
  --from-literal=DATABASE_URL="${APP_DB_URL}" \
  --from-literal=ACCOUNT_DATABASE_URL="${APP_DB_URL}" \
  --from-literal=DATABASE_SSL=false \
  --from-literal=ACCOUNT_DATABASE_SSL=false \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Creating/Updating secret 'blockscout-stats-env' (stats & blockscout URLs)…"
kubectl create secret generic blockscout-stats-env -n "$NS" \
  --from-literal=STATS_DB_URL="${STATS_DB_URL}" \
  --from-literal=STATS_BLOCKSCOUT_DB_URL="${APP_DB_URL}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "✅ Done. Secrets updated:
  - blockscout-db-env:     DATABASE_URL, ACCOUNT_DATABASE_URL, *_SSL flags
  - blockscout-stats-env:  STATS_DB_URL, STATS_BLOCKSCOUT_DB_URL"


