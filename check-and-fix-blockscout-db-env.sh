#!/usr/bin/env bash
set -euo pipefail

NS=${NS:-default}

# Bitnami Postgres release name (what you used when installing the chart)
REL=${REL:-blockscout-db}

# Blockscout Helm release (blockscout/blockscout-stack)
BS_RELEASE=${BS_RELEASE:-blockscout}
BS_DEPLOY="${BS_RELEASE}-blockscout-stack-blockscout"

PG_SVC="${REL}-postgresql"
PG_HOST="${PG_SVC}.${NS}.svc.cluster.local"
PG_PORT=5432

echo "==> Discovering Bitnami PostgreSQL settings…"
# Bitnami usually sets these envs on the StatefulSet
APP_USER="$(kubectl get sts "${PG_SVC}" -n "$NS" -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="POSTGRES_USER")].value}' 2>/dev/null || true)"
DB_NAME="$(kubectl get sts "${PG_SVC}" -n "$NS" -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="POSTGRES_DB")].value}' 2>/dev/null || true)"

# Fallbacks (match what you intended)
APP_USER="${APP_USER:-blockscout}"
DB_NAME="${DB_NAME:-blockscout}"

# App user password is in the Bitnami auth secret under key 'password'
APP_PASS="$(kubectl get secret "${REL}-auth" -n "$NS" -o jsonpath='{.data.password}' | base64 -d)"

echo "   PG host : ${PG_HOST}:${PG_PORT}"
echo "   User    : ${APP_USER}"
echo "   DB      : ${DB_NAME}"

# Build DB URLs — IMPORTANT: include the database name
DB_URL="postgresql://${APP_USER}:${APP_PASS}@${PG_HOST}:${PG_PORT}/${DB_NAME}?sslmode=disable"

echo "==> Creating/Updating secret 'blockscout-db-env' (DATABASE_URL, ACCOUNT_DATABASE_URL, *_SSL flags)…"
kubectl create secret generic blockscout-db-env -n "$NS" \
  --from-literal=DATABASE_URL="${DB_URL}" \
  --from-literal=ACCOUNT_DATABASE_URL="${DB_URL}" \
  --from-literal=DATABASE_SSL=false \
  --from-literal=ACCOUNT_DATABASE_SSL=false \
  --dry-run=client -o yaml | kubectl apply -f -


