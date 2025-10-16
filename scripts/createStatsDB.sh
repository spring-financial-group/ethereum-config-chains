#!/usr/bin/env bash
set -euo pipefail

NS=${NS:-default}
SECRET=${SECRET:-blockscout-db-env}
KEY=${KEY:-DATABASE_URL}
STATS_DB=${STATS_DB:-blockscout_stats}

# 1) Pull the working DSN (already ends with ?sslmode=disable)
DB_URL="$(kubectl get secret "$SECRET" -n "$NS" -o jsonpath='{.data.'"$KEY"'}' | base64 -d)"

# 2) Build an admin DSN that points at the 'postgres' database (keeps query string intact)
#    e.g. .../blockscout?sslmode=disable  -> .../postgres?sslmode=disable
ADMIN_URL="$(echo "$DB_URL" | sed -E 's#(postgres(ql)?://[^/]+/)[^?]+#\1postgres#')"

echo "Creating DB '$STATS_DB' if missing…"
kubectl run pgtool --rm -it --restart=Never -n "$NS" \
  --image=registry-1.docker.io/bitnami/postgresql:latest -- \
  bash -lc "
set -euo pipefail
psql \"$ADMIN_URL\" -v ON_ERROR_STOP=1 -P pager=off -A -t \
  -c \"SELECT 1 FROM pg_database WHERE datname='${STATS_DB}';\" | grep -q 1 \
  || psql \"$ADMIN_URL\" -v ON_ERROR_STOP=1 -P pager=off -A -t \
       -c \"CREATE DATABASE ${STATS_DB} ENCODING 'UTF8';\"
"

