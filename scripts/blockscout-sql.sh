#!/usr/bin/env bash
set -euo pipefail

# Usage: ./blockscout-sql.sh "SELECT * FROM blocks LIMIT 5;"
# Or:    ./blockscout-sql.sh -f query.sql
# 
# Environment variables:
#   NAMESPACE    - Kubernetes namespace (default: default)
#   SECRET       - Secret containing DATABASE_URL (default: blockscout-db-env)
#   KEY          - Key within secret (default: DATABASE_URL)

NAMESPACE=${NAMESPACE:-default}
SECRET=${SECRET:-blockscout-db-env}
KEY=${KEY:-DATABASE_URL}

usage() {
  cat <<EOF
Usage: $0 [OPTIONS] "SQL_QUERY"
       $0 [OPTIONS] -f QUERY_FILE

Run SQL queries against the Blockscout PostgreSQL database.

Options:
  -n, --namespace NAMESPACE   Kubernetes namespace (default: default)
  -s, --secret SECRET         Secret name (default: blockscout-db-env)
  -k, --key KEY               Key in secret (default: DATABASE_URL)
  -f, --file FILE             Read SQL from file instead of argument
  -h, --help                  Show this help message

Examples:
  $0 "SELECT MAX(number) FROM blocks;"
  $0 -n devnet "SELECT * FROM blocks ORDER BY number DESC LIMIT 5;"
  $0 -f my_query.sql

Common queries:
  # Check highest block
  $0 "SELECT MAX(number) as highest_block, MAX(timestamp) as last_time FROM blocks;"

  # Last 10 blocks
  $0 "SELECT number, timestamp, hash FROM blocks ORDER BY number DESC LIMIT 10;"

  # Block count by day
  $0 "SELECT DATE(timestamp) as day, COUNT(*) FROM blocks GROUP BY day ORDER BY day;"

  # Check when indexing stopped
  $0 "SELECT number, timestamp, inserted_at FROM blocks ORDER BY inserted_at DESC LIMIT 10;"
EOF
  exit 0
}

SQL_QUERY=""
SQL_FILE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -n|--namespace)
      NAMESPACE="$2"
      shift 2
      ;;
    -s|--secret)
      SECRET="$2"
      shift 2
      ;;
    -k|--key)
      KEY="$2"
      shift 2
      ;;
    -f|--file)
      SQL_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      SQL_QUERY="$1"
      shift
      ;;
  esac
done

# Get SQL from file if specified
if [[ -n "$SQL_FILE" ]]; then
  if [[ ! -f "$SQL_FILE" ]]; then
    echo "Error: SQL file not found: $SQL_FILE" >&2
    exit 1
  fi
  SQL_QUERY="$(cat "$SQL_FILE")"
fi

# Validate we have a query
if [[ -z "$SQL_QUERY" ]]; then
  echo "Error: No SQL query provided" >&2
  echo "Use -h for help" >&2
  exit 1
fi

# Get the DB URL from the secret
echo "Connecting to database (namespace: $NAMESPACE, secret: $SECRET)..." >&2

DB_URL="$(kubectl get secret "$SECRET" -n "$NAMESPACE" -o jsonpath='{.data.'"$KEY"'}' | base64 -d 2>/dev/null)" || {
  echo "Error: Could not retrieve DATABASE_URL from secret '$SECRET' in namespace '$NAMESPACE'" >&2
  exit 1
}

# Run the query using a temporary postgres pod
kubectl run pgtool-$$ --rm -i --restart=Never -n "$NAMESPACE" \
  --image=registry-1.docker.io/bitnami/postgresql:latest \
  --quiet=true \
  -- bash -lc "psql \"$DB_URL\" -P pager=off -c \"$SQL_QUERY\""
