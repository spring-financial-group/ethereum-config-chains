NAMESPACE=${NAMESPACE:-default}
DB_URL=$(kubectl get secret blockscout-db-env -n $NAMESPACE -o jsonpath='{.data.DATABASE_URL}' | base64 -d)

# Re-run without a pager and with terse output
kubectl run pgtest --rm -it --restart=Never -n $NAMESPACE \
  --image=registry-1.docker.io/bitnami/postgresql:latest \
  -- psql "$DB_URL" -v ON_ERROR_STOP=1 -P pager=off -A -t \
  -c "select current_database(), current_user, version();"
