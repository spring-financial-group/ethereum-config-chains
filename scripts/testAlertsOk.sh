#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="jx-observability"
PROM_DEPLOY="prometheus-server"
ALERTMANAGER_URL="http://localhost:9093"

# Unique suffix per run
RUN_ID="$(date +%s)"

CRIT_NAME="TestEthereumCritical_${RUN_ID}"
WARN_NAME="TestEthereumWarning_${RUN_ID}"

# Find the alertmanager pod dynamically
ALERT_POD="$(
  kubectl get pods -n "$NAMESPACE" \
    -l app.kubernetes.io/name=alertmanager,app.kubernetes.io/instance=prometheus \
    -o jsonpath='{.items[0].metadata.name}'
)"

echo "==> Using Alertmanager pod: $ALERT_POD"

echo "==> Checking Prometheus alerting rules with promtool..."
kubectl exec -n "$NAMESPACE" deploy/"$PROM_DEPLOY" \
  -c prometheus-server -- \
  promtool check rules /etc/config/alerting_rules.yml

echo "==> Checking Alertmanager config with amtool..."
kubectl exec -n "$NAMESPACE" "$ALERT_POD" \
  -c alertmanager -- \
  amtool check-config /etc/alertmanager/alertmanager.yml

echo "==> Sending test Ethereum alerts to Alertmanager..."
echo "    Critical alertname: $CRIT_NAME"
echo "    Warning  alertname: $WARN_NAME"

# Critical test alert -> ethereum-critical
kubectl exec -n "$NAMESPACE" "$ALERT_POD" \
  -c alertmanager -- \
  amtool --alertmanager.url="$ALERTMANAGER_URL" alert add "$CRIT_NAME" \
    severity=critical namespace=devnet component=execution \
    --annotation 'summary="Test Ethereum CRITICAL route"'

# Warning test alert -> ethereum-alerts
kubectl exec -n "$NAMESPACE" "$ALERT_POD" \
  -c alertmanager -- \
  amtool --alertmanager.url="$ALERTMANAGER_URL" alert add "$WARN_NAME" \
    severity=warning namespace=devnet component=execution \
    --annotation 'summary="Test Ethereum WARNING route"'

echo "==> Test alerts sent. Check Slack (#alerts-blockchain) / Alertmanager UI."
sleep 10

echo "==> Expiring test alerts from Alertmanager..."
# Expire any alerts whose alertname starts with TestEthereumCritical_ or TestEthereumWarning_
kubectl exec -n "$NAMESPACE" "$ALERT_POD" \
  -c alertmanager -- \
  amtool --alertmanager.url="$ALERTMANAGER_URL" alert expire 'alertname=~TestEthereumCritical_.*' || true

kubectl exec -n "$NAMESPACE" "$ALERT_POD" \
  -c alertmanager -- \
  amtool --alertmanager.url="$ALERTMANAGER_URL" alert expire 'alertname=~TestEthereumWarning_.*' || true

echo "==> Done. Configs valid, test alerts sent, and test alerts expired."

