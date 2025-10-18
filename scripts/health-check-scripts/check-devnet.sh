#!/usr/bin/env bash
set -Eeuo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

export EXIT=0

run(){ echo; echo ">>> $(basename "$1" .sh)"; bash "$1" || true; }

run "$DIR/10_discovery.sh"
run "$DIR/20_network.sh"
run "$DIR/30_jwt.sh"
run "$DIR/40_genesis_and_head.sh"
run "$DIR/50_merge_check.sh"
run "$DIR/60_engine_traffic.sh"
#run "$DIR/90_logs.sh"


# ===================== 70 images =====================

# Helper: print images for a single pod (spec + resolved imageIDs)
print_pod_images() {
  local ns="$1" pod="$2"
  echo
  echo "Pod: ${ns}/${pod}"

  # Spec (what was requested)
  kubectl -n "$ns" get pod "$pod" -o json \
  | jq -r '
      def rows($kind): (.spec[$kind] // []) | map({name:.name, image:.image});
      (rows("initContainers")[]? | "  init  \(.name): \(.image)"),
      (rows("containers")[]?     | "  run   \(.name): \(.image)")' || true

  # Resolved (what actually ran; includes digests)
  kubectl -n "$ns" get pod "$pod" -o json \
  | jq -r '
      def rows($kind): (.status[$kind] // []) | map({name:.name, imageID:.imageID});
      (rows("initContainerStatuses")[]? | select(.imageID!=null) | "  init  \(.name): \(.imageID)"),
      (rows("containerStatuses")[]?     | select(.imageID!=null) | "  run   \(.name): \(.imageID)")' \
  | sed 's#^docker-pullable://##; s#^containerd://##' || true
}

# Print EL / CL / VC if the script already discovered them
if [[ -n "${EL_POD:-}" && -n "${EL_NS:-}" ]]; then
  print_pod_images "$EL_NS" "$EL_POD"
fi
if [[ -n "${CL_POD:-}" && -n "${CL_NS:-}" ]]; then
  print_pod_images "$CL_NS" "$CL_POD"
fi
if [[ -n "${VC_POD:-}" && -n "${VC_NS:-}" ]]; then
  print_pod_images "$VC_NS" "$VC_POD"
fi

# Unique list of all images (spec) in the namespace
echo
echo "All images (spec) in namespace ${K8S_NS:-default}:"
kubectl ${K8S_NS:+-n "$K8S_NS"} get pods -o json \
| jq -r '
    [
      .items[]
      | (.spec.initContainers[]?.image),
        (.spec.containers[]?.image)
    ]
    | map(select(.!=null))
    | unique[]' \
| sort

# Unique list of resolved imageIDs/digests (what actually ran)
echo
echo "All resolved imageIDs in namespace ${K8S_NS:-default}:"
kubectl ${K8S_NS:+-n "$K8S_NS"} get pods -o json \
| jq -r '
    [
      .items[]
      | (.status.initContainerStatuses[]?.imageID),
        (.status.containerStatuses[]?.imageID)
    ]
    | map(select(.!=null))
    | map(gsub("^(docker-pullable://|containerd://)"; ""))
    | unique[]' \
| sort



exit "${EXIT:-0}"
