#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "10_discovery"

need kubectl
need jq

EL_POD="$(get_pod "$EL_LABEL")"; [[ -n "$EL_POD" ]] && pass "Found EL pod: $EL_POD" || fail "EL pod not found"
CL_POD="$(get_pod "$CL_LABEL")"; [[ -n "$CL_POD" ]] && pass "Found CL pod: $CL_POD" || fail "CL pod not found"
VC_POD="$(get_pod "$VC_LABEL")"; [[ -n "$VC_POD" ]] && pass "Found VC pod: $VC_POD" || warn "VC pod not found"

cache_names
