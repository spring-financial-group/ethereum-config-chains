#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "10 discovery"

need kubectl
need jq

section "Prysm Setup"
EL_POD="$(get_pod "$EL_LABEL")"; [[ -n "$EL_POD" ]] && pass "Found EL pod: $EL_POD" || fail "EL pod not found"
CL_POD="$(get_pod "$CL_LABEL")"; [[ -n "$CL_POD" ]] && pass "Found CL pod: $CL_POD" || fail "CL pod not found"
VC_POD="$(get_pod "$VC_LABEL")"; [[ -n "$VC_POD" ]] && pass "Found VC pod: $VC_POD" || warn "VC pod not found"

section "Lighthouse Setup"
EL_POD_LH="$(get_pod "$EL_LABEL_LIGHTHOUSE")"; [[ -n "$EL_POD_LH" ]] && pass "Found EL pod: $EL_POD_LH" || fail "EL pod not found"
CL_POD_LH="$(get_pod "$CL_LABEL_LIGHTHOUSE")"; [[ -n "$CL_POD_LH" ]] && pass "Found CL pod: $CL_POD_LH" || fail "CL pod not found"
VC_POD_LH="$(get_pod "$VC_LABEL_LIGHTHOUSE")"; [[ -n "$VC_POD_LH" ]] && pass "Found VC pod: $VC_POD_LH" || warn "VC pod not found"

cache_names

# Export for use by other scripts
export EL_POD CL_POD VC_POD EL_CTN CL_CTN VC_CTN
export EL_POD_LH CL_POD_LH VC_POD_LH EL_CTN_LH CL_CTN_LH VC_CTN_LH
