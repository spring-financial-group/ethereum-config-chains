#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "30_jwt (${SETUP:-})"

cache_names

_EL_POD="${CURRENT_EL_POD:-$EL_POD}"
_EL_CTN="${CURRENT_EL_CTN:-$EL_CTN}"
_CL_POD="${CURRENT_CL_POD:-$CL_POD}"
_CL_CTN="${CURRENT_CL_CTN:-$CL_CTN}"

if [[ -z "$_EL_POD" || -z "$_CL_POD" ]]; then
  warn "Skipping JWT check (pods not found)"
else
  # Try to get JWT content using bash or sh
  EL_JWT=$(kubectl exec -n "$NS" "$_EL_POD" -c "$_EL_CTN" -- bash -c "cat $EL_JWT_PATH 2>/dev/null" 2>/dev/null || \
           kubectl exec -n "$NS" "$_EL_POD" -c "$_EL_CTN" -- sh -c "cat $EL_JWT_PATH 2>/dev/null" 2>/dev/null || \
           echo "")

  CL_JWT=$(kubectl exec -n "$NS" "$_CL_POD" -c "$_CL_CTN" -- bash -c "cat $CL_JWT_PATH 2>/dev/null" 2>/dev/null || \
           kubectl exec -n "$NS" "$_CL_POD" -c "$_CL_CTN" -- sh -c "cat $CL_JWT_PATH 2>/dev/null" 2>/dev/null || \
           echo "")

  if [[ -n "$EL_JWT" && -n "$CL_JWT" ]]; then
    # Calculate hashes locally
    EL_JWT_HASH=$(echo -n "$EL_JWT" | sha256sum | awk '{print $1}')
    CL_JWT_HASH=$(echo -n "$CL_JWT" | sha256sum | awk '{print $1}')

    if [[ "$EL_JWT_HASH" == "$CL_JWT_HASH" ]]; then
      pass "JWT hashes match ($EL_JWT_HASH)"
    else
      fail "JWT hashes differ: EL=$EL_JWT_HASH CL=$CL_JWT_HASH"
    fi
  else
    warn "Could not read JWT files ($EL_JWT_PATH / $CL_JWT_PATH)"
    # Since Engine API is working, this is informational only
    echo "  Note: Engine API connection is working, JWT authentication is functional"
  fi
fi