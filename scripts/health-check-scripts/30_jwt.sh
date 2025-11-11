#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "30_jwt (${SETUP:-})"

cache_names

# Use CURRENT_* variables if set, otherwise fall back to defaults
_EL_POD="${CURRENT_EL_POD:-$EL_POD}"
_EL_CTN="${CURRENT_EL_CTN:-$EL_CTN}"
_CL_POD="${CURRENT_CL_POD:-$CL_POD}"
_CL_CTN="${CURRENT_CL_CTN:-$CL_CTN}"

if [[ -z "$_EL_POD" || -z "$_CL_POD" ]]; then
  warn "Skipping JWT check (pods not found)"
  return 0
fi

if kubectl exec -n "$NS" "$_EL_POD" -c "$_EL_CTN" -- sh -c "sha256sum $EL_JWT_PATH" >/dev/null 2>&1 && \
   kubectl exec -n "$NS" "$_CL_POD" -c "$_CL_CTN" -- sh -c "sha256sum $CL_JWT_PATH" >/dev/null 2>&1; then
  EL_JWT_HASH="$(kubectl exec -n "$NS" "$_EL_POD" -c "$_EL_CTN" -- sh -c "sha256sum $EL_JWT_PATH" | awk '{print $1}')"
  CL_JWT_HASH="$(kubectl exec -n "$NS" "$_CL_POD" -c "$_CL_CTN" -- sh -c "sha256sum $CL_JWT_PATH" | awk '{print $1}')"
  if [[ "$EL_JWT_HASH" == "$CL_JWT_HASH" ]]; then
    pass "JWT hashes match ($EL_JWT_HASH)"
  else
    fail "JWT hashes differ: EL=$EL_JWT_HASH CL=$CL_JWT_HASH"
  fi
else
  warn "Could not read JWT files ($EL_JWT_PATH / $CL_JWT_PATH)"
fi
