#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/env.sh"
source "$(dirname "$0")/00_lib.sh"

banner "30_jwt"

cache_names

if kubectl exec -n "$NS" "$EL_POD" -c "$EL_CONT" -- sh -c "sha256sum $EL_JWT_PATH" >/dev/null 2>&1 && \
   kubectl exec -n "$NS" "$CL_POD" -c "$CL_CONT" -- sh -c "sha256sum $CL_JWT_PATH" >/dev/null 2>&1; then
  EL_JWT_HASH="$(kubectl exec -n "$NS" "$EL_POD" -c "$EL_CONT" -- sh -c "sha256sum $EL_JWT_PATH" | awk '{print $1}')"
  CL_JWT_HASH="$(kubectl exec -n "$NS" "$CL_POD" -c "$CL_CONT" -- sh -c "sha256sum $CL_JWT_PATH" | awk '{print $1}')"
  if [[ "$EL_JWT_HASH" == "$CL_JWT_HASH" ]]; then
    pass "JWT hashes match ($EL_JWT_HASH)"
  else
    fail "JWT hashes differ: EL=$EL_JWT_HASH CL=$CL_JWT_HASH"
  fi
else
  warn "Could not read JWT files ($EL_JWT_PATH / $CL_JWT_PATH)"
fi
