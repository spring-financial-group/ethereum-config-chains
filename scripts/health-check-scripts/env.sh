#!/usr/bin/env bash
# Editable environment defaults for the devnet health checks

# Namespace
export NS="${NS:-default}"

# Label selectors (tweak if your Helm release names differ)
export EL_LABEL="${EL_LABEL:-app.kubernetes.io/instance=geth-devnet}"
export CL_LABEL="${CL_LABEL:-app.kubernetes.io/instance=beacon-devnet}"
export VC_LABEL="${VC_LABEL:-app.kubernetes.io/instance=validator-devnet}"

# Service names
export EL_SVC="${EL_SVC:-geth-devnet}"
export CL_SVC="${CL_SVC:-beacon-devnet-prysm}"

# Default container names (auto-detected if empty)
export EL_CONT="${EL_CONT:-}"
export CL_CONT="${CL_CONT:-}"
export VC_CONT="${VC_CONT:-}"

# Ports
export AUTHRPC_PORT="${AUTHRPC_PORT:-8551}"
export EL_HTTP_PORT="${EL_HTTP_PORT:-8545}"
export CL_REST_PORT="${CL_REST_PORT:-3500}"
export CL_GRPC_PORT="${CL_GRPC_PORT:-4000}"

# JWT paths inside containers
export EL_JWT_PATH="${EL_JWT_PATH:-/data/jwt.hex}"
export CL_JWT_PATH="${CL_JWT_PATH:-/data/jwt.hex}"

# Auto-fix controls for merge check (50_merge_check.sh)
# If true, script will patch TBH/EPOCH in the beacon data dir and restart the pod.
export AUTOFIX="${AUTOFIX:-false}"

# Log tail sizes
export EL_LOG_TAIL="${EL_LOG_TAIL:-120}"
export CL_LOG_TAIL="${CL_LOG_TAIL:-120}"
