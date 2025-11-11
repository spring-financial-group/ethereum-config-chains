#!/usr/bin/env bash
# Editable environment defaults for the devnet health checks

# Namespace
export NS="${NS:-devnet}"

# ===== PRYSM SETUP =====
# Label selectors
export EL_LABEL="${EL_LABEL:-app.kubernetes.io/instance=geth-devnet}"
export CL_LABEL="${CL_LABEL:-app.kubernetes.io/instance=beacon-devnet}"
export VC_LABEL="${VC_LABEL:-app.kubernetes.io/instance=validator-devnet}"

# Service names
export EL_SVC="${EL_SVC:-geth-devnet}"
export CL_SVC="${CL_SVC:-beacon-devnet-prysm}"

# Ports (Prysm)
export AUTHRPC_PORT="${AUTHRPC_PORT:-8551}"
export EL_HTTP_PORT="${EL_HTTP_PORT:-8545}"
export CL_REST_PORT="${CL_REST_PORT:-3500}"
export CL_GRPC_PORT="${CL_GRPC_PORT:-4000}"

# ===== LIGHTHOUSE SETUP =====
# Label selectors
export EL_LABEL_LIGHTHOUSE="${EL_LABEL_LIGHTHOUSE:-app.kubernetes.io/instance=geth-devnet-lighthouse}"
export CL_LABEL_LIGHTHOUSE="${CL_LABEL_LIGHTHOUSE:-app.kubernetes.io/instance=beacon-devnet-lighthouse}"
export VC_LABEL_LIGHTHOUSE="${VC_LABEL_LIGHTHOUSE:-app.kubernetes.io/instance=validator-devnet-lighthouse}"

# Service names
export EL_SVC_LIGHTHOUSE="${EL_SVC_LIGHTHOUSE:-geth-devnet-lighthouse}"
export CL_SVC_LIGHTHOUSE="${CL_SVC_LIGHTHOUSE:-beacon-devnet-lighthouse}"

# Ports (Lighthouse)
export CL_REST_PORT_LIGHTHOUSE="${CL_REST_PORT_LIGHTHOUSE:-5052}"
export CL_GRPC_PORT_LIGHTHOUSE="${CL_GRPC_PORT_LIGHTHOUSE:-5052}"

# ===== SHARED SETTINGS =====
# JWT paths inside containers
export EL_JWT_PATH="${EL_JWT_PATH:-/data/jwt.hex}"
export CL_JWT_PATH="${CL_JWT_PATH:-/data/jwt.hex}"

# Auto-fix controls for merge check
export AUTOFIX="${AUTOFIX:-false}"

# Log tail sizes
export EL_LOG_TAIL="${EL_LOG_TAIL:-120}"
export CL_LOG_TAIL="${CL_LOG_TAIL:-120}"