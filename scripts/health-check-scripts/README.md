# Devnet Health Check - Dual Setup (Prysm + Lighthouse)

This health check script now validates **both** your Prysm and Lighthouse setups simultaneously.

## What's Changed

### New Structure
- **Discovers both setups** in `10_discovery.sh`
- **Runs all checks twice** - once for Prysm, once for Lighthouse
- **Color-coded sections** to distinguish between setups
- **Block proposal tracking** for both validators

### Key Files

1. **`check-devnet.sh`** - Main orchestrator
   - Discovers all pods
   - Runs Prysm checks
   - Runs Lighthouse checks
   - Shows block proposal summary

2. **`00_lib.sh`** - Updated library
   - Supports both `*_POD` and `*_POD_LH` variables
   - Caches all pod/container names at once

3. **`env.sh`** - Configuration
   - Prysm labels and services
   - Lighthouse labels and services
   - Port configurations for both

4. **Individual check scripts** - Modified to accept both setups
   - Use `CURRENT_*` variables to check either setup
   - Support `SETUP` variable for logging

## Usage

```bash
# Run full health check (both setups)
./check-devnet.sh

# Check just Prysm (if you want)
export SETUP=PRYSM
./30_jwt.sh
./40_genesis_and_head.sh

# Check just Lighthouse
export SETUP=LIGHTHOUSE  
./30_jwt.sh
./40_genesis_and_head.sh
```

## Expected Output

```
================================
  DEVNET HEALTH CHECK
================================

>>> 10 discovery

=== Prysm Setup ===
PASS Found EL pod: geth-devnet-0
PASS Found CL pod: beacon-devnet-prysm-0
PASS Found VC pod: validator-devnet-prysm-0

=== Lighthouse Setup ===
PASS Found EL pod: geth-lighthouse-0
PASS Found CL pod: beacon-devnet-lighthouse-0
PASS Found VC pod: validator-devnet-lighthouse-0

╔═══════════════════════════════╗
║   PRYSM SETUP CHECKS          ║
╚═══════════════════════════════╝

>>> 20_network (PRYSM)
PASS Service geth-devnet present
...

╔═══════════════════════════════╗
║   LIGHTHOUSE SETUP CHECKS     ║
╚═══════════════════════════════╝

>>> 20_network (LIGHTHOUSE)
PASS Service geth-lighthouse present
...

╔═══════════════════════════════╗
║   VALIDATOR BLOCK PROPOSALS   ║
╚═══════════════════════════════╝

>>> Block Proposals
Prysm Validator: 145 blocks proposed
PASS Prysm validator is proposing blocks
Lighthouse Validator: 132 blocks proposed
PASS Lighthouse validator is proposing blocks

================================
✓ All checks passed!
================================
```

## Configuration

### Default Labels (in `env.sh`)

**Prysm:**
- EL: `app.kubernetes.io/instance=geth-devnet`
- CL: `app.kubernetes.io/instance=beacon-devnet-prysm`
- VC: `app.kubernetes.io/instance=validator-devnet-prysm`

**Lighthouse:**
- EL: `app.kubernetes.io/instance=geth-lighthouse`
- CL: `app.kubernetes.io/instance=beacon-devnet-lighthouse`
- VC: `app.kubernetes.io/instance=validator-devnet-lighthouse`

### Override Labels

```bash
# If your labels differ
export EL_LABEL="app=my-geth"
export CL_LABEL_LIGHTHOUSE="app=my-lighthouse-beacon"
./check-devnet.sh
```

### Override Services

```bash
# If your service names differ
export EL_SVC="my-geth-service"
export CL_SVC_LIGHTHOUSE="my-lighthouse-beacon-service"
./check-devnet.sh
```

## Troubleshooting

### Lighthouse checks fail but Prysm works
- Check that `geth-lighthouse` service exists
- Verify Lighthouse beacon has `--execution-endpoint=http://geth-lighthouse:8551`
- Check JWT tokens match between geth-lighthouse and lighthouse beacon

### Block proposals showing 0 for one validator
- Check validator logs: `kubectl logs validator-devnet-lighthouse-0 -n devnet`
- Look for "Successfully published block" (Lighthouse) or "Submitted new block" (Prysm)
- Verify beacon is connected to execution engine

### Can't find pods
- Check namespace: `export NS=your-namespace`
- List pods: `kubectl get pods -n devnet`
- Verify labels match your helm releases

## What Each Check Does

1. **10_discovery** - Finds all pods by label
2. **20_network** - Validates services, endpoints, TCP connectivity
3. **30_jwt** - Confirms JWT tokens match between EL and CL
4. **40_genesis_and_head** - Checks genesis alignment, head progression
5. **50_merge_check** - Validates merge configuration (TTD, TBH)
6. **60_engine_traffic** - Confirms engine API calls happening

## Files Included

- `check-devnet.sh` - Main script
- `00_lib.sh` - Helper functions  
- `env.sh` - Configuration
- `10_discovery.sh` - Pod discovery
- `20_network.sh` - Network checks
- `30_jwt.sh` - JWT validation
- `40_genesis_and_head.sh` - Genesis/head checks
- `50_merge_check.sh` - Merge validation
- `60_engine_traffic.sh` - Engine API validation
- `90_logs.sh` - Log inspection (optional)

## Quick Checks

```bash
# Just check if both validators are proposing
kubectl logs validator-devnet-prysm-0 -n devnet | grep -c '"Submitted new block"'
kubectl logs validator-devnet-lighthouse-0 -n devnet | grep -c "Successfully published block"

# Check JWT hashes
kubectl exec geth-devnet-0 -n devnet -- cat /data/jwt.hex | sha256sum
kubectl exec geth-lighthouse-0 -n devnet -- cat /data/jwt.hex | sha256sum
kubectl exec beacon-devnet-lighthouse-0 -n devnet -- cat /data/jwt.hex | sha256sum
```
