# Changes to Health Check Scripts

## Overview
Updated all health check scripts to support **dual validation** of both Prysm and Lighthouse setups simultaneously.

## Files Created/Updated

### Core Files
1. **`check-devnet.sh`** - NEW orchestrator
   - Runs discovery once
   - Checks Prysm setup (full suite)
   - Checks Lighthouse setup (full suite)
   - Shows block proposal summary for both validators
   - Pretty color-coded output

2. **`00_lib.sh`** - UPDATED
   - Added `*_LH` variables for Lighthouse pods/containers
   - Added `section()` helper for visual separation
   - Updated `cache_names()` to discover both setups
   - Now exports: `EL_POD_LH`, `CL_POD_LH`, `VC_POD_LH`, etc.

3. **`env.sh`** - UPDATED
   - Added Lighthouse labels: `EL_LABEL_LIGHTHOUSE`, `CL_LABEL_LIGHTHOUSE`, `VC_LABEL_LIGHTHOUSE`
   - Added Lighthouse services: `EL_SVC_LIGHTHOUSE`, `CL_SVC_LIGHTHOUSE`
   - Added Lighthouse ports: `CL_REST_PORT_LIGHTHOUSE`
   - Kept all Prysm config for backward compatibility

### Check Scripts (All UPDATED)
All check scripts now:
- Accept `SETUP` variable ("PRYSM" or "LIGHTHOUSE")
- Use `CURRENT_*` variables to work with either setup
- Show setup name in banner
- Skip gracefully if pods not found

4. **`10_discovery.sh`** - Discovers both Prysm and Lighthouse pods
5. **`20_network.sh`** - Validates services and TCP connectivity for current setup
6. **`30_jwt.sh`** - Checks JWT matches for current setup
7. **`40_genesis_and_head.sh`** - Validates genesis and head progression
8. **`50_merge_check.sh`** - Checks merge configuration
9. **`60_engine_traffic.sh`** - Verifies engine API traffic
10. **`90_logs.sh`** - Optional log inspection

### Documentation
11. **`README.md`** - Complete usage guide
12. **`CHANGES.md`** - This file
13. **`install.sh`** - Quick installation/test script

## Key Changes

### Before
```bash
# Old behavior
./check-devnet.sh  # Only checked Prysm

# To check Lighthouse, you had to manually edit env.sh
```

### After
```bash
# New behavior
./check-devnet.sh  # Checks BOTH Prysm AND Lighthouse automatically!

# Output shows clearly separated sections:
# ╔═══════════════╗
# ║ PRYSM CHECKS  ║
# ╚═══════════════╝
# ... all Prysm checks ...
#
# ╔═══════════════════╗
# ║ LIGHTHOUSE CHECKS ║
# ╚═══════════════════╝
# ... all Lighthouse checks ...
```

## New Features

1. **Automatic Discovery**
   - Finds both setups by label
   - Caches all pod/container names once
   - Exports for use by all sub-scripts

2. **Block Proposal Tracking**
   - Counts blocks from Prysm validator (`"Submitted new block"`)
   - Counts blocks from Lighthouse validator (`"Successfully published block"`)
   - Shows summary at end of check

3. **Graceful Fallbacks**
   - If Prysm setup missing → skips Prysm checks, warns
   - If Lighthouse setup missing → skips Lighthouse checks, warns
   - Continues checking what's available

4. **Color-Coded Output**
   - Blue boxes for setup sections
   - Green PASS, Red FAIL, Yellow WARN (as before)
   - Easy to scan visually

## Migration from Old Scripts

### If you have custom labels
```bash
# Old way
export EL_LABEL="my-custom-label"

# New way (same, but also set Lighthouse)
export EL_LABEL="my-custom-prysm-label"
export EL_LABEL_LIGHTHOUSE="my-custom-lighthouse-label"
```

### If you only want to check one setup
```bash
# Check only Prysm
export CL_LABEL_LIGHTHOUSE="nonexistent"  # Will skip Lighthouse
./check-devnet.sh

# Check only Lighthouse  
export CL_LABEL="nonexistent"  # Will skip Prysm
./check-devnet.sh
```

## Backward Compatibility

✅ All original variables still work
✅ Can still run individual check scripts
✅ Old `env.sh` variables unchanged
✅ Default namespace still `devnet`

## What Stays the Same

- All the actual checks (JWT, genesis, merge, etc.)
- Error detection logic
- Pass/fail criteria
- Tool requirements (kubectl, jq, curl)
- Port-forwarding behavior

## Installation

```bash
# Download all new files to your health check directory
cd /path/to/health-checks

# Copy new versions
cp /path/to/new/*.sh .

# Make executable
chmod +x *.sh

# Run!
./check-devnet.sh
```

## Example Output

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
PASS Service exposes Engine API port 8551
PASS Endpoints exist for geth-devnet
PASS Beacon → EL TCP geth-devnet:8551 OK
PASS Validator → Beacon TCP beacon-devnet-prysm:4000 OK

>>> 30_jwt (PRYSM)
PASS JWT hashes match (abc123...)

>>> 40_genesis_and_head (PRYSM)
PASS EL block0 timestamp: 1762433256
PASS CL genesis_time: 1762433256
PASS EL/CL genesis match
PASS EL blockNumber: 0x1a4f
PASS CL head advancing (6789 → 6790)

>>> 50_merge_check (PRYSM)
EL block0 hash: 0x51b4cd0...
PASS Merge trigger loaded correctly

>>> 60_engine_traffic (PRYSM)
PASS Geth engine is receiving payload/forkchoice calls

╔═══════════════════════════════╗
║   LIGHTHOUSE SETUP CHECKS     ║
╚═══════════════════════════════╝

>>> 20_network (LIGHTHOUSE)
PASS Service geth-lighthouse present
PASS Service exposes Engine API port 8551
[... similar checks for Lighthouse ...]

╔═══════════════════════════════╗
║   VALIDATOR BLOCK PROPOSALS   ║
╚═══════════════════════════════╝

Prysm Validator: 234 blocks proposed
PASS Prysm validator is proposing blocks

Lighthouse Validator: 198 blocks proposed
PASS Lighthouse validator is proposing blocks

================================
✓ All checks passed!
================================
```

## Troubleshooting

See README.md for full troubleshooting guide. Quick tips:

**Can't find Lighthouse pods?**
```bash
kubectl get pods -n devnet | grep lighthouse
# Adjust labels in env.sh if needed
```

**Only Prysm works?**
- Check geth-lighthouse service exists
- Verify Lighthouse beacon → geth-lighthouse connection
- Check JWT tokens match

**Want more details?**
```bash
# Run individual checks
export SETUP=LIGHTHOUSE
./40_genesis_and_head.sh
./90_logs.sh
```
