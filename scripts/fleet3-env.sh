#!/usr/bin/env bash
# The three-node fleet: the whole of the switch.
#
#   source scripts/fleet3-env.sh          # bench tier (the default)
#   source scripts/fleet3-env.sh lean     # the production-shaped chain
#
# then `scripts/fleet7-bench.sh --tag …`, `scripts/fleet7.sh up --fresh`,
# `scripts/fleet7.sh print` -- unchanged, every one of them.
#
# WHY three. Seven nodes at 16 physical cores each read 429-443k TPS and the
# limit is a node's own CPU budget: every node verifies every transaction
# (`F7_INGEST_ALL`) on the cores its import and its build run on, so at ~11 us
# of ingest per transaction 435k/s is about five of a node's sixteen cores
# before a block is touched, and what is left of the vote road and of the build
# are slices of one budget -- cutting one hands its time to another
# (`docs/FLEET7_PLAN_V4.md` sections 2o, 2p). Three nodes at 28 physical cores
# each change that budget without changing a line of the node: the same
# binaries, a three-validator genesis, quorum 3 of 4.
#
# This file sets six variables and sources fleet7-env.sh. It deliberately
# contains no launch argument of its own -- that is the rule at the top of
# fleet7-env.sh, and a second file that built its own arguments would be the
# next lever to get dropped.

# Sourced, not executed: `set -euo pipefail` here would apply to the caller's
# shell. fleet7-env.sh sets it for the scripts that source it in turn.

# The tier decides the genesis and the root, the way `F7_CORES_PER_NODE` is
# already chosen by profile in fleet7-env.sh. `fleet7-bench.sh` exports
# `F7_PROFILE=bench` itself, but it does so after this file has run, so the
# tier is named here instead: as the first argument, or by a `F7_PROFILE` the
# caller set before sourcing.
_f3_tier=${1:-${F7_PROFILE:-bench}}

# A root of its own, never a fleet7 datadir. The two chains share a genesis
# hash -- the `hotstuff` block lives in `config`, which the header does not
# cover -- so a fleet7 datadir would be accepted by a fleet3 node and diverge
# only at the committee-evidence link, which presents as
# `parent beacon root ... is not the parent's committee evidence` and names
# nothing. Separate roots make that impossible rather than merely unlikely.
if [[ $_f3_tier == bench ]]; then
  : "${F7_ROOT:=/data/blockchain/rust-fleet3-bench}"
  : "${F7_GENESIS:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/crates/chainspec/res/genesis/n42_fleet3_bench.json}"
else
  : "${F7_ROOT:=/data/blockchain/rust-fleet3}"
  : "${F7_GENESIS:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/crates/chainspec/res/genesis/n42_fleet3.json}"
fi

# Three members, quorum 3 (f = 1). `fleet7-env.sh`'s `f7_quorum` computes it;
# nothing needs it written down.
: "${F7_NODES:=3}"

# 28 physical cores a node, 56 CPUs with their SMT siblings.
#
# 4 x 56 = 224 of the box's 256 CPUs, and the 32 left are exactly the 32 the
# seven-node layout leaves the flood: nodes take physical cores 0-111 (with
# siblings 128-239) and the generator 112-127 with 240-255. So the flood's
# share does not change between the fleets and the two layouts are comparable
# in the only way that matters -- neither has a node sharing a physical core
# with anything. `scripts/fleet7.sh print` prints both ranges; check them.
: "${F7_CORES_PER_NODE:=74}"

# The ports are NOT changed, on purpose. The two fleets never run at once (one
# box, one claim), and sharing the ports is what makes that enforceable:
# `fleet7.sh down` refuses while anything still listens on them, so a fleet7
# node that outlived its round stops a fleet3 round instead of quietly running
# beside it on a chain with the same fork digest. Different ports would hide
# exactly the case worth catching.

# The seed is NOT changed either: `h2_keygen` derives validator `i` from
# `keccak256("<seed>-<i>")`, the index alone, so node `i` holds the same BLS
# key in both fleets and `crates/chainspec/res/genesis/n42_fleet3*.json` is the
# seven-node file's validator list truncated to three
# (`scripts/fleet-genesis.py`). A node's identity therefore does not depend on
# which fleet it is in.

# The tier is named BEFORE fleet7-env.sh is sourced, and this is not cosmetic.
# That file does `[[ $F7_PROFILE == lean ]] && export MALLOC_CONF="$F7_JEMALLOC"`,
# and `F7_PROFILE` defaults to `lean`. Sourced into the caller's shell with the
# profile unset, it would therefore export the LEAN allocator string
# (`thp:never,narenas:2`) into the environment, `fleet7-bench.sh` would find
# `MALLOC_CONF` already set and keep it, and every leg would run the lean
# allocator while reporting itself as the bench tier. Naming the tier here
# makes the string the one the tier wants.
: "${F7_PROFILE:=$_f3_tier}"
export F7_ROOT F7_GENESIS F7_NODES F7_CORES_PER_NODE F7_PROFILE
unset _f3_tier

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fleet7-env.sh"
