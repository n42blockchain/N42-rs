#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derive an N-validator fleet genesis from the seven-node one.

    scripts/fleet-genesis.py --nodes 4                  # writes n42_fleet4{,_bench}.json
    scripts/fleet-genesis.py --nodes 4 --check          # verify the checked-in files

The seven-node files were written once by hand from the devnet genesis, with
the validator list taken from

    cargo run -p n42-h2-node --example h2_keygen -- \
        --count 7 --seed n42-fleet7-validator --out-dir <dir>

and the addresses from hardhat's well-known development accounts, in the same
order the `alloc` funds them. `h2_keygen` derives validator `i` as
`BlsSecretKey::key_gen(keccak256("<seed>-<i>"))` -- the index alone, never the
count -- so the first four of a seven-key set ARE the whole of a four-key set
generated from the same seed. That is the property this script relies on and
the reason the fleets share `F7_SEED`: node `i` holds the same BLS key, and
`scripts/fleet7-env.sh`'s `f7_place_keys` reproduces it with `--count $F7_NODES`
whatever the fleet's size.

So a smaller fleet's genesis is the seven-node file with `hotstuff.validators`
truncated, and nothing else touched. Everything else in the file is either a
chain parameter that must stay comparable between the fleets (the forks, the
gas limit, the period, the committee pool, `chainId`) or is not keyed on the
validator set at all:

  * `alloc` funds hardhat accounts 0-7 -- the faucet and the flood's senders,
    not the validators -- and is left whole so both fleets have the same QMDB
    genesis root and the same genesis hash.
  * `extraData` carries one address (validator 0) in the clique layout; the
    HotStuff header profile does not read it.
  * `committeePool` is seeded independently of the validator set (a 200,000-key
    pool, 512 signers a block), so the committee evidence every header links to
    is the same function of the block on both fleets.

`f = (n - 1) / 3` and the quorum `n - f` are computed by the node from the
length of the list (`HotStuffGenesisConfig::fault_tolerance`), and the leader
of view `v` is `(v / leaderTenure) % n`. Neither is written in the file.
"""

import argparse
import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
GENESIS_DIR = REPO / "crates" / "chainspec" / "res" / "genesis"
# The two files a fleet is run from: the production-shaped chain and the
# throughput tier. Kept as a pair so they can never drift apart in anything but
# the three fields that separate them (period, gasLimit, deferredExecutionTime).
VARIANTS = ("", "_bench")


def derive(source: dict, nodes: int) -> dict:
    """The same genesis with the first `nodes` validators, and nothing else changed."""
    validators = source["config"]["hotstuff"]["validators"]
    if len(validators) < nodes:
        raise SystemExit(
            f"the source genesis names {len(validators)} validators; --nodes {nodes} "
            "would need keys that are not in it (generate them with h2_keygen first)"
        )
    out = json.loads(json.dumps(source))  # a deep copy that keeps key order
    out["config"]["hotstuff"]["validators"] = validators[:nodes]
    return out


def render(genesis: dict) -> str:
    """Exactly the formatting the checked-in files use, so a diff is the change."""
    return json.dumps(genesis, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--nodes", type=int, default=4, help="validators in the derived fleet (default 4)")
    parser.add_argument("--from-nodes", type=int, default=7, help="the fleet to derive from (default 7)")
    parser.add_argument("--check", action="store_true", help="compare with what is checked in; write nothing")
    args = parser.parse_args()

    if args.nodes < 1:
        raise SystemExit("--nodes must be at least 1")
    if args.nodes >= args.from_nodes:
        raise SystemExit(f"--nodes {args.nodes} must be smaller than --from-nodes {args.from_nodes}")

    failed = False
    for variant in VARIANTS:
        src_path = GENESIS_DIR / f"n42_fleet{args.from_nodes}{variant}.json"
        out_path = GENESIS_DIR / f"n42_fleet{args.nodes}{variant}.json"
        source = json.loads(src_path.read_text())
        text = render(derive(source, args.nodes))
        if args.check:
            if not out_path.exists():
                print(f"MISSING {out_path}")
                failed = True
            elif out_path.read_text() != text:
                print(f"STALE   {out_path} (re-run without --check)")
                failed = True
            else:
                print(f"ok      {out_path}")
            continue
        out_path.write_text(text)
        f = (args.nodes - 1) // 3
        print(f"{out_path}: {args.nodes} validators, f={f}, quorum {args.nodes - f}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
