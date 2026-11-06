#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Turn one of gov5's chains into a genesis a local devnet can run.

    gov5-local-genesis.py --chain crates/chainspec/res/genesis/gov5/mainnet_qmdb_staggered.json \
        --validators-from crates/chainspec/res/genesis/n42_devnet.json \
        --fork-time shanghai=+1 --fork-time cancun=+1 --out <genesis.json>

Two changes, both in `config`, so the genesis block and its hash stay the chain's:

  * the hotstuff validator set is replaced by the devnet's four dev validators
    (their secrets derive from the devnet seed; the chain's own keys are not here);
  * `shanghaiTime` / `cancunTime` are added (the README's `--fork-time` step).
    `+N` means the genesis timestamp plus N.

Why the fork times are not the production ones on a local fleet: a fresh chain's
block timestamps are genesis + slot x period, so a local fleet from chain 94 runs at
2023 timestamps. With the production schedule (Shanghai at block 305,000) it would be
pre-Shanghai for its whole life, and gov5 pays the block reward that the Rust side
can only express as withdrawals. `+1` puts Shanghai and Cancun on block 1 for both
clients (gov5 reads `IsShanghaiAt(num, time)`, so the time alone is enough). Every
timestamp fork (Pectra 2025, mobileAnchor 2026-07; chain 94 schedules no Glamsterdam)
stays where the chain has it, i.e. beyond the local fleet's clock.
"""
import argparse
import json

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--chain", required=True)
ap.add_argument("--validators-from", required=True)
ap.add_argument("--fork-time", action="append", default=[], help="shanghai=<ts|+N> or cancun=<ts|+N>")
ap.add_argument("--out", required=True)
a = ap.parse_args()

g = json.load(open(a.chain))
dev = json.load(open(a.validators_from))
g["config"]["hotstuff"]["validators"] = dev["config"]["hotstuff"]["validators"]
genesis_ts = int(g["timestamp"], 0)
for spec in a.fork_time:
    fork, ts = spec.split("=")
    if fork not in ("shanghai", "cancun"):
        raise SystemExit(f"unknown fork {fork}")
    g["config"][f"{fork}Time"] = genesis_ts + int(ts[1:]) if ts.startswith("+") else int(ts)
json.dump(g, open(a.out, "w"), indent=2)
c = g["config"]
print(f"chain {c['chainId']}: {len(c['hotstuff']['validators'])} validators, "
      f"shanghaiTime {c.get('shanghaiTime')} cancunTime {c.get('cancunTime')}, genesis timestamp {genesis_ts}")
