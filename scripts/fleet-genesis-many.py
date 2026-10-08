#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derive an N-validator bench genesis (N > 7) from the seven-validator one.

    scripts/fleet-genesis-many.py --nodes 21 99          # writes n42_fleet7_bench_v21.json, _v99.json
    scripts/fleet-genesis-many.py --nodes 21 99 --check  # compare with the checked-in files

The seven-validator bench genesis (n42_fleet7_bench.json) names its validators from

    h2_keygen --count 7 --seed n42-fleet7-validator

and h2_keygen derives validator `i` from keccak256("<seed>-<i>") -- the index
alone, never the count -- so the first 7 keys of a 21- or 99-key set generated
from the same seed ARE the seven in that file. `scripts/fleet7-env.sh`
(`f7_place_keys`) regenerates the keys with `--count $F7_VALIDATORS` and the
same seed, so a launch of N validators holds exactly the keys this file lists.

What is kept from the source, byte for byte: every chain parameter (forks,
gasLimit, period, timeouts, epochLength, committeePool, deferredExecutionTime,
altSigTx, frameBlocks), the alloc (so the QMDB genesis root is the same), and
validators 0-6 (address and BLS key). What changes:

  * hotstuff.validators grows to N. Validators 7.. get a derived address,
    sha256("n42-fleet7-validator-addr-<i>")[12:], and the BLS key from h2_keygen.
    The addresses are not hardhat accounts and are not in the alloc; they receive
    the block reward as withdrawals like any proposer.
  * extraData: the 32-byte vanity names the file ("n42-fleet7-bench-v<N>"), so
    the genesis hash differs from the seven-validator chain's (and from every
    other N's); the clique-layout address (validator 0) and the 65-byte seal
    slot are kept. The HotStuff header profile does not read extraData.

f = (n - 1) // 3 and the quorum n - f are not written in the file; the node
computes them from the length of the list (HotStuffGenesisConfig::fault_tolerance,
ValidatorSet::quorum_size): 21 -> f 6, quorum 15; 99 -> f 32, quorum 67.
"""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
GENESIS_DIR = REPO / "crates" / "chainspec" / "res" / "genesis"
SOURCE = GENESIS_DIR / "n42_fleet7_bench.json"
SEED = "n42-fleet7-validator"
KEYGEN_DEFAULTS = [
    "/data/n42-build/wt338/target/native/release/examples/h2_keygen",
    str(REPO / "target" / "release" / "examples" / "h2_keygen"),
]


def keygen_path(arg):
    for cand in ([arg] if arg else []) + KEYGEN_DEFAULTS:
        if cand and pathlib.Path(cand).exists():
            return cand
    raise SystemExit("no h2_keygen binary (pass --keygen; cargo build --release -p n42-h2-node --example h2_keygen)")


def derived_keys(keygen, count):
    """The BLS public keys h2_keygen derives from the fleet seed, in index order."""
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([keygen, "--count", str(count), "--seed", SEED, "--out-dir", tmp],
                       check=True, stdout=subprocess.DEVNULL)
        listed = json.loads((pathlib.Path(tmp) / "validators.json").read_text())
    return [v["bls_public_key"] for v in listed]


def derived_address(i):
    return "0x" + hashlib.sha256(f"n42-fleet7-validator-addr-{i}".encode()).digest()[12:].hex()


def derive(source, nodes, keys):
    out = json.loads(json.dumps(source))  # deep copy keeping key order
    have = source["config"]["hotstuff"]["validators"]
    if len(keys) != nodes:
        raise SystemExit(f"keygen produced {len(keys)} keys for --nodes {nodes}")
    for i, v in enumerate(have):
        if v["blsKey"] != keys[i]:
            raise SystemExit(f"validator {i} of the source is not the seed's key {i}: the seed or the source changed")
    vals = [dict(v) for v in have]
    taken = {v["address"].lower() for v in vals} | {a.lower() for a in source["alloc"]}
    for i in range(len(vals), nodes):
        addr = derived_address(i)
        if addr.lower() in taken:
            raise SystemExit(f"derived address {addr} collides")
        taken.add(addr.lower())
        vals.append({"address": addr, "blsKey": keys[i]})
    out["config"]["hotstuff"]["validators"] = vals[:nodes]
    vanity = f"n42-fleet7-bench-v{nodes}".encode()
    assert len(vanity) <= 32
    extra = source["extraData"]
    out["extraData"] = "0x" + vanity.ljust(32, b"\0").hex() + extra[2 + 64:]
    return out


def render(genesis):
    return json.dumps(genesis, indent=2) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nodes", type=int, nargs="+", required=True, help="validator counts to write (each > 7)")
    ap.add_argument("--keygen", help="path to the h2_keygen binary")
    ap.add_argument("--check", action="store_true", help="compare with what is checked in; write nothing")
    args = ap.parse_args()

    source = json.loads(SOURCE.read_text())
    keygen = keygen_path(args.keygen)
    failed = False
    for n in args.nodes:
        if n <= len(source["config"]["hotstuff"]["validators"]):
            raise SystemExit(f"--nodes {n} must exceed the source's {len(source['config']['hotstuff']['validators'])}")
        text = render(derive(source, n, derived_keys(keygen, n)))
        out = GENESIS_DIR / f"n42_fleet7_bench_v{n}.json"
        f = (n - 1) // 3
        if args.check:
            if not out.exists() or out.read_text() != text:
                print(f"{'MISSING' if not out.exists() else 'STALE  '} {out}")
                failed = True
            else:
                print(f"ok      {out} ({n} validators, f={f}, quorum {n - f})")
            continue
        out.write_text(text)
        print(f"{out}: {n} validators, f={f}, quorum {n - f}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
