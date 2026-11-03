#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check the MobileAnchor header fields of a gated devnet against the validators' logs.

    devnet-header-roots.py --rpc http://127.0.0.1:18545 --genesis <genesis.json> \
        --logs <fleet dir> --tag <tag> [--from 0] [--to <height>]

Every header is read raw (`debug_getRawHeader`) and RLP-decoded. Under the gate
(`glamsterdamTime` and `mobileAnchorTime`) a header carries 24 elements: element 22
is the slot and element 23 the `mobileRegistryRoot`. A Rust leader stamps the root
its own registry had committed when it built the block (zero before its first epoch
commit), which the validators log as `registry epoch committed ... root=0x..`.

The check: for every block, find its leader from the coinbase (the genesis's
hotstuff validator addresses) and the time it built the block (the first log line
of the leader's log that names the block hash), and compare the header's root with
the last root that leader committed before then. Blocks led by a member without a
Rust log (the gov5 member) are reported, not judged: the class of their root
(absent / zero / a root some Rust node committed / other).

Prints one `root change` line per block whose root differs from its parent's, a
`blocks` line with the counts per class and a `leader-root check` line.
"""
import argparse
import glob
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone

ZERO = "0x" + "00" * 32
ANSI = re.compile(r"\x1b\[[0-9;]*m")
TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?)Z")
ROOT = re.compile(r"registry epoch committed.*root=(0x[0-9a-fA-F]{64})")


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, body, {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        out = json.load(r)
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def rlp_list(b):
    """Decode one RLP list into its elements (bytes, or nested lists as raw bytes)."""

    def item(i):
        p = b[i]
        if p < 0x80:
            return b[i:i + 1], i + 1
        if p < 0xB8:
            n = p - 0x80
            return b[i + 1:i + 1 + n], i + 1 + n
        if p < 0xC0:
            ll = p - 0xB7
            n = int.from_bytes(b[i + 1:i + 1 + ll], "big")
            return b[i + 1 + ll:i + 1 + ll + n], i + 1 + ll + n
        if p < 0xF8:
            n = p - 0xC0
            return b[i:i + 1 + n], i + 1 + n
        ll = p - 0xF7
        n = int.from_bytes(b[i + 1:i + 1 + ll], "big")
        return b[i:i + 1 + ll + n], i + 1 + ll + n

    p = b[0]
    if p < 0xC0:
        raise ValueError("not a list")
    if p < 0xF8:
        start, end = 1, 1 + p - 0xC0
    else:
        ll = p - 0xF7
        start = 1 + ll
        end = start + int.from_bytes(b[1:1 + ll], "big")
    out, i = [], start
    while i < end:
        v, i = item(i)
        out.append(v)
    return out


def parse_time(line):
    m = TS.match(line)
    if not m:
        return None
    s = m.group(1)
    if "." in s:
        head, frac = s.split(".")
        s = head + "." + frac[:6]
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def read_log(path):
    """(commits [(time, root)], first time each 0x<64> hash appears)"""
    commits, first_seen = [], {}
    with open(path, "rb") as f:
        for raw in f:
            line = ANSI.sub("", raw.decode("utf-8", "replace"))
            t = parse_time(line)
            m = ROOT.search(line)
            if m and t:
                commits.append((t, m.group(1).lower()))
            if t:
                for h in re.findall(r"0x[0-9a-f]{64}", line):
                    first_seen.setdefault(h, t)
    return commits, first_seen


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rpc", default="http://127.0.0.1:18545")
    ap.add_argument("--genesis", required=True)
    ap.add_argument("--logs", required=True, help="fleet dir holding v<i>-<tag>.log")
    ap.add_argument("--tag", required=True)
    ap.add_argument("--from", dest="start", type=int, default=0)
    ap.add_argument("--to", type=int, default=None)
    a = ap.parse_args()

    g = json.load(open(a.genesis))
    vals = g["config"]["hotstuff"]["validators"]
    addr2idx = {v["address"].lower(): i for i, v in enumerate(vals)}
    # The root is stamped only where both gates are open; elsewhere a header carries none.
    cfg = g["config"]
    gate = max(int(cfg.get("glamsterdamTime", 2**63)), int(cfg.get("mobileAnchorTime", 2**63)))
    logs = {}
    for i in range(len(vals)):
        p = os.path.join(a.logs, f"v{i}-{a.tag}.log")
        if os.path.exists(p):
            logs[i] = read_log(p)
    rust_roots = set()
    for i, (commits, _) in sorted(logs.items()):
        rust_roots.update(r for _, r in commits)
        print(f"v{i}: {len(commits)} epoch commits, roots {[r[:10] for _, r in commits]}")

    to = a.to if a.to is not None else int(rpc(a.rpc, "eth_blockNumber", []), 16)
    stats = {"none": 0, "zero": 0, "committed": 0, "other": 0}
    ok = mismatch = foreign = 0
    foreign_classes = {}
    items_seen = set()
    prev = object()
    for n in range(a.start, to + 1):
        try:
            raw = bytes.fromhex(rpc(a.rpc, "debug_getRawHeader", [hex(n)])[2:])
            h = rlp_list(raw)
            items_seen.add(len(h))
            coinbase = "0x" + h[2].hex()
            ts = int.from_bytes(h[11], "big")
            slot = int.from_bytes(h[22], "big") if len(h) > 22 else None
            root = ("0x" + h[23].hex()) if len(h) > 23 else None
        except RuntimeError:
            # gov5 serves no debug_getRawHeader: read its JSON header fields instead.
            b = rpc(a.rpc, "eth_getBlockByNumber", [hex(n), False])
            items_seen.add("json")
            coinbase = b["miner"].lower()
            ts = int(b["timestamp"], 16)
            slot = int(b["slotNumber"], 16) if b.get("slotNumber") else None
            root = b.get("mobileRegistryRoot")
            root = root.lower() if root else None
        cls = "none" if root is None else "zero" if root == ZERO else "committed" if root in rust_roots else "other"
        stats[cls] += 1
        if root != prev:
            print(f"root change at block {n} miner {coinbase} ts {ts} root {root} ({cls}) slot {slot} items {len(h)}")
            prev = root
        if n == 0:
            continue
        leader = addr2idx.get(coinbase)
        if leader is None or leader not in logs:
            foreign += 1
            key = f"v{leader}:{cls}"
            foreign_classes[key] = foreign_classes.get(key, 0) + 1
            continue
        bhash = rpc(a.rpc, "eth_getBlockByNumber", [hex(n), False])["hash"].lower()
        commits, seen = logs[leader]
        built = seen.get(bhash)
        if ts < gate:
            expect = None
        elif built is None:
            expect = "unknown"
        else:
            expect = ZERO
            for t, r in commits:
                if t <= built:
                    expect = r
        if root == expect:
            ok += 1
        else:
            mismatch += 1
            print(f"MISMATCH block {n} leader v{leader} root {root} expected {expect}")
    print(f"blocks {a.start}..{to}: items={sorted(items_seen, key=str)} stats={stats}")
    print(f"leader-root check: ok={ok} mismatch={mismatch} not-a-rust-leader={foreign} {foreign_classes}")
    return 1 if mismatch else 0


if __name__ == "__main__":
    sys.exit(main())
