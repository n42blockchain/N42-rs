#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""One measurement window: TPS, and the occupancy that says what the TPS means.

    fleet7-measure.py <http_port> <seconds> <label>

TPS on its own is ambiguous in a way that has cost gov5 whole rounds: fast empty
blocks and slow full blocks produce the same mid-range number for opposite
reasons. So this reports, per window:

  * tps          — transactions sealed divided by the window
  * occupancy    — mean gas used over gas limit
  * full(>=95%)  — how many blocks actually filled

The last one separates the two things occupancy cannot. A spread of partial
blocks is a supply shortfall; blocks alternating full and empty at ~53%
occupancy is the fee market oscillating across the flood's price cap, which is
chain state and not a chain limit. `full ~= blocks/2` is the signature.
"""

import json
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

ANSI = re.compile(r"\x1b\[[0-9;]*m")
UNITS = {"": 1.0, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}


def log_blocks(path):
    """The execution layer's `Block added to canonical chain` lines as (epoch, number, txs, full%, gas_used)."""
    rows = []
    # grep, niced: the layer's log is hundreds of MB by the end of a leg and this runs beside the fleet
    found = subprocess.run(
        ["nice", "-n", "19", "grep", "-a", "Block added to canonical chain", path], capture_output=True, text=True, errors="replace"
    )
    if True:
        for line in found.stdout.splitlines():
            line = ANSI.sub("", line)
            try:
                when = datetime.strptime(line[:26], "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()
                txs = int(re.search(r" txs=(\d+)", line)[1])
                number = int(re.search(r" number=(\d+)", line)[1])
                full = float(re.search(r" full=([\d.]+)%", line)[1])
                used = re.search(r" gas_used=([\d.]+)([KMGT]?)gas", line)
                gas = float(used[1]) * UNITS[used[2]] if used else 0.0
            except (TypeError, ValueError):
                continue
            rows.append((when, number, txs, full, gas))
    return rows


def first_full(path, min_txs, wait):
    """Epoch of the first full canonical block after now (the flood's first block); now when none appears in `wait` s."""
    since = time.time()
    while time.time() - since < wait:
        for when, _, txs, _, _ in log_blocks(path):
            if when >= since - 1 and txs >= min_txs:
                return when
        time.sleep(1)
    return time.time()


def wait_idle(path, wait):
    """Blocks until the layer logs an empty canonical block (the pool drained, the chain idle), at most `wait` s."""
    since = time.time()
    while time.time() - since < wait:
        rows = [r for r in log_blocks(path) if r[0] >= since - 1]
        if rows and rows[-1][2] == 0:
            return
        time.sleep(2)


def shape_block(path, start, min_txs):
    """Number of a full block ten seconds into the flood, read from the log (the RPC read happens after the flood)."""
    for when, number, txs, _, _ in log_blocks(path):
        if when >= start + 10 and txs >= min_txs:
            return number
    return 0


def log_window(path, start, seconds, label):
    """One window from the log alone: no RPC. The window is [start, start + seconds)."""
    delay = start + seconds + 2 - time.time()
    if delay > 0:
        time.sleep(delay)
    rows = [r for r in log_blocks(path) if start <= r[0] < start + seconds]
    txs = sum(r[2] for r in rows)
    blocks = len(rows)
    full = sum(1 for r in rows if r[3] >= 95.0)
    occupancy = sum(r[3] for r in rows) / blocks if blocks else 0.0
    cycle = seconds / blocks if blocks else float("inf")
    print(
        f"{label:6} tps={txs / seconds:9,.0f} txs={txs:>9,} blocks={blocks:>4} "
        f"cycle={cycle:5.3f}s occupancy={occupancy:5.1f}% full(>=95%)={full}/{blocks} basefee=n/a (from the layer's log)"
    )


def call(port, method, params, attempts=5):
    """One RPC call, retried through transient refusals.

    A node under a throughput round answers the overflow with HTTP 429, and a
    measurement that raises on it takes the whole round with it -- which is
    exactly backwards: the round is the expensive thing and the sample is the
    cheap one. Retries are spaced so a node that is genuinely saturated is given
    time rather than added to.
    """
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(attempts):
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}", body, {"content-type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.load(response).get("result")
        except Exception:
            if attempt == attempts - 1:
                return None
            time.sleep(0.2 * (attempt + 1))
    return None


def height(port):
    result = call(port, "eth_blockNumber", [])
    if result is None:
        raise SystemExit("the node did not answer eth_blockNumber after retries")
    return int(result, 16)


def main():
    # Log mode (no RPC while the flood runs):
    #   --first-full <log> <min txs> <wait s>     epoch of the flood's first full block
    #   --log <log> <start epoch> <seconds> <label>  one window
    #   --shape-block <log> <start epoch> <min txs>  number of a full block 10 s in
    #   --wait-idle <log> <wait s>                returns once the chain makes empty blocks
    if sys.argv[1] == "--first-full":
        print(f"{first_full(sys.argv[2], int(sys.argv[3]), float(sys.argv[4])):.3f}")
        return
    if sys.argv[1] == "--log":
        log_window(sys.argv[2], float(sys.argv[3]), float(sys.argv[4]), sys.argv[5])
        return
    if sys.argv[1] == "--shape-block":
        print(shape_block(sys.argv[2], float(sys.argv[3]), int(sys.argv[4])))
        return
    if sys.argv[1] == "--wait-idle":
        wait_idle(sys.argv[2], float(sys.argv[3]))
        return
    port, seconds, label = int(sys.argv[1]), float(sys.argv[2]), sys.argv[3]
    start_h = height(port)
    started = time.time()
    time.sleep(seconds)
    end_h = height(port)
    elapsed = time.time() - started

    txs = gas_used = gas_limit = full = 0
    fees = []
    for n in range(start_h + 1, end_h + 1):
        block = call(port, "eth_getBlockByNumber", [hex(n), False])
        if not block:
            continue
        used, limit = int(block["gasUsed"], 16), int(block["gasLimit"], 16)
        txs += len(block["transactions"])
        gas_used += used
        gas_limit += limit
        fees.append(int(block.get("baseFeePerGas", "0x0"), 16))
        if limit and used / limit >= 0.95:
            full += 1

    blocks = end_h - start_h
    occupancy = 100 * gas_used / gas_limit if gas_limit else 0.0
    cycle = elapsed / blocks if blocks else float("inf")
    print(
        f"{label:6} tps={txs / elapsed:9,.0f} txs={txs:>9,} blocks={blocks:>4} "
        f"cycle={cycle:5.3f}s occupancy={occupancy:5.1f}% full(>=95%)={full}/{blocks} "
        f"basefee={min(fees) if fees else 0}->{max(fees) if fees else 0}"
    )


if __name__ == "__main__":
    main()
