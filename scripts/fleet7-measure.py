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
import sys
import time
import urllib.request


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
