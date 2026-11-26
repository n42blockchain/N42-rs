#!/usr/bin/env python3
"""The catch-up bench's sampler (scripts/catchup-bench.sh leg).

Every STEP seconds: time, the catching-up EL's height, and the CPU ticks of
every member process (el3 val3 el0 val0 el1 val1) into OUT/heights.tsv. Stops
at TARGET - 70 (the unanchored tail, <= 64 blocks, that nothing certifies
while the chain stands still) or when the height has not moved for STALL
seconds after it first moved (or 300 s before it ever did).

  catchup-sampler.py <el3 http port> <target> <step s> <stall s> <bin dir> <members dir> <out dir>
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

port, target, step, stall = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
binp, pdir, out = sys.argv[5], sys.argv[6], sys.argv[7]
PROCS = [("n42 node", 3), ("examples/h2_validator", 3), ("n42 node", 0),
         ("examples/h2_validator", 0), ("n42 node", 1), ("examples/h2_validator", 1)]


def pid(kind, member):
    pat = f"^{binp}/{kind} --datadir {pdir}/m{member}/"
    found = subprocess.run(["pgrep", "-f", pat], capture_output=True, text=True).stdout.split()
    return found[0] if found else None


def ticks(p):
    try:
        fields = open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()
        return int(fields[11]) + int(fields[12])
    except (OSError, IndexError, ValueError):
        return 0


def height():
    try:
        q = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{port}", q, {"content-type": "application/json"})
        return int(json.load(urllib.request.urlopen(req, timeout=5))["result"], 16)
    except (OSError, ValueError, KeyError):
        return 0


pids = [None] * len(PROCS)
last, since, moved = -1, time.time(), False
with open(os.path.join(out, "heights.tsv"), "w") as f:
    while True:
        pids = [p or pid(*PROCS[i]) for i, p in enumerate(pids)]
        h = height()
        f.write("\t".join([f"{time.time():.3f}", str(h)] + [str(ticks(p)) if p else "0" for p in pids]) + "\n")
        f.flush()
        if h >= target - 70:
            break
        if h != last:
            moved = moved or last >= 0 and h > 0
            last, since = h, time.time()
        elif time.time() - since > (stall if moved else 300):
            with open(os.path.join(out, "leg.txt"), "a") as leg:
                leg.write(f"stalled at {h}\n")
            break
        time.sleep(step)
