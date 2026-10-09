#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Once-a-second kernel counters for the fleet box, cumulative, one line per second:
<UTC timestamp as the node logs write it> CAL=.. TLB=.. pgfault=.. ... (NA when the kernel does not export it).
CAL and TLB are the rows of /proc/interrupts summed over CPUs. One read per file per second.
Memory guard: if MemAvailable stays under 4 GB for 3 s the fleet processes are terminated (the leg would be void
and the box is shared). usage: kernsample.py <out file>"""
import os, signal, subprocess, sys, time
from datetime import datetime, timezone

VM = ("pgfault pgmajfault nr_tlb_remote_flush nr_tlb_remote_flush_received thp_fault_alloc thp_fault_fallback "
      "compact_stall pgscan_kswapd pgsteal_kswapd").split()
stop = False
def _term(*_):
    global stop
    stop = True
signal.signal(signal.SIGTERM, _term); signal.signal(signal.SIGINT, _term)

def irq():
    want = {"CAL": 0, "TLB": 0}
    with open("/proc/interrupts") as f:
        for line in f:
            h = line.split(None, 1)
            if h and h[0].rstrip(":") in want and h[0].endswith(":"):
                tot = 0
                for x in h[1].split():
                    if not x.isdigit(): break
                    tot += int(x)
                want[h[0].rstrip(":")] = tot
    return want

def main():
    out = sys.argv[1]
    os.makedirs(os.path.dirname(out), exist_ok=True)
    low = 0
    with open(out, "w", buffering=1) as f:
        nxt = time.time()
        while not stop:
            r = irq(); vm = {}
            with open("/proc/vmstat") as g:
                for line in g:
                    k, v = line.split()
                    if k in VM: vm[k] = v
            avail = 0
            with open("/proc/meminfo") as g:
                for line in g:
                    if line.startswith("MemAvailable:"):
                        avail = int(line.split()[1]); break
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
            f.write(f"{ts} CAL={r['CAL']} TLB={r['TLB']} " + " ".join(f"{k}={vm.get(k, 'NA')}" for k in VM) + f" avail_kb={avail}\n")
            low = low + 1 if avail < 4 * 1024 * 1024 else 0
            if low >= 3:
                f.write(f"{ts} MEMORY GUARD: terminating the fleet\n")
                for pat in ("/n4[2] node --chain", "h2_validato[r]", "tx_floo[d]"):
                    for pid in subprocess.run(["pgrep", "-f", pat], capture_output=True, text=True).stdout.split():
                        try: os.kill(int(pid), signal.SIGTERM)
                        except OSError: pass
                low = 0
            nxt += 1.0
            d = nxt - time.time()
            if d > 0: time.sleep(d)
            else: nxt = time.time()

main()
