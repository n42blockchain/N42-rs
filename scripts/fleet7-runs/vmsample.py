#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Samples memory-system counters every 0.5 s as TSV: epoch ms, /proc/vmstat counters, a few /proc/meminfo
fields and the `some` line of /proc/pressure/{memory,cpu}.
usage: vmsample.py <out.tsv> <seconds>"""
import sys, time

VM = ("compact_stall compact_fail compact_success thp_fault_alloc thp_fault_fallback thp_collapse_alloc "
      "thp_split_page thp_deferred_split_page pgscan_kswapd pgscan_direct pgsteal_kswapd pgsteal_direct "
      "allocstall_normal allocstall_movable pgmajfault pgfault nr_dirty nr_writeback numa_pte_updates "
      "pgmigrate_success").split()
MI = ["MemAvailable", "AnonHugePages", "Dirty", "Writeback"]


def psi(name):
    try:
        for line in open(f"/proc/pressure/{name}"):
            if line.startswith("some"):
                kv = dict(x.split("=") for x in line.split()[1:])
                return [kv["avg10"], kv["total"]]
    except OSError:
        pass
    return ["", ""]


def main():
    out, secs = sys.argv[1], float(sys.argv[2])
    cols = ["t_ms"] + VM + [m + "_kb" for m in MI] + ["psi_mem_avg10", "psi_mem_total", "psi_cpu_avg10", "psi_cpu_total"]
    end = time.time() + secs
    with open(out, "w") as f:
        f.write("\t".join(cols) + "\n")
        nxt = time.time()
        while time.time() < end:
            vm = {}
            for line in open("/proc/vmstat"):
                k, v = line.split()
                vm[k] = v
            mi = {}
            for line in open("/proc/meminfo"):
                k, v = line.split(":", 1)
                if k in MI:
                    mi[k] = v.split()[0]
            row = [str(int(time.time() * 1000))] + [vm.get(k, "") for k in VM] + [mi.get(k, "") for k in MI] + psi("memory") + psi("cpu")
            f.write("\t".join(row) + "\n")
            f.flush()
            nxt += 0.5
            time.sleep(max(0, nxt - time.time()))


main()
