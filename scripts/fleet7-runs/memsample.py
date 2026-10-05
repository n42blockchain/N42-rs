#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Every 2 s, per execution-layer process of the bench fleet: RSS from /proc/<pid>/status and the in-memory block
metrics of its Prometheus endpoint (ports F7_METRICS_BASE + i, 19300 by default): num_blocks, latest and earliest
in-memory block (earliest - 1 is the persisted height), backpressure_active and the backpressure stall histogram.
usage: memsample.py <out file> [execution layers]. With F7_EL_MAP set (one layer per validator, comma list; see fleet7-env.sh)
the layer e lives in the node directory of its first validator; unset, layer e is node e as before. One line a node: `<epoch> <HH:MM:SS> node<i> pid= rss_g= num= latest= earliest= bp= stall_n= stall_s= sb_sum= sb_n= bs_sum= sft_sum= qp_sum= canon=` (the last six, loop339: the persistence sums and the canonical height)
(`-` where the process or endpoint did not answer). Runs until killed."""
import os, re, sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
out = sys.argv[1]; nodes = int(sys.argv[2]) if len(sys.argv) > 2 else 3
base = int(os.environ.get('F7_METRICS_BASE', '19300')); root = os.environ.get('F7_ROOT', '/data/blockchain/rust-fleet3-bench')
NAMES = {'reth_blockchain_tree_in_mem_state_num_blocks': 'num', 'reth_blockchain_tree_in_mem_state_latest_block': 'latest',
         'reth_blockchain_tree_in_mem_state_earliest_block': 'earliest', 'reth_consensus_engine_beacon_backpressure_active': 'bp',
         'reth_consensus_engine_beacon_backpressure_stall_duration_count': 'stall_n',
         'reth_consensus_engine_beacon_backpressure_stall_duration_sum': 'stall_s',
         # loop339: the persistence reading (cumulative; persist339.py differences them per window)
         'reth_storage_providers_database_save_blocks_total_sum': 'sb_sum', 'reth_storage_providers_database_save_blocks_total_count': 'sb_n',
         'reth_storage_providers_database_save_blocks_batch_size_sum': 'bs_sum', 'reth_storage_providers_database_save_blocks_sf_transactions_sum': 'sft_sum',
         'reth_storage_providers_database_save_blocks_qmdb_persisted_sum': 'qp_sum', 'reth_blockchain_tree_canonical_chain_height': 'canon'}
MAP = [int(x) for x in os.environ['F7_EL_MAP'].split(',')] if os.environ.get('F7_EL_MAP') else None
def first_of(i):
    return MAP.index(i) if MAP else i
def pid_of(i):
    for p in os.listdir('/proc'):
        if not p.isdigit(): continue
        try: c = open(f'/proc/{p}/cmdline', 'rb').read().replace(b'\0', b' ').decode(errors='replace')
        except OSError: continue
        if '/n42 node' in c and f'{root}/node{first_of(i)}/' in c: return int(p)
    return None
def sample(i):
    d = {k: '-' for k in NAMES.values()}; pid = pid_of(i); rss = '-'
    if pid:
        try: rss = '%.2f' % (int(re.search(r'VmRSS:\s+(\d+)', open(f'/proc/{pid}/status').read())[1]) / 1e6)
        except (OSError, TypeError): pass
    try:
        for l in urllib.request.urlopen(f'http://127.0.0.1:{base + i}/metrics', timeout=1.5).read().decode().splitlines():
            n, _, v = l.partition(' ')
            if n in NAMES: d[NAMES[n]] = v
    except Exception: pass
    return f'node{i} pid={pid or "-"} rss_g={rss} num={d["num"]} latest={d["latest"]} earliest={d["earliest"]} bp={d["bp"]} stall_n={d["stall_n"]} stall_s={d["stall_s"]} sb_sum={d["sb_sum"]} sb_n={d["sb_n"]} bs_sum={d["bs_sum"]} sft_sum={d["sft_sum"]} qp_sum={d["qp_sum"]} canon={d["canon"]}'
ex = ThreadPoolExecutor(nodes)
with open(out, 'a', buffering=1) as f:
    while True:
        t = time.time()
        for l in ex.map(sample, range(nodes)): f.write(f'{t:.2f} {time.strftime("%H:%M:%S", time.localtime(t))} {l}\n')
        time.sleep(max(0.0, 2 - (time.time() - t)))
