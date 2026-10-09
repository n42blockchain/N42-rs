#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Sampled substitute for `perf trace -s` where tracefs and ptrace are denied (perf_event_paranoid 1,
yama ptrace_scope 1): 10 Hz over every thread of one process, reading /proc/<pid>/task/*/{stat,wchan}.
Writes TSV: thread-name family, state, kernel wait function, samples. usage: wchansample.py <pid> <seconds> <out>"""
import collections, os, re, sys, time
pid, secs, out = int(sys.argv[1]), float(sys.argv[2]), sys.argv[3]
cnt = collections.Counter(); n = 0; end = time.time() + secs; nxt = time.time()
while time.time() < end:
    try: tids = os.listdir(f"/proc/{pid}/task")
    except OSError: break
    for t in tids:
        try:
            st = open(f"/proc/{pid}/task/{t}/stat").read()
            comm = st[st.index("(") + 1:st.rindex(")")]; state = st[st.rindex(")") + 2]
            w = open(f"/proc/{pid}/task/{t}/wchan").read().strip() or "-"
        except OSError: continue
        cnt[(re.sub(r"[-_.]?\d+$", "", comm), state, w if state != "R" else "-")] += 1
    n += 1; nxt += 0.1
    d = nxt - time.time()
    if d > 0: time.sleep(d)
with open(out, "w") as f:
    f.write(f"# {n} sweeps of pid {pid}\nfamily\tstate\twchan\tsamples\n")
    for (a, b, c), v in cnt.most_common(): f.write(f"{a}\t{b}\t{c}\t{v}\n")
