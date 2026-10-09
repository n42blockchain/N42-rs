#!/usr/bin/env bash
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
# Profiling companions of one bench leg (loop314): usage prof314.sh <tag> <flood.log> <out dir>.
# Waits for the flood's funding to be mined (window 1 starts there), then runs vmsample, perf stat on each EL
# and perf record on node0 (leader) and node1 from +5 s to +35 s (perf sched needs tracefs, not permitted here).
tag=$1; flog=$2; S=$3
HERE=$(cd "$(dirname "$0")" && pwd)
n=0; until grep -aq 'mined through nonce' "$flog" 2>/dev/null; do sleep 0.5; n=$((n+1)); [ $n -gt 700 ] && exit 0; done
T0=$(date +%s.%N); echo "$tag T0_ms=$(( $(date +%s%N) / 1000000 ))" > "$S/prof-$tag.t0"
python3 "$HERE/vmsample.py" "$S/vmstat-$tag.tsv" 100 &
pid_of() { for p in $(pgrep -f '/n4[2] node --chain'); do tr '\0' ' ' < /proc/$p/cmdline | grep -q "bench/node$1" && { echo $p; return; }; done; }
EV=task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions,cache-misses,dTLB-load-misses
for i in 0 1 2; do
  p=$(pid_of $i); [ -n "$p" ] && perf stat -p $p -I 1000 -e $EV -x, -o "$S/perfstat-$tag-node$i.csv" -- sleep 60 > /dev/null 2>&1 &
done
sleep 5
p0=$(pid_of 0); p1=$(pid_of 1)
echo "$tag record start_ms=$(( $(date +%s%N) / 1000000 )) pid0=$p0 pid1=$p1" >> "$S/prof-$tag.t0"
# The default mmap size per thread exhausts the unprivileged mlock budget (first attempt: empty data files); retry smaller.
rec() { local pid=$1 out=$2 m; for m in 16 8 4 2 1; do
    perf record -m $m -F 499 -g --call-graph fp -p $pid -o "$out" -- sleep 30 > "$out.log" 2>&1 &
    local rp=$!; sleep 2
    if kill -0 $rp 2>/dev/null; then echo "$out mmap_pages=$m" >> "$S/prof-$tag.t0"; wait $rp; return; fi
    wait $rp 2>/dev/null; done; }
rec $p0 "$S/perf-$tag-node0.data" &
rec $p1 "$S/perf-$tag-node1.data" &
wait
