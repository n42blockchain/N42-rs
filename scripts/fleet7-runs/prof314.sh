#!/usr/bin/env bash
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
# Profiling companions of one bench leg (loop314): usage prof314.sh <tag> <flood.log> <out dir>.
# Waits for the flood's funding to be mined (window 1 starts there), then runs vmsample, perf stat on each EL
# and perf record on node0 (leader) and node1 from +5 s to +35 s, then perf sched on node0 if permitted.
tag=$1; flog=$2; S=$3
HERE=$(cd "$(dirname "$0")" && pwd)
n=0; until grep -aq 'mined through nonce' "$flog" 2>/dev/null; do sleep 0.5; n=$((n+1)); [ $n -gt 700 ] && exit 0; done
T0=$(date +%s.%N); echo "$tag T0_ms=$(date +%s%3N)" > "$S/prof-$tag.t0"
python3 "$HERE/vmsample.py" "$S/vmstat-$tag.tsv" 100 &
pid_of() { for p in $(pgrep -f '/n4[2] node --chain'); do tr '\0' ' ' < /proc/$p/cmdline | grep -q "bench/node$1" && { echo $p; return; }; done; }
EV=task-clock,context-switches,cpu-migrations,page-faults,cycles,instructions,cache-misses,dTLB-load-misses
for i in 0 1 2; do
  p=$(pid_of $i); [ -n "$p" ] && perf stat -p $p -I 1000 -e $EV -x, -o "$S/perfstat-$tag-node$i.csv" -- sleep 60 > /dev/null 2>&1 &
done
sleep 5
p0=$(pid_of 0); p1=$(pid_of 1)
echo "$tag record start_ms=$(date +%s%3N) pid0=$p0 pid1=$p1" >> "$S/prof-$tag.t0"
perf record -F 499 -g --call-graph fp -p $p0 -o "$S/perf-$tag-node0.data" -- sleep 30 > "$S/perfrec-$tag-node0.log" 2>&1 &
perf record -F 499 -g --call-graph fp -p $p1 -o "$S/perf-$tag-node1.data" -- sleep 30 > "$S/perfrec-$tag-node1.log" 2>&1 &
sleep 33
perf sched record -p $p0 -o "$S/perf-$tag-node0-sched.data" -- sleep 10 > "$S/perfsched-$tag.log" 2>&1 || rm -f "$S/perf-$tag-node0-sched.data"
wait
