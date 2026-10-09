#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Derives run-loop351.sh and launch-loop351.sh from loop350's pair. loop351 = 200k blocks, 7 keys on one layer, all at 50 ms pacing after WARM (60 ms).
Stage a: WARM, BP50, S1P50, S1P50T64, S13P50, S13P50T64, BP50b (T64 = N42_PARALLEL_BUILD_THREADS=64). Stage b: WARM, then the pacing step-down 50 -> 45 -> 40 applied to the
stage-a configuration with the best window 1 (it must beat max(BP50, BP50b) by 1.5%), or, when none does, S1P50b and S1P50T64b."""
import re
D = '/data/n42-build/wt338/scripts/fleet7-runs/'
r = open(D + 'run-loop350.sh').read().replace('loop350', 'loop351').replace('LOOP350', 'LOOP351')
# a dry run owns no fleet: the EXIT trap must not kill the processes of a leg another stage is running (2026-10-08, S13P50)
r = r.replace('cleanup() {\n', 'cleanup() {\n  # a dry run (LOOP351_DRY=1) owns no fleet: on 2026-10-08 a dry run of stage c, exited while stage a held the box, killed the running leg (S13P50) through this trap\n  [ "${LOOP351_DRY:-0}" = 1 ] && return 0\n', 1)
r = r.replace('scripts/fleet7-runs/manykeys350.py ]; then echo "INSTRUMENTATION MISSING', 'scripts/fleet7-runs/manykeys350.py ] || ! grep -q N42_DEFERRED_IN_FLIGHT crates/n42/h2-execution/src/driver.rs || ! grep -q N42_BUILT_KEEP crates/n42/engine-types/src/built_executions.rs || ! grep -q N42_QMDB_RENAME_DEFER crates/n42/engine-types/src/chain_alias.rs || ! grep -q N42_HANDOFF_HEAD_MOVE bin/n42/src/payload_serve.rs || ! grep -q N42_HANDOFF_NO_CLONE crates/n42/engine-types/src/built_executions.rs || ! grep -q N42_HANDOFF_MOVE_BODY crates/n42/engine-types/src/built_executions.rs || ! grep -q N42_CANON_NOTIFY_LEAN crates/chain-state/src/in_memory.rs; then echo "INSTRUMENTATION MISSING', 1)
r = r.replace('manykeys351', 'manykeys350').replace('valsample351', 'valsample350')
r = r.replace('ACCOUNT_HISTORY|PERSIST_QMDB|', 'RENAME_DEFER|HANDOFF_|CANON_NOTIFY|ACCOUNT_HISTORY|PERSIST_QMDB|', 1)
r = re.sub(r'^# loop351 = .*\n# Stage a:.*\n', '''# loop351 = 200k blocks, 7 keys on one layer, 50 ms pacing: the base, check-before-slot alone (S1), 64 build threads (T64) and the merge at shards_ready (S3), then a step-down of the best. usage: run-loop351.sh <a|b|c|d>
# Stage a: WARM (60 ms), BP50, S1P50, S1P50T64, S13P50, S13P50T64, BP50b.  b: WARM, then 45 and 40 ms for the best stage-a configuration (window 1 at least 1.5% over max(BP50, BP50b), each step only while gate340 holds), else S1P50b and S1P50T64b.
''', r, count=1, flags=re.M)
r = r.replace('(loop351: the same commit as the', '(loop351: the same commit as the')
r = r.replace('FAR_AHEAD_BLOCKS|', 'FAR_AHEAD_BLOCKS|BUILT_KEEP|')
# stage-defs
i = r.index('S1="N42_CHECK_BEFORE_SLOT=1"')
j = r.index('w1of() {')
new_defs = '''S1="N42_CHECK_BEFORE_SLOT=1"; S2="N42_LEADER_LAYERS=6"; S3="N42_MERGE_AT_SHARDS_READY=1 N42_MERGE_POOL_THREADS=16"; S4="N42_SHARDS_BEFORE_RECEIPTS=1 N42_FREEZE_SPLIT=4"; T64="N42_PARALLEL_BUILD_THREADS=64"
VB="N42_VOTE_AGGREGATE_VERIFY=1 N42_VOTE_TRANSPORT=direct N42_GOSSIP_HANDLER_QUEUE=64 N42_GOSSIP_MAX_IHAVE=500"
b7() { local tag=$1; shift; mk $tag 7 16 $VB "$@"; }
# a configuration is NAME:SUFFIX (S1:, S1:T64, S13:, S13:T64); its flags and its leg tag at a pacing
cflags() { local f=""; case $1 in S1*) f="$S1";; S13*) f="$S1 $S3";; esac; case $1 in *T64) f="$f $T64";; esac; echo "$f"; }
ctag() { local c=$1 p=$2; case $c in *T64) echo "${c%T64}P${p}T64";; *) echo "${c}P${p}";; esac; }
# the next pacing step runs only while the previous step's cycle median is within 3 ms of its pacing and the backlog is flat (gate340.py: names the test that failed)
step() { local cur=$1 next=$2 cfg=$3; shift 3; local G tags=""; for t in "$@"; do tags="$tags loop351$t"; done
  if [ "${LOOP351_DRY:-0}" = 1 ]; then echo "(dry) gate at $cur ms assumed to hold"; b7 $(ctag $cfg $next) F7_BLOCK_INTERVAL_MS=$next $(cflags $cfg); return 0; fi
  if G=$(python3 scripts/fleet7-runs/gate340.py $cur $tags); then echo "gate at $cur ms ($*): $G"; b7 $(ctag $cfg $next) F7_BLOCK_INTERVAL_MS=$next $(cflags $cfg); return 0; fi
  echo "STEPS STOP before $next ms ($*): $G"; return 1; }
'''
r = r[:i] + new_defs + r[j:]
# stages
i = r.index('case $STAGE in')
j = r.index('esac', i) + 5
stages = '''case $STAGE in
  a) mk WARM 7 16; warm_gate WARM
     b7 BP50 F7_BLOCK_INTERVAL_MS=50
     b7 S1P50 F7_BLOCK_INTERVAL_MS=50 $S1
     b7 S1P50T64 F7_BLOCK_INTERVAL_MS=50 $S1 $T64
     b7 S13P50 F7_BLOCK_INTERVAL_MS=50 $S1 $S3
     b7 S13P50T64 F7_BLOCK_INTERVAL_MS=50 $S1 $S3 $T64
     b7 BP50b F7_BLOCK_INTERVAL_MS=50 ;;
  b) mk WARM 7 16; warm_gate WARM
     # needs the stage-a round.txt files on disk: the best of the four configurations by window 1 must beat max(BP50, BP50b) by 1.5%
     WB1=$(w1of BP50); WB2=$(w1of BP50b)
     BASEW=$(python3 -c "print(max(int('${WB1:-0}' or 0), int('${WB2:-0}' or 0)))")
     BEST=""; BESTW=0
     for cfg in S1 S1T64 S13 S13T64; do W=$(w1of $(ctag $cfg 50)); echo "stage a window 1: $(ctag $cfg 50) ${W:-none}"; [ "${W:-0}" -gt "$BESTW" ] && { BEST=$cfg; BESTW=$W; }; done
     if [ "${LOOP351_DRY:-0}" = 1 ] && [ -z "$BEST" ]; then BEST=S1; BESTW=1; BASEW=0; echo "(dry) no stage-a data: planning the step-down of S1"; fi
     echo "stage a base window 1: BP50 ${WB1:-none}, BP50b ${WB2:-none}; best configuration ${BEST:-none} at ${BESTW}"
     if [ -n "$BEST" ] && [ "$(python3 -c "print(1 if $BESTW >= 1.015 * $BASEW and $BASEW > 0 or ($BASEW == 0 and $BESTW > 0 and '${LOOP351_DRY:-0}' == '1') else 0)")" = 1 ]; then
       echo "$BEST beats the base by 1.5% or more: stepping it down"
       if step 50 45 $BEST $(ctag $BEST 50); then step 45 40 $BEST $(ctag $BEST 45); fi
     else
       echo "no configuration beat the base by 1.5%: second legs of S1P50 and S1P50T64"
       b7 S1P50b F7_BLOCK_INTERVAL_MS=50 $S1
       b7 S1P50T64b F7_BLOCK_INTERVAL_MS=50 $S1 $T64
     fi ;;
  c) mk WARM 7 16; warm_gate WARM
     b7 S2P50T64 F7_BLOCK_INTERVAL_MS=50 $S2 $T64
     b7 S12P50T64 F7_BLOCK_INTERVAL_MS=50 $S1 $S2 $T64
     b7 S123P50T64 F7_BLOCK_INTERVAL_MS=50 $S1 $S2 $S3 $T64
     b7 S12P50T64b F7_BLOCK_INTERVAL_MS=50 $S1 $S2 $T64
     b7 S123P50T64b F7_BLOCK_INTERVAL_MS=50 $S1 $S2 $S3 $T64
     b7 S2P50T64b F7_BLOCK_INTERVAL_MS=50 $S2 $T64 ;;
  d) mk WARM 7 16; warm_gate WARM
     D2="F7_GENESIS=$WT/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json"
     b7 S2P45T64 F7_BLOCK_INTERVAL_MS=45 $S2 $T64
     b7 D2S2P50T64 $D2 F7_BLOCK_INTERVAL_MS=50 $S2 $T64
     b7 D2S2P45T64 $D2 F7_BLOCK_INTERVAL_MS=45 $S2 $T64
     b7 D2S2P40T64 $D2 F7_BLOCK_INTERVAL_MS=40 $S2 $T64
     b7 D2S2P45T64b $D2 F7_BLOCK_INTERVAL_MS=45 $S2 $T64
     b7 D2S2P40T64b $D2 F7_BLOCK_INTERVAL_MS=40 $S2 $T64 ;;
  e) mk WARM 7 16; warm_gate WARM
     D2="F7_GENESIS=$WT/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json"
     b7 D2S12P45T64 $D2 F7_BLOCK_INTERVAL_MS=45 $S1 $S2 $T64
     b7 D2S12P40T64 $D2 F7_BLOCK_INTERVAL_MS=40 $S1 $S2 $T64
     b7 D2S12P45T64b $D2 F7_BLOCK_INTERVAL_MS=45 $S1 $S2 $T64
     b7 D2S12P40T64b $D2 F7_BLOCK_INTERVAL_MS=40 $S1 $S2 $T64
     b7 D2S12P35T64 $D2 F7_BLOCK_INTERVAL_MS=35 $S1 $S2 $T64
     b7 D2S12P35T64b $D2 F7_BLOCK_INTERVAL_MS=35 $S1 $S2 $T64 ;;
  f) mk WARM 7 16; warm_gate WARM
     D2="F7_GENESIS=$WT/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json"; F2="N42_FAR_AHEAD_BLOCKS=2"
     b7 D2S12F2P45T64 $D2 F7_BLOCK_INTERVAL_MS=45 $S1 $S2 $F2 $T64
     b7 D2S12F2P40T64 $D2 F7_BLOCK_INTERVAL_MS=40 $S1 $S2 $F2 $T64
     b7 D2S12F2P35T64 $D2 F7_BLOCK_INTERVAL_MS=35 $S1 $S2 $F2 $T64
     b7 D2S12F2P45T64b $D2 F7_BLOCK_INTERVAL_MS=45 $S1 $S2 $F2 $T64
     b7 D2S12F2P40T64b $D2 F7_BLOCK_INTERVAL_MS=40 $S1 $S2 $F2 $T64
     b7 D2S12F2P35T64b $D2 F7_BLOCK_INTERVAL_MS=35 $S1 $S2 $F2 $T64 ;;
  g) mk WARM 7 16; warm_gate WARM
     D2="F7_GENESIS=$WT/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json"; F6="N42_FAR_AHEAD_BLOCKS=6"
     b7 D2S12F6P45T64 $D2 F7_BLOCK_INTERVAL_MS=45 $S1 $S2 $F6 $T64
     b7 D2S12F6P40T64 $D2 F7_BLOCK_INTERVAL_MS=40 $S1 $S2 $F6 $T64
     b7 D2S12F6P45T64b $D2 F7_BLOCK_INTERVAL_MS=45 $S1 $S2 $F6 $T64
     b7 D2S12F6P40T64b $D2 F7_BLOCK_INTERVAL_MS=40 $S1 $S2 $F6 $T64
     b7 D2S12F6P35T64 $D2 F7_BLOCK_INTERVAL_MS=35 $S1 $S2 $F6 $T64 ;;
  h) mk WARM 7 16; warm_gate WARM
     D2="F7_GENESIS=$WT/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json"; F6="N42_FAR_AHEAD_BLOCKS=6"; I3="N42_DEFERRED_IN_FLIGHT=3"
     b7 D2S2I3P45T64 $D2 $S2 $I3 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S2I3P40T64 $D2 $S2 $I3 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S12F6I3P45T64 $D2 $S1 $S2 $F6 $I3 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S12F6I3P40T64 $D2 $S1 $S2 $F6 $I3 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S2I3P45T64b $D2 $S2 $I3 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S2I3P40T64b $D2 $S2 $I3 $T64 F7_BLOCK_INTERVAL_MS=40 ;;
  i) mk WARM 7 16; warm_gate WARM
     D2="F7_GENESIS=$WT/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json"; F6="N42_FAR_AHEAD_BLOCKS=6"; I3="N42_DEFERRED_IN_FLIGHT=3"; K8="N42_BUILT_KEEP=8"
     b7 D2S12F6I3K8P45T64 $D2 $S1 $S2 $F6 $I3 $K8 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S12F6I3K8P40T64 $D2 $S1 $S2 $F6 $I3 $K8 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S12F6I3K8P35T64 $D2 $S1 $S2 $F6 $I3 $K8 $T64 F7_BLOCK_INTERVAL_MS=35
     b7 D2S12F6I3K8P40T64b $D2 $S1 $S2 $F6 $I3 $K8 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S12F6I3K8P35T64b $D2 $S1 $S2 $F6 $I3 $K8 $T64 F7_BLOCK_INTERVAL_MS=35
     b7 D2S2I3K8P40T64 $D2 $S2 $I3 $K8 $T64 F7_BLOCK_INTERVAL_MS=40 ;;
  j) mk WARM 7 16; warm_gate WARM
     D2="F7_GENESIS=$WT/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json"; F6="N42_FAR_AHEAD_BLOCKS=6"; I3="N42_DEFERRED_IN_FLIGHT=3"; K8="N42_BUILT_KEEP=8"
     b7 D2S2P45T64 $D2 $S2 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S12F6I3K8P45T64 $D2 $S1 $S2 $F6 $I3 $K8 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S2I3K8P45T64 $D2 $S2 $I3 $K8 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S2I3K8P40T64 $D2 $S2 $I3 $K8 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S12F6I3K8P40T64 $D2 $S1 $S2 $F6 $I3 $K8 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S2P45T64b $D2 $S2 $T64 F7_BLOCK_INTERVAL_MS=45 ;;
  k) mk WARM 7 16; warm_gate WARM
     D2="F7_GENESIS=$WT/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json"; F6="N42_FAR_AHEAD_BLOCKS=6"; I3="N42_DEFERRED_IN_FLIGHT=3"; K8="N42_BUILT_KEEP=8"
     X3="N42_QMDB_RENAME_DEFER=1 N42_HANDOFF_HEAD_MOVE=number N42_HANDOFF_NO_CLONE=1"
     b7 D2S2P45T64X3 $D2 $S2 $X3 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S2P40T64X3 $D2 $S2 $X3 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S12F6I3K8P45T64X3 $D2 $S1 $S2 $F6 $I3 $K8 $X3 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S12F6I3K8P40T64X3 $D2 $S1 $S2 $F6 $I3 $K8 $X3 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S2P45T64X3b $D2 $S2 $X3 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S2P40T64X3b $D2 $S2 $X3 $T64 F7_BLOCK_INTERVAL_MS=40 ;;
  l) mk WARM 7 16; warm_gate WARM
     D2="F7_GENESIS=$WT/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json"; F6="N42_FAR_AHEAD_BLOCKS=6"; I3="N42_DEFERRED_IN_FLIGHT=3"; K8="N42_BUILT_KEEP=8"
     X3="N42_QMDB_RENAME_DEFER=1 N42_HANDOFF_HEAD_MOVE=number N42_HANDOFF_NO_CLONE=1"; X4="$X3 N42_HANDOFF_MOVE_BODY=1"
     b7 D2S2P45T64X4 $D2 $S2 $X4 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S2P40T64X4 $D2 $S2 $X4 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S12F6I3K8P45T64X4 $D2 $S1 $S2 $F6 $I3 $K8 $X4 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S12F6I3K8P40T64X4 $D2 $S1 $S2 $F6 $I3 $K8 $X4 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S2P45T64X4b $D2 $S2 $X4 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S2P40T64X4b $D2 $S2 $X4 $T64 F7_BLOCK_INTERVAL_MS=40 ;;
  m) mk WARM 7 16; warm_gate WARM
     D2="F7_GENESIS=$WT/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json"; F6="N42_FAR_AHEAD_BLOCKS=6"; I3="N42_DEFERRED_IN_FLIGHT=3"; K8="N42_BUILT_KEEP=8"
     X3="N42_QMDB_RENAME_DEFER=1 N42_HANDOFF_HEAD_MOVE=number N42_HANDOFF_NO_CLONE=1"; X4="$X3 N42_HANDOFF_MOVE_BODY=1"; X5="$X4 N42_CANON_NOTIFY_LEAN=1"
     b7 D2S12F6I3K8P45T64X5 $D2 $S1 $S2 $F6 $I3 $K8 $X5 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S12F6I3K8P40T64X5 $D2 $S1 $S2 $F6 $I3 $K8 $X5 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S12F6I3K8P35T64X5 $D2 $S1 $S2 $F6 $I3 $K8 $X5 $T64 F7_BLOCK_INTERVAL_MS=35
     b7 D2S2P45T64X5 $D2 $S2 $X5 $T64 F7_BLOCK_INTERVAL_MS=45
     b7 D2S12F6I3K8P40T64X5b $D2 $S1 $S2 $F6 $I3 $K8 $X5 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S12F6I3K8P35T64X5b $D2 $S1 $S2 $F6 $I3 $K8 $X5 $T64 F7_BLOCK_INTERVAL_MS=35 ;;
  n) mk WARM 7 16; warm_gate WARM
     D2="F7_GENESIS=$WT/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json"; F6="N42_FAR_AHEAD_BLOCKS=6"; I3="N42_DEFERRED_IN_FLIGHT=3"; K8="N42_BUILT_KEEP=8"
     X3="N42_QMDB_RENAME_DEFER=1 N42_HANDOFF_HEAD_MOVE=number N42_HANDOFF_NO_CLONE=1"; X4="$X3 N42_HANDOFF_MOVE_BODY=1"; X5="$X4 N42_CANON_NOTIFY_LEAN=1"
     b7 D2S12F6I3K8P30T64X5 $D2 $S1 $S2 $F6 $I3 $K8 $X5 $T64 F7_BLOCK_INTERVAL_MS=30
     b7 D2S12F6I3K8P25T64X5 $D2 $S1 $S2 $F6 $I3 $K8 $X5 $T64 F7_BLOCK_INTERVAL_MS=25
     b7 D2S12F6I3K8P35T64X5b $D2 $S1 $S2 $F6 $I3 $K8 $X5 $T64 F7_BLOCK_INTERVAL_MS=35
     b7 D2S12F6I3K8P30T64X5b $D2 $S1 $S2 $F6 $I3 $K8 $X5 $T64 F7_BLOCK_INTERVAL_MS=30
     b7 D2S12F6I3K8P25T64X5b $D2 $S1 $S2 $F6 $I3 $K8 $X5 $T64 F7_BLOCK_INTERVAL_MS=25
     b7 D2S12F6I3K8P20T64X5 $D2 $S1 $S2 $F6 $I3 $K8 $X5 $T64 F7_BLOCK_INTERVAL_MS=20 ;;
  o) mk WARM 7 16; warm_gate WARM
     D2="F7_GENESIS=$WT/crates/chainspec/res/genesis/n42_fleet7_bench_d2.json"
     X3="N42_QMDB_RENAME_DEFER=1 N42_HANDOFF_HEAD_MOVE=number N42_HANDOFF_NO_CLONE=1"; X4="$X3 N42_HANDOFF_MOVE_BODY=1"; X5="$X4 N42_CANON_NOTIFY_LEAN=1"
     b7 D2S2P40T64X5 $D2 $S2 $X5 $T64 F7_BLOCK_INTERVAL_MS=40
     b7 D2S2P35T64X5 $D2 $S2 $X5 $T64 F7_BLOCK_INTERVAL_MS=35
     b7 D2S2P30T64X5 $D2 $S2 $X5 $T64 F7_BLOCK_INTERVAL_MS=30
     b7 D2S2P25T64X5 $D2 $S2 $X5 $T64 F7_BLOCK_INTERVAL_MS=25
     b7 D2S2P35T64X5b $D2 $S2 $X5 $T64 F7_BLOCK_INTERVAL_MS=35
     b7 D2S2P30T64X5b $D2 $S2 $X5 $T64 F7_BLOCK_INTERVAL_MS=30 ;;
  *) echo "unknown stage $STAGE (a, b, c, d, e, f, g, h, i, j, k, l, m, n or o)"; exit 2 ;;
esac
'''
r = r[:i] + stages + r[j:]
import os
def atomic(path, text):
    # replace by rename: a runner may be reading the old file (a truncating write would corrupt its run)
    open(path + '.new', 'w').write(text); os.replace(path + '.new', path)
atomic(D + 'run-loop351.sh', r)

l = r'''#!/bin/bash
# loop351 (200k, 7 keys on one layer, 50 ms pacing; derive351.py). usage: launch-loop351.sh <a|b|c|d|e|f|g|h|i|j|k|l|m|n|o>. Launch: setsid nohup bash target/fleet-runs/launch-loop351.sh f > target/fleet-runs/loop351f.out 2>&1 &
# Waits for the box, checks the tree, and runs the stage. When crates/ or bin/ changed since the last build, the launcher builds target/native (the legs' F7_BIN) after the box is free and the runner
# runs its own test gate, clippy and the target/deferred build (once: this launcher does not export LOOP351_GATE_TREES for a changed tree). Unchanged tree: no build, no tests.
cd /data/n42-build/wt338
STAGE=${1:-a}; case $STAGE in a|b|c|d|e|f|g|h|i|j|k|l|m|n|o) ;; *) echo "usage: launch-loop351.sh <a|b|c|d|e|f|g|h|i|j|k|l|m|n|o>"; exit 2;; esac
# the tree (crates/ and bin/) the binaries in target/native and target/deferred were built from: f2794a821 until a build here records another (the marker is written after a stage that built)
MARK=target/fleet-runs/loop351-built-trees
BUILT=f2794a821
BUILT_TREES=$(cat $MARK 2>/dev/null || echo "$(git rev-parse $BUILT:crates)-$(git rev-parse $BUILT:bin)")
CUR_TREES="$(git rev-parse HEAD:crates)-$(git rev-parse HEAD:bin)"
if [ -n "$(git status --porcelain crates bin | grep -v pycache)" ]; then echo "uncommitted changes in crates/ or bin/; nothing run"; echo ALLDONE; exit 1; fi
n=0
while [ -n "$(find /data/blockchain/.box-claim-* -mmin -90 2>/dev/null)" ] || [ "$(pgrep -fc 'n42-[a-z0-9]+ --chai[n]')" != 0 ]; do sleep 60; n=$((n+1)); [ $n -gt 240 ] && { echo "gave up waiting after 4 h"; exit 1; }; done
grep -rq N42_LEADER_LAYERS crates/n42/engine-types/src || { echo "N42_LEADER_LAYERS is not in the tree; nothing run"; echo ALLDONE; exit 1; }
grep -rq N42_PARALLEL_BUILD_THREADS crates bin || { echo "N42_PARALLEL_BUILD_THREADS is not in the tree; nothing run"; echo ALLDONE; exit 1; }
grep -rq N42_IMPORT_ONCE bin/n42/src crates/n42 || { echo "N42_IMPORT_ONCE is not in the tree; nothing run"; echo ALLDONE; exit 1; }
for f in scripts/fleet7-runs/run-loop351.sh scripts/fleet7-runs/manykeys350.py scripts/fleet7-runs/valsample350.py scripts/fleet7-runs/gate340.py; do [ -r $f ] || { echo "$f is not in the tree; nothing run"; echo ALLDONE; exit 1; }; done
grep -q f7_fleet_cpus scripts/fleet7-env.sh || { echo "scripts/fleet7-env.sh lacks f7_fleet_cpus; nothing run"; echo ALLDONE; exit 1; }
avail=$(df -BG /data | awk 'NR==2{gsub("G","",$4); print $4}'); [ "${avail:-0}" -ge 120 ] || { echo "/data has only ${avail}G free (the smallest leg needs 120G); nothing run"; echo ALLDONE; exit 1; }
echo "/data free ${avail}G at launch"
STAMP=target/fleet-runs/.loop351-launch-stamp; touch $STAMP
if [ "$BUILT_TREES" = "$CUR_TREES" ]; then
  [ -x target/native/release/n42 ] && [ -x target/deferred/release/n42 ] || { echo "binaries missing in target/native or target/deferred; nothing run"; echo ALLDONE; exit 1; }
  grep -aq N42_IMPORT_ONCE target/native/release/n42 || { echo "the native n42 does not know N42_IMPORT_ONCE; no leg can run"; echo ALLDONE; exit 1; }
  echo "tree at $(git rev-parse --short HEAD) ($(git log -1 --format=%s | cut -c1-80)); box free at $(date +%H:%M); crates/ and bin/ unchanged since the build: no build, no tests"
  export LOOP351_GATE_TREES="$CUR_TREES"
else
  echo "tree at $(git rev-parse --short HEAD) ($(git log -1 --format=%s | cut -c1-80)); box free at $(date +%H:%M); crates/ or bin/ changed since the build ($BUILT_TREES): native build here, tests, clippy and deferred build in the runner"
  PKGS="-p n42 --bin n42 -p n42-h2-node --example h2_validator --example tx_flood --example h2_keygen --example send_tx"
  if ! RUSTFLAGS="-C target-cpu=native" nice -n 19 cargo build -j16 --release --target-dir target/native $PKGS > target/fleet-runs/build-native-loop351.log 2>&1; then echo "NATIVE BUILD FAILED"; grep -E '^error' -A6 target/fleet-runs/build-native-loop351.log | head -40; echo ALLDONE; exit 1; fi
  grep -aq N42_IMPORT_ONCE target/native/release/n42 || { echo "the built n42 does not know N42_IMPORT_ONCE; no leg can run"; echo ALLDONE; exit 1; }
  grep -aq N42_FAR_AHEAD_BLOCKS target/native/release/examples/h2_validator || { echo "the built h2_validator does not know N42_FAR_AHEAD_BLOCKS; nothing run"; echo ALLDONE; exit 1; }
  [ -z "$(find crates bin -name '*.rs' -newer target/native/release/n42 | head -1)" ] || { echo "a source file is newer than the native binary; nothing run"; echo ALLDONE; exit 1; }
  echo "native build done at $(date +%H:%M)"
fi
swap_used=$(free -m | awk '/Swap:/{print $3}'); if [ "${swap_used:-0}" -gt 1024 ]; then echo "SWAP IN USE: ${swap_used} MiB; waiting up to 4 h for it to be emptied."; n=0; while [ "$(free -m | awk '/Swap:/{print $3}')" -gt 1024 ]; do sleep 120; n=$((n+1)); [ $n -gt 120 ] && { echo "swap still in use after 4 h; giving up"; echo ALLDONE; exit 1; }; done; fi
bash scripts/fleet7-runs/run-loop351.sh $STAGE
# record the tree the binaries now match when the runner's gate built target/deferred in this run
if [ "$BUILT_TREES" != "$CUR_TREES" ] && [ target/deferred/release/n42 -nt $STAMP ] && [ target/native/release/n42 -nt $STAMP ]; then echo "$CUR_TREES" > $MARK; fi
'''
atomic(D + 'launch-loop351.sh', l)
