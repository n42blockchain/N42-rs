#!/bin/bash
# loop351 (200k, 7 keys on one layer, 50 ms pacing; derive351.py). usage: launch-loop351.sh <a|b>. Launch: setsid nohup bash target/fleet-runs/launch-loop351.sh a > target/fleet-runs/loop351a.out 2>&1 &
# Waits for the box, checks the tree, and runs the stage. No build and no test gate: crates/ and bin/ are unchanged since the built commit (f2794a821), so the binaries in target/native and target/deferred are current.
cd /data/n42-build/wt338
STAGE=${1:-a}; case $STAGE in a|b) ;; *) echo "usage: launch-loop351.sh <a|b>"; exit 2;; esac
BUILT=f2794a821
git diff --quiet $BUILT HEAD -- crates bin || { echo "crates/ or bin/ changed since $BUILT: the binaries are not current; nothing run"; echo ALLDONE; exit 1; }
if [ -n "$(git status --porcelain crates bin | grep -v pycache)" ]; then echo "uncommitted changes in crates/ or bin/; nothing run"; echo ALLDONE; exit 1; fi
n=0
while [ -n "$(find /data/blockchain/.box-claim-* -mmin -90 2>/dev/null)" ] || [ "$(pgrep -fc 'n42-[a-z0-9]+ --chai[n]')" != 0 ]; do sleep 60; n=$((n+1)); [ $n -gt 240 ] && { echo "gave up waiting after 4 h"; exit 1; }; done
grep -rq N42_LEADER_LAYERS crates/n42/engine-types/src || { echo "N42_LEADER_LAYERS is not in the tree; nothing run"; echo ALLDONE; exit 1; }
grep -rq N42_PARALLEL_BUILD_THREADS crates bin || { echo "N42_PARALLEL_BUILD_THREADS is not in the tree; nothing run"; echo ALLDONE; exit 1; }
grep -rq N42_IMPORT_ONCE bin/n42/src crates/n42 || { echo "N42_IMPORT_ONCE is not in the tree; nothing run"; echo ALLDONE; exit 1; }
for f in scripts/fleet7-runs/run-loop351.sh scripts/fleet7-runs/manykeys350.py scripts/fleet7-runs/valsample350.py scripts/fleet7-runs/gate340.py; do [ -r $f ] || { echo "$f is not in the tree; nothing run"; echo ALLDONE; exit 1; }; done
grep -q f7_fleet_cpus scripts/fleet7-env.sh || { echo "scripts/fleet7-env.sh lacks f7_fleet_cpus; nothing run"; echo ALLDONE; exit 1; }
[ -x target/native/release/n42 ] && [ -x target/deferred/release/n42 ] || { echo "binaries missing in target/native or target/deferred; nothing run"; echo ALLDONE; exit 1; }
grep -aq N42_IMPORT_ONCE target/native/release/n42 || { echo "the native n42 does not know N42_IMPORT_ONCE; no leg can run"; echo ALLDONE; exit 1; }
avail=$(df -BG /data | awk 'NR==2{gsub("G","",$4); print $4}'); [ "${avail:-0}" -ge 120 ] || { echo "/data has only ${avail}G free (the smallest leg needs 120G); nothing run"; echo ALLDONE; exit 1; }
echo "/data free ${avail}G at launch"
echo "tree at $(git rev-parse --short HEAD) ($(git log -1 --format=%s | cut -c1-80)); box free at $(date +%H:%M); no build"
swap_used=$(free -m | awk '/Swap:/{print $3}'); if [ "${swap_used:-0}" -gt 1024 ]; then echo "SWAP IN USE: ${swap_used} MiB; waiting up to 4 h for it to be emptied."; n=0; while [ "$(free -m | awk '/Swap:/{print $3}')" -gt 1024 ]; do sleep 120; n=$((n+1)); [ $n -gt 120 ] && { echo "swap still in use after 4 h; giving up"; echo ALLDONE; exit 1; }; done; fi
export LOOP351_GATE_TREES="$(git rev-parse HEAD:crates)-$(git rev-parse HEAD:bin)"
bash scripts/fleet7-runs/run-loop351.sh $STAGE
