#!/bin/bash
# loop351 (200k, 7 keys on one layer, 50 ms pacing; derive351.py). usage: launch-loop351.sh <a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p>. Launch: setsid nohup bash target/fleet-runs/launch-loop351.sh f > target/fleet-runs/loop351f.out 2>&1 &
# Waits for the box, checks the tree, and runs the stage. When crates/ or bin/ changed since the last build, the launcher builds target/native (the legs' F7_BIN) after the box is free and the runner
# runs its own test gate, clippy and the target/deferred build (once: this launcher does not export LOOP351_GATE_TREES for a changed tree). Unchanged tree: no build, no tests.
cd /data/n42-build/wt338
STAGE=${1:-a}; case $STAGE in a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p) ;; *) echo "usage: launch-loop351.sh <a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p>"; exit 2;; esac
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
