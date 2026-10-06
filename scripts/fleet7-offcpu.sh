#!/usr/bin/env bash
# An off-CPU profile of the leader's build pool: where the `n42-build-*`
# threads block, by call stack, and for how long.
#
#   scripts/fleet7-offcpu.sh [options] <output prefix>     record (during a leg)
#   scripts/fleet7-offcpu.sh --report <output prefix>      read it (after the leg)
#
# Options (record):
#   --dry-run       print what would run (pid, thread ids, commands) and exit
#   --node <i>      the execution layer to profile (default 0; under E=1 the
#                   one layer every validator key uses)
#   --pid <pid>     profile this process instead of finding node <i>'s
#   --secs <s>      how long to record (default 10)
#   --delay <s>     sleep this long first (to land in window 1; default 0)
#   --every <n>     record every n-th context switch (default 1)
#   --stack <bytes> user stack copied a sample for DWARF unwinding (default
#                   16384; a release build keeps no frame pointers)
#   --threads <re>  thread names to profile (default '^n42-build-')
#   --no-wchan      do not sample /proc/<tid>/wchan beside the recording
#
# Why this and not the sched tracepoints: on this host
# /proc/sys/kernel/perf_event_paranoid is 1 and /sys/kernel/tracing is root's
# (mode 0700), so `perf record -e sched:sched_switch`, `perf sched` and
# `perf record --off-cpu` (BPF) all need root. What needs none for one's own
# process: the `context-switches` software event, sampled at every switch-out
# with the thread's call stack, plus `--switch-events` (PERF_RECORD_SWITCH: a
# timestamped OUT, flagged `preempt` when involuntary, and IN, for each
# monitored thread). A sample's off-CPU time is its OUT to the thread's next IN;
# the report sums that by stack. Kernel frames stay unnamed without root
# (kptr_restrict 1, /proc/kallsyms hidden): the user frames name the lock or
# the load that blocked (`std::sync::...::lock_contended` under
# `OutputShards::enter_live`, `RwLock::read_contended` under
# `SharedOffsetIndex::read`, a fault at `EntryFileView::record`), and the
# wchan sampler names the kernel side (`futex_do_wait` on this kernel for a lock,
# `folio_wait_bit*` / `filemap_fault` for a file read, `rwsem_down_*` for
# mmap_lock) -- /proc/<tid>/wchan is readable by the owner, /proc/<tid>/stack
# is not. With root, the same answer with kernel names:
#   sudo perf record -e sched:sched_switch -e sched:sched_wakeup -g -t <tids> -- sleep 10
#   sudo perf sched timehist -i perf.data -V --state
#
# The binary has to carry symbols: build the fleet with the `profiling`
# profile and point F7_BIN at it (as `fleet7-profile.sh` says):
#   CARGO_TARGET_DIR=... cargo build --profile profiling -p n42 -p n42-h2-node --bins --examples
#   F7_BIN=target/profiling scripts/fleet7-bench.sh ...
# The recording perturbs the node (a 16 KB stack copy at every switch, ~4,000
# switches a second on the build pool under E=1): take it in one window of a
# dedicated leg and do not compare that window's rate with an unprofiled one.
# Reading it back (`--report`) is slow (DWARF unwinding against a ~2 GB
# binary): do it after the leg, never while one runs.

set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if [[ ${1:-} == --report ]]; then
  prefix=${2:?output prefix}
  [[ -r $prefix.data ]] || { echo "no recording at $prefix.data" >&2; exit 1; }
  perf script -i "$prefix.data" --no-inline --show-switch-events -F comm,tid,time,event,ip,sym 2>/dev/null |
    python3 "$HERE/fleet7-offcpu-fold.py" "$prefix"
  if [[ -r $prefix.wchan.tsv ]]; then
    echo "wchan samples (thread state, kernel wait channel; off-CPU only):"
    sort -t$'\t' -k3,3nr "$prefix.wchan.tsv" | head -15 | sed 's/^/  /'
  fi
  exit 0
fi

DRY=0 NODE=0 PID='' SECS=10 DELAY=0 EVERY=1 STACK=16384 THREADS='^n42-build-' WCHAN=1
while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run) DRY=1; shift;;
    --node) NODE=${2:?}; shift 2;;
    --pid) PID=${2:?}; shift 2;;
    --secs) SECS=${2:?}; shift 2;;
    --delay) DELAY=${2:?}; shift 2;;
    --every) EVERY=${2:?}; shift 2;;
    --stack) STACK=${2:?}; shift 2;;
    --threads) THREADS=${2:?}; shift 2;;
    --no-wchan) WCHAN=0; shift;;
    -*) echo "unknown option $1" >&2; exit 2;;
    *) break;;
  esac
done
PREFIX=${1:?output prefix}

if [[ -z $PID ]]; then
  # shellcheck source=/dev/null
  source "$HERE/fleet7-env.sh"
  PID=$(f7_pid "$NODE" el) || PID=''
fi
TIDS=''
if [[ -n $PID && -d /proc/$PID/task ]]; then
  for task in /proc/"$PID"/task/*; do
    name=$(cat "$task/comm" 2>/dev/null) || continue
    [[ $name =~ $THREADS ]] && TIDS+="${TIDS:+,}${task##*/}"
  done
fi

perf_cmd=(perf record -e context-switches -c "$EVERY" --switch-events --call-graph "dwarf,$STACK"
  -t "${TIDS:-<tids>}" -o "$PREFIX.data" -- sleep "$SECS")
wchan_cmd=(python3 "$HERE/fleet7-offcpu-fold.py" --wchan "${PID:-<pid>}" "${TIDS:-<tids>}" "$SECS" "$PREFIX.wchan.tsv")

if [[ $DRY == 1 ]]; then
  echo "dry run      : nothing is recorded"
  echo "process      : ${PID:-<not running: no execution layer pid for node $NODE>}"
  echo "threads      : $(tr ',' '\n' <<< "${TIDS:-}" | grep -c . || true) matching '$THREADS' (${TIDS:-<none>})"
  echo "paranoid     : $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null) (context-switches and switch events need <= 1 for one's own process)"
  echo "delay        : sleep $DELAY"
  echo "record       : ${perf_cmd[*]}"
  [[ $WCHAN == 1 ]] && echo "beside it    : ${wchan_cmd[*]}"
  echo "afterwards   : $0 --report $PREFIX"
  exit 0
fi

[[ -n $PID ]] || { echo "node $NODE's execution layer is not running (and no --pid)" >&2; exit 1; }
[[ -n $TIDS ]] || { echo "no thread of $PID matches '$THREADS'" >&2; exit 1; }
exe=$(readlink "/proc/$PID/exe" 2>/dev/null || true)
if [[ -n $exe ]] && ! file -L "$exe" 2>/dev/null | grep -q "with debug_info\|not stripped"; then
  echo "warning: $exe has no symbols; the stacks will name nothing (build --profile profiling)." >&2
fi
mkdir -p "$(dirname "$PREFIX")"
sleep "$DELAY"
wpid=''
if [[ $WCHAN == 1 ]]; then
  "${wchan_cmd[@]}" & wpid=$!
fi
"${perf_cmd[@]}" 2> "$PREFIX.perf.err" || {
  echo "perf record failed (see $PREFIX.perf.err); perf_event_paranoid is $(cat /proc/sys/kernel/perf_event_paranoid)" >&2
  exit 1
}
[[ -n $wpid ]] && wait "$wpid" || true
echo "off-CPU      : pid $PID, $(tr ',' '\n' <<< "$TIDS" | wc -l) threads, ${SECS}s to $PREFIX.data ($(du -h "$PREFIX.data" | cut -f1))"
echo "             : read it after the leg with '$0 --report $PREFIX'"
