#!/usr/bin/env python3
"""Off-CPU time by call stack, from `perf script --show-switch-events` output
(see scripts/fleet7-offcpu.sh), and the /proc wchan sampler that runs beside
the recording.

  perf script ... | fleet7-offcpu-fold.py <prefix>
      reads `context-switches` samples (the stack at a switch-out) and the
      PERF_RECORD_SWITCH OUT / IN records of each thread; a sample's off-CPU
      time is the thread's OUT to its next IN. Prints the stacks by time off
      the CPU (voluntary and preempted apart) and the leaf user frames by time,
      and writes <prefix>.offcpu.folded (`frame;frame;... microseconds`, the
      flame-graph format, root first).

  fleet7-offcpu-fold.py --wchan <pid> <tid,tid,...> <secs> <out.tsv>
      samples /proc/<pid>/task/<tid>/{stat,wchan} at ~1 kHz for <secs> and
      writes `state<TAB>wchan<TAB>samples` for the samples off the CPU.
"""
import collections
import os
import re
import sys
import time

HEADER = re.compile(r"^(?P<comm>.+?)\s+(?P<tid>\d+)\s+(?P<time>\d+\.\d+):\s+(?P<rest>.*)$")
SWITCH = re.compile(r"PERF_RECORD_SWITCH(?:_CPU_WIDE)?\s+(?P<dir>IN|OUT)(?P<preempt>\s+preempt)?")
FRAME = re.compile(r"^\s+[0-9a-f]+\s+(?P<sym>.+?)\s*$")
# Frames that say nothing about who blocked: the unwinder's and the pool's own.
DULL = ("[unknown]", "syscall", "__GI___", "__lll_", "futex_wait", "std::sys::pal::unix::futex",
        "std::sys::sync::", "core::ops::function", "rayon_core::", "std::panicking", "__rust_try",
        "std::thread::", "start_thread", "clone3", "__clone", "std::rt::", "core::panic")


def short(sym):
    sym = re.sub(r"\+0x[0-9a-f]+$", "", sym)
    sym = re.sub(r"::h[0-9a-f]{16}$", "", sym)
    return sym.replace(";", ":")


def wchan(pid, tids, secs, out):
    tids = [t for t in tids.split(",") if t]
    counts = collections.Counter()
    end = time.monotonic() + float(secs)
    while time.monotonic() < end:
        for tid in tids:
            base = f"/proc/{pid}/task/{tid}"
            try:
                with open(f"{base}/stat") as f:
                    stat = f.read()
                state = stat[stat.rindex(")") + 2]
                if state == "R":
                    continue
                with open(f"{base}/wchan") as f:
                    chan = f.read().strip() or "0"
            except (OSError, ValueError):
                continue
            counts[(state, chan)] += 1
        time.sleep(0.001)
    with open(out, "w") as f:
        for (state, chan), n in counts.most_common():
            f.write(f"{state}\t{chan}\t{n}\n")


def fold(prefix, lines):
    pending = {}  # tid -> stack of the last switch-out sample
    out_at = {}  # tid -> (time, preempt, stack)
    by_stack = collections.defaultdict(lambda: [0, 0.0, 0, 0.0])  # vol count, vol s, preempt count, preempt s
    stack = None
    tid = None
    samples = switches = 0
    for line in lines:
        if stack is not None:
            m = FRAME.match(line)
            if m and line.startswith(("\t", " ")):
                stack.append(short(m.group("sym")))
                continue
            pending[tid] = stack
            stack = None
        m = HEADER.match(line)
        if not m:
            continue
        tid, t, rest = int(m.group("tid")), float(m.group("time")), m.group("rest")
        s = SWITCH.search(rest)
        if s:
            switches += 1
            if s.group("dir") == "OUT":
                out_at[tid] = (t, bool(s.group("preempt")), pending.pop(tid, None))
            else:
                was = out_at.pop(tid, None)
                if was and was[2] is not None:
                    off = t - was[0]
                    key = ";".join(reversed([f for f in was[2] if f]))
                    entry = by_stack[key]
                    if was[1]:
                        entry[2] += 1
                        entry[3] += off
                    else:
                        entry[0] += 1
                        entry[1] += off
            continue
        if "context-switches" in rest:
            samples += 1
            stack = []
    if stack is not None:
        pending[tid] = stack
    total = sum(v[1] + v[3] for v in by_stack.values())
    vol = sum(v[1] for v in by_stack.values())
    print(f"samples {samples}, switch records {switches}, stacks {len(by_stack)}, "
          f"off-CPU {total * 1e3:.1f} ms ({vol * 1e3:.1f} voluntary, {(total - vol) * 1e3:.1f} preempted)")
    if total <= 0:
        return
    with open(f"{prefix}.offcpu.folded", "w") as f:
        for key, v in by_stack.items():
            us = int((v[1] + v[3]) * 1e6)
            if us > 0:
                f.write(f"{key or '[no frames]'} {us}\n")
    # The leaf-most frames that name something, four deep: the blocking site.
    by_site = collections.defaultdict(lambda: [0, 0.0])
    for key, v in by_stack.items():
        frames = [fr for fr in reversed(key.split(";")) if fr and not fr.startswith(DULL)]
        site = " <- ".join(frames[:4]) or "[no named frame]"
        by_site[site][0] += v[0] + v[2]
        by_site[site][1] += v[1] + v[3]
    print("by blocking site (leaf-most named frames; share of off-CPU time, switches, mean ms):")
    for site, (n, s) in sorted(by_site.items(), key=lambda kv: -kv[1][1])[:20]:
        print(f"  {100 * s / total:5.1f}%  {n:7d}  {1e3 * s / max(n, 1):7.3f}  {site[:300]}")
    print(f"folded stacks: {prefix}.offcpu.folded (flamegraph.pl --countname=us)")


def main():
    if len(sys.argv) == 6 and sys.argv[1] == "--wchan":
        wchan(*sys.argv[2:])
        return
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    fold(sys.argv[1], sys.stdin)


if __name__ == "__main__":
    main()
