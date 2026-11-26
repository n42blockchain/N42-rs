#!/usr/bin/env python3
"""The catch-up bench's report (scripts/catchup-bench.sh report <leg>).

  catchup-report.py <blocks.tsv> <leg dir>

blocks.tsv: number, txs, gasUsed, size (bytes), timestamp, as `produce` wrote
it. The leg dir holds heights.tsv (the sampler's), leg.txt, box.txt, v3.log.
Prints the whole pull's rate, the CPU each member process spent over it, the
rate per block-size class (5 s windows classed by their mean txs per block)
and the validator's `catch-up timing` lines.
"""
import os
import re
import sys

blocks = {}
for line in open(sys.argv[1]):
    r = list(map(int, line.split()))
    blocks[r[0]] = r
d = sys.argv[2]
raw = [l.split() for l in open(os.path.join(d, "heights.tsv"))]
hs = [(float(r[0]), int(r[1])) for r in raw]
cpu = [list(map(int, r[2:])) for r in raw]
tck = os.sysconf("SC_CLK_TCK")


def agg(lo, hi):
    rows = [blocks[n] for n in range(lo, hi + 1) if n in blocks]
    return len(rows), sum(r[1] for r in rows), sum(r[3] for r in rows), sum(r[2] for r in rows)


print(f"== leg {os.path.basename(d)} ==")
for name in ("leg.txt", "box.txt"):
    p = os.path.join(d, name)
    if os.path.exists(p):
        print(open(p).read().strip())
i0 = next((i for i, (_, h) in enumerate(hs) if h > 0), None)
if i0 is None:
    print("nothing imported")
    sys.exit()
# The pull starts at the last sample still at 0 (at most one step early).
s0 = max(i0 - 1, 0)
start = hs[s0][0]
end_t, end_h = hs[-1]
w = end_t - start
n, tx, by, gas = agg(1, end_h)
print(f"imported 1..{end_h} in {w:.1f} s: {n / w:.1f} blocks/s, {tx / w:,.0f} tx/s, "
      f"{by / w / 1e6:.2f} MB/s, {gas / w / 1e6:.0f} Mgas/s ({tx:,} txs, {by / 1e6:.1f} MB)")
names = ["el3", "val3", "el0", "val0", "el1", "val1"]
print("cpu, cores over the pull: " + " ".join(
    f"{nm} {(cpu[-1][k] - cpu[s0][k]) / tck / w:.2f}" for k, nm in enumerate(names) if k < len(cpu[-1])))
seg = []
i = s0
while i < len(hs) - 1:
    j = i + 1
    while j < len(hs) - 1 and hs[j][0] - hs[i][0] < 5.0:
        j += 1
    (ta, ha), (tb, hb) = hs[i], hs[j]
    if hb > ha:
        k, t, b, _ = agg(ha + 1, hb)
        if k:
            seg.append((t / k, k / (tb - ta), t / (tb - ta), b / (tb - ta) / 1e6))
    i = j
classes = [(0, 50, "near-empty (<50 tx)"), (50, 2000, "small (50-2k)"), (2000, 8000, "medium (2k-8k)"),
           (8000, 16000, "large (8k-16k)"), (16000, 10**9, "full-ish (>=16k)")]
for lo, hi, label in classes:
    s = [x for x in seg if lo <= x[0] < hi]
    if s:
        k = len(s)
        print(f"  {label:<20} windows {k:3d}: {sum(x[1] for x in s) / k:7.1f} blocks/s "
              f"{sum(x[2] for x in s) / k:10,.0f} tx/s {sum(x[3] for x in s) / k:7.2f} MB/s")
v = open(os.path.join(d, "v3.log"), errors="replace").read()
for m in re.finditer(r"catch-up timing.*", v):
    print("  " + re.sub(r"\x1b\[[0-9;]*m", "", m.group(0))[:400])
