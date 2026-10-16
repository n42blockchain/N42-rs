#!/usr/bin/env python3 -I
"""Score a fleet7 bench leg by its transaction drain rate.

The replay set is finite (400M transactions), so the round total is a cap.
The fair score is: transactions delivered / (seal of the last non-empty block
- seal of the first full block), read from node0's "seal-first build phases".

  drainrate.py LOOPTAG_OR_DIR
  drainrate.py --all PREFIX
"""
import glob
import os
import re
import statistics
import sys

ROOT = "/data/blockchain/rust-fleet7-bench"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
FULL = 199000  # a full block carries 200,000 transactions


def leg_dir(arg):
    if os.path.isdir(arg):
        return arg
    return os.path.join(ROOT, arg if arg.startswith("bench-") else "bench-" + arg)


def blocks(d):
    out = []
    with open(os.path.join(d, "node0-el.log"), errors="replace") as fh:
        for line in fh:
            if "seal-first build phases" not in line:
                continue
            line = ANSI.sub("", line)
            tx = re.search(r" txs=(\d+)", line)
            ts = re.search(r" sealed_unix_us=(\d+)", line)
            if tx and ts:
                out.append((int(ts.group(1)) / 1e6, int(tx.group(1))))
    return out


def score(d):
    tag = os.path.basename(d.rstrip("/"))
    tag = tag[6:] if tag.startswith("bench-") else tag
    b = blocks(d)
    i0 = next((i for i, (_, n) in enumerate(b) if n >= FULL), None)
    if i0 is None:
        return None
    b = b[i0:]
    ln = max((i for i, (_, n) in enumerate(b) if n > 0), default=0)
    span = b[ln][0] - b[0][0]
    txs = sum(n for _, n in b[: ln + 1])
    full = [t for t, n in b if n >= FULL]
    gaps = [(y - x) * 1000 for x, y in zip(full, full[1:])]
    return dict(tag=tag, txs=txs, first=b[0][0], last=b[ln][0], span=span,
                rate=txs / span / 1e6 if span > 0 else 0.0,
                empty=len(b) - 1 - ln, blocks=len(b),
                mean=statistics.mean(gaps) if gaps else 0.0,
                med=statistics.median(gaps) if gaps else 0.0)


def line(r):
    return (f"drainrate {r['tag']}: txs={r['txs']} first_full={r['first']:.3f} "
            f"last_nonempty={r['last']:.3f} span_s={r['span']:.2f} "
            f"rate={r['rate']:.3f}M/s empty_tail_blocks={r['empty']} "
            f"blocks={r['blocks']} mean_gap_ms={r['mean']:.1f} "
            f"median_gap_ms={r['med']:.1f}")


def main(argv):
    if len(argv) == 3 and argv[1] == "--all":
        rs = []
        for d in sorted(glob.glob(os.path.join(ROOT, "bench-" + argv[2] + "*"))):
            try:
                r = score(d)
            except OSError:
                r = None
            if r:
                rs.append(r)
        for r in sorted(rs, key=lambda r: -r["rate"]):
            print(line(r))
        return 0
    if len(argv) != 2:
        print(__doc__)
        return 2
    r = score(leg_dir(argv[1]))
    if not r:
        print("drainrate: no full block found in " + argv[1])
        return 1
    print(line(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
