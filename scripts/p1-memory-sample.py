#!/usr/bin/env python3
# Memory sampler for profile-1 members (docs/P1_MEMORY.md).
#
#   p1-memory-sample.py sample <bin dir> <run dir> <out.tsv> <seconds> <interval s> [metrics port per member, "i:port,.."]
#   p1-memory-sample.py summary <out.tsv> [skip seconds]
#
# `sample` finds every `n42 node` / `h2_validator` process of <run dir> (the
# processes scripts/profile1-round.sh starts from <bin dir>) and records per
# process, every <interval>: VmRSS, VmHWM, RssAnon, RssFile, RssShmem, threads,
# and, for an execution layer started with --metrics, jemalloc's
# allocated/active/resident/retained/mapped/metadata. One row per process and
# sample, plus the box's 1-minute load average and the member's height.
#
# `summary` prints, per member and role, the median and the maximum of each
# column over the samples after the first [skip] seconds.
import json
import os
import re
import statistics
import sys
import time
import urllib.request

STATUS_KEYS = ("VmRSS", "VmHWM", "RssAnon", "RssFile", "RssShmem", "Threads")
JE_KEYS = ("allocated", "active", "resident", "retained", "mapped", "metadata")
COLS = ["t", "load1", "member", "role", "pid", "height"] + [k for k in STATUS_KEYS] + ["je_" + k for k in JE_KEYS]


def procs(bin_dir, run_dir):
    pat = re.compile(
        "^" + re.escape(bin_dir) + r"/(n42 node|examples/h2_validator) --datadir " + re.escape(run_dir) + r"/m(\d+)/"
    )
    out = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cmd = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace")
        except OSError:
            continue
        m = pat.match(cmd)
        if m:
            out.append((int(m.group(2)), "el" if m.group(1) == "n42 node" else "val", int(pid), cmd))
    return sorted(out)


def status(pid):
    vals = {}
    try:
        for ln in open(f"/proc/{pid}/status"):
            k, _, v = ln.partition(":")
            if k in STATUS_KEYS:
                vals[k] = int(v.split()[0])  # kB, or a count for Threads
    except OSError:
        return None
    return vals


def jemalloc(port):
    try:
        body = urllib.request.urlopen(f"http://127.0.0.1:{port}", timeout=3).read().decode()
    except Exception:
        return {}
    vals = {}
    for ln in body.splitlines():
        m = re.match(r"^\w*jemalloc_(\w+)\s+([0-9.e+]+)", ln)
        if m and m.group(1) in JE_KEYS:
            vals[m.group(1)] = int(float(m.group(2)) / 1024)  # kB
    return vals


def height(port):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}).encode(),
        {"content-type": "application/json"},
    )
    try:
        return int(json.load(urllib.request.urlopen(req, timeout=3))["result"], 16)
    except Exception:
        return -1


def http_port(cmd):
    m = re.search(r"--http\.port (\d+)", cmd)
    return int(m.group(1)) if m else None


def sample(bin_dir, run_dir, out, seconds, interval, metrics):
    ports = {}
    for item in filter(None, metrics.split(",")):
        i, p = item.split(":")
        ports[int(i)] = int(p)
    end = time.time() + seconds
    t0 = time.time()
    new = not os.path.exists(out)
    with open(out, "a") as f:
        if new:
            f.write("\t".join(COLS) + "\n")
        while time.time() < end:
            load1 = open("/proc/loadavg").read().split()[0]
            heights = {}
            for member, role, pid, cmd in procs(bin_dir, run_dir):
                st = status(pid)
                if st is None:
                    continue
                je = {}
                if role == "el":
                    je = jemalloc(ports[member]) if member in ports else {}
                    hp = http_port(cmd)
                    heights[member] = height(hp) if hp else -1
                row = [f"{time.time() - t0:.1f}", load1, str(member), role, str(pid), str(heights.get(member, -1))]
                row += [str(st.get(k, -1)) for k in STATUS_KEYS]
                row += [str(je.get(k, -1)) for k in JE_KEYS]
                f.write("\t".join(row) + "\n")
            f.flush()
            time.sleep(interval)


def summary(path, skip):
    rows = [ln.rstrip("\n").split("\t") for ln in open(path)]
    head, rows = rows[0], rows[1:]
    idx = {k: i for i, k in enumerate(head)}
    groups = {}
    for r in rows:
        if float(r[idx["t"]]) < skip:
            continue
        groups.setdefault((int(r[idx["member"]]), r[idx["role"]]), []).append(r)
    show = ["VmRSS", "VmHWM", "RssAnon", "RssFile", "Threads", "je_allocated", "je_active", "je_resident", "je_retained"]
    print("member role  n    " + "  ".join(f"{c:>17}" for c in show) + "  load1(med/max)  height")
    for (m, role), rs in sorted(groups.items()):
        cells = []
        for c in show:
            vs = [int(r[idx[c]]) for r in rs if int(r[idx[c]]) >= 0]
            if not vs:
                cells.append(f"{'-':>17}")
            elif c == "Threads":
                cells.append(f"{statistics.median(vs):>8.0f}/{max(vs):<8d}")
            else:  # MiB, median/max
                cells.append(f"{statistics.median(vs) / 1024:>8.0f}/{max(vs) / 1024:<8.0f}")
        loads = [float(r[idx["load1"]]) for r in rs]
        hs = [int(r[idx["height"]]) for r in rs]
        print(f"{m:<6} {role:<5} {len(rs):<4} " + "  ".join(cells)
              + f"  {statistics.median(loads):.1f}/{max(loads):.1f}  {min(hs)}..{max(hs)}")
    print("(MiB median/max; Threads median/max)")


if __name__ == "__main__":
    if sys.argv[1] == "sample":
        sample(sys.argv[2], sys.argv[3], sys.argv[4], float(sys.argv[5]), float(sys.argv[6]),
               sys.argv[7] if len(sys.argv) > 7 else "")
    elif sys.argv[1] == "summary":
        summary(sys.argv[2], float(sys.argv[3]) if len(sys.argv) > 3 else 0)
    else:
        sys.exit(__doc__ or "usage: sample | summary")
