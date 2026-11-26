#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Blockscout-shaped JSON-RPC load against one node (docs/EXPLORER_RPC_PERF.md).

Reproduces the request shape of Blockscout's indexer fetchers with
ETHEREUM_JSONRPC_VARIANT=geth: JSON-RPC batches over keep-alive HTTP, a
fixed batch size and a fixed number of concurrent requests per fetcher.
Each fetcher runs as its own set of worker processes (so the client's JSON
decoding is never the bound), pulls work items from a shared counter and
reports per-method latency, items/s, blocks/s, bytes and errors. The node's
CPU (utime+stime from /proc) is sampled around the run when --pid is given.

  explorer-load.py --rpc URL prepare --from A --to B           # index the range once
  explorer-load.py --rpc URL run --from A --to B --fetchers blocks,receipts [--duration S]
  explorer-load.py --rpc URL dump --from A --to B --out FILE   # responses for a diff

Fetchers and their defaults (Blockscout's documented env defaults; see the
doc for the assumptions behind them):

  blocks          eth_getBlockByNumber(n, true)      batch 10   conc 10  (catch-up block fetcher)
  receipts        eth_getTransactionReceipt(h)       batch 250  conc 10  (receipts, per tx)
  block-receipts  eth_getBlockReceipts(n)            batch 10   conc 10  (receipts, per block)
  trace-tx        debug_traceTransaction(h, callTracer)  batch 10 conc 4 (internal txs, per tx)
  trace-block     debug_traceBlockByNumber(n, callTracer) batch 10 conc 4 (internal txs, by block)
  balances        eth_getBalance(addr, n)            batch 500  conc 4   (coin balances, historical)
  tokens          eth_call(balanceOf(holder), n)     batch 100  conc 10  (token balances, historical)
  code            eth_getCode(addr, n)               batch 50   conc 4   (contract code)
  realtime        eth_blockNumber + getBlockByNumber(latest, true) + receipts, every 1 s

Override any fetcher with --set fetcher.batch=N / fetcher.conc=N.
--rtt-ms R [--mbps M] adds a network hop to every request (sleep R ms plus
the response size at M Mbit/s, after the response arrives, inside the
measured latency): with Blockscout's fixed concurrency a fetcher's ceiling
is conc * batch / (rtt + transfer + service), so a run with and without the
hop tells a node-bound fetcher from a latency-bound one. Python stdlib only.
"""

import argparse
import http.client
import json
import multiprocessing as mp
import os
import statistics
import sys
import time
import urllib.parse

DEFAULTS = {
    "blocks": (10, 10),
    "receipts": (250, 10),
    "block-receipts": (10, 10),
    "trace-tx": (10, 4),
    "trace-block": (10, 4),
    "balances": (500, 4),
    "tokens": (100, 10),
    "code": (50, 4),
    "realtime": (1, 1),
}
CALL_TRACER = {"tracer": "callTracer", "timeout": "60s"}
BALANCE_OF = "0x70a08231"


class Rpc:
    """Keep-alive JSON-RPC over http.client (one connection per worker)."""

    def __init__(self, url, timeout=300):
        u = urllib.parse.urlparse(url)
        self.host, self.port, self.path = u.hostname, u.port or 80, u.path or "/"
        self.timeout = timeout
        self.conn = None

    def _connect(self):
        self.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def post(self, body):
        """Send raw bytes; returns (status, raw response bytes)."""
        for attempt in (0, 1):
            if self.conn is None:
                self._connect()
            try:
                self.conn.request("POST", self.path, body, {"content-type": "application/json"})
                r = self.conn.getresponse()
                return r.status, r.read()
            except (http.client.HTTPException, OSError):
                self.conn.close()
                self.conn = None
                if attempt:
                    raise
        raise RuntimeError("unreachable")

    def batch(self, calls, parse=True):
        """With parse=False an answer with no error and no null result is not
        decoded (its calls are counted as answered): the load generator then
        costs the bytes, not a JSON decode, so a fast node is not hidden
        behind the client."""
        body = json.dumps([{"jsonrpc": "2.0", "id": i, "method": m, "params": p}
                           for i, (m, p) in enumerate(calls)]).encode()
        status, raw = self.post(body)
        if status != 200:
            return status, raw, None
        if not parse and b'"error"' not in raw and b'"result":null' not in raw:
            return status, raw, [{}] * len(calls)
        out = json.loads(raw)
        if isinstance(out, dict):  # a batch-level error
            return status, raw, [out] * len(calls)
        out.sort(key=lambda x: x.get("id", 0))
        return status, raw, out

    def call(self, method, params):
        _, _, out = self.batch([(method, params)])
        if not out or "error" in out[0]:
            raise RuntimeError(f"{method}: {out}")
        return out[0]["result"]


# ---------------------------------------------------------------- index

def index_path(cache, a, b):
    return os.path.join(cache, f"index-{a}-{b}.jsonl")


def _prepare_worker(args):
    url, blocks = args
    rpc = Rpc(url)
    _, _, out = rpc.batch([("eth_getBlockByNumber", [hex(n), True]) for n in blocks])
    rows = []
    for n, r in zip(blocks, out):
        blk = r["result"]
        txs = blk["transactions"]
        addrs = {blk["miner"].lower()}
        for t in txs:
            addrs.add(t["from"].lower())
            if t.get("to"):
                addrs.add(t["to"].lower())
        rows.append({"n": n, "txs": [t["hash"] for t in txs], "addrs": sorted(addrs)})
    return rows


def load_index(cache, a, b):
    with open(index_path(cache, a, b)) as f:
        return [json.loads(line) for line in f]


def cmd_prepare(o):
    os.makedirs(o.cache, exist_ok=True)
    chunks = [list(range(s, min(s + 4, o.to + 1))) for s in range(o.frm, o.to + 1, 4)]
    with mp.Pool(16) as pool, open(index_path(o.cache, o.frm, o.to), "w") as f:
        ntx = 0
        for rows in pool.imap(_prepare_worker, [(o.rpc, c) for c in chunks]):
            for r in rows:
                ntx += len(r["txs"])
                f.write(json.dumps(r) + "\n")
    print(f"indexed blocks {o.frm}..{o.to}: {ntx} transactions -> {index_path(o.cache, o.frm, o.to)}")


# ---------------------------------------------------------------- work items

def work_items(fetcher, index, batch, opts):
    """A list of (calls, blocks_covered) per request."""
    items = []
    if fetcher in ("blocks", "trace-block", "block-receipts"):
        method = {"blocks": "eth_getBlockByNumber", "trace-block": "debug_traceBlockByNumber",
                  "block-receipts": "eth_getBlockReceipts"}[fetcher]
        for s in range(0, len(index), batch):
            rows = index[s:s + batch]
            calls = []
            for r in rows:
                if method == "eth_getBlockByNumber":
                    calls.append((method, [hex(r["n"]), True]))
                elif method == "debug_traceBlockByNumber":
                    calls.append((method, [hex(r["n"]), CALL_TRACER]))
                else:
                    calls.append((method, [hex(r["n"])]))
            items.append((calls, len(rows)))
        return items
    # Per-tx / per-address fetchers: flatten, then cut into batches; a batch
    # is credited with the fraction of blocks its items cover.
    flat = []
    for r in index:
        if fetcher == "receipts":
            units = [("eth_getTransactionReceipt", [h]) for h in r["txs"]]
        elif fetcher == "trace-tx":
            units = [("debug_traceTransaction", [h, CALL_TRACER]) for h in r["txs"]]
        elif fetcher == "balances":
            units = [("eth_getBalance", [a, hex(r["n"])]) for a in r["addrs"]]
        elif fetcher == "tokens":
            units = [("eth_call", [{"to": opts.token, "data": BALANCE_OF + "0" * 24 + a[2:]}, hex(r["n"])])
                     for a in r["addrs"]]
        elif fetcher == "code":
            units = [("eth_getCode", [a, hex(r["n"])]) for a in r["addrs"][: opts.code_per_block]]
        else:
            raise SystemExit(f"unknown fetcher {fetcher}")
        w = 1.0 / max(len(units), 1)
        flat.extend((u, w) for u in units)
        if not units:
            flat.append((None, 1.0))
    cur, credit = [], 0.0
    for u, w in flat:
        if u is not None:
            cur.append(u)
        credit += w
        if len(cur) >= batch:
            items.append((cur, credit))
            cur, credit = [], 0.0
    if cur or credit:
        items.append((cur, credit))
    return items


# ---------------------------------------------------------------- workers

def net_delay(o_rtt, o_mbps, nbytes):
    """The network hop a request would pay on a real link: one round trip plus
    the response's transfer time at the link rate (both 0 = loopback)."""
    d = o_rtt / 1e3
    if o_mbps:
        d += nbytes * 8 / (o_mbps * 1e6)
    if d > 0:
        time.sleep(d)


def worker(url, items, counter, deadline, q, max_items, rtt_ms=0.0, mbps=0.0):
    rpc = Rpc(url)
    stats = []  # (method, seconds, n_calls, bytes, n_errors, blocks, first_error)
    while time.time() < deadline:
        with counter.get_lock():
            i = counter.value
            counter.value += 1
        if i >= len(items) or (max_items and i >= max_items):
            break
        calls, blocks = items[i]
        if not calls:
            stats.append(("-", 0.0, 0, 0, 0, blocks, None))
            continue
        t0 = time.perf_counter()
        try:
            status, raw, out = rpc.batch(calls, parse=False)
            net_delay(rtt_ms, mbps, len(raw))
            dt = time.perf_counter() - t0
            if out is None:
                stats.append((calls[0][0], dt, len(calls), len(raw), len(calls), blocks,
                               f"HTTP {status}: {raw[:200]!r}"))
                continue
            errs = [r["error"] for r in out if "error" in r]
            nulls = sum(1 for r in out if "error" not in r and "result" in r and r["result"] is None)
            first = None
            if errs:
                first = json.dumps(errs[0])[:200]
            elif nulls:
                first = f"{nulls} null results"
            stats.append((calls[0][0], dt, len(calls), len(raw), len(errs) + nulls, blocks, first))
        except Exception as e:  # noqa: BLE001 - every failure is a data point
            stats.append((calls[0][0], time.perf_counter() - t0, len(calls), 0, len(calls), blocks,
                          f"{type(e).__name__}: {e}"[:200]))
    q.put(stats)


def realtime_worker(url, deadline, q, _interval=1.0):
    rpc = Rpc(url)
    stats = []
    while time.time() < deadline:
        t0 = time.perf_counter()
        head = int(rpc.call("eth_blockNumber", []), 16)
        status, raw, out = rpc.batch([("eth_getBlockByNumber", [hex(head), True])])
        txs = out[0]["result"]["transactions"] if out and out[0].get("result") else []
        if txs:
            rpc.batch([("eth_getTransactionReceipt", [t["hash"]]) for t in txs[:250]])
        stats.append(("realtime-cycle", time.perf_counter() - t0, 1, len(raw), 0, 1, None))
        time.sleep(max(0.0, _interval - (time.perf_counter() - t0)))
    q.put(stats)


def proc_cpu(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().rsplit(")", 1)[1].split()
        return (int(parts[11]) + int(parts[12])) / os.sysconf("SC_CLK_TCK")
    except OSError:
        return None


def pct(xs, p):
    if not xs:
        return 0.0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p / 100.0 * len(xs)))]


def parse_sets(sets):
    out = {}
    for s in sets or []:
        k, v = s.split("=", 1)
        f, field = k.split(".", 1)
        out.setdefault(f, {})[field] = int(v)
    return out


def cmd_run(o):
    index = load_index(o.cache, o.frm, o.to)
    nblocks = len(index)
    ntx = sum(len(r["txs"]) for r in index)
    sets = parse_sets(o.set)
    fetchers = o.fetchers.split(",")
    q = mp.Queue()
    procs, plan = [], {}
    deadline = time.time() + o.duration
    for f in fetchers:
        batch, conc = DEFAULTS[f]
        batch = sets.get(f, {}).get("batch", batch)
        conc = sets.get(f, {}).get("conc", conc)
        if f == "realtime":
            procs.append((f, mp.Process(target=realtime_worker, args=(o.rpc, deadline, q))))
            plan[f] = (1, 1, 0)
            continue
        items = work_items(f, index, batch, o)
        counter = mp.Value("l", 0)
        plan[f] = (batch, conc, len(items))
        for _ in range(conc):
            procs.append((f, mp.Process(target=worker, args=(o.rpc, items, counter, deadline, q, o.max_items,
                                                                    o.rtt_ms, o.mbps))))
    cpu0, t0 = (proc_cpu(o.pid) if o.pid else None), time.time()
    for _, p in procs:
        p.start()
    results = {}
    for f, _ in procs:
        results.setdefault(f, [])
    got = [q.get() for _ in procs]
    wall = time.time() - t0
    cpu1 = proc_cpu(o.pid) if o.pid else None
    for _, p in procs:
        p.join()
    # map results back: each worker's stats carry their method; group by fetcher via method
    by_method = {}
    for st in got:
        for s in st:
            by_method.setdefault(s[0], []).append(s)
    report = {"range": [o.frm, o.to], "blocks": nblocks, "txs": ntx, "wall_s": round(wall, 2),
              "fetchers": {}, "node_cpu_cores": None}
    if cpu0 is not None and cpu1 is not None:
        report["node_cpu_cores"] = round((cpu1 - cpu0) / wall, 2)
    print(f"range {o.frm}..{o.to} ({nblocks} blocks, {ntx} txs), wall {wall:.1f} s"
          + (f", node CPU {report['node_cpu_cores']} cores" if report["node_cpu_cores"] is not None else ""))
    print(f"{'fetcher':<15} {'method':<26} {'b x c':>9} {'reqs':>6} {'calls':>8} {'calls/s':>9} "
          f"{'blocks/s':>9} {'p50 ms':>8} {'p99 ms':>8} {'MB/s':>7} {'errs':>6}")
    method_of = {"blocks": "eth_getBlockByNumber", "receipts": "eth_getTransactionReceipt",
                 "block-receipts": "eth_getBlockReceipts", "trace-tx": "debug_traceTransaction",
                 "trace-block": "debug_traceBlockByNumber", "balances": "eth_getBalance",
                 "tokens": "eth_call", "code": "eth_getCode", "realtime": "realtime-cycle"}
    for f in fetchers:
        m = method_of[f]
        st = by_method.get(m, []) + (by_method.get("-", []) if len(fetchers) == 1 else [])
        lat = [s[1] for s in st if s[2]]
        calls = sum(s[2] for s in st)
        blocks = sum(s[5] for s in st)
        nbytes = sum(s[3] for s in st)
        errs = sum(s[4] for s in st)
        first = next((s[6] for s in st if s[6]), None)
        batch, conc, nitems = plan[f]
        row = {"method": m, "batch": batch, "conc": conc, "requests": len(lat), "calls": calls,
               "calls_per_s": round(calls / wall, 1), "blocks_per_s": round(blocks / wall, 2),
               "p50_ms": round(pct(lat, 50) * 1e3, 1), "p99_ms": round(pct(lat, 99) * 1e3, 1),
               "mean_ms": round(statistics.mean(lat) * 1e3, 1) if lat else 0.0,
               "mb_per_s": round(nbytes / wall / 1e6, 2), "errors": errs, "first_error": first,
               "done": f"{len(st)}/{nitems}"}
        report["fetchers"][f] = row
        print(f"{f:<15} {m:<26} {f'{batch}x{conc}':>9} {row['requests']:>6} {calls:>8} {row['calls_per_s']:>9} "
              f"{row['blocks_per_s']:>9} {row['p50_ms']:>8} {row['p99_ms']:>8} {row['mb_per_s']:>7} {errs:>6}")
        if first:
            print(f"    first error: {first}")
    if o.json:
        with open(o.json, "a") as fh:
            report["label"] = o.label
            report["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            fh.write(json.dumps(report) + "\n")


def cmd_dump(o):
    """Write one sample response per fetcher method (sorted keys) for a before/after diff."""
    index = load_index(o.cache, o.frm, o.to)
    rpc = Rpc(o.rpc)
    with open(o.out, "w") as fh:
        for f in ("blocks", "block-receipts", "receipts", "trace-block", "trace-tx", "balances", "tokens", "code"):
            for calls, _ in work_items(f, index[: o.sample_blocks], DEFAULTS[f][0], o)[:2]:
                if not calls:
                    continue
                _, _, out = rpc.batch(calls[: o.sample_calls])
                for c, r in zip(calls, out):
                    fh.write(json.dumps({"call": c, "response": r.get("result", r.get("error"))}, sort_keys=True) + "\n")
    print(f"wrote {o.out}")


def main():
    # fork: the workers inherit the work list instead of unpickling it each
    # (Python 3.14 defaults to forkserver, which made the client the bound).
    mp.set_start_method("fork")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--cache", default="/data/n42-build/explorer-rpc/cache")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("prepare", "run", "dump"):
        p = sub.add_parser(name)
        p.add_argument("--from", dest="frm", type=int, required=True)
        p.add_argument("--to", type=int, required=True)
        p.add_argument("--token", default="0x4242424242424242424242424242424242424242")
        p.add_argument("--code-per-block", type=int, default=20)
        if name == "run":
            p.add_argument("--fetchers", default="blocks")
            p.add_argument("--duration", type=float, default=60.0)
            p.add_argument("--set", action="append", help="fetcher.batch=N or fetcher.conc=N")
            p.add_argument("--pid", type=int, help="node pid, for its CPU")
            p.add_argument("--max-items", type=int, default=0)
            p.add_argument("--json", help="append the report as a JSON line here")
            p.add_argument("--label", default="")
            p.add_argument("--rtt-ms", type=float, default=0.0,
                           help="add one network round trip per request (the explorer on another host)")
            p.add_argument("--mbps", type=float, default=0.0,
                           help="and the response's transfer time at this link rate (0 = none)")
        if name == "dump":
            p.add_argument("--out", required=True)
            p.add_argument("--sample-blocks", type=int, default=3)
            p.add_argument("--sample-calls", type=int, default=5)
    o = ap.parse_args()
    {"prepare": cmd_prepare, "run": cmd_run, "dump": cmd_dump}[o.cmd](o)


if __name__ == "__main__":
    sys.exit(main())
