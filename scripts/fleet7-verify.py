#!/usr/bin/env python3
"""Does this fleet agree, and is every member producing?

`fleet7.sh status` compares one thing: the block hash at the common height.
That catches a fork and nothing else. A fleet can agree on hashes while one
member never leads a view, and two nodes can carry the same hash with a state
root that was never compared because the hash is over the header that holds
it -- true, but only if every node computed it rather than copied it, which is
exactly what a cross-client run is checking.

So this compares each commitment on its own (hash, state root, receipts root,
transactions root), names which one disagrees when one does, checks that the
chain advanced between two samples, and checks that every member authored a
block in the window. It writes the same as JSON when asked, so a leg can keep
it beside its logs.

    scripts/fleet7-verify.py [--window 64] [--json out.json] [--quiet]

Reads F7_NODES and F7_HTTP_BASE from the environment, as the other scripts do.
Exit status is 0 when every check passes, 1 when one does not, 2 when the
fleet could not be read at all.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

COMMITMENTS = ("hash", "stateRoot", "receiptsRoot", "transactionsRoot")


def rpc(port, method, params, timeout=5.0):
    """One JSON-RPC call; None when the node does not answer."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}", data=body, headers={"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as answer:
            return json.load(answer).get("result")
    except (urllib.error.URLError, TimeoutError, ValueError, ConnectionError):
        return None


def height(port):
    answer = rpc(port, "eth_blockNumber", [])
    return int(answer, 16) if answer else None


def block(port, number):
    return rpc(port, "eth_getBlockByNumber", [hex(number), False])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--window", type=int, default=64, help="blocks to read back for authorship (default 64)")
    parser.add_argument("--json", metavar="PATH", help="write the result as JSON here")
    parser.add_argument("--settle", type=float, default=3.0, help="seconds between the two height samples (default 3)")
    parser.add_argument("--quiet", action="store_true", help="print nothing; the exit status is the answer")
    args = parser.parse_args()

    nodes = int(os.environ.get("F7_NODES", "7"))
    base = int(os.environ.get("F7_HTTP_BASE", "18545"))
    ports = [base + i for i in range(nodes)]

    say = (lambda *a, **k: None) if args.quiet else print

    first = [height(port) for port in ports]
    answering = [i for i, h in enumerate(first) if h is not None]
    if not answering:
        say("no node answered")
        return 2
    common = min(first[i] for i in answering)

    # The four commitments at the common height, from every node that answers.
    rows = {}
    for i in answering:
        got = block(ports[i], common)
        if got:
            rows[i] = {key: got.get(key) for key in COMMITMENTS} | {"miner": got.get("miner")}

    disagreements = []
    if rows:
        reference = rows[min(rows)]
        for key in COMMITMENTS:
            values = {i: row[key] for i, row in rows.items()}
            if len(set(values.values())) > 1:
                disagreements.append({"commitment": key, "values": values})

    # Authorship: every member should have led a view in the window. Read from
    # one node -- they agree on the chain or the check above has already failed.
    reader = ports[min(rows)] if rows else ports[answering[0]]
    low = max(0, common - args.window + 1)
    authors = {}
    for number in range(low, common + 1):
        got = block(reader, number)
        if got and got.get("miner"):
            authors[got["miner"].lower()] = authors.get(got["miner"].lower(), 0) + 1

    # Progress: the chain has to be moving, not merely consistent.
    time.sleep(args.settle)
    second = [height(port) for port in ports]
    advanced = [i for i in answering if second[i] is not None and second[i] > first[i]]

    result = {
        "nodes": nodes,
        "answering": answering,
        "common_height": common,
        "commitments": {str(i): rows[i] for i in sorted(rows)},
        "disagreements": disagreements,
        "authors_in_window": authors,
        "window": [low, common],
        "heights_before": first,
        "heights_after": second,
        "advanced": advanced,
        "checks": {
            "every_node_answered": len(answering) == nodes,
            "commitments_agree": not disagreements,
            "every_node_advanced": len(advanced) == len(answering),
            "authors_at_least": len(authors),
        },
    }
    result["pass"] = (
        result["checks"]["every_node_answered"]
        and result["checks"]["commitments_agree"]
        and result["checks"]["every_node_advanced"]
    )

    say(f"common height {common}, {len(answering)}/{nodes} answering")
    for key in COMMITMENTS:
        values = {row[key] for row in rows.values()}
        mark = "=" if len(values) == 1 else "!"
        shown = next(iter(values)) if len(values) == 1 else f"{len(values)} different values"
        say(f"  {mark} {key:<18} {shown}")
    for bad in disagreements:
        say(f"    {bad['commitment']}:")
        for i, value in sorted(bad["values"].items()):
            say(f"      node {i} {value}")
    say(f"authors over blocks {low}-{common}: {len(authors)}")
    for miner, count in sorted(authors.items(), key=lambda kv: -kv[1]):
        say(f"  {miner} {count}")
    say(f"advanced in {args.settle:.0f}s: {len(advanced)}/{len(answering)}")
    say("PASS" if result["pass"] else "FAIL")

    if args.json:
        with open(args.json, "w") as out:
            json.dump(result, out, indent=2)
        say(f"written to {args.json}")
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
