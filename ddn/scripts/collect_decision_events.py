#!/usr/bin/env python3
"""Read-only conversion of a node/CI/benchmark log snapshot to shadow JSONL."""

import argparse
import json
import time
from pathlib import Path

from decision_shadow import SOURCES, collect_lines


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--source", choices=SOURCES, required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    stamp = time.time_ns() // 1_000_000
    with args.input.open(encoding="utf-8", errors="replace") as stream, args.output.open("x", encoding="utf-8") as out:
        for record in collect_lines(stream, args.source, args.prefix, stamp):
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
