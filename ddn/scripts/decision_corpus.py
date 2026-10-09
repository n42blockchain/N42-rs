#!/usr/bin/env python3
"""Join blind human adjudications with collected N42 System-1 events."""

import argparse
import json
from pathlib import Path

from decision_benchmark import validate_corpus


def join_labels(events, labels):
    events = list(events)
    by_id = {}
    for item in labels:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or item["id"] in by_id:
            raise ValueError("invalid or duplicate adjudication id")
        if set(item) != {"id", "truth", "need_escalation", "incident_id"}:
            raise ValueError("adjudication fields must match schema")
        by_id[item["id"]] = item
    if set(by_id) != {event.get("id") for event in events}:
        raise ValueError("adjudication set differs from events")
    corpus = []
    for event in events:
        if any(key in event for key in ("truth", "need_escalation", "incident_id")):
            raise ValueError("source events must not carry adjudicated labels")
        corpus.append({**event, **{key: value for key, value in by_id[event["id"]].items() if key != "id"}})
    return validate_corpus(corpus)


def read_jsonl(path):
    with path.open(encoding="utf-8") as source:
        for line in source:
            if line.strip():
                yield json.loads(line)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path)
    parser.add_argument("labels", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    corpus = join_labels(read_jsonl(args.events), read_jsonl(args.labels))
    with args.output.open("x", encoding="utf-8") as out:
        for row in corpus:
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
