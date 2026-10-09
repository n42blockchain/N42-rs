#!/usr/bin/env python3
"""Build a bounded, unlabelled review queue from real N42 log snapshots."""

import argparse
import hashlib
import json
import random
from pathlib import Path

from decision_shadow import SOURCES, collect_lines

ABNORMAL_WORDS = ("error", "fail", "panic", "timeout", "stalled", "mismatch", "regression", "unavailable", "warning", "warn")


def sample_lines(lines, source, prefix, per_bucket):
    if per_bucket < 1:
        raise ValueError("per-bucket must be positive")
    rng = random.Random(42)
    samples = {"normal": [], "abnormal": []}
    counts = {"normal": 0, "abnormal": 0}
    for record in collect_lines(lines, source, prefix, 0):
        bucket = "abnormal" if any(word in record["text"].lower() for word in ABNORMAL_WORDS) else "normal"
        record["candidate_bucket"] = bucket
        counts[bucket] += 1
        choices = samples[bucket]
        if len(choices) < per_bucket:
            choices.append(record)
        else:
            index = rng.randrange(counts[bucket])
            if index < per_bucket:
                choices[index] = record
    return sorted(samples["normal"] + samples["abnormal"], key=lambda item: int(item["id"].rsplit("-", 1)[1]))


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="+", help="SOURCE:PATH pairs")
    parser.add_argument("--per-bucket", type=int, default=100)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--label-template", type=Path, help="new blank adjudication JSONL")
    args = parser.parse_args(argv)
    if args.output.exists() or args.manifest.exists() or (args.label_template and args.label_template.exists()) or args.per_bucket < 1:
        parser.error("outputs must be new and per-bucket positive")
    events = []
    inputs = []
    for spec in args.input:
        source, separator, name = spec.partition(":")
        if not separator or source not in SOURCES or not name:
            parser.error("each input must be SOURCE:PATH")
        path = Path(name)
        prefix = source + "-" + hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:12]
        with path.open(encoding="utf-8", errors="replace") as stream:
            sampled = sample_lines(stream, source, prefix, args.per_bucket)
        events.extend(sampled)
        inputs.append({"source": source, "path": str(path.resolve()), "sha256": file_sha256(path),
                       "bytes": path.stat().st_size, "sampled": len(sampled)})
    with args.output.open("x", encoding="utf-8") as out:
        for event in events:
            out.write(json.dumps(event, ensure_ascii=False) + "\n")
    with args.manifest.open("x", encoding="utf-8") as out:
        out.write(json.dumps({"sampling": "deterministic reservoir, seed 42, normal/abnormal keyword buckets",
                              "per_bucket_per_input": args.per_bucket, "events": len(events), "inputs": inputs}, indent=2) + "\n")
    if args.label_template:
        with args.label_template.open("x", encoding="utf-8") as out:
            for event in events:
                out.write(json.dumps({"id": event["id"], "truth": None,
                                      "need_escalation": None, "incident_id": None}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
