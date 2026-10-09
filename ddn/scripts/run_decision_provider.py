#!/usr/bin/env python3
"""Run one System-1 provider on an identical labelled benchmark corpus."""

import argparse
import json
import os
import resource
import sys
import time
from pathlib import Path

from decision_benchmark import _read_jsonl, rule_predict, validate_corpus
from decision_providers import GliclassProvider, JevProvider, safe_prediction
from decision_shadow import redact


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", choices=("rules", "gliclass", "jev"))
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--model-dir", type=Path, help="pre-downloaded local GLiClass artifact")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--warmup", type=int, default=0)
    args = parser.parse_args(argv)
    if args.output.exists() or args.metadata.exists() or args.warmup < 0:
        parser.error("outputs must be new files and warmup nonnegative")
    if args.provider == "gliclass" and args.model_dir is None:
        parser.error("--model-dir is required for GLiClass")
    if args.provider == "jev" and not os.environ.get("TYPESAFE_API_KEY"):
        parser.error("TYPESAFE_API_KEY is required for Jev")
    corpus = validate_corpus(_read_jsonl(args.corpus))
    if args.provider == "rules":
        predict = rule_predict
        version = "rules-v1"
    elif args.provider == "gliclass":
        provider = GliclassProvider.from_local(args.model_dir)
        predict = provider.predict
        version = provider.model_version
    else:
        provider = JevProvider()
        predict = provider.predict
        version = "jev-1.13.0"
    for event in corpus[:args.warmup]:
        safe_prediction(predict, {**event, "text": redact(event["text"])})
    cpu_start = time.process_time_ns()
    wall_start = time.perf_counter_ns()
    failures = 0
    with args.output.open("x", encoding="utf-8") as out:
        for event in corpus:
            start = time.perf_counter_ns()
            prediction = safe_prediction(predict, {**event, "text": redact(event["text"])})
            if "error" in prediction:
                failures += 1
            prediction.update(id=event["id"], latency_ms=(time.perf_counter_ns() - start) / 1_000_000)
            out.write(json.dumps(prediction) + "\n")
    duration_ms = (time.perf_counter_ns() - wall_start) / 1_000_000
    cpu_seconds = (time.process_time_ns() - cpu_start) / 1_000_000_000
    maxrss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_ram_bytes = maxrss if sys.platform == "darwin" else maxrss * 1024
    metadata = {"provider": args.provider, "model_version": version, "events": len(corpus),
                "failures": failures, "warmup_events": min(args.warmup, len(corpus)),
                "duration_ms": duration_ms, "qps": len(corpus) * 1000 / duration_ms,
                "cpu_seconds": cpu_seconds, "peak_process_ram_bytes": peak_ram_bytes,
                "cost_usd": None}
    with args.metadata.open("x", encoding="utf-8") as out:
        out.write(json.dumps(metadata, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
