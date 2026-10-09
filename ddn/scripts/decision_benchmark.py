#!/usr/bin/env python3
"""Eight-class N42 System-1 benchmark with strict corpus/prediction matching."""

import argparse
import json
import math
import statistics
import time
from pathlib import Path

from decision_shadow import SOURCES, redact

LABELS = ("NORMAL", "NETWORK", "CONSENSUS", "EXECUTION", "STORAGE", "CONFIGURATION", "PERFORMANCE", "UNKNOWN")
ESCALATION = ("YES", "NO")


def validate_corpus(events):
    rows = list(events)
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not 1 <= len(row["id"]) <= 128:
            raise ValueError("invalid event id")
        if row["id"] in seen:
            raise ValueError("duplicate event id")
        seen.add(row["id"])
        if row.get("source") not in SOURCES or not isinstance(row.get("text"), str) or not 1 <= len(row["text"].encode()) <= 8192:
            raise ValueError("invalid event source or text")
        if type(row.get("observed_at_ms")) is not int or row["observed_at_ms"] < 0:
            raise ValueError("invalid observation time")
        if row.get("truth") not in LABELS or row.get("need_escalation") not in ESCALATION:
            raise ValueError("missing or invalid adjudicated labels")
        if not isinstance(row.get("incident_id"), str) or not row["incident_id"]:
            raise ValueError("missing incident group")
    if not rows:
        raise ValueError("empty corpus")
    return rows


def rule_predict(event):
    text = event["text"].lower()
    patterns = (
        ("CONSENSUS", ("consensus", "finality", "quorum", "qc mismatch")),
        ("STORAGE", ("qmdb", "storage", "state root", "database")),
        ("NETWORK", ("peer", "p2p", "peerdas", "network", "rpc timeout")),
        ("EXECUTION", ("block-stm", "evm", "execution", "transaction conflict")),
        ("CONFIGURATION", ("config", "invalid flag", "missing env", "genesis mismatch")),
        ("PERFORMANCE", ("regression", "tps", "latency", "slow block")),
    )
    label = next((name for name, words in patterns if any(word in text for word in words)), None)
    if label is None:
        label = "UNKNOWN" if any(word in text for word in ("error", "failed", "panic", "timeout")) else "NORMAL"
    urgent = any(word in text for word in ("finality stalled", "qc mismatch", "state root mismatch", "data unavailable", "consensus halted"))
    escalation = "YES" if urgent or label == "UNKNOWN" else "NO"
    return {"label": label, "need_escalation": escalation, "model": "rules-v1"}


def _percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * fraction
    low = math.floor(pos)
    high = math.ceil(pos)
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)


def evaluate_predictions(corpus, predictions, duration_ms=None, cpu_seconds=None, peak_ram_bytes=None, cost_usd=None):
    rows = validate_corpus(corpus)
    by_id = {}
    for pred in predictions:
        if not isinstance(pred, dict) or not isinstance(pred.get("id"), str) or pred["id"] in by_id:
            raise ValueError("invalid or duplicate prediction id")
        if pred.get("label") not in LABELS or pred.get("need_escalation") not in ESCALATION:
            raise ValueError("invalid prediction labels")
        latency = pred.get("latency_ms")
        if type(latency) not in (int, float) or not math.isfinite(latency) or latency < 0:
            raise ValueError("invalid prediction latency")
        by_id[pred["id"]] = pred
    if set(by_id) != {row["id"] for row in rows}:
        raise ValueError("prediction set differs from corpus")
    latencies = [by_id[row["id"]]["latency_ms"] for row in rows]
    result = {"events": len(rows),
              "accuracy": sum(by_id[row["id"]]["label"] == row["truth"] for row in rows) / len(rows),
              "unknown_rate": sum(by_id[row["id"]]["label"] == "UNKNOWN" for row in rows) / len(rows),
              "escalation_rate": sum(by_id[row["id"]]["need_escalation"] == "YES" for row in rows) / len(rows),
              "escalation_accuracy": sum(by_id[row["id"]]["need_escalation"] == row["need_escalation"] for row in rows) / len(rows),
              "latency_ms": {"p50": _percentile(latencies, .5), "p95": _percentile(latencies, .95), "p99": _percentile(latencies, .99)},
              "qps": len(rows) * 1000 / duration_ms if duration_ms and duration_ms > 0 else None,
              "cpu_seconds": cpu_seconds, "peak_ram_bytes": peak_ram_bytes,
              "cost_per_million_usd": cost_usd * 1_000_000 / len(rows) if cost_usd is not None else None}
    result["recall"] = {}
    result["fpr"] = {}
    result["fnr"] = {}
    for label in LABELS:
        positive = [row for row in rows if row["truth"] == label]
        negative = [row for row in rows if row["truth"] != label]
        recall = sum(by_id[row["id"]]["label"] == label for row in positive) / len(positive) if positive else None
        result["recall"][label] = recall
        result["fnr"][label] = 1 - recall if recall is not None else None
        result["fpr"][label] = sum(by_id[row["id"]]["label"] == label for row in negative) / len(negative) if negative else None
    return result


def _read_jsonl(path):
    with path.open(encoding="utf-8") as source:
        for line in source:
            if line.strip():
                yield json.loads(line)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("rules", "score"))
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--predictions", type=Path)
    parser.add_argument("--metadata", type=Path, help="provider runner resource metadata")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    corpus = validate_corpus(_read_jsonl(args.corpus))
    if args.mode == "rules":
        with args.output.open("x", encoding="utf-8") as out:
            for event in corpus:
                start = time.monotonic_ns()
                decision = rule_predict({**event, "text": redact(event["text"])})
                decision.update(id=event["id"], latency_ms=(time.monotonic_ns() - start) / 1_000_000)
                out.write(json.dumps(decision) + "\n")
    else:
        if args.predictions is None:
            parser.error("--predictions is required for score")
        metadata = json.loads(args.metadata.read_text()) if args.metadata else {}
        if metadata and metadata.get("events") != len(corpus):
            raise ValueError("resource metadata event count differs from corpus")
        result = evaluate_predictions(
            corpus, _read_jsonl(args.predictions), duration_ms=metadata.get("duration_ms"),
            cpu_seconds=metadata.get("cpu_seconds"), peak_ram_bytes=metadata.get("peak_process_ram_bytes"),
            cost_usd=metadata.get("cost_usd"))
        result["provider_errors"] = metadata.get("failures")
        with args.output.open("x", encoding="utf-8") as out:
            out.write(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
