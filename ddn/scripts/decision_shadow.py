#!/usr/bin/env python3
"""Read-only N42 node/CI decision shadow runner; never executes a recommendation."""

import argparse
import json
import math
import os
import re
import statistics
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

MODEL = "jev-1.13.0"
HEALTH = ("HEALTHY", "DEGRADED", "CRITICAL")
DOMAINS = ("NETWORK", "CONSENSUS", "EXECUTION", "STORAGE", "UNKNOWN")
SOURCES = ("node", "ci", "rpc", "network", "benchmark", "configuration", "peerdas", "block_stm", "qmdb")
KEY_RE = re.compile(r"(?i)\b([a-z_]*(?:api[_-]?key|secret|token|password|private[_-]?key)[a-z_]*)\s*[=:]\s*\S+")
HEX_KEY_RE = re.compile(r"\b0x[0-9a-fA-F]{64}\b")


def redact(text):
    return HEX_KEY_RE.sub("[REDACTED]", KEY_RE.sub(lambda m: m.group(1) + "=[REDACTED]", text))


def validate_event(event):
    if not isinstance(event, dict) or not isinstance(event.get("id"), str) or not 1 <= len(event["id"]) <= 128:
        raise ValueError("invalid event id")
    if event.get("source") not in SOURCES:
        raise ValueError("unsupported event source")
    if not isinstance(event.get("text"), str) or not 1 <= len(event["text"].encode()) <= 8192:
        raise ValueError("invalid event text length")
    stamp = event.get("observed_at_ms")
    if type(stamp) is not int or stamp < 0:
        raise ValueError("invalid observation timestamp")
    if "truth" in event and event["truth"] not in HEALTH:
        raise ValueError("invalid labelled health")
    return event


def collect_lines(lines, source, prefix, observed_at_ms):
    """Convert a finite text-log snapshot into bounded, redacted shadow events."""
    if source not in SOURCES or not re.fullmatch(r"[A-Za-z0-9_-]{1,96}", prefix):
        raise ValueError("invalid source or event prefix")
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        raw = redact(line.rstrip("\r\n"))
        encoded = raw.encode("utf-8")
        truncated = len(encoded) > 8192
        if truncated:
            raw = encoded[:8192].decode("utf-8", errors="ignore")
        record = {"id": f"{prefix}-{line_number}", "source": source, "text": raw,
                  "observed_at_ms": observed_at_ms, "truncated": truncated}
        validate_event(record)
        yield record


def load_labels(path):
    labels = {}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or item.get("truth") not in HEALTH or item.get("truth_domain") not in DOMAINS:
                raise ValueError("invalid adjudicated label")
            if item["id"] in labels:
                raise ValueError("duplicate adjudicated label")
            labels[item["id"]] = {"truth": item["truth"], "truth_domain": item["truth_domain"]}
    return labels


def rule_decision(event):
    text = event["text"].lower()
    critical = ("finality stalled", "qc mismatch", "state root mismatch", "data unavailable", "consensus halted")
    degraded = ("failed", "error", "regression", "timeout", "conflict", "latency", "unavailable")
    health = "CRITICAL" if any(k in text for k in critical) else "DEGRADED" if any(k in text for k in degraded) else "HEALTHY"
    patterns = {
        "CONSENSUS": ("consensus", "finality", "qc ", "quorum"),
        "NETWORK": ("peer", "p2p", "peerdas", "network"),
        "EXECUTION": ("block-stm", "evm", "execution", "conflict"),
        "STORAGE": ("qmdb", "storage", "state root", "database"),
    }
    domain = next((name for name, words in patterns.items() if any(w in text for w in words)), "UNKNOWN")
    return {"health": health, "domain": domain, "need_deep_analysis": health == "CRITICAL"}


def jev_request(event):
    return {"model": MODEL, "state": json.dumps({"source": event["source"], "text": redact(event["text"])}, ensure_ascii=False),
            "questions": {
                "q0": {"type": "choice", "instructions": "Classify operational health; do not recommend an action.", "criteria": {x: x for x in HEALTH}},
                "q1": {"type": "choice", "instructions": "Classify the N42 subsystem.", "criteria": {x: x for x in DOMAINS}},
                "q2": {"type": "noul", "instructions": "Does this require deep analysis by a human or reasoning model?"}}}


def _choice(answer, options):
    if not isinstance(answer, dict) or answer.get("type") != "choice" or answer.get("choice") not in options:
        raise ValueError("invalid Jev choice")
    probs = answer.get("probabilities")
    confidence = answer.get("confidence")
    if not isinstance(probs, dict) or set(probs) != set(options):
        raise ValueError("incomplete Jev distribution")
    if any(type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 1 for v in probs.values()):
        raise ValueError("invalid Jev probability")
    if abs(sum(probs.values()) - 1) > 0.02 or type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise ValueError("invalid Jev confidence or distribution")
    if probs[answer["choice"]] + 0.000001 < max(probs.values()):
        raise ValueError("Jev choice disagrees with distribution")
    return answer["choice"], float(confidence)


def evaluate(response):
    if not isinstance(response, dict) or response.get("model") != MODEL or not isinstance(response.get("answers"), dict) or set(response["answers"]) != {"q0", "q1", "q2"}:
        raise ValueError("invalid Jev model or answer set")
    health, hconf = _choice(response["answers"]["q0"], HEALTH)
    domain, dconf = _choice(response["answers"]["q1"], DOMAINS)
    deep = response["answers"]["q2"]
    if not isinstance(deep, dict) or deep.get("type") != "noul" or type(deep.get("noul")) not in (int, float) or not math.isfinite(deep["noul"]) or not 0 <= deep["noul"] <= 1:
        raise ValueError("invalid Jev escalation result")
    confidence = min(hconf, dconf)
    return {"health": health, "domain": domain, "need_deep_analysis": deep["noul"] >= 0.5 or confidence < 0.7, "confidence": confidence}


def classify(event, model_call=None):
    validate_event(event)
    started = time.monotonic_ns()
    rule = rule_decision(event)
    shadow = dict(rule)
    error = None
    called = model_call is not None
    if model_call is not None:
        try:
            response = model_call(jev_request(event))
            proposal = evaluate(response)
            # A model cannot downgrade a deterministic critical alert.
            if rule["health"] == "CRITICAL":
                proposal["health"] = "CRITICAL"
                proposal["need_deep_analysis"] = True
            shadow = proposal
        except (ValueError, TypeError, OSError, RuntimeError) as exc:
            error = type(exc).__name__
            shadow["need_deep_analysis"] = True
    result = {"id": event["id"], "source": event["source"], "observed_at_ms": event["observed_at_ms"],
              "rule": rule, "shadow": shadow, "model_called": called,
              "latency_ms": (time.monotonic_ns() - started) / 1_000_000}
    if error:
        result["model_error"] = error
    for field in ("truth", "truth_domain"):
        if field in event:
            result[field] = event[field]
    return result


def score(records, jev_cost_per_million_tokens=None, total_input_tokens=None, model_enabled=True):
    rows = list(records)
    labelled = [r for r in rows if r.get("truth") in HEALTH]
    result = {"events": len(rows), "labelled_events": len(labelled), "model_calls": sum(bool(r.get("model_called")) for r in rows),
              "model_call_reduction_vs_every_event": 1 - sum(bool(r.get("model_called")) for r in rows) / len(rows) if rows and model_enabled else None,
              "mean_latency_ms": statistics.mean(r["latency_ms"] for r in rows) if rows else None,
              "estimated_jev_cost_per_10000_events_usd": (total_input_tokens / len(rows) * 10000 / 1_000_000 * jev_cost_per_million_tokens) if rows and total_input_tokens is not None and jev_cost_per_million_tokens is not None else None}
    for key in ("rule", "shadow"):
        severe = [r for r in labelled if r["truth"] == "CRITICAL"]
        normal = [r for r in labelled if r["truth"] != "CRITICAL"]
        domain = [r for r in labelled if r.get("truth_domain") in DOMAINS]
        result[key + "s" if key == "rule" else key] = {
            "severe_recall": sum(r[key]["health"] == "CRITICAL" for r in severe) / len(severe) if severe else None,
            "false_positive_rate": sum(r[key]["health"] == "CRITICAL" for r in normal) / len(normal) if normal else None,
            "health_accuracy": sum(r[key]["health"] == r["truth"] for r in labelled) / len(labelled) if labelled else None,
            "domain_accuracy": sum(r[key]["domain"] == r["truth_domain"] for r in domain) / len(domain) if domain else None,
            "deep_analysis_rate": sum(bool(r[key].get("need_deep_analysis")) for r in rows) / len(rows) if rows else None,
        }
    return result


def official_jev(request):
    key = os.environ.get("TYPESAFE_API_KEY", "")
    if not key:
        raise ValueError("missing TypeSafe API key")
    endpoint = os.environ.get("TYPESAFE_API_URL", "https://api.typesafe.ai/v1/systemone")
    url = urllib.parse.urlparse(endpoint)
    if url.scheme != "https" and not (url.scheme == "http" and url.hostname in ("127.0.0.1", "localhost", "::1")):
        raise ValueError("Jev endpoint must use HTTPS or loopback HTTP")
    data = json.dumps(request).encode()
    req = urllib.request.Request(endpoint, data=data, headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as response:
        body = response.read(1_048_577)
    if len(body) > 1_048_576:
        raise ValueError("Jev response too large")
    return json.loads(body)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="sanitized, labelled JSONL input")
    parser.add_argument("--output", type=Path, required=True, help="new shadow JSONL output")
    parser.add_argument("--metrics", type=Path, required=True, help="new metrics JSON output")
    parser.add_argument("--labels", type=Path, help="separately adjudicated JSONL labels")
    parser.add_argument("--jev", action="store_true", help="call pinned TypeSafe Jev model")
    args = parser.parse_args(argv)
    if args.output.exists() or args.metrics.exists():
        parser.error("output files must not exist")
    if args.jev and not os.environ.get("TYPESAFE_API_KEY"):
        parser.error("TYPESAFE_API_KEY is required with --jev")
    labels = load_labels(args.labels) if args.labels else {}
    records = []
    seen = set()
    with args.events.open(encoding="utf-8") as source, args.output.open("x", encoding="utf-8") as out:
        for line in source:
            if not line.strip():
                continue
            event = json.loads(line)
            event_id = event.get("id") if isinstance(event, dict) else None
            if event_id in seen:
                raise ValueError("duplicate event id")
            seen.add(event_id)
            if event_id in labels:
                for field, value in labels[event_id].items():
                    if field in event and event[field] != value:
                        raise ValueError("embedded and adjudicated labels disagree")
                    event[field] = value
            record = classify(event, official_jev if args.jev else None)
            records.append(record)
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
    if set(labels) - seen:
        raise ValueError("labels refer to unknown event ids")
    args.metrics.write_text(json.dumps(score(records, model_enabled=args.jev), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
