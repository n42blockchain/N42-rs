#!/usr/bin/env python3
"""Read-only Falcon capability and common-head checks. Never signs or sends."""
import argparse
import json
import re
import sys
import urllib.request
from urllib.parse import urlsplit


class RpcRejected(ValueError):
    def __init__(self, method, code):
        super().__init__(method)
        self.method = method
        self.code = code


def rpc(endpoint, method, params):
    payload = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params)).encode()
    request = urllib.request.Request(endpoint, payload, {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.load(response)
    if result.get("id") != 1 or "error" in result or "result" not in result:
        raise RpcRejected(method, (result.get("error") or {}).get("code"))
    return result["result"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", action="append", required=True, help="Repeat once per node")
    parser.add_argument("--chain-id", type=int, default=94)
    args = parser.parse_args()
    reports = []
    for endpoint in args.rpc:
        uri = urlsplit(endpoint)
        if uri.username or uri.password or uri.query or uri.fragment:
            parser.error("Use endpoints without credentials or query secrets")
        if uri.scheme != "https" and not (uri.scheme == "http" and uri.hostname in ("localhost", "127.0.0.1", "::1")):
            parser.error("Use HTTPS or a loopback test endpoint")
        report = {"rpc": endpoint, "ok": False}
        reports.append(report)
        try:
            chain = int(rpc(endpoint, "eth_chainId", []), 16)
            caps = rpc(endpoint, "n42_getPQCapabilities", [])
            expected = dict(protocol="n42-pq-v1", transactionType="0x05", algorithm="Falcon-512",
                            signatureEncoding="padded-666", publicKeyMode=0, enabled=True)
            report.update(chainId=chain, capabilities=caps,
                          height=int(rpc(endpoint, "eth_blockNumber", []), 16))
            report["ok"] = chain == args.chain_id and int(caps.get("chainId", "-1"), 16) == chain and all(type(caps.get(k)) is type(v) and caps.get(k) == v for k, v in expected.items())
        except Exception as error:
            report["error"] = type(error).__name__
            if isinstance(error, RpcRejected):
                report.update(failedMethod=error.method, rpcCode=error.code)
    common = None
    if all(r["ok"] for r in reports):
        common = min(r["height"] for r in reports)
        for report in reports:
            try:
                block = rpc(report["rpc"], "eth_getBlockByNumber", [hex(common), False])
                if not isinstance(block, dict) or not isinstance(block.get("hash"), str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", block["hash"]):
                    raise ValueError("missing common block")
                report["commonBlockHash"] = block["hash"]
            except Exception as error:
                report.update(ok=False, error=type(error).__name__)
    matched = common is not None and all(r["ok"] for r in reports) and len({r.get("commonBlockHash") for r in reports}) == 1
    print(json.dumps(dict(commonHeight=common, consistent=matched, nodes=reports), indent=2))
    return 0 if matched else 1


if __name__ == "__main__":
    sys.exit(main())
