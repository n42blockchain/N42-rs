# /mobileverify cross-client fixtures, v1

Byte contracts of gov5's phone-facing mobile verification surface
(`internal/mobileverify`, `cmd/evmsdk`), written from the code that serves
them with fixed inputs, for a second implementation (the Rust node,
n42-rs `crates/n42/mobileverify`) to pin itself to byte for byte.

- Generator: `TestWriteCrossClientFixtures` in
  `internal/mobileverify/cross_client_fixtures_test.go`.
- Generated at gov5 `39cff9ce` (branch `test/mobileverify-cross-client-fixtures`).
- Regenerate:

  ```bash
  N42_WRITE_FIXTURES=1 go test ./internal/mobileverify/ -run TestWriteCrossClientFixtures -count=1
  ```

  Without `N42_WRITE_FIXTURES=1` the test rebuilds every file in memory and
  fails if the committed bytes differ, so CI catches a changed contract.
- Compare copies by SHA-256 of the raw bytes (`SHA256SUMS`, `sha256sum -c`).
  This README is not covered by the sums.

Every file is JSON with a `"_doc"` field describing its layout. Hex is
lowercase without `0x` unless the field is an HTTP body or names a 0x value
(`x_mobileverify_root`, uint256 quantities in `read_log.json`/`transactions.json`).
HTTP bodies are stored as exact strings, including the trailing `\n` gov5's
`json.Encoder` writes.

| File | Pins |
|---|---|
| `keys.json` | IKM -> blst `KeyGen` secret scalar, 48-byte pubkey, `AddrHex` for 4 devices |
| `pop.json` | 72-byte PoP message, PoP signatures (`_RO_POP_` DST), the SDK's register request body, register rejections (status + body) |
| `pow.json` | 79-byte PoW message, Keccak digests, smallest solving nonce for 0/4/8/12 bits, the 428 bodies, the SDK's retry body with `pow_nonce` |
| `registry.json` | key hashes, BMT leaf bytes/hashes, accumulator root and `ExportCommitted` after each of three commits, register/health bodies |
| `mask.json` | signer-mask encodings and the decoder's rejections |
| `receipt.json` | 72-byte receipt messages and signatures, the SDK's receipt POST body, server outcomes (status + body) |
| `cert.json` | majority-bucket certificate (aggregate sig, mask, aggregate pubkey, inputs), `GET /cert` bodies for the coordinator and window-manager variants, the 404 |
| `receipts_root.json` | native receipts root: per-receipt RLP, concatenation, root |
| `header.json` | `block.Header.Marshal()` (protobuf + `N42H` trailer), field list, RLP and hash for a full and a minimal header |
| `transactions.json` | protobuf transactions (legacy, 2930, 1559) with and without `from`, Ethereum encoding, hash |
| `read_log.json` | read-log entry codec, rejections, non-canonical inputs gov5 accepts |
| `stream_packet.json` | complete StreamPackets (empty block #88; one transfer with a non-empty read log) with decoded fields and `ExecuteAndVerifyV2` results |
| `topics.json` | gossip topic strings for `mainnet_qmdb_staggered` and the registration gossip payload |

Deterministic substitutions (the code would otherwise put wall-clock values in):

- `CommitEpoch` stamps each newly committed entry's `lastSeenMs` with the
  node's clock; the generator overwrites it (`1784372000000 + 45000*step`), so
  `export_committed` is reproducible. The snapshot bytes of two real nodes differ
  in these fields even when their roots agree.
- `windowClosedAt` of every certificate is `1784372090000` (production: the
  close-time wall clock; the coordinator run in the generator is checked to store
  the same aggregate and mask).
- Receipt `timestampMs` is `1784372012345` (the SDK's `SignReceipt` uses the clock).

Not covered: the HTTP limits and timeouts, the per-IP rate limiter (wall-clock
window), the cohort reveal/reconcile wire messages, and the packet gossip
validation path; none of these is a byte contract a single fixture can pin.
