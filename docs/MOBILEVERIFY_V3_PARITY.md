# Mobile verification v3 (`/mobileverify`) parity for the Rust node

Status: specification 2026-11-01; stages 0-2 implemented (see the table in section 4 and
"Stage 2 verification" at the end).

gov5's phone app (n42appv2, "mining v3", `docs/mobile-app-mobileverify-plan.md` in N42-gov5)
runs the Go SDK's `MobileVerifyMiner` loop against one HTTP surface on a fleet node:
`/mobileverify/{register,latest,packet/<hash>,receipt,cert/<hash>,health}`. The Rust node serves
none of it (its `crates/n42/mobile-service` is a POST-only JSON-RPC `mobile_*` API from an earlier
design, incompatible with the app), so the v3 app cannot verify blocks from an all-Rust fleet or
from the Rust member of a mixed one. This document is the byte-level specification of gov5's
surface (taken from N42-gov5 `39cff9ce`), the inventory of what n42-rs already has, the decisions,
and the staged plan. gov5 file references are relative to the N42-gov5 checkout.

## 1. gov5's surface

### 1.1 Wiring and configuration

- Server: `internal/mobileverify/httpserver.go` (routes :86-95), own listener,
  `ReadHeaderTimeout` 5 s, `ReadTimeout`/`WriteTimeout` 15 s, `MaxHeaderBytes` 16 KiB, graceful
  stop 3 s.
- Node wiring: `internal/node/node.go:2465-2711` (`startMobileVerify`): `NewHTTPServer(addr,
  registry, packetService, cohortCoordinator, certStore)`; `SetHead` returns
  `blockChain.CurrentBlock()` as (number, hash); receipt intake is the height-driven
  `CohortCoordinator` (:2561), the wall-clock `WindowManager` is test-only.
- Config `conf/mobileverify_config.go`: `enabled`, `packet_window` (256), `http_addr`,
  `collect_window_sec` (45; also the epoch-commit interval, node.go:2651), `cert_blocks` (512),
  `torrent_enabled`, `register_pow_bits` (0). CLI: `--mobileverify`,
  `--mobileverify.packet-window`, `--mobileverify.http`, `--mobileverify.pow-bits`
  (`cmd/n42/cmd.go:200-243`). The n42 profile turns it on (`cmd/n42/app.go:200-207`); a mining
  node with `MobileAnchorTime` set must have it enabled (node.go:1772-1775).

### 1.2 HTTP routes (`httpserver.go`)

General: every error body is `{"error":"<msg>"}` with `Content-Type: application/json`
(`httpError` :422-426); success bodies come from `json.NewEncoder` (trailing `\n`, map keys
sorted); hashes print as `0x` + lowercase hex; `hexInto` (:395-403) strips a lowercase `0x`
prefix, hex-decodes and requires the exact length; `hashFromPath` (:405-415) rejects an empty
suffix, a further `/`, or anything but 32 bytes; unknown paths get Go's plain-text 404.

**POST /mobileverify/register** (:140-193), checks in order:

1. Method: else `405 {"error":"POST only"}`.
2. Per-IP rate limit, before the body is parsed (a 428 retry counts): `429
   {"error":"registration rate limit"}`. Fixed window (:442-464): 10 per 1 min, one global window
   start, the whole map resets when it expires. IP from `RemoteAddr` only.
3. Body ≤ 4 KiB. `registerRequest` (:129-138): `pubkey` (48-byte hex, `0x` optional), `pop`
   (96-byte hex), `pow_nonce` (decimal uint64 **string**, omitempty), `attestation` (hex,
   omitempty). Bad JSON: `400 {"error":"bad json"}`; wrong lengths: `400 {"error":"pubkey must
   be 48 hex bytes, pop 96"}`.
4. PoW, only when `powBits > 0` (:163-173): missing/invalid nonce → **428** with body exactly
   `{"error":"mobileverify: registration proof-of-work required","pow_bits":N}`.
5. Device attestor if wired (never in production): `403`.
6. `Register(pubkey, pop)`: any error → **403** with `err.Error()`, e.g.
   `mobileverify: invalid proof of possession` (optionally `: pubkey decode: …` /
   `: signature decode: …`), `mobileverify: key was already registered; rotate to a fresh key`
   (revoked key).
7. `200 {"committed":bool,"index":N}`. `index` is 0 while pending; it becomes the append index
   once committed. Idempotent: committed key → `(idx,true)`, pending → `(0,false)`.

**GET /mobileverify/packet/{blockHash}** (:195-215): non-GET `405 "GET only"`; bad hash `400
"bad block hash"`; not cached **`404 {"error":"packet not in window"}`**; 200 → raw StreamPacket
bytes, `Content-Type: application/octet-stream`, `Cache-Control: public, max-age=31536000,
immutable`. Keyed by the **sealed** block hash.

**POST /mobileverify/receipt** (:217-254): body ≤ 8 KiB. `receiptRequest`: `blockHash` (32-byte
hex, `0x` optional), `blockNumber` (number), `receiptsRoot` (32-byte hex), `pubkey` (48-byte
hex), `signature` (96-byte hex), `timestampMs` (number, unsigned). The SDK sends hex **without**
`0x` (`cmd/evmsdk/mobileverify_client.go:303-310`). Errors: `400 "bad json"`, `400 "bad hex field
lengths"`; `404 "mobileverify: unknown block"` when the node has no header for the hash
(`ErrUnknownBlock`); everything else **403** with `err.Error()`:
`mobileverify: receipt is for a different block: receipt number X, block is Y`,
`mobileverify: too many open collection windows` (cap 128), `mobileverify: verifier not
registered` (pending/revoked count as unregistered), `mobileverify: invalid receipt signature`
(optionally `: pubkey decode/signature decode: …`), `mobileverify: collection window closed`.
Success `200 {"index":N}` (the device's committed index).

**GET /mobileverify/cert/{blockHash}** (:256-282, :373-391): `400 "bad block hash"`; nothing
stored **`404 {"error":"no certificates for block"}`** (the SDK maps it to
`ErrMobileVerifyNotFound`, the miner treats it as "still pending"); 200 → JSON **array** of

```
{"blockHash":"0x<64>","blockNumber":N,"receiptsRoot":"0x<64>","aggregateSig":"<192 hex, no 0x>",
 "signerMask":"<hex, no 0x>","signers":N,"windowClosedAt":<unix ms>}
```

`signers` = `len(DecodeMask(mask, registry.IndexBound()))` (0 on decode failure). With the
CohortCoordinator the array holds exactly one element, the merged majority winner
(`coordinator.go:791`).

**GET /mobileverify/latest** (:355-371, commit 47021e71): non-GET `405`; no head `503
{"error":"head not available"}`; 200, `Cache-Control: no-store`:
`{"hash":"0x…","number":N,"packet":bool}` (`packet` = the cache holds that head's packet).

**GET /mobileverify/health** (:336-349, no method check):
`{"accumulator":"0x<root>","alarms":N,"certBlocks":N,"openWindows":N,"pending":N,"registry":N}`
(`registry` = active committed keys, `pending` = awaiting commit, `accumulator` = BMT root, all
zeros when empty).

Other routes, not used by the miner: `GET /mobileverify/magnet/{hash}` → `{"magnet":"…"}` or
`404 "packet not seeded"`; `GET /mobileverify/alarms` → `[{"blockHash","blockNumber","cohorts",
"atMs"}]` newest first, ≤ 100; `GET /mobileverify/snapshot` → raw `ExportCommitted` bytes with
`X-Mobileverify-Root: 0x…`, `Cache-Control: no-store`; layout (`registry.go:409-446`)
`magic 0x4d565253 BE4 ‖ ver 0x01 ‖ count BE4 ‖ count × (pubkey48 ‖ pop96 ‖ active1 ‖ lastSeenMs BE8)`.

Client side (`cmd/evmsdk/mobileverify_client.go`): HTTP timeout 20 s; packet reads ≤ 256 MiB,
JSON ≤ 1 MiB, error bodies ≤ 4 KiB; any non-200 → `mobileverify client: server <code>: <error>`,
a 404 also wraps `ErrMobileVerifyNotFound`; on 428 it decodes `pow_bits`, solves, retries once
with `pow_nonce`.

### 1.3 Keys, proof of possession, proof of work, registry commit

- blst **min-pk**: 48-byte compressed G1 public keys, 96-byte compressed G2 signatures. DST
  **`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`** (`crypto/bls/blst/signature.go:18`) for both
  the PoP and receipts; plain `Sign(sk, msg, dst)`, no augmentation. Pubkey decode runs
  `KeyValidate` (subgroup check, rejects infinity); signature decode `SigValidate(false)` (group
  check, infinity allowed); verify `Verify(false, pk, false, msg, dst)`.
- Device secret: a 32-byte hex **IKM** fed to blst `KeyGen(ikm)` with empty info
  (`cmd/evmsdk/blst.go:22-33`), not a raw scalar. Rust: `blst::min_pk::SecretKey::key_gen(ikm, &[])`.
  `GenerateMobileBLSKey` returns `PrivHex`, `PubHex` (no `0x`), `AddrHex` (`pub[:20]`).
- PoP message (`registry.go:51-64`, pinned by `client_e2e_test.go:26`):
  `"n42/mobileverify/pop/v1\x00"` (24 bytes) `‖ pubkey48` = 72 bytes.
- PoW (`sybil.go:35-116`): message `"n42/mobileverify/pow/v1"` (23 bytes, no NUL) `‖ pubkey48 ‖
  nonce u64 BIG-endian` = 79 bytes; **Keccak256** (legacy); needs ≥ `bits` leading zero bits
  MSB-first; bits capped at 32; the client grinds nonces 0 … `1<<(bits+4)`. Production default 0.
- Pending → committed (`registry.go`): `Register` verifies the PoP, parks the key in `pending`,
  fires the gossip hook (raw `pubkey48‖pop96` on `/n42/<genesis4 hex>/mobileverify_registration/
  ssz_snappy`, `replication.go:37-51`). `CommitEpoch` (:209-252) runs every `collect_window_sec`
  (45 s) from the `EpochCommitter` (`replication.go:117-188`): pending keys sorted by
  `blake3(pubkey)` and appended; **index = append position**; BMT insert key `blake3(pubkey48)` →
  value `BE8(index)`.
- Accumulator root (`lib/bmt`): leaf bytes `'L'(0x4C) ‖ keyHash32 ‖ BE8(idx)`, leaf hash
  `blake3(0x00 ‖ leafbytes)`; internal `blake3(left32 ‖ right32)`; path = key-hash bits MSB first;
  empty child = 32 zero bytes; a single leaf is its own root; splits make a chain of internals
  with empty siblings, no path compression (`tree.go:117-175, 333-367`); delete collapses an
  internal whose only child is a leaf; empty root = all zeros. **n42-rs `bmt-core` hashes leaves
  differently (prefixed leaf/value hash) and must not be assumed equivalent.**
- On chain: when `IsMobileAnchor(header.Time)` the leader stamps `Header.MobileRegistryRoot =
  registry.Root()` (`internal/miner/worker.go:1797-1799`): header field 24, trailer flag 0x40.
  `mainnet_qmdb_staggered` has `mobileAnchorTime 1784372000`, so it is live there. Followers carry
  the field and do not validate it. Each commit is persisted to the rawdb anchor log
  (node.go:2669-2682).
- Client polling: the miner re-calls `register` every 10 s until `committed:true`
  (`mobileverify_miner.go:316-345`). With PoW on, each call is 2 requests, so a key waiting on
  the epoch can hit the 10/min/IP 429.

### 1.4 StreamPacket V2

Wire (`cmd/evmsdk/stream_packet.go:50-183`, header in `wire.go`); every length/count is u32
little-endian, no varints, no compression:

```
"N2"(0x4E 0x32) ‖ version 0x01 ‖ flags (0x01 iff len(Bytecodes) > 0)
‖ block_hash 32
‖ header_len u32 ‖ header_bytes
‖ tx_count u32 ‖ { tx_len u32 ‖ tx_bytes }*
‖ read_log_len u32 ‖ read_log_bytes
‖ bytecode_count u32 ‖ { code_hash 32 ‖ code_len u32 ‖ code }*
```

Decoder caps: 100 000 transactions, 10 000 bytecodes; when the flag is clear and the data ends
before `bytecode_count` the decoder accepts it (the encoder always writes the count). Bytecodes
are sorted ascending by hash (`internal/streamverify/producer.go:57-66`). `block_hash` must equal
the hash of the carried header (checked on the phone and in gossip validation,
`packetservice.go:166-182`).

`header_bytes` is **not RLP** but gov5 `block.Header.Marshal()` (`common/block/header.go:294-361`):
`proto(types_pb.Header) ‖ "N42H" ‖ flags1 ‖ UncleHash32 ‖ [WithdrawalsHash32 if 0x01] ‖
[ParentBeaconRoot32 if 0x02] ‖ [RequestsHash32 if 0x04] ‖ [BlobGasUsed LE8 if 0x08] ‖
[ExcessBlobGas LE8 if 0x10] ‖ [BlockAccessListHash32 if 0x20] ‖ [MobileRegistryRoot32 if 0x40] ‖
[SlotNumber LE8 if 0x80] ‖ protoLen u32 LE`. Protobuf fields (`proto/types_pb/types.proto:76-101`):
1 ParentHash, 2 Coinbase (H160), 3 Root, 4 TxHash, 5 ReceiptHash, 6 Difficulty, 7 Number,
8 GasLimit, 9 GasUsed, 10 Time, 11 Nonce (u64), 12 BaseFee, 13 Extra, 15 Bloom (H2048),
16 MixDigest, 17 BlobGasUsed, 18 ExcessBlobGas, 20 UncleHash, 21 WithdrawalsHash,
22 ParentBeaconRoot, 23 RequestsHash. `H256 = {hi: H128{hi, lo}, lo: H128{hi, lo}}` of u64s; a
hash maps to big-endian u64 chunks with `hash[0:8]` → `hi.hi` (`common/utils/util.go:279`); a
uint256 maps `hi.hi = w[3], hi.lo = w[2], lo.hi = w[1], lo.lo = w[0]` (:220); a nil `BaseFee`
stays absent; **always emit field 20 (UncleHash)**. Block hash = `keccak256(RLP(header))` in
Pectra order (fields 1-21), then 22 BlockAccessListHash, 23 SlotNumber, 24 MobileRegistryRoot,
optional fields written as empty placeholders for gaps (:62-128, :174-176).

`tx_bytes` are gov5 protobuf `types_pb.Transaction` (`transaction.go:475-488`,
`types.proto:120-150`) **with `from` (field 11) set**: `AsMessage` trusts `from` and skips
recovery (`common/transaction/message.go:114-117`). Bytes starting with `0xFF` (compact storage
form) are also accepted.

`read_log_bytes` (`cmd/evmsdk/read_log.go:109-198`): `count u32 LE` then entries: `0x00` =
account not found; account: header bits `0x01` exists, bits 1-3 nonce length (0..7), `0x40` =
8-byte nonce, `0x10` has balance, `0x20` contract (codeHash ≠ keccak(empty)); then nonce BE
stripped; then, if the balance bit is set, `len1 ‖ balance BE` stripped; then `codeHash32` if
contract. `0x80+len` (len 0..32) ‖ storage value BE stripped. `0xC0 ‖ hash32` = block hash entry
(never produced by the Go recorder). Max 500 000 entries.

How gov5 builds it: the leader wraps the build's `StateReader` in
`streamverify.ReadLogRecorder` (`worker.go:1708-1715`); every `ReadAccountData` /
`ReadAccountStorage` is logged in call order; code is not logged, every non-empty code read goes
into `Bytecodes`. The packet is built after sealing from the **sealed** header (the seal changes
Extra, hence the hash; `internal/miner/mobile_packet.go:30-170`); when the build "diverged" the
log is rebuilt by re-executing block-start + transactions over the recorded values. It is cached
(`PublishLocal`) and gossiped raw (no snappy despite the suffix) on
`/n42/<genesis4 hex>/mobileverify_packet/ssz_snappy`; followers validate the hash, accept
numbers from head−window to head+2, ≤ 8 packets per height (`packetcache.go:16`,
`packetservice.go:144-159`). Window: blocks with `number ≥ maxNumberSeen − packet_window`
(default 256), keyed by hash.

What the phone checks (`ExecuteAndVerifyV2`, `cmd/evmsdk/verify_v2_exec.go:58-178`): decode the
header, `header.Hash() == pkt.BlockHash`; unmarshal the transactions, insert the bytecodes into
the `CodeCache`; replay the log by cursor through `StreamReplayStateReader` (wrong entry type or
exhausted log = error; code from the cache); `state.New(reader)`, `ProcessExecutionBlockStart`
(EIP-4788, then EIP-2935 under Prague), `ApplyTransaction` per tx with `apos.NewFaker()`,
`author = nil`, **BLOCKHASH always zero** (:124); compute `ReceiptsRootFor(cfg, n, receipts)` and
compare with `header.ReceiptHash`; **the state root is not checked**. On a native chain the root
is `keccak256(concat_i RLP([status, cumulativeGasUsed, [[addr, [topics], data]…]]))` (an empty
block gives keccak of nothing, `0xc5d2…a470`); Ethereum-EL chains use the receipt trie.

**The read log is positional (no keys) and is consumed in the order Go's
`modules/state.IntraBlockState` calls the reader**: one `ReadAccountData` per address per block
(cached in `stateObjects`), missing accounts cached in `nilAccounts` and never re-read, each slot
read once, balance credits deferred through `balanceInc` (the coinbase is not necessarily read),
block-start system calls first. revm's `Database` call order is not this order; a Rust producer
cannot be derived from a revm read wrapper. See §3.2.

### 1.5 Receipt, collection window, certificate

Signed message (72 bytes; identical in `internal/mobileverify/receipt.go:28-55`,
`cmd/evmsdk/verification_receipt.go:40-49`, n42-rs `crates/n42/mobile-verify/src/receipt.rs:39-48`):
`block_hash(32) ‖ block_number(8, little-endian) ‖ computed_receipts_root(32)`; `timestampMs` is
not signed.

Server validation order: `lookup(blockHash)` from rawdb `ReadHeaderNumber` (any known header,
not only canonical; unknown → 404); number must match; ≤ 128 open windows; `Collector.Add`
(`collector.go:70-94`): block/number match, `registry.Lookup(pubkey)` (active committed keys
only), BLS verify, window not closed or frozen; dedupe by mobile index, **latest wins**;
`MarkActive`. The server does not compare the attested root with the header: each root is its
own bucket.

Collection window, production `CohortCoordinator` (`coordinator.go`, `DefaultCohortConfig`
1/2/3/5 blocks): a window opens on the first receipt with `openedHeight = receipt.BlockNumber`;
intake closes when the chain reaches **N+1** (then `403 collection window closed`); reveal at
N+2, reconcile and close at N+3, merge at N+5. At close each root bucket is aggregated: indices
sorted, signatures summed in G2, mask encoded (`collector.go:100-164`). Peer certs for the same
root are merged signer-disjointly (`certmerge.go:76-186`); only the **largest bucket** is stored,
ties → lexicographically smaller root hex (`SelectMajorityBucket` :198-229); losing buckets raise
a divergence alarm. Test `WindowManager` (`manager.go:57-169`): closes 45 s after the first
receipt, stores all buckets majority first.

Signer mask (`mask.go`): `uvarint count` then `count` uvarints over the sorted indices, the first
raw, each later one as `gap − 1`; decode rejects count > remaining bytes or > registry bound,
index ≥ bound, overflow, trailing bytes. Cert verify (`cert.go:40-61`): decode the mask, sum the
pubkeys in G1, one `Verify(aggPk, msg72)`.

"Certified" has no quorum rule: the miner counts a block certified when some cert's
`receiptsRoot` equals its own root (`EqualFold` on the `0x` hex) with `signers ≥ 1`
(`mobileverify_miner.go:409-421`); `cmd/mobileverify-device` wants `signers ≥ #devices`.

### 1.6 Miner loop, status, chain config

Timings (`mobileverify_miner.go:51-59`): poll 1 s, registerPoll 10 s, retry 10 s, certDelay 20 s,
certRecheck 10 s, certTimeout 2 min, callTimeout 30 s (`SetIntervalsMs` overrides the first three).
Loop: register until committed; each tick `/latest`, if `packet` and `number > last` → fetch,
execute, sign, submit (a failure increments `failed`, loop goes on); an error from `/latest` or
`/cert` ends the session (`retrying`, 10 s, register again); cert 404 = pending. Status JSON:
`{"running","phase"(idle|connecting|registering|mining|retrying),"endpoint","pubkey",
"deviceIndex"?,"verified","failed","certified","uncertified","lastBlock"?:{…},"lastSigners",
"lastError"?,"startedAtMs"?,"log":[… ≤ 100]}`.

`chainName` is mandatory and resolved with `params.ChainConfigByChainName` (`params/config.go:
737-768`): `mainnet`, `mainnet_compat`, `mainnet_v2`, `mainnet_v2_staggered`, `mainnet_mpt`,
`mainnet_qmdb`, `mainnet_qmdb_staggered`, `qs_epoch_test`, `h2_interop_test`, testnet, `eth-*`.
It drives the fork rules, CHAINID, the block-start system calls and the receipt-root rule.
**There is no Go config for chain id 1143 (`n42_devnet` / `n42_fleet7`)**; chain 94
(`mainnet_qmdb_staggered`) has Shanghai at 305000 and Cancun at 3935000. fleet7's `altSigTx`
(type 0x50) is not covered by the Go transaction protobuf.

### 1.7 Fixtures

None exist on either side for this surface: gov5 builds packets in code
(`session_e2e_test.go:22-51` empty block #88 under `mainnet`; `packet_test.go:95-115`) and pins
only the 72-byte message (`sdk_compat_test.go:21`: `hash[i]=i`, `root[i]=0xFF-i`, number
13220145), the PoP message (`client_e2e_test.go:26`) and the read-log header byte
(`read_log_test.go:196`). Go comments name N42-26's `read_log.rs`, `receipt.rs` and
`verifier.rs` as the Rust references.

## 2. What n42-rs has

- `crates/n42/mobile-verify`: `VerificationReceipt` + 72-byte message (`receipt.rs:14,39`),
  `encode_receipt`/`decode_receipt` (own 224-byte wire, not gov5's JSON), `VerifierRegistry`,
  `AggregatedAttestation` (bitfield, not gov5's uvarint mask), `AttestationBuilder`,
  `ReceiptAggregator`, SBMT/twig state-proof verifiers, `CodeCache`, the `"N2"` wire header
  (`wire.rs`; no StreamPacket type). **DST divergence:** it signs under
  `N42_MOBILE_RECEIPT_V1_…_RO_POP_` / `N42_MOBILE_V1_BLS_POP_…` (audit R3-P6) and the default
  `h2-primitives` DST is `…_RO_NUL_`; gov5 phones use the standard `…_RO_POP_` for both.
- `crates/n42/mobile-service`: node half of the old design: `MobileService` (register, record
  commit, submit receipt, attestation, proofs), `rpc.rs` (`mobile_*` JSON-RPC), `http.rs`
  (hand-rolled POST-only server). Mounted by `h2_validator --mobile <addr>`; under deferred
  execution it records no receipts root, so nothing is ever attested.
- `crates/n42/mobile-sdk`: the legacy APoS `consensusBeaconExt` subscribe/submit client with a
  keyed `CachedReads` witness; dead on HotStuff chains.
- `crates/n42/h2-primitives`: blst min-pk keys, `sign_with_dst`/`verify_with_dst`,
  `AggregateSignature::verify_aggregate_with_dst`.
- `crates/n42/header` + `crates/chainspec/src/qmdb.rs`: `N42Header.mobile_registry_root`
  (element 24), gates `glamsterdam_active_at` / `mobile_registry_root_in_header_at`; presence
  checked, value not; **no producer**, the assembler refuses to build under the gate
  (`engine-types/src/assembler.rs:291-315`).
- `crates/n42/h2-consensus/src/header_profile.rs`: gov5's header profile and the concat
  receipts root (`gov5_receipts_root`), so the RLP block hash already matches Go.
- `crates/n42/h2-net`: gov5 GossipSub transport with the genesis-digest topic scheme (adding the
  two mobileverify topics is routine).
- HTTP: no axum; hyper 1.9 / hyper-util / tower are in the graph; jsonrpsee in bin/n42.
- Hooks: `executed_fields` (receipts roots per block, in bin/n42), `QmdbNodeState` proofs,
  `evm_config.executor(StateProviderDatabase(parent state)).execute_one(block)` for a sequential
  re-execution.
- N42-26 (not ported): `n42-mobile/packet.rs` (StreamPacket with an **alloy** header and its own
  layout), `verifier.rs` (`StreamReplayDB`, Ethereum trie root), `n42-execution/read_log.rs`
  (the same entry codec as gov5's read log), `n42-node/mobile_packet.rs` producer over QUIC.

## 3. Decisions

### 3.1 Where the server lives

In `h2_validator` (crate `n42-h2-node`), as `--mobileverify.http <addr>`, replacing the
`--mobile` JSON-RPC service. It is the process that seals blocks (packets are keyed by the sealed
hash), sees commits (head for `/latest`, heights for the cohort windows), and runs the gov5
gossip stack (packet and registration relay). The registry root reaches the execution layer
through the payload attributes the driver already sends (`mobile_registry_root` on the N42
payload attributes; the assembler takes it when the gate is active), which closes
`HEADER_FIELD_PARITY.md` gap 6.

### 3.2 Where packets come from

A Go-consumable packet needs the gov5 protobuf header and transactions and a read log in Go
`IntraBlockState` order. The first two are codecs and get written in Rust. The read log cannot
be derived from a revm read wrapper (§1.4), and porting Go's state-layer read discipline is both
large and fragile against every gov5 change. So, in order:

1. **Relay** (mixed fleets): subscribe to `mobileverify_packet`, validate (decode header, hash
   check, window), cache and serve. Zero production risk, covers the Rust member of a Go fleet.
2. **Go sidecar builder** (all-Rust fleets): a small gov5 command (`cmd/mobileverify-packetd`)
   that follows the Rust node's head over JSON-RPC, re-executes each block with gov5's own
   execution and `ReadLogRecorder` against a `StateReader` answered by the Rust node's RPC at the
   parent block (`eth_getTransactionCount` / `eth_getBalance` / `eth_getCode` / `eth_getStorageAt`
   by block hash), and PUTs the packet to the Rust node's loopback ingest. It is the same code
   the phone runs, so the log order matches by construction. Cost: one Go process beside the
   Rust leader, ~1 s per block on devnet shapes; acceptable for a verification feature.
3. **Native Rust producer**: only if 2 proves the demand; needs a Go-order read-log emulation.

### 3.3 Chain config on the phone

The phone and the sidecar need a gov5 `params.ChainConfig` for the chain. Devnet/fleet7
(chain id 1143) has none, so end-to-end testing runs the Rust fleet on chain 94's genesis
(`crates/chainspec/res/genesis/gov5/mainnet_qmdb_staggered.json`, see that README) with
`chainName=mainnet_qmdb_staggered`. Adding an `n42_devnet` config to gov5 `params` (and shipping
a rebuilt AAR) is a follow-up for the app owner.

### 3.4 Byte contracts to pin before coding against them

Cross-client fixtures written by a Go test in gov5 and copied into the Rust crate's `testdata/`
(SHA-256 compared, as for the h2 fixtures): PoP message + signature for a known IKM, PoW digest
and a solved nonce per bits, registry accumulator roots after each commit of a key sequence,
signer-mask vectors, a cert (aggregate sig + mask) and its verification inputs, receipts-root
vectors (empty, one receipt with logs), gov5 header `Marshal` bytes for a header with every
trailer flag, protobuf transaction bytes (legacy, 1559, with `from`), read-log entry vectors, and
one complete StreamPacket for an empty block under `mainnet_qmdb_staggered`.

## 4. Plan

| Stage | Where | Content | Done when | Status |
|---|---|---|---|---|
| 0 | gov5 branch `test/mobileverify-cross-client-fixtures` | the Go fixture writer of §3.4, `internal/mobileverify/testdata/cross_client_v1/*.json` | `go test ./internal/mobileverify/... -run Fixture` writes them; copied to n42-rs with SHAs | done (gov5 76bc53c5, 961e4601) |
| 1 | n42-rs crate `crates/n42/mobileverify` | registry + gov5 BMT accumulator + snapshot export; PoP/PoW; mask; collector + cohort coordinator (single node, majority bucket, alarms); cert JSON; packet cache + window; StreamPacket V2 decoder with the gov5 header/tx protobuf codecs (encode too, for the sidecar path's validation); HTTP router on hyper 1.x with the exact routes, bodies, status codes and limits of §1.2 | unit tests against the stage-0 fixtures; an `httptest`-style test per route | done (635ce8538..8bc262b2f; hardening merged af7ba3771) |
| 2 | `n42-h2-node` | `--mobileverify.http`, head from commits, epoch commit every 45 s, gossip relay of packets and registrations (`h2-net` topics), registry root → payload attributes → assembler, anchor log; `--mobile` retired | mixed devnet: gov5 `cmd/mobileverify-device` pointed at the **Rust** member registers, verifies gov5-produced packets, gets certified | done (c36733319, 7a4f44fa8, 05657d113, f5bc78235, d3efa4651, 98dafeb94; gov5 harness 448db194); verified on a mixed devnet, see "Stage 2 verification" |
| 3 | gov5 `cmd/mobileverify-packetd` + Rust loopback ingest | the sidecar builder of §3.2 | all-Rust devnet on chain 94's genesis: `cmd/mobileverify-device` against a Rust node, 20/20 certified (gov5's own regression bar) | open |
| 4 | docs | `N42_26_PORT.md` "Joining a Go fleet" rules, `N42_CUSTOMIZATIONS.md`, this document's status | — | open |

Open for the owner: the reward model (gov5 item 8), TLS exposure (item 4), an `n42_devnet`
chain config in gov5 `params`, and whether the old `mobile-service` JSON-RPC API has any client
left (none known; it is retired in stage 2).

## Stage 2 verification

Run `mv2b`, 2026-11-02, n42-rs `feat/mobileverify-v3` at 98dafeb94 (debug build), gov5
`test/mobileverify-device-genesis` 448db194 (node and `cmd/mobileverify-device`). Mixed devnet on
`n42_devnet.json` (chain 1143, 3 s slots, four validators round-robin: three Rust, one gov5), 420 s:

```bash
DEVNET_BIN=/data/n42-build/mobile-target/debug N42_GOV5=<gov5 worktree> MOBILEVERIFY=1 GOV5_DELAY=0 \
  scripts/devnet-fleet.sh mv2b 420 --gov5
# Rust validator i serves http://127.0.0.1:2101<i>/mobileverify, the gov5 member :21020
mobileverify-device -mv http://127.0.0.1:21010 -rpc http://127.0.0.1:18545 \
  -genesis crates/chainspec/res/genesis/n42_devnet.json -devices 2 -blocks 5 \
  -skip-no-packet -commit-wait 150s -settle 30s
```

The device is aimed at Rust validator 0. gov5's harness gained `-genesis` (chain config from a
genesis file instead of `params`), `-skip-no-packet` and `-packet-wait`; the devnet has no packet
for a Rust-led block until stage 3, so 13 Rust-led blocks were skipped and the five verified blocks
are the gov5-led ones (packets relayed to the Rust node over `mobileverify_packet`).

```
SUMMARY devices=2 blocks=5 skipped=13 failures=0 certified(all devices)=5/5
```

Certificate served by the Rust node for block 19 (blocks 23, 27, 31, 35 alike, `signers` 2):

```json
[{"blockHash":"0x0f9fec1864e5facf250aab672889834022a6af6b6cede706686771723f4f4b66","blockNumber":19,
  "receiptsRoot":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
  "aggregateSig":"b3362ae2…bc731143","signerMask":"020000","signers":2,"windowClosedAt":1793601758747}]
```

Fleet summary at 420 s: the three Rust validators committed 185 blocks each, gov5 height 185, block
185 hash equal on reth and gov5 (`0xa0046c14…29bd1cf`), EL errors 0. `/mobileverify/health` on all
four members after the run: `registry` 2, accumulator `0x0faa5a99…8b06c1a5` on every member
(registrations made at the Rust node reached gov5 over `mobileverify_registration` and were
committed by each node's own 45 s epoch timer to the same index), `alarms` 0; `certBlocks` 5 on the
node the device used, 0 elsewhere (certificates are per serving node, as in gov5). Every
consensus dir has `mobileverify/registry.bin` (315 bytes); the three files carry the same keys and
indices and differ only in the node-local admission timestamp. Headers carry no
`mobileRegistryRoot`: the devnet has no Glamsterdam/`mobileAnchorTime`, so the gate is off
(the stamping under the gate is covered by `assembler::tests::the_registry_root_is_stamped_under_the_gate_only`).

Open after stage 2:

- Each node commits epochs on its own timer, so two nodes can assign different indices if
  registrations arrive on either side of an epoch boundary (gov5 has the same property; the
  device harness says "committed per node on its own epoch timer"). Here both registrations landed
  in one epoch everywhere. A header-anchored registry root would need a common commit point.
- The engine's payload id does not cover `mobile_registry_root` (upstream reth computes it); two
  builds that differ only in the root would share an id. The leader sets the root once per slot.
- Stage 3 needs from the Rust side: a hook that publishes a packet ingested through the loopback
  `PUT` on `mobileverify_packet` (gov5 `PublishLocal`); the loopback ingest itself exists.
