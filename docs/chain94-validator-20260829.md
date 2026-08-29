# A Rust validator in chain 94's committee — 2026-08-29

The qs fleet on this box is gov5's production chain (`mainnet_qmdb_staggered`,
chain id 94, seven HotStuff-2 validators, head near 13,560,000 at the
start). This is the record of taking over validator slot 6 with n42-rs: the
Go node6 stopped, an n42-rs execution layer bootstrapped from node6's state,
`h2_validator` under node6's BLS key and libp2p identity — voting first,
then leading. Everything on the "still missing" list of
`N42_26_PORT.md` that the fleet actually exercises was met on the way and is
fixed on this branch; what is not covered is listed at the end.

Outcome, measured over the last 151 blocks of the run (13,562,307 →
13,562,457, release build), with the fleet's Go node6 down since 06:09:47:

- **Voting.** 126 of those blocks carry a committed QC; 121 of the QCs
  include validator 6's signature. Of the 76 QCs certifying a *Go-led*
  view, 71 carry the Rust vote (the QC closes at 5 of 7 and the Rust vote
  is usually among the first five: `newPayload` → vote takes 4.1 ms p50).
- **Leading.** 25 of the 151 blocks were built by the Rust node (coinbase
  `0x1ccde065…`, up to 150 transactions each); every Go node holds them at
  the same hash and every QC that certifies them is a 5/7 that includes
  slot 6.
- **Same chain.** Go nodes 0–4 and the Rust execution layer report the same
  head, hash and state root at every sample (`13562457` at the last one).
- **No errors** on either side: Rust validator 0 WARN / 0 ERROR, execution
  layer 0 WARN / 0 ERROR, no `BAD BLOCK` in the Go logs.
- **Memory.** Execution layer 9.2 GB RSS (release; 9.5 GB in debug),
  validator 112 MB. Bootstrap peak 19.5 GB.

The Rust node was left running as validator 6 until 08:36:16, when the
operator paused every fleet on the box for a stress test (the second pass
below was done offline; its rollout is described there). Go node6 stays
stopped; to give the slot back, stop the Rust validator first (never two
holders of key 6), then `./roll-one-node.sh --node 6 …` as the runbook
says.

## Layout on the box

Everything lives under `/data/blockchain/mixed-fleet/n42-rs-qs`:

| path | what |
|---|---|
| `snapshot/state.jsonl` (+ `.header.rlp`, `.manifest.json`) | gov5's `n42-reth-state-dump` of node6's copy |
| `snapshot/state.qmdb` | the QMDB leaf-form portable snapshot (new, see below) |
| `el/` | the reth datadir (5.0 GB: 2.0 GB static files, 672 MB MDBX, 2.3 GB `qmdb/`) |
| `consensus/` | `h2_validator`'s checkpoint and vote log |
| `jwt.hex`, `env.sh`, `start-el.sh`, `start-validator.sh`, `qc-evidence.py` | how it is run |
| `logs/` | every run's log (`el-release.log`, `validator-release.log` are the live ones) |

Ports: Engine API 18581, JSON-RPC 18585, devp2p 30343 (discovery off, no
peers), validator libp2p 32006 — node6's port, under node6's peer id.

```bash
# env.sh: QS_RS_GENESIS, ports, QS_RS_BIN=$repo/target/${QS_RS_PROFILE:-release}
./start-el.sh <tag>                         # n42 node --chain <genesis> --datadir el --authrpc.port 18581 ...
./start-validator.sh <tag> [--propose]      # refuses to start while Go node6 runs
python3 qc-evidence.py http://127.0.0.1:20012 <from> <to>   # QC signer bitmaps from headers' extra data
```

`start-validator.sh` is, in full:

```
h2_validator --chain crates/chainspec/res/genesis/gov5/mainnet_qmdb_staggered.json \
  --index 6 --bls-key <slot 6 key from ~/qs-validators.md> \
  --el http://127.0.0.1:18581 --el-rpc http://127.0.0.1:18585 --jwt jwt.hex \
  --listen /ip4/127.0.0.1/tcp/32006 --net-key <QS_NETKEYS[6]> --datadir consensus \
  --peer /ip4/127.0.0.1/tcp/3200{0..5}/p2p/<QS_PEERIDS[0..5]> [--propose]
```

## Step by step

### 1. Genesis with the fork timestamps

Blocks 305,000 and 3,935,000 on node0: timestamps 1681295943 and
1710335881. Regenerated with `n42-gov5-genesis … --fork-time
shanghai=1681295943 --fork-time cancun=1710335881 --expect-hash 0xa2d2ff5d…`;
the hash reproduces, the fork digest on the wire is `a2d2ff5d`. The file
now also carries `shanghaiTime`/`cancunTime` (two lines changed). gov5's
own forks stay inert in `config` — and one of them, `mobileAnchorTime`
(1784372000, 2026-07-18), is now read: see the header extension below.

### 2. State bootstrap from node6's copy

The copy at `/data/blockchain/mixed-fleet/qs-snapshot/qs-node6` has a
12.9 GB `chaindata/mdbx.dat`; its QMDB applied head is block 13,560,375
(`0x0e37dae9…`, state root `0xa697c095…`). Tools built from the gov5
checkout (`go build ./cmd/…`).

| step | result | time | peak RSS |
|---|---|---|---|
| `n42-reth-state-dump --datadir <copy>/chaindata --out state.jsonl` | 6,120,111 accounts, 37,383 slots, 563 MB JSONL, 875-byte header RLP | 6.5 s | 151 MB |
| `n42-qmdb-export --db <copy>/chaindata --out state.qmdb` (v1) | **fails at slot 0**: "QMDB entry log is not contiguous … replay must retain full --qmdb-history" | 4 s | 2.9 GB |
| `n42-qmdb-export --leaf-form …` (v2, this work) | 30,933 twigs (all with leaf hashes), 6,157,495 live entries, 2.35 GB | 19 s | 3.6 GB |
| `n42-init-snapshot init --datadir el --chain <genesis> --state … --header … --qmdb …` | datadir at 13,560,375: dummy headers below, hashed state, forest rebuilt and checked against the header | 7 min 57 s (debug) | 19.5 GB |
| first `n42 node` start (debug) | forest restored from `forest.bin` (2.3 GB), `QMDB state ready` | 100 s | 10.5 GB |

**Where the v1 export choked, and the v2 form.** The fleet's nodes reclaim
dead entry rows (`FlushTo` with a `Deleter`: "the on-disk entry log tracks
the live set instead of the full history"), so of 63,349,357 appended slots
only 6,157,495 have rows — 9.7 %. The v1 portable snapshot needs every
slot's key and value, dead ones included, because their leaf hashes are
frozen into the twig commitments. But gov5 keeps what the commitment needs:
per twig, `qmdbTwigs` holds `root ‖ leafRoot ‖ activeBits` and
`qmdbTwigLeaves` the leaf hash of every appended slot (sparse-encoded).
`WritePortableSnapshotV2` (gov5 side, `lib/qmdb/portable_v2.go`, the patch
is in `docs/gov5-qmdb-export-leaf-form.patch` and applied in the scratch
checkout that built the tool) writes magic `N42QMDB\x02`: the v1 header
plus twig and live counts; per twig `leafRoot ‖ bits ‖ mode` with the
appended slots' leaf hashes when the node has them (mode 1) or nothing
(mode 0, allowed only when no slot of the twig is live); then the live
entries in slot order; then the Blake3 digest. The exporter checks each
blob against the twig's frozen leaf root before writing it. On the Rust
side `QmdbPortableSnapshot::decode` reads both versions;
`QmdbCompatTree::from_leaf_form` rebuilds every twig (leaves folded and
checked against the leaf root; a hollow twig carries its root and must
have no live bits), verifies every live entry sits on a set bit and hashes
to its leaf, and the upper root against the header. Dead slots become
tombstones (no key, no value — nothing ever asks for them: undo records
only revive slots that were live at the snapshot). A tree with tombstones
persists in leaf form (`QmdbSnapshot::leaf_form`, serde-default so older
files still read), and exports as v2.

**The forest was persisted whole on every block.** `on_canonical` wrote
`forest.bin` — 2.3 GB here — for each canonical block; at one block a
second that is not a node. It now appends the block's leaf operations to
`forest-deltas.bin` (1.2 MB after 875 blocks) and rewrites the base in a
background thread every 512 MiB of log or 20,000 blocks; a start replays
the log on the base (`restored the QMDB forest from the base snapshot and
the delta log … replayed=875`, 2 min in debug; 1,909 records in 35 s in
release). `persist_now` folds the log at shutdown when the canonical
stream closes in time; when it does not, the next start replays. A head
the log cannot reach still writes the tree whole.

### 3. The execution layer, and the pull

`n42 node --chain <genesis> --datadir el --authrpc.port 18581
--authrpc.jwtsecret jwt.hex --http --http.port 18585 --port 30343
--disable-discovery --ipcdisable`. With the validator up it pulled the gap
from the Go peers over `bodies_by_range`: 875 blocks (13,560,376 →
13,561,250) in 27 s through `newPayload` + forkchoice in the debug build
(32 blocks/s), then 976 more after the fix below, then the rest by
gossip. All six Go peers connected and were identified (`agent=5.7.960`),
the status handshake found the same chain.

### 4. Taking the slot

`qs_stop_node 6` (SIGINT, "stopped clean") at 06:09:47; the validator
started at 06:09:48 under node6's peer id
`16Uiu2HAmLpq62D7sSoUBUE8GxykmR6kuyZxMWymZSLfsCUxSKPN1` (new `--net-key`,
gov5's hex secp256k1 secret), vote-only. The Go peers' static `--p2p.peer`
entries for node6 therefore still match. Import-gated votes started as
soon as the pull reached the fleet's head (`import-gated vote: execution
validated, sending vote view=12965 … sending vote to leader … voter=6`),
then `--propose` at 06:35: `TC formed, I am the new leader for view 13012
… built a block to propose view=13012 txs=150`, and node0's chain:

```
13562262 view=13012 hash=0xd984ffad8f3aff0f miner=0x1ccde065 (no QC in extra)
13562263 view=13013 hash=0x80f86c195b1fb3c3 leader=0xd2a316a1 committedQC view=13012 for d984ffad8f3aff0f signers=1110101 votes=5/7 slot6=YES
13562268 view=13019 hash=0x1662baa3f0ff1150 miner=0x1ccde065 (no QC in extra)
13562269 view=13020 hash=0x2b0534a30be8f4b6 leader=0xd2a316a1 committedQC view=13019 for 1662baa3f0ff1150 signers=1011011 votes=5/7 slot6=YES
```

(`qc-evidence.py` decodes the committed QC gov5 embeds in each header's
extra data: `N42H ‖ view ‖ SSZ{view, blockHash, aggSig, signersBitmap} ‖
seal`, bitmap = u16 count + one bit per validator in genesis order; slot 6
is `0x1ccde065…`.) The same blocks read the same on 20012, 20014 and 18585.

Not observed on purpose: a Go node stopped while the Rust node is up. What
the bitmaps show instead is the Rust vote inside QCs that closed at
exactly quorum while Go node6 was down — 121 of 126 QCs in the last
sample, 71 of the 76 for Go-led views.

**A second Rust member was already there.** Go node5 had been stopped by
another session at 06:08:40 and replaced by an N42-26 node under node5's
peer id (`agent=n42/1.0.0/v5` in this node's peer list), voting but not
proposing; validator 5's bit is set in the QCs, and views led by slot 5
time out (6 s) before a TC hands the view to slot 6. So during this run
the committee was Go 0–4, N42-26 as 5, n42-rs as 6 — quorum 5 of 7, both
Rust nodes needed for any QC that lacks one Go vote. Nothing of node5's
was touched here.

## What the fleet refused, and the fixes

Each item was found by the fleet refusing to work, in this order.

**1. `MobileRegistryRoot`, the 23rd header field.** Every chain-94 header
since the `mobileAnchor` fork is a 23-item RLP list: gov5's codec writes
its optional tail "up to the last non-zero field, an empty-string
placeholder for any nil gap", and its producer leaves `blobGasUsed`,
`excessBlobGas` and `requestsHash` nil while stamping a zero
`MobileRegistryRoot` — so items 17, 18, 20 and 21 are `0x80` and item 22 a
32-byte zero (block 13,560,300, `qs-block-rlp`). `alloy`'s decoder stops
at the placeholder `requestsHash`; its encoder cannot write the tail; and
alloy 2.3's own 22nd/23rd fields (`block_access_list_hash`,
`slot_number`) are a different type at position 23. `n42-h2-consensus::header_profile`
now has gov5's codec: `Gov5HeaderExtension { mobile_registry_root }`,
`encode_gov5_header` / `decode_gov5_header` / `gov5_header_hash` (equal to
`Header::hash_slow` when the extension is empty), `Gov5ForkSchedule`
(reads `mobileAnchorTime` from the genesis; `extension_at(timestamp)` is
the zero root under the fork, nothing before). It is carried through the
Engine API in the vendored `ExecutionPayloadV1` as `mobileRegistryRoot`
(absent on every other chain; every deserializer helper reads it), so
`reconstruct_gov5_h2_block` returns the extension and the engine validator
seals the block with gov5's hash (`SealedBlock::new_unchecked`) after
checking the field is present exactly under the fork. `decode_block_rlp`
reads it off the wire, `encode_block_rlp_parts` writes it,
`Gov5HeaderExtension::recover(header, hash)` finds it for blocks served
from the execution layer (whose stored header lacks the field — reth
stores alloy's header, the hash separately), leaders stamp it
(`normalize_to_gov5_h2` with the schedule), and `ChainBlock` carries the
execution layer's hash instead of rehashing. Pinned against the real
header: bytes, hash `0x9f117dba…`, payload round trip with the block's 28
transactions and its two rewards (`chain94_tests`).

**2. `requestsHash` nil under Prague.** Chain 94's headers carry no
requests hash although `pectraTime` is active (the `FinalizeAndAssemble`
fill-in of 2026-07-02 does not reach the miner's path). The execution
layer's consensus rules now accept a missing requests hash on a Prague
block when execution produced no requests, and the reconstruction tries
"none" as a fourth spelling of the empty hash; a leader writes none under
the mobile-anchor fork and gov5's empty trie root before it.

**3. Signing without `interopV4`.** Chain 94's spec has no `interopV4`, so
gov5 signs its original messages: `view ‖ hash` for proposals and votes,
`"commit" ‖ view ‖ hash` for commit votes, `"timeout" ‖ view`, `"newview"
‖ view` — under the same proof-of-possession ciphersuite as v4. The
engine's native profile differs for proposals (adds a changes hash) and
commits (78 bytes, not 46). `ConsensusSigningProfile::Gov5Legacy` is that
profile; `h2_validator` selects it when the genesis has no `interopV4`,
and every gov5-behaviour gate (import-gated votes, import evidence kept
across views, the extends rule) keys on `is_gov5()`, which both gov5
profiles satisfy.

**4. A slot changed and restored within the block.** The first 875 blocks
imported with matching roots; block 13,561,251 did not (`computed
0xae5921f4…`, header `0x065cc14c…`). Every account balance and nonce the
block touched agreed with node0's historical reads (gov5's
`eth_getStorageAt` ignores the block tag, so storage could not be read
back; the ERC-20 slots were recomputed from the Transfer logs instead and
agreed too). The difference was a slot the block did not appear to
change: `0xe4fade81…`'s balance of `0x0417b930…` received 52 in
transaction 9 and paid 52 in transaction 18. gov5 writes it —
`BufferedPlainStateWriter.WriteAccountStorage` refuses to short-circuit on
`original == value`, and a QMDB write is an append: new slot, old one
deactivated, different root for the same value. revm drops exactly that
slot from its bundle (`TransitionAccount::update`: "if new value is same
as original value, remove storage entry"), and the bundle is all reth
hands the state-root job. `N42EvmConfig` wraps reth's Ethereum EVM
configuration with a block executor that sees every transaction's result
before it is committed and records, for each slot the transaction
changed, the value it had when the block began; at `finish` the block's
list is filed under keccak(parent hash ‖ transaction hashes), and the
root job — and the payload builder — add a rewrite for every slot the
bundle lost (`with_restored_slots`; a zero value is a deletion of nothing
and stays out). After the rebuild block 13,561,251 validated (`leaf: slot
rewritten (changed and restored within the block, as gov5 writes it)`).
Not covered: a slot changed and restored within a single transaction,
which revm reports as unchanged and gov5's journal still marks dirty; not
seen on chain 94's traffic.

**5. A finalised block the execution layer never had.** After the failed
import, `h2_validator`'s checkpoint held the fleet's commit as
`last_committed_qc`; the driver used it as the finalised block of the
catch-up forkchoice, and reth answered `-38002 Invalid forkchoice state`
for every pulled block. The validator now checks the recovered head against
its execution layer and starts from genesis when it is unknown, and the
driver's pull falls back to no finalised block on -38002 until the next
commit.

Tests added or extended: twig-core leaf form (6), qmdb-reth delta log,
restored slots and registry (3), header codec against the real chain-94
block (5), Gov5Legacy messages and ciphersuite (2), the range-serving test
re-linked through `ChainBlock::hash`; all 28 suites of the touched crates
pass (`cargo test -p n42-twig-core -p n42-qmdb-state -p n42-qmdb-reth -p
n42-h2-consensus -p n42-h2-net -p n42-h2-execution -p n42-h2-el-rpc -p
n42-h2-node -p n42-engine-types`).

## Sizes and timings, collected

| | |
|---|---|
| node6 copy `mdbx.dat` | 12.9 GB |
| state dump | 6.5 s, 151 MB RSS, 563 MB JSONL, 6,120,111 accounts / 37,383 slots |
| QMDB leaf-form export | 19 s, 3.6 GB RSS, 2.35 GB, 30,933 twigs, 6,157,495 live of 63,349,357 slots |
| `n42-init-snapshot init` (debug) | 7 min 57 s, 19.5 GB peak, 5.0 GB datadir |
| forest restore, base only (debug) | 100 s |
| forest restore, base + 1,909 deltas (release) | 35 s |
| range pull + import, debug | 32 blocks/s |
| `newPayload` → vote, release | 4.1 ms p50, 4.3 ms p90 |
| QMDB root per block, release | 2.7 ms p50 |
| execution layer RSS | 9.2 GB (release), 9.5 GB (debug) |
| validator RSS | 112 MB |
| Rust-led blocks in the last 151 | 25 (up to 150 transactions each) |

## Prague, EOF and the rest of the uncovered list — 2026-08-29, second pass

Done offline while the whole box was paused for a stress test (the operator
stopped the qs fleet, this node and the watchdog at 08:36:16; nothing was
started again — the rollout is described at the end of this section).
Reference data: the node6 snapshot copy (`qs-snapshot/qs-node6`, MDBX head
13,560,375), the state dump made from it, and gov5's source in the scratch
checkout.

### What chain 94 actually runs

gov5's rules for chain 94 come from `mainnet_qmdb_staggered.json`:
`pectraTime` 1746612311, `osakaTime` = `eofTime` = `fusakaTime` 1765238400
(2025-12-09), `glamsterdamTime` 1798761600 (2027-01-01, not yet),
`mobileAnchorTime` 1784372000. There is no `pragueTime`: gov5's `Rules`
cascade (`IsPectra → IsPrague`) turns the Prague rules on for execution,
but the `ChainConfig.IsPrague(time)` *method* stays false, and a few
things key on the method — the header's `requestsHash` (never stamped by
the live producer), and the transaction pool's admission of set-code
transactions (`validateSetCodeStructure` refuses type 4 on chain 94).
The Rust genesis carries `pragueTime` = `pectraTime` so reth activates
Prague; it also carries `osakaTime`, so revm runs its Osaka set.

What each side executes, and where they differ:

| item | gov5 on chain 94 | revm 42 / reth 2.5.1 here | status |
|---|---|---|---|
| EIP-7702 set-code tx (type 4) | executed under the cascade (`applyAuthorizations`: chain id 0 or 94, nonce < 2^64−1, signer recovery, empty-or-delegated code, nonce match, 25000−12500 refund for an existing authority; intrinsic 25000/auth; delegated target warmed) — but the pool never admits one, so no Go leader builds one | same semantics (revm Prague) | aligned; **the Rust pool now refuses type 4 on gov5 chains too**, so this node never proposes a transaction class the fleet has never executed |
| EIP-2935 | `StoreParentBlockHash` writes slot `(n−1) mod 8191` directly when the contract has code | system call into the contract at `0x…2935` | same state (the alloc code is the canonical contract); matched over 2,000 live blocks |
| EIP-4788 | direct `SetState` of the two ring-buffer slots | system call | same state, matched live |
| EIP-7002 / 7251 | `SysCallContract` from `0xffff…fffe`, output discarded (`ProcessExecutionBlockEnd(nil receipts, …)` and `_, err :=`) | system calls, output becomes `requests` | state matched live; **requests were a divergence: fixed** (below) |
| EIP-6110 deposits | never collected on this path | parsed from logs at the mainnet deposit address | no contract there (alloc has none, the address is unreachable by `CREATE`/`CREATE2`), so never non-empty; covered by the requests fix anyway |
| `requestsHash` | nil on every live-produced header (13,536,951 →); the replayed range below carries gov5's empty trie root | was: nil accepted only when execution produced no requests | **fixed**: nil commits to nothing |
| EIP-7623 floor gas | `rules.IsPrague` | Prague | same |
| EIP-7825 tx gas cap (2^24) | `ValidateTxGasLimit` exists but is called only from the Engine API validator — never for the chain it builds and validates | revm refuses the tx (`TxGasLimitGreaterThanCap`) under Osaka | **divergence, fixed**: the cap is lifted on gov5 chains; the block gas limit (30,000,000 in the replayed range, **480,000,000** in live production) is the only bound |
| EIP-7934 block RLP limit | not enforced on this path | not enforced by `HotStuffConsensus` either (reth's check lives in its payload builder, which caps what this node builds at 8 MiB) | aligned for validation |
| EIP-7883/7823 MODEXP, EIP-7951 P256VERIFY (`0x100`), EIP-7939 CLZ, EIP-2537 BLS | Osaka/Fusaka sets | revm Osaka | same |
| EIP-7843 SLOTNUM (`0x4b`) | in gov5's Fusaka table: pushes `BlockContext.Slot`, which nothing sets on chain 94 (0), 2 gas | invalid opcode (halt, all gas) | **inherent**: an Amsterdam opcode gov5 ships early; a contract executing `0x4b` diverges. None does: the 29 contracts in the state were disassembled, no reachable `0x4b` |
| EOF opcodes `0xe0–0xee` in *legacy* code | `requireEOFExecution` → `ErrInvalidOpCode` (all gas) | `OpcodeNotFound` (all gas) | same outcome |
| EIP-8024 DUPN/SWAPN/EXCHANGE in legacy code, EIP-7954 64 KiB code, EIP-7708/8037/2780 | Glamsterdam, 2027-01-01 | revm Amsterdam has 7954; the rest not | not active; revisit before 2027 |
| EOF containers | `eofTime` active: a `0xEF00` initcode or deployed container is parsed and run as EOF (`SetCodeOptionalHash`/`SetCallCode` parse it; legacy `CREATE`/`CREATE2` still refuse to *deploy* one — `allowEOFDeploy` is true only for `EOFCREATE`) | no EOF; the bytes run as legacy code and halt on `0xEF` | **inherent**; now **guarded** (below) |

Evidence from the chain (`chain94-scan-linux.go` and `chain94-hdr-linux.go`
in the gov5 scratch checkout, over every block MDBX still holds —
12,582,912 → 13,560,375, the 977,464 blocks since 2026-05-27; older
blocks are in the era files):

- 2,863,290 transactions: 352,067 legacy, 2,511,223 type 2, **no type 4**,
  no blobs; 10 creations, none with `0xEF00` initcode; no call to the
  2935/4788/7002/7251 contracts or the deposit address; the largest
  transaction gas limit 1,746,392 (nothing above 2^24 — yet).
- The Code table holds 20 distinct blobs, none `0xEF00`, none `0xEF01`,
  the largest 12,291 bytes; the state dump's 29 contracts, disassembled
  with jump-destination reachability, execute no fork-specific opcode.
- Headers: 12,582,912 → 13,536,950 carry `requestsHash` =
  `0x56e81f17…` (gov5's empty trie root), `blobGasUsed` = `excessBlobGas`
  = 0, no `mobileRegistryRoot`, gas limit 30,000,000 — the replay-v2
  resealed shape. From 13,536,951 (2026-08-19, live production):
  `requestsHash` nil, the blob fields nil or 0 by producer,
  `mobileRegistryRoot` set, gas limit 480,000,000. 954,039 headers with a
  requests hash, 23,425 without.

### What changed on this branch

1. **Requests hash** (`HotStuffConsensus::validate_block_post_execution`).
   A Prague header without a requests hash is accepted whatever execution
   returned — gov5 never commits to requests, and a withdrawal or
   consolidation request (a call to `0x…7002`/`0x…7251` with the fee)
   would have had this node refuse a block every Go node accepts. A header
   that carries a hash is still held to it, in either empty spelling.
   Test: `a_header_without_a_requests_hash_commits_to_no_requests`.

2. **EIP-7825 lifted on gov5 chains** (`N42EvmConfig::evm_env`,
   `next_evm_env`, `evm_env_for_payload` set `tx_gas_limit_cap` to
   `u64::MAX` when the genesis declares a gov5 HotStuff chain —
   `is_gov5_chain`: a `hotstuff` block without `interopV4`). The pool and
   the payload builder read the same environment. Tests:
   `the_transaction_gas_cap_is_lifted_on_a_gov5_chain_only`,
   `a_transaction_above_the_eip7825_cap_executes_on_a_gov5_chain` (a
   20,000,000-gas transaction executes on the gov5 chain and is refused
   with the cap error on the `interopV4` one).

3. **No set-code transactions from this node on gov5 chains**
   (`N42PoolBuilder`: `set_eip7702(false)`), matching gov5's pool.
   Validation of a type-4 transaction in a block is unchanged (revm's
   Prague rules; gov5 would execute it the same way if one ever appeared).

4. **EOF guard** (`EofGuardEvmFactory`, `TrackingExecutor`). Every EVM
   this node creates — validation, building, prewarming — has the
   instruction-table entry for opcode `0xEF` replaced: when the frame's
   code starts with `0xEF 0x00` it records the frame (address, initcode or
   code, length) in a thread-local before halting exactly as revm's
   `unknown` does. Execution of a container starts at its first byte, so
   this catches an initcode container in a creation transaction, in a
   `CREATE`/`CREATE2`, a deployed container that is called, and a
   container behind a 7702 delegation. The executor reads the record after
   each transaction and fails the block with
   `EOF_REQUIRED: block N transaction 0x… executes an EOF container
   (initcode|code, L bytes, magic 0xEF00) at 0x…; revm has no EOF and would
   diverge from gov5, so the block is refused` — logged at `ERROR` on
   `n42::evm`, counted in `n42_evm_eof_required_total`. A refused block is
   `INVALID` to `newPayload`, so the validator does not vote for it; a
   transaction that trips the guard while building fails the build, so the
   node does not propose (the view times out and passes). Not caught: a
   container that is inspected but never executed (`EXTCODESIZE` and
   friends answer differently under EOF rules). Tests:
   `a_creation_with_eof_initcode_is_refused_loudly`,
   `calling_deployed_eof_code_is_refused_and_names_the_account`,
   `a_stray_ef_byte_in_legacy_code_is_only_an_invalid_opcode` (`0xEF01`
   and a stray `0xEF` stay ordinary invalid opcodes).
   Not verified on a devnet block: no node could be started.

5. **Intra-transaction slot restores** (item 4's remainder). gov5's
   `SetState` journals a slot on the first store of a value other than the
   one it holds, and `dirtyKeys` keeps it through a later store of the old
   value and through the revert of the storing frame (`storageChange.revert`
   calls `setState`); at commit every dirty key is written with its block
   value, original or not. The `SSTORE` entry of the instruction table is
   wrapped to record every successful store; after the transaction, a slot
   with a recorded store whose value differs from the slot's value at the
   transaction's start is filed like a changed slot (with that value), and
   the existing restored-slot path rewrites it for the root job. Tests:
   `a_slot_stored_and_restored_within_a_transaction_is_filed_with_its_value`,
   `a_store_of_the_value_the_slot_holds_is_not_dirty`,
   `a_store_in_a_reverted_frame_still_dirties_the_slot`,
   `a_changed_slot_is_filed_once_with_the_value_before_the_transaction`.
   Not verified against a chain-94 block: none in the 2,000 executed live
   showed the case, and the offline harness has no chain-94 pre-state.

6. **Persistence at shutdown.** `persist_now` is idempotent (nothing to
   write when the base stands at the head with no log after it) and
   reports whether it wrote; `persist_for_shutdown(db_head)` writes the
   base only when the forest stands at the block the database will report
   as its head at the next start — advancing it there first when it lags
   and holds the block, leaving the log alone when it is ahead (a forest
   cannot rewind). `n42 node` calls it after the node's exit future
   resolves, from the database's own head; the canonical stream's close
   still calls `persist_now`, and whichever runs first does the write. On
   the last two restarts the database head equalled the last canonical
   block (13,562,284 both in the log and at the restart), so the write
   will normally happen. Test extended:
   `canonical_blocks_go_to_the_delta_log_and_a_restart_replays_them`.

Suites: `cargo test -p n42-engine-types` (26), `cargo test -p
n42-qmdb-reth` (23); `cargo check -p n42`.

### Rollout (for the operator, after the stress test)

Release binaries are built from this commit in `target/release`
(`n42`, `examples/h2_validator`; the validator binary is unchanged in
behaviour but rebuilt with the tree). Then, with the qs fleet up and Go
node6 still stopped:

1. `touch /data/blockchain/wr-logs/soak-20260829/STOP` if the watchdog is
   running (it is not, since 08:36).
2. `cd /data/blockchain/mixed-fleet/n42-rs-qs && ./start-el.sh <tag>`;
   wait for `QMDB state ready` in `logs/el-<tag>.log` (the forest replays
   the delta log this once; after this build's first clean SIGTERM the
   base is folded at exit and the next start is immediate). Expect
   `gov5 chain: the pool refuses EIP-7702 set-code transactions` in the
   log.
3. `./start-validator.sh <tag> --propose`; confirm lag 0 against 20012
   and the slot-6 bit in fresh QCs: `python3 qc-evidence.py
   http://127.0.0.1:20012 <head-60> <head>`.
4. Watch for `EOF_REQUIRED` in the execution layer log (there should be
   none) and `n42_evm_eof_required_total` on the metrics endpoint.
5. Restart the watchdog: first make it append rather than truncate —
   in `soak-watchdog.sh` replace the `echo "ts,go_head,…" > $S/soak.csv`
   line with `[ -s $S/soak.csv ] || echo "ts,…" > $S/soak.csv` — then
   `rm STOP` and `setsid nohup ./soak-watchdog.sh > watchdog.out 2>&1 <
   /dev/null &`.

To hand the slot back to Go node6: stop the Rust validator first, then
`./roll-one-node.sh --node 6 …`.

## Still open

- **EOF** (`eofTime` active): revm 42 has none, and no EOF can be added
  here. The guard above makes the node refuse — loudly — rather than
  diverge; a chain-94 block that executes an EOF container would leave
  this validator out of that block's QC and every later one until Go
  node6 takes the slot back. No such code exists on the chain (scan
  above). Also inherent, and unguarded because it needs no execution:
  `EXTCODESIZE`/`EXTCODEHASH`/`EXTCODECOPY` of a deployed container.
- **SLOTNUM (`0x4b`)**: gov5 executes it (pushes 0) from its Fusaka table;
  revm halts. No deployed contract reaches it; a new one could. Could be
  aligned by inserting the opcode the same way the guard is inserted, if
  gov5 keeps it.
- **Glamsterdam** (2027-01-01): gov5's Amsterdam set (EIP-7708 transfer
  logs, 8037/8038/2780 gas, 8024 stack ops, 7954 code size) is not in
  revm 42's Osaka; this node must not be in the committee past that
  timestamp without an Amsterdam-capable revm or an aligned gate.
- **Intra-transaction slot restores** and the **EOF guard** are verified
  by unit tests only; no chain-94 block or devnet block could be run while
  the box is paused.
- **Persistence at shutdown** is wired but not yet observed on a live
  restart (the node was down when the code landed).
- **The forest is still in memory whole**: 9 GB RSS for 63 M slots, of
  which 57 M are dead. `entries` could be sparse; leaf hashes are 2 GB.
- **Proofs for keys in hollow twigs** would be wrong; no such twig existed
  in this export (all 30,933 had leaf hashes), and the builder refuses a
  hollow twig with live bits.
- **gov5's `eth_getStorageAt` ignores the block tag** — worth a note in
  gov5, it cost an hour here.
- The gov5 exporter change (`--leaf-form`) lives in the scratch checkout
  and in `docs/gov5-qmdb-export-leaf-form.patch`; it belongs on gov5's
  main.
