# Header field parity: Ethereum's trailing fields and N42's `MobileRegistryRoot`

Status: 2026-10-30.

- gov5 side: implemented on gov5 branch `design/header-field-parity` (not
  pushed). The patches are in `docs/patches/gov5-header-field-parity/`.
- Rust side: a fixture test pins today's behaviour
  (`crates/n42/h2-consensus/tests/header_field_parity.rs`), and section 8 is the
  implementation spec for carrying field 24.

Ethereum keeps appending optional fields to the end of the execution block
header. gov5 (the Go client) appended one of its own, `MobileRegistryRoot`, and
Amsterdam's EIP-7843 `slot_number` landed on the same RLP position.

## 0. Decisions (user)

1. **The root moves on a conflict.** "If the mobile root in the header
   conflicts with an Ethereum field, it moves to the next position." So
   `slot_number` is element 23 (EIP-7843, execution specs) and
   `MobileRegistryRoot` is element 24.
2. **The layout is purely fork-gated, with no legacy decode rule.** From the
   activating fork, element 23 is the slot and element 24 is the root. Before
   it the header ends at element 21 or 22. Chain 94 already holds headers with
   the root at element 23. Nothing reads that layout any more: it is rebuilt
   with gov5's `replay-v2` under the new fork schedule (section 5).
3. **The Rust side carries field 24** with a custom N42 header type (section 8).

## 1. Sources

| Source | What it settles |
| --- | --- |
| execution-specs, Amsterdam `Header` ([blocks.py](https://raw.githubusercontent.com/ethereum/execution-specs/forks/amsterdam/src/ethereum/forks/amsterdam/blocks.py), [diff view](https://ethereum.github.io/execution-specs/diffs/amsterdam/bogota/blocks.py.html)) | The field order 1-23: `... requests_hash, block_access_list_hash: Hash32, slot_number: U64`. Nothing comes after `slot_number`. `slot_number` is "the slot number of this block as provided by the consensus layer". |
| [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559), [EIP-4895](https://eips.ethereum.org/EIPS/eip-4895), [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844), [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788), [EIP-7685](https://eips.ethereum.org/EIPS/eip-7685) | Each appends its fields at the end: 16 `base_fee_per_gas`, 17 `withdrawals_root`, 18 `blob_gas_used`, 19 `excess_blob_gas`, 20 `parent_beacon_block_root`, 21 `requests_hash`. |
| [EIP-7928](https://eips.ethereum.org/EIPS/eip-7928) (Last Call, deadline 2026-11-01) | Adds `block_access_list_hash`: the keccak of the RLP access list. The empty list hashes to `0x1dcc4de8…9347`. The EIP gives no position; the specs put it at 22. Engine API: `ExecutionPayloadV4.blockAccessList`, `engine_newPayloadV5`, `engine_getPayloadV6`. |
| [EIP-7843](https://eips.ethereum.org/EIPS/eip-7843) (Last Call, deadline 2026-11-01) | Adds `slotNumber`, a big-endian `uint64`. Also the opcode `SLOTNUM` (`0x4b`, gas 2), and `slotNumber` in `ExecutionPayloadV4` and `PayloadAttributesV4` (`engine_forkchoiceUpdatedV4`). The EIP gives no position; the specs put it at 23. |
| [EIP-7773](https://eips.ethereum.org/EIPS/eip-7773) (Glamsterdam meta) | Scheduled for inclusion: 2780, 7688, 7708, 7732, 7778, 7843, 7928, 7954, 7976, 7981, 7997, 8024, 8037, 8038, 8045, 8061, 8246, 8282. Only 7928 and 7843 add an execution-header field. [EIP-7732](https://eips.ethereum.org/EIPS/eip-7732) (ePBS) changes consensus-layer containers only ("No other changes are required" on the EL). [EIP-7778](https://eips.ethereum.org/EIPS/eip-7778) changes how `gas_used` is counted, not the header shape. **No field after `slot_number` is scheduled.** |
| go-ethereum master [`core/types/block.go`](https://raw.githubusercontent.com/ethereum/go-ethereum/master/core/types/block.go) | `BlockAccessListHash *common.Hash rlp:"optional"`, then `SlotNumber *uint64 rlp:"optional"`, last. |
| go-ethereum master [`consensus/beacon/consensus.go`](https://raw.githubusercontent.com/ethereum/go-ethereum/master/consensus/beacon/consensus.go) `verifyHeader` | Amsterdam gate: "header is missing block access list hash", "header is missing slotNumber". Before Amsterdam, either field present is invalid. |
| go-ethereum [`rlp/doc.go`](https://raw.githubusercontent.com/ethereum/go-ethereum/master/rlp/doc.go) | `optional`: "the output RLP list contains all values up to the last non-zero optional field", and "optional fields may be omitted from the end of the input list". Without the `nil` tag, "input values must match the required input length exactly". |
| erigon main [`execution/types/block.go`](https://raw.githubusercontent.com/erigontech/erigon/main/execution/types/block.go) | The same order: `... RequestsHash, BlockAccessListHash, SlotNumber *uint64` (EIP-7843). Hand-written `EncodeRLP`/`DecodeRLP`: an optional is written only when non-nil, and the decoder checks `s.MoreDataInList()` before each one. A hash must be 32 bytes. |
| alloy-consensus 2.5.0 `src/block/header.rs:149,161,404-544` | `block_access_list_hash: Option<B256>`, then `slot_number: Option<u64>`, last. `Encodable` writes each `Some` in order and never a placeholder. `Decodable` reads optionals while payload remains, and returns `ListLengthMismatch` for anything after `slot_number` (`:536-541`). |
| reth v2.8.1 `crates/ethereum/consensus/src/lib.rs:250-263` | Under `is_amsterdam_active_at_timestamp`: `BlockAccessListHashMissing` and `SlotNumberMissing`. Before Amsterdam: `SlotNumberUnexpected`, and `BlockAccessListHashUnexpected` unless `allow_bal_hashes`. |
| reth-codecs 0.8.2 `src/alloy/header.rs:24-66` | The storage `Compact` form of the alloy header: `extra_fields: Option<HeaderExt { requests_hash, block_access_list_hash, slot_number }>` before the trailing `extra_data`. This is the extension pattern for new fields (reth issue 7820). |

**Fewer trailing fields.** All four clients stop at the end of the list, and a
missing trailing field means "not this fork":

- geth and gov5 use struct `optional` tags;
- erigon checks `MoreDataInList`;
- alloy compares the bytes consumed against the list length.

None of them can skip a field in the middle except gov5. Its tags are
`optional,nil`, so it writes an empty string (`0x80`) for every nil optional
that sits before a non-nil one, and it reads `0x80` back as nil. geth, erigon
and alloy all refuse that empty string where a hash is expected. This is gap 2
in section 7.

## 2. The field table

Positions are 1-based RLP list elements.

| # | Ethereum spec | geth master | erigon main | alloy 2.5.0 / reth 2.8.1 | gov5 before 65f2c63f | gov5 now |
| --- | --- | --- | --- | --- | --- | --- |
| 1-15 | parent_hash … nonce | same | same | same | same | same |
| 16 | base_fee_per_gas (1559, London) | BaseFee | BaseFee | base_fee_per_gas | BaseFee | BaseFee |
| 17 | withdrawals_root (4895, Shanghai) | WithdrawalsHash | WithdrawalsHash | withdrawals_root | WithdrawalsHash (N42: the rewards commitment) | same |
| 18 | blob_gas_used (4844, Cancun) | BlobGasUsed | BlobGasUsed | blob_gas_used | BlobGasUsed | same |
| 19 | excess_blob_gas (4844, Cancun) | ExcessBlobGas | ExcessBlobGas | excess_blob_gas | ExcessBlobGas | same |
| 20 | parent_beacon_block_root (4788, Cancun) | ParentBeaconRoot | ParentBeaconBlockRoot | parent_beacon_block_root | ParentBeaconRoot (N42: Blake3 of the parent's committee evidence) | same |
| 21 | requests_hash (7685, Prague) | RequestsHash | RequestsHash | requests_hash | RequestsHash | same |
| 22 | block_access_list_hash (7928, Amsterdam) | BlockAccessListHash | BlockAccessListHash | block_access_list_hash | BlockAccessListHash (`balTime`) | same |
| 23 | slot_number (7843, Amsterdam) | SlotNumber | SlotNumber | slot_number | **MobileRegistryRoot** (`mobileAnchorTime`) | SlotNumber (`glamsterdamTime`) |
| 24 | none | none | none | none (refused: `ListLengthMismatch`) | none | **MobileRegistryRoot** (`mobileAnchorTime` and `glamsterdamTime`) |

gov5 code locations:

- `common/block/header.go:94-119`: `BlockAccessListHash` (22), `SlotNumber` (23), `MobileRegistryRoot` (24). The struct order since gov5 `65f2c63f`.
- Trailer codec, `header.go:293-448`: flag bit `0x40` for the root, `0x80` for the slot.
- Compact codec, `common/block/header_compact.go:73-75`: `hcfBlockAccessListHash` 1<<19, `hcfMobileRegistryRoot` 1<<20, `hcfSlotNumber` 1<<21.

## 3. The collision and its history

- **gov5 `059bddd3` (phase 6c)** added `MobileRegistryRoot` right after
  `BlockAccessListHash`, which made it element 23.
  - The leader stamps it under `mobileAnchorTime` (`internal/miner/worker.go:1789-1799`).
  - Before this change, verifyHeader made it mandatory after the fork and
    forbidden before it.
  - `cmd/n42/cmd.go:215`: on that chain the feature cannot be switched off.
- **Chain 94** (`params/chainspecs/mainnet_qmdb_staggered.json:26` in gov5)
  has `mobileAnchorTime` 1784372000 (2026-07-18 10:53:20 UTC). Since then it has
  sealed every header with a 32-byte string at element 23 and an empty string
  at 22 (`balTime` is unset).
- **Amsterdam's `slot_number`** is element 23 in every Ethereum client. The
  collision is by position and by kind: a `u64` against a 32-byte hash.
- **gov5 `65f2c63f` (2026-10-29)** gave `SlotNumber` element 23 and moved the
  root to 24 in the struct order. An eth-el Amsterdam header now hashes as
  geth's does (`internal/devp2p/header_amsterdam_geth_test.go`). Chain-94
  history (root at 23) no longer decodes: the 32-byte element does not fit the
  `*uint64`.

## 4. The rule

**Layout.** From gov5's Amsterdam fork, `glamsterdamTime` (`params/config.go:245`;
`IsGlamsterdam`, `params/config_rules.go:395`), a native-chain header carries
`SlotNumber` at element 23. If MobileAnchor is also active, it carries
`MobileRegistryRoot` at element 24. The root's gate is the new
`params.ChainConfig.IsMobileRegistryRootInHeader` (`config_rules.go:446-456`):
`IsMobileAnchor(t) && IsGlamsterdam(t)`. A `mobileAnchorTime` earlier than
Glamsterdam therefore takes effect at Glamsterdam, and a header never carries
the root without the slot. That rules out the ambiguous "empty 23, root at 24"
shape.

If Ethereum ever adds a field 24, the same rule moves the root to 25, behind
the fork that activates that field.

**Why `glamsterdamTime`, and no new `slotNumberTime`:**

- gov5 already gates the `SLOTNUM` block context on it (`internal/evm.go:84`).
- It gates the Amsterdam Engine-API header shape too
  (`internal/api/engine_payload_validation.go:255-270`, `engine_overlay.go:177`).
- Ethereum activates the field with Amsterdam, so a separate knob could only
  drift away from it.

The BAL hash keeps its own gate, `balTime` (gap 2).

**Which value goes in the slot.** EIP-7843 takes the slot from the consensus
layer. A HotStuff chain has views, not slots, and the view sits inside `Extra`,
where no Ethereum client sees it. Both clients use the **block number**: it is
the one monotonic index derivable from the header alone. The Rust client
already does this:

- `crates/n42/h2-el-rpc/src/engine.rs:1373-1380` (JSON path): the V4 payload's
  `slot_number` is the number.
- `engine.rs:2666-2675` (raw path): `header.slot_number = Some(number)` in the
  sealed header.
- `crates/n42/h2-consensus/src/header_profile.rs:441,515,527`: payloads carry
  `slot_number: header.number`.
- `crates/n42/h2-execution/src/driver.rs:653` orders builds by it.

gov5 now does the same (`NativeSlotNumber`, `internal/consensus/hotstuff/adapter.go:1137`).

**No context-free disambiguation.** Element 23 is a `u64` (at most 8 content
bytes) in Ethereum's layout and a 32-byte string in chain 94's old one, so a
decoder *could* tell them apart. By decision 2 neither client does. The header
codecs know one layout, and old data is rebuilt instead.

## 5. Old chain-94 data: the replay-v2 operator step

gov5's `replay-v2` (`cmd/n42/replay_v2_cmd.go`, engine `internal/replay/engine_v2.go`)
re-executes a source datadir into a new target datadir.

**It builds every target header itself.** It does not copy source headers:

- `newHeader := &block.Header{...}` at `engine_v2.go:1071`, and synthetic gap
  blocks at `:817`.
- `Extra` is a fresh 32-byte vanity.
- The state root comes from the target's tree, and the tx and receipt roots are
  recomputed.
- The withdrawals root is the rewards hash, and `ParentBeaconRoot` is Blake3 of
  the parent's target consensus evidence.
- Blob gas is zero, and `RequestsHash` is the empty-list root.

**Before this change it wrote nothing after `RequestsHash`.** No BAL hash, no
slot, no root. So under any config replay produced 21-element headers, and a
target config with Glamsterdam inside the replayed range produced headers that
the live verifier refuses. The third gov5 commit (`081804f6`) adds
`stampForkHeaderFields` (`engine_v2.go:1727`), called at `:836` (gap blocks)
and `:1094` (replayed blocks). It stamps exactly what the target config
schedules, the way live production does:

- `SlotNumber` = the target block number, from Glamsterdam.
- `MobileRegistryRoot` under `IsMobileRegistryRootInHeader`. The root is copied
  from the source block, because it is a leader-provided commitment that
  followers store verbatim. A gap block, or a source block without one, gets
  the last source root seen. If the target needs a root before the source ever
  had one, replay stops with an error that names the fork to move.

**Where the fork time comes from.** `replay-v2 --chain <name>` resolves the
target config with `params.ChainConfigByChainName` (`replay_v2_cmd.go:100`).
That returns the chainspec embedded at build time (`params/config.go:44`
`go:embed chainspecs`, `:158` `mainnet_qmdb_staggered.json`). Changing a fork
time therefore means editing that JSON (or adding a chain name) and rebuilding
gov5. The command binds the target datadir to the chain name and genesis hash
(`validateReplayTargetNetworkBinding` `:106`, `persistReplayTargetNetworkBinding`
`:195`).

**The step for chain 94:**

1. Build gov5 with this branch. The fields to set in the target chainspec are:
   - `glamsterdamTime`: the slot fork, and so the root's effective fork;
   - `mobileAnchorTime`: no earlier than `glamsterdamTime` (an earlier value
     has no effect before Glamsterdam).

   gov5's own `mainnet_qmdb_staggered.json` schedules no `glamsterdamTime` at
   all. So with that file unchanged, replayed chain-94 headers carry neither the
   slot nor the root and end at element 21, and live production keeps not
   stamping the root until Glamsterdam is scheduled.
2. Run:

   ```
   n42 replay-v2 --source <live chain-94 datadir> --target <new datadir> \
     --chain mainnet_qmdb_staggered --tree qmdb --bls-reseal --bls-seed <seed> [...]
   ```

   Use the same flags as the base the fleet was built from.
3. Start every member from the new datadir. Do not reuse old datadirs:
   - `CheckCompatible` (`params/config.go:960-1000`) does not cover
     `MobileAnchorTime`, so a node started on an old datadir would not notice
     the config change. It would only fail later, decoding the root at 23.
   - The live chain-94 headers since 2026-07-18 do not decode under the new
     layout (section 3).

**What happens to the hashes.** Every replayed block gets a new hash. replay-v2
re-seals all headers (new `Extra`, roots, consensus evidence), and the dropped
or moved root changes them further. Block 0 is not replayed, and the genesis
header does not depend on these fork times, so the genesis hash, chain id and
fork digest stay the same. Everything above genesis is a different chain. This
is a **coordinated re-genesis on the same chain id**: every member restarts
from the same replayed base, and anything that pinned an old block hash
(explorers, mobile anchors, bridges) must be rebased. A new chain id is not
needed, since no old and new member can peer past genesis, but it is the safer
choice if old nodes might stay online.

**Caveats:**

- Replay executes transactions under the target config's rules. Moving
  `glamsterdamTime` into the replayed range re-executes those blocks with
  gov5's Glamsterdam rules (EIP-7904 repricing, `SLOTNUM`). State, gas and
  receipts then differ from the source. Keep `glamsterdamTime` after the
  replayed range unless that is intended.
- The root copied for history is the source's value. If `mobileAnchorTime`
  moves later, blocks between the old and new times lose the root from their
  headers. The anchor log (`modules/rawdb/accessors_mobileverify.go`) still
  holds it.

## 6. The gov5 change (branch `design/header-field-parity`, not pushed)

| Commit | Summary |
| --- | --- |
| `d070b88d` feat(hotstuff): stamp the EIP-7843 slot number and gate MobileRegistryRoot behind it | `IsMobileRegistryRootInHeader` (params). The miner (`worker.go:1798`) and `verifyHeaderWithBatch` (`adapter.go:479-492`) gate the root on it. `FinalizeAndAssemble` stamps `SlotNumber = NativeSlotNumber(header)` from Glamsterdam (`:846-850`). `verifySlotNumber` (`:1144`) requires the slot from Glamsterdam, equal to the number, and refuses it before. Tests: `TestVerifySlotNumberByFork`, `TestMobileRegistryRootNeedsGlamsterdam`, `TestVerifyHeader_MobileAnchorForkShape` (rewritten: MobileAnchor 50, Glamsterdam 100), and the `internal/mobileanchor_test.go` config. |
| `e9d3ed36` test(block): pin the Glamsterdam header layout and write cross-client fixtures | A slot binds the hash. Slot plus root is 24 elements and round-trips through RLP, the trailer and the compact codec, with and without a BAL hash. `TestWriteHeaderParityFixtures` writes the Rust fixtures (`N42_HEADER_PARITY_FIXTURE_DIR`). No codec change: the struct order of `65f2c63f` is the layout. |
| `081804f6` feat(replay): stamp the slot number and registry root the target config schedules | `stampForkHeaderFields`, section 5; test `TestStampForkHeaderFields`. |

Checked:

- `go build ./...`.
- `go test -p 4 ./common/block/... ./internal/consensus/hotstuff/... ./params/...`.
- `./internal/replay/`.
- `-run 'Amsterdam|Header|Anchor|Size'` in `internal/devp2p`, `internal/ethel`,
  `internal/miner` and `internal`.

Not changed, noted for the gov5 owner:

- `internal/ethel/stateless/serve/header_rlp.go:25-60` hand-encodes the header
  up to `RequestsHash` and drops the Amsterdam fields. This is eth-el only.
- `CheckCompatible` does not compare `MobileAnchorTime`.
- `node.go:2534` still describes the stamp as "under IsMobileAnchor". The code
  it refers to now uses the combined gate.

## 7. Header rules each client enforces, and the gaps

Rust:

- `HotStuffConsensus::validate_header` / `validate_header_against_parent`
  (`crates/n42/engine-types/src/hotstuff_consensus.rs:296-406`);
- `validate_gov5_h2_header` and payload reconstruction
  (`crates/n42/h2-consensus/src/header_profile.rs:266-280,576-665`).

gov5: `verifyHeaderWithBatch` and `FinalizeAndAssemble` (`internal/consensus/hotstuff/adapter.go`).

| Rule | Rust | gov5 |
| --- | --- | --- |
| extra = `N42H` + view + [QC] + 96-byte seal, at most 4096 B | yes (`header_profile.rs:199-205`) | yes (`decodeHeaderExtra`) |
| difficulty 0 (1 on a legacy range), nonce 0, ommers hash zero or empty-list | yes (`:266-280`) | no (stamped, not checked) |
| parent by hash, number = parent + 1, time > parent | yes (reth `validate_header_against_parent`) | yes |
| gas used ≤ limit (deferred: the ancestor's limit) | yes | yes |
| base fee re-derived | yes (`validate_header_base_fee`) | no, deliberately (`adapter.go:461-474`) |
| withdrawals root from Shanghai (the rewards commitment) | presence; the value through body checks | stamped, not checked |
| blob gas fields from Cancun | yes (`validate_4844_header_standalone`) | stamped zero, not checked |
| requests hash from Prague | presence; both empty spellings accepted on reconstruction | stamped `EmptyRootHash`, not checked |
| parent beacon root = Blake3(parent committee evidence) | yes (`:395-402`) | yes |
| deferred-execution fields = ancestor's result | yes (`:362-391`) | yes, at import |
| block access list hash | **no presence rule**; reconstruction tries both candidates (`header_profile.rs:604-622`) | gated on `balTime` (dormant everywhere), recomputed at import |
| slot number | **no presence rule**; set to the number when a BAL is present | required from Glamsterdam, equal to the number (new) |
| MobileRegistryRoot | **cannot be represented** | required under MobileAnchor and Glamsterdam, forbidden otherwise (new gate) |

**Gaps to fill:**

1. **The Rust client cannot hold `MobileRegistryRoot`.** alloy refuses every
   gov5 header that carries it
   (`a_gov5_header_with_a_mobile_registry_root_is_refused_by_alloy_today`).
   Block gossip decodes with alloy (`crates/n42/h2-consensus/src/block_body.rs:204,278`,
   `compact_body.rs:320,473,496`), so this is the first refusal a Rust member
   would meet. Section 8 covers it.
2. **gov5's empty-string gaps are not Ethereum RLP.** With `balTime` unset, the
   native header from Glamsterdam is `[…, 0x80, slot, root]`. alloy refuses it
   (`UnexpectedLength`), and so would geth and erigon. reth also requires a real
   BAL hash at Amsterdam. Two ways to close it:
   - (a) gov5 stamps `BlockAccessListHash` from Glamsterdam, which is the
     Ethereum rule. It needs a BAL that is deterministic across both clients,
     and `params/config.go:290-305` says that is not yet validated.
   - (b) `N42Header` reads and writes gov5's gaps. That is gov5's `optional,nil`
     semantics, and it is canonical: a gap is written exactly when a later
     field is set.

   Section 8 specifies (b), because it works with either choice of (a).
3. **Rust has no Amsterdam presence rules in `HotStuffConsensus`.** reth's
   `EthBeaconConsensus` has them; `HotStuffConsensus` does not delegate
   `validate_header` to it.
4. **Fork names differ.** gov5's Amsterdam is `glamsterdamTime`; reth's is
   `amsterdamTime` (alloy-genesis 2.5.0 `ChainConfig::amsterdam_time`).
   `n42-gov5-genesis` (`bin/n42/src/gov5_genesis.rs:21`) carries
   `glamsterdamTime` through inert. The Rust copy of chain 94's genesis
   (`crates/chainspec/res/genesis/gov5/mainnet_qmdb_staggered.json:8316`)
   says `glamsterdamTime` 1798761600 (2027-01-01). gov5's embedded chainspec
   for the chain has none. One of the two is stale.
5. **`mobileAnchorTime` has no Rust spelling.** Section 8 step 4 adds it.
6. **Nothing in Rust consumes or produces the anchor.**
   `crates/n42/mobile-verify` and `crates/n42/mobile-service` never mention a
   registry root. Followers only store the value, so a Rust follower needs just
   the field. A Rust leader on a MobileAnchor chain needs a root provider, the
   equivalent of gov5's `mobileAnchorRoot()` (`worker.go:377-381`).

### 7.1 Rust status (branch `feat/n42-header-field-24`)

Gaps 1-5 are closed on the Rust side; gap 6 is closed for followers only.

- **The node runs on `N42Header`.** `N42Primitives::BlockHeader` is
  `n42_header::N42Header`. reth's `ChainSpec` is not generic over its header,
  so the node's chain spec is `n42_header::N42ChainSpec`, a wrapper over the
  parsed spec whose genesis header is the inner one without a root (same
  hash). `bin/n42` converts at launch with the additive
  `NodeBuilder::map_chainspec`. The CLI's `init` and `db` commands still run
  on `ChainSpec`; root-less headers store byte-identically (8.3).
- **Presence rules (gap 3).** `HotStuffConsensus::validate_header` calls
  `n42_h2_consensus::validate_gov5_header_tail` with
  `HotStuffConsensus`'s `header_tail_rules(genesis, timestamp)`:
  - The slot number is required from Glamsterdam and must equal the block
    number. It is refused before Glamsterdam.
  - `mobileRegistryRoot` is required when MobileAnchor and Glamsterdam are
    both active, and refused otherwise.

  Only presence is checked. The root's **value** is not: gov5 derives it from
  mobile registry state that this node does not keep, and the block hash that
  consensus agreed on covers it. The gate is read from the genesis only.
- **Fork names (gaps 4-5).** Both fork times are read from the genesis by
  `reth_chainspec::qmdb`:
  - `glamsterdam_time` is gov5's `glamsterdamTime` or reth's `amsterdamTime`,
    whichever is earlier.
  - `mobile_anchor_time` is `mobileAnchorTime`.

  The native devnet sets neither. The Rust copy of chain 94 sets both, so the
  question in gap 4 (which copy is stale) is still open.
- **Engine API.** `ExecutionPayloadV4` (alloy fork) gains
  `mobileRegistryRoot`. An empty `blockAccessList` means a header without a
  BAL hash (gov5's gap). `n42_header::engine` carries the root and the slot
  number in both directions. The raw channel encodes a root-carrying V4 as
  kind 5, and headers on it travel as RLP. The SSZ payload form does not carry
  the root, because the N42 engine path does not use it.
- **Gossip.** `block_body.rs` and `compact_body.rs` decode and re-encode
  24-element headers.
- **Leader (gap 6, open).** The Rust builder has no registry root provider.
  It refuses to assemble a block whose timestamp falls under the root gate
  (`assemble_n42_block`), so it never builds a header that other members
  would refuse.
- **Not covered yet.** `n42-init-snapshot` decodes the snapshot head as
  Ethereum's header, so it cannot start a node at a head that carries a
  root. The APoS miner and reth's own `init` / `db` commands stay on
  Ethereum's header (an APoS header never carries a root).
- **Verified (2026-10-30).** The check
  `cargo check -p n42 -p n42-h2-node -p n42-testing --tests --examples` passes.
  So do the tests of `n42-header` (features `chainspec,engine`),
  `reth-chainspec`, `n42-h2-consensus`, `n42-h2-el-rpc`, `n42-h2-execution`,
  `n42-h2-net`, `n42-clique`, `n42-engine-types`, `n42-h2-node` and
  `n42-testing`.

## 8. Rust implementation spec: `N42Header` with field 24

Today `N42Primitives::BlockHeader = alloy_consensus::Header`
(`crates/n42/tx-types/src/primitives.rs:27`). Patching alloy's `Header` is
rejected:

- reth v2.8.1 alone has 45 exhaustive header literal sites in 21 files
  (`crates/ethereum/evm/src/build.rs`, `crates/ethereum/payload/src/lib.rs`,
  `crates/net/eth-wire-types/src/header.rs`,
  `crates/payload/validator/src/amsterdam.rs`, …). Each lives in a git
  dependency we would have to vendor.
- The patch would have to be re-merged on every alloy bump.
- Every chain would accept a 24-element header.

Carrying the root outside the header is impossible: the block hash is
`keccak(rlp(header))` with the root inside.

### 8.1 The type

```rust
/// N42's block header: Ethereum's fields 1-23 (alloy) plus gov5's
/// MobileRegistryRoot at element 24.
pub struct N42Header {
    pub inner: alloy_consensus::Header,
    pub mobile_registry_root: Option<B256>,
}
```

It lives in a new crate `crates/n42/header` (`n42-header`). It depends only on
alloy, alloy-rlp, reth-codecs and reth-primitives-traits, so `tx-types`,
`h2-consensus` and `engine-types` can all use it. It derefs to `inner`
(`derive_more::Deref`/`AsRef`), so the field reads that fill most of the code
keep compiling. reth's own precedent is the `custom-node` example's
`CustomHeader` (reth commit `b3d532ce9`,
`crates/optimism/examples/custom-node/src/primitives/header.rs`; it left the
tree with op-reth after 2.7). We follow it except for the RLP, which must be
flat.

**Traits reth 2.8.1 requires.** `NodePrimitives::BlockHeader: FullBlockHeader`
(`reth-primitives-traits` 0.8.2 `src/node.rs:15`), where
`FullBlockHeader = BlockHeader + MaybeCompact` (`src/block/header.rs:12`).

| Trait | Implementation |
| --- | --- |
| `Send + Sync + Unpin + Clone + Hash + Default + Debug + PartialEq + Eq` | derive |
| `alloy_rlp::Encodable`, `Decodable` | hand-written, flat (8.2) |
| `alloy_consensus::BlockHeader` | delegate all accessors to `inner` (about 25, including `block_access_list_hash`, `slot_number`) |
| `alloy_primitives::Sealable` | `hash_slow` = keccak of our encoding |
| `reth_primitives_traits::InMemorySize` | `inner.size() + size_of::<Option<B256>>()` |
| `MaybeSerde` (`serde::Serialize`/`Deserialize`) | `#[serde(flatten)] inner` + `#[serde(rename = "mobileRegistryRoot", skip_serializing_if = "Option::is_none", default)]`, gov5's JSON name |
| `AsRef<Self>` | trivial |
| `reth_primitives_traits::BlockHeader` | empty impl |
| `reth_codecs::Compact` (`MaybeCompact`, static-file headers segment) | 8.3 |
| `reth_db_api::table::{Compress, Decompress}` (`Headers<H>` table, `crates/storage/db-api/src/tables/mod.rs:331`) | via `Compact`, as the example does |
| `serde_bincode_compat` (`RlpBincode`) | for ExEx/WAL notifications |
| `arbitrary` (`#[cfg(test)]`) | for codec round-trip tests |
| `From<alloy_consensus::Header>` | root `None` |

### 8.2 RLP (byte-exact with gov5)

The semantics are gov5's `optional,nil`. Fields 1-15 are as alloy writes them.
For the optional tail (16 to 24), let *last* be the last `Some` field:

- write every optional from 16 to *last*;
- write `0x80` for a `None` before *last*;
- write nothing after *last*.

Decoding reads optionals while the list has payload left, and reads `0x80` as
`None` for every optional. Two constraints:

- *last* = 24 needs a 32-byte root.
- A header with more than 24 elements is refused.

This is canonical: the bytes are a function of the `Option`s. A header without
gaps and without a root is alloy's exact encoding, so Ethereum-shaped headers
keep their hashes. Acceptance test: the gov5 fixtures in
`crates/n42/h2-consensus/testdata/header_field_parity/` decode, re-encode byte
for byte, and `hash_slow` equals `gov5_header_hashes.json`.

`base_fee_per_gas` is the one field where gov5 writes a different empty form
(`nilString`). It is always set on the native chain, so the codec refuses a
missing base fee followed by later fields instead of modelling it.

### 8.3 Storage (additive: old databases must open)

Every header stored today is reth-codecs' alloy `Compact`. Its derive layout
starts with a bitfield and ends with `extra_data`, which consumes the rest of
the buffer. So a suffix after it would be ambiguous: a leader controls
`extra_data` and could forge one.

The format, decided by the first byte:

- **`mobile_registry_root == None`**: exactly the alloy `Compact` bytes. Every
  header written before the change decodes unchanged, as root `None`, and new
  headers without a root are byte-identical to before.
- **`Some(root)`**: the marker byte `0xFF`, then a version byte `1`, then the
  32-byte root, then the alloy `Compact` bytes. No alloy `Compact` header can
  start with `0xFF`. Its first byte is flag bits: bit 0 is `withdrawals_root`'s
  presence and bits 1-6 are the byte length of `difficulty` (at most 32), so
  bits 1-6 can never all be set.

  The test `no_alloy_compact_header_starts_with_the_marker` (`crates/n42/header/src/compact.rs`)
  checks this bit position against reth-codecs 0.8.2. A side table was the
  fallback, and it is not needed.

Tests: an alloy `Compact` blob from before the change decodes to
`N42Header { root: None }`. `Some` round-trips. `arbitrary` round-trips.

### 8.4 Engine API carrier

`ExecutionPayloadV4` in our fork `crates/n42/alloy-rpc-types-engine`
(`src/payload.rs:1562-1575`) gains
`#[serde(rename = "mobileRegistryRoot", default, skip_serializing_if = "Option::is_none")] mobile_registry_root: Option<B256>`.

- The hand-written `Deserialize` `Helper` (`:1577`) and the SSZ types
  (`ssz_engine_types`) carry it too.
- The root only exists from Glamsterdam, which is also the V4 fork, so V1 to V3
  stay unchanged.
- `try_into_block*` keeps returning alloy blocks. A new
  `try_into_n42_block<T>() -> Block<T, N42Header>` sets the root.
- The raw channel (`crates/n42/h2-execution/src/raw_engine.rs:446,531`) writes
  a presence flag and 32 bytes after `slot_number`.
- `h2-el-rpc/src/engine.rs` (`:1373-1380`, `:2666-2715`) and
  `header_profile.rs` (`:392-540`) build V4 payloads with the root.
- `reconstruct_gov5_h2_block_from_or_tx_root` (`:576-665`) needs no new
  candidate dimension, because the payload carries the root.

### 8.5 Wire codec (gov5 interop)

Gossip bodies (`block_body.rs:198-290,350-390`, `compact_body.rs:314-496`)
decode `RLP [header, txs, verifiers, rewards]` with alloy's `Header::decode`.
They switch to `N42Header::decode`, with the fixtures as the contract,
compared by SHA-256.

h2-wire's own codecs carry block hashes only, never headers (a grep for header
decoding in `crates/n42/h2-wire` finds none), so they are untouched.

### 8.6 Header rules (mirror `adapter.go`)

In `HotStuffConsensus::validate_header`, with the chainspec predicates
`is_glamsterdam_active_at(ts)` and `mobile_anchor_active_at(ts)` read from the
gov5 genesis keys `glamsterdamTime` and `mobileAnchorTime`. Rules 1-3 are an
exact port of `verifySlotNumber` and the root gate in `verifyHeaderWithBatch`:

1. From Glamsterdam, `slot_number == Some(number)`. Before it, `slot_number == None`.
2. Under both forks, `mobile_registry_root.is_some()`. Otherwise it is `None`.
3. The root is never set without the slot (implied by 1 and 2).
4. BAL hash: follow gov5's `balTime`. If gap 2(a) is chosen, require it from
   Glamsterdam as reth does.

`validate_gov5_h2_header` stays field-local. A Rust leader stamps the slot (it
already does) and, under both forks, the root from a provider (gap 6). Without
a provider it must refuse to build, as gov5 does.

### 8.7 Ordered steps

| Step | Files and crates | Estimate |
| --- | --- | --- |
| 1. `N42Header`: type, flat RLP (8.2), `Sealable`, accessors, serde, `InMemorySize`; tests byte-exact against the gov5 fixtures | new `crates/n42/header`; `Cargo.toml` workspace member; tests reading `crates/n42/h2-consensus/testdata/header_field_parity/` | **done** on `feat/n42-header-field-24` (`cbdfbfd8a`, about 500 lines) |
| 2. `Compact` (8.3), with old-blob compatibility tests; then `Compress` / `Decompress` / bincode | `crates/n42/header` | `Compact` **done** (same branch); `Compress`/`Decompress` need `reth-db-api` (a git dependency), and bincode follows; about 100 lines left |
| 3. Chainspec: `type Header = N42Header` (`crates/chainspec/src/api.rs:85`) and the genesis header builder; `glamsterdamTime` / `mobileAnchorTime` predicates (`reth_chainspec::qmdb`-style, read from the genesis JSON) | vendored `crates/chainspec` (additive) | 150-250 lines, 1 day |
| 4. Primitives switch: `N42Primitives::BlockHeader = N42Header`, `Block = alloy_consensus::Block<N42TxEnvelope, N42Header>`; follow the cascade | `crates/n42/tx-types/src/primitives.rs`, then `engine-types` (consensus bounds `EthChainSpec<Header = Header>` at `hotstuff_consensus.rs:294,409`, payload builder, `N42EvmConfig` block assembler: reth's `EthBlockAssembler` builds an alloy header, so a thin N42 assembler wraps it and sets the root), `N42NetworkBuilder` (`NetworkPrimitives::BlockHeader`), `N42RpcTypes`/`crates/n42/reth-rpc` (RPC header with `mobileRegistryRoot`), `qmdb-reth`; about 52 files reference `alloy_consensus::Header` and 44 touch `SealedHeader`, most of which keep the inner alloy header | 1,200-2,000 lines, 1-1.5 weeks |
| 5. Engine API carrier (8.4) | `crates/n42/alloy-rpc-types-engine`, `h2-execution/src/raw_engine.rs`, `h2-el-rpc/src/engine.rs`, `h2-consensus/src/header_profile.rs` | 300-500 lines, 2 days |
| 6. Gossip decode (8.5) | `h2-consensus/src/{block_body,compact_body}.rs` | 50-100 lines, half a day |
| 7. Rules (8.6) + Amsterdam presence (gap 3) | `engine-types/src/hotstuff_consensus.rs` | 100-200 lines, 1 day |
| 8. Measurement: fleet7 bookend (header hash and `Compact` are on the hot path), SIGKILL `roll --kill` recovery, and a mixed devnet with gov5 on a Glamsterdam + MobileAnchor genesis | scripts only | 1-2 days of box time |

**Total:** about 2,500-4,000 changed lines, 2-3 weeks. Most of reth is generic
over the header type, which bounds the cascade in step 4.

## 9. Rust fixture test (today's behaviour)

`crates/n42/h2-consensus/testdata/header_field_parity/` holds three headers
written by gov5's codec (`TestWriteHeaderParityFixtures`, gov5 `e9d3ed36`) and
`gov5_header_hashes.json`. Raw bytes are compared by SHA-256.

| Fixture | Elements | SHA-256 | alloy 2.5.0 today |
| --- | --- | --- | --- |
| `gov5_header_slot23_root24.rlp` | 24: `0x80` at 22, slot 1001 at 23, root at 24 | `60751acf…0803c` | refused, `UnexpectedLength` (the empty 22) |
| `gov5_header_bal22_slot23_root24.rlp` | 24: BAL hash, slot, root | `1ddfb52d…879aa` | refused, `ListLengthMismatch` (the 24th element) |
| `gov5_header_bal22_slot23.rlp` | 23: BAL hash, slot (Ethereum Amsterdam) | `9241512f…78213` | decodes; `hash_slow` equals gov5's hash; re-encodes byte for byte |

Tests (`cargo test -p n42-h2-consensus --test header_field_parity`):

- `the_fixtures_are_the_bytes_gov5_wrote`
- `the_fixtures_have_the_layouts_they_are_named_after`
- `a_gov5_header_with_a_mobile_registry_root_is_refused_by_alloy_today`
- `a_gov5_amsterdam_header_without_the_root_decodes_with_alloy_and_hashes_the_same`
- `dropping_the_root_changes_the_hash`

## 10. Open questions

1. Gap 2: should the native chain stamp a real `BlockAccessListHash` from
   Glamsterdam (Ethereum RLP, no gaps), or keep `balTime` separate?
   `N42Header` handles both.
2. Which chain-94 genesis is current for `glamsterdamTime`: gov5's embedded
   chainspec (none) or the Rust copy (2027-01-01)? The answer decides when the
   slot and root appear on chain 94.
3. Is the block number the right slot in the long run? The view would expose
   HotStuff timing to `SLOTNUM`, but no Ethereum client could derive it.
4. The re-genesis in section 5: same chain id or a new one? And who rebases
   what pinned old block hashes (mobile anchors, explorers)?
