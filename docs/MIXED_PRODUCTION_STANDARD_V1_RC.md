# N42 mixed block production standard, profile 1 — v1.0-rc1, frozen 2026-11-24

This is the single normative text of profile 1. It consolidates `docs/MIXED_PRODUCTION_STANDARD.md`
(v0.2 + decisions O1-O10 of 2026-11-23 + the `0x50`-`0x5F` reservation + amendments AM1-AM23) and the pins
agreed in `/data/blockchain/wr-logs/HANDOFF-gov5-performance-5m-2026-10-15.md` after AM23 (posts of
2026-11-24 03:31-04:42 EST). Every item id of the source (A1 … J4) appears once, with its final rule. Where
the source changed a rule several times, only the last version is written here; the appendix "Trace" lists,
per decision, amendment and pin, which item ids it changed, so the consolidation can be audited against the
source. The source documents stay as history; this text replaces them as the rule set.

Agreed by: gov5 (Go), n42-rs (Rust, reth fork), n42-26 (Rust). Per-client progress is not part of this text;
it is kept in `docs/MIXED_PRODUCTION_STATUS.md`.

Terms: **MUST / MUST NOT / SHOULD / MAY** as in RFC 2119. "Refused" means: a genesis is refused at start-up,
a transaction is invalid, a header/block is invalid, a message is dropped and never voted for. "A profile-1
chain" is a chain whose genesis `config` carries `"n42Profile": 1`.

---

## 1. Scope and principles

**Profile 1 is N42's own chain at an 8-second slot.**
**Every value in this text is a value of that chain; it is not a limit on any client's other chains.**
**Performance chains (sub-second pacing, type `0x50`, frame blocks, deferred depth > 1, bench knobs) are outside
the profile.**

- **P1. One profile.** Profile 1 has exactly one signing profile (H2-v4, chain-bound domains, POP DST), one
  header layout, one transaction set and one sync protocol set. No legacy profile, signing domain, header
  variant or decoder is reachable on a profile-1 chain.
- **P2. Everything from block 0.** Every rule here holds from genesis (block 0 / block 1 / view 0 as stated per
  item). A profile-1 genesis carries no activation field for anything specified here. The Ethereum fork fields
  are present and all 0 only because they name the EVM rule set. `"n42Profile": 1` (the JSON integer 1) is the
  single switch.
- **P3. The genesis is the only source.** Every consensus-visible value comes from the genesis `config`. No
  environment variable, command-line flag or side file may set, override or default one (J4).
- **P4. Fail closed at start-up.** A client MUST refuse to start on a genesis that contains a key outside the
  closed key list (§4), a legacy or activation field, a missing mandatory field, or a value outside the range
  the client implements. Unknown keys are never ignored.
- **P5. No old-data rules.** Rules that existed only for old data are not part of the profile (legacy
  unchanged-account write, "every stored slot is written", portable snapshot format `0x01`, v1 sync tolerance,
  legacy QC/Extra layouts, chain-94/95 exceptions, the per-chain env switches that selected them).
- **P6. Choice order.** Correctness, then simplicity, then performance. Execution and header validity follow
  Ethereum; byte formats follow gov5 where gov5 is the byte-exact reference.
- **P7. "Deleted" means unreachable.** Wherever this text says a rule, format, type or switch is deleted,
  removed or not in profile 1, read: it MUST NOT be reachable on a profile-1 chain. A client MAY keep the code
  for chains outside the profile. Adding such a feature to N42's chain is a profile change (§8).
- **P8. Premise.** Every N42 native chain so far is a testnet; profile 1 starts from a new genesis. Nothing old
  is served, replayed or read.

---

## 2. The rules by item id

### (a) Chain configuration and genesis

**A1. Chain id, genesis hash, fork digest.** `config.chainId` and the genesis hash computed from the genesis
file (A6) are the only sources. Fork digest = `genesisHash[0:4]`. The signing identity is
`(chainId, genesisHash)`. The standard chain id is 1144.

**A2. Source of consensus parameters.** Every parameter of the §4 `config` is read from the genesis by every
client, and nothing else is (P3, P4).

**A3. Validator set.** `config.hotstuff.validators[] = {address, blsKey}`; list order = QC bitmap order =
leader index. `f = ⌊(n−1)/3⌋`, quorum `2f+1`, `n ≥ 4` (fewer refuses the genesis). The set is the genesis set
for the whole chain and for every epoch (E2).

**A4. Fork schedule.** Execution is every Ethereum fork through Osaka plus `amsterdamTime: 0`, all at 0,
spelled with Ethereum names. On profile 1 `amsterdamTime: 0` activates exactly the execution changes tabled in
`docs/GLAMSTERDAM_EXECUTION_PARITY.md` and nothing else: it is not a library's own bundle of that name; a
reth-derived client MUST NOT enable any other EIP its library ties to that field, and lists in its conformance
note every EIP its library would have enabled and how it is switched off. No EOF, no block-number forks, no
N42-only fork fields (each refuses the genesis).

**A5. State scheme.** QMDB only; `stateScheme: "qmdb"` is a mandatory key with that value.

**A6. Genesis header and root.** Header fields from §4. `stateRoot` = QMDB root of the alloc (`qmdb_compat`
encodings). `extraData` empty. `ommersHash` zero (exactly; the empty-list hash is refused). `difficulty`,
`nonce`, `mixHash`, `coinbase` zero. `transactionsRoot`, `receiptsRoot` and `withdrawalsRoot` are the
empty-trie root `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`; `requestsHash` is the
same empty-trie root (B8). `parentBeaconRoot` zero. Element 22 is the `0x80` gap (B12). `mobileRegistryRoot`
(element 24) present and zero. Every other fork-dependent field as Ethereum derives it at timestamp 0. Vector
V1 pins the bytes and hash of the test genesis; the cut standard genesis gets its hash in V8.

**A7. Alloc validity.** An alloc entry with nonce 0, balance 0, no code and non-empty storage refuses the
genesis; so does any storage entry with value 0.

**A8. Block reward.** `config.hotstuff.devBlockReward` is a JSON **decimal string of wei** that MUST be a whole
number of gwei and at most `u64::MAX` gwei (a JSON number, a fraction of a gwei or a larger value refuses the
genesis). `config.hotstuff.devFaucetAddress` MUST be non-zero. From block 1 every block pays
`devBlockReward` to the coinbase and to `devFaucetAddress`, as rewards carried in the withdrawals list (B6).

**A9. Unchanged accounts.** From block 1, an account in a block's execution with **no change at all** (nonce,
balance, code hash and storage all equal to their pre-block values) is not written to QMDB. An account with
any change, **including a storage-only change**, gets its account op written as well as its storage ops. No
field gates this.

**A10. Deferred execution.** Always on, depth `k = config.hotstuff.deferredExecutionDepth`, a mandatory
per-chain constant that MUST be 1 (any other value refuses the genesis). Header N carries `stateRoot`,
`receiptsRoot`, `logsBloom` and `gasUsed` of block N−1; block 1 carries genesis's.

**A11. Type `0x50` (AltSig).** Not in profile 1. A `0x50` transaction is invalid in pool, builder, block
validity, includability and execution; the genesis key `altSigTx` refuses the genesis (C4).

**A12. Frame blocks.** Not in profile 1. `transactionsRoot` = the ordered Ethereum transactions trie; bodies
carry full transactions; the key `frameBlocks` refuses the genesis.

**A13. Vote gating.**
- **Round 1 (prepare vote):** a node votes only after (1) the static header checks of §2(b) including the seal
  (B2) and the vote-time clock bound (B4), (2) the deferred-execution proposal check — the header's carried
  execution fields equal this node's own execution of the ancestor they describe, and every transaction of the
  block passes the includability check against the state it will run on — and (3) the parent's import. Never
  on a header alone, never on an import alone. A block that passes the check MUST be importable; a case where it
  is not is a bug, never a rule.
- **Round 2 (CommitVote):** a follower votes only after its own independent execution of the block (not a diff
  or result received from the leader). The leader's build of the block counts as the leader's own execution;
  the leader MAY cast its CommitVote when the PrepareQC forms.

**A14. Signing profile.** H2-v4 only (E10). Legacy domains and the `interopV4` key are not in profile 1.

**A15. Leader tenure.** `config.hotstuff.leaderTenure` T, mandatory, `T ≥ 1` (missing or 0 refuses the genesis);
`leader(v) = (v / T) mod n`. Standard value: **1**. A slow but live leader keeps its tenure; only a timeout
rotates it (A22).

**A16. Timeouts.** `config.hotstuff.baseTimeoutMs` and `maxTimeoutMs`, mandatory, no defaults,
`maxTimeoutMs ≥ baseTimeoutMs`. Standard values: **24000** and **96000**. The view timer runs from view start;
the base timeout exceeds the slot plus a block's build plus two network hops.

**A17. Block interval.** `config.hotstuff.blockIntervalMs`, mandatory: a leader proposes no earlier than this
long after it first held the parent. It is pacing, not a timestamp step (B4). Standard value: **8000**.

**A18. Epochs.** `config.hotstuff.epochLength` E, mandatory, `E ≥ 1` views (missing or 0 refuses the genesis);
`epoch(v) = (v−1)/E`; boundary b: `b > 1` and `(b−1) mod E = 0`. Standard value: **10800** (about 24 h). With a
fixed set (E2) epochs only number the QCs.

**A19. Committee pool.** `config.hotstuff.committeePool {seedHex, poolSize, committeeSize, rampBlocks}`,
mandatory, always on; no `enabled`, no `allowHandover` (either refuses the genesis). It feeds B5. Its keys
derive from a public seed, so the per-block committee evidence has **no security meaning**: it authenticates
nothing and only fixes a deterministic per-block value.

**A20. Amsterdam and MobileAnchor.** Both from block 0 (A4, B10, B11, I1); no `mobileAnchorTime`,
`glamsterdamTime` or similar key.

**A21. Local pacing knobs.** `fastPropose`, `minProposeDelayMs`, `ethELCompat` are not genesis keys (they refuse
the genesis under the closed list). Local proposal timing is free within A17.

**A22. Rotate on timeout.** SYNC §10.2 `view_after_tc`, active from view 0, no key. At `T = 1` it reduces to
`x+1` and changes nothing; a chain with a longer tenure gets it with no further change.

**A23. Gas limit.** Every header's `gasLimit` equals `config.hotstuff.gasLimit`, which equals the genesis
header's `gasLimit`; no ramp, no per-node target. Standard value: **480,000,000** (not scaled by the slot).

### (b) Header and block format

**B1. Extra.** `"N42H" ‖ view u64 LE ‖ QC ‖ seal(96)`, at most 4096 bytes. QC = the leader's highest CommitQC
(commit domain) of the genesis set, with a view below the header's view, naming an ancestor of the block; an
absent QC is zero bytes, used only while the leader holds no CommitQC. "Naming an ancestor" is checked when the
QC's block is known locally (walk ≤ 4096), else the QC's signature alone is checked; "absent only while the
leader holds none" is not checkable from a header and is not enforced.

**B2. Seal.** `sealHash = keccak256(rlp(H'))`, where H' is the full header (every element,
`mobileRegistryRoot` included) with the last 96 bytes of `extraData` removed (removed only when `extraData` is
longer than 96 bytes). The seal is the proposer's BLS signature over those 32 bytes with the H2-v4 POP DST,
placed in the last 96 bytes of `extraData`. It is verified on import and before the Round-1 vote; a wrong seal
or a seal by any key but the view's leader makes the header invalid.

**B3. Constant fields.** `difficulty` 0, `nonce` 0, `mixHash` zero, `ommersHash` zero (exactly; the empty-list
hash is invalid), no ommers, `coinbase` = the proposer's address. All checked, in every header including
genesis.

**B4. Timestamp.** `parent.time ≤ header.time` is checked on import; `header.time ≤ floor(local_now) + 2` is
checked only before voting (never on import of a committed block). The leader stamps
`max(parent.time, floor(now))`. Equal timestamps are valid (Ethereum's strict `>` does not apply). How a
leader caches its stamp across a restart is local.

**B5. parentBeaconRoot.** `Blake3(committee evidence(parent.number, parent.hash, parent.receiptsRoot))` from
the committee pool (A19); zero for block 1.

**B6. withdrawalsRoot = rewards.** `withdrawalsRoot = keccak256(concat(rlp([address, amount])))` over the
block's reward list (amount in gwei, EIP-4895 withdrawals), `keccak256("")` when the list is empty (genesis: A6).
The list order is: the reward function's output, then the coinbase, then the faucet. The body's reward list is
checked against the root after execution.

**B7. receiptsRoot.** `keccak256(concat(rlp([status, cumulativeGas, logs])))`, `keccak256("")` when empty
(genesis: A6). Under A10 the value describes block N−1.

**B8. requestsHash.** The empty-trie root `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`
in every header including genesis, checked. Neither `sha256("")` (`0xe3b0c442…`) nor the empty-ommers hash
(`0x1dcc4de8…`) is valid. No EIP-7685 requests and no EIP-8282 calls run.

**B9. Blob gas fields.** `blobGasUsed = 0`, `excessBlobGas = 0`, checked.

**B10. slotNumber.** Header element 23 = the block number.

**B11. mobileRegistryRoot.** Header element 24, always present (zero at genesis). Its value is the proposer's
statement, covered by the seal and the QC; followers check its presence and carry it, and do not re-derive it.
A leader without a running mobileverify service repeats its parent's value. (A validation rule is open, §7.)

**B12. Element 22 (block access list hash).** Written as the empty string `0x80` (the gap), in every header
including genesis. A real EIP-7928 hash is not in profile 1.

**B13. Deferred fields.** Per A10. `header.gasUsed ≤ parent.gasLimit` (= the A23 constant); under EIP-8037
`gasUsed = max(regular gas, state gas)`.

**B14. Base fee.** EIP-1559 from the parent header (elasticity 2, denominator 8), using the parent's `gasUsed`
field as written (under A10 the grandparent's execution), checked on import. Gas limit per A23.

**B15. Block size.** `MAX_BLOCK_BYTES = config.hotstuff.maxBlockBytes` (standard: 67,108,864 = 64 MiB, decoded
RLP) is the only block-size bound. It bounds production (F3) and every carrier: gossip, push, by-hash, range
chunks. EIP-7934's block-RLP cap and any client's own smaller cap do not apply; no env cap exists. (A range
REPLY may have its own reply cap; §3.)

**B16. Transaction count.** No count bound; gas and bytes bound a block.

### (c) Transactions

**C1. Types 0, 1, 2.** Ethereum rules at Amsterdam (A4).

**C2. Type 3 (blob).** Invalid in pool, builder, block validity, includability and execution.

**C3. Type 4.** EIP-7702 including the shape checks (no create, non-empty authorization list).

**C4. Every other type byte.** Only `0x00`, `0x01`, `0x02`, `0x04` are valid. `0x03`, `0x05`, `0x06`, every
type in the N42 range `0x50`-`0x5F` (A11) and every other byte are invalid in pool, builder, block validity,
includability and execution. The range `0x50`-`0x5F` is reserved for N42 (`0x50` Ed25519, `0x51` reserved for a
post-quantum signature type, `0x52`-`0x5F` unassigned); a type in it enters N42's chain only by a profile change;
if Ethereum L1 allocates a type inside the range, N42's next new type moves to the next free number, a live type
keeps its number.

**C5. Gas cap per transaction.** Amsterdam's EIP-8037 cap (2^32−1) applies, and a transaction whose gas limit
exceeds the block gas limit (A23) is invalid at pool, includability and import; a gas limit exactly equal to it
is valid.

**C6. Initcode.** Amsterdam's EIP-7954 cap (131,072 bytes) from block 0, with no native exemption.

**C7. Pool vs block.** Only block validity is standard; a pool's policy MUST be a subset of it (a pool MAY
refuse valid transactions, e.g. by size; it MUST NOT admit invalid ones).

**C8. Zero-tip / zero-value.** No restriction; their state effect is fixed by A9 and D4.

### (d) Execution

**D1. EVM set.** Per A4.

**D2. Amsterdam on native.** `docs/GLAMSTERDAM_EXECUTION_PARITY.md` as closed: no EIP-8282 calls, no
EIP-7997, no EIP-7928 block access list.

**D3. System calls.** EIP-2935 and EIP-4788 run every block. The system caller `0xff…fe` is written only if A9
says it changed; a never-written or unchanged caller does not appear.

**D4. Deletion.** EIP-161: an account empty after the block (nonce 0, balance 0, no code) is deleted; code
accounts are never deleted by emptiness. On profile 1 the reachable form is: a touched account that did not
exist before produces no op.

**D5. Storage.** Per slot, from block 1: pre-block value equal to post-block value ⇒ no write; post = 0 and
pre ≠ 0 ⇒ delete; otherwise write (net change over the block, including set-and-reset inside a creation).

**D6. QMDB root.** gov5 `lib/qmdb` twig tree with `qmdb_compat` encodings, ops sorted by key hash; one unsharded
tree; compaction and any storage maintenance MUST be root-neutral.

### (e) Consensus

**E1. Quorum.** Per A3.

**E2. Validator-set change.** None on profile 1: the validator set is the genesis set; the reconfiguration API
is disabled and a node refuses a staged change. Every QC and TC of every epoch verifies against the genesis set;
a node that restarts in epoch E anchors QCs of E+1, E+2, … from that set. `changesHash` is zero in every
signature. (A design for changes is open, §7.)

**E3. Leader.** Per A15.

**E4. Rotate on timeout.** Per A22.

**E5. Pacemaker** (SHOULD, not consensus-visible). `timeout = min(eff · 2^k, maxTimeoutMs)`, k = consecutive
local timeouts, reset on QC/commit or TC adoption; `eff = max(baseTimeoutMs, 2 · p95)` of the last 20 commit
latencies once ≥ 5 exist.

**E6. Proposal validity.** Proposer = leader(view); justify QC valid (E11) in the vote or commit H2-v4 domain;
block parent = the justify QC's block (an unknown parent is fetched first); the header valid per §2(b) with
seal (B2) and timestamp (B4). Locking: a node locks on the block of the highest PrepareQC it has seen and votes
only for a proposal whose justification is not below its lock (`justify.view ≥ locked.view`). A leader that
enters a view by a TC proposes on the highest QC the TC carries.

**E7. Votes.** One Round-1 vote and one CommitVote per view per validator, journalled (synced to disk) before
sending, gated per A13.

**E8. Early votes.** No vote before its A13 gate.

**E9. Progress votes.** Not in profile 1; no message with an invalid vote signature is ever sent. A straggler
grace (F8), if any, sends no progress votes.

**E10. Signing domains.** `"N42H2V4" ‖ phase (1 proposal, 2 vote, 3 commit, 4 timeout, 5 newview) ‖ chainId u64
LE ‖ genesisHash ‖ view u64 LE ‖ payload`; payload `blockHash ‖ changesHash(=0)` for proposal and commit,
`blockHash` for vote, empty for timeout/newview; DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`; aggregates are
plain BLS aggregates over the bitmap's signers.

**E11. QC/TC.** SYNC §1.2 wire forms (H2-v4); bitmap width = n.

**E12. Commit.** A CommitQC on a block commits it and its ancestors (its order; its execution per E14); Decide
is broadcast. **Conflicting commit:** a node that holds proof of a conflicting commit — two CommitQCs at one
height, or an authenticated chain that does not join its committed head — MUST stop importing, voting and
producing past the conflict, keep the evidence, and raise an error and a gauge; only an operator resumes it.
Data from a single peer that is not such a proof never halts a node.

**E13. QC verification everywhere.** SYNC §3.3 on every path (live, header, sync): the exact set of the QC's view
(the genesis set, E2), commit domain for anchors, no fallback set, unknown set ⇒ fail closed.

**E14. Finality tags** (RPC, normative). A CommitQC on N finalises N's order; N's execution is certified when a
committed descendant carries N's execution fields (depth 1: the commit of N+1). `latest` = highest committed
block; `safe` = highest block whose execution is certified; `finalized` = certified and persisted by this node.

**E15. Equivocation.** Detect two Round-1 votes, two CommitVotes or two proposals by one validator in one view;
verify, persist the signed pair, expose it over RPC (`n42_equivocations`) and a metric (J2); never vote twice.
Evidence only: no slashing.

**E16. Vote transport.** Every consensus message is published on `/n42/<digest>/hotstuff_consensus/ssz_snappy`;
a sender MAY also deliver it over `/rpc/hotstuff_direct/1` (same bytes). Direct-only delivery and `/n42/vote/1`
are not in profile 1.

**E17. Decide.** Published on `/n42/h2/4/ssz_snappy`.

### (f) Production behaviour

**F1. Pacing.** Per A17 and B4.

**F2. Empty blocks.** A leader proposes in every view it leads, empty if it has nothing.

**F3. Byte budget** (builder). Transactions ≤ `maxBlockBytes / 10 · 9 − 32 KiB − header`.

(F4: no item; the source has no F4.)

**F5. Stale parent.** Never propose a block whose parent is not the justify QC's block.

**F6. One proposal per view.** At most one signed proposal per (view, proposer); a leader MAY re-propose an
identical block in a later view of its tenure. A second different proposal is equivocation (E15).

**F7. Seal before own execution.** Allowed (headers carry the ancestor's result). A leader MUST NOT propose
block N+1 before it has executed N.

**F8. Straggler grace.** Local; bound by E9.

### (g) Networking

**G1. Transport.** libp2p, secp256k1 identities, Noise, yamux, identify.

**G2. Topics.** Consensus, block, `transaction_v2`, `/n42/h2/4`, `mobileverify_{packet,registration}`; legacy
topics (`/n42/consensus/1`, `/n42/blocks/1`, …) are not in profile 1.

**G3. Message id.** `keccak(genesisHash ‖ topic ‖ data)[:20]`.

**G4. GossipSub parameters.** gov5's values, a wire contract; published as vector V9.

**G5. Consensus message cap.** `MAX_CONSENSUS_MSG = 64 KiB` decoded.

**G6. Single-client protocols.** None may be needed by another client.

### (h) Sync

See §3.

### (i) Mobile verification

**I1. Surface.** `docs/MOBILEVERIFY_V3_PARITY.md` (gov5's `/mobileverify`, "mining v3"), from block 0.

**I2. Validators and the service.** A validator SHOULD run the mobileverify service; one without it MUST still be
able to lead and repeats its parent's `mobileRegistryRoot` (B11). Phones never delay a block; collection windows
are defined against the 8-second slot.

### (j) Operations

**J1. RPC.** `eth_config` refused (−32004, gov5's message); witness/proof methods refused on QMDB; finality per
E14; equivocations per E15.

**J2. Metrics.** Every client exposes at least `n42_head_number`, `n42_committed_view`, `n42_committed_number`,
`n42_view_timeouts_total`, `n42_tc_formed_total`, `n42_equivocations_total`, `n42_blocks_refused_total{reason}`.

**J3. Activation.** Nothing in this text has an activation field; a client refuses every key outside the closed
list (P4). New rules enter only by a profile change (§8).

**J4. Environment and flags.** On a profile-1 genesis a node that finds a forbidden variable or flag set
REFUSES TO START, naming it; on any other genesis the same variables stay that client's ordinary
configuration. Forbidden: anything that sets or changes a consensus-visible value, or skips a check. At least:
gov5 `N42_MAX_GOSSIP_MB`, `N42_STRESS_GASLIMIT`, `N42_DEFERRED_DEPTH*`, `N42_DEFERRED_EXECUTION_TIME`,
`N42_TXROOT_BLAKE3_TIME`, `N42_FRAME_BLOCKS`, `N42_VOTE_ON_AVAILABILITY`, `N42_HOTSTUFF_LEADER_TENURE`,
`N42_HOTSTUFF_ROTATE_ON_TIMEOUT`, `N42_SYNC_ANCHOR` (unless `enforce`), `--miner.gasceil`, `--block-interval-ms`;
n42-rs `N42_MAX_GOSSIP_MB`, `N42_VOTE_TRANSPORT=direct`, `N42_VOTE_BEFORE_SLOT`, `N42_VOTE_BEFORE_IMPORT`,
`N42_FRAME_BLOCKS`, `N42_BENCH_UNSAFE` and every path that skips checks, `N42_SYNC_ANCHOR` (unless enforce),
`N42_SETTLEMENT_TAGS` (unless split), `--builder.gaslimit`; n42-26 `N42_CHAIN_ID`, `N42_CONSENSUS_CONFIG`,
`N42_VALIDATOR_COUNT`, `N42_BASE/MAX_TIMEOUT_MS`, `N42_BLOCK_INTERVAL_MS`, `N42_GOV5_*`, `N42_LEADER_TENURE`,
`N42_FRAME_BLOCKS`, `N42_SKIP_STATE_ROOT`, `N42_DEFER_STATE_ROOT`, `N42_SKIP_TX_VERIFY`, `N42_REWARD_*`,
`N42_MAX_EMPTY_SKIPS`. Permitted (cannot change meaning): thread counts, allocator, parallel build/import,
persistence and cache knobs, ingest/flood knobs, logging/trace.

---

## 3. Sync

`/data/blockchain/wr-logs/qs-scratch/sync/N42-SYNC-SPEC.md` ("SYNC") stays the wire reference. Profile 1 uses
only its final protocol set; there is no `/1` range protocol and no negotiation.

| Protocol | Profile 1 |
| --- | --- |
| `/rpc/status/1/ssz_snappy` | required (SYNC §4.1, 72 bytes, frozen) |
| `/rpc/block_by_hash/1/ssz_snappy` | required (SYNC §4.2); serves committed blocks **and uncommitted proposals** (proposal recovery); miss = `0x03 RESOURCE_UNAVAILABLE` |
| `/rpc/block_push/1/ssz_snappy`, `/rpc/hotstuff_direct/1` | required (SYNC §4.4) |
| `/rpc/bodies_by_range/1` | not in profile 1 |
| `/rpc/bodies_by_range/2/ssz_snappy` | required (SYNC §5.1): **committed blocks only**, byte budget, END trailer |
| `/rpc/commit_qc/1/ssz_snappy` | required (SYNC §5.2) |
| `qmdb_status/1`, `qmdb_manifest/1`, `qmdb_twigs/1`, `code_by_hash/1` | required servers on every client (SYNC §5.3), portable `0x03` records only |
| `headers_by_range`, snapshot `get_*_range`, gov5 witness RPCs | not in profile 1 |

Rules:
- **Anchors enforced** (SYNC §3.3, §3.4): a pulled block is executed only once a CommitQC (commit domain, genesis
  set, E13) names it or a descendant; there is no `observe` mode and no anchor switch.
- **Conflict halt** per E12 (SYNC §3.3's halt is normative and includes consensus).
- **Seal** checked on every road (B2); this overrides SYNC's statement that the seal is not checked.
- **Limits:** SYNC §6 for `/2` and state sync; block size per B15; a range REPLY MAY carry its own reply cap
  (gov5: 128 MiB) above `maxBlockBytes`.
- **Validator sets** (SYNC §3.6): the genesis set answers every epoch (E2). The weak-subjectivity checkpoint of
  §3.6 stays; "checkpoint without QC" is not needed (every header after the first commit carries a QC, B1).
- **Rotate on timeout:** SYNC §10.2 per A22.

Parts of SYNC not used on profile 1: §1.2 legacy Extra layouts and §3.2's rule that decoders accept them;
breakages B2, B4, B6, B7, B8, B9, B10 of §2 (resolved by construction); §3.1's "legacy profile" clause and a
`deferredExecutionDepth` k > 1; §4 except §4.1, §4.2 and §4.4; §5.0 capability discovery and fallback to v1;
§6 limits that refer to v1; §7.2 rollout order and §7.1 rows that only bridge v1; §10.3 activation
(`rotateOnTimeoutView`) and its bench env; §10.4 vectors S6 and S8.

---

## 4. The standard genesis

The authoritative files are gov5's, under `/data/blockchain/wr-logs/qs-scratch/profile1/vectors/`:
- `V8/allowed-keys.json` — the CLOSED key list of `config`, `config.hotstuff`, `config.hotstuff.committeePool`
  and each `validators[]` entry; any other key refuses the genesis. `blobSchedule` is the only optional key.
- `V1/genesis_8s.json` — the profile-1 genesis with the values below and four deterministic **test**
  validators (`BLS secret i = 0x00 ‖ sha256("n42-profile1-test-validator-<i>")[1:]`, see `V8/README.md`);
  genesis hash `0x6f733745517957b421dcea37f6c879db89501aac0715f769fbc76ec54efe7e4f`.
- `V8/genesis.json` + `hash.txt` — the cut standard genesis: **not published yet** (gov5 cuts it after its 8 s
  round). For a mixed round the `validators` array is replaced with the participants' keys and every client
  recomputes the hash.

The `config` block (values as in `genesis_8s.json`):

```jsonc
{
  "config": {
    "chainId": 1144,
    "n42Profile": 1,
    "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0,
    "byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0, "istanbulBlock": 0,
    "berlinBlock": 0, "londonBlock": 0,
    "mergeNetsplitBlock": 0, "terminalTotalDifficulty": 0, "terminalTotalDifficultyPassed": true,
    "shanghaiTime": 0, "cancunTime": 0, "pragueTime": 0, "osakaTime": 0, "amsterdamTime": 0,
    "blobSchedule": { /* Ethereum defaults (cancun, prague, osaka); inert because type 3 is invalid */ },
    "consensus": "hotstuff",
    "stateScheme": "qmdb",
    "hotstuff": {
      "validators": [ { "address": "0x…", "blsKey": "0x…(48 bytes)" } ],   // n >= 4 (A3)
      "leaderTenure": 1,                 // A15
      "baseTimeoutMs": 24000,            // A16
      "maxTimeoutMs": 96000,             // A16
      "blockIntervalMs": 8000,           // A17
      "epochLength": 10800,              // A18
      "deferredExecutionDepth": 1,       // A10
      "gasLimit": 480000000,             // A23
      "maxBlockBytes": 67108864,         // B15
      "committeePool": { "seedHex": "0x0101…01 (32 bytes)", "poolSize": 200000,
                         "committeeSize": 512, "rampBlocks": 1000000 },   // A19
      "devBlockReward": "1000000000000000000",                            // A8
      "devFaucetAddress": "0x42e9819036f61bF665D5f727E8C03121f12f586e"   // A8, non-zero
    }
  },
  "nonce": "0x0", "timestamp": "<T0>", "extraData": "0x", "gasLimit": "0x1c9c3800",
  "difficulty": "0x0", "mixHash": "0x00…00", "coinbase": "0x00…00", "baseFeePerGas": "0x3b9aca00",
  "alloc": { /* EIP-7002, EIP-7251, EIP-2935, EIP-4788 system contracts and the faucet; A7 applies */ }
}
```

---

## 5. Conformance vectors

Bytes come from gov5 (the reference); a vector is compared by SHA-256 of the raw file bytes. Each lives under
`/data/blockchain/wr-logs/qs-scratch/profile1/vectors/<Vn>/` with a README.

| Vector | Proves | State (2026-11-24) |
| --- | --- | --- |
| V1 header profile | genesis header (A6) and two sealed headers (block 1 without QC, block 2 with block 1's CommitQC): B1-B4, B6, B8-B12, B14, A23, seal (B2); 25 refused headers with the stage (`import`, `vote`, `execution`) | published: `V1/README.md`, `genesis_8s.json`, `header_profile_v1.json` |
| V2 roots | receipts root, rewards root, committee evidence derivation (B5-B7) | not published yet |
| V3 QMDB write sets | A9 (incl. storage-only account op), D3, D4 (reachable form), D5, A7, A8 reward ops, genesis QMDB root | published: `V3/main.json` (7 cases), `system_address_live.json`; the equal-timestamp pair (B4) is still to be added |
| V4 transaction validity | C1-C6, A11, the range `0x50`-`0x5F`, 17 cases with the refusing stage | published: `V4/transactions.json` |
| V5 header validity | deferred fields (A10, B13 incl. EIP-8037 `gasUsed = max`), B4 equal-timestamp pair, B9, B14, A23 | not published yet |
| V6 consensus messages | E10, E11 wire/envelope/snappy bytes; A13 gates, E6 lock and TC rule, E12, E13, A14, A22 at an epoch boundary; 19 verdicts; sizes at n = 4 / 100 / 512 (G5) | published: `V6/consensus_messages_v6.json` |
| V7 schedule | A15, A22 (SYNC §10.4 without S6/S8) | not published yet as a profile-1 vector (SYNC §10.4 table exists) |
| V8 genesis | closed key list (P4), 33 refused geneses; the cut genesis and its hash | partly published: `V8/allowed-keys.json`, `V8/refused/` (33 cases); `genesis.json` and `hash.txt` not yet |
| V9 GossipSub parameters | G4 | not published yet |

---

## 6. Milestones (gates)

A gate is passed only by evidence posted in the handoff file. **Only a passed mixed round counts as done**: a
client that passes every vector but has not passed the round is not "done" for that gate.

1. **Vectors alone.** Each client passes every vector V1-V9 alone, with no behaviour changed to fit a vector
   except where the vector shows the client wrong.
2. **First mixed round: gov5 + n42-rs, idle, 8 s.** Shape: `V1/genesis_8s.json` with its four test keys,
   validators 0-1 run by gov5 and 2-3 by n42-rs (each with its own execution layer), 30 minutes idle at the
   8-second slot. Pass: every validator leads its views (T = 1) and its blocks are committed by the others; the
   same block hash at every height on every node; zero refused blocks; no conflicting commit and no safety
   halt; `mobileRegistryRoot` per B11 on every header. n42-26 MAY join as a verifying non-validator node once it
   reports V1 equal and can follow.
3. **Mixed catch-up.** One member at a time is stopped and pulls the chain back by range, in all four pull
   directions (gov5 from gov5, gov5 from n42-rs, n42-rs from gov5, n42-rs from n42-rs), first idle, then under
   load; needs `bodies_by_range/2` and `commit_qc/1` (§3) on both clients. Pass: the member rejoins at the
   head with equal hashes and votes within 60 s of reaching it.
4. **Long absence.** A member absent ≥ 1 h rejoins by state sync (`qmdb_*`, `code_by_hash`, §3). Pass as gate 3.
5. **Scale.** A mixed round with ≥ 100 validators (several per execution layer, every producing client
   present), including a killed leader and 33 absent members. Prerequisites: batched vote verification and a
   timeout-certificate path that is not quadratic in n, in every participating client.
6. **n42-26 as producer.** n42-26 is in the validator set and leads in a mixed round (the gate-2 criteria,
   then gates 3-5 with n42-26 present).

---

## 7. Open items and non-goals

Open (each closes only by a profile change or an agreed post, §8):
- **E2 validator-set changes.** Design needed: the change carried in a block and bound by the votes on that
  block (candidate: non-zero `changesHash` = keccak of the canonical encoding of the full new set + activation
  epoch; vote only if valid against the current set and boundary; activation at the first boundary after
  commit), with a vector and a mixed round. Until then E2's fixed set holds.
- **B11 registry root validation.** A follower rule that cannot split honest nodes over registry gossip timing.
  Until then the proposer's statement holds (B11, I2).
- **Kept (unanchored) tail.** SYNC §3.4 item 6 keeps pulled blocks above the highest anchor unexecuted
  (≤ 64 blocks, ≤ 512 MiB, highest evicted first, released by a later QC, a Decide or `commit_qc/1`). Profile 1
  uses that rule as written, but its bounds have not been re-derived for the 8-second slot and no vector covers
  it; it stays open until gate 3 exercises it.
- **Missing vectors** V2, V5, V7, V9 and the cut genesis of V8 (§5); the equal-timestamp pair in V3/V5.
- **Rounds not yet in a gate:** tenure > 1 with rotate-on-timeout and a killed tenure leader (on a test
  genesis), ≥ 5 epoch boundaries with a TC landing on one, a negative leader (invalid blocks, a double proposal)
  refused by every honest member.
- **gov5's 8 s round** (idle + load, one leader killed, view-change time vs `baseTimeoutMs`), owed before the
  standard genesis file is cut.

Non-goals of profile 1: type `0x50` and the rest of `0x50`-`0x5F`; blob transactions; frame blocks; EOF;
deferred depth > 1; a real EIP-7928 block access list hash; state proofs as a consensus object; an LtHash
summary in the header; post-quantum consensus or phone signatures; phone rewards; staking and slashing; dynamic
validator sets (until E2 is designed); sub-second pacing and any throughput figure of the performance line.

---

## 8. Change control

This text is **frozen** as v1.0-rc1 on 2026-11-24. It changes only when a vector disagrees between two clients
and the standard is shown to be the one in error, by a post in the handoff file agreed by all three clients
(gov5, n42-rs, n42-26). Every change records the item id, the vector case and the post. A new feature
(anything in §7's non-goals, or a new rule) is a **profile change**: one activation point in the genesis on all
clients (`<name>Time` for execution and header rules, `<name>View` for pacemaker/schedule rules, absent = off),
with a vector set and a mixed round; a client that does not implement it refuses to start on a genesis that
sets it (P4).

---

## Appendix: Trace

Source ids: v0.2 = the item text of `MIXED_PRODUCTION_STANDARD.md` §2; O = decisions of 2026-11-23; R = the
`0x50`-`0x5F` reservation; AM = amendments; PN = pins in the handoff file after AM23 (date/time EST of the post
that settled them).

| Source | What it changed | Item ids |
| --- | --- | --- |
| Q-S1 (owner, 2026-11-22) + v0.2 | storage-only alloc entry refused; zero-value slot clause | A7 |
| O1 | n42-26 full producer | §6 gate 6 (amended by AM6) |
| O2 | blob transactions off | C2 |
| O3 | `0x50` not in profile 1 | A11, C4 |
| O4 | `deferredExecutionDepth` mandatory constant, 1 | A10 |
| O5 | equivocation evidence only, no slashing | E15 |
| O6 | element 22 = `0x80` gap | B12 |
| O7 | equal timestamps, vote-time clock bound | B4 |
| O8 | tenure 8 / 6000 / 30000 / 500 / epoch 200 (superseded by AM17, AM22) | A15-A18 |
| O9 | gas limit fixed 480M | A23 |
| O10 | EOF off | A4 |
| "Also decided with the premise" | no-op and net-change from block 0/1, rotate-on-timeout from view 0, sync straight to `/2` | A9, D5, A22, §3 |
| R (owner, 2026-11-24) | `0x50`-`0x5F` reserved, all refused in profile 1 | A11, C4 |
| AM1 | `amsterdamTime` = the parity set only | A4, D2 |
| AM2 | `maxBlockBytes` is the only size bound | B15 |
| AM3 | requestsHash = empty-trie root in every header | B8, A6 |
| AM4 | seal bytes; verified on import and before Round 1; overrides SYNC | B2, §3 |
| AM5 | fixed genesis set, reconfiguration disabled; E2 reopened | E2, A3, E13, §7 |
| AM6 | only a client that can lead is in the set; verifying non-validator otherwise | §6 gates 2, 6 |
| AM7 | n42-26 status from its own post | status file only |
| AM8 | `devBlockReward` decimal string of wei | A8 |
| AM9 | "deleted" = unreachable on profile 1 | P7 (all REMOVE items) |
| AM10 | J4 refusal only on a profile-1 genesis | J4 |
| AM11 | profile-1 numbers are profile 1's only; 100-validator round | §1, §6 gate 5 |
| AM12 | tenure/epoch ≥ 1; reward whole gwei ≤ u64::MAX gwei; closed key list; V8 cases; equal-timestamp pair; `gasUsed = max`; B11 interim | A15, A18, A8, P4, J3, B4, B13, B11, §5 |
| AM13 | n42-26 status corrections | status file only |
| AM14 | T0 definition (milestone dates) | replaced by §6 gates (no dates) |
| AM15 | positions on v0.3 | — |
| AM16 | `devFaucetAddress` non-zero; more V8 cases; gov5 B11 presence check | A8, B11, §5 |
| AM17 | 8-second slot; 500 ms is the performance line; 100 validators designed and tested | §1, A17, §6 gate 5 |
| AM18 | n42-26 agrees | — |
| AM19 | Round 1 needs the deferred check; own import = own execution; E14 split; lock and TC rules | A13, E6, E14 |
| AM20 | one unsharded tree, root-neutral; non-goals; slow leader keeps tenure | D6, §7, A15 |
| AM21 | registry-root fallback; committee pool question | B11, I2, A19 |
| AM22 | 8000 / 24000 / 96000 / tenure 1 / epoch 10800 / 480M / depth 1; batched verification and non-quadratic TC before 100 | A15-A18, A23, A10, §4, §6 gate 5 |
| AM23 | gov5 agrees AM19; fallback adopted; committee pool kept, no security meaning | A13, B11, I2, A19 |
| gov5 02:55 readings (accepted in v0.2.1) | D3 caller only if changed; D5 gap; C6 no exemption; ommers zero in genesis; B15 gossip; J4 extra entries | D3, D5, C6, B3, B15, J4 |
| gov5 02:55 | type `0x05` refused | C4 |
| PN gov5 03:46 (V1 readings, unobjected; V1 equal both ways 04:09/04:28) | QC ancestry checked when known; "QC absent only while none" not enforced; stamp cache local | B1, B4 |
| PN gov5 03:46 (slice 5) | range reply cap is a reply cap; by-hash miss `0x03` | B15, §3 |
| PN 04:09 (gov5 03:31 Q1) | genesis tx/receipts/withdrawals roots = empty-trie root | A6, B6, B7 |
| PN 04:09 | reward list order: reward function, coinbase, faucet | B6 |
| PN 04:09 (gov5 03:46 reading) | by-hash serves uncommitted proposals; ranges committed-only | §3 |
| PN 04:09 (a) | leader's build counts as its own execution | A13 |
| PN 04:09 (b) | conflicting-commit halt of importing, voting, producing; evidence kept; operator resumes | E12, §3 |
| PN 04:07 PIN 1 / 04:28 | storage-only change writes the account op; A9's no-op only for no change at all | A9 |
| PN 04:07 PIN 2 / 04:28 | gas above block gas limit invalid; exactly the limit valid | C5 |
| PN 04:07 PIN 3 / 04:28 | D4 in its reachable form | D4 |
| PN 04:42 (gov5) | the genesis set answers every epoch after a restart | E2 |
| PN first mixed round (owner brief of 2026-11-24; no handoff post found) | genesis_8s.json test keys, validators 0-1 gov5, 2-3 n42-rs, 30 min idle at 8 s | §6 gate 2 |
| Source §6 milestones M1′, M2a-c, M3a-d | replaced by gates 1-6; M3a, M3b, M3d and M3c (set change) moved to §7 | §6, §7 |

---

## Consolidation questions

1. **Range of `blockIntervalMs` (and of other per-chain values).** gov5 03:31 Q2: "gov5 accepts only
   maxBlockBytes = 67108864 (the one value it implements, P4) and any blockIntervalMs >= 1 (the standard gives
   no range). Object if either should differ." No post answers it. This text writes no lower bound for
   `blockIntervalMs` beyond "mandatory"; P4 lets a client refuse a value it does not implement. Confirm whether
   profile 1 fixes a range.
2. **Gossip of equivocation evidence.** O5: "Evidence only (detected, logged, **gossiped**, never voted for
   twice)". E15 (v0.2 and unchanged since): "verify, persist the signed pair, expose it over RPC
   (`n42_equivocations`) and a metric." No topic for evidence exists in G2. This text follows E15 (no gossip);
   confirm, or define a topic.
3. **Pass criteria of gate 2.** The round's shape is from the owner brief; no handoff post with its pass
   criteria was found. This text uses the source's M1′ criteria as amended by AM6 and AM22 (every member in the
   set leads, equal hashes, 0 refusals) plus the conflict halt. The source's M1′ also required "mobileverify
   registry root committed", which AM21/AM23 make optional for a leader; confirm which applies.
4. **V9 in gate 1.** The source lists V9 (GossipSub parameters, G4); the frozen plan names V1-V8. This text keeps
   V9 in gate 1; confirm or move G4 to "not vectorised".
