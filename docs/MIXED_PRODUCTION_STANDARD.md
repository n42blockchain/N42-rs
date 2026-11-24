# N42 mixed block production standard, profile 1 (v0.3 = v0.2 + decisions O1-O10 + amendments AM1-AM15)

Status: proposal for the owner, 2026-11-23. Read-only research; no repo was changed.
Supersedes the 2026-11-23 draft (`MIXED-PRODUCTION-STANDARD-DRAFT.md`, "the draft"), keeping its item ids
(A1… J4) so the two can be diffed. Code citations, evidence and revision notes are in the draft and not repeated;
this document is self-contained as a **rule set**.

**Premise (owner, 2026-11-23):** every N42 native chain so far is a testnet. All restart from one new genesis.
Nothing old is served, replayed or read. There is no compatibility debt.

Clients: **gov5** (Go, reference for bytes), **n42-rs** (Rust, reth fork), **n42-26** (Rust).
Per-client status tokens: **OK** (conformant today), **CHANGE** (must implement or alter; what and where),
**REMOVE** (legacy code becomes dead under this profile and may be deleted; deleting it is optional, but it MUST NOT
be reachable on a Profile-1 chain).

---

## 1. Design principles

- **P1. One profile.** Profile 1 has exactly one signing profile (H2-v4 chain-bound domains, POP DST), one header
  layout, one transaction set and one sync protocol set. There is no legacy profile, no legacy signing domain, no
  legacy header variant, no legacy decoder. A client's code for those MUST be unreachable on a Profile-1 chain.
- **P2. Everything from block 0.** Every rule in this document holds from genesis. A Profile-1 genesis carries
  **no** activation field for anything specified here (no `deferredExecutionTime`, `mobileAnchorTime`,
  `unchangedAccountNoOpTime`, `rotateOnTimeoutView`, `balTime`, `eofTime`, `ltHashTime`, `interopV4`,
  `twoPhaseVoteGate`, …). The Ethereum fork fields are present and all 0 only because they name the EVM rule set.
  The genesis field `"n42Profile": 1` is the single switch that says "all of this, from block 0".
- **P3. The genesis is the only source.** Every consensus-visible value comes from the genesis `config`. No
  environment variable, CLI flag or side file may set, override or default one. Bench overrides are permitted only
  for local behaviour that cannot change what a block, a vote, a QC or a view means (list in §1.J4).
- **P4. Fail closed at start-up.** A client MUST refuse to start on a genesis that contains a field it does not
  know or does not implement, a missing mandatory field, or a value outside its implemented range. Unknown fields
  are never "ignored on purpose".
- **P5. Delete old-data rules.** Rules that existed only for old data are not part of the standard: the legacy
  unchanged-account write, "every stored slot is written", legacy portable snapshot formats (`0x01`), v1 sync
  tolerance of old servers, the legacy QC/extra layouts, chain-94/95 exceptions (block-number forks, EOF, replay-v2
  base fees, the native exemptions of D3/D5), and the per-chain env switches that selected them.
- **P6. Choice order.** Correctness first, then simplicity, then performance. Pure execution and header validity
  follow Ethereum. Byte formats follow gov5 where gov5 is already the byte-exact reference and is sane. N42
  mechanisms take the fastest design that is proven across clients.
- **P7. Future changes** (only): a new rule activates at one genesis-config point (`<name>Time` for execution and
  header rules, `<name>View` for pacemaker/schedule rules), absent = off; it ships with a vector, a row here and a
  mixed round; a client that does not implement it refuses to start on a genesis that sets it (P4).

---

## 2. The rule for every inventory item

`(draft: X)` gives the draft's verdict. Where the draft said DIFF or UNDEF, the line "Why" gives the reason for the
chosen rule.

### (a) Chain configuration and genesis

**A1. Chain id, genesis hash, fork digest.** (draft: DIFF)
Rule: `config.chainId` and the genesis hash computed from the genesis file (A6) are the only sources; fork digest
= `genesisHash[0:4]`; the signing identity is `(chainId, genesisHash)`.
Why: P3. — gov5 OK · n42-rs OK · n42-26 CHANGE (drop `N42_CHAIN_ID`, `N42_INTEROP_GENESIS_HASH`; compute both
from the genesis).

**A2. Source of consensus parameters.** (draft: DIFF)
Rule: every parameter in §5's `config` is read from the genesis by every client; nothing else.
Why: P3. — gov5 OK · n42-rs CHANGE (refuse unknown `hotstuff` fields, `qmdb-reth/src/hotstuff.rs:33-37`) ·
n42-26 CHANGE (read `config.hotstuff`; retire the `N42_CONSENSUS_CONFIG` file and every env listed in J4).

**A3. Validator set.** (draft: DIFF)
Rule: `config.hotstuff.validators[] = {address, blsKey}`; list order = QC bitmap order = leader index;
`f = ⌊(n−1)/3⌋`, quorum `2f+1`; `n ≥ 4`.
Why: P3. — gov5 OK · n42-rs OK · n42-26 CHANGE (read from genesis; drop `initial_validators` and the
`N42_VALIDATOR_COUNT` dev path for Profile 1).

**A4. Fork schedule.** (draft: DIFF)
Rule: execution is Ethereum **Amsterdam as implemented by gov5 and n42-rs on native chains**
(`docs/GLAMSTERDAM_EXECUTION_PARITY.md`) with every earlier fork, all at 0. No EOF, no block-number forks, no
N42-only fork fields. The genesis spells the forks with Ethereum names (`shanghaiTime` … `osakaTime`,
`amsterdamTime`), all 0.
Why: Ethereum dropped EOF; no Rust client has it; nothing old needs it. — gov5 CHANGE (accept `amsterdamTime` as its
Glamsterdam, refuse `eofTime`/block-number forks on Profile 1) + REMOVE (EOF reachability on native) · n42-rs OK
(already reads `amsterdamTime`, `qmdb.rs:120`) · n42-26 CHANGE (Amsterdam execution; drop forced
`cancun_activated()` and `N42_GOV5_PRAGUE_TIME`).

**A5. State scheme.** (draft: DIFF)
Rule: QMDB only (`stateScheme: "qmdb"` implied by `n42Profile: 1`; the field is still written for tooling).
— gov5 OK + REMOVE (legacy-keccak/JMT/BMT paths unreachable) · n42-rs OK · n42-26 CHANGE (drop
`N42_GOV5_QMDB_EXECUTION*`, `N42_GOV5_STATE_ROOT_TRUST`; always recompute).

**A6. Genesis header and root.** (draft: AP)
Rule: header fields from §5; `stateRoot` = QMDB root of the alloc (`qmdb_compat` encodings); `extraData` empty;
every fork-dependent field as Ethereum derives it at timestamp 0 with Amsterdam active, `parentBeaconRoot` zero,
`mobileRegistryRoot` zero. A shared vector (V8) pins the hash.
— gov5 OK · n42-rs OK · n42-26 CHANGE (build the genesis header itself and match V8).

**A7. Alloc validity.** (draft: DIFF)
Rule: an alloc entry with nonce 0, balance 0, no code and non-empty storage is a start-up error (Q-S1); so is any
storage entry with value 0.
Why: owner decision Q-S1; the zero-value clause removes the remaining ambiguity at no cost. — gov5 CHANGE (zero-value
slot clause) · n42-rs CHANGE (both clauses, `changes_from_alloc`) · n42-26 CHANGE (both).

**A8. Block reward.** (draft: AP)
Rule: `hotstuff.devBlockReward` wei to the coinbase and to `devFaucetAddress` each block, as rewards (B6), from
block 1. — gov5 OK · n42-rs OK · n42-26 OK.

**A9. Unchanged accounts.** (draft: DIFF, consensus fork)
Rule: an account whose post-block value equals its pre-block value is **not written** to QMDB, from block 1. No
field gates it.
Why: the no-op rule is what n42-rs does and gov5 implements; QMDB is positional so the write set must be defined;
"not written" is the smaller write set. — gov5 CHANGE (apply unconditionally under `n42Profile`) + REMOVE (legacy
write path, `unchangedAccountNoOpTime`) · n42-rs OK · n42-26 CHANGE (verify by V3; implement if needed).

**A10. Deferred execution.** (draft: DIFF)
Rule: always on, depth `k = config.hotstuff.deferredExecutionDepth` (Profile 1: **1**). Header N carries
`stateRoot`, `receiptsRoot`, `logsBloom`, `gasUsed` of block N−k; block 1's are genesis's.
Why: on from genesis removes the switch-over invariant; depth 1 is the only depth gov5 main and n42-rs both
implement and both have run; depth > 1 is a future P7 change (O4). — gov5 CHANGE (read depth from genesis, refuse ≠ 1)
+ REMOVE (`qs` `N42_DEFERRED_DEPTH*` env, `deferredExecutionTime` switch) · n42-rs CHANGE (on without
`deferredExecutionTime`) + REMOVE (gate-crossing logic) · n42-26 CHANGE (implement deferred execution).

**A11. 0x50 AltSig.** (draft: DIFF)
Rule: **not in Profile 1** (O3). A 0x50 transaction is invalid everywhere (pool, block, execution).
Why: gov5 has no implementation; admitting it makes milestone 1 depend on new gov5 work. — gov5 OK · n42-rs CHANGE
(refuse at start-up if `altSigTx` is set on a Profile-1 genesis; keep the code for a later P7 activation) · n42-26
CHANGE (refuse type 0x50 on Profile 1).

**A12. Frame blocks.** (draft: DIFF)
Rule: **not in Profile 1.** Transactions root = ordered Ethereum transactions trie; bodies carry full transactions.
Why: three incompatible designs, none specified across clients, and gov5's changes what a vote attests; one design is
a future P7 change. — gov5 REMOVE (unreachable `N42_FRAME_BLOCKS`/`N42_VOTE_ON_AVAILABILITY` on Profile 1) ·
n42-rs CHANGE (refuse `frameBlocks` on Profile 1) · n42-26 REMOVE (`N42_FRAME_BLOCKS`).

**A13. Vote gating.** (draft: DIFF)
Rule: a Round-1 vote requires static validity of the proposal (E6) including the deferred fields of B13 (which
need the ancestor's execution); a node MAY additionally wait for its own import before voting Round 1. The
CommitVote requires the node's own import of the block to have succeeded.
Why: this is gov5's two-phase gate, which keeps "a CommitQC proves 2f+1 executions"; n42-rs's import-gated Round 1
is a permitted delay, not another rule. — gov5 CHANGE (always on; drop the flag) · n42-rs OK (drop the flag) ·
n42-26 CHANGE (CommitVote after import; vote on B13 fields).

**A14. Signing profile.** (draft: DIFF)
Rule: H2-v4 only (E10). — gov5 CHANGE (always v4) + REMOVE (legacy domains, `interopV4` flag) · n42-rs REMOVE
(`Native`, `Gov5Legacy` profiles unreachable) · n42-26 REMOVE (`N42_GOV5_LEGACY_SIGNING`, Native profile).

**A15. Leader tenure.** (draft: DIFF)
Rule: `config.hotstuff.leaderTenure` T ≥ 1, mandatory; `leader(v) = (v / T) mod n` over the set of view v.
Why: P3; with E4 a dead leader costs one base timeout whatever T is. — gov5 OK + REMOVE
(`N42_HOTSTUFF_LEADER_TENURE`) · n42-rs CHANGE (mandatory field) · n42-26 CHANGE (implement tenure, from genesis).

**A16. Timeouts.** (draft: DIFF)
Rule: `baseTimeoutMs`, `maxTimeoutMs` mandatory, no defaults.
Why: the defaults differed by 10x. — gov5 CHANGE (mandatory) · n42-rs CHANGE (mandatory) · n42-26 CHANGE (from genesis;
drop `N42_BASE/MAX_TIMEOUT_MS`).

**A17. Block interval.** (draft: DIFF)
Rule: `config.hotstuff.blockIntervalMs` (mandatory): a leader proposes no earlier than this long after it first
held the parent. It is pacing, not a timestamp step (B4).
Why: sub-second pacing is proven on the bench; whole-second `period` cannot express it. — gov5 CHANGE (ms field;
`period` gone) · n42-rs CHANGE (field replaces `period` and `F7_BLOCK_INTERVAL_MS` as the source) · n42-26 CHANGE
(from genesis; drop `N42_BLOCK_INTERVAL_MS`).

**A18. Epochs.** (draft: DIFF)
Rule: `epochLength` E ≥ 1 views, mandatory; epoch(v) = (v−1)/E; boundary b: b > 1 and (b−1) mod E = 0.
— gov5 OK · n42-rs OK (mandatory) · n42-26 CHANGE (from genesis).

**A19. Committee pool.** (draft: AP)
Rule: `config.hotstuff.committeePool {seedHex, poolSize, committeeSize, rampBlocks}` mandatory and always on
(B5). No `enabled` flag, no `allowHandover`.
— gov5 CHANGE (drop flag; refuse `allowHandover`) · n42-rs CHANGE (same) · n42-26 CHANGE (same).

**A20. Amsterdam and MobileAnchor.** (draft: DIFF)
Rule: both from block 0 (B10, B11, I1).
— gov5 CHANGE (under `n42Profile` without `mobileAnchorTime`) · n42-rs CHANGE (same) · n42-26 CHANGE (implement).

**A21. Local pacing knobs.** (draft: UNDEF)
Rule: `fastPropose`, `minProposeDelayMs`, `ethELCompat` are not genesis fields; local proposal timing is free
within A17.
Why: they do not change what a block means. — gov5 REMOVE (genesis fields; `ethELCompat` unreachable) · n42-rs OK ·
n42-26 OK (env stays a bench knob).

**A22. Rotate on timeout.** (draft: UNDEF)
Rule: SYNC §10.2 `view_after_tc`, active from view 0 (A = 0), no field.
Why: owner-approved; with it tenure costs nothing in liveness. — gov5 CHANGE (merge `feat/hotstuff-rotate-on-timeout`,
active unconditionally) + REMOVE (`N42_HOTSTUFF_ROTATE_ON_TIMEOUT`) · n42-rs CHANGE (SYNC §10.5 list) · n42-26 CHANGE
(SYNC §10.5).

**A23. Gas limit.** (draft: UNDEF)
Rule: every header's `gasLimit` equals `config.hotstuff.gasLimit` (= the genesis header's `gasLimit`). No ramp.
Why: simplest correct rule; it satisfies Ethereum's ramp check trivially; a change is a P7 activation. — gov5 CHANGE
(check it; ignore `--miner.gasceil`) + REMOVE (`N42_STRESS_GASLIMIT`) · n42-rs CHANGE (check equality; builder takes
it from the genesis, not `--builder.gaslimit`) · n42-26 CHANGE.

### (b) Header and block format

**B1. Extra.** (draft: DIFF)
Rule: `"N42H" ‖ view u64 LE ‖ QC ‖ seal(96)`, ≤ 4096 bytes. QC = the leader's highest CommitQC (commit domain),
naming an ancestor of the block; empty only while the leader holds none (views before the first commit).
Why: SYNC §3.2 (owner-approved); one layout, legacy decoders deleted. — gov5 OK + REMOVE (legacy fallbacks in
`decodeHeaderExtra`) · n42-rs OK · n42-26 CHANGE (embed the QC).

**B2. Seal.** (draft: AU)
Rule: 96-byte BLS signature by the proposer, H2-v4 POP DST, over the header hash computed with the last 96 extra
bytes removed; **verified on import** (header invalid if wrong).
Why: correctness first: with no old unsealed headers, attributing every block costs one verification. — gov5 CHANGE
(verify) · n42-rs CHANGE (verify; `n42_h2_consensus::verify_seal` exists) · n42-26 CHANGE (sign and verify).

**B3. Constant fields.** (draft: AP)
Rule: difficulty 0, nonce 0, mixHash zero, ommersHash zero (exactly zero; the empty-list hash is invalid), no
ommers, coinbase = proposer address. All checked. — gov5 CHANGE (check, not only stamp) · n42-rs CHANGE (refuse the
empty-list hash) · n42-26 CHANGE (difficulty 0 only).

**B4. Timestamp.** (draft: UNDEF)
Rule: `parent.time ≤ header.time ≤ floor(local_now) + 2`, checked when voting (not on import of a committed block);
the leader stamps `max(parent.time, floor(now))`.
Why: sub-second blocks with whole-second timestamps cannot be strictly increasing and stay near the wall clock
(≥ 1 s per block otherwise); a vote-time bound keeps them honest; import of committed blocks must not depend on the
clock (sync). This deliberately allows equal timestamps (Ethereum requires `>`) — O7. — gov5 CHANGE · n42-rs CHANGE
(override reth's strict check inside `HotStuffConsensus`) · n42-26 CHANGE.

**B5. parentBeaconRoot.** (draft: AP)
Rule: `Blake3(committee evidence(parent.number, parent.hash, parent.receiptsRoot))`; zero for block 1.
— gov5 OK · n42-rs OK · n42-26 OK.

**B6. withdrawalsRoot = rewards.** (draft: AP)
Rule: `keccak(concat(enc(reward_i)))`, `keccak("")` when empty; the body's reward list is checked against it.
— gov5 CHANGE (check, not only stamp) · n42-rs OK · n42-26 OK.

**B7. receiptsRoot.** (draft: AP)
Rule: `keccak(concat(rlp([status, cumulativeGas, logs])))`, `keccak("")` when empty. — all OK.

**B8. requestsHash.** (draft: AP)
Rule: `keccak(rlp([]))` (no EIP-7685 requests on a native chain; the EIP-8282 calls do not run). One spelling.
— gov5 CHANGE (check) · n42-rs REMOVE (second accepted spelling) · n42-26 CHANGE (verify).

**B9. Blob gas fields.** (draft: AU)
Rule: `blobGasUsed = 0`, `excessBlobGas = 0`, checked. — gov5 CHANGE (check) · n42-rs OK · n42-26 CHANGE (check).

**B10. slotNumber.** (draft: DIFF)
Rule: element 23 = block number. — gov5 OK · n42-rs OK · n42-26 CHANGE.

**B11. mobileRegistryRoot.** (draft: DIFF)
Rule: element 24, always present (B12 for element 22). — gov5 OK · n42-rs OK · n42-26 CHANGE (element 24, not 23)
+ REMOVE (old layout).

**B12. Element 22 (block access list hash).** (draft: UNDEF)
Rule: Profile 1 writes element 22 as the empty string `0x80` (gov5's `optional,nil` gap) — the shape proven in
`mv4h4b2`; a real EIP-7928 hash is a P7 change (O6).
Why: proven byte-exact in both producing clients today; a real BAL needs a cross-client BAL vector that does not exist.
— gov5 OK · n42-rs OK (`N42Header`) · n42-26 CHANGE.

**B13. Deferred fields.** (draft: DIFF)
Rule: per A10; `header.gasUsed ≤ parent.gasLimit` (= the constant of A23).
— gov5 OK (k=1) · n42-rs OK · n42-26 CHANGE.

**B14. Base fee.** (draft: DIFF)
Rule: EIP-1559 from the parent header (elasticity 2, denominator 8; the parent's `gasUsed` field is used as
written, i.e. under A10 the grandparent's execution), checked on import. Gas limit per A23.
Why: Ethereum semantics; the reason gov5 skipped it (replay-v2 history) is gone. — gov5 CHANGE (enforce) + REMOVE (the
replay exception) · n42-rs OK · n42-26 CHANGE (verify).

**B15. Block size.** (draft: DIFF)
Rule: `MAX_BLOCK_BYTES = config.hotstuff.maxBlockBytes` (Profile 1: 64 MiB, decoded RLP). It bounds production
(byte budget F3) and **every** carrier: gossip, push, by-hash, ranges. No env cap.
Why: SYNC §3.1 value; one number instead of a gossip env plus a chunk constant. — gov5 CHANGE (from genesis; remove
`N42_MAX_GOSSIP_MB`) · n42-rs CHANGE (same, `h2-net/src/config.rs:57`) · n42-26 CHANGE (32 → genesis value).

**B16. Transaction count.** (draft: AU)
Rule: no count bound (gas and bytes bound a block). — all OK.

### (c) Transactions

**C1. Types 0, 1, 2.** (draft: AP) Ethereum rules at Amsterdam. — all OK.

**C2. Type 3.** (draft: DIFF) Rule: invalid (decided D4; O2 confirms). — gov5 CHANGE (merge
`fix/native-conformance-2026-11`; no history scan needed any more) · n42-rs OK · n42-26 CHANGE (pool, block, execution).

**C3. Type 4.** (draft: DIFF) Rule: Ethereum EIP-7702 including the shape checks (no create, non-empty list).
— gov5 CHANGE (merge D3) + REMOVE (native exemption) · n42-rs OK · n42-26 verify.

**C4. 0x50.** See A11.

**C5. Gas cap per transaction.** (draft: AU) Rule: Amsterdam's (EIP-8037, 2^32−1). — gov5 OK · n42-rs OK ·
n42-26 CHANGE (Amsterdam).

**C6. Initcode.** (draft: AU) Rule: Amsterdam's EIP-7954 cap (131,072) from block 0; the pre-Amsterdam native
exemption is moot. — gov5 OK + REMOVE (exemption) · n42-rs OK + REMOVE (`native_tx_rules.rs` exemption) · n42-26 CHANGE.

**C7. Pool vs block.** (draft: AU) Rule: only block validity is standard; pool policy MUST be a subset. — all OK.

**C8. Zero-tip / zero-value.** Covered by A9; no restriction remains.

### (d) Execution

**D1.** EVM set per A4. **D2. Amsterdam on native.** (draft: DIFF) Rule: `GLAMSTERDAM_EXECUTION_PARITY.md` as
closed (no EIP-8282 calls, no EIP-7997). — gov5 OK · n42-rs OK · n42-26 CHANGE.

**D3. System calls.** (draft: AP) Rule: EIP-2935 and EIP-4788 calls; the caller `0xff…fe` is a live empty leaf only
if A9 says it changed — **verify with V3**: under the no-op rule a never-written caller must not appear.
— gov5 verify · n42-rs verify (`changes_from_execution` adds it unconditionally on Prague blocks) · n42-26 verify.

**D4. Deletion.** (draft: AP) Rule: EIP-161 empty (nonce 0, balance 0, no code) after the block ⇒ delete; code
accounts never deleted by emptiness. — gov5 OK · n42-rs OK · n42-26 verify (V3).

**D5. Storage.** (draft: UNDEF)
Rule: per slot, compare the pre-block and post-block values: equal ⇒ no write; post = 0 and pre ≠ 0 ⇒ delete;
otherwise write. ("Net change", from block 1.)
Why: the storage analogue of A9; the smallest write set; positional roots need it stated. — gov5 verify/CHANGE (V3) ·
n42-rs verify/CHANGE (V3) · n42-26 verify/CHANGE.

**D6. QMDB root.** (draft: AP) Rule: gov5 `lib/qmdb` twig tree with `qmdb_compat` encodings, ops sorted by key hash.
— all OK.

### (e) Consensus

**E1. Quorum.** (draft: AP) per A3. — all OK.

**E2. Validator-set change.** (draft: DIFF)
Rule: a change is proposed through the reconfiguration API, staged when its block is committed, and active from the
next boundary view (A18); QCs verify against the set of their own view; `changesHash` stays zero in signatures (sets
are not on-chain).
Why: gov5's design, already matched by n42-rs's exact-view sets. — gov5 OK · n42-rs OK · n42-26 CHANGE (implement
staging; today disabled).

**E3. Leader.** per A15. **E4. Rotate on timeout.** per A22.

**E5. Pacemaker.** (draft: AU) Rule (SHOULD, not consensus-visible): `timeout = min(eff · 2^k, maxTimeoutMs)`,
k = consecutive local timeouts, reset on QC/commit or TC adoption; `eff = max(baseTimeoutMs, 2 · p95)` of the last
20 commit latencies once ≥ 5 exist. — all OK.

**E6. Proposal validity.** (draft: AP)
Rule: proposer = leader(view); justify QC valid (E11) in the **vote** or **commit** H2-v4 domain; block parent =
justify QC's block (fail-open only for an unknown parent, which is fetched first); `justify.view ≥ locked.view`;
header valid (§b), seal valid (B2), timestamp per B4.
— gov5 CHANGE (domain set per A14; seal) · n42-rs CHANGE (seal; drop "any domain") · n42-26 CHANGE (extends rule always).

**E7. Votes.** (draft: AU) Rule: one Round-1 vote and one CommitVote per view, journalled before sending, gating
per A13. — all OK (n42-26 per A13).

**E8. Early votes.** (draft: UNDEF) Rule: no vote before its A13 gate. — n42-rs REMOVE (`N42_VOTE_BEFORE_SLOT`,
`N42_VOTE_BEFORE_IMPORT` unreachable on Profile 1); others OK.

**E9. Progress votes.** (draft: UNDEF) Rule: not part of Profile 1; no message with an invalid vote signature is
ever sent. — n42-rs CHANGE (straggler grace without progress votes, or a separate message type via P7).

**E10. Signing domains.** (draft: AP) Rule: `"N42H2V4" ‖ phase(1 proposal, 2 vote, 3 commit, 4 timeout, 5 newview)
‖ chainId u64 LE ‖ genesisHash ‖ view u64 LE ‖ payload`, payload `blockHash ‖ changesHash(=0)` for proposal and
commit, `blockHash` for vote, empty for timeout/newview; DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. — all OK.

**E11. QC/TC.** (draft: AP) Rule: SYNC §1.2 wire forms. — all OK.

**E12. Commit.** (draft: AP) Rule: CommitQC on a block commits it and its ancestors; Decide broadcast. — all OK.

**E13. QC verification everywhere.** (draft: DIFF) Rule: SYNC §3.3 on every path (live, header, sync): exact set of
the QC's view, commit domain for anchors, no fallback set, unknown set ⇒ fail closed. — gov5 CHANGE (enforce, no
skip) · n42-rs CHANGE (commit domain for anchors) · n42-26 CHANGE (verify header QCs).

**E14. Finality tags.** (draft: DIFF) Rule (RPC, normative): `latest` = highest imported canonical block,
`safe` = committed (CommitQC) and executed, `finalized` = committed, executed and durable on this node.
Why: under deferred execution these differ; the definitions are the ones every client can compute. — gov5 CHANGE
(stop aliasing) · n42-rs CHANGE (`split` becomes the only mode; remove `legacy`) · n42-26 CHANGE.

**E15. Equivocation.** (draft: UNDEF) Rule: detect two Round-1 votes or two CommitVotes, or two proposals, by one
validator in one view; verify, persist the signed pair, expose it over RPC (`n42_equivocations`) and a metric. No
slashing in Profile 1 (O5). — gov5 CHANGE (proposals; RPC) · n42-rs CHANGE (persist, RPC) · n42-26 CHANGE.

**E16. Vote transport.** (draft: DIFF) Rule: every consensus message is published on
`/n42/<digest>/hotstuff_consensus/ssz_snappy`; a sender MAY also deliver it over `/rpc/hotstuff_direct/1` (same
bytes); `/n42/vote/1` is not standard. — gov5 OK · n42-rs REMOVE (`direct`-only mode on Profile 1) · n42-26 OK.

**E17. Decide on `/n42/h2/4/ssz_snappy`.** (draft: AP) — all OK.

### (f) Production behaviour

**F1. Pacing.** (draft: UNDEF) per A17/B4. — gov5 CHANGE · n42-rs OK · n42-26 CHANGE.

**F2. Empty blocks.** (draft: UNDEF) Rule: a leader proposes in every view it leads, empty if it has nothing.
Why: a skipped view costs a timeout for every member. — gov5 verify · n42-rs OK · n42-26 REMOVE (`N42_MAX_EMPTY_SKIPS`).

**F3. Byte budget.** (draft: AU) Rule (builder): transactions ≤ `maxBlockBytes/10·9 − 32 KiB − header`. — gov5
CHANGE (cap source) · n42-rs CHANGE (cap source) · n42-26 CHANGE.

**F5. Stale parent.** (draft: AP) Rule: never propose a block whose parent is not the justify QC's block. — all OK.

**F6. One proposal per view.** (draft: UNDEF) Rule: at most one signed proposal per (view, proposer); a leader
may re-propose an identical block in a later view of its tenure. A second different proposal is equivocation (E15).
— gov5 OK · n42-rs verify (same-parent rebuild path) · n42-26 verify.

**F7. Seal before own execution.** (draft: AU) Rule: allowed (headers carry the ancestor's result); a leader MUST
NOT propose block N+k before it has executed N. — all OK (n42-26 with A10).

**F8. Straggler grace.** (draft: AU) Local; see E9.

### (g) Networking

**G1.** (draft: AP) libp2p, secp256k1 identities, Noise, yamux, identify. — all OK.
**G2. Topics.** (draft: AP) consensus, block, `transaction_v2`, `/n42/h2/4`, `mobileverify_{packet,registration}`.
— n42-26 CHANGE (mobileverify topics) + REMOVE (`/n42/consensus/1`, `/n42/blocks/1`, … on Profile 1).
**G3. Message id.** (draft: AP) `keccak(genesisHash ‖ topic ‖ data)[:20]`. — all OK.
**G4. GossipSub parameters.** (draft: AU) gov5's values, a wire contract; publish them as vector V9. — n42-26 verify.
**G5. Consensus message cap.** (draft: UNDEF) Rule: `MAX_CONSENSUS_MSG = 64 KiB` decoded (a 512-member bitmap QC +
TC + headers fit with margin; vector V6 with n = 512). — all CHANGE (one constant).
**G6. Single-client protocols.** (draft: AU) none may be needed by another client. — n42-rs/n42-26 OK.

### (h) Sync

See §3.

### (i) Mobile verification

**I1.** (draft: DIFF) Rule: `docs/MOBILEVERIFY_V3_PARITY.md` surface, from block 0. — gov5 OK · n42-rs OK ·
n42-26 CHANGE (implement).
**I2. Every validator runs it.** (draft: UNDEF) Rule: a Profile-1 validator MUST run the mobileverify service (it
needs the registry root to lead). — gov5 OK (root provider: verify) · n42-rs CHANGE (refuse to start a validator
without `--mobileverify.http`) · n42-26 CHANGE.

### (j) Operations

**J1. RPC.** (draft: AU) `eth_config` refused (−32004, gov5's message); witness/proof methods refused on QMDB;
finality per E14. — n42-26 verify.
**J2. Metrics.** (draft: UNDEF) Rule: common minimum set exposed by every client: `n42_head_number`,
`n42_committed_view`, `n42_committed_number`, `n42_view_timeouts_total`, `n42_tc_formed_total`,
`n42_equivocations_total`, `n42_blocks_refused_total{reason}`. — all CHANGE.
**J3. Activation.** (draft: DIFF) P7. — all CHANGE (refuse unknown fields, P4).
**J4. Environment.** (draft: DIFF) Rule: P3. Permitted bench overrides (cannot change meaning): thread counts,
allocator, parallel build/import, persistence and cache knobs, ingest/flood knobs, logging/trace, settlement
timing of `latest` only. **Forbidden on Profile 1** (each client refuses to start if set): gov5
`N42_MAX_GOSSIP_MB`, `N42_STRESS_GASLIMIT`, `N42_DEFERRED_DEPTH*`, `N42_FRAME_BLOCKS`,
`N42_VOTE_ON_AVAILABILITY`, `N42_HOTSTUFF_LEADER_TENURE`, `N42_HOTSTUFF_ROTATE_ON_TIMEOUT`; n42-rs
`N42_MAX_GOSSIP_MB`, `N42_VOTE_TRANSPORT=direct`, `N42_VOTE_BEFORE_SLOT`, `N42_VOTE_BEFORE_IMPORT`,
`N42_FRAME_BLOCKS`, `N42_BENCH_UNSAFE` paths that skip checks; n42-26 `N42_CHAIN_ID`, `N42_CONSENSUS_CONFIG`,
`N42_VALIDATOR_COUNT`, `N42_BASE/MAX_TIMEOUT_MS`, `N42_BLOCK_INTERVAL_MS`, `N42_GOV5_*`, `N42_LEADER_TENURE`,
`N42_FRAME_BLOCKS`, `N42_SKIP_STATE_ROOT`, `N42_DEFER_STATE_ROOT`, `N42_SKIP_TX_VERIFY`, `N42_REWARD_*`,
`N42_MAX_EMPTY_SKIPS`.

---

## 3. Sync: straight to the final form

**Recommendation: Profile 1 speaks only the final protocol set; no `/1` range protocol, no negotiation.**

| Protocol | Profile 1 |
| --- | --- |
| `/rpc/status/1/ssz_snappy` | keep (72 bytes, frozen; it carries no legacy behaviour) |
| `/rpc/block_by_hash/1/ssz_snappy`, `/rpc/block_push/1/ssz_snappy`, `/rpc/hotstuff_direct/1` | keep (no v2 exists or is needed); miss = `0x03 RESOURCE_UNAVAILABLE` (one encoding, closes SYNC B9) |
| `/rpc/bodies_by_range/1` | **drop**; use `/rpc/bodies_by_range/2` (SYNC §5.1): committed-only, byte budget, END trailer |
| `/rpc/commit_qc/1` | **required** (SYNC §5.2) |
| `qmdb_status/1`, `qmdb_manifest/1`, `qmdb_twigs/1`, `code_by_hash/1` | **required servers** on every client (SYNC §5.3), portable `0x03` records only |
| `headers_by_range`, snapshot/`get_*_range`, witness RPCs of gov5 | not standard |

Anchored ranges (SYNC §3.3/§3.4) are **enforced** from day one: the `observe` mode and `N42_SYNC_ANCHOR` switch are
removed. Servers serve committed blocks only.

Parts of N42-SYNC-SPEC.md that become unnecessary under Profile 1 (the spec is not rewritten; these are skipped):

- §1.2 the legacy Extra layouts and their decoder rule in §3.2 ("Decoders MUST accept the legacy layouts").
- §2 breakages B2 (error chunk after prefix), B4 (uncommitted serving), B6 fallbacks, B7 (env gossip cap), B8
  (scoring of ahead requests on v1), B9 (miss encoding), B10 (genesis alloc, replaced by A7) — resolved by
  construction; B1, B3, B5 remain as n42-26 work items.
- §3.1 the "legacy profile is gov5-only" clause; `deferredExecutionDepth` with a qs-line-only k > 1.
- §4 entirely (v1 as it is, early-stop/cap clarifications, v1 tolerance), except §4.1 status, §4.2 by-hash and §4.4
  push, which stay as the frozen definitions.
- §5.0 capability discovery and the fallback-to-v1 rule; v1 result-code restriction.
- §6 limits that refer to v1 (keep the v2 and state-sync limits; block size per B15).
- §7.2 rollout order (nothing to stay compatible with); §7.1 rows that only bridge v1.
- §10.3 activation (`rotateOnTimeoutView`) and the bench override env; §10.4 vectors S6 and S8 (switch-off /
  activation view).
- The weak-subjectivity checkpoint of §3.6 stays, but "checkpoint without QC" is not needed while every chain
  starts from genesis with every header carrying a QC (B1).

---

## 4. Decisions the premise does not settle (with recommendations)

| # | Decision | Recommendation |
| --- | --- | --- |
| O1 | n42-26's role | **Full producer**, but milestone 1 may start with n42-26 as a voting follower: following already requires every validity rule (Amsterdam, deferred, field 24), producing adds only the builder, the QC embedding and the registry root. Decide whether n42-26 is staffed for this at all; if not, Profile 1 is a two-client standard with n42-26 as an observer. |
| O2 | Blob (type 3) | **Off** (already D4; no data-availability layer on a native chain). |
| O3 | 0x50 AltSig in Profile 1 | **Out** of Profile 1; first P7 activation once gov5 implements it (it is the biggest proven throughput lever, so schedule it). |
| O4 | Deferred execution depth | **1** (both clients proven); depth 2 as a P7 change after a mixed depth-2 round. |
| O5 | Equivocation | **Evidence only** (E15); slashing needs on-chain stake, which testnets do not have. |
| O6 | Element 22 (BAL hash) | **`0x80` gap** in Profile 1 (proven); real EIP-7928 hash after a cross-client BAL vector. |
| O7 | Equal timestamps (B4) | **Allow** (`≥`), with the vote-time clock bound; the alternative is timestamps running ahead of the wall clock at sub-second pacing. |
| O8 | Tenure, timeouts, interval | **T = 8**, base 6,000 ms, max 30,000 ms, interval 500 ms (tighter base timeouts measured worse; 8 is gov5's run-97 shape, harmless with rotate-on-timeout). |
| O9 | Gas limit | **480,000,000** per block (the n42-rs bench tier at which both clients' import is proven); raise by P7. |
| O10 | EOF | **Off** (no Rust implementation; Ethereum dropped it). |

---

## 5. The standard genesis ("N42 native chain, Standard Profile 1")

```jsonc
{
  "config": {
    "chainId": 1144,                    // new id; no testnet reuses it (94, 95, 1142, 1143 retired)
    "n42Profile": 1,                    // the single switch: every rule of this document from block 0
    "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0,
    "byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0, "istanbulBlock": 0,
    "berlinBlock": 0, "londonBlock": 0,  // Ethereum pre-merge forks, all at 0 (EVM rule set only)
    "mergeNetsplitBlock": 0, "terminalTotalDifficulty": 0, "terminalTotalDifficultyPassed": true,
    "shanghaiTime": 0, "cancunTime": 0, "pragueTime": 0, "osakaTime": 0,
    "amsterdamTime": 0,                 // Amsterdam execution per GLAMSTERDAM_EXECUTION_PARITY
    "blobSchedule": { /* Ethereum defaults; inert because type 3 is invalid */ },
    "consensus": "hotstuff",
    "stateScheme": "qmdb",
    "hotstuff": {
      "validators": [ { "address": "0x…", "blsKey": "0x…(48 bytes)" } ],  // n ≥ 4; order = bitmap = leader index
      "leaderTenure": 8,                // views per leader (A15)
      "baseTimeoutMs": 6000,            // first view timeout (A16)
      "maxTimeoutMs": 30000,            // backoff ceiling (A16)
      "blockIntervalMs": 500,           // minimum pacing after the parent is held (A17)
      "epochLength": 200,               // views per epoch; set changes activate at boundaries (A18, E2)
      "deferredExecutionDepth": 1,      // header N carries block N-1's execution (A10)
      "gasLimit": 480000000,            // every header's gasLimit (A23); equals the genesis header gasLimit
      "maxBlockBytes": 67108864,        // 64 MiB decoded RLP, every carrier (B15)
      "committeePool": { "seedHex": "0x…32 bytes", "poolSize": 200000, "committeeSize": 512, "rampBlocks": 1000000 },
      "devBlockReward": "1000000000000000000",   // wei per block to coinbase and faucet (A8)
      "devFaucetAddress": "0x42e9819036f61bF665D5f727E8C03121f12f586e"
    }
  },
  "nonce": "0x0", "timestamp": "<T0>", "extraData": "0x", "gasLimit": "0x1c9c3800",
  "difficulty": "0x0", "mixHash": "0x00…", "coinbase": "0x00…00", "baseFeePerGas": "0x3b9aca00",
  "alloc": { /* Prague system contracts (EIP-2935, EIP-4788, …), faucet balance; no storage-only entries (A7) */ }
}
```

The genesis hash is pinned by vector V8 once the alloc is fixed. To load it:

- **gov5:** recognise `n42Profile` (all predicates true; refuse legacy activation fields); read `amsterdamTime`;
  `baseTimeoutMs`/`maxTimeoutMs`/`blockIntervalMs`/`gasLimit`/`maxBlockBytes`/`deferredExecutionDepth` (new names;
  `period`, `baseTimeout`, `maxTimeout`, `committeePool.enabled`, `interopV4`, `twoPhaseVoteGate` refused);
  `devBlockReward` as a decimal string (verify the type: uint64 today, 1e18 fits, a string does not).
- **n42-rs:** the same field set in `HotStuffGenesisConfig` with `deny_unknown_fields`; derive every
  `*_active_at` predicate from `n42Profile`; genesis `extraData` empty (today's devnet genesis carries a Clique-style
  extra).
- **n42-26:** read the whole `config.hotstuff` object; build the QMDB genesis header itself; Amsterdam.

(Field naming follows camelCase with explicit units; renaming is cheap now and never again.)

---

## 6. Per-client work, by milestone

Vectors (create first, bytes from gov5): **V1** header profile (B1-B12, element 22 gap, seal), **V2** roots
(receipts, rewards, committee evidence), **V3** QMDB write sets (A9, D3, D4, D5, A7), **V4** transaction validity
(C2, C3, A11 refusals, C5, C6), **V5** header validity (B4, B9, B14, A23, B13), **V6** consensus messages incl.
n = 512 (E10, E11, G5), **V7** schedule (A15, SYNC §10.4 without S6/S8), **V8** genesis hash + refused geneses (P4),
**V9** GossipSub parameters.

### Milestone 1 — three clients produce and finalise blocks on the standard genesis, idle

Gate: V1, V2, V3, V5, V6, V8 green in all three; mixed round **M1′**: 4+ validators with every client present
(at least one per client), standard genesis, T = 1 override **not** allowed (T = 8 as in genesis), 30 min idle,
every client leads ≥ 1 full tenure, equal hashes at every height, 0 refusals, mobileverify registry root committed.

- **gov5:** `n42Profile` + new field names + refuse unknown/legacy fields (A2, A4, J3); always-on deferred k=1,
  two-phase gate, H2-v4, committee pool, MobileAnchor/Amsterdam without time fields (A10, A13, A14, A19, A20); merge
  D3/D4 (C2, C3); unchanged-account no-op unconditional (A9); checks for B3, B6, B8, B9, B14, A23, seal B2,
  timestamp B4; `maxBlockBytes` (B15); merge rotate-on-timeout active from 0 (A22) — needed because T = 8.
- **n42-rs:** `deny_unknown_fields` + `n42Profile` predicates (A2); mandatory tenure/timeouts/interval/gasLimit/
  maxBlockBytes from genesis (A15-A17, A23, B15); B4 timestamp rule overriding reth's strict check; seal verify (B2);
  ommers-hash exactness (B3); one requestsHash spelling (B8); rotate-on-timeout (A22, SYNC §10.5); D3/D5 per V3;
  Q-S1 (A7); refuse `altSigTx`/`frameBlocks` on Profile 1; disable progress votes and direct-only votes (E9, E16).
- **n42-26:** genesis-sourced config (A1-A3, A15-A18, A23); tenure + rotate-on-timeout (A15, A22); Amsterdam
  execution, field 24, slot number, element-22 gap (A4, B10-B12, D2); deferred execution k=1 and the A13 gate
  (A10, B13); QC embedding and seal (B1, B2); type-3/0x50 refusal (C2, A11); 64 MiB (B15); mobileverify service and
  topics (I1, I2, G2); V3 write-set conformance. (If O1 = follower first: everything except the builder-side B1/B2/I2.)

### Milestone 2 — under load, with a crash and a rejoin

Gate: V4, V7, V9 green; sync servers and clients of §3 in all three (`bodies_by_range/2`, `commit_qc/1`, state
sync servers; anchored ranges enforced); rounds **M2a** each client leads under load (≥ 50% full blocks at 480M gas)
while the others follow; **M2b** SIGKILL of one member of each client in turn, rejoin by range within one epoch;
**M2c** a member absent ≥ 1 h rejoins by state sync; pass = M1′ criteria + no conflicting commit + rejoined member
votes within 60 s of reaching the head.

- **gov5:** bodies_by_range/2 + commit_qc/1 + state-sync servers/clients; enforce anchors (remove observe mode);
  equivocation evidence RPC (E15); metrics J2.
- **n42-rs:** stream `/2` replies, serve committed only; `commit_qc/1`; state-sync servers; finality tags (E14);
  E15, J2.
- **n42-26:** range client (it has none), `/2` + `commit_qc/1` servers, open serving to statused peers (SYNC B3),
  state-sync servers; E14, E15, J2.

### Milestone 3 — tenure > 1 with rotate-on-timeout, epoch change, validator change

Gate: rounds **M3a** kill the current tenure leader (each client in turn): every TC hands the window on per
`view_after_tc`, ≤ 1 base timeout per dead leader; **M3b** ≥ 5 epoch boundaries with a TC landing on a boundary
(the clamp); **M3c** add a validator of each client and remove one, through the reconfiguration API, activation at the
boundary on every client; **M3d** negative leader (a test build) proposing V4/V5-invalid blocks and a double proposal:
every honest member refuses and records evidence.

- **gov5:** nothing new beyond M1/M2 if rotate-on-timeout and reconfig are merged; proposal-equivocation detector.
- **n42-rs:** reconfiguration API parity with gov5's (`ProposeAddValidator`/`ProposeRemoveValidator`) if absent
  (unverified); epoch clamp in `advance_to_view`.
- **n42-26:** staged validator-set changes (E2, today disabled), epoch boundaries from genesis.

## Decisions of 2026-11-23 (owner-delegated; these close section 4)

The owner delegated the open decisions of section 4 and the standard genesis of section 5 to the
n42-rs side, on the premise that every chain so far is a testnet and restarts from a new genesis.
Order of preference used: no fork or stall risk; what the clients already implement and have
proven; the first milestone must be reachable soon (optional features start off); measured values
for performance settings. A decision changes only by a post from the owner, or by a documented
objection from gov5 or n42-26 that the owner accepts.

| Id | Decision | Reason |
| --- | --- | --- |
| O1 | n42-26 is a full producer in the standard. It may join milestone 1 as a voting follower and must lead by milestone 2. | A standard with a permanent second-class client is not a mixed production standard; the follower start keeps milestone 1 from waiting on its Amsterdam and deferred-execution work. |
| O2 | Blob (type 3) transactions are OFF: refused by pool, builder and block validity. | No blob consumer exists on the chain; n42-rs already refuses; one rule instead of three behaviours. |
| O3 | Type 0x50 (Ed25519) is NOT in profile 1. It is the first candidate for a later profile once gov5 implements it and the shared vectors pass. | Only the Rust clients implement it; milestone 1 must not wait for it. All-Rust bench chains are outside the profile. |
| O4 | `deferredExecutionDepth` is a mandatory genesis field, a per-chain constant (not an activation). The standard genesis sets 1. A client refuses a value it does not implement. | Depth 1 is proven on gov5 and n42-rs; depth 2 (the n42-rs bench chains) stays expressible without an activation mechanism and becomes mixed-eligible after a mixed depth-2 round. |
| O5 | Equivocation: evidence only (detected, logged, gossiped, never voted for twice); no slashing in profile 1. | Slashing needs staking state none of the clients share today. |
| O6 | Block access list hash: keep the `0x80` gap at header element 22. | The shape proven in the mixed MobileAnchor round mv4h4b2. |
| O7 | Equal timestamps are allowed: `parent.time <= time <= now + 2 s`, checked when voting; the leader stamps `max(parent.time, now)`. | With sub-second blocks a strict `>` pushes timestamps ahead of the wall clock by a second a block. |
| O8 | Standard genesis: `leaderTenure` 8, `baseTimeoutMs` 6000, `maxTimeoutMs` 30000, `blockIntervalMs` 500, `epochLength` 200. All four are mandatory per-chain genesis constants; no client default exists. | Chain 94's proven timeouts; tenure > 1 exercised from the start (with rotate-on-timeout from view 0); differing client defaults were a liveness risk. |
| O9 | Gas limit: a fixed per-chain genesis constant, 480M on the standard genesis; a header with any other gas limit is invalid. | The measured bench tier; removes the per-node command-line gas target and the unchecked gas-limit step. |
| O10 | EOF is OFF. | Neither Rust client implements it; nothing on a new genesis needs it. |

Also decided with the premise: the account no-op rule and the storage net-change rule hold from
block 0; rotate-on-timeout holds from view 0; sync goes straight to `bodies_by_range/2`,
`commit_qc/1`, anchored ranges enforced and committed-only serving (section 3), keeping status/1,
block_by_hash/1, block_push/1 and hotstuff_direct/1.

Standard genesis (section 5): accepted as proposed, chain id 1144, with one item to verify before
the file is cut: the JSON encoding of `devBlockReward` (number or decimal string) must be the one
gov5 parses; the three clients agree on the file by loading it to the same genesis hash (vector V1).

## Transaction type range reserved for N42 (owner, 2026-11-24)

EIP-2718 type bytes `0x50`-`0x5F` are reserved for N42-specific transaction types.

| Type | Use | Status |
| --- | --- | --- |
| `0x50` | Ed25519-signed transaction (`docs/spec/N42_TX_0x50.md`) | Not in profile 1 (decision O3); first candidate for a later profile once gov5 implements it and the shared vectors pass. |
| `0x51` | Reserved for a post-quantum signature transaction (Falcon / FN-DSA is the candidate) | Not specified. To be designed when the FN-DSA standard and Ethereum's frame transaction (EIP-8141, type `0x06`, with its post-quantum frame mode) have settled; the choice is between a native type with batch verification and following the frame transaction. A Falcon-512 signature plus public key is ~1.5 KB against ~110 bytes for a transfer today, so it is an opt-in type, never the default. |
| `0x52`-`0x5F` | Unassigned | Reserved. |

Rules:
- In profile 1 every type in `0x50`-`0x5F` is refused by pool, builder and block validity.
- A type in this range is added only by a profile change (one activation point on all clients,
  with a vector set and a mixed round).
- If Ethereum L1 ever allocates a type inside this range, N42's NEXT new type moves to the next
  free number (`0x53`, `0x54`, ...); a type already live on a chain keeps its number.
- Known allocations elsewhere, for reference (not verified one by one): Ethereum L1 `0x00`-`0x04`
  and `0x06` (frame transaction, draft); Arbitrum `0x64`-`0x6A`; zkSync `0x71`; OP-stack deposit
  `0x7E`; other L2s in `0x7x`. Nothing known in `0x50`-`0x5F`.
- Blob transactions (type `0x03`) stay off in profile 1 (decision O2): they exist to give rollups
  cheap data availability on a slow L1, and no rollup posts data to N42. If N42 is ever used as
  a data availability layer they return as a profile change.

## Amendments of 2026-11-24 (v0.2.1): n42-26's review and gov5's confirmation

gov5 confirmed v0.2 (handoff posts of 2026-11-24, about 02:52 and 02:55 EST). n42-26 reviewed it and raised
the points below; each was checked against the code and decided under the owner's delegation. Where
an amendment contradicts the text above, the amendment holds.

**AM1 (n42-26, accepted): what `amsterdamTime` means.** On Profile 1 `amsterdamTime: 0` activates
exactly the execution changes tabled in `docs/GLAMSTERDAM_EXECUTION_PARITY.md` (the set gov5 and
n42-rs run byte-equal today) and nothing else. It is NOT the upstream client's own bundle of that
name: a reth-derived client must not enable any other EIP its library ties to the same field. The
vector set V2/V3 pins the result; a client lists, in its conformance note, every EIP its library
would have enabled and how it is switched off.

**AM2 (n42-26, accepted): block size.** The only size bound is `config.hotstuff.maxBlockBytes`
(B15). The Ethereum block-RLP size cap (EIP-7934) and any client's own smaller cap do not apply to
production or import on a native chain. n42-26 still enforces 8 MiB at build and import
(`native_payload.rs:227`, `:447`): CHANGE.

**AM3 (n42-26, accepted; corrects B8 and gov5's reading of it): requestsHash.** B8's
"`keccak(rlp([]))`" was a mislabel. The rule is the value gov5 and n42-rs produce today on every
live header, the empty-trie root:
`0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`, in every header including
genesis, checked. Neither EIP-7685's `sha256("")` (`0xe3b0c442…`) nor the empty-ommers hash
(`0x1dcc4de8…`) is valid. gov5: do NOT implement `0x1dcc4de8…` (your 03:40 post); only your genesis
header changes. n42-rs REMOVE (the second spelling, `is_empty_requests_hash`). n42-26 CHANGE.

**AM4 (n42-26, accepted): the seal, byte for byte.** `sealHash = keccak256(rlp(H'))` where `H'` is
the full header (every element, `mobileRegistryRoot` included) with the last 96 bytes of
`extraData` removed (removed only when `extraData` is longer than 96 bytes). The seal is the
proposer's BLS signature over those 32 bytes with the H2-v4 proof-of-possession DST, placed in the
last 96 bytes of `extraData`. Reference: gov5 `sealHash` / `Seal`, n42-rs
`h2-consensus/src/header_profile.rs` `seal_hash` / `seal_header` / `verify_seal`; pinned by V1. On
Profile 1 the seal IS verified on import and before the Round-1 vote; this overrides the sync
spec's statement that the seal is not checked (that described pre-profile chains).

**AM5 (n42-26, formal objection, accepted): validator-set changes.** As written, E2 leaves a staged
set covered by no signature (`changesHash` zero, sets not on chain), so a faulty leader could make
honest nodes activate different sets. Decision: on Profile 1 the validator set is the genesis set;
the reconfiguration API is disabled and a node refuses a staged change. Milestones 1 and 2 run on
the fixed set. E2 is reopened: before milestone 3 a design is agreed in which the change is carried
in a block and bound by the votes on that block (a non-zero `changesHash` over the canonical
encoding of the new set is the candidate), with a vector and a mixed round. Milestone 3's
"validator added / removed" gate waits for it.

**AM6 (n42-26, accepted; amends O1 and the M1' gate).** A voting member that does not propose times
out every one of its tenures, so "voting follower" cannot pass "every client leads a full tenure".
O1 becomes: a client is in the validator set of a mixed round only if it can lead. A client not yet
able to lead joins as a verifying non-validator node (imports and verifies every block, same
hashes, not in the set). M1' gate: every client IN THE SET leads at least one full tenure; every
participating client holds the same hash at every height. n42-26 is a full producer by milestone 2.

**AM7 (n42-26): stale status lines about n42-26.** Accepted in principle (W6 QC embedding, 64 MiB,
reward parsing are reported done). n42-26 posts its corrected status per item id with file:line in
the handoff file; the per-client status column is then updated from that post.

**AM8 (gov5): `devBlockReward` encoding.** A decimal string of wei on a Profile-1 genesis; a JSON
number is refused. All three clients.

gov5's 03:40 readings of D3 (the system caller appears only if it changed), D5, C6, B3 (ommersHash
zero in genesis too), B15, A13 and J4 are accepted as the reading of the standard. n42-rs takes D3
(the `0xff…fe` live empty leaf goes away) and A13 on its milestone-1 list.

### Amendments AM9-AM11 (n42-26, second batch, accepted)

**AM9: "deleted" means "not available on Profile 1".** Wherever this standard says a rule, format,
transaction type or switch is deleted or removed, read: it MUST NOT be reachable on a chain whose
genesis says `"n42Profile": 1`. A client may keep the code for chains outside the profile (its own
performance or research chains: type `0x50`, frame blocks, deferred depth 2, bench knobs). Joining
Profile 1 with such a feature later is welcome and goes through a profile change; it is not
required of any client.

**AM10: forbidden environment and flags (J4).** On a genesis with `"n42Profile": 1`, a node that
finds one of the J4 variables or flags set REFUSES TO START, naming it. On a genesis without the
field the same variables remain that client's ordinary configuration. (Precedent in n42-26: the
test chain-id range and `N42_BENCH_UNSAFE=1`.)

**AM11: the Profile-1 numbers are Profile 1's only.** `leaderTenure` 8, gas limit 480M and
`blockIntervalMs` 500 are the values of the standard genesis, chosen so three clients can run
together; they are per-chain genesis constants (O4, O8, O9), not limits on any client's own chains.
At 480M gas and 500 ms a block holds at most 480M / 21,000 ≈ 22,857 plain transfers, about 46k TPS,
so a Profile-1 round is never compared with a single-client performance figure. Open, for the
owner: (a) how the 500 ms block interval relates to the project's 8-second slot; (b) the values are
proven on 4-7 validators only: a mixed round with 100+ validators is added as a gate before the
profile is called production-ready (after milestone 3).

### Amendments AM12-AM15 (n42-26's C9, C10, C12; with these the document is v0.3)

Source: n42-26's written review, `n42-26/.artifacts/profile1-reply/n42-26-reply-v0.2.md` (C1-C12).
gov5 agreed AM1-AM11 item by item (handoff post of 2026-11-24, about 03:02 EST).

**AM12: byte-level gaps closed (C9).**
- A15 / A18: on Profile 1 `leaderTenure` and `epochLength` are mandatory and ≥ 1; no default from
  the sync spec applies. A genesis without them, or with 0, is refused.
- A8: `devBlockReward` (AM8: decimal string of wei) MUST be a whole number of gwei and at most
  `u64::MAX` gwei, because rewards are paid as EIP-4895 withdrawals; anything else refuses the
  genesis. Whether a zero `devFaucetAddress` is legal is fixed by the genesis cases of V8 (gov5 cuts
  them; until then: a non-zero faucet amount requires a non-zero address).
- P4: the allowed `config` and `config.hotstuff` keys are a CLOSED list, published with the
  standard genesis file; any other key refuses the start. V8 carries refused-genesis cases (unknown
  key, legacy activation field, missing mandatory field, zero tenure, reward not whole gwei, a
  JSON-number reward, a storage-only alloc entry).
- B4: V3/V5 gain a pair of consecutive blocks with EQUAL timestamps, including the EIP-4788
  system call's effect for both.
- B13: under EIP-8037 `gasUsed = max(regular gas, state gas)`; V5 gains a block where state gas is
  the larger.
- B11 (`mobileRegistryRoot`): OPEN. Today a follower carries the root and does not validate it.
  Until a rule is agreed that cannot split honest nodes over registry gossip timing, Profile 1's
  rule is explicit: the root is the proposer's statement, covered by the seal and the QC, not
  re-derived by followers. gov5 states its follower behaviour; the item is revisited before
  milestone 3.

**AM13: n42-26's status (C10, AM7), from its own post (n42-26 main 4831e77).** Done: B1 QC in
Extra (34bad2b, `n42-network/src/gov5_block.rs`), 64 MiB block chunks (`gov5_rpc.rs:23-25`), clean
EOF after a served prefix (`gov5_rpc.rs:184-248`), reward parsing (string or integer, whole gwei),
a range catch-up client with strict anchors (`range_catchup.rs`), tenure from genesis and
rotate-on-timeout with the §10.4 vectors. Still CHANGE: AM2's 8 MiB cap, `bodies_by_range/2`,
`commit_qc/1`, the state-sync servers, `code_by_hash`, and the rest of §4 of its review. The
n42-26 lines of section 2, section 3 and section 6 above are read with this correction.

**AM14: dates (C12).** Milestones are counted from T0 = the owner accepts v0.3 AND the vector files
V1, V3, V5 and V8 (with the standard genesis file and its hash) exist. gov5 produces them under
`/data/blockchain/wr-logs/qs-scratch/profile1/vectors/`, V1 first.

**AM15: positions on v0.3.** gov5: agrees (AM1-AM11; AM12-AM15 to confirm). n42-rs: agrees.
n42-26: facts confirmed; its agreement and its milestone-1 entry form (recommended by its session:
verifying non-validator node in M1, producer in M2) are with its owner.

**AM16 (gov5, 2026-11-24, about 03:07 EST).** gov5 agrees v0.3. `devFaucetAddress` MUST be non-zero on a
Profile-1 genesis (a zero address refuses the genesis). B11: gov5 followers check only that the
field is present after activation and carry the value, which is the interim rule of AM12. V8's
refused cases also include zero `epochLength`, a reward above `u64::MAX` gwei, and a non-zero
reward with a zero faucet address.
