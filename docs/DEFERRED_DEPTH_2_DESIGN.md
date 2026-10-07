# Deferred execution two blocks deep: the rule, every depth-1 assumption, the timing model, the plan

*2026-10-07. A design study: code and logs read, nothing run (no cargo, no fleet, no node). The owner approved a
consensus-rule change; this document is what an implementing agent works from. Every figure that is not a quotation
of a measurement is labelled "estimate". Sources: `docs/PHASE_D_DEFERRED_EXECUTION.md` (PD) sections 2, 4, 10-13, 17;
`docs/SHARED_EXECUTION_SCOPE.md` (SES) sections 8, 15-17; `docs/INDUSTRY_SURVEY_2026_10.md` (IS) section 11;
`docs/BREAKTHROUGH_DESIGN.md` (BD) 10.86-10.90 (loop339-loop343).*

## 0. The short version

- **Rule.** Header N carries the execution result of the block two behind it on N's own chain (its parent's parent),
  for all four fields. The genesis block carries the genesis state; blocks 1 and 2 carry the genesis result (there is
  no N-2); block 3 is the first to carry an executed result (block 1's).
- **The claim to verify held, with one exception that matters.** N's execution and its includability check read the
  *output* of N-1 (the kept layers, the published output), never its header fields, so "N still executes on N-1's
  output, execution stays sequential" is true in the code. But the seal's wait for the parent's *fields* also served as
  a barrier that the parent's QMDB tree had been filed (section 2, item 8): remove the wait and the early rename of the
  parent's tree has to wait for something else, or it falls back to the parent's `Complete` stage (~105 ms after the
  parent's seal) and the root chain stops being a pipeline.
- **What D=2 buys.** It removes the root chain (`seal_to_fields` 45-46 ms + ~5) from the seal-to-seal path. It does
  not remove the *other* serial chain: the child's execution waits for the parent's state view (freeze, graft, finish).
  After section-17's seal work that chain, not the root, sets the floor: estimated 41 ms (34-48) at 200k against the
  51 ms of D=1. So D=2 is necessary for 5M TPS at 200k-transaction blocks and not sufficient (section 3).
- **Chain constant, not a fork time.** `deferredExecutionDepth` (default 1) is read at genesis and applies to every
  block at or past `deferredExecutionTime`; depth 2 is accepted only with `deferredExecutionTime` 0 (active from
  genesis). A mid-chain switch is possible (appendix A) but nobody needs it.

## 1. The rule

### 1.1 Definition

Let `result(B)` be what executing block `B` on the post-state of its parent produces: `{state_root (the QMDB root),
receipts_root (gov5's), logs_bloom, gas_used}`, exactly `executed_fields::ExecutedFields`
(`crates/n42/qmdb-reth/src/executed_fields.rs`). Let `D` be the chain's depth (`deferredExecutionDepth`, 1 or 2).

For a block `N >= 1` with parent `P` on its own chain, let `A_D(N)` be the ancestor of `N` at distance `D` on that
chain (`A_1 = P`, `A_2 = P.parent`). **The header of `N` carries `result(A_D(N))` in `stateRoot`, `receiptsRoot`,
`logsBloom` and `gasUsed`**, with `result(genesis)` = the genesis header's own four fields, and `A_D(N)` = genesis
whenever `N <= D` (the ancestor would be below genesis).

| block | D = 1 (today) | D = 2 |
| --- | --- | --- |
| genesis (0) | its own state (by definition) | its own state |
| 1 | `result(0)` | `result(0)` |
| 2 | `result(1)` | `result(0)` |
| 3 | `result(2)` | `result(1)` |
| N >= 3 | `result(N-1)` | `result(N-2)` |

Two things to read off the table. First, D=1 is the same formula, so one implementation with a depth parameter covers
both and every D=1 test stays valid. Second, the chain start repeats the genesis result `D` times (blocks 1..D)
instead of once; nothing is lost, because `result(0)` is the genesis state and every later result appears in exactly
one header (`result(k)` in header `k+D`).

**The ancestor is the ancestor on N's own chain, by hash.** Block N has one parent hash, its parent has one parent
hash: `A_2(N)` is `parent.parent_hash`. There is no "canonical" lookup and no number arithmetic: a block built on a
sibling chain carries the result of *that* chain's grandparent, and a follower checks it against the result it
recorded under that hash. This is why view changes need no special rule (section 4.2).

### 1.2 What is not deferred (unchanged from PD section 4)

`transactionsRoot` (the frame tree or MPT of the block's own body), `withdrawalsRoot` (gov5's rewards commitment),
`requestsHash` (the block's own, held to the EIP in `validate_block_post_execution`), the blob fields, `baseFeePerGas`,
`gasLimit`, `parentBeaconRoot`, `extraData`. Two consequences of the rule for the fields that *read* a deferred field:

- **Base fee.** `calc_next_block_base_fee` reads the parent header's `gasUsed` and `gasLimit`
  (`self.ethereum.validate_header_against_parent`, the builder's `base_fee`). Under D the parent's `gasUsed` field is
  `result(parent - D).gas_used`, so the fee of N responds to the gas of block `N-1-D`: at D=1 two blocks late (today),
  at D=2 three. No code change; the response is one block (25-45 ms) later again. State it in the chain's economics.
- **The committee link.** `HotStuffConsensus::validate_header_against_parent` computes
  `pool.parent_beacon_root(parent.number, &parent.hash(), &parent.receipts_root)` from the parent *header's*
  `receipts_root` field. That is a header field read, so the link stays well defined at any depth. It only stays
  byte-compatible with gov5 if gov5 reads the header field too and not its stored `ExecutedResult` (section 2, item 24).

### 1.3 The genesis flag

Today (`crates/chainspec/src/qmdb.rs`): `config.deferredExecutionTime` (u64, absent = never) parsed by
`deferred_execution_time(genesis)` with `get_deserialized::<u64>(..).and_then(Result::ok)`, and
`deferred_execution_active_at(genesis, timestamp)` = `timestamp >= at`. Seven readers: `HotStuffConsensus`
(`validate_header_against_parent`, `validate_block_post_execution`), the builder (`default_n42_payload`), the QMDB
state-root strategy (`strategy.rs`, `deferred_at`), the follower import (`deferred`, `parent_in`), the driver
(`set_deferred_execution_time`, `deferred_at`, `commit_forkchoice`), `bin/n42/src/main.rs` (restart seed) and
`h2_validator.rs`. Both fleet genesis files carry `"deferredExecutionTime": 0` in `config`
(`n42_fleet3_bench.json:85`, `n42_fleet4_bench.json`, `n42_fleet7_bench.json:101`); `n42_devnet.json` and
`n42_fleet7.json` do not.

Proposal:

```json
"config": { ..., "deferredExecutionTime": 0, "deferredExecutionDepth": 2 }
```

- `reth_chainspec::qmdb::deferred_execution_depth(genesis) -> Result<u64, DepthError>`: absent = 1; present must be an
  integer 1 or 2. **Parsed strictly.** The existing parsers swallow a malformed value (`.and_then(Result::ok)` turns
  `"deferredExecutionTime": "0"` into "never"); for the depth that is a silent safety downgrade (a typo gives depth 1,
  and a depth-1 member of a depth-2 fleet refuses every header, section 4.6). The node refuses to start on a bad value.
- `deferred_execution_depth_at(genesis, timestamp) -> u64`: `1` before the gate, the depth at or past it. With the
  restriction below the gate is genesis and this is the constant depth.
- **A chain constant, not an activation height.** `deferredExecutionDepth` is read once and holds for every block at
  or past `deferredExecutionTime`. A depth greater than 1 is accepted only when `deferredExecutionTime` is present and
  `<=` the genesis timestamp (active from block 1; every fleet file already has 0). Reasons: (a) the consensus trait
  `validate_header_against_parent(header, parent)` sees one ancestor; a pre-gate grandparent would need its header or a
  registry fed on the pre-gate path; (b) there is no live depth-1 chain that has to be migrated: the bench files and
  any new gov5-compatible deployment start at genesis; (c) the gate and the depth stay one decision for the other
  client to implement. Appendix A gives the transition rule if (b) changes.
- `deferredExecutionDepth` without `deferredExecutionTime` is an error, not a no-op.

### 1.4 The follower's vote rule

A validator votes on N (Round 1) when all of these hold; the first two are today's, the third and fourth change:

1. The proposal is valid: leader and view, justify QC, committee evidence, signatures (unchanged).
2. The body is held and well formed: transaction decode, gas limit, size, the sender recovery (unchanged).
3. **The header's four fields equal this node's recorded result for `A_D(N)`** (D=2: `executed_fields::get(&parent.parent_hash)`),
   and that result is complete (state root and receipts both filed). Today this reads the parent's.
4. **The transactions are includable on the *output* of the parent** (nonce contiguous, balance covers value and gas at
   the fee cap, chain id, fee cap over the base fee, intrinsic gas, gas limits within the header's). Today this reads
   the parent's output too (`check_on_parent_output`, `check_on_shards`), over the kept layers; it is unchanged, and
   it is the reason D=2 needs no pending-state ledger (section 2, item 11).

What a vote attests at D=2: the body is held; the header carries *this node's own* result for the grandparent; the
transactions can be charged on the parent's post-state *as this node computed it*. What it no longer attests: that the
parent's result agrees. That attestation moves one block later, to the vote on the child of N (which carries
`result(N-1)`), so **"execution certified"** for block B is: B's result appears in the header of `B+D`, and a quorum
voted on `B+D` (D=1: B+1 today; D=2: B+2). Section 4.3 gives the tag and RPC consequences.

Unchanged: execution cannot fail a block (PD section 4). A block whose execution fails on a node leaves that node
without a recorded result and without an output for it. It then refuses the block's child (nothing to check
includability on) as today, and also the block's grandchild (D=2), whose header carries the missing result. An
invalid block is still caught, one block later in the header chain, by the nodes that did execute it.
