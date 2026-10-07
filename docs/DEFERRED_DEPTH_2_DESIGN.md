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

## 2. Every place that assumes depth 1

Method: grep for every reader of `deferred_execution_*`, `executed_fields::`, `parent_executed_fields*`,
`wait_for_parent_fields`, `PARENT_OUTPUTS_KEPT`, `ancestry_of`, `fields_at_seal`, `Settlement::advance`, then read each
caller to see whether it needs the parent's *result* (a header input or a check) or the parent's *output* (state to
execute or check on). Result: **17 places assume depth 1 (15 rule or semantics, 2 capacity), 6 read the parent's
fields without needing them at depth 1 either (benign), and nothing in the build or the includability check reads the
parent's fields as an input** (they read its output). The three hardest are items 5, 8 and 15.

### 2.1 The claim to verify: N reads N-1's output, never its fields

- **The leader's build.** `N42PayloadBuilder::build_on_own` (`crates/n42/engine-types/src/payload.rs:350`) opens the
  parent's post-state through `ParentExecution` (`direct_build.rs:70`): `Ready` = the parent's `BuiltExecution`,
  `Sealed` = wait for its `StateReady` shards (`opener_on_sealed_parent`), `Published` = a peer's block this node
  executed (`opener_on_published_parent`). All three are state. The header assembly then needs the parent's fields
  (`seal_block!`, item 4); that is the only field read, and it moves to the grandparent.
- **The includability check.** `follower_import.rs`: `wait_for_parent_layer` / `layer_of` return the parent's
  shards or published output ("the parent's execution *fields* are not waited for here", the comment at line 535), and
  `check_includable` reads senders from `ParentBundles`. The fields are waited for separately
  (`wait_for_parent_fields`, five sites) on the "vote road", which already runs beside the execution
  (`two_roads`). The comparison is the only reader of the parent's fields.
- **Execution.** `exec_on_parent_output` (on by default) executes N on the parent's published output laid over the
  nearest landed ancestor. State only.
- **So execution stays sequential and no pending-state ledger is needed.** N's execution needs N-1's output; N's check
  needs the same; that is the chain "exec(N-1) -> view(N-1) -> exec(N)" that section 3 shows becomes the floor.

One exception, and it is not a header input: `fields_at_seal.rs` (item 8) uses "N's seal waited for the parent's
fields" as proof that the parent's QMDB tree is filed. That is a dependency of the *root job*, not of the seal, and
it needs its own wait at D=2.

### 2.2 The inventory

| # | where (file: function) | what assumes depth 1 | change at D=2 |
| --- | --- | --- | --- |
| 1 | `crates/chainspec/src/qmdb.rs`: `deferred_execution_time`, `deferred_execution_active_at` | only the gate exists; both parsers swallow a malformed value | add `deferred_execution_depth` (strict), `deferred_execution_depth_at` (section 1.3) |
| 2 | `engine-types/src/hotstuff_consensus.rs`: `parent_executed_fields` | keyed by the parent; `parent.number == 0 \|\| !active_at(parent.timestamp)` returns the parent's header fields | a depth-aware `ancestor_executed_fields(genesis, parent, depth)`: for `D=1` today's body; for `D=2`, `parent.number == 0` (block 1) and `parent.number == 1` (block 2) return the genesis header's fields (`chain_spec.genesis_header()`, no lookup), otherwise `executed_fields::get(&parent.parent_hash)` |
| 3 | same file: `validate_header_against_parent` (line ~277) | expected = parent's result; error names `parent` | expected = item 2's result; `DeferredExecutionError::{ParentUnknown, Mismatch}` carry the ancestor's hash. Needs no extra header: the trait's `parent` carries `parent_hash` |
| 4 | `engine-types/src/payload.rs`: `seal_block!` (line ~1765) and the ordinary finish (line ~4344) | `parent_executed_fields_or_built(genesis, &parent_header, parent_built, PARENT_FIELDS_WAIT)`: the parent's result, waiting for it under the builder's hash | the same call with the grandparent (item 5); `parent_fields_ms` becomes `ancestor_fields_ms` (the log field keeps its name for the scripts) |
| 5 | `engine-types/src/direct_build.rs`: `BuildOnOwnRequest`, `ParentExecution::built_hash`; `payload_serve.rs` lines 839, 969, 1085 (the three request constructions) and line 448 | **the build knows its parent's builder hash only.** A leader's own block has two hashes: the builder's (its results are filed under it the moment its build ends) and the sealed one consensus gives after normalising the header; the results are copied to the sealed hash only at the own-block hand-off, ~2 cycles after the seal (SES 8.2). At D=1 the child's seal files the parent's result under the sealed hash as a side effect (`parent_executed_fields_or_built`: "the found fields are filed under the sealed hash as well"). At D=2 the child needs the *grandparent's*, whose hand-off has not run and whose sealed hash nothing has filed it under | an alias table `sealed -> built` in `executed_fields` (`note_built(sealed, built)`, 16 entries, written where the request is made: the parent's `(sealed, built)` pair is in hand there, one block before it becomes a grandparent), read by item 2/4: `get(hash)` falls back to `get(alias(hash))`, and `wait_for` waits on the alias. A grandparent that is a peer's block is filed under its sealed hash by the follower import: no alias |
| 6 | `payload_serve.rs:448`: the own-block hand-off | files the builder's result under the sealed hash | unchanged (now redundant for the next seal; still needed by the follower-side `parent_in`) |
| 7 | `engine-types/src/payload.rs:3060-3130`: `publish`, `rename_parent` | publishes block N's fields the moment its QMDB root is in (`fields_published_at`), the consumer being the child's seal at D=1 | unchanged (consumer is N+2's seal, ~2 cycles later: the slack grows). Keep `N42_FIELDS_AT_SEAL` |
| 8 | `engine-types/src/fields_at_seal.rs`: `file_parent_under_seal`; `payload.rs:3076` | **"N's own seal waited for those fields" is the stated reason an early rename of the parent's tree is safe** (module doc: "the record it moves is filed before N-1's fields are remembered, and N's own seal waited for those fields"). At D=2 N's seal waits for `result(N-2)`, so N-1's tree may not be filed when N's root job starts (`seal_to_root_start` +14 ms; N-1's fields appear at its seal +45, N's seal is N-1's seal +41-46: ~half the blocks) and `qmdb.root_of(&built)` is `None` -> the late path, `wait_complete` = the parent's `Complete`, ~105 ms after its seal | before the early rename, `executed_fields::wait_for(parent_built)` (the fields are published after the tree is filed: `publish` files `qmdb_state.insert` first, then `remember`). In the root job, behind the seal, so it costs the seal nothing. Test: a unit test where the parent's fields arrive after the child's seal and the rename still takes the early path |
| 9 | `direct_build.rs:712`: `grandparent_state` waits `executed_fields::wait_for(&built_hash)` | used as a *proxy for the forest lock's release* when the anchor is not landed, not as a header input | unchanged and benign |
| 10 | `bin/n42/src/follower_import.rs`: `wait_for_parent_fields(parent_hash)` at lines 2521, 2976, 3151, 3426, 3479; `validate_against_parent` (607) | the vote road waits for the parent's result and compares the header to it | wait for the ancestor's (`parent.parent_hash` at D=2); `validate_against_parent` already calls `consensus.validate_header_against_parent(header, parent)` and inherits item 3. `parent_fields_wait_us` keeps its name |
| 11 | same file: `parent_in` (733), `wait_for_parent` (746), the guard at 3337 | "parent in" = provider has it **and** (past the gate) its result is recorded, i.e. its root is done | keep: it is the "parent *landed and executed*" test used for reading the engine's tree, which needs the parent's root job done. The vote road no longer uses it for the header comparison |
| 12 | `follower_import.rs:300`: `PARENT_OUTPUTS_KEPT = 4`, `FOLLOWER_SHARDS_KEPT = 2`; `h2-execution/driver.rs:108-135`: `DEFERRED_IN_FLIGHT = 2`, `_MAX = 3` | capacity sized for a 60 ms cycle: a block stays unlanded for ~2 cycles, so a check stacks 1-2 unlanded ancestors | **not a rule**, a consequence of the shorter cycle: at 41 ms, 3-4 unlanded ancestors. Raise to 6 / 3 / cap 3 (estimate), watch `decline_on_output` counts (section 4.4) |
| 13 | `direct_build.rs`: `N42_LEADER_LAYERS` (2..=4), `N42_GRANDPARENT_SHARDS`; `built_executions.rs` store `KEEP = 3` | same: the leader lays N-1 (and with 3-4 layers N-2, N-3) over the engine's state at the nearest landed ancestor | same reasoning; 4 is the cap today (section 3.4) |
| 14 | `bin/n42/src/main.rs:270-290` (restart) | seeds the persisted **head's** result only (root from the forest, receipts from the database) | the first header after a restart at head H carries `result(H-1)` at D=2, and no store has it (the forest holds the head's tree; no header carries `result(H-1)`: header H carries `result(H-2)`, header H+1 does not exist yet). New: a persisted `ExecutedFields` journal (section 4.5) |
| 15 | `qmdb-reth/src/executed_fields.rs` | keyed by hash, 256 entries, no parent link; `seed_from_header` only for the head | fine for D=2 (the ancestor is `parent.parent_hash`). `fields_from_child_header` is misnamed: "fields a header carries for its depth-D ancestor". For D=3 the registry would need parent links (not planned) |
| 16 | `h2-execution/src/driver.rs`: `deferred_execution_time` (638), `deferred_at` (2077), `commit_forkchoice` (1058) | the driver knows the gate and passes `|ts| gate <= ts` to settlement | add `deferred_depth: u64`, `set_deferred_depth`, pass `depth_at(ts)`; the three call sites in `h2_validator.rs` and `h2-node` that call `set_deferred_execution_time` call it too |
| 17 | `h2-execution/src/settlement.rs`: `Settlement::advance` | `certified = link.number - 1` with `link.parent` as its hash | `certified = lineage.ancestor_at(committed, link.number - depth)`; `safe` moves from the parent to the grandparent of the committed block. Tests in `tests/settlement_tags.rs` gain a depth parameter |
| 18 | `h2-execution/src/el.rs:470-490`, `raw_engine.rs:129` (`CHECKED` frame), `consensus` `BlockChecked` | doc and semantics: "found the header's execution fields equal to its own result for the parent" | doc only: "for the depth-D ancestor". The frame's timing (after the check, before the import) is unchanged |
| 19 | `HotStuffConsensus::validate_header` path through reth: `gas_used <= gas_limit` | the header's `gasUsed` is another block's gas; at D=1 a block `N-1` that was full at limit `L` and a gas limit that then shrank would trip it (limit moves by at most 1/1024 a block); at D=2 the window is two blocks | the builder must not shrink the limit below the carried `gasUsed`; one line in the builder's limit step and a test. Not reachable on the bench (fixed limit), reachable on a chain with a limit target |
| 20 | `n42-testing` `test_deferred_execution__headers_carry_the_parents_execution_across_the_fork` and `testdata/deferred_execution_vectors.json` | fork at block 3, `deferred: true` per block, "block N carries block N-1's root and gas" | parametrise by depth; a new vector file for D=2 (section 4.7) |
| 21 | genesis files: `n42_fleet3_bench.json`, `n42_fleet4_bench.json`, `n42_fleet7_bench.json` (all `deferredExecutionTime: 0`), `n42_devnet.json`, `n42_fleet7.json` (ungated) | the flag is absent | **new files** `n42_fleet3_bench_d2.json`, `n42_fleet7_bench_d2.json` (copies with `deferredExecutionDepth: 2`); never edit the D=1 files: their genesis hash is the fork digest of running fleets (`h2-net/src/status.rs`: first 4 bytes of the genesis hash) and a copy with the same alloc and header has the *same* hash, so a depth-1 and a depth-2 binary given the same file would share a digest but not a rule (section 4.6) |
| 22 | `docs/N42_26_PORT.md` "Joining a Go fleet"; `docs/PHASE_D_DEFERRED_EXECUTION.md` sections 2, 3, 17 | the text says "N-1" | a new subsection (section 2.4 below lists what gov5 changes); PD gets a pointer, not an edit of history |
| 23 | `scripts/fleet7.sh`, `fleet7-bench.sh`, `fleet3-env.sh`, `devnet-fleet.sh` | pick a genesis by name; none reads the depth | `F7_GENESIS` already selects the file; add the depth to the printed header lines so a leg is labelled; nothing else |
| 24 | gov5: `parentBeaconRoot` derivation, `ExecutedResultOfHeader`, `CheckDeferredBlock` | (read from PD section 15, not from gov5's code) | section 2.4 |
| 25 | `mobile-verify` receipts and `n42-init-snapshot` pairing | PD section 3: "proof for state after N is against header N+1's stateRoot; receipt of N under N+1" | N+D; neither is implemented for depth 1 either (PD section 15: "not yet") |

Items 1-5, 8, 10, 14, 16, 17, 18, 19, 21, 24 and 25 are the 15 rule or semantic places; 12 and 13 are the 2 capacity
ones; 6, 7, 9, 11 and the two registry writers (`strategy.rs:147` `remember_state_root`, `hotstuff_consensus.rs:475`
`remember_receipts`) are the 6 benign reads, which need no change. Items 20, 22 and 23 are the tests, documents and
scripts that follow the rule rather than assumptions of their own.

### 2.3 The three hardest

**Item 5, the grandparent's identity.** A leader's own block has a builder hash and a sealed hash, and its result is
filed under the first. The depth-1 code gets away with one hash because the child's seal files the parent's result
under the sealed hash while it waits for it. At depth 2 nothing has filed the grandparent's result under the sealed
hash `parent.parent_hash` names when the child needs it, and the child's request does not carry the grandparent's
builder hash. Without the alias table a leader's chained build fails with `ParentUnknown` on every block after the
first, in the tenure's second view. This is the single most likely first-leg failure.

**Item 8, the seal's wait was also a barrier.** The wait for the parent's fields at the seal had a second job nobody
wrote down as one: it made sure the parent's QMDB tree was filed before the child's root job looked for it. At D=2 the
seal no longer waits, and the child's root job, `fields_at_seal`'s early rename, would find the tree missing in about
half the blocks and wait for the parent's `Complete` (~105 ms after its seal). The cure is one wait in the root job,
behind the seal; the hazard is that nothing fails: the chain stays correct and the root chain silently drops from a
~31 ms pipeline stage to ~105 ms per two blocks.

**Item 14, the restart.** `result(H-1)` exists in no persistent store: the database holds H-1's receipts but the forest
holds only the head's tree, and no header carries `result(H-1)` (header H carries `result(H-2)`). A node restarted at
H cannot build or check H+1. At D=1 `result(H)` is seeded from the forest and the database. At D=2 a journal of
`ExecutedFields` per block hash (about 330 bytes a block) written when the fields complete is the smallest cure;
recomputing H-1's root from the forest's persisted tree is not possible.

### 2.4 The engine, RPC, the non-HotStuff chains, the Go client

**How reth accepts a header whose root is not the block's.** Three places, none depth-specific:

1. `QmdbStateRootJob::finish` (`crates/n42/qmdb-reth/src/strategy.rs:130`): under the gate it files the block's own
   QMDB root (`insert_block_operations`, `remember_state_root`) and **returns `StateRootJobOutcome::new(header.state_root(), ..)`**,
   i.e. the header's own value, so reth's comparison of "computed" and "header" root passes trivially. The check that
   the header's root is right is `validate_header_against_parent` (item 3), on the consensus side.
2. `HotStuffConsensus::validate_block_post_execution` (`hotstuff_consensus.rs:449`): under the gate it records the
   block's receipts root, bloom and gas into the registry *instead of comparing them with the header*, and holds
   `requestsHash` to the EIP as before.
3. reth's header rules (`validate_header`, `validate_header_against_parent` from `EthBeaconConsensus`) run unchanged;
   only the gas-used-versus-limit relation of item 19 is sensitive to what the field means.

All three generalise as they are: the override never says which block's result the header carries, and the registry
write is by the block's own hash. `forkchoiceUpdated` and `newPayload` need no change.

**RPC.** `eth_getBlockByNumber(N)` returns a header whose `stateRoot`, `receiptsRoot`, `logsBloom`, `gasUsed` are
`result(N-2)`'s; at D=1 they are `result(N-1)`'s already (PD section 3). `eth_getBalance`, `eth_call` and the other
state reads at `latest` read the QMDB read view, which stands at the committed head's *own* post-state, so they are as
fresh as today; only the header is stale as an anchor. Wallets that verify a receipt against `receiptsRoot` must
look in the header of `N+2`; `eth_getBlockReceipts` answers from the node's own execution as before. Document in the
RPC notes; no code.

**Non-HotStuff chains.** `bin/n42` installs `HotStuffConsensus` only on a genesis that names a `hotstuff` validator
set (`N42ConsensusBuilder`); APoS chains and every reth chain never call `deferred_execution_active_at` (the reads are
inside `HotStuffConsensus`, the QMDB strategy's `deferred_at` closure, the builder's `deferred_now`, and the driver).
A genesis without the key gives depth 1 and the existing behaviour, bit for bit. The only shared-crate edit is the
additive `reth_chainspec::qmdb` function.

**What gov5 would change** (from PD sections 8, 9, 15; gov5's code was not read for this study, so each line is "the
mirror of" the Rust item):

- chainspec: `config.deferredExecutionDepth`, strict parse, depth 2 only with the gate at or before genesis time.
- `ExecutedResultOfHeader` and the builder's stamping: the stored result of the *grandparent* by hash (own sealed
  record for chained builds); blocks 1 and 2 stamp the genesis result.
- `CheckDeferredBlock`: header against the grandparent's stored result; includability against the **parent's
  post-state, not "the applied head"** (PD section 15 says the check requires the parent to be the applied head; that
  keeps the vote behind the parent's import. Whether "applied" includes its state-root commit decides how much of the
  speed-up gov5 sees; correctness needs only the grandparent's stored result).
- the vote: `EventBlockChecked` as today; the certification tag moves to `N+2`.
- `parentBeaconRoot`: confirm it is derived from the parent *header's* `ReceiptHash` (as `HotStuffConsensus` does),
  not from a stored `ExecutedResult`; the link is then depth-independent.
- the gov5 header profile fields (`extra_data` view and seal, `difficulty`, `ommers_hash`, the rewards commitment in
  `withdrawalsRoot`, the empty-requests spelling) are untouched; `normalize_to_gov5_h2_from_header` patches only extra
  data, ommers, difficulty, nonce and the two placeholder roots (`h2-consensus/src/header_profile.rs:719`), so the
  Rust profile is depth-agnostic.
- the `verifiers` and `rewards` body fields (`[header, txs, verifiers, rewards]` block gossip) are the block's own and
  unchanged.
- fork digest: `genesis_hash[..4]` (`h2-net/src/status.rs:84`) is gov5's contract; depth cannot be added to it
  without gov5 changing it, so mixed depths are not separated by the transport (section 4.6).

## 3. Timing model

All figures E=1 (one execution layer, 200,000 one-transfer transactions, 3 validators, 400M set) unless stated. **Measured**
= from BD 10.86-10.90 (loop339-loop343) or SES 15-16; **plan** = SES section 16.4/17 (built, not measured: `sealed_at`
~24-28 ms with items 1-4); **estimate** = this document. The model is a set of serial chains, each with a period (the
least time between two consecutive seals that the chain allows); the cycle is the largest period.

### 3.1 What each chain's period is

| chain | what it is | D=1 | D=2 | source |
| --- | --- | --- | --- | --- |
| **root chain** | N's seal waits for N-1's fields: `seal_to_fields` + the header, block and hook (~5) | **50-51** (45-46 + 5; p90 59-61 + 5) | **off the seal path**; remains as a pipeline stage whose *latency* (45-46) must stay under `2P - 5` (~80) and whose *period* is the root job, below | measured (BD 10.90), SES 16.5 |
| **build chain** | exec(N) needs N-1's state view: view(N-1) = exec_end(N-1) + V; then gap, then exec | 41 (estimate) | 41 (estimate) | below |
| **root job** | N's QMDB root runs on N-1's tree: serial per block | 30-32 | 30-32 | measured (`roots_ms` 30-32 on F2) |
| **persistence** | one thread, back to back | 31-37 | 31-37 | measured (BD 10.87, 10.90: 31.6-33.4) |
| **vote road** | proposal -> check -> R1 -> PrepareQC -> R2 -> Decide -> next proposal (the next proposal waits for the previous Decide) | not binding at 52-62 ms cycles | **unmeasured below 52 ms** | components: slowest key's vote delay 26 median / 52 p90 (BD 10.90), vote-to-commit transit 17-20, commit-to-proposal 6-8, send 2.5 (IS 11.1, 163k) |
| **tick** | `F7_BLOCK_INTERVAL_MS` pacing | 60 (set by the leg) | set to 0 or under the floor for the leg | |
| **landing** | the engine lands a block ~2 cycles after its seal (`Complete` +105, hand-off ~30, commit ~17) and a build can stack only `N42_LEADER_LAYERS` (<= 4) unlanded layers | | binds when `landing / layers` exceeds the cycle | SES 8.2; estimate below |

**The build chain, derived.** After SES 17's items 1-4 the seal comes at the batches' end plus ~3 ms (commit on counters,
tx root, fields wait 0, header). What the next block's execution waits for is not the seal but N-1's *state view*: the
shards frozen (`index_ms` 13-15 measured, one slow shard task of 13.5 ms) and laid with the residual (the graft scope,
receipts-from-slots, the fee credit and the executor's finish: `seal_to_finish_us` 11.8 measured in the D ordering,
`seal_to_view_us` 12.7). With the freeze on its own thread the two overlap only in part (the graft joins the freeze
where it first reads the shards). So **V = exec_end -> view is 18-28 ms (central 23, estimate)**; the task's "~25 ms
after the seal" is the upper end (seal + 25 = exec_end + 28). Then

    P_build = V + gap (~1: state open, `gap_before_exec` after item 2) + exec (18.5 after item 4; 23 today)
            = 38-48, central ~42 ms (estimate)

Today the seal (60-61) hides all of this; after section 17 the seal is no longer the long pole and this chain, the one
the claim in section 2.1 says stays sequential, is. **The root chain's removal does not make the cycle 27 ms; it makes
the build chain the floor.** Levers on V and exec, in order of size (all estimates): split the heavy shard task (SES 16.3:
14 -> ~8 ms), keep only the part of the graft the next exec reads on the critical path (the receipts and the fee
credit are behind it), 96-128 batches largest first (exec 23 -> 18.5, built).

### 3.2 The expected floor and rate, 200k

| | D=1 after SES 17 | D=2 |
| --- | --- | --- |
| seal (`sealed_at`) | 24-28 median | 24-28 median |
| root chain on the seal path | 50-51 | 0 |
| build chain | 38-48 | 38-48 |
| persistence / root job | 33 / 31 | 33 / 31 |
| vote road | unmeasured, not binding | unmeasured; 35-50 (components) |
| **cycle (largest period)** | **~51 ms** (SES 16.5 states it) | **~42-45 ms; range 38-50** |
| rate at 200,000 | ~3.9M (SES) | **~4.4-4.8M; range 4.0-5.3M** |

Reading: D=2 moves the floor from the root chain (51) to the build chain (~42) with the vote road (35-50, unmeasured)
possibly just above it. That is a **+10 to +20% rate, not +30%**; the 5M goal at 200k needs a 40 ms cycle: it is at the
optimistic end (V = 18 and a vote road under 38) and not the expectation. Reaching it needs one or two of the levers
above in addition. After D=2 the next things that bind, in this order (estimates): the build chain's V, then the vote
road (`proposal -> Decide` has never been read at pacing 0 and 40-45 ms), then persistence (33 of 42 ms is 79% busy;
a 5% backlog growth fills the 48-block throttle in ~2 minutes), then landing (3.4).

### 3.3 400k-transaction blocks

Scaling rules (estimates): execution and the per-account passes double; the root job's apply (24 of 31 at 200k) grows
with the accounts touched (~192k -> ~384k); persistence ~66 (BD 10.86: 60-68 ms at 200k *before* the static-file
switches, 31-37 after, so 62-74 at 400k); the check doubles; the tick and the fixed 5-6 ms of the seal path do not.

| | D=1 after SES 17 | D=2 |
| --- | --- | --- |
| seal | ~45 | ~45 |
| root chain on the seal path | ~91 (finish 24 + 3 + root ~58 + 1, + 5) | 0 |
| build chain: V + gap + exec | | 28-52 (central 40) + 2 + 37 = 65-90, central ~79 |
| persistence / root job | 66 / 58 | 66 / 58 |
| vote road | | 60-100 |
| **cycle** | **~91 ms** | **~80 ms; range 66-100** |
| rate at 400,000 | **~4.4M** | **~5.0M; range 4.0-6.0M** |

At 400k the gain is the same ~14% but the rate is higher at equal cycle ratio because the fixed costs amortise, so
**5M is the central estimate at 400k and the optimistic one at 200k**. Persistence (66-74) and the root job (~58) sit
at 70-90% of the D=2 cycle and are the next bound at once; a chain that wants more than ~5M at 400k needs the
persistence and root job work (BD 10.87 "the next bound") as much as D=2.

### 3.4 The landing bound D=2 exposes (estimate)

A build of N lays N-1 (and with `N42_LEADER_LAYERS` = 3 or 4, N-2, N-3) over the engine's state at the nearest landed
ancestor. A block lands ~2 cycles after its seal at today's cycle (SES 8.2): about 120-150 ms. At 42 ms that is 3-4
unlanded blocks, so the stack the build needs is 4-5 deep against a cap of 4 (`LEADER_LAYERS_MAX`) and the follower's
`PARENT_OUTPUTS_KEPT` 4. The rule of thumb: `landing / layers <= cycle`, i.e. 150 / 4 = 37 ms. Counters that read it
already exist: `great_grandparent_missing`, `grandparent_ms`, `grandparent_layer` on the build line,
`decline_on_output` on the follower's. If they rise the fix is a deeper stack (raise the cap to 6) or a faster
hand-off, not a rule change. It is a consequence of the faster cycle, not of the depth.

### 3.5 What the model cannot see

The execution of N runs while N-1's behind-seal jobs (freeze, graft, receipts, root ops) still use the 32-worker
build pool; section 16.2's nested-steal story says a latency-critical pass can finish behind a long task of another
job. Items 5 and 1 of SES 16.4 (a pool of its own for behind-seal work) are therefore *more* valuable at D=2 than
before: the child's exec now overlaps its parent's whole behind-seal tail every block instead of half of them. CPU:
the layer burned ~34 cores at 61 ms and ~52 at 40 ms (SES 16.5) of 208; at 42 ms ~50. E=3 (independent execution
layers, one per validator) is not modelled: a follower's chain is the same exec -> view -> exec on its own hardware
plus the check; at D=1 the 3-node follower's import was 38-40 ms median (E=1 layer, own-import) and 275 ms in the
older seven-node rounds; a D=2 E=3 round has to be run before anything is claimed for it.

## 4. Risks and tests

### 4.1 Safety: a block certified two later, and the commit rule

What the rule needs from consensus: nothing beyond what any header needs. The result a header carries is a
deterministic function of the chain the block extends, bound by hash (`parent.parent_hash`, section 1.1), so a header
can never carry "the wrong N-2": a sibling chain's blocks carry that chain's result and are checked against it.
Whether N-2 is *committed* when N is proposed does not enter the check. For completeness, what the protocol gives
(read in `h2-consensus/src/protocol/{proposal,round,state_machine}.rs`):

- **Optimistic path.** The protocol is two rounds a view (Propose, R1 vote, PrepareQC, R2 CommitVote, Decide) and the
  next proposal is made after Decide (`state_machine.rs` flow comment; the proposal's `justify_qc` is `locked_qc`,
  `proposal.rs:145`; the piggybacked `previous_prepare_qc` only carries the QC to voters). So when N is proposed N-1 has
  a CommitQC, and with it every ancestor: N-2 is committed.
- **Timeout path.** A new leader proposes on the highest QC it holds. N-1 may be prepared but not committed; its
  proposal carried `justify = QC(N-2)`, and every voter ran `update_locked_qc` on it (`proposal.rs:369`), so n-f
  validators are locked on N-2's QC and `is_safe_to_vote` (`justify.view >= locked.view`) keeps a conflicting N-2'
  from ever gathering a quorum. N-2 is not "committed" in the protocol's sense yet, but it cannot be replaced, which is
  all the rule needs.
- **A reorg of N-1 after N was built.** N is on N-1; if N-1 is replaced by a sibling N-1' (a TC re-proposal), N is
  dropped as today (its parent is wrong; `payload_serve` and the build store discard it) and a new N' is built on N-1'.
  N and N' carry the same four fields (both `result(N-2)`: same grandparent) and differ in parent hash and body;
  nothing about a result is ever re-decided. The build store's identity (parent, number, transactions root;
  `built_executions`, PD 16) already separates them: at D=2 two blocks with *different* parents and the same grandparent
  also share their fields, and the identity includes the parent, so no change; the test in 4.7 pins it.
- **What a vote no longer proves** (the real change): a quorum on N proves the grandparent's result, not the parent's.
  A block whose execution diverges between nodes (a non-determinism bug) is caught at its `D`-th child instead of its
  first. The cost of a bug is therefore one more block of chain built on a state some nodes disagree about; recovery is
  today's (a mismatch refuses the votes, a TC, the diverging node resyncs). The unit and fleet gates `fields_mismatches`
  0 and `fleet7-verify` read exactly this and stay.

### 4.2 Liveness: handover, view changes, a block dropped under a header

- **The tenure handover** (BD 10.15-10.17's stall). The incoming leader's first build of a tenure reads its parent as
  `ParentExecution::Published` (a peer's block it executed; `N42_TENURE_FIRST_ON_OUTPUT`): the parent's *output*, which
  its follower import publishes as soon as the parent's execution ends. The header needs `result(parent.parent)`, filed
  under that block's sealed hash by the follower import ~one cycle earlier. At D=1 the incoming leader waits for the
  parent's *root* (30-45 ms after the parent's execution); at D=2 it does not. The handover gets shorter, not
  longer.
- **A view change.** The new leader's parent is the highest-QC block P; its header carries `result(P.parent)`. A voter on
  P executed P.parent (a voter of P checked its header against `P.parent.parent`, and executed `P.parent` to check P's
  includability), so a node that voted for P has the result. A node that never saw P (lagging) abstains and catches up
  by range sync: the same cure as at D=1.
- **N-1 dropped, "what is N's parent then".** N's parent is whatever block it was built on; its header says
  `result(parent.parent)` of *that* chain. There is no canonical-chain lookup anywhere in the rule, so a drop needs no
  handling in the rule; the implementation hazard is only the alias table of item 5 (a re-sealed block, view moved by a
  timeout, has a new sealed hash and the alias must follow it: `chain_alias::remember` is the existing pattern).
- **A leader whose grandparent's result is missing** fails the build (`ParentUnknown`, as at D=1 for the parent), the
  view times out, TC. With the alias table this should not occur on the first leg; if it does it is the loud failure.

### 4.3 Settlement tags and what a wallet waits for

`Settlement::advance` (item 17): at depth D a commit of B certifies the ancestor of B at distance D; `safe` is that
block, `finalized` the newest certified block at or below the persisted height; `latest` is the committed block as
today. Wall-clock time from a block's proposal to its certified state (estimate): D=1 about one cycle plus the vote
road, ~60 + ~45 = ~105 ms at today's cycle; D=2 two cycles plus the vote road, ~2 x 44 + ~45 = ~133 ms at the D=2
cycle, i.e. **about 30 ms later, not 60** (the cycle shrinks while the depth doubles). Consequences:

- a client that reads `latest` sees the same freshness as today (the QMDB read view stands at the committed head);
- `eth_getBlockByNumber(latest).stateRoot` is the root two blocks back; a proof of state after B is anchored by
  header B+2 (and for a receipt, `receiptsRoot` of B+2);
- the mobile receipt and proof formats (`mobile-verify`) are not implemented for depth 1 either; define them with the
  depth in the document (`anchor = B + D`) so a verifier reads it from the chain constant rather than hard-coding 1.

### 4.4 Follower memory and the slot cap

A follower must hold N-1's and N-2's execution outputs unlanded and, at a shorter cycle, up to 4-6 of them (item 12).
Size: a block's published output plus its shards residual is dominated by the bundle (~190k accounts and as many
reverts; BD: ~30 MB of QMDB record a block, ~60 MB for a provisional bundle clone, ~120 MB for a prepared body at
200k). Four extra unlanded outputs are 0.3-0.5 GB a node against peaks of 32-51 GB (BD 10.60-10.63): not the risk.
The risk is the **in-flight cap**: `DEFERRED_IN_FLIGHT` 2 (max 3) frees a slot only when a block has *landed* (~120-150
ms at today's seals). At a 42 ms cycle that is 3-4 blocks in flight, so blocks queue for a slot and their votes wait
(`FOLLOWER_LAG_CAP` 4, `N42_VOTE_BEFORE_SLOT` exists for exactly this). Plan: step 8 raises the maxima with a
documented relation (`PARENT_OUTPUTS_KEPT >= cap + 2`, the arithmetic of `driver.rs:116-129`) and keeps the defaults;
legs set them by env; the deciding counters are `decline_on_output` (stack too deep), imports over 600 ms and
`parent_engine_wait_ms`.

### 4.5 Restart, late joiners and sync

- **Restart** (item 14). At D=2 a leader restarted at head H cannot build H+1: `result(H-1)` is in no store. A follower
  abstains on H+1 and recovers at H+2 (which carries `result(H)`, seeded as today). Cure: a journal of `ExecutedFields`
  by block hash, number and parent hash, appended when an entry becomes complete (`executed_fields::remember*`), read back
  at startup for the last 8 canonical blocks and cross-checked against the head's forest root and database receipts.
  About 330 bytes a block; an append-only file beside the QMDB state, flushed with the persistence batch. Missing or
  torn tail: the node starts without it and costs one abstention or one lost leader view, never a wrong vote.
- **A late joiner pulling by range** (`import_pulled`) executes each block and records its result; the header of B is
  verified when its D-th descendant arrives (PD section 3 had one block of look-ahead; it is D now). The last D blocks of a
  pulled range are unverified until the next block, as on Ethereum with EIP-7862.
- **`n42-init-snapshot`** pairs header and state: the state after B is certified by header B+D, so the tool takes that
  header (not B+1) and the snapshot's head result is the third-last header's.

### 4.6 Mixed fleets: a depth-1 member in a depth-2 chain

It cannot vote, and that is by the rule, not by a handshake. A depth-1 validator checks every header against
`result(parent)` (`validate_header_against_parent`, item 3); the header carries `result(parent.parent)`; the two differ
whenever any state changes between the two blocks (the block reward and withdrawals alone change the QMDB root every
block on the fleet genesis files), so the proposal fails the header check, the payload is answered INVALID by its own
engine, and the member neither votes nor imports; as a leader its blocks fail everywhere else and its view times out.
Safety is unaffected (a refusing member signs nothing); liveness degrades by that member's votes and its leader views.
Symmetrically a depth-2 member refuses depth-1 headers. Two honest limits:

1. On a quiescent chain (no state change, no receipts, gas 0) both rules give identical headers and a mixed fleet
   appears to work until the first transaction or reward. The fleet files never idle that way; a mixed-fleet test must
   include a state-changing block.
2. The transport cannot separate the depths: the fork digest is the first four bytes of the genesis hash
   (`h2-net/src/status.rs:84`, gov5's contract) and `deferredExecutionDepth` is a `config` extra field, not part of
   the genesis header. Mitigation: print the depth at startup and in the fleet scripts' header, make the new genesis files
   separate files with a different `extraData` (so their hash, hence digest and block-gossip topic, differ from the
   D=1 files: `n42_fleet7_bench_d2.json` carries `"extraData": "...d2"`; cheap, native-only), and keep depth out of any
   gov5-facing wire.

### 4.7 Tests

**Unit, per rule** (each next to its code; D=1 behaviour pinned by the existing tests staying green):

| # | test | where |
| --- | --- | --- |
| T1 | depth parse: absent = 1; 1; 2; `"2"` (string), 0, 3, `null` refused; depth without gate refused; depth 2 with a gate after the genesis timestamp refused; depth 2 refused until step 5 flips it | `crates/chainspec/src/qmdb.rs` |
| T2 | `ancestor_executed_fields`: D=1 equals the old function over random chains; D=2: blocks 1 and 2 carry the genesis fields, block 3 `result(1)`, unknown grandparent -> `ParentUnknown`; two sibling parents of one grandparent give equal expected fields; different grandparents give different | `hotstuff_consensus.rs` tests |
| T3 | `validate_header_against_parent` at D=2: accepts `result(N-2)`, rejects `result(N-1)` (the D=1 value) and `result(N-3)` with `Mismatch`; and the same header at D=1 rejected the other way; both depths in one test = the mixed-fleet refusal at unit level | same |
| T4 | builder: a chained build whose grandparent's result is filed under the builder hash only (hand-off not run) seals; after a view timeout re-seals the grandparent the alias follows; `ParentUnknown` only when nothing was filed | `payload.rs`, `direct_build` tests |
| T5 | `file_parent_under_seal` waits for the parent's fields, not its `Complete`, when the tree is not yet filed; early path taken when the fields arrive after the child's seal | `fields_at_seal.rs` |
| T6 | follower: the vote road passes while N-1's root is not computed (N-1 fields absent, N-2 present) and waits when N-2's are absent; includability still reads N-1's output; `parent_in` unchanged | `follower_import_tests.rs` |
| T7 | settlement at D=2: safe = committed - 2, finalized capped by persisted; a dropped uncommitted block moves nothing; restart sends zero tags; D=1 unchanged | `tests/settlement_tags.rs` |
| T8 | base fee: header N's `baseFeePerGas` from the parent's carried `gasUsed` (= `result(N-3)` at D=2), golden numbers | `n42-testing` |
| T9 | the gas-limit step never goes below the carried `gasUsed` (item 19) | `payload.rs` |
| T10 | journal: round trip, torn tail, missing H-1 -> `ParentUnknown`, never a panic or a wrong value | new module |
| T11 | build store identity: two blocks, different parents, same grandparent, same fields: kept apart | `built_executions.rs` |
| T12 | end to end on the dev chain, `deferredExecutionDepth: 2`: block N's header fields equal the registry's result for N-2 for N = 1..12, a restart in the middle, the head's own result restored | `n42-testing/src/dev.rs`, a sibling of the existing `test_deferred_execution__...` |
| T13 | `h2-execution` mock loop: four members, three at D=2 and one at D=1: the chain advances, the D=1 member never votes; settlement tags at D=2 | `tests/consensus_execution_loop.rs` |

**Fixture-style tests against gov5.** None exist for depth 2. The shape to follow is
`crates/n42/n42-testing/testdata/deferred_execution_vectors.json` (keys `genesis {alloc, hash, header}`, `blocks[]
{number, hash, header, transactions (raw 2718), executed, deferred}`, fixed keys and timestamps,
`N42_WRITE_VECTORS=1` rewrites it). A depth-2 document, `deferred_execution_vectors_d2.json`, with the gate at
genesis and `deferredExecutionDepth: 2`, needs, from gov5: the same genesis alloc and header; seven blocks with
transfers in blocks 1, 2, 3 and 5 (so `result(k)` differs for each k); for each block its full header as carried, its
own `executed` result (gov5's `ExecutedResult`) and the transactions; plus a **fork vector**: two sibling blocks 4 and
4' on block 3 (different transactions), each with a child (5 on 4, 5' on 4'), where headers 4 and 4' carry
`result(2)` and headers 5 and 5' carry `result(3)` (identical fields, different parent hashes), and a block 6 on 5'
that carries `result(4')`. Both clients' suites compare every header byte for byte and every `executed` result.
The Rust side can produce its half first (T12 with `N42_WRITE_VECTORS`); gov5 produces its half from the same keys.
Also needed from gov5: its `parentBeaconRoot` vectors across the chain start (block 2's evidence link uses block 1's
header `receiptsRoot`, which is the genesis value at D=2).

**Rounds** (to run by the fleet agent; this study ran none):

1. *Three-node independent-execution round* (`scripts/fleet3.sh`, three validators each with its own execution layer,
   `n42_fleet3_bench_d2.json`): 200 tx/s offered for 90 s, then a flood; gates: heads equal on all three, `invalid_blocks`
   0, `fields_mismatches` 0, `fleet7-verify` clean, no `ParentUnknown`, `decline_on_output` rate, imports over 600 ms.
   Then faults: kill a follower for 60 s and restart it (journal and range sync); stop the leader in its tenure (TC;
   the first header after it carries the right ancestor); one node started late with a fresh layer.
2. *E=1 round at 200k*: pairs (D=1 control and D=2 on one binary, same day, `fleet7-repeat.sh`; no conclusion from one
   leg), pacing 50 / 45 / 42 / 40 and 0, reading `sealed_at`, `parent_fields_ms` (should be 0 at every block),
   `seal_to_fields_us`, the **proposal-to-Decide time per block** (never read below 52 ms), `rename_wait_us` (must be 0 on
   the early path: item 8), persistence backlog, `great_grandparent_missing` / `grandparent_ms`, `exec_end -> view` (V).
3. *400k round* after 2, same pairs.

### 4.8 Risks, ranked

1. **The grandparent's identity** (item 5): the first chained build on a leader fails `ParentUnknown` without the alias.
   Loud. Covered by T4 and the round-1 smoke.
2. **The silent regression of the root chain** (item 8): correct chain, a root job that waits ~105 ms. Quiet; the
   counter is `rename_wait_us` / `rename_early` on the build line and the gate is round 2.
3. **The vote road is unmeasured** below 52 ms (3.2): it may be the floor, and then D=2 yields less than the +10-20%.
   Cheap to learn first: one E=1 leg at D=1 with pacing 45 reads the proposal-to-Decide time before any code (the
   leg is only worth running once SES 17's switches are on).
4. **Persistence and the root job run at 70-90% of the D=2 cycle** (3.2, 3.3): a small backlog growth fills the
   throttle in minutes (BD 10.86's +40 blocks a minute at 55 ms).
5. **The landing bound and the slot cap** (3.4, 4.4): capacity knobs, no rule change, but the first D=2 leg at 42 ms
   will meet them.
6. **gov5 delays or differs.** Mixed fleets fail closed (4.6), but a gov5 member in a depth-2 fleet is a refusing
   member; the cross-client claim in PD (a mixed fleet at 0.43 s) is not available at depth 2 until gov5 implements it.
7. **A wallet-visible delay of ~30 ms** and headers two blocks stale as proof anchors (4.3). Document.
8. **Gas limit and base fee edges** (items 19, T8, T9): minor on the bench, relevant on a chain with a limit target.
9. **Restart and sync** (4.5): one abstention or one lost view, bounded.
10. **E=3 is not modelled** (3.5).

## 5. Implementation plan

For an implementing agent. Rules for every step: one commit, behind the genesis flag (a chain without
`deferredExecutionDepth` runs byte-for-byte as before; the D=1 vectors file and every existing test stay green and
unedited); Conventional Commits, English, no attribution; no fleet is needed to land a step, the gate is `cargo test`
in the crates named; the fleet legs are run by whoever holds the box, after step 7. `crates/n42/engine-types/src/payload.rs`
and `built_executions.rs` are also edited by the seal work (SES 17): do step 3 after that work is committed and rebase
on it; the other steps do not touch those files.

| step | what | files | size (estimate) | gate |
| --- | --- | --- | --- | --- |
| 0 | **Depth as a parameter, value always 1.** `ancestor_executed_fields(genesis, parent, depth)` and `ancestor_executed_fields_or_built` as the general forms; the old names call them with 1; `fields_from_child_header` renamed in docs. No behaviour change | `engine-types/src/hotstuff_consensus.rs`, `qmdb-reth/src/executed_fields.rs` | ~120 lines | `cargo test -p n42-engine-types --lib` (single-threaded, as BD 10.86 notes), `-p n42-testing` (the vectors test byte-equal), `-p n42-h2-execution` |
| 1 | **The flag.** `deferred_execution_depth`, `deferred_execution_depth_at`, strict parse, validation (T1) called at node start (`bin/n42/src/main.rs`, `h2_validator.rs`); depth 2 is refused with "not implemented yet" until step 5; the depth printed at startup | `crates/chainspec/src/qmdb.rs` (additive, no signature changes), `bin/n42/src/main.rs`, `h2-node/examples/h2_validator.rs` | ~150 lines | T1; `cargo check --workspace` (a chainspec edit rebuilds the graph: additive only) |
| 2 | **The consensus rule.** Depth in `validate_header_against_parent` and `parent_executed_fields` (genesis cases for N <= D, `registry[parent.parent_hash]` otherwise); error variants name the ancestor | `hotstuff_consensus.rs` | ~150 lines + tests | T2, T3 (including the both-depths refusal) |
| 3 | **The builder.** The alias table (`executed_fields::note_built`, `get`/`wait_for` through it; written where the three `BuildOnOwnRequest`s are made); the grandparent in `seal_block!` and the ordinary finish; the root job's wait for the parent's fields before the early rename (item 8); the gas-limit clamp (item 19); log fields renamed or documented | `engine-types/src/payload.rs`, `direct_build.rs`, `fields_at_seal.rs`, `executed_fields.rs`, `bin/n42/src/payload_serve.rs` | ~250 lines (payload.rs edits are ~30; the rest is the alias and its tests) | T4, T5, T9, T11; the existing `fields_at_seal` and builder tests; `N42_FIELDS_AT_SEAL=verify` path still compiles |
| 4 | **The follower.** `wait_for_parent_fields` takes the ancestor's hash (a function `ancestor_hash(parent_header, depth)`), five call sites, `validate_against_parent`; `parent_in` untouched; knobs for capacity read from env but defaults unchanged (step 8 changes the maxima) | `bin/n42/src/follower_import.rs`, `follower_import_tests.rs` | ~150 lines | T6; the existing `follower_import_tests` |
| 5 | **The driver, settlement and the flip.** `Driver::set_deferred_depth`, `commit_forkchoice` passes the depth to `Settlement::advance` (item 17), docs of the `CHECKED` frame; the three callers of `set_deferred_execution_time`; **step 1's refusal of depth 2 is removed here**; first end-to-end test on the dev chain | `h2-execution/src/{driver,settlement,el}.rs`, `h2-node/examples/h2_validator.rs`, `n42-testing/src/dev.rs` | ~200 lines + the dev test | T7, T8, T12, T13; the new vectors file written by T12 (`N42_WRITE_VECTORS=1`) and checked in |
| 6 | **The journal** (restart, 4.5): `ExecutedFields` by hash, appended on completion, read at start for the last 8, cross-checked; `bin/n42/src/main.rs` seeding generalised | new `qmdb-reth/src/executed_journal.rs`, `executed_fields.rs`, `bin/n42/src/main.rs` | ~250 lines | T10; a restart in T12 |
| 7 | **Genesis files and scripts.** `n42_fleet3_bench_d2.json`, `n42_fleet7_bench_d2.json` (copies, `deferredExecutionDepth: 2`, a distinct `extraData`); the depth in the fleet scripts' printed header and `fleet7-verify`'s output; nothing else in the scripts | `crates/chainspec/res/genesis/`, `scripts/fleet7-env.sh`, `fleet3-env.sh`, `fleet7-verify.py` | files only | the genesis loads; `n42 init` of each prints a hash different from the D=1 file |
| 8 | **Capacity**, by env with documented relations: `DEFERRED_IN_FLIGHT_MAX` 3 -> 4, `PARENT_OUTPUTS_KEPT` 4 -> 6, `LEADER_LAYERS` cap 4 -> 6, `FOLLOWER_SHARDS_KEPT`; defaults unchanged | `follower_import.rs`, `h2-execution/driver.rs`, `direct_build.rs` | ~80 lines | the stacking tests at depth 6 (`ancestry_of` tests exist at 4); a leg decides the defaults |
| 9 | **Documents.** `N42_CUSTOMIZATIONS.md` (the additive chainspec function), `docs/N42_26_PORT.md` (a gov5 subsection from 2.4), a pointer in `PHASE_D_DEFERRED_EXECUTION.md`, `CLAUDE.md`'s mention if any, the round results as they come | docs | | |

Order and dependencies: 0 -> 1 -> 2 -> {3, 4, 5, 6 independent; all before 5's flip is used} -> 7 -> 8; step 5's
flip is the first moment a depth-2 genesis loads. Total estimate: ~1,350 lines of change, 60% tests, about 4-6 agent
sessions; steps 0-2 and 4 are mechanical, 3 is the one that needs care (items 5 and 8).

**The legs after step 7** (not part of any step): (a) the three-node independent-execution smoke and the three fault
legs of 4.7; (b) before any of it, a D=1 leg at pacing 45 ms with SES 17's switches on, to read the proposal-to-Decide
time (risk 3) and `V`; (c) the E=1 pacing sweep at 200k in pairs; (d) 400k. Success is not a rate: it is
`fields_mismatches` 0, `invalid_blocks` 0, `rename_wait_us` 0 on the early path, no `ParentUnknown`, and a floor read
from the counters of 3.1 that says which chain binds.

## Appendix A. Switching a live depth-1 chain to depth 2 (not planned)

If a chain that already runs depth 1 had to move at time `T`: the first depth-2 block `X` (parent `X-1` at depth 1)
carries `result(X-2)`, which is *also* in the parent's header (a depth-1 header carries its parent's result). So the
transition rule is: for the first block at or past `T`, expected = the parent's own header fields; for every later
block expected = `registry[parent.parent_hash]`. No result is skipped (`result(X-1)` appears in header `X+1`) and one
is repeated (`result(X-2)` appears in headers `X-1` and `X`), exactly as the genesis fields repeat at the chain
start. It needs the parent header in the check (already given) and the registry to hold every block executed before
`T` (feed `seed_from_header` on the pre-`T` import path). The cost is a `deferredExecutionDepthTime` key and the
two-case check; the benefit is zero until a chain needs it. Not built.
