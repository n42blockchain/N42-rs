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
