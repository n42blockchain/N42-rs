# Shared execution: seven validator keys on E execution layers

Scope study, 2026-10-04. Read from code and scripts only; nothing was built or run. "Verified" below means
read in the source, not measured.

## 1. How the devnet attaches four validators to one EL

`scripts/devnet-fleet.sh` starts one `n42 node` (auth 18551, http 18545, one jwt) and four
`h2_validator --el http://127.0.0.1:18551 --el-rpc http://127.0.0.1:18545 --jwt ...`, each with its own BLS key,
libp2p port and datadir, peered through validator 0. It sets **no** `N42_PAYLOAD_SERVE`, `N42_TX_INGEST` or
`N42_FOLLOWER_DIRECT_IMPORT`. So every channel is plain Engine API (JSON `newPayload`, `forkchoiceUpdated`,
`getPayload`); the raw payload channel, direct import, compact bodies and the CHECKED frame are all off.
A follower's `newPayload` for a block the EL already holds is answered from reth's tree (`already_seen`,
`engine/tree/src/tree/mod.rs`), and a repeated `forkchoiceUpdated` to the canonical head takes reth's "head is
already canonical" fast path. That is why the devnet shape works: the engine dedupes by block hash.
The leader's validator alone builds (`forkchoiceUpdated` with attributes, `getPayload`, seal with its own key and
view, own-block import). Nothing else needs to run on the other keys.

## 2. The bench path with more than one validator on an EL

The bench path sits **in front of** reth's dedupe. `bin/n42/src/payload_serve.rs` (`import_for_validator`) has no
"block already known" check (no per-hash gate exists in `payload_serve.rs` or `follower_import.rs`), so each
request executes the block again. k keys on one EL means k executions, k QMDB root jobs, k hashed-state builds.
Per singleton:

| Singleton | Verdict |
| --- | --- |
| `built_executions` store (`take` consumes the build) and `sealed_store` | **Breaks.** The first of k requests takes the own build; the rest, and the leader's own `OWN_BLOCK`, find "unknown build" and fall back to a full import or a payload send. *Corrected after reading `built_executions.rs`:* `take` moves the build to a "handed" list that only `find_kept*` reads (the build-on-own lookups), not `find`/`take`, so the import roads miss it as described -- but only without `N42_BUILD_ON_SEAL`. With it, `OWN_BLOCK` uses `find` and leaves the build in place, so every later taker finds it and repeats the whole hand-off (a second executed insert and queue forget per key) instead of failing. |
| `chain_alias::rename(built_hash, sealed_hash)` (QMDB tree filed under the sealed hash) | *Corrected:* does **not** break. `QmdbForest::rename` (`crates/n42/qmdb-state/src/forest.rs`) answers Ok when `from` is gone and `to` is already filed (the build-on-seal path relies on that), and when both are filed with the same root. The second taker's failure is the lookup above, not the rename. |
| `HELD_EXECUTIONS` (hash -> one receiver, `N42_VOTE_BEFORE_SLOT`) | **Breaks** with two requesters (the second insert replaces the first's receiver). Off by default; keep off. |
| `executed_fields` registry (hash -> result), `IMPORT_LANDED`, `HANDED` | Works as is: hash-keyed, EL-wide. A second key's "parent fields equal my EL's result" read hits the same record. |
| Chain slot / build registry in `engine.rs` (`ChainState.slot`, `generation`) | Client-side, one per validator process, so per key. Works: only the leader builds. At a tenure change two keys may each have a chained build on the EL for a moment (1-2 GB each). Handover is where past defects lived (17.7, defect 8): test it, do not assume. |
| Import slot accounting in `h2-execution/src/driver.rs` (`N42_DEFERRED_IN_FLIGHT`) | Per validator process. Works, but k keys ask for k imports of one block, so the EL sees k concurrent imports (the code notes execution inflates with two in flight). |
| Commit `forkchoiceUpdated` per key | Works; k-1 are no-ops on the canonical head (reth fast path). Cost on the engine thread not measured (the real one is 30-36 ms). |
| In-memory/persisted poller, build throttle | Works: k pollers of two cheap RPCs. |
| Queue taken list (`forget_mined`, `hold_own_block`) | *Verified idempotent:* a second forget finds nothing left in the taken list or the lanes, and `hold_own_block` returns at once on an empty list, so no second hold and no give-back. Called k times per block today; once with `N42_IMPORT_ONCE`. |
| `payload_serve` `LISTED_TRANSACTIONS` (last two blocks) | Works (keyed by hash). |

## 3. What a vote means with k keys

A vote attests: body held and well-formed, transactions includable on the parent's post-state, the header's four
fields for N-1 equal this EL's result (section 17 of `PHASE_D_DEFERRED_EXECUTION.md`). All three are EL facts,
and the third is already a hash-keyed shared lookup. But the CHECKED frame is produced per request, so today k
votes cost k checks and k executions. **Needed:** an `ImportOnce` registry in the EL keyed by block hash, taken
by all four request kinds (`OWN_BLOCK`, `COMPACT_BODY`, `FOREIGN_BODY`, `NEW_PAYLOAD`). The first request does
the work; later ones wait on it and get CHECKED as soon as the check cell is set, then the final status. If the
first connection dies the cell is reset so another key takes over. Estimated 300-500 lines plus tests, in
`bin/n42` only (no vendored reth change). Fault domain note: k keys on one EL share one EL's mistakes by design.

**Implemented (2026-10-04): `N42_IMPORT_ONCE=1`**, `bin/n42/src/import_once.rs`, used by the four roads in
`payload_serve.rs` (the list is complete: `BUILD_ON_OWN`, `OWN_BODY` and `GET_PAYLOAD*` import nothing).
What differs from the sketch above:

- The hash is taken before any work: `OWN_BLOCK` decodes the header, the two body roads read the hash the frame
  announces, `NEW_PAYLOAD` reads it straight out of the frame (`peek_payload_hash`) without decoding 19 MB. A
  later key's request is constant-time: the frame is read off the socket and nothing of it is decoded,
  assembled, hashed or copied.
- A first request that ends without a final status (connection died, road refused, engine failed) resets the
  cell on drop; one waiter takes the work over with its own request. Only VALID/INVALID answer later requests;
  SYNCING/ACCEPTED answer the waiters of the moment only.
- The leader's own block resolves to one hand-off of the build whichever key's request arrives first: the
  `OWN_BLOCK`, a payload (`reuse_own_build`, which under the registry uses `find` like `OWN_BLOCK` when the
  validators build on seal), or a compact body, which is recognised as an own build by its header and imported
  by header instead of being assembled and executed (with `N42_BLOCK_BY_DESCRIPTION` that road never tried the
  build before). The own-block road publishes CHECKED as soon as the build is found, so the other keys vote
  without waiting for a build sealed before its finish.
  *Correction after loop328/330:* the first version compared the sealed header's withdrawals root with the
  build's raw, and gov5's seal rewrites it as the rewards commitment, so the compact-body recognition never
  matched: at E=1 the follower keys' compact bodies won the race for almost every own block and 1,175 of 1,179
  built blocks were executed a second time (only blocks whose `OWN_BLOCK` arrived first were handed off).
  Now all three follower roads recognise an own build by its header before any assembly or decode, comparing
  the withdrawals root in both shapes (the payload road rebuilds the sealed header from the build), answer
  CHECKED at once and the status when the build is handed off (waiting for a build still finishing), and fall
  through to an ordinary import only when the build was abandoned. `own_from_build` / `own_executed_again`
  on the per-block lines prove the second stays 0.
- Held executions (`N42_VOTE_BEFORE_SLOT`) are refused: start-up error with both switches, and an ERROR answer
  to a `HOLD_EXECUTION` request under the registry.
- Gated behind the switch (default off): with it off every road is byte-for-byte the old code, and the
  registry also changes who answers a repeated request for a known hash, which is a behaviour change even with
  one key.
- Tenure handover between two keys on one EL: the incoming leader's first build (`BUILD_ON_OWN` on the sealed
  parent, sent at tenure start under `N42_BUILD_ON_SEAL=1 N42_TENURE_FIRST_ON_OUTPUT=1`) finds the outgoing
  leader's build in the EL-wide registry (`find_kept_sealed` reads the store and the handed list), so the
  published-output path is skipped and the build chain runs on across the handover with no code change.

## 4. Networking

Proposals and votes stay on libp2p (static full mesh, loopback). Bodies: `push_body` goes per peer address
(`body_channel::address_for`), and with `N42_COMPACT_BODY` plus frame blocks the compact body is a few hundred
KB; the receiving EL assembles from its queue, which on a shared EL already holds the transactions (the queue
keeps an own block's transactions until the height settles). The topic publish is skipped when every peer took
the push. So no new transport code is needed for loopback; at most the cost is k assemblies, which the gate in
section 3 removes. A "skip the body for peers on my EL" rule would be new work (a same-EL peer set in
`service.rs::push_body`) and only matters off loopback or if compact bodies are not used.
Unchanged cost: k consensus loops, k BLS verifications per QC, k sets of vote messages.

## 5. What the runner needs

- **Script, new variables:** `F7_VALIDATORS` (=7; today `F7_NODES` means validators, ELs, quorum and the
  genesis check at once), `F7_EL_MAP` (e.g. `0,0,0,0,0,0,0`; `0,1,2,3,0,1,2` or `0,0,1,1,2,2,3`) giving E ELs.
  `f7_el_args`/`f7_pin` iterate ELs, `f7_validator_args` takes the EL index from the map for `--el`, `--el-rpc`
  (omit on all but the first key of an EL, or keep `F7_NO_TX_GOSSIP=1`, as the bench does) and `--el-ingest`.
  `fleet7.sh up` spawns ELs then validators; `N42_INGEST_SHARD` becomes `e/E`. Datadirs: `node<i>/consensus` per
  key, `node<first key>/el` per EL.
- **Genesis:** `n42_fleet7_bench.json` already has seven validators (quorum 5, f=2), `deferredExecutionTime`,
  `frameBlocks`, `altSigTx`; the replay set `/data/n42-pregen/g900000` is keyed to the alloc, which is shared.
  No new genesis.
- **Cores:** keep the fleet total at 224 CPUs (112 physical) so the flood keeps its 16: E=7 32 each, E=4 56
  (as `fleet4-env.sh`), E=3 74 (as `fleet3-env.sh`), E=1 224. Pin each EL's validators into that EL's set.
  Caveat for E=1: pool sizes are fixed by env (`RAYON_NUM_THREADS=16`, `TOKIO_WORKER_THREADS=8`) while reth sizes
  its own pools from the affinity mask, so 224 CPUs may not scale; add an E=1 leg at 74 CPUs.
- **Order of keys:** contiguous (`0,0,1,1,...`) makes half the tenure handovers stay on one EL, which removes the
  handover import wait; interleaved does not. Run both for E=3/4 or the result mixes two effects.
- **Scripts that assume one EL per validator:** `fleet7-bench.sh` (`RPCS`, `INGESTS`, the clean-up loop, lines
  272/307/400), `fleet7-verify.py` (`F7_NODES` as ports and as validator count, authors "of N"),
  `fleet7-phases.py` (pairs `node*/v.log` with `node*/el.log`), runner `memsample`/`perf`/`threadcpu` loops over
  `node0..2` and `F7_METRICS_BASE+i`. `fleet7-measure.py` reads node 0 only: fine.

## 6. Estimate

| | Script only | Code |
| --- | --- | --- |
| (a) E=1, seven keys | mapping variables, core sets, bench/verify loops: ~0.5 day | `ImportOnce` gate, tests: ~1-1.5 days; plus handover test with two keys on one EL |
| (b) arbitrary mapping | same script work (the map is general); phases analyzer pairing: ~0.5 day | none beyond (a) |

**First experiment:** script mapping plus the `ImportOnce` gate, then legs on `n42_fleet7_bench.json`, same
knobs as the latest runner (`run-loop326.sh`): WARM; control `F7_EL_MAP=0,1,2,3,4,5,6` (must reproduce the fleet7
bench, which proves the refactor is neutral); E=1 at 224 CPUs; E=1 at 74 CPUs. Report win1 TPS, cycle, `imports
per block per EL` (must read 1, else the gate leaks), handover stall count, EL peak memory. Without the gate an
E=1 run measures k-fold execution, not shared execution; it is not an honest number.

## 7. What was built (script side, 2026-10-04)

No cargo, fleet or node was run; everything below was checked with `fleet7.sh print|plan`, which start nothing.

**Variables** (`scripts/fleet7-env.sh`; `fleet3-env.sh` and `fleet4-env.sh` layer on it unchanged):
`F7_VALIDATORS` (default `F7_NODES`; `F7_NODES` stays "validators" for every script that reads it), `F7_EL_MAP` (one layer
index per validator, comma list), derived `F7_ELS`, `F7_MAPPED`, `F7_SHARED` (fewer layers than validators). `F7_EL_CPUS=<n>`
caps a layer; `F7_VAL_CPUS=<n>` (default 16 when shared, 0 = validators share their layer's CPUs) sets validators' CPUs aside.
Ports, datadirs (`node<first key>/el`), pids, shard (`e/E`), flood RPC and ingest lists are per layer; `--el`, `--el-rpc`
and `--el-ingest` per validator, the last two on the first key of each layer only (`F7_NO_TX_GOSSIP=1` still drops gossip).
`fleet7.sh up` refuses a shared fleet unless `N42_IMPORT_ONCE=1` is set and the `n42` binary contains the string
(`F7_ALLOW_UNGATED=1` overrides, to measure k-fold execution on purpose); `roll` is refused with a map; `F7_PIN_SWAP` is
refused with a map. `fleet7.sh plan` prints the layer and validator tables then `print`'s exact command lines.

**CPU layout (224 CPUs = 7 x 32, the fleet's budget; the flood keeps 112-127,240-255):** one-to-one is unchanged. Shared:
validators on 16 CPUs of their own at the end of the budget (`104-111,232-239`), layers share the rest in whole physical
cores: E=1 208 CPUs (`0-103,128-231`), E=1 capped 74 (`0-36,128-164`), E=4 52 each. I chose a separate validator set
because seven validator processes on the layer's cores would take CPU from the one thing E=1 measures.

**Dry-run results** (`plan`, bench genesis, `N42_IMPORT_ONCE=1`): `0,1,2,3,4,5,6` -> 7 layers, 32 CPUs each, byte-for-byte the
old `print` (the identity map takes the old code path); `0,0,0,0,0,0,0` -> 1 layer, validators 0-6, key 0 carries
`--el-rpc`/`--el-ingest`, shard 0/1, flood feeds `127.0.0.1:8700` once; `0,0,1,1,2,2,3` -> layers at node0/2/4/6, shards
e/4; `0,1,2,3,0,1,2` -> layers at node0-3, keys 4-6 without gossip flags. Bad maps (wrong length, a gap) are refused.
**Empty-diff check:** `fleet7.sh print` at HEAD (the commit before this change, scripts copied out with `git show`) against the new
script, same environment, for the lean and bench defaults, `F7_INGEST=1`, `F7_PIN_SWAP=1:2`, `F7_PIN_PHYSICAL=0`,
`F7_PIN=0` and the three-node and four-node setups: identical.

**Loops updated:** `fleet7-bench.sh` (RPC and ingest lists per layer; a `layers` header line only when shared),
`fleet7-verify.py` (ports per layer via `F7_ELS`, quorum and authors over `F7_VALIDATORS`), `memsample.py` (layer e in the
directory of its first key, reads `F7_EL_MAP`), `fleet7-phases.py` (comment only: its globs are already per layer for `el.log` and
per validator for `v.log`). `fleet7-measure.py` reads layer 0 only: unchanged.
**Analysis scripts that need per-layer versus per-validator handling (not rewritten):** the runner copies `node<e>-el.log`
per layer and `node<i>-v.log` per validator, so `analyze32x.py` (pairs `node<n>-el.log` with `node<n>-v.log`),
`fleet7-excess-anatomy.py` (`node{leader}-el.log` with the leader a validator index; cross-node follower stages),
`fleet7-depth-replay.py` and `fleet7-windows.py` (`builds-node*.log`) read a validator's index as a layer's. With E=1 only
`node0-el.log` exists and the leader's own and the followers' stages are in one log.

**Replay set and tier:** `n42_fleet3_bench.json` and `n42_fleet7_bench.json` are identical except for the `validators` list
(chain id 1143, the 14-account alloc, gas limit `0x1c9c3800`, `altSigTx`, `frameBlocks`, `deferredExecutionTime: 0`,
committee pool). A pre-generated set is bound to chain id, alg, senders, pertx, offset, gas, gasprice, recipients,
rpcbatch, conc, claim-sender and the gateway key (`tx_flood --help`), not to validators or layers, so `/data/n42-pregen/g900000`
(64 workers, offset 900000) is valid on the seven-validator genesis and the 480M-gas tier as is; `--ingest-all` sends each
frame to each listed layer, once. Nothing needs regenerating. What does change: the offer is per layer (2.0M tx/s each), so E=1
is offered a seventh of what E=7 is; and the loop326 knob set was tuned at 74 CPUs a node, so the E=7 control runs 32.
With `leaderTenure` 1024 key 0 leads for the whole round: handovers do not occur in a leg, so E4 and E4I differ only in which
key shares key 0's layer.

**Runners:** `scripts/fleet7-runs/derive328.py` writes `run-loop328.sh`/`launch-loop328.sh` (E=1 peak search: WARM, E7, E1, E1b,
E1P80, E1P70, E1T build pool 32->64 and rayon 16->32, E1C74, E1FS) and `run-loop329.sh`/`launch-loop329.sh` (WARM, E7, E4, E4I, E4b,
E4Ib) from the loop326 pair. The switch is the variable `ONCE` at the top of the runner; the runner and the launcher (after
its build) refuse to start when the tree or the binary lacks `N42_IMPORT_ONCE`. Not launched.

## 8. E=1: the seal's tail and the decay after the first minute

Offline read of loop333 (`/data/blockchain/rust-fleet7-bench/bench-loop333*`, the strip/mem/threadcpu/pf files under
`target/fleet-runs`; BREAKTHROUGH_DESIGN 10.80), no new run. Legs G80, G80b, X, Xb (200,000 transfers, 80 ms), H100
(250,000, 100 ms), G70 and B70b (163,000, 70 ms). Times are seconds from the first full build (t0). All counts come from
the layer's `seal-first build phases`, `own block handed to the engine`, `Canonical chain committed`, `Block added`
lines; `state_wait_on` and `state_wait_split` are the build line's own attribution
(`direct_build::open_wait`: output / grandparent / parent_root / parent_complete, and "open" for the rest of the open).

### 8.1 The decay is mostly the harness, and what is left is the engine falling behind

**The state wait has two kinds, and one of them is switched on by the measurement.** Per 10 s, builds whose
`state_wait_ms` > 20 by `state_wait_on`:

| leg | 0-30 s | 30-140 s | 140-172 s |
| --- | --- | --- | --- |
| G80b | open 0, grandparent 7-14 | open 8-16, grandparent 5-13 | open 0, grandparent 8-18 |
| H100 | open 0, gp 5-7 | open 10-14, gp 1-9 | open 0, gp 9-13 |
| B70b | open 0, gp 4-9 | open 8-22, gp 4-11 | open 0-6, gp 6-11 |

On every one of the eleven legs (and on loop332's G80 and B80) the "open" waits begin at t0+31-32 s, exactly when
window 1 ends, and stop when `fleet7-measure.py` stops reading: after window 1 it fetches every block of the window with
`eth_getBlockByNumber(n, false)` (367 blocks of 200,000 hashes, ~13 MB of JSON each, one at a time), which takes about
110 s (t0+30 to t0+140); the bench's own window 2 then sleeps over t0+140-170 (G80b: 347 blocks there by my count and
by the bench's), and window 3 starts after the flood has ended (its "0 transactions" is the end of the set, not an RPC
refusal). `analyze333.py`'s canonical slices 2 and 3 (t0+30-90) therefore lie entirely inside the read. Rates by period
(seal `sealed_at` mean / p90 / p99, share of builds sealed later than the tick minus 3 ms):

| leg | 0-30 s | 40-130 s (harness reading) | 140-172 s (quiet) | bench win2 / win1 |
| --- | --- | --- | --- | --- |
| G80 | 2.45M, 70/85/132, 20% | 2.20M, 87/147/227, 42% | 2.24M, 84/124/225, 47% | 91.7% |
| G80b | 2.45M, 74/93/144, 23% | 2.21M, 86/138/215, 44% | 2.32M, 78/114/153, 33% | 94.5% |
| X | 2.45M, 74/91/135, 28% | 2.20M, 86/141/230, 43% | 2.29M, 83/115/165, 50% | 93.8% |
| Xb | 2.45M, 74/89/127, 29% | 2.20M, 86/138/217, 42% | 2.33M, 80/120/162, 38% | 95.1% |
| H100 | 2.45M, 92/107/177, 28% | 2.18M, 108/180/267, 40% | 2.27M, 104/164/219, 37% | 93.5% |
| G70 | 2.51M, 73/91/142, 57% | 2.21M, 86/142/225, 63% | 2.30M, 83/124/198, 73% | 88.7% |
| B70b | 2.28M, 58/70/114, 14% | 2.10M, 72/120/189, 34% | 2.25M, 63/88/124, 26% | 100.0% |

So of the 9-12% loss in 10.80's windows 2-3, about two thirds is the harness's RPC read of window 1 contending with
the leader's state open, and one third is real: in the quiet period the full-block legs at 200-250k read 91-95% of
window 1 and B70b (163k at 70 ms) reads 100%. What the RPC read does to the leader: 9-13% of builds wait 60-120 ms in the
open with no named wait (`split` 0/0/0/0, `gp_layer=1`, the great-grandparent already in the engine), so the time is
inside `client.state_by_block_hash(great_grandparent)` (in-memory lookup, `database_provider_ro`, the stage checkpoint
and the anchor's `block_hash` read from the static files, `OverlayStateProvider::new`) or in `leader_layers::keep`
(it drops the released great-grandparent layer on the build thread). Which of these the RPC read blocks is not
named by any field; the static-file path (the anchor's header read while persistence commits static files, 47 ms a
commit on average: `save_blocks_commit_sf` 84 s over 1,777 commits) is the first suspect. It is a product issue too: a
node that serves block reads while it leads would lose the same 10%.

**What tracks the real residual (t0+140-172 against window 1, G80b/X/Xb pooled, slow = `sealed_at` >= 85):** slow
builds 23% of 1,110 against 12% of 1,468; of them 46% wait on the grandparent (the engine), 36% on the parent's
fields, 16% other. Medians hardly move (`sealed_at` 71 -> 73, `par_ms` 61 -> 61, `par_exec_ms` 26 -> 26); means move
by the tail (`sealed_at` 73.5 -> 77.8, `roots_ms` 28.9 -> 33.8, `root_faults_undo` 2 -> 21, `root_append_faults`
5 -> 23, `state_wait_ms` 5.7 -> 8.1, `sealed_ms` 10.7 -> 12.3). The engine is two to three blocks behind the seal at
every build start (median lag 3: the newest block in the engine is N-3 when N starts; lag 4 on 5-15% of starts),
its own-block hand-off grows from 29-32 ms to 32-40 ms (p90 40 -> 45-59) and its per-block busy time (hand-off +
canonical commit 15-22 ms + head moves on 25-45% of blocks, `own block forks from the engine's head`) from 50-53 ms to
55-71 ms on an 82 ms cycle. That is the "grandparent" class growing from 6-8% to 10-12% of builds.

**What does not track it:**

- In-memory blocks: 10-17 for the whole leg (memsample `num`), throttle silent; persistence 58 ms a full block
  (215 s over 3,691 blocks in 1,180 batches), below the cycle throughout. Overlay filter cache 15-17 entries, ~2 builds
  a block, flat.
- Accounts: the 400M set pays 2,000,000 recipients (`--recipients 2000000`), 190,503 distinct a block (shape line). The
  range is fixed, so creations decay geometrically: 95% of the range exists after ~30 blocks (~2.5 s) and the rest of
  the leg is updates only (`root_twig_pool_refills` mean 5.2 in window 1, 0.6 late). The later part of the set does
  not create more or touch a wider range; window 1 carries the creations.
- RSS: the layer's RSS climbs 16 -> 40 G, but host-wide `AnonPages` only 19.5 -> 22.7 G (validators and flood
  included, Shmem flat 14.6 G): about 20 G of the growth is file-backed mapped pages (the entry file and static files
  mapped by readers), not heap. No leak is visible. `AnonHugePages` 12.9-15.1 G flat; `compact_stall` +124 over a leg.
- Memory pressure: `Cached` grows 1.1 GB/s (35 -> 105 G) until `MemFree` reaches ~1.7 G at about t0+65 s, then kswapd
  reclaims (Cached 105 -> 64 G over t0+70-95 s) and the cycle repeats (MemFree 3.6-16 G at t0+125-145). The fillers are
  the replay set (64.9 GB read over 175 s) and the layer's static-file writes. This overlaps the harness read, so its
  share cannot be separated in loop333; page-fault samples (`pf-*.csv`, perf stat for 60 s) cover only t0-4 to +55 s
  (67k/s rising to 140-148k/s).
- QMDB growth: the delta-log checkpoint grows linearly with updates (5.7 MB at t0 -> 47.7 MB at t0+165; compaction wall
  29 -> 95-224 ms, on its own nice-10 thread, 131 -> 8 compactions per 20 s). The entry file is append-only, so every
  update grows the tree whether or not it creates an account; the root's undo/append faults (above) are where that shows
  up on the seal.

**Verdict.** "The chain is slower on a bigger state" is a real but small property at E=1: 5-9% at 200-250k a block after
two to three minutes, 0% at 163k, carried by (a) the engine's per-block import growing until the great-grandparent
is sometimes not in the engine at the child's start and (b) the root's faults growing with the append-only tree. Neither
is a leak, and both are fixable (8.4). The rest of 10.80's decay is the harness (fixable in the script) and a real RPC
contention in the leader's state open (fixable in code once named).

### 8.2 The tail: what `state_wait_ms` waits for

The chained build of N starts at N-1's seal and opens N-1's state lazily after its pull
(`N42_STATE_AFTER_PULL=1`) through `opener_on_sealed_parent_with`: N-1's output (filed as shards + residual, never
waited on here: `output_ms` 0 on every build), N-2 from the kept layer (`N42_GRANDPARENT_SHARDS`, default on), and the
engine's state at N-3 underneath. When N-3 is not in the engine yet (`ggp_missing=1`) it falls back to
`grandparent_state`, i.e. polls (2 ms) until **N-2** is in the engine. Slow builds' `split` is `0/60-90/0/0` with
30-36 polls, `gp_layer 0`, `ggp_missing 1`: the 90 ms is the wait for the engine to land N-2 after it was still missing
N-3. Timeline of a typical case (G80 block 718): N-1 sealed at 0; the engine adds 714 at -86 ms, 715 at +28 ms
(hand-off 30 ms), moves its head at +56 for 716 and adds 716 at +84; the open ends at about +68-70, once 716 is
reachable. Had the fallback waited for N-3 (715) it would have ended at about +30; had a third layer been kept it would
not have waited at all. What delays N-3: nothing exotic. The engine imports one own block per ~55 ms of serial work
(the hand-off's `chain_alias::rename` behind the forest lock held by the root job, `forest lock held
label="compute_operations"` 20-25 ms on 30-76 builds per 10 s; the insert behind the previous canonical commit;
the head move when the new block's parent is not the head), and the hand-off itself starts only after the block's
`Complete` (~100-110 ms after its seal: `state_ready_ms` 98-109). So a block reaches the engine about two cycles after
its seal, which is exactly where N's start lands N-2, and one slow import (a 40-60 ms hand-off, a head move, a QMDB
compaction or persistence batch near it; none of them is present in more than 25% of the cases) puts N-3 behind too.
No periodicity (10.80: no pattern mod 8, isolated).

**Not the waits the three-node switches shortened.** `N42_SHARDS_MERGE_OFF_PATH` is read only by
`bin/n42/src/follower_import.rs`; with `N42_IMPORT_ONCE` the layer never imports its own block by execution, so the
switch does nothing at E=1. `N42_FIELDS_AT_SEAL=1` shortens the parent-fields chain (8.3: `rename_wait_us` 19-25 ms
median), which is the 36% "parent_fields" share of the late slow builds, and it renames the parent's tree early, so the
grandparent's later hand-off finds the rename done; it may thin the grandparent class indirectly but does not address
it. Starting the build on the parent's shard view without the merge is what the opener already does (`output_ms` 0).
The fix for this wait is a third kept layer (8.4 C1).

### 8.3 What is serial per block and the seal's floor

Window 1 medians / p90, ms (G80; G80b, G70 within 1-3 ms; H100 scales with 250k, B70b with 163k):

| chain | piece | median / p90 |
| --- | --- | --- |
| child's build (start at N-1's seal) | start (`start_best`: walk 5, handoff 2) | 8 / 21 |
| | pull 4 + prep 3 + partition 0 | 7 / 9 |
| | state open (`state_wait`) | 0 / 0 (tail 8.2) |
| | execution `par_run` (batch start skew 13 + longest batch 16-17; `par_exec` 26) | 28 / 38 |
| | commit 2 + fold 6 (+ index 4-5 inside) + tx root 2 | 10 / 12 |
| | parent's fields (`parent_fields_ms`) | 0 / 16 |
| | seal (`sealed_ms`, remember 3) | 5 / 22 |
| | **`sealed_at`** | **67 / 85** |
| parent's fields (N-1 after its seal) | finish to shard view (`seal_to_view`) | 13 / 15 |
| | rename wait for N-2's `Complete` (`rename_wait_us`, fields at seal off) | 19 / 32 |
| | QMDB root (`roots_ms`: apply 14, hash 1, the rest undo/append/lock) | 29 / 35 |
| | **`seal_to_fields`** | **64 / 77** |
| engine (per own block) | hand-off (rename under the forest lock, insert) | 29-32 / 40 |
| | canonical commit | 17-18 / 22 |
| persistence (own thread) | ~3-block batches | 58 per block |

The execution is 42% of the median seal, start 12%, pull/prep 10%, commit/fold/tx root 15%, seal 8%; the roots
(22-28 in 10.80's phrasing, 29 here at 200k) are not on the child's chain but on the parent-fields chain, which runs
beside it and is nearly as long (64 against 67). The floor today is the longer of the two: ~64-67 ms median, p90
~85. With `N42_FIELDS_AT_SEAL=1` the fields chain drops to ~45 (13 + 29 + publish) and the floor is the build chain
itself, ~58-60 ms of waits-free work (the sum of the medians above). For a 60 ms tick to stop binding (35-43% of
blocks at 60-70 ms in loop332/333), the p90 has to come under 60: fields at the seal (removes ~20 ms from the fields
chain), the grandparent wait gone (8.4 C1: the 60-90 ms tail of 6-12% of builds), and one more piece of the build
chain cut by 10-15 ms. The single piece that can give that is the execution's batch start skew (13 ms of the 28:
batches start 13 ms apart from first to last on a 32-thread pool, then the longest batch runs 16-17 ms); more build
threads did not help at 163k (loop331 R with 96 against B32: 49 against 43 ms), so it is the dispatch, not the
thread count.

### 8.4 Ranked changes

Switches to try on a leg first (no code; G80 and G70 on the 400M set, harness fix S0 in place):

| # | switch | targets | expected | confirm by |
| --- | --- | --- | --- | --- |
| S0 | measure windows from the layer's canonical log (or read the windows' blocks after the leg), not by RPC between windows | the 30-140 s "open" waits | windows 2-3 from 2.20M to the quiet 2.24-2.33M; nothing on window 1 | no `state_wait_on="open"` > 20 ms anywhere in the leg |
| S1 | `N42_FIELDS_AT_SEAL=1` (run `=verify` once first) at 200k / 80 and 70 ms | `rename_wait`, parent-fields tail | seal p90 -10 to -15 ms; G70 seal-bound share 43% -> under 30%; peak +2-4% | `seal_to_fields` median < 50, `parent_fields_ms` p90 < 5, `fields_mismatches` 0, no handover TC (tenure 1024 has no handover in a leg) |
| S2 | `N42_QMDB_APPEND_AHEAD_MB=256 N42_QMDB_APPEND_REWALK=1 N42_QMDB_UNDO_POOL=128 N42_TWIG_POOL_FLOOR=1024` | root's append/undo faults growing late | late `roots_ms` back to ~29; sustained +1% | `root_append_faults`, `root_faults_undo` means flat across the leg |
| S3 | replay reader with `POSIX_FADV_DONTNEED` (or `F7_DROP_CACHE` mid-leg), harness only | page cache full at +65 s, reclaim | removes the reclaim from the measurement; unknown share | `MemFree` never under ~10 G; compare quiet-period rates |

Code changes, by expected effect:

1. **C1, a third kept layer for the leader's opener** (`crates/n42/engine-types/src/direct_build.rs`:
   `leader_layers` keeps three generations; the opener walks the kept layers newest first down to the first
   ancestor the engine holds; the fallback waits for the oldest missing ancestor, never for N-2). Removes the
   "grandparent" class (6-8% of builds in window 1, 10-12% late, 60-90 ms each). (a) sustained +3-5%, (b) peak at
   G70/H80 +4-8% (fewer seal-bound blocks). Risk low: one more block's shard set in memory (hundreds of MB), one more
   overlay level on reads; the overlay-order tests in `direct_build.rs` cover it. Confirm: `gp_layer` 1 on >= 99%
   of builds, `ggp_missing` ~0, `state_wait_on="grandparent"` < 0.5%. A one-line interim: in the fallback wait
   for the great-grandparent instead of the grandparent (about 30-50 ms of each such wait).
2. **C2, name and remove the RPC contention in the open** (split `state_by_block_hash` and `leader_layers::keep`
   into timed fields first; then likely candidates: hand the released layer to a release thread; avoid the
   static-file `block_hash` read in `n42_layered_state_provider` by checking the anchor against the in-memory
   chain). (a) for any node serving reads while leading, the 10% of 8.1; on the bench equal to S0. Risk low.
   Confirm: an RPC-reading leg (today's harness) with no "open" waits.
3. **C3, a cheaper own-block import** (`bin/n42/src/payload_serve.rs` hand-off: rename before `Complete` when the
   fields are early, the insert not queued behind the canonical commit, and no head move for a block whose parent is
   the engine's pending head). Shrinks the engine's 55-70 ms per block that makes N-3 late and that grows over the
   leg. (a) +2-3% (the late drift), (b) small. Risk moderate (engine ordering). Confirm: hand-off p90 flat at <= 35
   across the leg, lag-4 starts < 2%.
4. **C4, the execution's batch dispatch** (pre-armed workers or batches handed out by work-stealing instead of a
   serial start, `crates/n42/engine-types/src/batch_state.rs` / the parallel step in `payload.rs`). Only for (b):
   with S1 and C1 the build chain is the floor and `batch_start_skew` 13 ms is its largest removable piece; -8 to -12
   ms on the seal would let 60 ms ticks hold (163k at 60 ms: 2.7M; 200k at 70 ms: 2.86M). Risk moderate. Confirm:
   `batch_start_skew_ms` < 4, `par_run_ms` median <= 20, B60 seal-bound share < 10%.

Analysis scripts used: ad-hoc parsers of the same lines as `scripts/fleet7-runs/analyze333.py` (per-10 s phase
medians, `state_wait_on` counts, wait end against engine events, period comparisons); none was kept.

## 9. E=1: the seal's floor taken apart (loop334 L3FS70 / L3FS60, offline)

Offline read of loop334's L3FS70 and L3FS60 (`/data/blockchain/rust-fleet7-bench/bench-loop334L3FS{70,60}`, the layer is
node 0; validator 0's tenure for the validator-side figures), window-1 blocks 20-420 of the layer's `seal-first build
phases` lines, joined with `build on the sealed block answered on the early seal`, `built ahead on the sealed own
block`, and validator 0's `chain started`, `proposal sent` and `block committed!` lines. No run. Medians (p10 / p90).

### 9.1 The seal (L3FS70, `sealed_at_ms` 62 / 57 / 70; L3FS60 59)

| piece | median | what is serial in it |
| --- | --- | --- |
| start (`par_start_ms`) | 10 (8 / 15) | `start_handoff_ms` 2 (the wait for the parent's queue hand-off, `forget_mined_parallel`, started when the request arrives), `start_walk_ms` 6 (the frame plan under the queue's lock: ids, a parallel check that reads < 1 ms, then the decisions in arrival order and 400 segments of 500 hashes copied, serial), the rest 1-2 |
| pull (`par_pull_ms`) | 5 | the puller thread walks the plan's 400 segments and clones 200,000 `Arc`s into 196 batches of 1,024 over a channel; the build thread only receives. Serial on one thread, ~25 ns a transaction of cold atomics |
| prep (`par_prep_ms`) | 3 | already a parallel pass over the candidates (keys, body ahead) |
| partition + slots (`gap_before_exec_ms`) | 2 | `partition_by_sender` (one comparison a transfer on sender runs), `batch_groups`, the 200,000 slots made on the pool, the deferred state open (`state_wait_us` 166) |
| execution (`par_exec_ms`) | 27 (25 / 29) | see 9.2 |
| commit / fold / index / tx root | 1 + 6 (index 5 inside) + 2 | on the pool already |
| seal (`sealed_ms`) | 5 | header, block, remember, hook |

### 9.2 The batch stagger is two waves, not a slow dispatch

The block is 400 sender runs of 500 (shape line: `senders=400 run_median=500`). `batch_groups` packs at most
`2 x workers` batches of about `total / wanted` transfers: 200,000 / 64 = 3,125, so 7 runs a batch, 57 batches of
3,500 and one of 500 (`batch_txs_max` 3500, `batch_txs_min` 500 on every block), on 32 threads. Rayon splits the 58
batches into about 32 leaves of one or two, and a thread runs its leaf in order: the second wave starts only when a
first-wave batch ends. The line says so: `batch_start_skew_ms` is `batch_median_ms` + 2-3 ms on 80% of blocks
(skew 14, median batch 11; correlation 0.96 over 400 blocks), `par_exec_ms` is skew + median + 2, and
`batch_wait_ms` (the first batch's start after the hand-over plus the last end to the return) is 0. The 2-3 ms the
skew exceeds a batch is the first wave's own spread (thread hand-off, page faults at the start of a batch). None of
the other suspects is visible in it: the partition and the slots are before the batches' clock starts
(`gap_before_exec_ms` 2), the dispatch is one `par_iter` from one thread with nothing else to do, a sleeping pool
would show in `batch_wait_ms`, and first-touch shows inside each batch (`batch_max_ms` 17 against
`batch_cpu_max_ms` 9: the slowest batch spends half its wall off the CPU or faulting). The per-batch times were not
logged one by one; the fields below now give the first wave's length directly.

### 9.3 After the seal: the cycle is the seal plus the road to the child's start

At 60 and 70 ms pacing the cycle (seal to seal) is 71-73 ms median against `sealed_at_ms` 59-62. The difference is
the road from the parent's seal to the child's build start, 9.4 / 10.1 ms median (mean 11.6 / 12.7, p90 25 / 27):

| leg | seal -> validator's `chain started` | `chain started` -> the child's request at the layer | request -> build start |
| --- | --- | --- | --- |
| L3FS70 | 1.9 (p90 16.3) | 4.9 (p90 11.3) | 0.1 |
| L3FS60 | 2.5 (p90 17.0) | 4.8 (p90 12.4) | 0.1 |

The layer's own part is nothing (`frame_ms`, `decode_ms`, `find_ms`, `rename_ms`, `spawn_ms` all 0; `pre_ms` 0;
`build_ms` - `sealed_at_ms` = 3 ms of hops). The median road is two runtime hops and a loopback write each way.
The layer's main tokio runtime runs at 11.1 cores in window 1 (`threadcpu`, family `tokio-rt`, which includes its
blocking pool: the ingest's Ed25519 recovery at 2.6M tx/s) and the road shares it (`N42_ROAD_RUNTIME` off in
loop334): the chain header is written after the build's `spawn_blocking` handle wakes its task
(seal -> answer encode start 2.5 ms median, p90 16.8). The tail (a third of blocks over 5 ms) is the chain's
one-ahead rule: the validator defers the child's start until the proposal path has taken the parent's chained build,
which happens when the parent's view starts, i.e. at the grandparent's commit. In the examples the deferred start
follows the commit or the preamble by < 1 ms. Consensus is therefore on the cycle in its tail: seal -> proposal sent
24.3 / 19.7 ms median (p90 41 / 48; the tick, the answer's 6.4 MB of hashes encoded and written in 5.5 ms median,
p90 16, and the view's start), proposal -> commit 20.2 / 24.3 ms (p90 48 / 65; `R1_collect` 5-6 ms, p90 33-45,
`R2_collect` 5).

What is per key at E=1, and what it costs:

- Commit forkchoices: seven a block, one per key, over the authenticated JSON-RPC (`engine_forkchoiceUpdatedV3`
  12,761 calls by chain height 1,658: 7.7 a block; the engine counted 13,610 messages). Each costs ~28 us on the engine
  thread (`forkchoice_updated_last`), ~0.2 ms a block in all; the calls wait 12.9 ms mean in the engine's queue but are
  sent from a task (`N42_COMMIT_FCU_ASYNC=1`) and are on no build's road. Not coalesced: the gain is ~0.2 ms of an
  engine thread that is 31% busy, and it would mean intercepting reth's Engine API.
- Own-block imports: seven `OWN_BLOCK`/body requests, already one import (`N42_IMPORT_ONCE`, `once_reqs=7`,
  `once_served` the other six).
- Compact bodies: six, header only (15 KB), each decoded once in its own process.
- Votes: each key signs its own (separate processes, in parallel); the leader collects 5 of 7 per round. The R1 tail
  (p90 33-45 ms) is the slowest of the five, not a serial verification.

### 9.4 What was changed (all observable, one switch)

- `N42_BUILD_ONE_WAVE=1` (default off): at most one batch a pool thread, the groups cut at even shares of the block
  in candidate order (`batch_groups_one_wave`: 32 batches of 6,000-6,500 for this shape where the default makes 58),
  every batch spawned onto the pool at once rather than split from one thread. Same groups, same order inside each
  batch: the block's QMDB operations, gov5 receipts root and bloom, gas, grafted accounts and reverts, and the output
  shards' merged bundle are equal with it on and off (`the_one_wave_dispatch_equals_the_default_one`, three block
  shapes). Estimate: `par_exec_ms` 27 -> 20-22 (one batch of 6,500 at the measured ~3.1 us a transfer of wall plus the
  dispatch), `sealed_at_ms` -5 to -7; at 60 ms pacing a cycle of ~65-67 instead of 72 if the road of 9.3 does not take
  the gain (+7-10% on the 2.65M). Confirm: `batch_last_start_us` - `batch_first_start_us` under 2,000,
  `batch_dispatch_us` = `batch_last_start_us`, `par_exec_ms` median <= 22, and the cycle.
- Fields on `seal-first build phases` (always on): `batch_first_start_us`, `batch_last_start_us`,
  `batch_dispatch_us`, `batch_last_end_us`, `batches`, `batch_threads`, `one_wave`; `start_walk_ids_us`,
  `start_walk_check_us`, `start_walk_settle_us`, `start_walk_us`; the parent's road (`post_seal.rs`)
  `prev_seal_to_header_us`, `prev_seal_to_answer_us`, `prev_seal_to_request_us`, `prev_seal_to_entry_us`,
  `prev_seal_to_start_us`, `prev_seal_to_import_us` (the first import request by header for the parent: at E=1 the
  leader key's, right after its proposal); `sealed_unix_us` to join the validator's `proposal sent` and
  `block committed!` lines (quorum and commit are on the latter). `next_start_gap_ms` read 0 on every build since it
  was added (it read the last seal at the line's time, by then the block's own); it is now taken at the build's start.

Not changed, and why:

- The pull's per-transaction clones and the frame plan's serial decisions (start 6 + pull 5): the largest piece left
  before the execution. They cannot overlap the parent's tail as they are (the plan needs the parent's taken set), but
  the parent's plan is known at the parent's start, so the child's plan could be made speculatively right after it and
  only checked at the seal: ~10-15 ms off the chain. A tx-queue change with its own tests; not "clearly safe" here.
- The road of 9.3: `N42_ROAD_RUNTIME=1` already exists (the road on its own runtime and blocking pool, away from the
  ingest) and was off in loop334; it is the switch to try for the 4.9 ms hop and the 2.5 ms (p90 17) wake before the
  chain header. Answering the chained build without the 200,000 hashes at E=1 (every key reads the block from the same
  layer) would take ~5 ms off seal -> proposal; it changes what the validator receives and is left to whoever owns the
  compact path.
- Forkchoice coalescing (above): not worth intercepting reth's Engine API for ~0.2 ms of engine thread.

Leg to run: the L3FS60 configuration with `N42_BUILD_ONE_WAVE=1`, paired, against L3FS60 as it was; then the same
with `N42_ROAD_RUNTIME=1` added. Read `par_exec_ms`, `batch_*_us`, `prev_seal_to_*_us`, the cycle.

## 10. E=1: the feed ceiling (loop335-336 logs, offline)

Question: loop336 (`BREAKTHROUGH_DESIGN.md` 10.83) read delivery into the one layer at 2.5-2.6M/s on every leg and
called it the feed's cap. What between the replay files and the builder's queue saturates there? Sources: every leg's
`flood.log`, the layer's `ingest` lines (5 s), `seal-first build phases`, `frame build sealed` and `canonical blocks
pruned from the queue` lines, `threadcpu-loop336*.tsv`; code in `tx_flood.rs`, `n42-tx-ingest`, `n42-tx-queue`,
`bin/n42/src/main.rs`. Nothing was run.

**Short answer.** It is not one ceiling. (a) With 12 recovery slots (claim 1: P60, P60r, W, Wb, Wr, WR, WRr, and every
loop335 leg) the ingest sits in a *convoy* at its recovery semaphore: ~5,100 frames/s, 2.53-2.62M/s, on every 5 s
sample, whether the queue is full or empty. (b) With 24 slots (claim 2, the F legs) the convoy formed on one leg of nine
(RF, from its third sample on, then stayed); on the other eight the ingest followed the gate, the queue held at the
2.5M gate, delivery equalled consumption and read up to 2.88M/s in a 5 s sample (RFb). The F legs' ~2.6M is the chain,
not the feed. The short blocks are a rate problem, not an ordering problem.

### 10.1 The path, stage by stage (WR = feed-bound with 12 slots, RFb = feed-clean with 24)

| stage | where it runs, what it shares | measured | ceiling |
| --- | --- | --- | --- |
| replay read | 64 flood worker threads, one file each (64 files, 64.9 GB, 800,000 frames of 500, ~81 KB a frame), 8 MB `BufReader`; flood pinned to CPUs 112-127, 240-255 | reads are outside the send and wait clocks, and those two cover 98.8% of worker time (`wait` 5,690 worker-s in 90 s of 64 workers), so the reads take ~1%; 2.6M/s is ~420 MB/s across the 64 files | not binding |
| send | one blocking TCP connection per worker to the one ingest address (64 in all; `F7_FLOOD_PROCS` splits the 64, it does not add any), `TCP_NODELAY`, one `write_all` a frame; at most `--window` frames unanswered per worker (**`F7_FLOOD_WINDOW=6`** in the runner since loop333), one frame in flight per sender; process-wide token bucket `--rate` | `send` 6 s of 5,760 worker-s; the flood process uses 0.28 cores of 32; in flight 64 x 6 x 500 = 192,000 transactions, and by Little's law delivery = 192,000 / reply latency: 71-77 ms on every leg (2.49-2.72M) | window-bound only if the server answered faster than it does; see 10.2 |
| accept, read | layer's main tokio runtime (`TOKIO_WORKER_THREADS=16`): one task per connection, a 1 MB `BufReader`, the frame read field by field | not clocked (the clocks start after the read) | - |
| gate | same connection task: `gate_view` takes the queue's lanes `Mutex` (`gate_len` -> `lock_inner`, which also runs the lazy `settle`) on the tokio worker; shut frames wait on one `Notify` that a watcher polls every 2 ms | `gate_us_per_frame` 1.3-1.4 ms (WR, gate open: queue median 203k against a 1.67M gate); 1.3-7.4 ms on the F legs (gate shut, queue at 2.1-2.3M) | the gate ties delivery to consumption when it binds (F legs) |
| decode | same connection task, before the slot: 500 x `decode_2718_exact` | inside `acq_us_per_frame`; 0.46 ms a frame when there is no wait (F legs) | ~0.9 us a transaction on a runtime worker |
| recovery slot | node-wide `tokio::sync::Semaphore` of `N42_TX_INGEST_RECOVER_PARALLEL` permits, then `spawn_blocking` (nice 10) | **`acq_us_per_frame` 10.6-11.3 ms on every 12-slot leg** and on RF; 0.45-0.47 ms on the other 24-slot legs; `spawn_us` 10-15 us | see 10.2 |
| attested-frame check | blocking pool, holding the slot: attestation (one Ed25519 verify + frame root, ~150 us a frame), 0x50 sender from the public key, no per-transaction verification | `busy_us_per_tx` 0-1; slots 20-22% busy with 12 slots, 10-11% with 24: 2.5-2.6 slots busy, **0.49-0.51 ms a frame** | 12 slots x 2,000 frames/s = 24,000 frames/s (12M/s) of CPU; not binding |
| reply | connection task: `admit_tx.send` into the per-connection channel (8 frames), then the reply, whose `pending` takes the lanes `Mutex` again | `chan_us` 0 (12 slots) / 43-74 us (24); `reply_us_per_frame` 12.1-12.7 ms (12 slots), 2.8-8.1 ms (24) | - |
| admit / push | one admitter task per connection on the main runtime: awaits the recovery, frame-scan hook, `push_frame`: the lanes' `Arc`s, the by-hash index (sharded `RwLock`s), the inbox `Mutex` | `pool_us_per_tx` 0-1 | not binding |
| inbox -> lanes | drainer: every 5 ms a `spawn_blocking` `drain_now` that inserts the inbox into the per-sender `BTreeMap` lanes **under the lanes `Mutex`** | not logged | unknown; the next thing to instrument |
| selection | builder: frame plan by reference under the lanes `Mutex` (`start_frames_by_ref=400`), settle of the taken frames deferred to the next lock | `start_walk_us` ~0.9-4 ms | - |
| prune | one tokio task per canonical block (sync work on a runtime worker): `settle_own_block`, `remove_mined_batch` (lanes `Mutex`), `forget_hashes` (index shards) | `prune_ms` 49-65 median, p90 69-88 per 200k block (`remove_us` 17-24 ms, `forget_us` 13-37 ms, larger on the feed-bound legs); 41 ms at 163k, 71 ms at 300k (~0.25 us a transaction) | serial: ~3.1-4.1M/s at the median, ~2.7M at the p90 |

Per-thread CPU: `threadcpu4.py` sums threads by name, so the 16 runtime workers and the blocking pool are one
`tokio-rt` group (~5 cores averaged over the sample span) and no single thread can be named as the one at 100% of a
core; the data cannot show it. The flood is idle (0.28 cores), and the slots are 11-22% busy.

### 10.2 The binding stage: a convoy at the recovery semaphore

On a 12-slot leg every connection spends ~11 of its ~12.4 ms per frame waiting at `acquire` (decode excluded: 0.46 ms):
5,100 frames/s x 11 ms = **~56 of the 64 connections waiting at the semaphore at any moment, while only 2.5 of its 12
permits are doing work**. A permit cycles every 12 / 5,100 = 2.35 ms but works 0.49 ms of it; with 24 slots on RF it
cycles every 4.65 ms and works 0.51. Doubling the permits doubled the idle part of the hold and left the frame rate
where it was (5,060-5,170 frames/s on WR, WRr, P60r and RF alike). That is the signature of a permit that is granted to
a waiting task which is then not polled for 1.9-4.1 ms: the release happens on a blocking-pool thread, the wake goes
through the main runtime's injection queue, and the woken connection task then does its frame's reply, the next read,
the gate's lock and the 500-transaction decode before it waits again. The runtime it waits on also runs the prune (49-65
ms of synchronous work per block), 128 connection and admitter tasks, and gate reads that block a worker on the lanes
`Mutex` whenever the prune's removal (17-24 ms a block) or the drainer holds it (`BREAKTHROUGH_DESIGN.md` 10.71 already
caught a dozen callers at `gate_len` waiting 4.9 s behind one holder). Which of those makes the poll late is not
separable offline; what is measured is that the wait is scheduling, not CPU.

It is bistable. With 12 slots the semaphore's capacity at a ~2 ms poll delay (12 / 2.35 ms = 5,100/s) sits right on
the demand (2.6M/s = 5,200 frames/s), so a queue of waiters forms, the poll delay grows with it, and it never clears:
every 12-slot leg is in it on every sample, full queue (P60r's first 40 s, queue 1.7-2.5M) or empty. With 24 slots the
capacity is ~10,000/s and the waiters normally do not accumulate (acq 0.45 ms on 8 of 9 legs); RF fell in after 10 s
(acq 0.4 -> 8.1 -> 10.6 ms) and stayed, at the same 5,160 frames/s.

Weighed and set aside:

- **The workers' request-reply pacing.** Delivery is exactly 192,000 in flight / reply latency on every leg, but the
  reply latency is the server's: 6 frames x 12.4 ms of per-connection service on the convoy legs. A larger window puts
  more frames into the same convoy. Not the binding stage while the server is; see 10.4 for when it would be.
- **The gate throttling to consumption.** True of the eight clean 24-slot legs, and there "delivery equals
  consumption" is no ceiling at all. On the feed-bound legs the gate was open (`gate_us` 1.2-1.4 ms; WR's queue median
  203k against a 1.67M gate).
- **Too few connections / one reader.** 64 connections and 64 readers; each connection waits 89% of its time at the
  shared semaphore, so the per-connection serial loop is not the limit while the convoy is.
- **The flood's CPU, the files, the rate limiter, the pool size.** 0.28 cores, ~1% of worker time, 4-8M against
  2.6M delivered, gate never reached on the feed-bound legs.
- **Queue push contention.** `pool_us_per_tx` 0-1 and `chan_us` 0: the admitters keep up. The lanes `Mutex` matters
  through the gate reads and the runtime (above), not through the push.

### 10.3 Rate, not ordering

At the leader's short builds (`seal-first build phases` with txs < 95% of a block, after the first 50 builds; the
line is written at the build's end, so `queued` is what was left plus what arrived during the build):

| leg | short builds | txs (median) | queued after | usable | parked |
| --- | --- | --- | --- | --- | --- |
| WR | 267 of 1,204 | 146k | 74k | 71k | 0 |
| WRr | 483 of 1,272 | 142k | 82k | 83k | 0 |
| RF | 343 of 1,265 | 146k | 119k | 117k | 0 |
| P60r | 102 of 1,155 | 166k | 136k | 136k | 0 |
| W | 36 of 1,157 | 166k | 156k | 156k | 0 |

Every short build took every whole-usable frame there was (289 frames on WR and RF), `usable` equals `queued`, no lane
was parked, and the frame plan's `skipped` (1,610-1,673 a short build) is the same as on full builds (1,190-1,650 on
WR, RF, RFb, P60F): those are the index entries of the one to three chained builds ahead whose frames are taken but not
yet pruned, not senders waiting for an earlier frame. The flood keeps one frame per sender in flight and a sender's
frames in file order, so a lane has no hole to stall on (no `parked`, no gap warnings). The leftover 74-156k is what
arrived during the ~60 ms build at ~2.5M/s. **So at a short build's start the queue held less than a block: the
builder ran out of transactions, i.e. rate.**

### 10.4 What raises it, ranked

Variables first (no code):

1. **`N42_TX_INGEST_RECOVER_PARALLEL` at 48 or unset (unbounded).** With attested frames a frame holds a slot 0.5 ms
   of real work (2.6 slots busy at 2.6M/s), so the permits were never protecting CPU; they only create the queue the
   convoy lives in. Expected: no convoy on any leg, acq <= 0.5 ms on every sample, delivery following the gate
   (> 2.88M/s, the highest 5 s sample read; the ingest's own ceiling past that is unmeasured, estimated well above 3.5M
   from 0.5 ms of recovery + 0.46 ms of decode a frame). Confirming leg: RF's configuration (`N42_ROAD_RUNTIME=1`, 60 ms)
   with slots 64, run twice: both legs >= 97% full blocks in every window and `acq_us_per_frame` < 1,000 on every
   `ingest` line. 24 is the minimum from now on; 12 is the 2.55M ceiling of claim 1.
2. **Frames of 1,000-2,000 transactions** (a regenerated set): every cost on the convoy path is per frame (the wake,
   the two lock takes, the reply), so the frame-rate ceiling stays and the transaction ceiling scales (estimate ~5M at
   1,000 with 12 slots). It changes the block's shape (one sender per frame today, so 100-200 senders a 200k block
   instead of 400) unless the pregen writes multi-sender frames, which the queue's runs already support. Confirming
   leg: a 1,000-transaction set with 12 slots and nothing else changed should read ~5,100 frames/s = ~5.1M/s offered.
   Second priority, because (1) is cheaper and does not move the block.
3. `F7_FLOOD_WINDOW` 6 -> 12: no gain in either regime measured (convoy: the server is the bound; clean: the gate is).
   It only becomes the bound when the chain wants more than 192,000 / (6 x per-frame service): at 1 ms service that is
   32M/s. Harmless to raise; nothing to confirm.
4. Not levers: more flood CPUs (0.28 of 32 used), `F7_FLOOD_PROCS` (the 64 connections are split, not multiplied),
   `--conc` (the set has exactly 64 files; more connections need a new set and, in the convoy, only add waiters),
   `N42_INGEST_SHARD` (sender verification sharding; attested frames verify nothing per transaction), a second ingest
   listener at E=1 (same runtime, same semaphore), the pool size and the gate's 5/6 fraction (the gate decides how
   deep the queue is, not how fast it fills).

Code changes:

5. **The ingest on its own runtime** (as `N42_ROAD_RUNTIME` did for the vote road; the road runtime already cut the
   ingest's reply from 7.8 to 2.8-3.9 ms on the F legs by moving work off the main runtime) and the slot acquired on
   the blocking side, so no permit is ever parked on a task waiting for a main-runtime poll. Estimate: per-frame
   service ~1 ms, frame ceiling > 20,000/s (> 10M/s at 500). Leg: claim-1 configuration (12 slots) with the switch on;
   the convoy must not form.
6. **Gate and reply read atomics, not the lanes `Mutex`.** `gate_len` and the reply's `pending` take the lanes lock
   twice a frame on a runtime worker (~10,000 takes a second at 2.6M) and run the deferred `settle`; any 17-24 ms
   removal blocks every connection that reaches the gate and the worker it is on. `len`, `staged` and `parked_len`
   kept as atomics beside the lanes would make the gate lock-free. Leg: the convoy configuration, gate_us under 0.1 ms.
7. **The prune off the runtime and in parallel.** 49-65 ms median, 69-88 p90 per 200,000-transaction block, serial, on
   a runtime worker: ~0.25 us a transaction is a consumption-side cap of ~3.1-4.1M/s at the median and ~2.7M at the
   p90 (S300r: 71 ms for 300k). At 3.5M with 200k blocks the cycle is 57 ms and the p90 prune does not fit; a lagging
   prune keeps the gate shut and the feed then tracks the pruner. `forget_hashes` is per shard and `remove_mined` per
   sender: both split. Instrument `drain_now`'s hold first (inbox -> lanes is the third lanes-lock holder and is not
   logged), then shard the lanes by sender if the lock's duty (removal ~30% of the cycle today, plus the drain) is
   over ~50% at the target rate.
8. **An in-process replay source** (frames read from the set and pushed through `push_frame` and the same gate inside
   the layer, no TCP, no connection tasks): it would measure the chain, the queue, the gate and the prune at a feed
   that cannot be the limit, i.e. the consensus-plus-execution capacity at E=1. It would not measure the ingest (its
   socket reads, decode, attestation check, slots and runtime), which is exactly the stage that bound loop336, so a rate
   read that way is not a fed-chain result and must be labelled as such. Useful as the upper reference for (1)-(7),
   not as a record.

**3.5M TPS** needs ~3.5M/s delivered with the queue kept >= 2 blocks deep: 7,000 frames/s of 500, 17.5 blocks of
200,000 a second (57 ms cycle). Today's design cannot with 12 slots (5,100 frames/s). With slots unbounded the ingest's
CPU at 7,000 frames/s is ~3.2 runtime cores of decode and ~3.5 blocking cores of attestation checks, which the layer's
208 CPUs have, so the feed itself is reachable provided the convoy does not re-form (that is what (5) removes for good);
the first hard limit then is the per-block prune (7), which at the measured 0.25 us a transaction runs out around
3.1-4.1M/s and at its p90 below 3M. So: reachable with (1) and (7), probably (5) as insurance; not with the runner as
it stands.

## 11. The feed path, built (2026-10-05, code only, no fleet leg)

Section 10's code items 5-7 plus the drain's clock. Every switch is default off; the internal changes keep behaviour.
Gate: `cargo check --workspace`, clippy on the touched crates (no new warnings), tests of `n42-tx-queue`,
`n42-tx-ingest`, `n42-engine-types`, `n42-h2-el-rpc`, `n42-h2-node`, `n42 --lib`.

### 11.1 What runs where

| work | before | after |
| --- | --- | --- |
| ingest listener, connection read loops, gate, decode, reply, admitters, gate watcher, 5 s line | main runtime | `N42_INGEST_RUNTIME=1`: own runtime `n42-ingest` (`N42_INGEST_RUNTIME_WORKERS`, default 8, 1..=64) |
| recovery slot | node-wide `tokio::sync::Semaphore` awaited by the connection task, then `spawn_blocking` | same switch: the slot is taken on the blocking thread from a counting semaphore (`parking_lot` Mutex + Condvar); the ingest runtime's blocking pool is bounded at slots + 2 (512 unbounded), so the excess waits in tokio's own blocking queue and a finishing thread takes the next frame directly. No async task holds or awaits a permit. `acq_us_per_frame` is then the blocking-side wait |
| gate depth and the reply's `pending` | `gate_len` took the lanes Mutex (and ran the deferred settle) twice a frame | lock-free, always (11.2) |
| canonical prune | tokio task on the main runtime, three calls, frees under the lanes lock and the index shard locks | one pass, always (11.3); `N42_QUEUE_PRUNE_THREAD=1`: thread `n42-queue-prune`, the task only forwards (and marks `canonical_head::saw`); a wake takes every waiting notification (`coalesced`, `prune_wait_ms`) |
| freeing a pruned block | inside the prune, partly under locks | thread `n42-queue-free` (channel four blocks deep; a full channel frees inline) |

Still on the main runtime: engine API and RPC, the network, the payload builder's tasks, the 5 ms inbox drainer
(`N42_TX_QUEUE_DRAINER`, a `spawn_blocking` per tick), the pool's new-transaction feed into the queue, the
canonical-head watcher the gate's lag allowance reads, the pruner without its switch, and the vote road without
`N42_ROAD_RUNTIME`.

### 11.2 The gate's staleness

`len` and `parked_len` are packed into one `AtomicU64` stored as every guard of the lanes lock is released (still
under the lock, so the stores are ordered by it); `gate_len` = mirror + live `staged`, the old formula. With nobody
holding the lock the reading is exactly the locked one, so every gate decision is the same. While somebody holds it
the reading is the depth at the last release: **staleness is one hold** of the lanes lock (a build's take, a prune's
removal, a give-back become visible when their hold ends; the longest hold per 5 s is now on the `ingest` line). The
drain is the exception that is never undercounted: it adds its batch to the mirror before it subtracts it from
`staged` (counted twice for nanoseconds, the shut side). Tests: after each of 20 kinds of operation the two readings
and the decisions at limits around them agree; a reader racing a pusher and a drainer never reads fewer than were
pushed before it read (100,000 transactions).

### 11.3 The prune's cost

Unit test (`prune_tests`, release, a loaded host, system allocator): 400,000 queued in frames of 500 (one sender's
run each), a 200,000-transaction block = the oldest 400 frames, with the by-hash index.

| | follower (block in the lanes) | leader (a frame build took it) |
| --- | --- | --- |
| old three calls (settle, `remove_mined_batch`, `forget_hashes`), at 7ae94f038 | 69.0-70.6 ms | 69.9-76.3 ms |
| `prune_block` | 5.2-10.0 ms | 9.0-9.3 ms |
| of which fold / lanes hold / index | 0.24-0.44 / 0.9-2.1 / 3.0-7.3 ms | 0.37-0.47 / 2.9-4.9 / 2.7-3.6 ms |

What made the 70 ms: freeing 200,000 transactions (600,000 references) was 27-31 ms on its own, most of it under the
lanes lock and the 64 shard locks; one shard write lock per hash (200,000 takes); `remove_mined_batch`'s fold of
200,000 pairs under the lock; the taken list retained with a map lookup per transaction; a split of every block
sender's lane even when the build had already taken everything below the head; and `by_first.retain` over every
indexed frame. Now: the fold runs outside the lock and follows the block's runs (one map touch per sender run); a lane
whose head is above the mined nonce is not split; the taken list is split in one pass read once per run; each dead
frame removes its own `by_first` entry; the index is grouped by shard and visited one write lock a shard, on the
queue's 8-thread pool; and nothing is freed until every lock is released, and then on `n42-queue-free`. Freeing in
parallel on four threads was tried and measured 110-153 ms (cross-thread frees contend in the allocator), so the free
stays serial on its own thread: ~30 ms of one thread per 200k block, ~53% of a core at 17.5 blocks a second, off
every path. The lanes lock is held 1-5 ms per block instead of ~20.

`mark_invalid` and `forget_taken` still search the taken list from the back (`rposition`); they are per refusal, the
refused transaction is at or near the end, and neither is on the prune path, so they were left.

Invariants, tested: the one pass and the three calls leave identical queues (offer order, depth, gate, frames, index
over a probe of both halves); the other 200,000 are offered in nonce order; a re-arrival or an untake of the block is
never offered; two prunes racing each other, a pusher and a builder that walks, untakes and is superseded lose
nothing and break no sender's order; an own block held at a height comes back minus what another committed block at
that height carries, and is settled by its own block.

### 11.4 The drain's clock

New on every `ingest` line (one 5 s interval each, from `n42_tx_queue::take_lock_stats`): `lock_holds`,
`lock_duty_pct` (sum of holds over the interval), `lock_hold_max_us` and `lock_hold_max_at` (the caller's
`file:line`), `lock_wait_max_us`, `lock_wait_us`, `drains`, `drain_txs`, `drain_us_mean`, `drain_us_max`. The prune
line adds `fold_us`, `lock_us`, `free_us`, `frames_swept`, `coalesced`, `prune_wait_ms`; its `remove_us` is now the
hold alone.

Unit bench (`bench_drain`, release, quiet host): the feed's target, 3.5M/s, is 17,500 transactions per 5 ms
drainer tick (35 frames of 500 appended to lanes already queued); into a 2,000,000-deep queue each drain holds the
lanes lock **0.82-0.87 ms** (47-50 ns a transaction), the whole `drain_now` 0.95-1.07 ms. That is ~17% duty of the
lock at 3.5M/s from the drain, plus the prune's 1-5 ms a block (~5-9% at 17.5 blocks a second) and the builder's
frame plan: well under the ~50% at which section 10.4 (7) said the lanes should be sharded by sender, so the queue is
not sharded here. If the fleet's `drain_us_max` reads several milliseconds, the cheaper step first is batching: drain
on every tick into a per-sender pre-sorted batch outside the lock (group the inbox by sender, then one lane lookup and
one `BTreeMap::append` per run under it) before splitting the lanes into sender shards with a lock each.

### 11.5 Legs to run

Claim-1 configuration (12 slots, `N42_ROAD_RUNTIME=1`, 60 ms) with `N42_INGEST_RUNTIME=1 N42_QUEUE_PRUNE_THREAD=1`,
paired with the same configuration without the two switches (the gate mirror and the one-pass prune are in both).
Pass: no convoy (`acq_us_per_frame` under 1,000 on every `ingest` line with 12 slots), delivery above 2.88M/s when the
chain wants it, `prune_ms` under 15 at 200k, `lock_hold_max_us` and `drain_us_max` read. Then the same with
`N42_TX_INGEST_RECOVER_PARALLEL=64` to separate the runtime from the slot count.

## 12. The seal's start, the answer and the drain, built (2026-10-05, code only, no fleet leg)

Section 9's two left-out pieces (the child's plan and pull, the answer's hashes), the drain section 11.4 left as
"batch it if the fleet shows several milliseconds" (loop338 showed 25-35 ms), and a read of loop338's window-3 sag.
Four switches, all default off; with them off every path is today's (tests pin it). Gate: `cargo check
--workspace`, clippy on the touched crates (no new warnings), tests of `n42-tx-queue`, `n42-tx-ingest`,
`n42-engine-types`, `n42-h2-el-rpc`, `n42-h2-execution`, `n42-h2-node`, `n42 --lib`.

### 12.1 The child's plan prepared while the parent executes (`N42_PLAN_AHEAD=1`)

What is serial today: N's build start takes the lanes lock, drains, opens the build (the hand-off already forgot
N-1's take) and plans: the ids in arrival order, a parallel check of the ~420 frames the gas reaches, then the
decisions in arrival order and ~400 segments, under the lock (`start_walk` ~6 of `start` ~10 ms). N-1's plan is
known ~60 ms earlier, and the lanes N's plan is made on are exactly the lanes after N-1's take: the hand-off and
`hold_own_block` do not touch the lanes, and nothing else does on a quiet chain.

What was built (`crates/n42/tx-queue/src/lib.rs`): the thread that applies a frame plan's takes
(`n42-frame-settle`) then prepares the next plan (`prepare_next_plan`): the same `plan_frames` on the lanes as
the current take left them, its takes into a list of their own (`Inner::prepared`), never into the current
build's taken list (that list is what the hand-off forgets). The next frame build accepts it only if
(`prepared_verdict`, after draining the inbox):

| check | what it rules out | discard reason |
| --- | --- | --- |
| no build began since it was made (`builds` counter) | a second build on any parent, a build that planned in between | `other_build` |
| the hand-off forgot the whole previous take as mined by an own block, and `hold_own_block` named that block, which is the new parent | the previous build refused or abandoned, a handover, another block at the height, the tenure's first build on a peer's block | `not_on_its_parent` |
| nothing of the previous take is still out | a block shorter than its take (refusals, a cut) | `take_left` |
| its gas fits the new limit | a lower gas limit | `gas` |
| per sender it draws on: the lane's mined watermark is below its lowest nonce | a canonical prune that mined one of its frames (also discarded at once inside the prune) | `mined` |
| per sender: the lane holds nothing below its lowest nonce | a give-back (`untake`, a refusal, a superseded build), a re-sent or late arrival into a hole | `below` |
| the build takes frames | a walking build (`best_for_build`) gives it back first | `not_frames` |

A discarded plan goes back through the ordinary give-back, minus what the chain mined (freed after the lock),
and the build plans afresh. Why an accepted plan is a block the fresh path could have built: it was made by the
fresh algorithm on a queue state Q (the lanes after N-1's take); since then the lanes changed only by arrivals
(each sender's arrivals above its lanes' content: the `below` check catches any that is not) and nothing was
taken or given back (checks 1-3, 6); the parent carries every nonce N-1 took (check 2), so each prepared run
starts at its sender's next nonce; nothing in it is mined (check 5); its transactions were out of the lanes from
the moment it was made, so no other plan can hold them, and a discarded plan is given back before any fresh plan
is made, so no transaction is in two plans. Frames that arrived after it are behind it in arrival order: a full
prepared plan is the plan a fresh one makes now, and only the ordering of frames that were unusable at Q and
became usable later can differ (the fresh path has the same race between its plan and a late arrival).

Top-up: a prepared plan that ran out of frames (no cut last frame, at least 21,000 gas of room) is extended at
use by `plan_frames` over the room, on the lanes as it left them (`plan_ahead=2`, `plan_topup_txs`); a plan that
ends in a cut frame is not extended, because a cut frame in the middle of a body is not a run of frames. At
saturation (2.5M queued) every plan is full and the top-up never runs.

Cost and side effects: the preparation holds the lanes lock for a plan's length (~6 ms) while the parent executes,
so drains wait behind it (run it with 12.3); the prepared frames are out of the lanes, so the gate's depth reads a
block lower and the ingest admits ~200k more (RSS +~1 GB). Fields: `plan_ahead`, `plan_age_us`, `plan_prep_us`,
`plan_topup_txs`, `plan_discard` on `seal-first build phases`; `plan_discards` (reason:count) on `ingest`.
Tests (`ahead_tests.rs`): a chain of six own blocks on prepared plans equals the chain on fresh plans block for
block at four gas limits; late frames top a short plan up into the fresh one; a refused build, a handover, an
untake, a re-sent arrival below the plan and a lower gas limit each discard it by name and the chain keeps nonce
order, takes nothing twice and loses nothing; a prune of one of its frames discards it inside the prune; a
walking build gets it back; a preparation racing an untake and a prune (20 rounds) loses nothing and offers
nothing mined.

### 12.2 The pull by frame (`N42_PULL_BY_FRAMES=1`)

The pull was the `n42-builder-puller` thread calling `next()` 200,000 times (one cold `Arc` clone each, ~25 ns)
in batches of 1,024 over a channel. `QueueBest::take_frame_segments` now hands the plan's frames over whole, and
`frame_blocks::select` clones each frame's slice on the build pool into the build's candidate vector; the build
starts its parallel step with it, starts no puller, and keeps the iterator on its own thread for refusals and
give-backs (same candidates, same order). Only when the parallel step with the puller is on and senders are not
claims to check (those go through `claimed_build`'s batches). Fields `pull_bulk_txs`, `pull_bulk_us` (inside
`start_best_ms`; `par_pull_ms` then reads ~0).

What stops a block from taking frames truly by reference: the build's candidates are a `Vec<Arc<ValidPoolTransaction>>`
that the prep pass, the partition and `batch_groups`, the slots, `BodyAhead`, `body_matches_pull`,
`receipts_from_slots` and the lookahead give-back all index by position and own; a two-level (frame, offset) view
would mean rewriting those consumers in `parallel_transfer.rs`, and the give-back of an unbuilt candidate needs an
owned `Arc`. The queue's own taken list already holds the lanes' `Arc`s by move, not by clone. One clone per
transaction remains, now parallel (~0.3-1 ms for 200k on 32 threads, estimate); not worth the refactor before a
leg says otherwise.

Expected effect of 12.1 + 12.2 (estimate, no leg): `start` 10 -> ~3-4 ms (lock, drain, verdict ~0.3 ms, the
hand-off wait 2 ms unchanged), `pull` 5 -> ~1 ms: `sealed_at` 62-65 -> ~53-56 ms median. Confirm: `plan_ahead=1`
on >= 95% of full builds, `plan_discard` empty, `start_walk_us` < 1,000, `pull_bulk_us` < 1,500, `sealed_at` and the
cycle at 55 ms pacing. But see 12.4: persistence is already at the cycle.

### 12.3 The answer without the hash list (`N42_ANSWER_LAYOUT_ONLY=1`)

Every consumer of `CompactAnswer.tx_hashes` / `BuiltBlock.tx_hashes` on the proposer side with frame blocks on:
`elided_compact_body` (h2-node `service.rs`, from `publish_elided_body`) is the only reader, and its frame branch
reads only the layout; `publish_body` runs on whole (non-elided) answers, which keep their hashes; the elided own
body, `OWN_BODY` serving, the fill (`NEED_TXNS`), `import_own` / `fill_elided` and the own import by header go by
the sealed header, the transaction count and the body fetched by it; no tx-gossip, pool removal, log or metric
reads the hashes. So nothing needs them when the layout covers the block. With the switch (implies
`N42_TAKE_COMPACT`, effective only with `N42_FRAME_BLOCKS=1`) the proposer adds a last tail tag to its build-on-own
request; an execution layer that knows it answers a block whose layout is non-empty and sums to the transaction
count with an empty hash list and never builds the hash vector (6.4 MB at 200,000). An older layer stops at the tag
and sends the hashes; a block that is not frame-aligned gets them too; the decoder accepts an empty list only beside
a covering layout; without frame blocks a short hash list is refused rather than published. The published compact
body is byte for byte the same (`elided_compact_body_with`, tested with an empty list against the full one).
Fields: `answer_layout_only` on the layer's `built ahead on the sealed own block` and the validator's `proposal
sent`; the gain reads from `answer_bytes` and the encode/read/decode stamps. Expected (estimate): seal -> proposal
-5 ms (the 5.5 ms median encode+write of 9.3), off the seal itself; on the cycle only where the proposal road binds.

### 12.4 The drain in bounded holds (`N42_TX_QUEUE_DRAIN_CHUNK=<n>`)

loop338: ~70,000 transactions a drain, 4-5 ms mean, 17-26 ms max, the longest hold of every window `drain_now`
at 25-35 ms (B, Q); with the ingest runtime 17-19k a drain and 5-7 ms max. With the switch the drainer takes the
inbox and the frame inbox without the lanes lock (the batch counted in a new `in_hand` the gate reads between
`staged` and the mirror, so it is never in none of them), hands it to `Inner::pending_drain` under the lock (a
`Vec` becomes the deque in O(1)), and inserts `n` at a time, releasing the lock between chunks. The insert is the
one-hold drain's (`insert_valid`, transaction by transaction in inbox order: duplicates, the mined watermark,
parks and the arrival order decided exactly as before); the batch's frames are indexed in the hold that inserts
its last transaction, so no plan sees a frame before its transactions. Any other drain (a build's start, a prune,
the vote road's `take_frames`) finishes the remainder first, so the lanes see the inbox's order whoever moves it;
those holds are unbounded and counted (`drain_finished`). A lock holder that does not drain (an untake, a
give-back) sees a prefix of the batch queued, which is what two consecutive drains would show; lanes are keyed by
nonce, so per-sender order does not depend on it. The depth mirror counts the remainder.

Bench (`drain_tests::bench_drain_chunked`, release, 17,500 a 5 ms tick into a 2,000,000-deep queue, warm caches):
one hold 0.96-1.1 ms; chunks of 16,384 / 8,192 / 4,096 ~0.56 / 0.37 / 0.21 ms a hold (mean per hold), the whole
drain unchanged (0.97 ms). At the fleet's ~70 ns a transaction (cold), 8,192 is ~0.6 ms a hold and 16,384 ~1.2 ms:
both under the 2 ms bound. Lock duty is unchanged (the same transactions are inserted); what changes is the longest
hold, which is what a selection waits behind. Fields on `ingest`: `drain_chunks`, `drain_chunk_max_txs`,
`drain_finished`. Tests (`drain_tests.rs`): for chunks 1 to 100,000 the chunked drain leaves the one-hold drain's
queue (depth, frames in order, offer order); every hold moves at most its chunk; a build during a pending
remainder plans exactly as after a one-hold drain; the gate never reads fewer than were pushed under racing
chunked drains (75,000 transactions). Not built: grouping the batch by sender outside the lock (one lane look-up a
run): the chunk alone gives the bound, and grouping changes only the hash look-ups.

### 12.5 Window 3 and persistence (loop338 B, Bb, IQ, IQb, offline)

Windows of 30 s from the first full block; `seal-first build phases` and `own block handed` from the layer's log,
in-memory blocks and RSS from the 2 s `mem.log` samples, persistence from the end-of-run metrics (cumulative only,
so not per window). Ad-hoc parsers, not kept.

The sag is a tail, not a slower cycle. Mean cycle w1 / w2 / w3: B 66.8 / 66.2 / 68.7, Bb 67.7 / 67.0 / 69.2, IQ
67.8 / 68.0 / 68.9, IQb 66.2 / 66.3 / 69.6 ms; the median is flat (B 65.9 / 64.8 / 65.5) and the p90 rises (B
82 / 81 / 87, IQb 83 / 83 / 91). Cycles over 100 ms: B 10 / 9 / 23, IQb 4 / 7 / 15; their excess over 66 ms grows
by 0.7-1.2 s per 30 s in window 3, which is the whole 2-4%. What grows across the leg:

| quantity | w1 | w2 | w3 |
| --- | --- | --- | --- |
| in-memory blocks, median / p90 (B) | 14 / 17 | 15 / 18 | 15 / 29 (max 31; IQ max 34, IQb 36) |
| persisted lag (latest - persisted) at +0 / +30 / +60 / +90 s (B) | 6 | 15 / 13 | 30 |
| RSS median, G (B; others alike) | 23.9 | 31.2 | 36.8 (end 44.1) |
| `sealed_at` median / p90 (B) | 63 / 69 | 63 / 69 | 64 / 73 |
| `roots_ms` median / p90 (B) | 39 / 47 | 41 / 50 | 42 / 54 |
| own-import hand-off median / p90 (B) | 30 / 57 | 33 / 62 | 43 / 66 (IQb 29 -> 31 / 39 -> 55) |

Not tracking it: `par_exec` (29 / 28 / 28), `state_wait` (0), the root's undo/append faults (B higher in w2 than
w3, IQ rising: inconsistent). New in window 3 only, on every leg: forest-lock waits behind
`sync_entries_if_file`; `jemalloc_bg_thd` CPU 2.1 / 2.7 / 5.2 s a window (B). The best single correlate of the
5 s block rate is `sealed_at` (r -0.6 to -0.9); in-memory blocks and RSS correlate too but are collinear with time,
so the cause is not separated by these logs.

Persistence (B, 1,883 blocks in 399 batches of 3-15, median 5, ~1,384 of them full): `save_blocks_total` 89.8 s =
49.6 ms a block over all blocks and up to ~65 ms a full block; the batch median is 0.328 s = ~66 ms a block, the
batches run back to back, and the persistence thread's own CPU is 2-2.7 s a window: it is busy at ~100% of the
cycle and falls behind by ~1.5% (lag 6 -> 30 blocks over 90 s). Per full block: the static-file scope ~50 ms, of
which `sf_transactions` ~50 ms is the critical path (its siblings in the scope `sf_receipts` ~20, `sf_account_changesets`
~17, `sf_senders` ~10 run beside it), then `qmdb_persisted` ~12 ms serial after the scope, `plain_reverts` ~2.5 ms
before it; the commits, `write_state`, the trie and hashed state are each under 1 ms. The history index is already
off in these legs (`N42_ACCOUNT_HISTORY=off`; `update_history_indices` 0.3 ms in all), so the floor with it off is
today's ~65 ms a 200k block. **Persistence is already the bound at a 66 ms cycle**: a seal 8-10 ms faster (12.1-12.2)
makes the in-memory chain grow ~15% of the blocks produced until the engine's backpressure (1,024 blocks) or the
memory stops it. To keep up at a 50 ms cycle `sf_transactions` must drop under ~35 ms (sharded or pre-encoded
transaction segments, or written off the persistence thread as the body is already encoded for the wire); at 40 ms
`qmdb_persisted` must also overlap the scope instead of following it (~20 + 2.5 + overlap < 40).

Next round: run 12.1-12.4 with a per-window persistence reading (the `save_blocks_*` sums scraped every 10 s, or a
log line per batch), and take `sf_transactions` apart before any pacing below 60 ms.

### 12.6 Legs to run

Base: loop338's B (three leader layers, fields at seal, `N42_ROAD_RUNTIME=1`, 24 permits, 200k, 60 ms; it already
has `N42_FRAME_BLOCKS=1`, `N42_PARALLEL_BUILD=1` and a non-zero `N42_BUILDER_PULLER`, which 12.2 needs). Pairs:
B against B + `N42_TX_QUEUE_DRAIN_CHUNK=8192 N42_PLAN_AHEAD=1 N42_PULL_BY_FRAMES=1 N42_ANSWER_LAYOUT_ONLY=1`; then
the same at 55 ms pacing; one leg with `N42_TX_QUEUE_DRAIN_CHUNK=8192` alone to read `lock_hold_max_us`. Read
`plan_ahead` / `plan_discard`, `start_walk_us`, `pull_bulk_us`, `sealed_at`, `answer_bytes`, `drain_chunk_max_txs`,
`lock_hold_max_us`, the in-memory blocks and the persistence lag per window.

## 13. E=1: what bounds the execution and the QMDB root (2026-10-05, microbenchmark, no fleet leg)

The question from 10.87: at 200,000 transfers a block the seal's execution (`par_exec` 29-30 ms on 32 threads) and the
parent's QMDB root (`roots_ms` 38-40, `root_apply_ms` 21) did not get faster with more threads before, so what bounds
them. Measured on a quiet box (load < 3, no fleet, no claim) with `crates/n42/engine-types/tests/e1_bound_bench.rs`,
fleet `MALLOC_CONF`, release build; perf counters from `perf stat --control` enabled around the measured rounds only.

### 13.1 The bench

`e1_exec_bound`: one block of the replay set's shape -- 200,000 pooled 0x50 transfers, 400 sender runs of 500,
recipients drawn from 2,000,000 (190,700 distinct) -- through `execute_for_build` with the leader's partition and
two-wave dispatch (58 batches of 3,500 on 32 threads; `E1_WAVE=one` for `N42_BUILD_ONE_WAVE`), the builder's own
`convert` (`tx_env` of the pooled transaction), and each batch's bundle handed to the output shards in live index
mode (16 shards). The parent's state is the leader's read stack: three kept layers of frozen shards from three
executed blocks (`N42_LEADER_LAYERS=3`; 26% of the reads end there), ten in-memory engine blocks of ~190,000
accounts behind their `overlay_filter` filters (63% of the rest end there), then a QMDB read view over an entry file of
2,012,501 accounts (`E1_JOURNALS` journals ahead of the readers). Not modelled: the provider's `dyn` chain and
`StateProviderDatabase`, the latest provider's version lookup, and the process around it (persistence, ingest, the
RPC, 40 G of RSS). `e1_root_bound`: `sorted_operations_from_accounts` and `QmdbNodeState::compute_operations` in
entry-file mode over the same 2,012,501 accounts after 30 blocks of churn, 190,700-account blocks. `e1_overlap`:
the execution with the parent's root running beside it on the global pool, and with 10 more threads verifying
Ed25519 signatures (the ingest).

### 13.2 The execution: per-thread CPU work, latency-bound; it scales with threads

| build threads | exec ms (two waves) | batch CPU sum ms | on CPU | cycles / transfer | IPC | cache misses / transfer | DRAM fills / transfer | dTLB misses / transfer | faults a block | vcsw / ivcsw a block |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 243.4 | 240 | 100% | 5,030 | 0.97 | 35.6 | 14.4 | 0.62 | 85 | 0 / 2 |
| 8 | 34.0 | 245 | 99% | 5,470 | 0.93 | 40.0 | 11.1 | 0.67 | 103 | 29 / 0 |
| 16 | 18.7 | 245 | 95% | 5,630 | 0.92 | 40.8 | 10.4 | 0.61 | 97 | 105 / 0 |
| 32 | 11.5 | 266 | 95% | 6,370 | 0.83 | 43.7 | 10.6 | 0.74 | 95 | 345 / 0 |
| 48 | 8.9 | 269 | 92% | 6,790 | 0.80 | 46.3 | 10.8 | 0.97 | 73 | 652 / 0 |
| 64 | 8.8 | 291 | 88% | 7,840 | 0.72 | 53.7 | 11.5 | 1.83 | 82 | 760 / 0 |

(One wave reads the same at every count: 11.7 ms at 32. The counters are the process's over the measured rounds,
divided by the transfers.) The execution is CPU work on each thread and scales: 21x on 32 threads, 27x on 48; the
CPU a transfer rises 11% from 1 to 32 threads and IPC falls from 0.97 to 0.83. It is not memory bandwidth (10.6 DRAM
fills a transfer is ~11 GB/s at 32 threads, on a 12-channel host), not a lock (no involuntary switches; the voluntary
ones are pool threads parking after the last batch, the batches' wall is 95% CPU), not allocation (95 minor faults a
block), and not serial (one thread runs it in 243 ms, 32 in 11.5). At 64 it stops scaling because two waves of
4 ms batches are the floor. Where the CPU goes at 32 threads (perf record, symbols): the batch state's map
(`batch_state::loaded` 19.6%, `BatchState::basic` 6.8%, the map's own probes 5.5%) -- the first write of each
account's 264-byte slot into a 2.2 MB map, cold memory recycled from blocks freed three blocks earlier; the batch
loop with the transfer and the conversion 12.9%; kernel 7.1%; the output shards' live index 4.2%; the read stack
itself (shards `get`, the filters and bundles, the view's index and blake3 key) ~9%. A read alone costs 345-412 ns
on one thread and 1.2-1.8x that with 8-64 threads reading (shared-cache effects, not a lock).

Beside the parent's root and the ingest: alone 12.1 ms, beside the root 12.2, beside the root and 10 Ed25519
threads 12.5 (the root 24.8 alone, 27.3-27.7 beside the execution): co-running work on this host costs the
execution 1-3%.

**The fleet's execution is 2.5x the bench's, and the bench says where not to look for the difference.** loop340
(P3b, PEW, BEST, window 2 medians): `par_exec` 30 ms on 32 threads, the slowest batch 20-21 ms wall and 11-12 ms of
CPU for 3,500 transfers (3.3 us a transfer against 1.3-1.5 here), so the fleet both does ~2.3x the CPU a transfer and
spends ~45% of the slowest batch off the CPU. Neither the root beside it nor the ingest's load reproduces either
(above). Two things the bench does reproduce when switched on:

- **Journal walks in the QMDB view.** A view read whose reader stands behind the view's head (a persistence batch's
  readers, `hold_journals_from`) or meets a block being indexed (`pending`) binary-searches every journal in
  between: ~17 dependent probes of a ~9 MB vector each. Per journal walked, 200-300 ns more a view read; with 2 and
  4 journals the execution goes 11.4 -> 13.6 -> 16.1 ms and its CPU 263 -> 329 -> 400 ms. Whether the fleet's reads
  walk journals, and how many, was not logged; it is now (13.4).
- **The shared `Bytecode::default()` `Arc`.** revm 43's `AccountInfo::default()` carries `Some(Bytecode::default())`,
  a clone of one process-wide `Arc`: every clone from any thread is an atomic on the same line. Filling the batch
  maps with such infos takes 1,583 ns an entry on 32 threads against 101 without (119 against 89 on one thread). The
  provider's accounts carry no code (`From<Account>` sets `None`), so steady-state reads never touch it; a new
  recipient does (`commit_transfer`'s `unwrap_or_default()`), so blocks that create accounts pay it -- on the replay
  set, the first ~30 blocks of window 1. Not changed: an account created with `code: None` puts no empty-code entry
  into the bundle's `contracts`, which changes what is persisted.

What is left for the fleet's 2.3x CPU and 45% off-CPU is outside the bench: the provider's per-read path (the `dyn`
chain, `StateProviderDatabase`, the latest provider's version lookup), the pooled transactions' cold memory (the
fetch read 407-457 ns a transfer on the fleet against 110 on a bench, 10.26), and whatever takes the batch threads
off the CPU. The batch counters added here (13.4) name the last on the next leg.

### 13.3 The root: serial sections; more threads stop helping past 16

| global pool threads | ops ms (cores) | `compute_operations` ms (cores) | CPU ms | IPC | DRAM fills a block | sort | leaves | retire | writes | index | rehash + root | delta | the apply's call |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 8 | 6.6 (6.0) | 24.9 (4.0) | 100 | 1.24 | 3.0M | 0.1 | 7.4 | 1.6 | 7.5 | 2.7 | 1.3 | 1.3 | 22.1 |
| 16 | 4.9 (9.7) | 20.4 (5.7) | 117 | 1.13 | 3.4M | 0.1 | 4.6 | 1.6 | 7.4 | 1.6 | 1.0 | 1.3 | 17.6 |
| 32 | 4.0 (16) | 18.2 (8.6) | 156 | 0.96 | 3.3M | 0.2 | 3.0 | 1.8 | 7.3 | 1.1 | 1.0 | 1.0 | 15.7 |
| 64 | 4.2 (30) | 17.7 (15) | 270 | 0.64 | 3.6M | 0.1 | 2.5 | 1.8 | 7.4 | 0.9 | 0.8 | 1.4 | 14.9 |

(ms; the phase columns from the new `RootSplit` fields; delta after the change below, 2.4 ms before it.) From 16 to
64 threads the compute falls 2.7 ms while its CPU more than doubles (rayon's idle spinning: IPC 1.13 -> 0.64, DRAM
traffic flat). The pieces that scale (leaves and lookups, index inserts, rehash) are 7.2 ms at 16 threads; the
rest is serial on the root's thread and does not move: the structural writes 7.3-7.5 (entry appends, twig leaves,
undo keys, one after another), the retirement 1.6-1.8, the delta's sort 2.4, ~2 ms inside the apply between its
phases (`root_apply_total_us` minus the phases), ~2.5 ms around it (the lock, the counters, the records), and the
operations' concat and sort ~2 of their 4-5 ms. **The root is bound by its serial sections (~15 of 20 ms at 16
threads); the fleet's 39 ms is the same shape slower (apply 21 against 15 here).**

### 13.4 What was changed

| commit | change | switch | measured on the bench | expected on the fleet | confirm by |
| --- | --- | --- | --- | --- | --- |
| 0188370e9 | batch counters on the seal-first line: `batch_wall_sum_us`, `batch_cpu_sum_us`, `batch_minflt`, `batch_vcsw`, `batch_ivcsw` (`ThreadMark`, `getrusage(RUSAGE_THREAD)` per batch); root phases `root_{sort,leaves,retire,writes,index,rehash,note,delta}_us` | always (observability) | - | names the fleet's off-CPU half: faults (`minflt` in the thousands), blocking (`vcsw` >> 58), preemption (`ivcsw` > 0) | the fields on every line |
| 03efb811c | `e1_bound_bench` | test only | - | - | - |
| a640452d8 | the delta's retired-slot sort on the pool; `root_apply_total_us` | always (same order, same delta) | delta 2.4 -> 1.0-1.6 ms | `roots_ms` -1 ms | `root_delta_us` ~1,000 |
| 74e685e00 | the apply's three structural writes side by side on the pool | `N42_QMDB_PARALLEL_WRITES=1` | writes 7.3 -> 5.1 ms, compute 20.4 -> 18.4 ms | `roots_ms` -2 ms, `seal_to_fields` -2 ms; only the tail and pacing under 60 ms feel it | `root_writes_us` ~5,000, roots identical (`fields_mismatches` 0, `fleet7-verify`) |
| 8e7b6705d | an address filter on each read-view journal; `view_journal_reads`, `view_journal_searches`, `view_journal_skips` on the line | `N42_VIEW_JOURNAL_FILTER=1` (the counters always) | 4 journals: exec 16.1 -> 12.4 ms; 2: 13.6 -> 11.9 | 0 if the fleet's reads walk no journals; up to the 2.3x CPU gap's share that is journals (~0.25 us a journal a view read; at 1-3 journals on a quarter of the reads, 2-8 ms of `par_exec`) | `view_journal_searches` / `view_journal_reads` before (the depth) and after (~0.1 + hits), `par_exec_ms` and `batch_cpu_sum_us` |

Equality: `parallel_writes_equal_the_serial_ones` (twig-core, with and without `rayon`: root, undo record, cursor,
snapshot and entry file, eight blocks in memory and in the file), `journal_filters_change_no_answer` (qmdb-reth: every
key at every depth through views with and without filters), the existing forest and node-state suites for the delta.
Block contents, receipts, roots and everything validators exchange are untouched by construction: the switches change
only how the root's writes are scheduled and how a view read finds a journal entry.

Not done, and why: a smaller batch map (the 264-byte `BundleAccount` slot is what the output shards and the graft
consume; a compact map means rebuilding the bundle, which was 490 ns a transfer before `BatchState` kept the map,
loop283) and a tighter pre-size (the lines written are per entry, not per bucket); one wave (equal on the bench);
`code: None` for new recipients (changes the bundle's `contracts`); a cheaper `push_batch` (the longest arm of the
parallel writes at ~5 ms: a per-record populate check and an atomic, small each); NUMA placement (one node; the
L3 domains are 16 CCDs of 8 cores, and the bench's far-cache fill counter read 0).

### 13.5 Legs to run

Base PEW (10.87). Pairs: PEW / PEWb against PEW + `N42_VIEW_JOURNAL_FILTER=1 N42_QMDB_PARALLEL_WRITES=1` twice; one
leg with `N42_PARALLEL_BUILD_THREADS=48` added (27x scaling at 48 on the bench against 21x at 32; 64 was slower on an
earlier fleet). Read, per window: `batch_cpu_sum_us` / `batch_wall_sum_us` and `batch_minflt`, `batch_vcsw`,
`batch_ivcsw` (what the off-CPU half is), `view_journal_reads` / `view_journal_searches` / `view_journal_skips` (whether
the reads walk journals), `par_exec_ms`, `root_writes_us`, `root_delta_us`, `roots_ms`, `seal_to_fields_us`,
`sealed_at` p90, and the cycle. Correctness: `fields_mismatches` 0, `invalid_blocks` 0, `fleet7-verify` clean.

## 14. E=1: what the batches wait on (2026-10-05, code and loop341 logs, no fleet leg)

The question from 10.88: the build's batches are on the CPU 64-70% of their wall, with `batch_vcsw` 248-261 a block
(~4.3 a batch, ~0.9 ms each), no preemption and few faults; 48 threads wait more (372-380, on-CPU 0.48). The bench
(13.2) is 95% on the CPU. What do the batches block on?

### 14.1 Where a batch can block, from the code

A batch (`execute_for_build_opts`, `run_batch`, on the `n42-build-*` rayon pool) does, in order: open its view of
the parent (`open()` -> `ParentStateOpener`), execute its transfers reading through the read stack (kept layers,
the in-memory blocks behind their filters, the QMDB read view over the entry file), take its bundle, and hand it to
the output shards (`OutputShards::add`, inside the batch's span). No rayon `join`/`scope` runs inside a batch, and
no channel or condvar is waited on outside the open. The points that can sleep:

| rank | point | what it waits on | who holds it during a build | what loop341 says |
| --- | --- | --- | --- | --- |
| 1 | the live index's shard locks in the hand-over (`OutputShards::enter_live`, `N42_OUTPUT_INDEX_LIVE=1`, 16 shards): a rotated `try_lock` pass, then a blocking `Mutex::lock` on every shard that was busy | another batch entering its addresses into that shard | the other batches' hand-overs, nobody else; a batch ending holds each of the 16 locks in turn | **this is it.** `shard_append_ms` (pool time inside `add`) is 251 / 253 ms a block on P / Pb against 227 / 227 ms off the CPU, r = +0.99 over 1,453 blocks; T48 541 against 520, r = +1.00. On every leg `append - off` is 24-29 ms (the hand-over's own CPU), i.e. **the batches' off-CPU time is the hand-over's waiting, all of it.** The J legs wait more (255-262 ms) because their batches are faster (`batch_cpu_max_ms` 10 against 12) and reach the hand-over together: the journal filter's gain went into the queue, which is why it moved nothing (10.88). With 48 threads, 10.8 ms a thread a block against 7.1 |
| 2 | the QMDB read view's reader slot (`read_at`'s slot `RwLock`) and the offset index's shard `RwLock` (`SharedOffsetIndex::read`) | a publish (all 128 slot write locks, twice an `advance`), an `apply_sorted` run (one shard's write lock for its run of ~750 keys) | the persistence thread's `advance` (`N42_PERSIST_QMDB_IN_SCOPE=1`), once a persisted block | nothing correlates with the off-CPU time (`roots_ms`, `root_*`, journal reads: r -0.31..+0.16), and after the hand-over nothing is left to explain. Bounded small; counted now |
| 3 | a major fault on the entry file (`EntryFileView`: a shared read-only mapping, `MADV_RANDOM`; a page not in the page cache is read from disk) or on a database page | the disk | - | `batch_minflt` ~1,100 a block, r ~0 with the off-CPU time; major faults were not logged (`root_majflt` 0 on the root's side). Counted now |
| 4 | the batch's open of the parent (`open()`: the opener's waits for an ancestor -- `engine_landed`'s `Condvar`, `wait_for_state` -- the overlay filter cache's `Mutex`, the provider's version lookup) | the parent's output or import; the filter cache's lock | the engine, the other 57 opens | the builder's own open waits 0.3 ms (`state_wait_us` median 295); the batches' opens were not logged. Counted now |
| - | jemalloc (`thp:always`, background thread): arena locks, a huge page zeroed or compacted | other threads of the arena; the kernel | - | faults are minor and uncorrelated; per-thread arenas |
| - | `mmap_lock` under a fault | an `mmap`/`munmap` elsewhere in the process | - | per-VMA locks on this kernel; faults uncorrelated |
| - | `batches` / `contracts` mutexes in `add`, the `CountedDb` passthrough, `convert` | one push a batch; transfers carry no code | - | - |

Why ~0.9 ms a wait when a shard's insert for one batch is ~20-40 us: the batches of a wave end within a few ms of
each other (`batch_txs_max` 3,500, the same shape), so ~29 hand-overs arrive at once and queue on the same 16
locks; each blocked `lock` is a futex sleep and a wake-up, and the queue behind a shard is the sum of the holders
ahead plus each one's wake-up latency. 48 threads make the queues longer, which is T48's 380 switches and 0.48.

### 14.2 What was changed

| commit | change | switch |
| --- | --- | --- |
| 09fdadb38 | `twig-core` `thread_read_waits()`: offset-index reads that found their shard held, count and ns (a failed `try_read` alone is timed) | always (observability) |
| 3e353d195 | `qmdb-reth` `ViewLockWaits`: reader-slot and index-shard waits per thread | always (observability) |
| 103a07da8 | `OutputShards`: `LiveLockCounts` per thread (blocked shard locks, the time blocked, the time held, shards left to the freeze); `N42_LIVE_INDEX_DEFER=1`: a shard still busy after the rotated pass and one more try is left to the freeze, which enters that batch's addresses there (same rules) before the conflicts' sums | `N42_LIVE_INDEX_DEFER=1`, default off |
| 4724f2926 | `ThreadMark` / `BatchSpan` carry major faults, the view's waits, the hand-over's counts and the batch's open time; the seal-first line prints `live_index_defer`, `batch_majflt`, `batch_view_slot_waits`, `batch_view_slot_wait_us`, `batch_view_index_waits`, `batch_view_index_wait_us`, `batch_live_lock_waits`, `batch_live_lock_wait_us`, `batch_live_lock_hold_us`, `batch_live_deferred`, `batch_open_sum_us`, `batch_open_max_us` | always (observability) |
| 337a6c65a | `scripts/fleet7-offcpu.sh` (+ `fleet7-offcpu-fold.py`): the build pool's off-CPU profile, without root | - |

Equality: `a_live_index_with_shards_left_to_the_freeze_equals_the_direct_graft` (engine-types `tests/output_shards.rs`:
every other shard of every batch left to the freeze, in order and reversed, and busy shards left by 16 concurrent
hand-overs, at 1, 16 and 64 shards: accounts, contracts, reverts and sizes equal the direct graft's). The order the
batches enter a shard was already arbitrary under the live index (the order they ended), and every rule there is
indifferent to it; the freeze enters left shards after the live ones, in batch-number order. The counters change no
answer: `a_read_behind_a_held_shard_is_counted_as_a_wait_and_answers_the_same` (twig-core),
`a_read_behind_a_publish_is_counted_and_answers_the_same` (qmdb-reth).

### 14.3 The off-CPU profile (`scripts/fleet7-offcpu.sh`)

`perf_event_paranoid` is 1 on this host and `/sys/kernel/tracing` is root's, so the sched tracepoints, `perf sched`
and `perf record --off-cpu` need root. Without it: the `context-switches` software event sampled at every
switch-out with the call stack, and `--switch-events` (a timestamped OUT, `preempt` when involuntary, and IN, per
thread); a sample's off-CPU time is its OUT to the thread's next IN. Kernel frames stay unnamed (`kptr_restrict` 1);
`/proc/<tid>/wchan`, readable by the owner, is sampled beside it at ~1 kHz for the kernel side (`futex_do_wait` for
a lock, `folio_wait_bit*`/`filemap_fault` for a file read). Recipe for the runner:

```bash
CARGO_TARGET_DIR=/data/n42-build/<dir> cargo build --profile profiling -p n42 -p n42-h2-node --bins --examples
# the leg with F7_BIN=<that dir>/profiling; in window 1 (after the flood's funding and the first window's start):
scripts/fleet7-offcpu.sh --dry-run --node 0 --secs 10 <dir>/offcpu-<tag>     # pid, build-pool tids, commands
scripts/fleet7-offcpu.sh --node 0 --secs 10 [--delay <s>] <dir>/offcpu-<tag>
#   = perf record -e context-switches -c 1 --switch-events --call-graph dwarf,16384 -t <n42-build-* tids> \
#       -o <prefix>.data -- sleep 10      (+ the wchan sampler)
# after the leg, with the box returned:
scripts/fleet7-offcpu.sh --report <dir>/offcpu-<tag>
#   = perf script -i <prefix>.data --no-inline --show-switch-events -F comm,tid,time,event,ip,sym
#       | fleet7-offcpu-fold.py <prefix>   -> time off the CPU by blocking site, <prefix>.offcpu.folded
```

With root the same answer with kernel names: `perf record -e sched:sched_switch -e sched:sched_wakeup -g -t <tids>
-- sleep 10`, then `perf sched timehist -V --state`. The recording copies 16 KB of stack at each of ~4,000
switches a second: a profiled window is not a measured one.

### 14.4 What the next leg must read

Base P (10.88). Pair P / Pb against P + `N42_LIVE_INDEX_DEFER=1` twice (D / Db); one T48 + defer leg. Per window:
- `batch_live_lock_waits` / `batch_live_lock_wait_us` on P (expected ~250 and ~220,000: the waits named) and on D
  (expected ~0, with `batch_live_deferred` the shards moved and `batch_live_lock_hold_us` ~25,000 either way);
- `batch_wall_sum_us - batch_cpu_sum_us` and `batch_vcsw` (expected to fall from ~227 ms / ~255 to tens), the
  on-CPU share, `batch_max_ms` (20 -> ~12), `par_exec_ms` (30 -> low 20s if the second wave starts sooner),
  `shard_append_ms` (251 -> ~27);
- the cost moved: `shard_fold_ms` / the "output shards folded" line's `index_build_us` and `task_max_us`
  (the left shards entered at the freeze), `seal_to_fields_us`, `roots_ms`;
- the residual candidates: `batch_view_slot_waits`, `batch_view_index_waits` (and their us), `batch_majflt`,
  `batch_open_sum_us` / `batch_open_max_us` -- if the off-CPU time does not fall with the defer, these name what
  is left; then the off-CPU profile of 14.3 on one D leg;
- `sealed_at` median / p90, the cycle, the rate; correctness `fields_mismatches` 0, `invalid_blocks` 0,
  `fleet7-verify` clean.

## 15. E=1: the shard merge, the freeze and the parent's root chain (2026-10-06, code and loop342 logs, no fleet leg)

The question from 10.89: with `N42_LIVE_INDEX_DEFER=1` the execution fell 30 -> 23 ms (17 at 48 threads) and the
seal did not move; `shard_merge_ms` read 52-54 ms "inside `par_ms`". Offline read of loop342 P, D and D48 (layer
node 0, full blocks, the first 20 dropped; medians, p10 / p90 where given) against the code.

### 15.1 `shard_merge_ms` is not on the seal's path; the freeze is

`shard_merge_ms` is the wall of `FrozenShards::merged` plus `append_reverts` on the `n42-shard-merge` thread
(`payload.rs`, the shard branch behind the seal). That thread is spawned **after the block's fields are published**
(seal + 53 ms), runs on the background cores, and every input is in hand when it starts (the shards frozen, the
residual taken): it waits for nothing. It is work: ~190,000 `BundleAccount`s cloned into one pre-reserved map, the
kept reverts copied and sorted, then appended, on one thread (~280 ns an account). It ends at seal + ~106 ms and
`StateReady` is filed at seal + ~108 (`state_ready_ms` 96 from the finish's start at seal + 12).

Who reads the merged bundle on the leader at E=1, and when:

| consumer | what it reads | when it needs it |
| --- | --- | --- |
| the child's build (`opener_on_sealed_parent`, `wait_for_state`) | the parent as `Sharded` (residual over the frozen shards), filed at seal + ~12 | its first open, seal + ~20; it never sees the bundle (`StateReady` comes 90 ms later) |
| the kept layers (`leader_layers`, depth 3) | the layer the child filed: the frozen shards, not the bundle | every later build's open |
| the own-block import (`built_executions::take` -> engine `InsertExecutedBlock`) | the `Complete` execution: merged bundle, receipts, hashed state | at the commit's import; the engine is 2-3 blocks behind and the deepest layer's anchor is N-4 |
| persistence | the engine's executed block | after the import |
| `N42_FIELDS_AT_SEAL=verify` | the merged bundle's operations | behind `Complete`; off on the fleet |

**None of them is before the seal**, and none is on the child's seal: the merge already runs after the seal and after
the root, the way the fields-at-seal change moved the root. Shortening it would make `Complete` (and the engine's
import) earlier, nothing else; the follower's two-halves split (`N42_SHARDS_MERGE_OFF_PATH`, ~10 ms there) is not
ported to the leader for that reason. 10.89 read the number as a piece of `par_ms`; it is not.

What **is** on the seal's path is the freeze (`OutputShards::freeze`, `index_ms`), between the batches' end and the
seal in the `N42_SEAL_AT_EXEC` path, although the seal reads only the body, the transactions root and the parent's
fields:

| leg | start | prep | gap | `par_run` (exec) | **`index_ms` (freeze)** | commit | seal (`sealed_ms`) | `sealed_at` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P | 4 | 4 | 3 | 33 (31) | **4** | 2 | 6 | 61 |
| D | 4 | 4 | 3 | 26 (23) | **13** (p10 10, p90 18) | 2 | 6 | 61 |
| D48 | 5 | 3 | 3 | 19 (17) | **14** | 2 | 8 | 60 |

**D moved 9 ms of the shards' index from the batches into the freeze, on the seal's path; the execution's 7 ms gain
was spent there**, which is why the seal did not move (14.1 assumed the freeze was behind the seal; it was not). The
freeze's wall is its slowest task's CPU (`task_max_us` = `task_cpu_max_us`, no faults, no preemption): 12.8 ms on D
against 4.2 on P for the same ~7,700 conflicts; regressing the slowest task on the conflicts gives P 0.47 us a
conflict + 0.4 ms, D 0.67 us + **8.0 ms**, D48 0.82 us + 7.7 ms: the deferred entries cost a fixed ~8 ms in the
slowest task that their count (35-56 shard entries a block, ~220 addresses each) does not explain. The new fields
`pending_max` / `pending_us_max` / `drops_max` on the "output shards folded" line say which.

### 15.2 The parent's root chain into the child's fields (D, us from the parent's seal)

| stamp | median | piece |
| --- | --- | --- |
| `seal_to_finish_us` | 11,791 | the graft scope behind the seal (receipts from the slots), the fee credit, the diagnosis, the executor's finish |
| `seal_to_bundle_us` | 11,967 | merge transitions, bundle taken |
| `seal_to_view_us` | 12,726 | shards filed (`shards_ready`), overlaps and the view |
| `seal_to_rename_us` | 14,227 | the grandparent renamed under its seal (early path, 0 wait) |
| `seal_to_root_start_us` | 14,334 | the root job starts |
| `seal_to_root_end_us` | 52,170 | **the root job, 37.9 ms**: the operations' encode, join and sort over the view (~12 ms: the job less the compute; now `root_ops_*_us`), two sortedness passes (~0.5-1), the lock (0), the apply (`root_apply_total_us` 23.9: leaves 6.8, writes 6.9, index 3.0, rehash + root 2.0, retire with the undo lists 1.6, sort 0.1, gaps ~3.5), the delta 1.05, the note 0.1 |
| `seal_to_fields_us` | 53,290 | receipts joined, the tree filed, the fields published |

The child reads the parent's fields inside `seal_block` (after its transactions root) and the header, block and hook
follow (~4-5 ms). So **the cycle cannot be shorter than `seal_to_fields` + ~5 = 58-59 ms** whatever the seal does:
that is D48P55's 59.0 ms cycle at 55 ms pacing, and D48's `parent_fields_ms` median of 1 (the child already waits
for the parent's root on half its builds once its own seal is 60). The seal (61) and the root chain (53 + 5) are now
within 2-3 ms of each other; shortening only one moves the cycle by at most that.

For a 50 ms cycle: the child's seal at <= 50 ms (15.3 brings it to ~48) **and** `seal_to_fields` <= ~45 ms, i.e. the
root job <= ~29 ms if the 12 ms before it and the 1 ms after it stay, or the 12 ms before it shortened as well. The
operations encoded beside the finish (15.3) take ~8-10 of the 37.9; the rest has to come from the apply (24 ms, of
which leaves and writes are 13.7) or from the 12 ms finish before the root starts.

### 15.3 What was changed

| commit | change | switch | expected (estimate) | confirm by |
| --- | --- | --- | --- | --- |
| 71943f85e | the leader's merge timed (`seal_to_merge_start_us`, `seal_to_merge_end_us`, `seal_to_state_ready_us`, `seal_to_complete_us`, `merge_state_us`, `merge_reverts_us`, `merge_append_us`, `merge_tail_us`, `merge_threads`, `merge_accounts`, `merge_reverts`); the root job split (`root_ops_us`, `root_ops_encode_us`, `root_ops_concat_us`, `root_ops_sort_us`, `root_compute_us`); the live freeze's slowest task (`pending_max`, `pending_us_max`, `drops_max`) | always | - | merge start ~= `seal_to_fields_us`, end ~= start + 53 ms, 1 thread; `root_ops_us` + `root_compute_us` ~= the root job |
| fd48c1abe | the freeze on its own thread from the batches' end, beside the commit and the seal, joined where the graft first reads the shards (beside the receipts job); a block that will not seal early joins it before the withdrawals' check; `freeze_late`, `seal_to_frozen_us`, `freeze_join_wait_us` | `N42_FREEZE_AFTER_SEAL=1` (needs `N42_SEAL_AT_EXEC=1`) | `sealed_at` 61 -> ~48-50 on D, ~46 on D48 (the 13-14 ms freeze off the path; the commit and seal share the pool with it); `seal_to_fields` +0-3 ms (the freeze ends ~5 ms after the seal, beside the receipts) | `index_ms` ~13 with `freeze_late=true`, `seal_to_frozen_us` <= ~6,000, `freeze_join_wait_us` small, `sealed_at`, `seal_to_view_us` |
| 9dd1da23d, 3bcf476bd | the shards' QMDB leaf operations encoded and sorted on a thread of their own from the graft's end (`qmdb-reth` `operations_ahead`), the root job encoding only the residual's accounts and merging them in (`OpsAhead::finish`, `QmdbOps::merge_sorted`: one pass, the replaced accounts' keys dropped); `root_ops_ahead`, `seal_to_ops_ahead_us`, `root_ops_ahead_wait_us`, `root_ops_finish_us` | `N42_ROOT_OPS_AHEAD=1` | the root job 38 -> ~29-31 ms, `seal_to_fields` 53 -> ~45-47 | `root_ops_us` (with: the wait + the finish, ~1-4 ms), `seal_to_ops_ahead_us` < `seal_to_root_start_us`, `seal_to_fields_us`, `fields_mismatches` 0 |
| 2ff77c20b | `QmdbOps` keeps a sorted flag (set by `sort` and a merge of sorted sets, cleared by any push): the forest's and the apply's sortedness checks stop scanning the block's keys | always (same operations, same order) | root -0.5 to -1 ms | `root_apply_gap_us`, the root job |
| b20ae3740 | `root_undo_us`, `root_apply_gap_us` on the line | always | - | what the apply's ~3.5 ms between phases is |

Estimates, not measurements. With both switches on D (or D48): the seal ~48 (46), the root chain ~45-47 + 5, so the
cycle at a 60 ms tick stays the tick (no rate change expected there), at 55 ms ~55-56 (from 59), and **at 50 ms
~51-53**: then the root chain binds again (F + 5), with the seal 2-4 ms under it.

Equality (all switches change scheduling only; block contents, roots, bundles and what validators exchange are the
same by construction, and the tests say so on built blocks of the shapes the shard tests use):
`a_freeze_on_its_own_thread_equals_the_inline_freeze` (engine-types `tests/output_shards.rs`: every fold mode, live
deferral none / forced / busy-concurrent, 1, 16 and 64 shards, the pool busy and a job beside the join: shards,
merged bundle, view, QMDB operations with and without Prague, hashed post-state, and the staged fallback against the
direct graft), `the_operations_encoded_ahead_equal_the_views` (the same shards and residual: ahead + finish equals
`sorted_operations_from_accounts` of the view and of the merged bundle), `operations_ahead_finished_equal_the_whole_views`
(qmdb-reth: storage on both sides of an overlap, a deletion, the system caller in the shards, the residual or
neither, Prague on and off), `merge_sorted_equals_join_filter_sort` (twig-core). Gate: `cargo check --workspace`;
clippy on engine-types, qmdb-reth and twig-core adds no warning; tests of `n42-engine-types` (229 + 13 + benches
ignored), `n42-twig-core` (66, and `--features rayon`), `n42-qmdb-reth` (56), `n42-h2-el-rpc`, `n42 --lib` (134) pass.

Not done, and why: the leader merge's two-halves split (off the seal and the root chain; it would only bring
`Complete` forward); the freeze's ~8 ms fixed cost under the defer (not explained by the code's entry counts; the new
fields name it first, and with `N42_FREEZE_AFTER_SEAL` it overlaps the seal anyway); the apply's leaves and writes
(13.7 ms, section 13: the next pieces of the root chain once the operations are ahead); the 12 ms between the seal
and the root's start (the receipts job and the executor's finish), which the 50 ms cycle needs next.

### 15.4 What the next leg must read

Base D (or D48). Pairs: D / Db against D + `N42_FREEZE_AFTER_SEAL=1 N42_ROOT_OPS_AHEAD=1` twice, at 60 ms and then at
55 ms; if the 55 ms cycle median reads <= 56, one 50 ms leg. Per window:
- the seal: `sealed_at` median / p90 (61 -> ~48), `index_ms` with `freeze_late`, `seal_to_frozen_us`,
  `freeze_join_wait_us`, `par_commit_ms`, `sealed_ms`; `parent_fields_ms` (it becomes the child's wait if the root
  chain does not shrink with the seal);
- the root chain: `seal_to_view_us` (should not grow by more than ~3 ms), `seal_to_ops_ahead_us` against
  `seal_to_root_start_us`, `root_ops_us`, `root_ops_ahead_wait_us`, `root_ops_finish_us`, `root_compute_us`,
  `root_apply_total_us`, `root_apply_gap_us`, `seal_to_fields_us` (53 -> ~45-47);
- on the base legs too (always on): `root_ops_encode_us` / `root_ops_concat_us` / `root_ops_sort_us` (what the
  ~12 ms of operations is), the merge's `seal_to_merge_start_us` / `seal_to_merge_end_us` / `merge_*` (confirming it
  waits for nothing and is one thread's work), and on the folded line `pending_max` / `pending_us_max` / `drops_max`
  (what the freeze's slowest task is);
- the cycle median / p90, the rate; correctness `fields_mismatches` 0 (with `N42_FIELDS_AT_SEAL=verify` on one leg:
  it compares the published fields with the operations of the merged bundle, which is exactly what
  `N42_ROOT_OPS_AHEAD` changes), `invalid_blocks` 0, `fleet7-verify` clean.

## 16. E=1: the seal's timeline, why the freeze's work came back, and the way to a 40 ms seal (2026-10-07, code and loop343 logs, no fleet leg)

The question from 10.90: with `N42_FREEZE_AFTER_SEAL=1 N42_ROOT_OPS_AHEAD=1` (F2) the child's fields came 6 ms sooner and
`sealed_at` stayed at 60-61 ms, the freeze's 14 ms reappearing as `par_commit` 2 -> 16 and `par_fold` 6 -> 21. Read offline:
the layer's `el.log` of loop343 D and F2 (node 0, full blocks (`txs=200000`), first 20 dropped: 1,405 and 1,415 blocks),
paired block by block with the "output shards folded" line (`fold_us` against `index_ms`: r 0.997 at offset 0), the
thread-CPU samples of D, F2, F2P55 and FZ (every 5 s by thread-name group), and the code. Medians, p90 where given. The
seal's own `sealed_at` is read from the build's start; every `*_ms` field is floored to a whole millisecond, so the phases
below sum to 59-60 where `sealed_at` reads 61 (seven floors, mean 0.5 each, and the median of a sum is not the sum of
medians).

### 16.1 The timeline

`par_commit` and `par_fold` are **not additive**: `fold_at` is taken at the commit's start, `par_commit_ms` ends at the
commit's end, and `par_fold_ms` runs to the end of the graft behind the seal minus the seal's own time. So `par_fold` =
`par_commit` + the behind-seal graft (D 6 = 2 + 4; F2 21 = 16 + 5), and only the commit part is on the seal's path. The
behind-seal part did not move. The path, with each phase's start offset from the build's start (cumulative per block,
median / p90) and duration (median / p90):

| phase (field) | D start | D duration | F2 start | F2 duration | runs on | waits for | must follow the previous phase? |
| --- | --- | --- | --- | --- | --- | --- | --- |
| start (`par_start_ms`; of it `start_handoff_ms` 3 / 9, select 0) | 0 | 4 / 9 | 0 | 4 / 11 | the `build-on-own` blocking thread; the hand-off on the queue's own 8-thread pool; the lanes lock | `before_pull`: the parent's queue hand-off (`forget_mined_parallel`: a parallel compare of the 200,000 taken (sender, nonce) with the sealed block) | a real dependency only on "the parent's take is forgotten"; the compare proves what the builder knew by construction (`body_matches_pull`) |
| prep (`par_prep_ms`; pull 0) | 4 | 4 / 6 | 4 | 4 / 6 | the build thread blocked in `build_pool().install`: `BodyAhead::make_keyed` on 32 workers (clones 200k transactions, their senders, tips, the (sender, recipient) keys) | the plan's candidates only | code order. Nothing in it reads the parent's state; the tips need the child's base fee, which only the (behind-seal) fee credit uses |
| gap (`gap_before_exec_ms` = run_at - prep_done + `batches_start_us`; `par_part_ms` 1) | 8 | 3 / 6 | 8-9 | 3 / 6 | the build thread: `partition_by_sender` + `batch_groups` (1 ms), `before_batches` = `open_deferred_state` (`state_wait_us` 236-568, p90 3.5-4.3 ms; waits on the parent's output in 28-38% of blocks), then `slots` (200,000 `OnceLock<BuiltTransfer>` ~470 B = ~94 MB) allocated and touched on the pool | the parent's `StateReady` shards (state open, real); the rest nothing | partition and slots: code order; the state open: real |
| exec (`par_exec_ms`; `batch_last_end_us` 21.9 ms; 58 batches of 500-3,500, `batch_median_ms` 9, `batch_max_ms` 14) | 12 | 23 / 28 (F2 29) | 12 | 23 / 29 | the 32 `n42-build-*` workers (`install` + `par_iter` over batches: two waves, `batch_last_start_us` 11.3 ms) | the parent's view; the live index's shard locks (none waited on D/F2: the defer) | real |
| freeze (`index_ms`; one slow shard task: `task_max_us` 13.5-13.8 ms = `task_cpu_max_us`, 16 shards, `pending_us_max` 9.3-9.6 ms, ~8,200 conflicts, `drops_max` ~16,500) | 35 | 14 / 20, **inline, before the commit** | 35 | 14 / 19, on `n42-freeze`, its 16 tasks on the build pool; **beside the commit** | D: the build thread + the pool; F2: `n42-freeze` + the pool | the batches' end | **no.** The seal reads the body, the transactions root and the parent's fields, none of which the freeze produces; first read of the shards is the graft behind the seal |
| commit (`par_commit_ms`; of it `commit_refs_ms`) | 50 | 2 / 2 (refs 1) | 37 | **16 / 21 (refs 15)** | the build thread in `install`: `slot_refs_and_gas` over 200,000 slots on the pool; the body parts come from `BodyAhead` (`commit_body_ms` 0) | all batches done; **in F2 it ends 0.1-1.5 ms after the freeze's fold ends (16.2)** | **no for the seal:** the seal needs only the count, the gas and "nothing skipped", which every batch knows |
| `tx_root_ms` | 52 | 2 / 3 | 53 | 2 / 3 | the build thread, serial: a 200,000-hash vector (6.4 MB) from the body, then the frame tree over 400 frames (`seal_frames_indexed` 400, `hashed` 0) | the body | no: the hashes exist at ingest; a prep-time pass would hold them |
| `parent_fields_ms` | 54 | 0 / 8 | 55 | 0 / 6 | the build thread blocked in `parent_executed_fields_or_built` | the parent's published fields (`seal_to_fields_us` 46.9 ms in F2 + the parent's seal) | real: the header carries the parent's execution |
| remember (`seal_remember_ms`) | 56 | 3 / 5 | 56 | 3 / 5 | the build thread: `built_executions::remember_pending` -> `put` -> `make_room`: **`store.remove(at)` drops the evicted `Complete` entry (its bundle, receipts and hashed state) inline, under the store's mutex** | nothing | no: it is a free |
| header, `SealedBlock`, `RecoveredBlock`, hook (rest of `sealed_ms` 6) | 59 | 0 / 1 | 59 | 0 / 1 | the build thread (`cons.seal`, header hash, the hook that answers the validator) | the fields | real |
| **`sealed_at_ms`** | | **61 (p90 75)** | | **61 (p90 76)** | | | |

Means (D / F2): start 4.8 / 5.6, prep 4.2 / 4.4, run (gap + exec) 26.9 / 28.2, freeze inline 14.4 / 0, commit 1.9 / 15.2,
`sealed_ms` 8.3 / 7.5; they sum to 60.5 / 60.9 against a mean `sealed_at` of 63.0 / 63.0 (the floors), so **there is no
hidden phase**: `par_run` = gap + exec to within a millisecond in every block of both legs.

What the tail is made of (blocks with `sealed_at` >= 72: 209 of 1,405 on D, 219 of 1,415 on F2). Share of the variance
of `sealed_at` by phase, D / F2: run (gap + exec) 0.54 / 0.65, `sealed_ms` 0.36 / 0.14, commit 0 / 0.11, start 0.03 /
0.10, freeze inline 0.06 / 0. Inside `sealed_ms`, 83-86% of its variance is `parent_fields_ms` (p90 6-8 ms: the root
chain is already the seal's tail). In F2 the slow blocks are half long gap (`state_wait` p90 40 ms, and `grandparent` as
the wait's cause in 61 of 219 against 11 of 209 on D) and half long exec (p90 52 ms, `batch_last_end_us` p90 51 ms).

### 16.2 Why the freeze's work came back in the commit

Fact 1 (the arithmetic). From the batches' end to the seal's start: D = freeze 14 + commit 2 = 16 ms; F2 = commit 16 ms
with the freeze beside it. The freeze moved to another thread and the seal did not wait for it, yet the commit ends
when the freeze ends: **`commit_refs_ms` - fold wall = +0.8 ms median (p10 +0.1, p90 +1.5), refs >= the fold's whole
milliseconds in 1,284 of 1,395 blocks (92%)**; by freeze duration (`index_ms` bucket -> refs median): 0-10 -> 10, 10-13 ->
13, 13-16 -> 15, 16-20 -> 18, >20 -> 22 ms; D's refs is 1 ms in every bucket. F2P55 reads the same (refs - fold +0.75,
p90 +1.3). The pass is 1 ms of work when the pool is quiet (D) and finishes ~0.8 ms after the freeze when it is not.

Fact 2 (the freeze is unharmed). Its wall is 14.3 ms on D (alone) and on F2 (beside the commit); `task_max_us` 13.8 / 13.5
and `task_cpu_max_us` equal it, `task_migrated` 0, `task_nivcsw_max` 0 on both. So nothing slows the freeze and something
holds the commit: an asymmetry that a bandwidth or SMT explanation cannot make (those slow both sides). Its work is one
shard task that is 13.5 ms on a 16-task fold (the others end earlier: the build pool burns 12.3 -> 12.5 cores on average,
+0.25 = ~15 core-ms a block, about the freeze's own CPU).

Excluded, with the evidence:

| candidate | verdict |
| --- | --- |
| the freeze thread takes a core of the 32 | no. `n42-freeze` blocks in `install`; its tasks run on pool workers. The layer is `taskset` on 208 logical CPUs (`f7_pin`: 7 x 32 - `F7_VAL_CPUS` 16, one layer, physical cores 0-103 with their siblings 128-231) and the whole layer burns 33.5 (D) / 34.5 (F2) / 34.9 (F2P55) cores of them; the pool is 32 threads, `core_layout="off"` |
| SMT siblings of busy workers | cannot be read from these logs (the thread samples are 5 s sums by name; `n42-freeze` is alive in 2 of 40 samples; no CPU-of-thread trace). At ~34 of 208 CPUs busy it cannot explain a gate that ends with the freeze |
| a lock both take | none found. The output shards' live locks are taken by the batches only (0 waits, 0 us on D and F2); `freeze` owns the batches' vector (`into_inner`), the freeze thread's `Mutex<Option<OutputShards>>` is taken once at its start; `SHARD_POOL` is off (`N42_SHARD_RECYCLE`); the `built_executions` store is first touched at the seal (offset 56), after the commit; the queue's lanes are not read in the commit |
| memory bandwidth | no: both sides would slow, and the freeze does not (Fact 2); the refs pass is ~25 MB of lines for 200k slots |
| the pool is saturated | no: 12.5 of 32 cores on average over the leg, and the freeze holds ~16 tasks of which one runs 13 ms |

The mechanism that fits all of it, **untested**: both jobs run on the one 32-worker `build_pool`, and `slot_refs_and_gas`
is `par_iter().filter_map().unzip()` under `install`, a tree of rayon joins. A worker that waits in a join for a stolen
child does not sleep: it takes any job it can find (`find_work`: its deque, then the others', then the injector) and
cannot return to the join until that job returns. With the freeze's 13.5 ms shard task in the pool, some worker of the
refs tree takes it while waiting, and the refs `install` cannot finish before that task does: **a latency-critical
1 ms pass shares a pool with a 13 ms task, and finishes behind it.** It predicts exactly the data: the commit ends just
after the freeze's slowest task, the freeze is untouched, CPUs are idle, no lock. The same mechanism would let the parent's
behind-seal pool jobs (graft, receipts, frees, ops-ahead's pool use) hold the child's exec tail (`batch_last_end_us` p90
51 ms in the slow blocks) and prep. **The cheap test:** put the freeze's `install` on a pool of its own (16 threads out
of the 174 idle logical CPUs): if the story holds, `commit_refs_ms` falls to 1-2 in F2 and `index_ms` stays 14. The fix
that does not depend on the story is 16.5 item 1: the seal never runs a pool pass.

### 16.3 What each phase does per block, and what can start earlier

Counts (F2, medians): 200,000 transfers in 400 frames; 58 batches (500-3,500 transfers, 32 workers: 26 workers take two
batches, six take one); ~192,000 accounts (`merge_accounts`), as many reverts; ~8,200 index conflicts, ~16,500 `drops`,
36 deferred shard entries (`batch_live_deferred`), 16 shards; `batch_cpu_sum_us` 537 ms (on-CPU share 1.0, so 16.8 ms is
the 32-worker floor of the execution against 23 measured: 73% efficiency); `batch_minflt` 701 (p90 5,130).

| phase | work | avoidable, or can start before the previous phase ends |
| --- | --- | --- |
| start 4 | lanes lock, drain, plan verdict (~0.3 ms), **hand-off wait 3 ms: a 200,000-element compare of the take with the sealed block on the queue pool, after the seal** | the compare is a proof of what `body_matches_pull` + `skipped.is_empty()` already say; do it as an O(1) take at the seal, or run the compare on the pool while the parent executes (the take is fixed once the plan is applied). 3 of the 4 ms |
| prep 4 | 200,000 transaction clones (~22 MB), senders (4 MB), tips (3.2 MB), keys (8 MB): one pass on 32 workers | none of it depends on the parent: it is a function of the plan. `prepare_next_plan` (12.1) already holds the plan 55 ms ahead (`plan_age_us` 55,253) and builds it in 6.6 ms: build the `BodyAhead` there, keep it with the plan under the same discard rules (`other_build`, `not_on_its_parent`, `take_left`, `gas`, `mined`, `below`, `not_frames`). Tips: at the fee credit, behind the seal |
| gap 3 | partition by sender (~160k small vectors, 1 ms), the state open (0.2-0.6, p90 4), the 94 MB slot array allocated and touched (estimate 1-1.5, not timed alone) | partition and `batch_groups` are functions of the keys: with the plan. The slot array: two arenas used alternately (the previous block's slots are freed on the pool behind its seal) or allocated in the plan-ahead; first touch costs the same, off the path |
| exec 23 | 537 CPU-ms over 32 workers | balance: 58 equal batches on 32 workers is 1.8 waves (`batch_last_start_us` 11.3 ms, last end 21.9). 64, 96 or 128 batches, largest first, give a makespan within one small batch of 16.8 ms (estimate 18-19). 48 threads read 16 (F2T48) but also moved `par_start` 4 -> 12 and the p99 (10.90): unexplained, so not the lever |
| freeze 14 | one 13.5 ms shard task: ~36 deferred entries entered (9.3 ms) then ~16,500 conflict sums | off the seal (done); its slowest task is split by shard imbalance: split the heavy shard's entries into two tasks (estimate 14 -> ~8 ms; it matters for `Complete` and the graft's start, not the seal) |
| commit 2 (16) | 200,000 `OnceLock::get` + gas sum into a `Vec<&BuiltTransfer>` | the seal needs `executed_count` (= candidates when nothing was skipped) and `executed_gas`; both are known per batch (`txs` and each transfer's `gas_used` are in the batch's hand). Sum them from the batches' results (58 integers); build the refs vector behind the seal beside the receipts job, which already builds it again serially (`receipts_job`: `slots.iter().filter_map(OnceLock::get).collect()`) |
| `tx_root` 2 | 200,000 hashes copied into a vector, serial | take the hashes in the prep/plan pass (the pooled transaction holds its hash from ingest) |
| remember 3 | a free of ~190k-account bundle, 200k receipts and hashed state, inline under the store mutex | move the evicted entry out of the lock and drop it on a background thread (the same as the shard recycle does): 3 ms, and the lock hold with it |
| fields wait 0 (p90 6-8) | parent's `seal_to_fields_us` 46.9 ms median, 60.8 p90 | needs the root chain: 16.5 "the floor" |

The behind-seal graft (`par_fold` - commit, 4-5 ms; `seal_to_finish_us` 11.7 ms) is the parent's own chain: it matters
only through `seal_to_fields`.

### 16.4 The plan, ranked

Baseline for the savings: F2 `sealed_at` 61 = start 4 + prep 4 + gap 3 + exec 23 + (commit 16) + seal 6, minus floors. All
savings are estimates unless stated.

| # | change | phase | mechanism | saving | risk | equality test |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | **seal on the batches' counters; no pool pass on the seal's path** (`N42_SEAL_ON_COUNTS=1`) | commit 16 -> ~1 | `executed_count` and `executed_gas` summed from the batches' results; the seal runs when the batches end (with `skipped` empty and the count = candidates, else today's refs pass); refs vector, receipts, fees and graft behind the seal. With the freeze on its own thread (already built) the seal then does not meet the freeze at all. Also removes the D-style inline 14 ms for anyone without the freeze switch | **-14 to -15 ms** (measured arithmetic: the commit is 16 in F2, 2 in D with a quiet pool) | low-medium: the behind-seal jobs now start with the freeze and the graft on the same pool, so `seal_to_fields` can grow by the same nested-steal delay (watch `seal_to_view_us`, `seal_to_fields_us`, 45-46 ms); fall back is the old path | `seal_on_counts_equals_the_refs_pass` (engine-types: random blocks with failures and skipped senders: count, gas, body, receipts, header and block hash equal); the n42-h2-el-rpc `build_chain` and the replay legs: block hashes equal the F2 legs' on the same replay (`F7_FLOOD_REPLAY`), `fields_mismatches` 0 with `N42_FIELDS_AT_SEAL=verify`, `fleet7-verify` clean |
| 2 | **the child's start, prep and gap into the plan-ahead; hand-off by construction** | start 4, prep 4, gap 3 -> ~1 + ~0.5 + ~1.5 | (a) the take's hand-off an O(1) move at the seal; (b) `BodyAhead` (+ the 400-frame layout and the transaction-hash vector) built with the plan; (c) partition + `batch_groups` + slot arena with the plan; tips behind the seal | **-7 to -8 ms** (start -3, prep -4, gap -1.5; the state open, 0.2-0.6 median, stays) | medium: the plan has to carry the prepared body under the existing discard rules; RSS +~35 MB; the plan's age is 55 ms and shrinks with the cycle (at 40 ms still ahead of its use by ~30 ms: the prep takes 7 ms) | extend `ahead_tests.rs`: a chain of blocks on prepared bodies equals the fresh path block by block (hashes) at four gas limits; each discard reason discards the body too; `body_made_with_the_plan_equals_body_made_at_start` |
| 3 | **the seal's own 6 ms**: eviction drop off the thread, hashes ahead | remember 3, `tx_root` 2 -> ~0 + ~0 | `make_room` hands the evicted entry to a background thread after the lock is released; the hash vector comes from the prep pass | **-5 ms** (remember is exactly the `remember_pending` call: `seal_remember_ms` 3, p90 5; `tx_root_ms` 2) | low | `an_evicted_entry_is_dropped_off_the_lock_and_the_store_is_the_same` (the store's contents and order after N puts equal the inline eviction's); `hash_vector_from_prep_equals_the_seal_collect`; block hash equal |
| 4 | **balance the execution**: 96-128 batches, largest first | exec 23 -> ~18-19 | `batch_groups` closes batches at `total / (workers x k)`, dispatched longest first (LPT) so no worker starts a second wave behind a 14 ms batch; each batch still opens its own view (+~0.2 ms CPU a batch: 12 ms summed at 58, ~26 at 128) | **-4 to -5 ms** (16.8 ms is the floor at 32 workers; 23 now) | medium: more opens and more live-index hand-overs per block (D's defer removes the lock wait; re-read `shard_append_ms`, `batch_minflt`) | the block's state and receipts do not depend on batch boundaries: a property test of `batch_groups` (every group once, in order within a sender) plus `execute_for_build_dispatch` equal to the serial executor over random blocks, as the existing one-wave tests do |
| 5 | **a pool of its own for the behind-seal and freeze work** (`N42_BEHIND_POOL_THREADS=16-24`; `n42-core-layout` isolate is the existing way to give the build pool cores) | tails | freeze, graft, receipts, frees and ops-ahead's parallel work never share the 32 workers of exec, prep and the seal's passes | median ~0 after 1; **p90 -3 to -5 ms** (exec p90 29 -> ~24, F2's slow blocks: half are exec tails, half the parent's wait) and a lower mean (63.0 vs 61) | low: CPU is free (34 of 208), only thread count and RSS | `a_freeze_on_its_own_pool_equals_the_inline_freeze` (the existing 1/16/64-shard cases, with the pool a parameter); the 16.2 test leg |

Order of work: 1 (and the 16.2 leg first, it costs one run and tells whether the nested-steal story holds), then 3 (an
afternoon), 2, 4, 5. Items 1, 3 and 5 touch scheduling only; 2 and 4 touch what is prepared when, never what is built.

### 16.5 The floor, and whether 40 ms is in reach

After 1-4 (estimates): start 1 + prep 0.5 + gap 1.5 + exec 18.5 + join 0.5 + commit 1 + seal ~2 (header, block, hook; the
fields wait is 0 at the median) = **~26-27 ms at the median, p90 ~36-38** (today 61 / 75). **A 40 ms seal at 200,000 is
within reach with no structural change**, with ~10 ms in hand for the tail. Items 1 alone give ~46-47.

**A 40 ms cycle is not.** The child's header carries the parent's execution, so the child's seal waits for the parent's
`seal_to_fields_us`: 45-46 ms in F2 (46.9 median over the 1,415 full blocks, p90 60.8) + ~5 ms for the header, block and
hook = a cycle floor of ~51 ms however fast the seal is. With 1-4 and nothing else the cycle at 200k is ~51 ms (~3.9M TPS,
estimate); at 250k-transaction blocks and 50 ms the chain grows with the accounts (~56 ms) and still binds. The chain is
`seal_to_finish_us` 11.7 (graft scope, receipts, fee credit, finish) + 2.8 to the root job + 30-32 root (apply 24: leaves
6.8, writes 6.9) + ~1. Taking 10-11 ms off it means halving the finish and the apply: possible in pieces (the receipts job
is one serial thread, the apply's leaves and writes are 13.7 ms) but not within a plan of five changes.

**The structural change that makes 40 ms (and 5M TPS at 200k) reachable: deferred execution two blocks deep.** Header N
carries the execution of N-2, not N-1 (`deferredExecutionTime` family, `parent_executed_fields_or_built`, the follower's
check, the chain-spec rule, `fleet7-verify`, the gov5 header profile if the Go clients are to follow): the root chain then
has two cycles (75 ms at 40) minus ~5, against 45-46 today, and the seal never waits for it (`parent_fields_ms` p90 6-8
goes to 0). Equivalent forms: pipelining two blocks' seals on the shard view before the fold (what items 1-2 already do:
the seal precedes the fold) does not remove the dependency; only the deeper deferral does. What it costs: a longer
finality-to-state lag by one block, state roots two blocks old in headers (light clients, the mobile verifier read one
block more), and a consensus-rule change every client must adopt together.

Other bounds at a 40 ms cycle (read from 10.90, not re-measured): persistence 31-37 ms a full block (85-92% busy: the
next bound after the seal, as 12.5 said at 50); CPU: the layer burns ~34 cores at 61 ms, ~52 at 40 ms of 208; the feed
has room.

### 16.6 What was not established, and the legs to run

- The nested-steal mechanism of 16.2 is inferred (data fit, rayon's documented behaviour), not observed: no
  per-worker trace of the refs `install` exists. The leg that decides it is F2 + the freeze on its own pool.
- `n42-freeze` and SMT placement are not observable in the existing thread samples; `fleet7-offcpu.sh` on an F2 leg
  (the profiling build) would show who the refs tree's workers ran while it waited.
- The slot array's allocation (gap) is estimated from its size and `batches_start_us`, not timed alone: one timer
  around the `install` in `execute_for_build_opts` settles it.
- F2T48's `par_start` 12 ms (hand-off 6, p90 25) with 48 threads is unexplained; it blocks the cheap route to a faster
  execution.
- Legs, in order: F2 + `N42_FREEZE_POOL_THREADS=16` (item 5's switch, build it first: one `commit_refs_ms` read);
  item 1 on F2; items 1+3; the 40 ms leg only after the two-deep deferral exists. Read per window: `sealed_at` median /
  p90, `commit_refs_ms`, `index_ms`, `seal_to_view_us`, `seal_to_fields_us`, `parent_fields_ms`, `seal_remember_ms`,
  `tx_root_ms`, `par_exec_ms`, `batch_last_end_us`, persistence per block and its backlog, `fields_mismatches` 0,
  `invalid_blocks` 0, `fleet7-verify`.

Ad-hoc parsers over `node0-el.log` (not kept); sources: `/data/blockchain/rust-fleet7-bench/bench-loop343{D,F2,F2T48,F2P55}/node0-el.log`,
`/data/n42-build/target-n42-rs/fleet-runs/threadcpu-loop343{D,F2,F2P55,FZ}.tsv`.

## 17. The seal's path shortened: section 16's items 1-4 and the freeze-pool test, built (2026-10-07, code only, no fleet leg)

Section 16.4's items 1-4 and 16.2's decisive test, each behind its own switch (default off) except the two pure
changes of item 3. With every switch off each path is the one before (the equality tests pin it). Block contents,
roots, bundles and everything validators exchange are unchanged with every switch on: the switches change only when
and where the same values are made. Savings below are estimates from section 16's timeline, not measurements.

### 17.1 What was built

| item | switch | what it does | phase it removes (16.1 F2) | expected |
| --- | --- | --- | --- | --- |
| 1 | `N42_SEAL_ON_COUNTERS=1` (`N42_SEAL_ON_COUNTS=1` too) | every batch counts its executed transfers, their gas and their fees (`RunCounters`; the tip read on the batch's thread beside the conversion, the prep's formula); a block that seals at the execution's end with every candidate executed in pull order seals on those sums and the body made in the prep or with the plan | commit 16 (refs 15) -> ~0-1 | `sealed_at` 61 -> ~46-47 |
| test | `N42_FREEZE_POOL=own`, `N42_FREEZE_POOL_THREADS` (16) | the shards' freeze (its tasks and frees), the receipts from the slots and the slots' free run on `behind_pool` (`n42-behind-*`) instead of the build pool | - | if 16.2 holds, `commit_refs_ms` 15 -> 1-2 on F2 *without* item 1, `index_ms` stays ~14 |
| 2 | `N42_PLAN_AHEAD_BODY=1` (needs `N42_PLAN_AHEAD`, `N42_PULL_BY_FRAMES`, `N42_SEAL_ON_COUNTERS`); `N42_PLAN_AHEAD_BODY_THREADS` (8) | the queue's plan-ahead hook makes, with the next plan and on its own pool, the candidates cloned out of the frames, the transfer keys, the body's transactions, senders and hashes, the partition at this node's beneficiary and the empty slot array (`PreparedBuild`); a build on that plan, used whole, takes them; a block sealed on its counters from that vector is noted as its whole take and the parent's hand-off forgets it in O(1) | start 4 -> ~1, prep 4 -> ~0, gap 3 -> ~1 | -7 to -8 ms |
| 3 | always (pure) | the store's evicted entry leaves `put` and is freed on `n42-built-free` after the lock; the body's hashes come with the body (`BodyAhead.hashes`, `PreparedBuild.hashes`) into the seal's frame layout | remember 3 -> ~0, `tx_root` 2 -> ~0.5 | -4 to -5 ms |
| 4 | `N42_BUILD_BATCHES=<n>` | `n` batches of about equal size (whole sender groups, candidate order), spawned FIFO largest first | exec 23 -> ~18-19 | -4 to -5 ms |

All four (estimate): start 1 + prep 0 + gap 1 + exec 18.5 + commit 1 + seal ~2 = **~24-28 ms median** against 61, with
the root chain (`seal_to_fields` 45-46 + ~5) then binding the cycle as 16.5 says.

### 17.2 Where the refs pass went, and who needs it

The pass (`slot_refs_and_gas`: the filled slots by reference and the block's gas) fed, on the seal path: the count and
gas (the seal decision and `tx_count` / `cumulative_gas_used`), the fees (`fees_from_tips(refs, tips)`), and, without
a prep body, the body (`body_and_fees`). With item 1 the count and gas are the batches' sums, the fees their
`tip x gas_used` sums (exactly `fees_from_tips`' sum on a block with nothing skipped: U256 addition is exact and
order-free), the body the prep's or the plan's. The only remaining reader of the references is the receipts job
behind the seal (cumulative gas and receipts), which already built its own (`receipts_job`); so on a counted block the
pass does not run before the seal at all. A block that does not qualify (something skipped, a cut candidate vector,
no prep body, a non-early seal) makes the references right after the decision, as before (`commit_refs_ms` then
names it). Fields: `seal_on_counters`, `exec_end_to_seal_us` (the batches' end to the seal's start).

### 17.3 Item 2: what moved into the plan-ahead, and what could not

| piece | where it is now | why |
| --- | --- | --- |
| the hand-off's 200,000-position compare (`start_handoff_ms` 3) | O(1) `forget_whole_take`: length and three (position, sender, nonce) points, on the builder's note that the block is its whole take | a counted seal from the uncut bulk vector is, by construction, the take in take order (the compare proved what the builder knew); any mismatch falls back to `forget_mined_parallel` |
| candidates (200k `Arc` clones out of the frames) | the hook (plan's segments, cloned as frame `Arc`s under the lock, read after it) | a function of the plan |
| transfer keys, transactions, senders, hashes | the hook (`make_keyed_on` on the plan-body pool) | a function of the plan |
| tips | the batches (item 1's `tip_of`) | they need the child's base fee, which the plan-ahead cannot know; read beside the conversion they cost nothing extra |
| partition by sender | the hook, at the beneficiary the last build used; used only when the build's beneficiary is that one and the sizes match | needs the beneficiary, which is the leader's and stable |
| `batch_groups` | the call (~0.1 ms on 400 groups) | depends on the pool's worker count and the dispatch |
| the slot array (~94 MB) | the hook, allocated and touched on the plan-body pool | a function of the plan's length |
| the lanes lock, the drain, the verdict (~0.3-1 ms) | the build's start | must follow the parent's seal: the verdict (`prepared_verdict`) is what proves the plan is still valid on the new parent |
| the state open (`state_wait_us` 0.2-0.6 ms, p90 4) | the gap | waits for the parent's `StateReady` shards: real |

A topped-up plan (`plan_ahead=2`) hands no body (its take is not the plan the body was made from); a plan whose
hook had not finished hands none (`plan_body=2`); every discard of the plan drops its body with it. RSS: one
prepared body is ~120 MB (slots 94 MB, transactions ~22 MB). The hook's CPU (~130 CPU-ms at 200k) runs on 8 idle
threads while the parent executes: ~16 ms of a 55 ms plan age; watch `plan_body_us` and `plan_body=2` at shorter
cycles.

### 17.4 Tests and gate

`seal_on_counters_equals_the_refs_pass` (five shapes, whole and with senders a nonce ahead or running out of balance,
both dispatches: count, gas, fees equal the slots' pass; body, senders, hashes and fees from `BodyAhead` equal
`body_and_fees`); `a_freeze_on_its_own_pool_equals_the_inline_freeze` (1/16/64 shards, every index mode and deferral,
the build pool busy: accounts, beneficiary, merged bundle, QMDB operations, hashed post-state); tx-queue
`a_prepared_body_is_the_take_of_the_build_on_its_plan` (four gas limits, six blocks, chain equal to the fresh one),
`the_whole_take_hand_off_is_the_compared_one`, and the discard tests (refused, handover, untake, arrival below, gas,
prune) now assert the body goes with its plan; `body_made_with_the_plan_equals_body_made_at_start` (three shapes: keys,
transactions, senders, hashes, partition, empty slots; executed on the prepared partition and slots equal to fresh:
transfers, gas, success, skips, counters, the batches' accounts; wrong sizes fall back);
`an_evicted_entry_is_dropped_off_the_lock_and_the_store_is_the_same` (400 puts); 96 and 128 largest-first batches
through the output shards equal the default dispatch (receipts root, skips, beneficiary, merged accounts, reverts, QMDB
operations), and `the_largest_first_packing_keeps_every_sender_run_whole_and_in_order`. Not covered by a unit test:
the block hash of a whole built block (the payload builder has no harness); the fleet's `fields_mismatches`,
`invalid_blocks` and `fleet7-verify` are that check.

### 17.5 Legs to run

Base F2 (`N42_FREEZE_AFTER_SEAL=1 N42_ROOT_OPS_AHEAD=1` on loop343's D). In order:
1. F2 + `N42_FREEZE_POOL=own` (16 threads): read `commit_refs_ms` (15 -> 1-2 says 16.2 holds), `index_ms`,
   `freeze_pool_own=true`.
2. F2 + `N42_SEAL_ON_COUNTERS=1`: `seal_on_counters=true` on full blocks, `commit_refs_ms` ~0, `exec_end_to_seal_us`,
   `sealed_at`; watch `seal_to_view_us` / `seal_to_fields_us` (the behind-seal jobs now meet the freeze).
3. 2 + `N42_PLAN_AHEAD=1 N42_PULL_BY_FRAMES=1 N42_PLAN_AHEAD_BODY=1`: `plan_body=1`, `prep_from_plan`,
   `exec_prepared_groups`, `exec_prepared_slots`, `whole_take_noted`, `par_start_ms`, `start_handoff_ms` ~0,
   `par_prep_ms` ~0, `gap_before_exec_ms`, the hand-off's `queue_partition_us`; `plan_discard` empty.
4. 3 + `N42_BUILD_BATCHES=96` (and 128): `par_batches`, `batch_last_end_us`, `par_exec_ms`, `batch_open_sum_us`,
   `shard_append_ms`, `batch_minflt`.
Item 3 is on in every leg (`seal_remember_ms` ~0, `seal_hashes_ahead=true`, `tx_root_ms`). Correctness on every leg:
`fields_mismatches` 0 (one leg with `N42_FIELDS_AT_SEAL=verify`), `invalid_blocks` 0, `fleet7-verify` clean, block
hashes against F2 on the same replay (`F7_FLOOD_REPLAY`).

## 18. E=1 at depth 2: what binds the 53 ms floor is the landing latency, not the shard hand-off or the vote itself (2026-10-07, code and loop346 logs, no fleet leg)

Question from 10.93: depth 2 took the parent's root chain off the seal (`parent_fields_ms` 0, `sealed_at` 49 -> 41-43) and the
cycle stayed at 53.1 ms (A2P50, 200k, pacing 50) and 107-115 ms (S400A2, 400k). 10.93 names two causes, the child's wait for the
parent's state shards (`gap_before_exec` 16-17 ms median at 200k, 56-59 at 400k) and the vote road's tail. Read offline: A2P50 and
S400A2 `node0-el.log` (the layer, ANSI stripped; full-block builds only: 1,430 blocks 546-1975 at 200k, 739 at 400k) joined block by
block with all seven `node*-v.log` (view V is block V-1; view 1..1023 led by key 0, 1024.. by key 1; one host clock, millisecond stamps),
and the code in `direct_build.rs`, `payload.rs`, `output_shards.rs`, `h2-execution/src/driver.rs`, `h2-el-rpc/src/engine.rs`,
`bin/n42/src/payload_serve.rs`. Medians (p90) unless stated; "estimate" is arithmetic from these, never a measurement.

### 18.1 Summary

1. **Both causes are one cause: the landing latency L**, the time from a block's seal to the layer having it imported by header
   (A2P50 201 ms, p90 266; S400A2 418, p90 502) and to its canonical commit (238, p90 286; 476, p90 551). Three couplings carry L
   back into the cycle: the leader's anchor wait (18.3), the follower driver's two import slots (18.4) and the one-ahead rule (18.5).
   At 50 ms pacing L is four cycles, so every one of them is in its tail.
2. **The child's wait for the parent's shards is only half of `state_wait`, and the smaller half.** Measured split at A2P50:
   output (shards) wait mean 8.8 ms (median 9, p90 17); anchor wait mean 16.3 (median 0, p90 47, present in 48% of blocks). At
   S400A2: output mean 40.5 (median 46), anchor mean 23.2 (p90 80, 43% of blocks). The anchor wait ends within 3 ms of the anchor's
   *canonical commit* (exec start minus `Canonical chain committed` of block N-4: median -2.5 ms; against the insert: +18.6).
3. **The vote road's own latency is ~12 ms; what 10.93 measured as the tail is a gate.** 10.93's proposal-to-quorum median of 11 ms is
   over every view of the leg including the ~3,400 empty ramp blocks. Over the full-block views only (A2P50 views 560-1975, n=1,416)
   it is median 41.4, p90 91.6, p99 116.5 ms; S400A2 median 91.9, p90 166.7. The six followers vote within 0.4 ms of each other
   (p99 4.3 ms), so the tail is common-mode, there is no slow key, and the last key changes (A2P50: keys 4, 6, 2, 3, 5, 0, 1 last in
   24, 19, 15, 15, 12, 10, 5% of views). The common event is the **import slot freeing**: quorum(n) minus "own block imported by
   header"(n-2) is +0.8 ms median, IQR 5.9 (vs -56.8 for n-1 and +64.8 for n-3).
4. **Estimated floor of the plan in 18.7: 42 ms (38-50) at 200k, ~80 (75-95) at 400k, i.e. 4.8M (4.0-5.3M) and 5.0M (4.2-5.3M).**
   5M is the optimistic end at both sizes, not the expectation; it needs items 1-4 and headroom in two loops this section cannot
   see (the engine thread, persistence). No consensus-rule change is needed for it; 18.8 names the next lever if the floor is 45+.

### 18.2 The state hand-off timeline (ms after the parent's seal; seal = execution end + 0.1 at 200k, 0.13 at 400k)

| step | field / event | 200k | 400k | on the child's path? |
| --- | --- | --- | --- | --- |
| child build asked for | `prev_seal_to_start_us` (chain, trigger seal; 86% of builds) | 1.2 (1.5) | 1.3 (1.7) | start; the other 14% / 9% wait for the previous proposal's send (+55 / +116, 18.5) |
| shards frozen | `seal_to_frozen_us` (`index_ms` 14.1 / 50) | 13.0 (17.5) | 48.5 (60.4) | **yes, by code order; the child needs only the index** |
| scope joined | `seal_to_finish_us`: freeze + graft `take_cached` + **receipts job + transactions-root job** | 17.2 (21.6) | 54.4 (66.1) | **yes, by code order: +4.2 / +5.9 ms the child does not need** |
| executor finish + merge_transitions | `seal_to_bundle_us` | 17.4 (21.8) | 54.7 (66.4) | yes (the residual) |
| **`shards_ready` filed: the child's open proceeds** | between bundle and view | ~17.5 | ~55 | the event `wait_for_state` is woken by |
| parent's own view | `seal_to_view_us` | 18.2 (22.7) | 56.7 (68.8) | no |
| QMDB tree renamed early | `seal_to_rename_us` | 20.7 (30.9) | 63.0 (82.6) | no (root job) |
| root and fields published | `seal_to_fields_us` | 54.3 (73.5) | 130.5 (183.1) | no at depth 2 (consumer is block N+2's header) |
| `StateReady` = `Complete` | `seal_to_complete_us`; shard merge 58 / 131 ms, one thread, starts at the fields | 114.1 (140.5) | 267.3 (321.9) | no; the hand-off waits for it |
| hand-off starts | handed minus `total_ms`; **fork-move forkchoice** + body lookup | 143.5 (200.1) | ~313 | no |
| handed to the engine | "own block handed to the engine as executed" (`total_ms` 41 / ~85) | 187.7 (249.4) | 397.9 (483.8) | no |
| imported by header | "own block imported by header"; new_payload +4.3 / +8 | 201.3 (265.5) | 418.0 (501.9) | no |
| canonical commit | "Canonical chain committed" (+31.6 after import, p90 +89; 400k +52) | 237.9 (285.7) | 475.7 (550.8) | **yes: the anchor of a 3-layer open** |

What the child needs before its first batch. Its senders are the parent's senders (the flood draws 12,500 senders into every
block), so every first read of a sender is a read of the parent's output; each sender lives in exactly one parent batch, so that
read needs only the live index entry of the batch, never the conflict sum. It does not need: the receipts (a different job, joined
in the same scope), the transactions root, the view, the rename, or anything from `StateReady` on. What the code makes it wait for:
the freeze's *completion* (conflict sums of ~8,000 recipients at 200k, ~32,000 at 400k, and the deferred shard entries), and the
scope's join of the receipts and transactions-root jobs. The freeze task is one shard: `task_max_us` 13.6 of `fold_us` 14.2, with
`pending_max` 73 of 128 batches deferred into the heaviest shard (9.5 ms of `pending_us_max`) and `drops_max` 16k (the rest).

The scaling at 400k. Blocks are 2x; the freeze is 3.7x (13.0 -> 48.5) and `index_conflicts` 4.0x (8,054 -> 32,003).
Recipients are drawn from 2,000,000 addresses, so the expected number of repeated recipients is N^2/(2 x 2M): 10,000 and 40,000
(observed 8,054 and 32,003). The conflict work is quadratic in block size, the pending entries superlinear (`pending_us_max` 9.5
-> 30.0, a 3.2x for cache-cold per-batch maps), and both sit in the single heaviest shard task, so more workers do not help.
The wait itself is the same ratio: output wait median 9 -> 46 (5x), because the child's start (1.3 ms) and open do not scale
while the freeze does. The anchor wait scales with L (2.1x) over the same cycle (2.0x): it grows slowly (16.3 -> 23.2 mean).
`gap_before_exec` median 19 -> 58 is therefore mostly the freeze at 400k and mostly the anchor at 200k.

Locks and notifications on this path: none measurable at the child's open (`open_keep_us` 4, `open_provider_us` 72, `polls` mean
0.9). The anchor wait's wake is the engine's canonical notification (`engine_landed::notify`), 20 ms safety slice otherwise.
The forest lock does show on the landing side: `compute_operations` holds it 26 ms (p90 35) in 74% of blocks and `rename`,
`on_canonical`, `on_persisted` wait behind it (97 + 190 + 122 waits of ~25-28 ms in 1,430 blocks).

### 18.3 The two landing couplings of the build

**Anchor.** `N42_LEADER_LAYERS=3` lays N-1, N-2, N-3 over the engine and needs block N-4 *canonical* in the engine
(`opener_on_sealed_parent_with` -> `grandparent_state` -> `state_at_soon`). Build N starts at seal(N-1)+1, so the wait is
`canonical(N-4) - seal(N-1) - 1 = L_canon - 3c - 1` with `L_canon` 238: at c = 60, 57 ms in the late half of blocks, 0 in the
early half (observed: 48% of blocks, mean 16.3). It cannot be made smaller by pacing: at c = 42 the same arithmetic gives
`238 - 126 = 112`. The layer count that clears it is `L_canon / c` rounded up: 6 at 42 ms (7-8 for p90). The code caps the count at 4
(`leader_layers::DEPTHS` 2..=4).

**Hand-off tail.** The hand-off of block n begins with a forkchoice moving the engine head to the parent when it is not already
there (`own block forks from the engine's head`, 1,328 of 1,430 blocks, `moved_ms` median 16, p90 75, 685 of them answered
SYNCING because the parent has not landed). Hand-off start minus `Complete` by `moved_ms` bucket: <3 ms: 6.5; 3-15: 14.6; 15-40: 32.1;
>=40: 87.1 (200k); the remainder (c2h minus moved) is 5.6-6.2 ms flat, so the tail of the whole landing is this one forkchoice,
which waits for the engine thread (commit forkchoices of 9.2 ms mean, p90 27, p99 90, three per block; lock waits above).

### 18.4 The vote tail: anatomy of the slowest 10%

The mechanism, from `h2-execution/src/driver.rs` (`spawn_execute_deferred`: `executing.len() >= in_flight_cap`, cap 2 by default,
3 at most; the slot is freed when the import returns its verdict, i.e. when the block has landed) and `payload_serve.rs`
(`own_block_by_header`: `once.checked()` fires the moment the build is found, `serve_from_own_build` writes CHECKED first of
all): **at E=1 the layer answers CHECKED at once, but only when the request arrives, and the driver sends the request for
block n only when block n-2 has landed.** `N42_VOTE_BEFORE_SLOT` is the existing way round the slot and the start-up refuses it
together with `N42_IMPORT_ONCE` (18.2's table in section 2: one receiver per hash). None of the loop346 legs set it.

Timeline of a view (A2P50, medians; p90 in brackets), time from the proposal's send: key receives the body 1.6-2.1; all six votes
sent at 31.7 (82.2); leader commit 41.4 (91.6), of which 9.0 (13.8) are the R1 and R2 collects after the fourth vote
(`R1_collect=5ms R2_collect=5ms`). The vote therefore costs ~2 + ~1 + 9 = ~12 ms when the gate is open and 30-80 ms when it is not.
S400A2: receive 1.7-2.2, votes at 80.4 (156.2), commit 91.9 (166.7).

The slowest 10% (vote delay >= 82.2 ms at 200k, >= 156.2 at 400k), by the landing of the block that frees the slot, n-2:

| component of the freeing block's L | slowest 10% | the rest | excess share |
| --- | --- | --- | --- |
| seal -> imported (L) | 265.9 (200k) / 515.0 (400k) | 198.2 / 412.7 | +67.7 / +102.3 |
| `Complete` (seal -> `StateReady`) | 107.4 / 268.9 | 114.6 / 267.3 | -4.6 / +3.4 (not the cause) |
| `Complete` -> hand-off start | 82.8 / 70.4 | 19.4 / 21.4 | **+50.1 / +60.7** |
| hand-off duration | 49.0 / 129.0 | 40.0 / 83.0 | +10.1 / +42.0 |
| head-move forkchoice `moved_ms` | 73 / 58 | 11 / 5 | the c2h excess |
| hand-off -> new_payload, new_payload | +3.6, +0.3 | | |

Fork-move >= 20 ms in 77% of the slowest decile against 39% of the rest (73% / 39% at 400k). The tail correlates with the
layer's own work through the engine thread and the forest lock (the head move waits for the engine; `rename` waits for
`compute_operations`), not through the freeze (`seal_to_frozen` is not different in the tail) and not through the key. The vote
tail is the landing tail of block n-2 delivered through the slot.

Is the vote road on the critical path at 50 ms pacing? **Yes, through the gate, and for about half the views.** 52% of proposals are
tick-bound (interval median 51.4); 41% are sent within 5 ms of the previous view's commit (interval median 77.1) and only 3 of 671
non-tick-bound proposals are within 5 ms of their own seal: the proposals are commit-bound, not build-bound. The proposal lags its
seal by 45 ms (median), 93 ms at 400k: the build runs ahead of the road. The chain-start rule (`ChainState.slot`, one chained
build, held until its proposal takes it): 1,220 builds start at the parent's seal ("S"), 195 at the previous proposal's send ("D",
14%), and D happens only when the parent's proposal lagged its seal by more than ~45 ms (fraction of D by lag bucket: 0% below 45 ms,
26% at 45-60, 33% at 60-75). A D start costs ~55 ms at 200k (cycle 89.8 median against 56.6 for S). Cycle: S-class mean 60.9, D-class
92.1, mean 65.2. So the one-ahead rule is not what binds; the gate that makes proposals lag is.

The closed form that fits both legs: with cap C, vote(n) = land(n-C) + 1, so a proposal is held until `L + 10 - C c` after the
seal of its block; the build loop (D start) then closes at about `(L + 10 + B_send)/(C + 1)` with `B_send` the shorter build of a
send-started block (sealed_at 26): (201 + 10 + 26)/4 = 59 ms against 65 measured. At 400k: (418 + 10 + 41)/4 = 117 against 126.

### 18.5 Candidates weighed against the data

| candidate | verdict |
| --- | --- |
| Child executes on the parent's unfrozen batch state (read-through to per-batch maps) | Worth it, but not first. It removes the output wait (mean 8.8 / 40.5 ms; only while the anchor is not the later wait), i.e. ~6 ms mean at 200k and ~25 at 400k after item 2. Reads of a sender are non-conflicting (one batch); a recipient read needs the sum of its batches (lazy, 4% of accounts); the deferred shards' entries need a probe of the deferred batches. High risk (consistency of three sources), so it comes after the cheap freeze items. |
| Freeze and publish per shard as batches end | Little: every batch reads recipients across all 16 shards, and one shard (13.5 of 14.1 ms) is the whole freeze. Splitting the heaviest shard's pending list over two to four tasks is the useful form (item 3). |
| Overlap the child's first batches with the parent's freeze on disjoint senders | Not applicable to this flood (every sender in every block); no disjoint set. |
| CHECKED from the build's counters as soon as the seal exists | Already how the layer answers (`once.checked()` on `find_kept_sealed`). What is missing is the request: the driver does not send it until a slot frees. Item 1. |
| Proposals two deep (one-ahead relaxed) | Not before item 1: D starts are 14% of builds and exist only because proposals lag. After item 1 the lag is the tick, and relaxing the rule would let two unproposed builds be discarded on a view change for nothing. |
| Not on the list | (a) the layer count cap and the receipts-join order (items 2, 4); (b) the shard merge starting only after the fields (items 3's sibling, 18.7 item 3); (c) the fork-move forkchoice in the hand-off; (d) the `listed_for` cache of two blocks against a landing 4 cycles late (the re-encoding of 200k transactions on the pool, part of the 5.6-6.2 ms c2h floor; unmeasured). |

### 18.6 Costs the plan has to keep an eye on

CPU: the layer burns ~35 of 208 CPUs; a dedicated pool for the merge costs nothing the box lacks (the freeze pool precedent: `index_ms`
unchanged, `commit_refs` -15). Memory: a kept layer is one shard set (~50 MB at 200k, ~100 at 400k); six layers are ~0.3-0.6 GB of
41.8 GB RSS. Read cost: every read no layer answers walks every layer (one index probe each), estimate +3 ms exec at 200k, +6-8 at 400k
for six layers (~800k reads x 3 more layers x 30 ns / 32 threads, 200k). Engine thread: 3.2 canonical commits per block at 9.2 ms mean
is ~29 ms of 65; at 42 ms that is 70%, and `compute_operations` holds the forest lock 26 ms in 74% of blocks: the engine thread and the
forest lock are the loops this log cannot bound below 50 ms.

### 18.7 The plan (ranked by expected effect on the floor; estimates labelled)

1. **Vote before slot, by a check-only request (`N42_CHECK_BEFORE_SLOT`).** Mechanism: when the driver holds a proposal's body and
   every slot is busy, it sends a header-only CHECK to the layer (new raw frame, or `OWN_BLOCK` with a "no hand-off" flag) answered
   by `find_kept_sealed` + `once.checked()` with the CHECKED frame and nothing else; the vote goes at once. The import stays queued
   in the slot exactly as today (landing order, parent-before-child and the slot semantics unchanged). Saving: vote delay 31.7 ->
   ~3 ms (200k), 80 -> ~3 (400k); proposal-to-commit ~12 ms; D starts vanish: mean cycle 65.2 -> ~61 (estimate, 200k), 126 -> ~121 (400k).
   Alone it does not move the median block (the build loop is 56.6): it is the precondition for everything below, because without it
   `c >= (L + 10 - x)/3` is 69 ms at E=1. Risk: moderate (a second reply path; a vote must still be withheld for a block the layer
   does not hold, which falls back to today's road). Test: for every key and view, CHECKED-before-slot is sent only when
   `find_kept_sealed` matches parent, number, state root, receipts root, gas and transactions root; a mock layer returning CHECKED
   for a different build must produce no vote; `fields_mismatches` 0, `invalid_blocks` 0, `fleet7-verify`; same replay, same block
   hashes as A2P50.
2. **Layers 3 -> 6 (`DEPTHS` 2..=8, `N42_LEADER_LAYERS=6`, `PARENT_OUTPUTS_KEPT` and `built_executions KEEP` to match).** Mechanism:
   the anchor becomes N-7 and the wait `L_canon - 6c - 1` is <= 0 for c >= 40 at the median (6 x 40 = 240 vs 238; p90 needs item 3).
   Saving: anchor wait mean 16.3 -> ~1 (200k), 23.2 -> ~2 (400k), less the read cost: net ~ -12 ms (200k), -15 (400k), estimate.
   Risk: low in correctness (the stack is the same code with more entries), moderate in speed. Test: `open_on` over 6 layers equals the
   engine's own state at the same height for every account of two replayed blocks (existing 2-4 layer tests extended);
   state roots equal under `N42_FIELDS_AT_SEAL=verify`; exec time and `view_journal_searches` before/after.
3. **Cut L: start the shard merge at `shards_ready` on a dedicated pool, parallel by shard.** Today the merge (58 / 131 ms, one thread:
   `merge_threads=1`, state 38 + reverts 15 at 200k) starts at the fields (54 / 130) and sets `Complete`, hence the hand-off, hence
   L. Started at 18 / 55 on 16 threads it ends near the root job's end: `Complete` 114 -> ~65-75, 267 -> ~150-170 (estimate), L -45 /
   -100, `L_canon` 238 -> ~190 (200k). Together with item 2 this lets 5 layers do the work of 6 and brings the slot's service time
   (arrival -> landing, now ~2c) under `C c` for C = 2 at c = 42. Risk: CPU contention with the child's execution if the pool is
   shared (use `behind_pool`); 10.16 moved the merge after the root for exactly that. Test: the merged `BundleState`, hashed post-state
   and trie updates equal the single-thread merge for 1/16/64 shards (the `freeze_pool` test shape); `fleet7-verify`.
4. **Output wait: reorder the scope and split the heavy shard.** (a) `shards_ready` is filed after the scope joined the receipts and
   transactions-root jobs (`seal_to_frozen` 13.0 -> `seal_to_finish` 17.2, 48.5 -> 54.4): file the shards after `take_cached` and
   the executor's finish, join the receipts job afterwards (the executor's finish already ignores receipts; `direct_receipts` is
   substituted after it): -4.2 / -5.9 ms of output wait. (b) Split the heaviest shard's `pending` list (73 of 128 entries) over 2-4
   tasks, summing conflicts per task and merging: the freeze 14 -> ~8 ms, 50 -> ~25 (estimate; SES 16.4 had 14 -> 8). Saving on the
   mean cycle after item 2 (the output wait becomes the gap): -6 ms (200k), -26 (400k). Risk: low. Test: receipts root, QMDB operations,
   accounts and reverts equal to the current freeze (`tests/output_shards.rs` shapes); a changed order of joins must not move a root.
5. **Read-through on the unfrozen state (18.5, first row)**, after 1-4, when the output wait left is above 5 ms (400k: ~20 ms).
   Saving ~ -4 ms (200k), -18 (400k), estimate. Test: the child's reads against the frozen view for every address the block touches,
   equal; a randomised batch/shard schedule; block hashes equal.

### 18.8 The floor, and 5M

Loops after items 1-4 (200k; estimates except where marked): build `1.2 + 6 + 3 (output wait) + 20.5 (exec, measured) + 3.5
(layers) + 1.5 = 36`; proposal tick 35-40 (a setting); vote road ~12 (measured pieces); root job 27 (measured, `roots_ms`); persistence
33 (10.87-10.90: 79% busy at 42); engine thread ~29 per block (this section); landing service `(L - x)/C` = (190 - 5)/2 = 92 per
two blocks, 46 each. **Floor 42 ms (38-50)**: 200k / 0.042 = 4.76M (4.0-5.3M). At 400k: build `1.3 + 7 + 20 + 35.2 + 7 + 2 = 72`, root
job 58, persistence 67-78 (10.93), tick 80: **floor ~80 (75-95)**, 5.0M (4.2-5.3M); persistence is within a few ms of the floor
there. **Verdict: 5M is reachable at E=1 only at the optimistic end of both sizes, and without a rule change.** What decides it is
unmeasured below 50 ms: the engine thread (3.2 commits a block, forest lock 26 ms in 74% of blocks) and persistence. If the first
leg after items 1-4 reads 45+ ms at 200k, the next change is not a consensus rule but the block: 300k transactions per block
(gas limit 6.3e9) amortises the ~6 ms start, ~1.5 seal and ~12 vote road over 50% more work, and the 400k floor above says it
fits. A consensus rule would be next only for the commit: proposing on the R1 QC (not Decide) takes ~5 ms off the proposal loop,
which matters only when the proposals are commit-bound, i.e. after item 1 only if the intrinsic road (12 ms) exceeds the tick.

### 18.9 Legs to run, in order (one variable each from A2P50 / S400A2)

1. Item 2 alone (`N42_LEADER_LAYERS=6`): `ggp_missing`, `state_wait_on`, `gp_ms` -> 0; exec time; cycle at 50 and 45.
2. Item 1 alone: proposal-to-quorum over full-block views (use `voteroad346.py` restricted to views whose block has txs=200000, or
   the filter in 18.1), `build_start_trigger` D share, commit-bound share.
3. Items 1 + 2, pacing 45, 40, 35.
4. Item 3, then item 4, each added to leg 3; read `seal_to_complete_us`, `seal_to_frozen_us`, `seal_to_finish_us`, `moved_ms`.
Instrumentation to add first (cheap): log `landing` events per block (arrival of the import request, hand-off start, fork-move
start/end, engine insert start/end) so 18.3's c2h split needs no join; per-shard entry counts of the freeze (is the heavy shard a
property of the address derivation?); the canonical notification's wake latency in `grandparent_state`.

## 19. Section 18's items 1-4, built (2026-10-07, code only, no fleet leg)

Each item behind its own switch, default off; with every switch off each path is the one before (the existing tests and
the new equality tests pin it). With every switch on, block contents, roots, bundles, votes and everything validators
exchange are unchanged: the switches change when and where the same values are made, and which request carries a check
the execution layer already makes. Savings are estimates from section 18's timeline, not measurements.

### 19.1 What was built

| item | commit | switch (process) | what it does | expected (estimate) |
| --- | --- | --- | --- | --- |
| 1 | dc40c0a3c | `N42_CHECK_BEFORE_SLOT=1` (validator; the execution layer serves the request always) | a deferred block queued behind busy import slots sends its sealed header as a `CHECK_ONLY` raw request (kind 10). The layer answers one CHECKED frame (VALID, naming the header's hash) when the header is one of its kept builds (`is_own_build`, the same check the body roads answer CHECKED with) or the import-once registry holds another request's check of that hash (`Registry::is_checked`); else one ERROR frame. Nothing is imported, held, claimed or registered. The driver releases the vote only on a VALID answer naming exactly the block (`vouches_for`); the import stays in the queue, in order, under the slot bound, and its own later check releases no second vote (`first_check`, 64 hashes kept) | vote delay 31.7 -> ~3 ms (200k), 80 -> ~3 (400k); proposal-to-commit ~12 ms; send-started builds (14%) vanish: mean cycle 65 -> ~61 (200k), 126 -> ~121 (400k) |
| 1 | 6008a5e6d | always (observability) | the "proposal sent" line carries running `build_starts_seal` / `_send` / `_commit` / `_other`, so a leg reads the one-ahead rule's send share from its last line | - |
| 2 | 099f5ec1b | `N42_LEADER_LAYERS` 2..=8 (layer) | the cap was 4 (`DEPTHS`); nothing else bounded it: layers live in `leader_layers::KEPT` from their child's first open, not in the build store (`built_executions` `KEEP` 3 holds builds until their hand-off; the six-layer test files six builds through it), and `PARENT_OUTPUTS_KEPT` is the follower's own stack (already `N42_PARENT_OUTPUTS_KEPT` 2..=16). Memory: `leader_layers::held()` and `open_kept_accounts` on the open's split (accounts in the kept shard sets and bundles; ~260 B an account, so ~50 MB a layer at 200k). The anchor N-7 must still be in the engine's in-memory tree: `--engine.memory-block-buffer-target` 6 (the fleet default) covers six layers at a canonical lag of ~4 | anchor wait mean 16.3 -> ~1 (200k), 23.2 -> ~2 (400k); read-through +3 / +6-8 ms exec; net ~-12 / -15 ms |
| 3 | 01235ca8e | `N42_MERGE_AT_SHARDS_READY=1`, `N42_MERGE_POOL_THREADS` (16) (layer) | the leader's shard merge starts at `shards_ready` on `n42-merge-*` (`FrozenShards::merged_on`: each source map, a v4 shard or a batch's map or a shard's conflicts, cloned with the residual laid over on a task; the copies inserted in the serial merge's source order; reverts copied per source and sorted as before; map and reverts at once), instead of after the fields' publication on one thread | merge 58 -> ~12-15 ms, ending at seal + ~33 (200k), before the fields (54): `Complete` 114 -> ~56 (fields + hashed), L -55 ms; 400k: merge 131 -> ~30, `Complete` 267 -> ~132, L ~-130 |
| 4a | 213a6e362 | `N42_SHARDS_BEFORE_RECEIPTS=1` (layer) | on a block sealed at the execution's end with its output in its shards, the receipts from the slots are built on `n42-receipts-late`, which owns its inputs (the slots moved, the candidates shared in an `Arc`), instead of in the graft's scope; the scope ends with the freeze join and `take_cached`, the executor's finish follows, and `shards_ready` is filed. The receipts join the block's result where they are first read (the receipts-root thread beside the QMDB root) | output wait -4.2 ms (200k), -5.9 (400k) |
| 4b | f24ada784 | `N42_FREEZE_SPLIT=<k>` (1; at most 8) (layer) | the live freeze's heavy shard (work = deferred batches' addresses entered + occurrences summed; split when >= 2,048 and >= 1.5x the mean) is worked on by k tasks, one sub-range of its addresses each (bytes 2-3; the shard is bytes 0-1) | freeze 14 -> ~6-8 ms at k=4 (200k), 50 -> ~20-25 (400k); output wait follows |

All five on (estimate, 200k at 42-45 ms pacing): the vote leaves the slot (item 1), the anchor is canonical when the build
opens (item 2), L drops by ~55 ms so the slot's service time falls under `C c` (item 3), and the output wait shrinks from
~9 to ~3 ms (item 4): section 18.8's floor of 42 ms (38-50) is what the first leg should test.

### 19.2 `N42_VOTE_BEFORE_SLOT`: a new switch, not a compatible old one

`N42_VOTE_BEFORE_SLOT` holds an execution on the layer: the request is prefixed `HOLD_EXECUTION`, the layer assembles and
checks the body, and then waits for one release byte from the connection that sent it before it executes. Under
`N42_IMPORT_ONCE` seven keys share the layer and the registry gives each block one owner whose work every other key's
request waits on. Making the hold compatible would mean deciding whose byte releases a shared execution (the owner's,
whose key may drop a block another key still needs, or a vote of seven keys' slots that disagree), keeping a second
registry of releases per hash, and changing when the shared import runs relative to each key's slot order. A check needs
none of it: at E=1 the block is the layer's own build, the layer's answer depends only on the header, and the import can
stay on today's road. So the new `N42_CHECK_BEFORE_SLOT` holds nothing, claims nothing in the registry, and composes with
`N42_IMPORT_ONCE`; the start-up refusal of `N42_VOTE_BEFORE_SLOT` + `N42_IMPORT_ONCE` stays, and `N42_VOTE_BEFORE_SLOT`
keeps its use where it was built (one key per layer, foreign blocks the layer did not build). A block the layer did not
build and nobody checked is declined and votes on its import's check, as without the switch (at E>1 every follower's
blocks are such blocks: one extra loopback round trip each, nothing else). The send-started builds of 18.4 exist only
because proposals lag their seal behind the gate; `build_starts_send` on the "proposal sent" line shows whether they go.

### 19.3 Item 3: what moved earlier with the merge, and what could not

| step | before | with `N42_MERGE_AT_SHARDS_READY` | why |
| --- | --- | --- | --- |
| merge start | after the fields' publication (seal + 54 / 130) | `shards_ready` (seal + ~18 / ~55) | every input is in hand there: the frozen shards, the residual, the graft's reverts. The receipts are not an input of the merge (they are put beside the merged bundle in the output) |
| merge end | seal + ~114 / ~267 | seal + ~33 / ~85 (estimate) | 16 threads by source map; the inserts into the one map and the reverts' sort remain serial (~8-10 ms at 200k) |
| `StateReady` | after the merge, after the publication | right after the publication (the merger thread only joins the early merge) | not moved before the publication: a child that opens after `StateReady` reads the full bundle instead of the shards (`wait_for_state` prefers it), and keeping the filing after the fields keeps every reader's order as before |
| `Complete` (the engine's hand-off, then the executed insert and persistence) | after the merge | after the publication and the hashed post-state | must not move before the publication: the publication files this block's QMDB tree (`qmdb_state.insert`), which the engine's executed insert, persistence and the child's root job read. It sees the same inputs: the same merged bundle, receipts and hashed post-state |
| the QMDB root, the receipts root, the fields | unchanged | unchanged | the root reads the view, never the merged bundle; the merge pool is not the root's or the build pool |
| `N42_FIELDS_AT_SEAL=verify` | behind `Complete` | behind `Complete` (earlier with it) | compares the published fields with the merged bundle's operations: the same comparison on the same bundle |

### 19.4 Item 4: what the child needs, and how the heavy shard was split

(a) The child's open reads `ShardedParent { residual, shards }`. The residual is the executor's own changes taken after
its finish; its `result` is built empty (no receipts, no gas), and the executor's finish does not read the direct
receipts (they are substituted after it). So filing the shards before the receipts exist is a pure reordering, which
`a_sharded_parent_opens_the_same_with_or_without_its_receipts` checks on a filed parent: every account the batch or the
residual wrote, an untouched and an absent one and `BLOCKHASH` read the same with the block's receipts and gas in the
residual's result and without. The transactions-root job of 18.2 does not run in this path (the counted seal computes
the root at the seal from the hashes the body carries, `seal_hashes_ahead`): only the receipts join was in the scope.

(b) The heavy shard's two phases, entering the deferred batches (`pending`) and summing the repeated occurrences
(`drops`), are both per address: an address's index entry, its kept revert and its conflicting sum depend only on the
batches that wrote it, in batch order. A sub-range of the shard (the address's bytes 2-3, independent of the shard's
bytes 0-1) is therefore a self-contained job: each task enters the deferred batches' addresses of its sub-range in batch
order, reading the live index and keeping what it adds in its own map (a newly repeated live address in a list), then
sums its sub-range's occurrences in the single task's order (the live ones, then the deferred ones); the parts are put
back into the one shard part (index entries, CONFLICT marks, kept reverts, drops, the size taken off, the conflicting
sums). The kept reverts' order inside the shard changes (sub-range major), which no reader depends on: the merge sorts the
reverts by address and `take` scans them. The folded line names the heaviest shard (`heavy_shard`, always on) and its
work (`heavy_work`), which answers 18.9's question whether the heavy shard is a property of the address derivation: the
same shard index leg after leg says yes.

### 19.5 Timestamps added on existing lines

| boundary | field | line |
| --- | --- | --- |
| vote released relative to the body's arrival | `check_us` (queue entry, body in hand, to the answer) and `vouched` | validator "check ahead of the import slot" (info for large blocks), with `check_ahead_sent` / `_vouched` / `_declined` on "imported a block" |
| `shards_ready` filed | `seal_to_shards_ready_us` (always) | layer seal-first phases line, beside `seal_to_view_us` |
| merge start / end | `seal_to_merge_start_us`, `seal_to_merge_end_us` (existing), `merge_early`, `merge_join_wait_us`, `merge_threads` | same line |
| the receipts past the shards | `receipts_late`, `receipts_late_wait_us` | same line |
| the heavy shard's task | `task_max_us` (existing), `heavy_shard`, `heavy_work`, `split_tasks`, `pending_us_max` | "output shards folded" |
| the layers' memory | `open_kept_accounts` | the open's split (`state_wait_on` details) |
| send-started builds | `build_starts_seal` / `_send` / `_commit` / `_other` | validator "proposal sent" |

### 19.6 Tests and gate

New: `h2-execution` `tests/check_before_slot.rs` (a block behind busy slots voted for on its check-only answer before any
slot frees, imported in order, voted for once; a CHECKED answer naming another build releases no vote; no request
without the switch, against a layer that does not serve it, or for a body whose header does not hash to the block);
`h2-el-rpc` `a_check_only_answer_vouches_only_for_the_block_asked_about` (only a VALID CHECKED naming the asked block
vouches; another build's hash, ERROR, SYNCING, no channel do not; one connection reused) and
`a_check_only_request_without_a_channel_vouches_for_nothing`; `n42` `a_check_only_request_vouches_for_a_kept_build_and_nothing_else`
(a kept build by its gov5-sealed header vouched for with nothing imported, executed, handed off or registered; a
sibling with another state root, an unknown block and no header refused; a block another key's import checked vouched
for from the registry); `six_kept_layers_read_as_the_engine_after_it_landed_them` (six layers, bundles and shard sets
alternating, over the engine at N-7: every account, a slot written twice, a created account, the coinbase from a
residual, untouched, absent, `BLOCKHASH` of each, equal to the engine after it landed all six; four and three layers
over the matching deeper engine equal too); `the_merge_on_its_own_pool_equals_the_serial_merge` (1/16/64 shards, every
index mode and live deferral, 1 and 4 threads, the build pool busy: accounts, contracts, reverts in order, sizes, against
the serial merge and the direct graft, QMDB operations with and without Prague, hashed post-state; the account map's
iteration order is no property of either merge: its hasher is seeded per map, two serial merges of the same shards
iterate differently, and every consumer sorts); `a_sharded_parent_opens_the_same_with_or_without_its_receipts`;
`a_split_heavy_shard_freezes_as_one_task` (2/4/8 tasks against one at 1/16/64 shards, forced, busy-concurrent and no
deferral: every address read through the shards, conflicts, accounts, beneficiary, merged bundle against one task and
the direct graft, QMDB operations, hashed post-state). Gate: `cargo check --workspace`; clippy on the touched crates adds
no warning on changed lines; `n42-engine-types` lib single-threaded 242 passed (10 ignored) and its integration tests
(16 in `output_shards`), `n42-h2-execution`, `n42-h2-el-rpc`, `n42-h2-node`, `n42 --lib` single-threaded (137),
`n42-qmdb-reth` single-threaded (63) pass. Not covered by a unit test: a whole built block's hash with the switches on
(the payload builder has no harness): the fleet's `fields_mismatches`, `invalid_blocks`, `fleet7-verify` and block hashes
against A2P50 on the same replay are that check.

### 19.7 Legs to run (18.9's order, one variable each from A2P50 / S400A2)

Validator env: `N42_CHECK_BEFORE_SLOT=1` (with the existing `N42_IMPORT_ONCE=1`, `N42_BODY_ONCE=1`). Layer env:
`N42_LEADER_LAYERS=6`, `N42_MERGE_AT_SHARDS_READY=1 N42_MERGE_POOL_THREADS=16`, `N42_SHARDS_BEFORE_RECEIPTS=1`,
`N42_FREEZE_SPLIT=4`.
1. `N42_LEADER_LAYERS=6` alone: `ggp_missing`, `state_wait_on`, `gp_ms` -> 0, `open_kept_accounts`, exec time; cycle at 50 and 45.
2. `N42_CHECK_BEFORE_SLOT=1` alone: `check_ahead_vouched` ~ `check_ahead_sent`, `check_us` (expect ~1-3 ms), proposal-to-quorum
   over full-block views, `build_starts_send` share (14% -> ~0), commit-bound share.
3. 1 + 2 at pacing 45, 40, 35.
4. + `N42_MERGE_AT_SHARDS_READY=1`: `merge_early=true`, `seal_to_merge_start_us` ~ `seal_to_shards_ready_us`,
   `seal_to_merge_end_us` < `seal_to_fields_us`, `merge_join_wait_us` ~0, `seal_to_complete_us` (114 -> ~56), `moved_ms`, L.
5. + `N42_SHARDS_BEFORE_RECEIPTS=1 N42_FREEZE_SPLIT=4`: `receipts_late=true`, `seal_to_shards_ready_us` (17.5 -> ~13),
   `receipts_late_wait_us`, `split_tasks`, `task_max_us` (13.6 -> ~6-8), `heavy_shard` stable across legs or not, output wait.
Correctness on every leg: `fields_mismatches` 0 (one leg with `N42_FIELDS_AT_SEAL=verify`), `invalid_blocks` 0,
`fleet7-verify` clean, block hashes against A2P50 on the same replay.

## 20. The seal chain at 50 ms and what the tail is (2026-10-08, loop350 BP50/B logs, no new leg)

Question: at 50 ms pacing and 200k the cycle holds 53.9 ms median but 63.4 mean. What does the seal chain consist of, and what
makes the tail? Read offline from loop350 `bench-loop350BP50/node0-el.log` (the layer; window 1, 475 builds) and the validator
logs of BP50 and B (60 ms). Medians (p90) unless stated; sums of means are arithmetic, never a measurement.

### 20.1 Seal chain anatomy at BP50 (base, 50 ms pacing, 200k)

Order from build start to `sealed_at`: `par_start` (setup and header, `payload.rs` ~1721-1727) -> `state_wait_ms` (macro ~1548-1553;
`direct_build.rs:405` `open_wait`: waits for the parent's StateReady or the grandparent's import; over all builds the wait was on
the parent's output 673 times, on the grandparent 539, none 241) -> prep/part/pull (0 ms; ~2036, 2851) -> `par_exec_ms` (~2852;
128 batches on build_pool, `parallel_transfer.rs:850-861`, `N42_BUILD_BATCHES` at ~1388) -> seal at the execution's end (2520-2545,
hook 1880-1899, `sealed_at` stamped at 1899; `exec_end_to_seal` median 106 us). Not inside `sealed_at`: `par_fold` (after the
seal), `index` (the freeze, on its own thread, ~2200-2245), roots, `state_ready`.

| phase (ms) | median | p90 | mean | note |
| --- | --- | --- | --- | --- |
| par_start | 2 | 15 | 5.0 | |
| state_wait | 20 | 57 | 25.2 | a wait, not work |
| par_exec | 20 | 26 | 20.9 | the only parallel part |
| sealed_ms | 3 | 21 | 7.8 | unexplained, see below |
| tx_root | 1 | 1 | 0.8 | |
| **sealed_at** | 59 | 82 | 60.6 | |
| par_fold | 9 | 19 | 10.4 | after the seal |
| index | 13 | 21 | 14.5 | beside |

Means add up: 5.0 + 25.2 + 20.9 + 7.8 = 58.9 against `sealed_at` mean 60.6. corr(`sealed_at`, `state_wait`) = 0.81,
corr(`sealed_at`, `par_exec`) = -0.13. Only `par_exec` (35%) is parallel; ~65% is serial or a wait. `sealed_ms` (mean 7.8, p90 21)
is not explained: `seal_block_ms`, `seal_remember_ms`, `seal_hook_ms` are all 0. B at 60 ms: `state_wait` median 4 (mean 8.3),
`sealed_at` median 46, p90 62: at 60 ms the parent's state is ready before the tick; at 50 ms the child waits 20-25 ms for it.

### 20.2 The tail

| | w1 | w2 |
| --- | --- | --- |
| views (consecutive `proposal sent`) | 473 | - |
| cycle median / mean / p90 (ms) | 53.9 / 63.4 / 91.1 | 53.6 / 63.2 / - |
| slow views (> 60 ms) | 173 (36.5%), mean 82.5 | same share |
| other views, mean | 52.3 | |

The tail costs ~11 ms of the mean. 94% of slow views (163/173, both windows) follow a view whose `R1_collect` exceeded 45 ms
(R1 median 71-74 for slow against 24 for fast; corr(cycle, R1) 0.81 / 0.83; of views > 100 ms, 24/26 and 25/27 have R1 > 45).
`R2_collect` is 3 ms and the leader's `verify_us` ~2.9 ms in both groups. `sealed_at` > 55 ms does not discriminate (63% of slow,
55% of fast; corr 0.30 / -0.02). One tenure change in w1 (131.7 ms), none in w2; no periodicity (slow views flat across view
mod 16, gaps between slow views mostly 2). `forest lock waited` warnings in 21% of slow against 17% of fast intervals: no link.
So the tail is the previous view's R1 quorum (the first-vote road), not the seal chain.

### 20.3 `par_exec` parallelism

200,000 x 3.0 us / 20 ms = 30 effective cores. `build_pool` has 32 threads (`N42_PARALLEL_BUILD_THREADS=32` in the runner, default 16
at `parallel_transfer.rs:853`; log `batch_threads=32 batches=128`); the layer at E=1 has 208 CPUs. Batches of 2000 run 4 ms median
(8 max); 128 batches are ~4 waves on 32 threads; `batch_last_start` median 15.6 ms, last end 20.0; dispatch 0.2 ms. The bound is the
pool size, not prep/partition/fold.

### 20.4 What follows (loop351, environment-only, 50 ms, 200k, bookended)

1. BP50 repeated.
2. S1 alone (`N42_CHECK_BEFORE_SLOT=1`; in stage a it cut the first-vote p90 from 29-36 to 3-3.5 ms, the R1 tail of 20.2, and was
   never run alone at 50 ms).
3. S1 + `N42_PARALLEL_BUILD_THREADS=64` (`par_exec` 21 -> ~11 ms if the reads keep up).
4. S1 + S3 (`N42_MERGE_AT_SHARDS_READY=1`, which removes the state wait of 20.1 without S2/S4's CPU competition).
5. S1 + S3 + T64; then a 50 -> 45 -> 40 step-down of the best.

Expected floor with S1+S3+T64: exec ~11 + state ready after seal ~15 + serial ~13 = ~40 ms, the 5M line at 200k if the tail goes.
Runner: `scripts/fleet7-runs/run-loop351.sh`.
