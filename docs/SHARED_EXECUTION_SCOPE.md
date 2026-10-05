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
