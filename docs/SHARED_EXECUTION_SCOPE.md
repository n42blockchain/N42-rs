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
| `built_executions` store (`take` consumes the build) and `sealed_store` | **Breaks.** The first of k requests takes the own build; the rest, and the leader's own `OWN_BLOCK`, find "unknown build" and fall back to a full import or a payload send. |
| `chain_alias::rename(built_hash, sealed_hash)` (QMDB tree filed under the sealed hash) | **Breaks** for the second taker (warns, imports the ordinary way, so k-1 full executions). |
| `HELD_EXECUTIONS` (hash -> one receiver, `N42_VOTE_BEFORE_SLOT`) | **Breaks** with two requesters (the second insert replaces the first's receiver). Off by default; keep off. |
| `executed_fields` registry (hash -> result), `IMPORT_LANDED`, `HANDED` | Works as is: hash-keyed, EL-wide. A second key's "parent fields equal my EL's result" read hits the same record. |
| Chain slot / build registry in `engine.rs` (`ChainState.slot`, `generation`) | Client-side, one per validator process, so per key. Works: only the leader builds. At a tenure change two keys may each have a chained build on the EL for a moment (1-2 GB each). Handover is where past defects lived (17.7, defect 8): test it, do not assume. |
| Import slot accounting in `h2-execution/src/driver.rs` (`N42_DEFERRED_IN_FLIGHT`) | Per validator process. Works, but k keys ask for k imports of one block, so the EL sees k concurrent imports (the code notes execution inflates with two in flight). |
| Commit `forkchoiceUpdated` per key | Works; k-1 are no-ops on the canonical head (reth fast path). Cost on the engine thread not measured (the real one is 30-36 ms). |
| In-memory/persisted poller, build throttle | Works: k pollers of two cheap RPCs. |
| Queue taken list (`forget_mined`, `hold_own_block`) | Probably idempotent; not verified. Called k times per block today. |
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
