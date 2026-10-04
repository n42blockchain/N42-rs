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
