# Industry survey and proposals toward 1.5M TPS (2026-10-04)

Scope: what the fastest chains and storage engines do about consensus/execution decoupling, state,
parallel execution, memory and kernel-side tail latency, dissemination and signatures, and which of it
N42 can use. Written after reading `docs/BREAKTHROUGH_DESIGN.md` (BD), `docs/PHASE_D_DEFERRED_EXECUTION.md`
(PD, section 17), `docs/NATIVE_FLEET7.md`, `docs/SIGNATURE_AND_BATCH_TX_SURVEY.md`,
`docs/BLOCK_SHAPE_SURVEY.md`, `docs/ROADMAP_ED25519_TX.md` and the QMDB comparison documents. Nothing in
this document was run: no cargo, no fleet, no node. Code claims come from `grep` and reading.

How to read the evidence. Each external claim carries a URL. Pages fetched from a project's own
documentation, paper or source are marked (P); claims that reached me only through search-engine summaries
or news and blog coverage are marked (S) and are weaker. My fetch tool summarises pages with a small model,
so a quoted figure is "as summarised from the page", not re-read in the original. Inference is labelled
"Inference". Expected gains are my estimates, not measurements; they are ranges meant to be falsified.

The numbers this survey starts from (BD 10.60-10.63, PD 17): baseline about 1.176M TPS at a mean cycle of
about 137 ms; the 1.5M goal at 163,000 transactions a block needs 163,000 / 1,500,000 = 108.7 ms. The gap
is 28 ms (20%). Chain medians are already under the 100 ms tick; BD 10.44 reads the mean as "the variance of
two ~95-105 ms chains against a 100 ms pacing" (the leader's seal chain and the followers' fields chain),
and BD 10.62 puts 26-30% of on-CPU samples in the kernel (futex-entered syscalls, `madvise`, `sched_yield`,
page faults about 450k/s).

---

## 1. Summary: proposals ranked by expected effect on the 1.5M goal

Every proposal below is a hypothesis with a pre-registered confirming and falsifying measurement. None is
presented as established. The ranking is by expected gain times confidence, not by gain alone.

| # | Proposal | Expected gain on mean cycle | Cost (days, risk) | Confirms | Falsifies | Source of the idea |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Memory-tail program: find what the `madvise`/fault/futex time is (IPIs, off-CPU waits), then a jemalloc matrix (`narenas`, lazy `muzzy` purge, application-scheduled budgeted purge) and pooled output buffers | 4-11 ms (3-8%), low confidence | 4-6 days, low (env knobs, one mallctl hook, pools behind flags) | `/proc/interrupts` CAL/TLB rate and off-CPU stacks tie slow blocks to purge IPIs; then page faults per second down at least 40% at flat resident memory, mean cycle down at least 5 ms over 5 A-B-A repeats, sealed_at p90 and fields p90 down | IPI and off-CPU waits show no relation to slow blocks, or faults fall and the mean does not move (as in loop315) | jemalloc tuning guide (P), mimalloc options (P), Tail at Scale (S), Linux TLB-flush work (S) |
| 2 | Persistence as a bounded, cheaper background: history indices built lazily in batches from the changesets (a mode, never a deletion), tx-lookup pruned or lazy, a real bound on unpersisted blocks (PD 17.4 P1/P5) | 3-7 ms (2-5%), plus removes the unbounded-memory tail | 4-6 days, low to medium | persistence ms/block (batch wall) down from ~97 to under ~50, `storage-*` CPU share down, unpersisted-depth distribution recorded and bounded, fields p90 and seal p90 not worse | persist ms/block falls but the `storage-*` family's CPU and the tails do not change (then persistence is not coupled to the cycle) | reth Storage V2 (P), reth history-rebuild path (P), MonadDb/Firewood versioned stores (P), Zaptos commit stage (P) |
| 3 | Deferral depth D greater than 1: header N carries the result of N-D (Monad: D=3) with a consensus-side nonce and reserve ledger replacing the parent-state includability check; first an offline replay of existing run logs | unknown, 0-12% on the 3-node bench, larger at 7 nodes (quorum is an order statistic; Inference) | replay 2 days; protocol change 15-25 days, high (hard fork, gov5 must match, includability rules, leader handover) | the replay shows the cycle mean falls at least 8% when the follower-fields term is relaxed to a D-block slack | the replay shows the leader seal chain alone sets the mean (cycle barely moves) | Monad docs (P), Sei Giga (P), Zaptos (P) |
| 4 | Thread and wake-up discipline: fewer, persistent rayon pools (build, queue, import, global) with bounded idle spinning, so idle workers stop running the 32-round `sched_yield` loop and each fork-join stops paying a condvar wake | 1-4 ms (1-3%), low confidence | 4-5 days, medium (touches every parallel section) | `perf trace -s` or bpftrace futex and `sched_yield` counts per second fall at least 50% and wake-to-run latency (runqlat) p99 falls; seal and fields p90 fall | counts fall but p90s do not | rayon-core source (P), ForkUnion (S), off-CPU analysis (P) |
| 5 | Bounded flattening of the oldest in-memory bundles behind the new per-block address filters (Geth's diff-layer aggregator pattern), so a read probes at most a small fixed number of layers however many blocks are unpersisted | 0-3 ms, rises when proposal 2 lets the unpersisted depth grow | 2-3 days, low | probe counts per read on the leader's phases line (`overlay skips and probes`) drop and execution time per transfer falls with unpersisted depth 8 to 24 | probes per read already at about 1 at the fleet shape (filters already skip almost everything) | go-ethereum `difflayer.go` (P), commit `e3d7e9495` (code) |
| 6 | Lane-batched Keccak for the fixed-length 0x50 transactions (AVX-512 8-way) in the ingest and frame-root paths, after the asm-keccak build is measured | 0-2 ms on the cycle; 3-8% of node CPU | 3-4 days, low | after `da9f16608`, perf still shows Keccak above about 5% of samples; batched version cuts it at least 2x | asm Keccak already takes it under about 3% | XKCP times8 (S), BD 10.62 |
| 7 | Settlement tags in the RPC and a bounded execution-and-persistence budget (not a TPS lever): `safe` = certified (N+1 voted), `finalized` kept, and Monad-style named states | 0 ms | 2-3 days, low | a wallet test reads N's state certified one block after ordering | none needed; this is correctness and operations | Monad block states (P), PD 17.1 |

Reading the table. Proposals 1 and 2 are cheap, reversible and aimed at the measured bottleneck, so they
go first, and proposal 1's step 0 (naming the kernel time) is a precondition for deciding between 1 and 4.
Proposal 3 is the only structural change that removes a whole term of the cycle (the followers' chain from
the vote path) and the only one whose benefit grows with validator count, which is why it is worth an offline
replay before anyone writes protocol code. The sum of the cheap proposals' optimistic ends is about 20 ms,
which is on the order of the 28 ms gap; the pessimistic ends sum to under 10 ms. I do not claim the goal is
reachable from these alone.

What the industry does not offer. No source I read measures a chain at N42's block shape (163k transfers,
100 ms pacing, three nodes) with a reproducible method. Every throughput figure below is either a project's own
claim or a testnet number on different hardware and workloads; section 8 lists them as such.

---

## 2. Consensus and execution decoupling

### 2.1 What the industry does

Monad. Consensus orders blocks without executing them; each proposal carries the merkle root of the block
three behind (`D = 3`), a mismatch triggers rollback and re-execution, and the delay bounds the execution
lag. Transactions admitted before execution are checked by "reserve balance" rules; the documentation says a
newly funded account cannot send until the funding is three blocks old, about 1.2 s (P:
https://docs.monad.xyz/monad-arch/consensus/asynchronous-execution). Block states are Proposed, Voted
(speculatively final, one block later), Finalized (T+2) and Verified (state root agreed, T+5) (S:
https://docs.monad.xyz/monad-arch/consensus/block-states, read through a search summary). A node may
speculatively execute a proposed block if execution is not lagging (same source). MonadBFT adds tail-fork
resistance by forcing a leader to re-propose a block that gathered enough support (S:
https://www.category.xyz/blogs/monadbft-fast-responsive-fork-resistant-streamlined-consensus).

Aptos. Three post-ordering stages (execute, certify, commit). Zaptos starts all three optimistically on the
proposal and overlaps certification with the last consensus round; on 32- and 64-CPU nodes with 100
validators in 10 regions it reports 160 ms lower latency at low load and 0.5 s lower at 14-20k TPS (P:
https://arxiv.org/html/2501.10612). Raptr removes the quorum-store proof round via "prefix consensus", with
up to 25% lower latency than the baseline and about 15% latency growth at 1% message drops (S:
https://arxiv.org/pdf/2504.18649, search summary). Block-STM v2 is announced as scaling to 256-core
machines; the only source I found is Aptos's own post, so it is a marketing claim (S:
https://x.com/Aptos/status/1839379657122345248).

Sui. Mysticeti v2 merges transaction validation into the DAG commit rule; validators vote explicitly only
for rejections; Sui reports latency down 35% (Asia nodes, about 1.00 s to 0.65 s) and 25% (Europe, 0.55 s to
0.40 s), as observed on its own infrastructure (P: https://www.sui.io/blog/mysticeti-v2-sui-consensus).
Pilotfish scales execution across machines: about 60,000 simple transfers/s on 8 workers of 32 vCPUs, and
"struggles with contended workloads" (P: https://arxiv.org/html/2401.16292).

Sei Giga. Autobahn ordering, asynchronous execution after block finality with state attestations "in a
subsequent block n+x" where x is "bounded by execution timing" (the paper gives no value I could extract),
OCC parallel execution, an LSM flat store with asynchronous writes, a claimed 5 gigagas and sub-250 ms
finality on a 40-node internal testnet (P: https://arxiv.org/html/2505.14914; these are authors' own numbers).

Solana. Alpenglow replaces TowerBFT with Votor (votes off-chain) and later Rotor (single-hop relays with
Reed-Solomon shreds), targeting 100-150 ms finality; it entered public testnet in September 2026 (S:
https://www.anza.xyz/blog/alpenglow-a-new-consensus-for-solana,
https://cryptodaily.co.uk/2026/09/solana-alpenglow-public-testnet-150ms-finality). Firedancer pre-allocates
everything in huge pages and pins one tile per core with no global locks (S:
https://rpcfast.com/blog/what-is-firedancer-solana-validator-client).

MegaETH. A single sequencer keeps state in memory, produces mini-blocks about every 10 ms and EVM blocks
about every second; replica nodes apply state diffs without re-execution, full nodes re-execute (P:
https://docs.megaeth.com/architecture; the 10 ms figures are the project's claims with no stated method).
RISE and Hyperliquid describe similar single-sequencer or tight-pipeline designs; I have only secondary
sources (S: https://www.blocmates.com/articles/what-is-rise-chain-a-beginners-guide,
https://cleansky.io/blog/hyperliquid-architecture-hypercore-hyperevm-2026/). Hyperliquid's quoted median
0.2 s and p99 0.9 s are from such coverage, not a measurement I can reproduce. A recent analysis of block-time
distributions of Hyperliquid and Aptos finds Hyperliquid unimodal and Aptos multimodal, attributing the modes
to deployment heterogeneity, and does not give a tail mechanism (P: https://arxiv.org/abs/2608.01934).

SPICE (Near) and GridSMR were covered in the earlier digest and in PD 17.6; I did not re-read them here.

### 2.2 Settlement states and backpressure, compared

| System | Ordered / voted | Execution certified | What bounds the execution lag | Source |
| --- | --- | --- | --- | --- |
| Monad | Voted at T+1, Finalized T+2 | Verified at T+5 (root of block T carried in block T+3) | `D = 3` in the block validity rule; reserve-balance rules on admission | docs.monad.xyz (P/S as above) |
| Sei Giga | ordering finality | state attestation in block n+x by 2/3+ stake | "bound based on execution timing", value not found | arxiv 2505.14914 (P) |
| Zaptos/Aptos | ordered block | certification vote on `Hash(B.state)` run in parallel with the last ordering round; OptCommitted then Committed in storage | pipeline stages; I did not find the Aptos backpressure thresholds | arxiv 2501.10612 (P) |
| N42 today | vote on N attests N-1's fields equal the voter's own result and N is includable | one block after ordering (PD 17.1) | follower cannot vote on N+1 without N's result (hard, binary, `PARENT_WAIT` 3 s); persistence effectively unbounded (backpressure threshold 1024) | PD 17.1-17.3 |

Comparison. N42 is already a Zaptos-shaped pipeline with the certification folded into the next vote, and
its execution lag is hard-bounded at D = 1, tighter than Monad's 3. That is correct for settlement and is also
why a follower's execution tail lands directly on the vote chain (BD 10.44: vote delay tracks import
backlog with r = 0.65). Monad pays for its larger D with admission rules (reserve balance) that N42's
includability pass does not yet have a form for. The debts N42 does not bound are the ones outside the vote
chain: unpersisted blocks and memory (PD 17.2). The industry sources I found bound these only implicitly;
none gives a threshold I could reuse, so PD 17.4's thresholds remain N42's own to measure.

### 2.3 Usable and not usable

Usable: a configurable deferral depth with a consensus-side nonce and balance-reserve ledger (proposal 3).
Monad's own documentation shows the price: funding must age D blocks before it can be spent. For N42's
flood (pre-funded senders) that price is nil; for production wallets it is a visible rule.

Zaptos's optimistic execution on the proposal: N42 already starts the import after the stateless check and
before its own vote is needed (PD section 11), so the gain Zaptos gets from this is mostly taken.

Not usable at this shape: Autobahn/Mysticeti multi-proposer ordering (section 7), Pilotfish-style distributed
execution (60k tx/s on 8 machines against N42's 1.2M on one), MegaETH replicas applying diffs without
re-execution (needs a trusted sequencer plus provers, which is a different trust model).

Inference. The three-node bench has quorum 2 of 3 (PD 17.5: a faulted follower leaves "exactly the quorum"),
and the leader's own vote needs no wait, so the quorum latency is the faster of two followers. A seven-node
production fleet needs five of seven: the fifth-fastest vote, an order statistic that is more sensitive to
tails. If so, tails matter more in production than the bench shows, which strengthens the case for depth
greater than 1 and for fixing tails before scaling validators. This is reasoning from the quorum rule, not a
measurement; it should be checked on `fleet7.sh` (open question 6).

---

## 3. State storage and commitment

### 3.1 What the industry does

| Engine | Design | History and persistence | I/O | Source |
| --- | --- | --- | --- | --- |
| MonadDb | Patricia trie natively on disk and in memory | persistent (versioned) trie; keeps recent versions, history length adjusts to free disk; sequential writes with inline compaction | io_uring, can bypass the filesystem and use the block device | docs.monad.xyz/monad-arch/execution/monaddb (P) |
| NOMT | binary Merkle trie packed into 4 KB pages plus a flat KV store | page-aligned; "50,000 accounts in 1151 ms" on 2^27 accounts, single-threaded engine (project's figure) | io_uring, NVMe | github.com/thrumdev/nomt (S) |
| Firewood | trie is the on-disk index, compaction-less; "future-delete log" frees nodes when a revision expires | configurable number of revisions in memory and on disk; README says beta | no io_uring mention | github.com/ava-labs/firewood (P) |
| QMDB (LayerZero) | append-only entries plus twig Merkle trees | in-memory indexer, SSD for entries | io_uring in the reference crate | arxiv.org/abs/2501.05262 (S); `docs/QMDB_PAPER_REVIEW.md` |
| reth Storage V2 | hashed state in MDBX; changesets in static files; history indices and tx-hash lookups in RocksDB | indices written per persisted batch; a rebuild path from changesets exists | RocksDB | reth.rs/run/storage (P), reth PR 27314 (P) |
| Sei Giga | flat KV in an LSM, no Merkle tree; commitments are digests of write sets | asynchronous writes after a WAL; cold tier in a columnar store | async | arxiv 2505.14914 (P) |
| MegaETH | SALT (authenticated large trie, IPA/Pedersen commitments), whole authentication structure in RAM | replicas receive diffs; stateless validators use witnesses | memory | docs.megaeth.com (S/P mix) |
| Solana accounts-db | append vecs plus index; Agave 4.0 shipped May 2026 | I found no primary source for a rewrite | | solana.com changelog (S) |

### 3.2 Comparison with N42 and what is usable

State root. N42's QMDB root (Blake3, twig engine, about 30 ms a block) is in gov5's frozen format, so swapping
the engine changes the root. `docs/QMDB_PAPER_REVIEW.md` already concluded: borrow ideas, do not swap. NOMT
was measured by the QMDB paper as slower than QMDB at 4B keys (that document's reading). io_uring: the
LayerZero comparison measured 23.1 s with io_uring against 21.9 s without on the same replay
(`docs/QMDB_LAYERZERO_COMPARISON.md`, section 3), because the bench state is memory-resident. io_uring helps
when state exceeds memory (MonadDb and NOMT are built for that); at the bench's 2M-account shape it is
rejected (section 9) and stays a production-scale item.

History and indexing off the critical path. This is where the industry contrast is sharpest. MonadDb,
Firewood and NOMT make history a property of the versioned structure, so there is no separate index to
write per block. N42's persisted batch pays for three things (PD 17.2): RocksDB history indices about 64 ms a
block, static files about 49 ms, MDBX 0.3 ms (the figures supplied with the task; I could not locate the
breakdown in BD). NATIVE_FLEET7.md around line 7076 found that the RocksDB commit "is the write itself, not the
sync": "163,000 transaction-hash index entries and the history indices into the memtable". So the cost is
memtable work (skiplist splice and comparator, `RocksDBProvider::write_account_history` 4.5-5.6% in BD 10.62's
storage family), and `N42_ROCKSDB_NOSYNC`/`DIRECT_IO` do not remove it.

What is usable: reth itself treats the history index as rebuildable from changesets (PR 27314 describes the
append-only rebuild when the durable checkpoint is zero, P: https://github.com/paradigmxyz/reth/pull/27314).
That fits the project's rule that history writes become a mode and are never deleted
(memory note "gov5 changeset retention"): write changesets (the rollback source) on the persist path, build
the account/storage history indices later in larger batches from those changesets, and prune or lazily build
the transaction lookup. Proposal 2. Note that older runners passed `--prune.transaction-lookup.full`
(`FLEET7_PLAN_V4.md` section 2g, runners loop189-252); `scripts/fleet7-env.sh` has no prune flag and I did not
verify loop316's command line, so whether the baseline pays for the lookup is open question 8.

Zaptos has the same split: the commit stage is last and optimistic (state is persisted as OptCommitted and
upgraded when certified), so storage never gates certification. N42's persistence is likewise beside the
chain; the issue is its cost coupling (CPU, memory, lock hold) and its missing bound, not its position.

Memory and an unbounded batch. None of the engines above gives a policy for "unpersisted blocks grow without
limit"; MonadDb's answer is that history length adapts to disk, which is a retention policy, not backpressure.
N42 needs its own bound (PD 17.4, P1: K = 24 with a hard stop at 48, untested).

Overlay reads. N42's layered in-memory overlay walked every unpersisted block's bundle per read; commit
`e3d7e9495` (2026-10-04) adds per-block split-block Bloom filters (11 bits a key, about 1% false positives).
This is the same device as Geth's snapshot diff layers, each with a filter that lets a miss skip the memory
layers, plus a bottom aggregator that flattens layers at 4 MB or about 95,000 entries (P:
https://raw.githubusercontent.com/ethereum/go-ethereum/master/core/state/snapshot/difflayer.go). N42 has the
filter; it does not have the aggregator, so probes still grow linearly with unpersisted depth. At 8-18
unpersisted blocks that is small; it grows if proposal 2 lets the depth rise. Proposal 5, low value until
measured.

---

## 4. Parallel execution and scheduling

### 4.1 What the industry does

Block-STM and v2 (Aptos): optimistic execution with an ordered commit; 110k and 170k TPS at 32 threads in the
original paper (P/S: https://arxiv.org/pdf/2203.06871, https://aptoslabs.com/pdf/2203.06871.pdf); v2 claims
256-core scaling (S, marketing, above). NEMO (Mysten/academic): static read/write hints plus a greedy commit
rule for owned objects, up to 42% over Block-STM at 16 workers, simulated, with the evaluation hardware not
given (P: https://arxiv.org/abs/2510.15122). Sei Giga: OCC with access-list parsing; "64.85% of Ethereum
transactions can be parallelized" quoted from an external blog (P: arxiv 2505.14914). Pilotfish: per-object
versioned queues across machines (P above). EIP-7928 block-level access lists make the access set a header
commitment: clients prefetch state in parallel and execute non-overlapping transactions together; the EIP
text and community write-ups claim up to 5x faster validation on 6-core machines (S:
https://eips.ethereum.org/EIPS/eip-7928, https://dev.to/etherspot/eip-7928-parallelization-native-privacy-roadmap-eip-8141-deep-dive-ef-restructuring-1fbj).
Reth 2.6.0's release notes report a 39% cut in state-root wait on a 300M-gas BAL workload through storage-trie
job parallelism (S: https://github.com/paradigmxyz/reth/releases/tag/v2.6.0).

JIT/AOT: revmc compiles EVM bytecode to native code; Paradigm shows 1.85x-19x on contract benchmarks, and the
BNB Chain write-up reports up to 6.9x on compute-heavy workloads with state-heavy ones "limited by bridge
crossings" (S: https://www.bnbchain.org/en/blog/a-technical-deep-dive-on-the-jit-aot-compiler-for-revm-of-bnb-chain).

### 4.2 Comparison with N42

N42's execution is already the thing these systems approximate. Transfers run through a native path
(`crates/n42/engine-types/src/parallel_transfer.rs`) in per-sender groups on a 16-thread pool and are grafted
onto block state; BD 10.22 measured 1.26 us a transfer alone and 2.5 us under sixteen threads, so a 163k block
is about 30-40 ms of execution (BD 10.45: exec 38-40 ms in the leader's seal, 44 ms in the followers' fields). A sender-
partitioned schedule needs no speculation and no re-execution for transfers, so Block-STM-style OCC buys
nothing here and NEMO's hints are what the sender groups already are.

Nothing in revmc applies: a transfer executes no bytecode. It matters only for a contract-heavy workload,
which is not the 1.5M target (`docs/BLOCK_SHAPE_SURVEY.md`).

BAL deserves one honest look. N42's "design A" (a read-set resolve pass before execution) was measured and
rejected because the pass costs more than it saves (BD 10.20). A BAL moves that work to the leader, which
already knows every address it touched, so the follower pays only the prefetch. But it costs header bytes
(a full 163k block touches about 147,000 accounts, `docs/BLOCK_SHAPE_SURVEY.md` and round 43 in `NATIVE_FLEET7.md`: a list of that many addresses with post-values
is megabytes) and a header-format change on both clients. It is rejected for now (section 9) and listed as a
question only if the follower's reads become the dominant term again (BD 10.24 says the view's lock fix already
took the 16-thread read from 2.11 to 0.57 us).

---

## 5. Memory and kernel-side tail latency (the deepest section)

This is N42's measured bottleneck: 26-30% kernel samples, 450k page faults/s, IPC 0.84, jemalloc purge thread
4-5% of samples and 96-97% kernel, futex-entered syscalls about 43-50% of syscall entries and `madvise` 22-24%
(BD 10.62). What BD rules out: THP compaction, writeback, memory pressure, node-specific effects. What it
leaves open: why a given block is slow (the profile is a 30 s average).

### 5.1 What the evidence and the sources say

jemalloc mechanics. Pages go dirty then muzzy then clean; the first step uses `MADV_FREE` and the second
discards (S: https://github.com/jemalloc/jemalloc/issues/521 and the Debian man page). With `muzzy_decay_ms:0`
(N42's setting, `scripts/fleet7-env.sh` lines 188 and 244) dirty pages go straight to forced discard
(Inference from the documented semantics): the next touch is a fresh zero-fill fault. `MADV_DONTNEED` always
faults on the next touch; `MADV_FREE` normally does not unless the kernel reclaimed the page (S, same
sources). jemalloc's tuning guide: background threads "generally improve the tail latency for application
threads since purging is shifted"; fewer arenas often improve memory use; `metadata_thp` reduces TLB misses;
shorter decay trades memory for CPU (P: https://github.com/jemalloc/jemalloc/blob/dev/TUNING.md). Release 5.3.1
(Meta's renewed investment, March 2026) adds `process_madvise` use with a batch option, `calloc_madvise_threshold`
and hugepage-size reporting; the HPA remains experimental (P:
https://github.com/jemalloc/jemalloc/releases, S: https://engineering.fb.com/2026/03/02/data-infrastructure/investing-in-infrastructure-metas-renewed-commitment-to-jemalloc/).
N42's build links jemalloc 5.3.0 (`tikv-jemalloc-sys 0.6.1+5.3.0-1`, `Cargo.lock`), so it lacks those options.

Kernel mechanics. `MADV_FREE` and `MADV_DONTNEED` use the per-VMA read lock rather than `mmap_lock` in
current kernels, per patches that extend the same to `MADV_COLD`/`MADV_PAGEOUT` (S:
https://ratatoskr.run/linux-mm/2026/07/17281362; I did not read the merge in a kernel tree). The host runs
Linux 7.0.0-31 with `CONFIG_PER_VMA_LOCK=y` (read from the running kernel's config). So `mmap_lock` is probably not the
hot lock in `madvise` on this host. What `madvise(DONTNEED)` and `MADV_FREE` still need is a TLB flush. On
x86 without broadcast invalidation that is an inter-processor interrupt to every CPU in the process's
mask; AMD's `INVLPGB` broadcast flush (merged for 6.15, used only for processes active on 3 or more CPUs,
cutting TLB-invalidation CPU time "from 40% to around 4%" on a Milan test) removes the IPIs (S:
https://www.phoronix.com/news/AMD-INVLPGB-Ready-For-Linux, https://lwn.net/Articles/1008298/). This host is
bare metal (no `hypervisor` flag; `systemd-detect-virt` says none), an EPYC 9B45 with 16 L3 instances, and
`/proc/cpuinfo` lists no `invlpgb` flag, so (Inference) its flushes are IPI-based. `/proc/interrupts` shows
15.2 billion CAL (function-call IPI) events since boot against 163 million TLB events in 10.4 days, about
17k CAL/s on average over a box that is mostly loaded; on newer kernels TLB flush IPIs are issued through
the call-function path, so CAL is the counter to watch (Inference; I sampled only an idle five seconds).
Kernel symbols and the hot instruction BD 10.62 saw (6-8% of samples, reached from both `madvise` and page
faults) fit IPI-wait spinning or a page-table lock, but BD says that is a reading, not a measurement, and I
agree.

Futex and `sched_yield`. rayon-core's idle worker calls `yield_now()` for 32 rounds, announces sleepiness,
yields once more and then blocks on a condvar; waking a sleeper takes a mutex and `notify_one` (P:
https://raw.githubusercontent.com/rayon-rs/rayon/main/rayon-core/src/sleep/mod.rs). N42's repository builds at
least five rayon pools (global from reth node startup, the 16-thread build pool, the tx-queue pool, the
follower-import pool, the QMDB read view's), each with its own idle workers (`ThreadPoolBuilder` sites in
`parallel_transfer.rs:663`, `tx-queue/src/lib.rs:330`, `follower_import.rs:3362`,
`node/builder/src/launch/common.rs:240`). BD 10.62's `__sched_yield` at 3-6% of syscall entries and the futex
share are what this design produces (Inference: BD did not see the syscall number, as it notes). Kernel 6.16
and later also give each process a private futex hash sized by thread count (S:
https://manpages.ubuntu.com/manpages/stonking/man2/PR_FUTEX_HASH.2const.html), which should reduce collisions
here; it is not a lever.

Page-fault volume. 450k faults/s at 4 KiB is 1.84 GB/s of first-touch memory per node
(450,000 x 4,096; arithmetic). Whether BASE legs use huge pages is unclear: the BASE `MALLOC_CONF` in BD 10.63
is `thp:always,oversize_threshold:0,dirty_decay_ms:2000,background_thread:true` (it does carry a `thp` token: the
BASE legs run with `thp:always`), and the host's THP mode is `madvise` with `defrag=defer`. Open question 4. BD 10.48
and 10.54 already removed the QMDB root's own faults with pooled twig trees, a populated append buffer, a
scratch set and an undo pool (`crates/n42/twig-core/src/prefault.rs`); BD 10.62 lists `rayon collect` frames
as 7-17% of fault entries, which is what is left.

### 5.2 Allocator choices at this scale

| Option | What it offers | Cost or risk | Evidence |
| --- | --- | --- | --- |
| jemalloc as is (2 s dirty decay, `muzzy:0`, bg thread, default arena count) | known baseline | periodic forced purge (IPI), faults after each purge | BD 10.62-10.63 |
| jemalloc, fewer arenas (`narenas:N`) | fewer dirty caches, better reuse; guide says lower counts usually improve memory | more lock sharing between threads; not tested in the repo (grep: no `narenas` in BD or NATIVE_FLEET7 outside the `lean` profile) | TUNING.md (P) |
| jemalloc with `muzzy_decay_ms` above 0 | the first purge step becomes `MADV_FREE`: no fault on reuse unless the kernel reclaimed the page, and the kernel may take it back under pressure instead of the node running out | RSS stays high until reclaim; observability of RSS misleading | man page and issue 521 (S) |
| jemalloc long dirty decay | halves faults (BD 10.63: 407-455k to 211-239k at 30 s) | 41-51 GB resident, one leg at 2.1 GB available | BD 10.63 |
| jemalloc, long decay on hot arenas plus application-triggered purge under a memory budget | bounded version of the line above | needs a `mallctl` hook; none exists (no `jemalloc_ctl` use outside reth's metrics) | mallctl API; repo grep |
| jemalloc `thp:always` plus `hugeprep` | 2 MB pages cut fault count | reclaim storms and bimodal windows (BD, project notes); bench already runs `hugeprep.py` | NATIVE_FLEET7 |
| mimalloc | purge delay and eager arena commit are options (`MIMALLOC_PURGE_DELAY`, default 1000 ms in v3; `ARENA_EAGER_COMMIT`), and it can reserve 1 GiB huge pages at start | a whole-allocator swap in a reth graph; no repeatable benchmark on this workload found | mimalloc docs (P) |
| Firedancer-style pre-reserved hugepage workspaces, no allocation in the hot path | removes the problem | needs the hot data in owned regions, not `Vec`/`HashMap` from revm and reth | Firedancer coverage (S) |

My reading: the single un-tried jemalloc axis with a plausible mechanism is "make purge rarer and keep it under
a budget" rather than "make decay longer": hot arenas keep their pages, and a small piece of node code
purges only when `MemAvailable` falls under a floor or in an idle point after the seal. BD 10.63 says its own
decay result is not established (the BASE leg of that round read 836k, an outlier against 1.18M in loop312-313),
so I treat "a longer decay" as not yet decided, not falsified, and I do not re-propose it as such. What is new
is a bounded purge, a lazy `muzzy` step, and an arena count; each is an environment or a few lines.

### 5.3 What to do and in what order (proposal 1 in detail)

Step 0, measurement only (about 1 day). On one leg: read `/proc/interrupts` CAL and TLB rows each second and
align to block times; `perf trace -s` (or bpftrace) counting `futex`, `madvise`, `sched_yield` by thread
name; the off-CPU analysis recommended by Gregg, because on-CPU profiles miss blocked time ("off-CPU analysis
is complementary to CPU analysis so that 100% of thread time can be understood") and BD 10.38's "waits, not
work" says the seal chain is waiting (P: https://www.brendangregg.com/offcpuanalysis.html). Cost warning from
the same source: tracing scheduler events can cost 6-13% throughput at high event rates, so run it for short
windows and treat the leg as diagnostic only. Kernel symbols need `sudo` (BD's own next step).
Dean and Barroso's rule applies to what comes next: tail latency comes from many small sources, and
background activity is best synchronized into one short burst rather than scattered (S:
https://www.andrew.cmu.edu/course/14-848-f18/applications/ln/14848-l23.pdf).

Step 1 (about 2 days): a leg matrix, five repeats each, A-B-A, with the box quiet, over `narenas` (default,
16, 8), `muzzy_decay_ms` (0, 5000), and background thread on or off. Step 2 (about 2 days): a node-side
`mallctl` hook that purges only under a floor or at a named point after the seal, on top of a long dirty
decay in the hot arenas. Step 3 (about 2 days): pooled output buffers for the `collect` sites BD 10.62 names,
reusing capacity instead of allocating 16 MB-class vectors per block (the repository already has
`N42_FOLLOWER_FREE_ASYNC`, off by default, worth "5-6 ms of a 120 ms call" on an idle bench per the code
comment at `parallel_transfer.rs:3584`; the freeing cost is real and the pools remove it instead of moving it
to another thread, which BD 10.39 found "moved, did not shrink").

Gain estimate: faults from 450k/s to about 250k/s and the purge IPIs mostly gone. Kernel share from 26-30%
toward about 18-22%. If a quarter of that share sits on the critical chains, that is 3-8% of wall. The loop315
result that halving faults left tails unmoved is the evidence against; that is why step 0 comes first.

### 5.4 NUMA, CCDs and cores

The host is one NUMA node with 16 L3 instances (512 MiB total, 32 MB per 8-core CCD on Zen 5; the Zen 5
figure is from https://www.tomshardware.com/pc-components/cpus/new-zen-5-128-core-epyc-cpu-weilds-512mb-of-l3-cache,
S). `scripts/fleet7-env.sh` pins each node to physical cores plus siblings (32 logical CPUs for 16 physical
cores); that is 2 CCDs a node if the offsets are CCD-aligned, which I did not check. BD 10.61 found core
isolation did not flatten tails or move the mean, so I do not re-propose it. Cross-CCD cache-line transfer is
about 90-110 ns on Milan against about 23 ns within a CCD in one community measurement (S:
https://ratatoskr.run/linux-rt-users/2026/04/3537048/t); I found no Zen 5 number. Question 5: are a node's
pools confined to whole CCDs? The host also exposes `cat_l3`, `mba` and `cdp_l3` flags (resctrl cache and
bandwidth allocation); that is measurement hygiene against noisy neighbours (the box is shared, load average
about 68 when I checked), not a product lever.

### 5.5 Thread pools and wake-ups (proposal 4)

Idle spinning via `yield_now` is cheap per call but it is 32 syscalls per idle worker per wake cycle, across at
least five pools. ForkUnion (S: https://github.com/sub4biz/ForkUnion) claims a fork-join pool with no
syscalls or CAS on the hot path using hardware wait instructions; x86 `UMWAIT` is an Intel feature, the host
shows AMD `mwaitx`, and the claim is the README's own, so I treat it as unverified. The portable move is the
smaller one: one persistent gang pool sized to the physical cores of the node, shared by build, queue and
import sections, so workers do not park and unpark per section. Because nodes use only about 31% of their CPUs,
spinning is affordable, which is exactly why the claim "futex is the tail" must be checked by wake-to-run
latency (`runqlat`) first, not assumed.

---

## 6. Signatures and verification

N42's Ed25519 type 0x50 with batch verification (`N42_ED25519_BATCH`, sender cache) is in place
(`crates/n42/tx-types`, `docs/SIGNATURE_AND_BATCH_TX_SURVEY.md`; the earlier survey is Chinese and I did not
repeat it). What new sources add:

BLS. N42's HotStuff-2 runs 3-7 validators, so aggregate verification is a handful of pairings per round; the
cost is not on the 28 ms path and I found nothing that changes that. At 100+ validators it would matter
(Zaptos aggregates certification signatures across 100 validators, P above).

Batch Keccak. BD 10.62 attributes the software `keccak_p` backend about 11.5% of samples, in the tokio ingest
threads (transaction hashes, frame roots). Commit `da9f16608` (2026-10-04 00:01) turns on the assembly backend
for the n42 binary; `Cargo.lock` shows `alloy-primitives` and `keccak-asm` both depend on `sha3`/`keccak`,
which is the fallback that produced the symbol. Whether the symbol is gone is not yet measured. The 0x50
transactions are fixed-length, the one precondition of XKCP's 8-lane AVX-512 permutation (S:
https://github.com/XKCP/XKCP and a Go wrapper noting "all non-nil inputs must have the same length"), and this
host has AVX-512. Proposal 6, only if Keccak is still visible after asm.

Post-quantum. Ethereum's direction is hash-based XMSS signatures (about 3,000 bytes against 96 for BLS) with
a zkVM aggregation that puts one proof in the block (S: https://pq.ethereum.org/,
https://hackmd.io/@tcoratger/S1t-qhPFJx). For N42 the relevant point is that 0x50 (`AltSig`) is already the
extension point for a post-quantum transaction signature; a validator-vote PQ migration is a roadmap item with
no effect on the 1.5M goal, and the earlier digest's ark-pq covers the library side.

---

## 7. Block dissemination and networking

Monad's RaptorCast sends a block as UDP chunks (1,480-byte MTU, 1,220-byte payload, 1,640 source chunks for a
2 MB block), redundancy 2.5x, over a two-level tree per chunk with stake-weighted assignment (P:
https://docs.monad.xyz/monad-arch/consensus/raptorcast). Solana's Rotor uses single-hop stake-weighted relays
with Reed-Solomon shreds (S, above). Autobahn separates a data layer that "always makes progress" from a
low-latency consensus layer on snapshots, matching Bullshark's throughput at about half its latency (S:
https://dl.acm.org/doi/10.1145/3694715.3695942), and Sei Giga ships it.

N42's position: the body goes over libp2p gossipsub on TCP to a few validators; `NATIVE_FLEET7.md` section "Two
transports that are not the problem" measured the wire encode and decode at 4.03 ms for a 22,857-transaction
block and found the body's arrival (27.8 ms) mostly propagation. On the 3-node loopback bench this is not the
cycle's term, and at 163k transactions a body is about 26 MB of RLP (BD 10.36), so geo-distributed
production is where erasure-coded multicast earns its place: with a 26 MB body and a seven-node fleet, the leader
uploading six copies is the cost RaptorCast's tree removes. That is a production-scale item, not a bench lever.
Not usable at the bench: DAG mempools and multi-proposer lanes (the supply is one generator and one leader per
tenure; section 9).

QUIC against TCP. `NATIVE_FLEET7.md` around line 3769 notes gov5's leader unicasts over QUIC, and around line
4322 that the UDP receive-buffer ceiling is "a QUIC problem". No source I found measures QUIC against TCP at
this block size on loopback; skip.

---

## 8. Other findings bearing on the tail and persistence

1. Tails are an order statistic of the quorum (section 2.3, Inference), which makes 7-node tails worse than
   the 3-node bench's; the 1.5M goal measured on three nodes may not carry to seven.
2. Monad's "Voted" state is speculative finality one block after proposal, with execution speculative at
   proposal time. N42's `safe`/`finalized` tags are one hash (the last committed block, PD 17.1), weaker than
   either Monad's Finalized or Verified. Cheap and correct to fix (proposal 7); no TPS effect.
3. Hedged and tied requests (Dean and Barroso) need duplicate capacity at the slow step; N42's slow steps are
   single-leader chains. Not applicable except for the one place already used (give-back of a stale parent).
4. The throughput figures in this survey are unreproduced claims: Pilotfish 60k tx/s (own paper), Sei Giga 5
   gigagas and sub-250 ms (own paper, internal 40-node net), Zaptos 20k TPS (own paper), Hyperliquid 0.2 s median
   (coverage), MegaETH 10 ms (project claim), Block-STM v2 256-core scaling (project post), NOMT 43k updates/s
   per thread (README claim). None is evidence about N42's shape; all are context.

---

## 9. Ideas considered and rejected

| Idea | Why rejected | Source |
| --- | --- | --- |
| io_uring for QMDB reads and writes | measured: 23.1 s with io_uring against 21.9 s without on the LayerZero replay; bench state is memory-resident. Revisit at state far above memory | `docs/QMDB_LAYERZERO_COMPARISON.md` section 3 |
| Swap QMDB for NOMT, Firewood or MonadDb | root is gov5's frozen format; NOMT measured slower than QMDB by the QMDB paper review; Firewood is beta | `docs/QMDB_PAPER_REVIEW.md`, Firewood README (P) |
| Block-STM v2, NEMO or any OCC scheduler | sender-partitioned groups need no speculation for transfers; contention is only recipient credits, already grafted | BD 10.22, parallel_transfer.rs |
| revmc or other JIT/AOT EVM | a transfer runs no bytecode | BNB/Paradigm figures are for contract benchmarks (S) |
| BAL (EIP-7928) as a header commitment | design A (read-set resolve) lost in BD 10.20; a BAL moves its cost to header bytes and a two-client format change; reconsider only if follower reads dominate again | eips.ethereum.org (S) |
| Pilotfish-style multi-machine execution | 60k tx/s on 8 machines against 1.2M on one | arxiv 2401.16292 (P) |
| MegaETH-style replicas applying diffs without re-execution | needs a trusted sequencer and asynchronous provers; breaks replicated-execution trust | docs.megaeth.com (P) |
| DAG mempool, Autobahn, Mysticeti multi-proposer | three to seven validators, one flood source; the data layer's throughput is not the limit (BD 10.46: the supply is about 1.2M/s) | BD 10.46 |
| Erasure-coded multicast (RaptorCast, Rotor) on the bench | wire cost is 4 ms of encode and decode; loopback propagation, not coding | NATIVE_FLEET7 transport section |
| Swapping to mimalloc as a whole | no repeatable benchmark on this workload; a graph-wide risk. Allowed as one arm of the proposal 1 matrix only | mimalloc docs (P) |
| Arena-per-block bump allocation | revm and reth own their `Vec` and `HashMap` types; custom allocators there are an invasive, cascading change in vendored crates | CLAUDE.md fork boundary |
| Hugetlbfs or 1 GiB page reservation for the whole heap | jemalloc does not use it; mimalloc's reservation is an allocator swap; THP `thp:always` already cost reclaim storms | mimalloc docs (P), project notes |
| ForkUnion-style UMWAIT pools | `UMWAIT` is Intel; the host is AMD; unverified README claim | github.com/sub4biz/ForkUnion (S) |
| Core isolation, pacing changes, larger blocks, output shards v1/v2, build-ahead at seal, tighter view timeout, read-set design A, dense ids | already falsified per the task brief and BD 10.8-10.61 | BD |
| MegaETH SALT (IPA commitment) | elliptic-curve work per key against a 30 ms Blake3 root; different commitment | docs.megaeth.com (S) |
| Post-quantum validator signatures now | no effect on the 28 ms gap; 3-7 validators | pq.ethereum.org (S) |

---

## 10. Open questions that need a measurement on the fleet

1. What is the kernel time? Hot kernel symbols (`perf record -a` with kallsyms under `sudo`), the CAL and TLB
   IPI rate per second against block times, `perf trace -s` counts of `futex`/`madvise`/`sched_yield` by
   thread name. Decides proposals 1 and 4. Diagnostic only; do not use as a throughput leg.
2. Off-CPU stacks of the leader's seal chain and a follower's fields chain on slow against fast blocks
   (offcputime or `perf sched timehist`), and run-queue latency (`runqlat`) p99. Does any wait sit behind a
   futex, a page fault, or an IPI?
3. Offline replay of loop logs: if the follower-fields term were relaxed to a two-block slack, how far does
   the cycle mean fall? Needs per-block `fields_ready`, `sealed_at`, and vote times from the existing run
   directories. Decides proposal 3 before any protocol work.
4. Do BASE legs run with `thp:always`? Read `MALLOC_CONF` from the node environment and `AnonHugePages`
   in `/proc/<pid>/smaps_rollup`; split the 450k faults/s into 4 KiB and 2 MB.
5. Are each node's pools confined to whole CCDs (offsets multiple of 16 physical cores)? Was the pinned
   range aligned in loop312-316?
6. Quorum order statistic: run the same leg with seven nodes (`scripts/fleet7.sh`) and compare the vote
   delay distribution with three. Does the tail get worse as the fifth-fastest vote governs?
7. Persistence: the per-batch wall time distribution, the unpersisted-block depth (needed for PD 17.4's K),
   and `storage-*` CPU with history indices deferred (a mode flag in the provider's save path).
8. Does the loop316 command line include `--prune.transaction-lookup.full`? Older runners did.
9. After `da9f16608`, does `keccak_p` vanish from the profile? If the share is under about 3%, drop
   proposal 6.
10. Probes per read at unpersisted depth 8, 18, 24 (the leader's phases line now prints overlay skips and
    probes), to decide proposal 5.
11. Does `muzzy_decay_ms:5000` (lazy `MADV_FREE`) reduce faults at flat `MemAvailable`, and does the kernel's
    reclaim of lazily freed pages produce the page-cache pressure that thp:always caused?
12. Seven-node memory: at 1.5M TPS the unpersisted blocks hold about 30 MB of QMDB record a block (PD 17.3);
    what is the depth at which `MemAvailable` crosses the floor on a persistence-delayed leg (PD 17.5 B)?

---

## Sources

Fetched from the project's own documentation, paper or source (P):
https://docs.monad.xyz/monad-arch/consensus/asynchronous-execution;
https://docs.monad.xyz/monad-arch/execution/monaddb;
https://docs.monad.xyz/monad-arch/consensus/raptorcast;
https://arxiv.org/html/2501.10612 (Zaptos); https://arxiv.org/html/2505.14914 (Sei Giga);
https://arxiv.org/html/2401.16292 (Pilotfish); https://arxiv.org/abs/2608.01934;
https://arxiv.org/abs/2510.15122 (NEMO); https://www.sui.io/blog/mysticeti-v2-sui-consensus;
https://docs.megaeth.com/architecture; https://github.com/ava-labs/firewood;
https://reth.rs/run/storage/; https://github.com/paradigmxyz/reth/pull/27314;
https://github.com/jemalloc/jemalloc/blob/dev/TUNING.md; https://github.com/jemalloc/jemalloc/releases;
https://microsoft.github.io/mimalloc/environment.html;
https://raw.githubusercontent.com/rayon-rs/rayon/main/rayon-core/src/sleep/mod.rs;
https://raw.githubusercontent.com/ethereum/go-ethereum/master/core/state/snapshot/difflayer.go;
https://www.brendangregg.com/offcpuanalysis.html.

Search-summary or secondary only (S): the remaining URLs cited inline, including the Monad block-states page,
MonadBFT, Raptr, Block-STM v2, Alpenglow, Firedancer, RISE, Hyperliquid, EIP-7928, revmc, Autobahn, INVLPGB,
per-VMA madvise patches, futex private hash, XKCP, pq.ethereum.org, ForkUnion, Tail at Scale, NOMT and the
QMDB paper. Their figures should be re-read in the original before they are quoted elsewhere.

Local facts (grep or read in this tree): `bin/n42/Cargo.toml` (asm-keccak default), `Cargo.lock` (jemalloc
5.3.0, rayon-core 1.13.0), `scripts/fleet7-env.sh` (`MALLOC_CONF`, pinning, persistence flags),
`crates/storage/provider/src/providers/rocksdb/provider.rs` (`N42_ROCKSDB_NOSYNC`, `DIRECT_IO`),
`crates/n42/twig-core/src/prefault.rs`, `crates/n42/engine-types/src/parallel_transfer.rs`, commits
`e3d7e9495` and `da9f16608`, and the host's `/proc/cpuinfo`, `/proc/interrupts`, `/proc/vmstat`,
`/sys/kernel/mm/transparent_hugepage/*`.

---

## 11. Deferral depth replay (loop316 logs)

Question: what would the cycle have been if header N carried the result of block N-D, for D = 2 and 3, on logs
already taken? Answer from three judged legs (NEW, FOFF, NEWb of loop316, window 1, 218-222 full blocks each,
3-node fleet, 100 ms pacing, 163,000 transactions a block): **the same cycle.** D = 2 and 3 change the mean
by 0.0 to -0.3%, because at D = 1 the parent's result is almost never the wait that sets the cycle. The script is
`scripts/fleet7-depth-replay.py`; it reads `node<i>-v.log` and `node<i>-el.log` and nothing else.

### 11.1 Method

Window 1 is the 30 s after the first full body, in the first leader's tenure (node 0 in all three legs). Per block
the logs give, on the leader: the proposal's preamble time, `tick_late_us`, `take_sealed_us`, the leader's own commit
of the previous block, and the EL's `seal-first build phases` (build start, `par_ms`, `sealed_at_ms`,
`state_ready_ms`); on each follower: the body arrival (`import starting`), the vote time, and the direct-import
line's `exec_start_ms`, `exec_end_ms`, `fields_ready_ms` and `road_end_ms`. Block view V is EL number V-1.

What the logs show about the waits at D = 1 (measured, not assumed):

- A follower's vote on V is `max(body + check, F(V-1))`. In window 1 the vote came 4 to 8 ms or more after the parent's
  fields were ready in every block of every leg (NEW: minimum margin 3.8 ms, p10 42-46 ms, median 83-89 ms; one
  `parent_wait_ms` above zero in 436 votes). The check itself, 12-70 ms, is the vote delay.
- The leader's seal of V is `start + max(par_ms, R(V-1) - start) + about 1 ms`, where `R` is `state_ready`. This fits to
  within 5 ms for the median block. The parent term is the larger one in 2, 3 and 6 of about 220 blocks.
- The proposal is `max(previous proposal + 100 ms tick, previous commit + 3 ms, the sealed header in hand) + about 2 ms`.
  The sealed header reaches the proposer 55-290 ms after `sealed_at` (the build-ahead's encode and hand-off).
- The leader's chained build starts either at the previous seal (`build_start_trigger="seal"`) or, in 29-40% of blocks
  (63-88 of 220), at the previous *send* (`"send"`). The second is the one-ahead slot of `crates/n42/h2-el-rpc/src/engine.rs`: "the
  sealed build has not been taken; its successor starts when it is". It is a rule about the build slot, not about a
  result.

The replay (`simulate` in the script) recomputes, for D = 1, 2, 3, the leader's start, seal and proposal, each follower's
body arrival, vote, execution and fields-ready times, and the quorum, with `result(N-D)` in the leader's seal and in the
follower's vote. Every per-block duration is the measured one (`par_ms`, `state_ready_ms`, build-start delay,
hand-off, body offset, check time, execution time, root time). Execution is serial per node (execution starts after
the previous block's execution ends; the root after the previous block's root). The gating constants are medians
(tick 100-101 ms from the previous send, commit-to-preamble floor 6-8.5 ms, send overhead 2.5 ms, vote-to-commit
transit 17-20 ms, execution start 15-16 ms ahead of the check's end because the execution begins beside it). The first four blocks of the window keep their measured times.

### 11.2 Validation at D = 1

| Leg | Measured mean cycle | Model D = 1 | Error |
| --- | --- | --- | --- |
| NEW | 136.7 ms | 136.5 ms | -0.1% |
| FOFF | 135.5 ms | 135.3 ms | -0.2% |
| NEWb | 137.1 ms | 136.7 ms | -0.3% |

Passed (the bar was a few percent). The medians and p90s agree to 3-8% (model median 124.1 / 124.7 / 120.2 ms
against 128.5 / 125.5 / 122.3; p90 188.9 / 177.1 / 188.8 against 190.4 / 184.0 / 192.3). Honest limit: the model is fed
every duration the nodes measured, so a pass shows the gating structure (tick, previous commit, seal, vote) accounts for
the cycle, not that the durations are independent of D. Measured here means the mean of consecutive proposal-to-proposal
intervals, 0.5 ms above `cycles.txt`'s 136 ms because the window edges differ.

### 11.3 Result

Cycle in ms (mean / median / p90) and implied transactions per second at 163,000 a block:

| Leg | D = 1 (model) | D = 2 | D = 3 |
| --- | --- | --- | --- |
| NEW | 136.5 / 124.1 / 188.9, 1.194M | 136.5 / 124.1 / 188.9, 1.194M | 136.5 / 124.1 / 188.9, 1.194M |
| FOFF | 135.3 / 124.7 / 177.1, 1.205M | 135.2 / 124.7 / 177.1, 1.206M | 135.2 / 124.7 / 177.1, 1.206M |
| NEWb | 136.7 / 120.2 / 188.8, 1.193M | 136.3 / 117.6 / 188.5, 1.196M | 136.3 / 117.6 / 188.5, 1.196M |

What gates each block's proposal at D = 1 (share of blocks, mean cycle of that class):

| Gate | NEW | FOFF | NEWb |
| --- | --- | --- | --- |
| Pacing tick | 53.9%, 107 ms | 55.7%, 113 ms | 55.0%, 109 ms |
| Leader seal, build waits for the previous send (one-ahead slot) | 38.8%, 173 ms | 28.1%, 171 ms | 35.3%, 175 ms |
| Leader seal, own build (`par_ms`) | 4.6%, 152 ms | 12.7%, 154 ms | 7.8%, 163 ms |
| Quorum of the previous block (vote path) | 2.7%, 166 ms | 3.6%, 134 ms | 1.8%, 135 ms |
| of which the leader's seal waited for its own parent result | 2 blocks | 3 blocks | 6 blocks |
| of which a follower's vote was set by its parent result | 0 | 0 | 0 |

The excess of the cycle over the 100 ms tick (about 36 ms a block) is the one-ahead slot and the leader's own build,
neither of which depends on D.

Execution lag, follower fields-ready minus proposal time, in window 1: mean 79-83 ms, p90 100-103 ms, growth +0.02 to
+0.07 ms per block measured and +0.00 to +0.06 in the replay at every D. Execution (40-42 ms) plus root (30-31 ms) per
block is 70-73 ms against a 136 ms cycle, so execution does not fall behind ordering in this window; D = 2 and 3 do
not change that because they do not change the cycle. The backpressure cost of deferral is therefore not visible in
these logs, because the logs contain no regime in which execution is the slower stage.

Two extrapolations, both beyond what was measured and shown only to find where D would start to matter:

| Scenario (model, one-ahead slot lifted: a build starts at the previous seal) | D = 1 | D = 2 | D = 3 |
| --- | --- | --- | --- |
| 100 ms tick | 102.8 / 104.8 / 103.3 ms | same | same |
| tick 50 ms or none (cycle then set by the leader's own seal chain) | 85.6 / 96.5 / 90.5 ms | 82.2 / 94.3 / 88.3 ms | 82.2 / 94.3 / 88.3 ms |

(NEW / FOFF / NEWb.) With the slot lifted and the tick removed, D = 2 buys 2-4% and D = 3 nothing more; the lag slope stays
+0.01 to +0.07 ms per block because execution (70 ms) stays below the 82-97 ms cycle. Lifting the slot alone is worth
more than any D here: about 103 ms against 136 ms, 1.55-1.59M transactions per second against 1.19-1.20M in the model,
if the build's `par_ms` and hand-off survive the extra overlap (not shown by these logs; the follower and leader
share cores).

### 11.4 What the model cannot see

- Quorum. The bench is 2 of 3 with the leader's own vote, so the quorum is the faster follower. A rough 5-of-7 check
  (leader plus the fourth fastest of six followers, each vote delay drawn independently from the measured pool) gives
  the same cycle as the 3-node replay at every D (136.5 / 135.3 / 136.7 ms for NEW / FOFF / NEWb at D = 1): the quorum gates 2-4% of blocks here and a slower fifth voter
  would only matter if its tail exceeded the 100 ms tick. That check assumes independent delays, no fan-out cost for
  seven peers and no tail beyond window 1; it is not a measurement. `fleet7.sh` is the place to check it (open question 6).
- Window 1 only. Windows 2 and 3 of the same legs show the cycle at 163-196 ms and occupancy falling (BD 10.60-10.64),
  and the tails of execution (whole-round follower payload-to-canonical p99 436 ms, max 738 ms in `phases.txt`) are where `F(V-1)` would set the vote
  and D would help. Window 1 has no follower vote set by its parent result, so it cannot show that gain. A replay of
  windows 2 and 3 on the same legs is the obvious next check; it needs the same script with the window changed.
- Durations are held as measured. Under D > 1 the leader's build and the follower's execution would overlap more with
  the next block's check and build; contention among them (the leader's par phase against its own parent's roots,
  followers' check against execution) would lengthen the measured durations and is not modelled.
- Admission. At D > 1 the includability pass of PD section 11 cannot read the parent's post-state, since it is not
  settled; the replay keeps the measured check time, which is the optimistic case. Monad's reserve-balance rule
  (section 2.3) is what makes that possible, and this replay does not price it.
- Execution lag against backpressure. Execution never exceeded the cycle here, so no lag growth was observed at any
  D. If a later configuration shortens the cycle below the 70-73 ms of execution plus root, lag grows by about the
  difference every block (replay on this data: not reached), and D bounds it only by the validity rule, not by running
  out of anything; PD 17.4's thresholds would have to be there first.
- Clock and parse. Times come from the nodes' own log stamps on one host; `seal-first` start is the line's time
  minus `total_ms`, and the view-to-number map (view = number + 1) was checked against block hashes for one block.

### 11.5 What the logs support

They do not support going further with D > 1 *for the bench's window-1 cycle*: the parent's result is the binding wait
in 2-6 of about 220 seals and in none of the votes, and D = 2 or 3 reproduces the D = 1 cycle to within 0.3%. The
gate that sets the 36 ms of excess is the leader's one-ahead build slot, and that is a change to test first (replay
suggests 136 ms to about 103 ms on the same logs, with the caveats above). D > 1 might matter in the stalls and tails of
windows 2 and 3 and in production's seven-node tail; that is a replay of those windows, not a protocol change yet.

### 11.6 Reconciliation with the earlier build-at-seal legs (loop307, loop312): the 103 ms prediction is falsified

Earlier rounds (BD 10.55, loop307 ON/ONb/OFF/ONP90; BD 10.60, loop312 AHEAD against B1-B3) set `N42_BUILD_AHEAD_AT_SEAL=1`
and window 1 did not move. Their logs are still under `/data/blockchain/rust-fleet3-bench/bench-loop307*` and `bench-loop312*`;
`scripts/fleet7-depth-replay.py <dir>` runs on them unchanged (model D = 1 within 0.4% on every one).

**What the slot is** (`crates/n42/h2-el-rpc/src/engine.rs`, `start_chain_locked`; `crates/n42/h2-node/src/service.rs`,
`build_start_fields`). `ChainState.slot` holds the one chained build of a block that has been requested or built and
not yet *taken*; a build is taken when the proposer fetches it for the proposal (`take_sealed_us`), that is, at the
proposal's send. When build N seals, the chain asks to start N+1 on the sealed header. If the slot is still occupied,
the start is refused ("one ahead, never two"). Without the switch, N+1 then starts from the request the leader makes
after publishing the previous block (trigger `send`, start about 2 ms after the previous proposal). With the switch, the
refused start is kept in `deferred` and runs the moment the occupying build is taken. What the logs show that this moves:
build V starts at `P(V-2) + 3 ms`, one tick earlier, instead of at `P(V-1) + 2 ms` (trigger-send blocks: start minus P(V-1)
of -101 ms with the switch against +2 ms without). What it does not change: still one build in the slot and one
more in flight, the start still waits for a proposal's send, and the build still needs the sealed parent's state.
The model's "slot lifted" scenario started a build at the previous *seal* (about 50 ms earlier again than the switch)
and kept every other duration as measured, so the switch is a milder version of the same lift.

**Gating attribution on the earlier legs** (same classes as 11.3; share of blocks; window 1; leader node 0):

| Leg | Cycle ms | Pacing tick | Seal waits for previous send (slot) | Leader own build | Quorum of N-1 |
| --- | --- | --- | --- | --- | --- |
| loop307 OFF | 137.0 | 58.7% | 26.6% | 3.2% | 11.5% |
| loop307 ON | 135.1 | 61.5% | 5.0% | 11.3% | 22.2% |
| loop307 ONb | 131.1 | 68.9% | 4.8% | 9.2% | 16.7% |
| loop307 ONP90 (90 ms) | 132.5 | 53.5% | 11.9% | 13.3% | 20.8% |
| loop312 B1 / B2 | 136.2 / 142.3 | 47.9% / 53.8% | 31.5% / 29.5% | 13.2% / 11.4% | 6.4% / 4.3% |
| loop312 AHEAD | 129.5 | 70.1% | 4.3% | 9.5% | 14.3% |

With the switch on the slot's share falls from 27-32% to 4-5% (ONP90 12%), as intended, and the cycle falls by 2-9 ms,
not the 33 ms the model predicted. The time moved to the quorum of the previous block and to longer durations that the
model held fixed (medians, OFF/B legs against ON/AHEAD legs):

| Duration | OFF / B1-B3 | ON / ONb / AHEAD |
| --- | --- | --- |
| Quorum after proposal, `Qc - P` median / p90 (ms) | 58 / 150 (307), 45-50 / 90-98 (312) | 76 / 172, 72 / 154, 60 / 142 |
| Follower check, vote minus body, p90 (ms) | 93 (307), 52-58 (312) | 113, 97, 91 |
| Seal to proposer's hand-off, `h` median (ms) | 100 (307), 98-102 (312) | 138, 129, 129 |
| Leader `par_ms` median (ms) | 76-81 | 83-86 |
| Peak EL memory, 312 (BD 10.60) | 32-33 G | 40.7 G |

The same slot-lifted replay, run on the ON/AHEAD legs' own durations, still says 105-106 ms, while those legs measured
129-135 ms. The replay therefore fails an out-of-sample check: it assumes the per-block durations do not change when
builds start earlier, and they do. ONP90 is a second witness: at 90 ms pacing the cycle stayed 132 ms, so the tick is not
what limits it once the slot is open. The 103 ms in 11.3 is an upper bound under zero contention, not a forecast.
Section 11.5's statement that lifting the slot is worth more than any D should be read with this correction: the switch
that does it was measured twice and delivered 2-9 ms.

**What a real lift would need.** A second build in flight on state the first has not finished: the leader would execute
N+1's transactions against N's output shards while N's roots and import are still running, and also hold N's
unfinished block in memory. Candidates for what it then contends with, none separated by these logs: the leader's own
import of N-1 (170-230 ms, `own block imported by header`) and root on the same pinned cores; the 32-thread build pool;
memory bandwidth and page faults (peak memory +7-8 G with the switch); and the vote path of the *followers*, whose check
and the leader's quorum time both grew although followers run no builds, which points at host-wide contention (memory,
page cache, hugepage pool) and not only at the leader's cores. That cause is open.

**One measurement that would confirm or falsify** the slot as the cycle's limit: a leg with the switch on and the leader's
build, import and root threads on cores and memory disjoint from the other work, with the three counters `Qc - P`,
follower check p90 and `h` printed per leg. If the lift is purely a scheduling gain, `Qc - P` median stays at 45-58 ms and the
cycle drops to about 105-115 ms; if those counters rise again to 60-76 ms and the cycle stays at 130-135 ms, the
contention reading holds and neither the slot nor D is the lever. The existing ON/AHEAD logs already lean to the
second outcome.

### 11.7 Anatomy of the excess over the tick (loop317 BASE and BASEb, window 1)

`scripts/fleet7-excess-anatomy.py <round-dir>` (reuses the parser of `fleet7-depth-replay.py`). 220 blocks per leg, leader
node 0, cycle mean 135.6 / 135.4 ms, median 124.8 / 128.4, p90 187.7 / 180.4; the excess over 100 ms is 35.6 / 35.4 ms.

**Segments** (each block's cycle = 100 ms + the six segments, exactly; mean over blocks, ms; share of the excess, BASE / BASEb):

| Segment | Meaning | median | mean | p90 | share |
| --- | --- | --- | --- | --- | --- |
| late (timer) | preamble after P(V-1) + 100 ms, not explained by the commit | 0.5 | 1.7 / 3.1 | 12.8 / 18.5 | 4.9% / 8.8% |
| late (quorum overshoot) | preamble held for the previous commit | 0.0 | 2.1 / 2.5 | 0.0 / 3.8 | 5.9% / 7.0% |
| start lag, queue, build | inside the sealed-header wait, clipped to it | 0.0 | 0.7 / 0.6 | 0 | 1.8% |
| encode | the EL encoding its ~26 MB answer (`encode_ms`) | 0.0 | 4.9 / 4.1 | 22 / 18 | 14% / 12% |
| delivery | the EL's `built ahead on the sealed own block` line to `take_sealed` returning | 0.0 | 21.1 / 20.0 | 61 / 58 | 59% / 56% |
| send | sealed header in hand to the proposal on the wire (sign, publish) | 2.6 | 5.0 / 5.2 | 13 | 14% / 15% |

The median block has 0 in every segment except `send` (2.5 ms) and a 0.5 ms timer lateness: half the blocks are on the tick.
Delivery is large only in the 42% of blocks whose wait for the sealed header was binding (median 51 ms there, p90 83). In
the code (`bin/n42/src/payload_serve.rs`, `driver.rs`) the EL logs "built ahead on the sealed own block" *before* its
`stream.write_all` of the whole ~26 MB answer, and `take_us` ends after the proposer has read and resolved it, so
delivery is the write, read and decode of that answer; the logs do not split those three. The previous block's quorum path
(first follower's check 28 ms median, vote-to-commit transit 19.6 ms, `Qc - P` 48 ms median, 85-98 ms p90) sits inside the
100 ms and overshoots it in only 6-9% of blocks (the 2.1-2.5 ms above). The negative "receipt" median (-0.7 ms) is the
followers' `import starting` stamp preceding the leader's `proposal sent` stamp by under a millisecond; nothing in the logs
is more precise than that.

**Groups** (mean ms; BASE; BASEb in brackets):

| | <= 110 ms (79 blocks) | middle (119) | slowest 10% (22) |
| --- | --- | --- | --- |
| cycle | 101.5 (99.8) | 145.3 (144.5) | 205.9 (200.2) |
| late (timer + quorum) | -1.4 (-2.7) | 6.8 (9.5) | 6.8 (10.6) |
| build | 0 | 0.3 (0.2) | 5.1 (5.2) |
| encode | 0 | 5.1 (4.3) | 21.6 (16.2) |
| delivery | 0.1 (0) | 27.1 (24.3) | 64.4 (60.1) |
| send | 2.7 (2.5) | 6.1 (6.1) | 7.9 (8.1) |
| `Qc - P` | 50.3 (49.3) | 55.6 (57.5) | 63.1 (59.5) |
| share with trigger `send` | 0% | 49% (41%) | 77% (64%) |

Between the fast group and the middle one the only segments that grow are delivery (+27 ms) and encode (+5 ms), and they grow
together with the build trigger: every block with the `send` trigger is slow and none is fast. Between the middle and the
slowest 10%, delivery grows by another 37 ms, encode by 16 ms, build by 5 ms: the same segments, longer.

**Fixed part or noise.** Fixed, and tied to the build trigger. A build that starts at the previous *seal* (trigger `seal`, 66-70%
of blocks) finishes before the next tick and gives a 98-109 ms cycle (cycle p10 / median / p90 98 / 109 / 147 BASE). A build that
starts at the previous *send* (trigger `send`, one-ahead slot, 30-34%) starts a fixed lag after the previous proposal and
needs queue 4 + build 76-80 + encode 25-26 + delivery 49-51 = 158-161 ms to reach the proposer (median
160.6 / 157.9 ms from the previous send to the hand-off, p90 194 / 192): cycle 170 / 166 ms mean (p10 144 / 140, p90 204 /
198). Mean excess 35 ms is 0.32 x 68 ms plus 0.68 x 19 ms. Only 74 of the 220 BASE blocks are in the first class, so the typical
(median) 25 ms is a mix of the two modes, not a uniform lag: it is the 125 ms median of a 109 ms mode and a 168 ms mode.
Within the `send` blocks the spread is noise around the fixed chain (cycle against delivery r = 0.73 / 0.74, against build
0.67 / 0.43, build against delivery 0.16 / -0.10, so the two vary independently).

**Leadership.** In both legs `F7_LEADER_TENURE` ends at 1024 views: node 0 proposes views 1-1023, node 1 views 1024-2047,
node 2 from 2048 (61 and 72 proposals before the leg ends, all in the empty tail; `seal-first` builds 755 / 423 / 0 on
nodes 0 / 1 / 2 because node 2 never reaches a full block). Rotation is node 0, 1, 2 by tenure; window 1 (views about 270-490) lies
inside node 0's tenure, so no handover is in it, and the question whether slow blocks cluster at handovers cannot be
answered from window 1; windows 2-3 hold the 0-to-1 handover. Autocorrelation of the cycle is -0.55 / -0.49 at lag 1, +0.53 /
+0.34 at lag 2, -0.33 / -0.16 at lag 3: a period-2 alternation. The mechanism is visible in the trigger: a `send`
block is never followed by another `send` block (0 of 75 and 0 of 66), and after a `seal` block the next is `send` in 51% /
42%. P(slowest 10% | previous slowest) = 0.00 / 0.05 against a base rate of 0.10. Slow blocks do not follow slow
predecessors; they follow fast ones, because a slow block frees the slot so that the next build starts early.

**Cross-node coincidence.** Not host-wide. For the slowest 10% of blocks the followers' stages are at their medians or
below (check 0.83-1.01x, exec 0.88-0.97x, root 0.86-1.00x, fields lag 0.98-1.01x; the block before: 0.91-1.23x, check on node 1
in BASE the only one above 1.1x). Blocks above a follower's own p90 on both followers: 2 / 5 / 3 (check / exec / root, BASE)
against 2.2 expected by independence; on exactly one follower 32-40. Cross-follower correlation of the check is +0.04 / +0.07,
of exec +0.42 / +0.37, of root +0.15 / +0.31 (exec and root share the block's content, so some correlation is expected).
The leader's `par_ms` is 1.06x and its seal-to-hand-off 1.03-1.07x at the slowest blocks. The slowness is local to one node's
one path: the leader's build-to-delivery chain.

**Cause and cheapest confirmation.** The fixed part: with the one-ahead slot, a third of the blocks (all `send` blocks) pay a chain of
about 160 ms (build 80, encode 26, delivery 50, queue 4) from the previous send against a 100 ms tick, and the second half of
that chain (encode and the write, read and decode of the 26 MB answer, 75 ms) is the only part that is not computation
overlapped with something else. The tail part: the variance of that same chain, dominated by delivery (p90 83 against median 51)
and by build (p90 145-147 against 76-80). Cheapest measurement for the fixed part: put three timestamps on the take (EL
`write_all` start, `write_all` end, proposer read end) and one on the decode, one extra line per proposal, on one ordinary
BASE leg; if the sum of write, read and decode is the 50 ms of `delivery`, the lever is not sending 26 MB to the proposer
(the proposal itself carries a 12.5 KB compact body) and the prediction is that `send`-trigger cycles fall from 168 toward 135
ms. For the tail: the same three timestamps plus the leader's thread CPU (`threadcpu-*.tsv`) around the slowest blocks; if the
long deliveries coincide with the write or the read side being descheduled, it is scheduling, and if the write
itself takes the time, it is the copy of the 26 MB. This analysis cannot say which, because the line that ends the EL's
stage is logged before the write.

### 11.8 Why block N+1's seal waits for N's fields: it is not the own import (loop318, offline)

Method: code reading plus a parse of `node0-el.log` of `/data/blockchain/rust-fleet3-bench/bench-loop318{COMPACT,COMPACTb,BASE}`:
the 237 full blocks (txs >= 100,000) of window 1 on the leader (blocks 268-509), the `seal-first build phases`,
`built ahead on the sealed own block`, `own block handed to the engine as executed` and `own block imported by header` lines
joined by block number. A block's seal time is the build line's timestamp minus `total_ms - sealed_at_ms`. Median / p90 in ms.
Script: `/tmp/a318.py` (not kept; about 60 lines of regex). Nothing was run on the fleet.

**The premise needs correcting.** Header N+1 carries N's `stateRoot`, `receiptsRoot`, `logsBloom` and `gasUsed` (deferred
execution). Those are not read from the own import. `parent_executed_fields_or_built` (`engine-types/src/hotstuff_consensus.rs`)
waits on `executed_fields::wait_for(built_hash)`, and the only writer on the leader is the `publish` closure inside build N's own
finish (`engine-types/src/payload.rs`, "behind the seal"), which files the QMDB tree and calls `executed_fields::remember` right
after the QMDB root and the receipts root are computed. The own import happens later and only copies the key
(`payload_serve.rs::hand_off_own_build`: `remember(sealed_hash, get(built_hash))`).

**Own import of block N, step by step** (`driver::spawn_import_own_block` -> `import_own` -> `OWN_BLOCK` ->
`payload_serve::own_block_by_header`):

| step | work | recomputed or reused | COMPACT med / p90 | BASE med / p90 |
| --- | --- | --- | --- | --- |
| 0 | spawned after the proposal is sent | - | starts about 10 ms after N's seal | |
| 1 | `built_executions::take/find` waits for the build to reach `Complete` (merge of the bundle, hashed post-state) | reused; pure wait | about 70 (derived: total - handoff - payload - new_payload) | about 45 (derived) |
| 2 | `hand_off_own_build`: body moved or cloned, `chain_alias::rename` of the QMDB tree, fields copied to the sealed hash, `forget_mined` in the queue, `ExecutedInsert` into the engine, pool prune on a blocking thread (`handoff_ms`) | reused; bookkeeping | 41 / 64 | 42 / 66 |
| 3 | payload assembled from the kept encodings (`payload_ms`) | reused | 2 / 3 | 2 / 4 |
| 4 | `engine.new_payload`: finds the block in the tree, answers Valid | reused | a few | a few |
| total | `own block imported by header` `total_ms` | | 116 / 157 (COMPACTb 113 / 151) | 91 / 136 |

Nothing is executed again and no root is recomputed: the engine takes the build's `BuiltExecution` as an executed insert. The
100 ms is waiting for the build's own finish (step 1) plus 41 ms of hand-off bookkeeping. In absolute time the import ends about
255 ms (COMPACT) after N's seal, the build's `Complete` about 185, and the hand-off line about 243.

**What `parent_fields_ms` waits for.** Block N+1 starts at N's seal on 93% of builds and finishes its parallel step about 78 ms
after N's seal (gap seal(N)->seal(N+1) minus `parent_fields_ms`, binding blocks, median 78 / p90 92). N's fields are published at
a median 115 / p90 145 ms after N's seal (the gap seal(N)->seal(N+1) on the 182 of 237 blocks where `parent_fields_ms` >= 10;
COMPACTb 116 / 145, 173 blocks; BASE 114 / 142, only 47 blocks bind because its builds start later). The gap is the wait: 30
median (31 on binding blocks), p65 at p90. It is the publish of N's QMDB root, not the import, which ends 140 ms later.

Of those 115 ms, `roots_ms` of N is 35 (p90 59) and covers only the root job and the receipts root, so about 80 ms are before
the roots start: `executor.finish()`, `merge_transitions`, `take_bundle`, the shard residual and view, `rename_parent`. Only the
last two are conditional waits; `merge_ms` and `shard_ready_ms` print 0-1. The remaining time is not instrumented (this is the
gap in the logs, and the main uncertainty below). One more fact points to contention: `par_ms` of N+1 is 107 / 137 on binding
blocks and 74 on the non-binding ones (BASE: 105 against 70), with `par_exec_ms` unchanged at 29-31, so the overlap of N's finish
with N+1's execution on the same pool and cores costs N+1 about 30 ms too. That is the second "30 ms": the leader now runs N's
finish and N+1's execution concurrently.

**Which fields the build of N has at seal time.**

| field | known at N's seal? | where it is produced |
| --- | --- | --- |
| `gasUsed` | yes | `direct_receipts` (the cumulative gas), complete when the parallel step ends, which is the seal under `seal_at_exec` |
| `receiptsRoot`, `logsBloom` | yes (inputs complete) | `gov5_receipt_root_bloom(receipts)`, a thread spawned in finish; it needs only the receipts, not the state |
| `stateRoot` | the inputs yes, the value no | the QMDB root job over the block's accounts (`sorted_operations_from_accounts`, `compute_operations(parent_sealed, ops)`): needs the merged output, i.e. `finish`, and the parent's tree |

So the wait is an artefact of the order of work, not of a different structure: the leader has everything the root needs at the
seal (the execution is complete; only the fold of the output into one bundle is pending), and the receipt side could be published
earlier still. The only real dependency is the QMDB root (35 ms) of N after N-1's tree is filed.

**Smallest change (not made, no code edited).** Start the root job at the seal instead of after the pre-roots steps, on the
shard view that already exists, and publish the fields as soon as it returns, before and independent of the merge, hashed state,
`state_ready` and `complete`. In the sharded branch `publish` is already called before the merge thread starts; what has to move
is the work ahead of it: take `rename_parent` (conditional) and the residual/view construction off the critical path, give the
root job and the receipts root thread the pool first, and defer `executor.finish` details that the root does not read. Publish
the receipt-side fields (`remember_receipts`) at the seal itself, since they need no state.

**Risks.** (1) A build that is sealed but never committed: fields are keyed by the sealed hash, so a published entry for a block
that loses is never read by the chain that wins; the build on top of it is discarded on the parent mismatch as today. (2) The
tree must be filed before the fields say "executed" (the comment on `publish` says so): keep `qmdb_state.insert` before
`remember`. (3) A handover: the next leader builds on the committed block and finds its fields through its follower import
(`remember_state_root`, `remember_receipts`), unchanged. (4) A follower that disagrees: the values are the same, only earlier;
every follower still checks them against its own execution, and the leader's header is rejected as before if they differ.
(5) Contention: starting the root earlier moves CPU work into the window where N+1's execution also runs, and could lengthen
`par_ms` of N+1 further; this is the thing to measure.

**Estimate (not measured).** If the fields appeared at the root's own length after the seal (35 ms median, 59 p90) instead of
115 / 145, N+1's execution (done at 78) would no longer wait: `parent_fields_ms` 30 -> about 0-5 and `sealed_ms` 37 -> about 8,
`sealed_at_ms` 108 -> about 78-85. The cycle is bound by the 100 ms tick, so the effect on the median cycle is smaller than the
30 ms: perhaps 10-15 ms (the 125 ms seal-trigger mean toward about 110), mostly on the p65-p90 blocks. The second 30 ms (`par_ms`
inflation by overlap) would not go away with this change; it would need the finish of N to take less CPU or run on cores the
build pool does not use, and could even grow. The 80 ms before the roots is the figure that decides: a one-line timestamp on
the phases line at `roots_from` (and after `rename_parent`) turns the above from an inference into a measurement, and costs
nothing on the fleet.

### 11.9 What holds the cycle above the tick after the compact answer (loop324 F, Fb, FS, FSb, window 1)

`scripts/fleet7-excess-anatomy.py <dir>` (segments) and `... --binding <dir>` (binding wait, last voter, counterfactual).
234 / 233 / 237 / 236 blocks, leader node 0, cycle mean 117.1 / 117.6 / 115.7 / 116.2 ms, median 111.7 / 112.4 / 110.7 / 111.7,
p90 140.8 / 140.9 / 137.9 / 138.0. Excess over 100 ms: 17.1 / 17.6 / 15.7 / 16.2 ms.

**1. Segments** (mean ms and share of the excess, F / FS; median, p90 in brackets):

| Segment | F | FS |
| --- | --- | --- |
| late, timer (preamble after P(V-1) + 100 ms, not the commit) | 0.7 ms, 4.0% (0.0, 0.8) | 0.8 ms, 4.9% (0.0, 1.3) |
| late, quorum overshoot (preamble held for the previous commit) | 15.0 ms, **87.8%** (9.8, 38.4) | 13.5 ms, **85.6%** (7.3, 36.6) |
| build, encode, delivery (inside the sealed-header wait) | 0.1 ms, 1.0% | 0.2 ms, 1.2% |
| send (sign, publish) | 1.2 ms, 7.2% (0.8, 1.7) | 1.3 ms, 8.2% (0.8, 2.2) |

The two modes of 11.7 are gone. Trigger `seal` 79% / 72% of blocks, cycle mean 117.2 / 115.6 ms; trigger `send` 21% / 28%, 116.8 /
116.2 ms: the build trigger no longer predicts the cycle. The sealed-header wait binds in 2 (F), 7 (Fb), 5 (FS) and 11 (FSb) blocks of
about 235. The excess is almost entirely the leader's preamble waiting for the previous block's commit.

**2. Binding wait per block** (tick: the preamble came on the tick and nothing was later; quorum: the preamble came within 10 ms of the
previous commit and more than 3 ms after the tick; seal: the proposer waited more than 3 ms for the sealed header; the build throttle,
soft 48 / hard 80 unpersisted blocks, never engaged: in-memory maximum 11-16 in the round table):

| Leg | Quorum | Tick | Seal |
| --- | --- | --- | --- |
| F | 60.7%, mean cycle 124.8 | 38.5%, 105.1 | 0.9%, 114.6 |
| Fb | 67.8%, 123.9 | 29.2%, 102.8 | 3.0%, 119.0 |
| FS | 52.3%, 124.4 | 45.6%, 106.0 | 2.1%, 110.3 |
| FSb | 59.3%, 123.1 | 36.0%, 105.5 | 4.7%, 110.8 |

The quorum waits for every vote (votes = 3 + 3 in the commit line, the straggler grace of the bench; with f = 0 and three validators there is
no slack), so the last voter binds: **node 2 in 232 of 234 blocks (F) and 235 of 237 (FS)**. A correction to 11.1-11.4: those sections
modelled the quorum as the faster follower, which was close enough while the quorum was not binding (loop316 and loop317, `Qc - P` 48 ms);
it is not close here, `Qc` lies 81 ms after the first vote and 5.1 ms after the last (F).

The last voter's path from the proposal to the commit (F; FS in brackets), median / mean / p90 ms:

| Step | median | mean | p90 |
| --- | --- | --- | --- |
| proposal to body arrival (receipt) | -0.5 (-0.5) | 0.0 | 2.4 |
| body arrival to the start of the compact-body assembly (`wait_for_engine`) | **73.0 (71.1)** | 74.0 (68.6) | 105.7 (103.2) |
| assembly start to the vote sent (assemble plus check) | 27.6 (27.4) | 28.5 | 37.7 |
| last vote to the leader's commit (transit) | 5.1 (5.3) | 6.2 | 8.4 |
| proposal to commit (`Qc - P`) | 108.0 (105.2) | 108.7 | 136.7 |

Node 1 starts the assembly 1 ms after the body arrives and votes 25.6 ms after it. Node 2's vote road itself is as short (26 ms total in
its own `vote road` line); what is long is the 73 ms before it starts. The assembly start minus node 2's engine landing of block n-2
(`Block added to canonical chain`): minimum 0.7 ms, p10 2.9, median 11.3, p90 20.9, and below zero in 0 of 234 blocks (FS: 0.5 / 3.2 / 12.2 /
23.0, 0 of 237). So the vote of block n waits for the node's own engine landing of block n-2. On node 2 that landing comes 300 ms
(p90 330) after the body arrival, on node 1 117 ms (p90 146); node 2's direct import carries `parent_engine_wait_ms` 40 median (p90 89) against
0, `engine_ms` 36 against 18 and `engine_new_payload_ms` 24 against 7, while its execution and roots are the same (exec 35 / 37 ms, roots
25 / 27 ms, `fields_ready` 73 on both). Node 2 is not computing slower; its engine takes the executed block about 80 ms longer to land
and waits for its parent's landing. The logs do not say why node 2 and not node 1 (loop317's node 2 landed at 168 ms and was not the late voter).
Quorum-bound blocks have a longer wait (88 ms mean) than tick-bound ones (53 ms), the binding class follows that wait.

**3. Why FS did not pay.** FS moved `sealed_at` from 104 / 93 to 75 / 77 ms, but the seal was binding in 0.9% (F) and 2.1% (FS) of blocks,
so there was nothing to take: the wait that sets 52-68% of the cycles is node 2's vote, which the seal does not touch. When the seal moved
earlier, the tick (38.5% to 45.6%) took the blocks the quorum did not claim; the quorum's own share fell from 60.7% to 52.3% between
F and FS, but Fb to FSb shows 67.8% to 59.3% and F to Fb alone moves it 7 points, so the difference is inside the leg-to-leg spread. The
cycle gain, 1.4 to 1.4 ms (F to FS 117.1 to 115.7; Fb to FSb 117.6 to 116.2), is that spread.

**4. What 109 ms needs.** Floor: tick 100 ms + `send` 1.2-1.3 ms + timer lateness 0.25-0.30 ms mean (`tick_late_us` median 0.00, p90 1.0-1.2 ms)
= about 101.5-101.6 ms. Timer granularity is not a share of the excess; it is 2% of the 16-17 ms. A 109 ms mean leaves 7.5 ms of excess against
today's 15-16, so the quorum overshoot (13.5-15.0 ms mean) has to halve:
- Follower side, node 2's `wait_for_engine`: 74 ms mean (p90 106) to about 50 ms, the level of the tick-bound blocks. That is -24 ms on the
  last voter's path and is the only large term. It is the node's own previous-block engine landing (parent landing wait 40 ms plus the engine's 36 ms).
- Last-vote-to-commit transit: 5.1-5.3 ms median on every quorum-bound block, so 3 ms off it is worth about 1.7 ms of mean cycle (transport on one host plus the leader's
  event loop; not separable here).
- Leader side: nothing. The seal binds in 1-5% of blocks and the preamble is already 1.3 ms behind the commit.
Counterfactual, every follower's vote path as fast as node 1's (per-block receipt and check as measured, commit transit 5.1 ms, the
seal wait kept where it was binding): mean cycle 102.0 / 101.8 / 102.3 / 102.2 ms, about 1.6M. It is an upper bound that holds the other durations fixed,
and 11.6 showed that earlier starts lengthen them; do not read it as a forecast. Half of it, 109-110 ms, is the target.

**5. The tail.** The slowest 10% (24 blocks, at least 141 / 138 ms in F / FS): 22 of 24 (F) and 20 of 24 (FS) are quorum-bound, and the previous
block's `Qc - P` is 144 / 140 ms against 109 / 105 overall. Within it the last voter's `wait_for_engine` is 106.6 / 98.0 ms against 74.0 / 68.6 on
average, the assemble-plus-check 30.2 / 33.0 against 28.5 / 29.9 and the transit 7.6 / 9.1 against 6.2 / 6.7: the tail is node 2's engine-landing wait getting 25-30 ms longer,
nothing else moves. No slow block follows a slow one (autocorrelation of the cycle -0.37 at lag 1, -0.09 at lag 2, +0.21 at lag 3 in F; 0.00 probability of two slowest in a row),
and the cycles alternate (60% of consecutive blocks fall on opposite sides of 110 ms): a late landing of n-2 delays block n and the following block's vote finds the
engine caught up.

Cheapest fleet measurement for the cause: node 2's engine landing latency per block (`Block added to canonical chain` minus body arrival, already in the
log) and its `parent_engine_wait_ms` against node 1's on one ordinary F leg with the two nodes' cores swapped (node 1's execution layer and
validator pinned where node 2's were, and the reverse). If the late landing follows the node, it is the node's configuration or core
placement; if it follows the position, it is the order in which the engine accepts the executed blocks, and the wait is the design.
