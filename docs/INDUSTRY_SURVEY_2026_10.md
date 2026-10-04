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
is `dirty_decay_ms:2000,background_thread:true` with no `thp` token, the project notes say records were
measured with `thp:always`, and the host's THP mode is `madvise` with `defrag=defer`. Open question 4. BD 10.48
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
