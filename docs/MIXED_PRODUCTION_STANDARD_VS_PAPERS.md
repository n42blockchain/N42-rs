# Mixed production standard, profile 1 (v0.3) against the project's papers and design documents

2026-11-24. Read-only review. Subject: `/data/n42-build/wt-docs/docs/MIXED_PRODUCTION_STANDARD.md`
(v0.3: sections 1-6, decisions O1-O10, the 0x50-0x5F reservation, amendments AM1-AM16; amendments
override earlier text). "Std" below means that file; item ids are the standard's own.

## 0. Sources used, and what is not available

| Short name | File | What it is |
| --- | --- | --- |
| WP | `/home/n42/src/n42/n42-26/docs/N42_Distributed_Decision_Network_Whitepaper_v0.1_EN.md` | The whitepaper (v0.1, "Development & Validation Edition"), 1481 lines |
| ARCH | `/home/n42/src/n42/n42-26/docs/01-System-Architecture.md` | n42-26 system architecture |
| FLOWS | `/home/n42/src/n42/n42-26/docs/02-Core-Flows.md` | n42-26 core flows (mobile, reward, staking, reconfig) |
| PL | `/home/n42/src/n42/n42-26/docs/04-Product-Lines-and-Performance.md` | the three product lines and performance baselines |
| SLOT | `/home/n42/src/n42/n42-26/docs/task-real-slot-measurement.md`, `devlog-71-real-slot-profile.md`, `devlog-06-network-quick-optimize.md` | the "8-second slot" |
| FVM | `/home/n42/src/n42/n42-26/docs/follower-validation-modes.md` | n42-26 "approved target architecture" for follower validation (QMDB + LtHash) |
| ORCH | `/home/n42/src/n42/n42-26/crates/n42-consensus-service/src/orchestrator/mod.rs:545-559` | the code's definition of a slot |
| HS2-MAP | `/home/n42/src/n42/n42-gov5/docs/consensus/hotstuff2-spec.md` | gov5's rule-by-rule map of the HotStuff-2 paper (Malkhi, Nayak, ePrint 2023/397) onto code |
| HS2-AUD | `/home/n42/src/n42/n42-gov5/docs/HotStuff-2.txt` | a Chinese audit summary (not the paper, despite the name) |
| QMDB-REV | `/home/n42/src/n42/n42-rs/docs/QMDB_PAPER_REVIEW.md` | review of the QMDB paper (LayerZero Labs, arXiv 2501.05262) against the code |
| MV3 | `/home/n42/src/n42/n42-rs/docs/MOBILEVERIFY_V3_PARITY.md` | byte-level spec of gov5's `/mobileverify` ("mining v3") |
| MAD | `/home/n42/src/n42/n42-gov5/docs/mobile-attestation-design.md` | gov5's unified mobile attestation design ("design approved") |
| PHD | `/home/n42/src/n42/n42-rs/docs/PHASE_D_DEFERRED_EXECUTION.md` | deferred execution design (17.7 settlement tags) |
| SIG | `/home/n42/src/n42/n42-rs/docs/SIGNATURE_AND_BATCH_TX_SURVEY.md` | signature / post-quantum survey |
| GCFG | `/home/n42/src/n42/n42-gov5/params/config.go:593-609` | gov5's own definition of the committee pool |
| POI | `/data/n42-build/wt-docs/docs/PLAN_OPEN_ITEMS_2026_11.md:20` | the `mv4h4b2` round record |

**Not available locally:** the HotStuff-2 paper text (ePrint 2023/397) and the QMDB paper text (arXiv
2501.05262). No PDF or text copy exists under `/home/n42/src/n42` or `/data/n42-build` (searched).
Statements about those papers below come only from HS2-MAP / HS2-AUD and QMDB-REV and are marked
**[via review doc]**. The whitepaper's own references (WP:1479, the internal PDFs "N42技术持续领先")
are also not in any repo.

### The most important framing fact

The whitepaper is **not a protocol paper**. It specifies an AI "Distributed Decision Network" layered on
top of the chain and says so: "Decision is not Consensus" (WP:99); signature validity, nonce, balance,
state transition validity, block validity, consensus vote validity, gas accounting and cryptographic
verification "must continue to be handled by deterministic algorithms" (WP:103-116); "AI may influence
optimization; it must not influence validity" (WP:1224). Words that a consensus specification would use
do not occur in it at all: `slot`, `HotStuff`, `BLS`, `Ed25519`, `quantum`, `slash`, `blob`, `stateless`,
`light` (zero matches each). `validator` appears only as a model tier (WP:218, WP:1382); `stake` only as
a Sybil defence for DDN providers (WP:1089). Its chain-level content is a list of "existing technical
foundation" items (WP:44): "Block-STM parallel execution, consensus-execution separation, the QMDB state
engine, PeerDAS, WASM/Batch/Inference/Scheduler/Worker components, distributed storage, DID messaging,
and a mobile-node build path", plus one throughput figure (WP:1166). So most of the questions below can
only be answered against the design documents, not the whitepaper; where that is the case it is said.

---

## 1. Slot / block time

**Paper text.** WP never uses the word "slot" and states no block time. The "8-second slot" comes from
n42-26's engineering documents, where it is the **block interval** (a consensus tick per block), not a
mobile or attestation window:

- ORCH:547-553: "The consensus slot interval acts as a 'bus clock': within each tick, build / import /
  consensus / communication stages run in parallel ... Slot N clock tick ... [Build] [Broadcast]
  [Consensus] [Import] [Commit]".
- SLOT (`task-real-slot-measurement.md`:45): "8s slot 预算那张表(EVM 2000ms / BLS 687ms / 状态根 500ms)是
  **2026-03 的老估计**" -- a per-block budget, explicitly called an old estimate.
- `devlog-71-real-slot-profile.md`: "Testnet: 4 validators, 8s slot, standard cache mode, 2G block gas limit."
- `devlog-06-network-quick-optimize.md`:14: a 3 s phone send timeout "在 8 秒 slot 内留足余量" -- phones
  were served inside the block slot.
- HS2-AUD:139: deferred execution is "必要性: 高 — 8 秒 slot 目标下，执行时间直接影响出块速率" (an n42-26
  target, in a Go-vs-Rust audit).
- MV3 Stage 2 ran on "chain 1143, 3 s slots" (MV3:391): the same word for the devnet's block period.

**Standard.** A17 `blockIntervalMs` (pacing, not a timestamp step); O8/§5: 500 ms; AM11(a) leaves "how the
500 ms block interval relates to the project's 8-second slot" open for the owner.

| # | Finding | Severity |
| --- | --- | --- |
| 1.1 | "Slot" in the project's documents = block interval of n42-26's consensus loop, an engineering budget from 2026-03, not a requirement of any paper. 500 ms is a per-chain constant (AM11). No paper is violated. | CONSISTENT. Recommendation: close AM11(a) with this answer; add one sentence to A17 ("the 8 s slot of n42-26's earlier testnets was its block interval; Profile 1 replaces it"). |
| 1.2 | **Mobile verification timing at 500 ms is unspecified and unproven.** MV3:245-248: the production cohort window "opens on the first receipt ... intake closes when the chain reaches **N+1** ... reveal at N+2, reconcile and close at N+3, merge at N+5" -- windows counted in **blocks**, sized when a block was 3-8 s. At 500 ms a phone has roughly one block interval to fetch the packet, re-execute and return a receipt. The only mixed MobileAnchor proof, `mv4h4b2`, produced "159 blocks" in a "360 s round" (POI:20), i.e. ~2.3 s blocks, not 500 ms. The 45 s registry epoch (MV3:137, "`CommitEpoch` ... runs every `collect_window_sec` (45 s)") is a wall-clock timer per node and is independent of the slot; it only decides when new phones become attestable. | SILENT gap. Recommendation: change the standard -- either state the cohort windows in milliseconds (or scale the block counts by `blockIntervalMs`), or add to the M1' gate a certification rate measured at 500 ms. Note as a Profile-1 limitation until then. |
| 1.3 | Registry epochs commit "on its own timer" per node, so two nodes can assign different indices (MV3:432-435). MAD:173-181 says canonical agreement "requires the epoch batch to be settled on-chain" (phase 6b, a batch transaction listing members). Std AM12/AM16 make the header root "the proposer's statement ... not re-derived by followers", consistent with MAD:231 ("carried, not consensus-validated"), but the standard has no canonical membership rule at all. | SILENT gap (acknowledged as "revisited before milestone 3"). Paper-level goal beyond Profile 1; record it as a limitation in I1. |

## 2. Validator / verifier model and scale

**Paper text.** WP is silent on validator count, set dynamics or staking for chain consensus. Mobile
devices appear only as AI edge nodes (WP:817-847: "N42-System1 Edge ... simple classification, spam
detection ..."). The design documents say:

- MAD:7-9: "Mobiles are **not** in the consensus path: they never vote, never affect quorum/finality, and
  can never delay a block."
- MAD:101-103: "**T1 — staked consensus validators.** ETH-style stake (deposit contract), HotStuff
  validator set, committee sampling for voting. Economic security; inside consensus."
- MAD:105-110: "**T2 — the CommitteePool bridge** ... the 200K-voter / 512-committee pool carried over
  from the replay reseal ... with an `AllowHandover` path where real staked keys replace simulated pool
  slots. A transitional consensus-evidence layer".
- GCFG:594-595: "The seed and sizes MUST match the replay resealer's (--bls-seed / pool sizes) for the
  live node to continue a resealed chain byte-identically." GCFG:603-606: with `AllowHandover` off the
  committee is "fully simulated and the per-block evidence deterministic across nodes."
- ARCH:134-135 / FLOWS (staking scan path): n42-26 has a staking plane ("track validator stake deposits
  and registrations; resolve BLS pubkey → staker EVM address"); FLOWS (validator reconfig path):
  `propose_add_validator`.
- PL:46-47: "7 节点为常用基线，扩展更多验证者时必须按实际验证者集合核对 quorum，同时验证投票处理开销、换主、超时及同步。"
- ARCH:203: "a failure in mobile verification should not prevent consensus progress unless the
  implementation incorrectly couples the two."

**Standard.** A3 genesis set, n >= 4; AM5 fixed genesis set, reconfiguration disabled; A19 committee pool
`{poolSize 200000, committeeSize 512}` "mandatory and always on", `allowHandover` refused; I2 "a Profile-1
validator MUST run the mobileverify service (it needs the registry root to lead)"; AM11(b) proven on 4-7
validators, 100+ gate later; G5 64 KiB sized for n = 512.

| # | Finding | Severity |
| --- | --- | --- |
| 2.1 | **The committee pool is a simulated artefact made mandatory.** By gov5's own definition (GCFG:594-606) the 200,000/512 pool exists to continue a *resealed* (replayed) chain byte-identically, and with handover refused (A19) every committee key derives from the public `seedHex`: the per-block "committee evidence" hashed into `parentBeaconRoot` (B5) carries no security. MAD calls it "transitional" and a "T2 artifact for backfilling legacy chain evidence" (MAD:117). The standard's own premise is "no compatibility debt" and P5 "Delete old-data rules", yet A19 makes this replay artefact mandatory from block 0. The genesis comment "total mobile-voter pool" (GCFG:599) also invites the misreading that 200,000 phones vote. | DEVIATION (from P5 and from the design documents' stated purpose of the pool). Recommendation: change the standard -- either drop A19/B5's evidence from Profile 1 (`parentBeaconRoot` zero, as Ethereum-free native chains allow) or keep it and state in A19 that the evidence is a deterministic simulated commitment with no security meaning, not a validator or verifier committee. |
| 2.2 | **I2 couples leadership to the mobile service.** "A validator without `--mobileverify.http` cannot build" (CLAUDE.md; I2: "it needs the registry root to lead"). MAD:7-9 ("can never delay a block") and ARCH:203 forbid that coupling: if the service fails, the leader cannot propose and its tenure costs a timeout. | DEVIATION. Recommendation: change I2 -- a leader whose registry is unavailable stamps the last committed root (or zero) and proposes; running the service becomes SHOULD; the header root stays the proposer's statement (AM12). |
| 2.3 | Fixed genesis set (AM5) vs n42-26's staking plane and reconfig path, gov5's "动态验证者（commit-then-activate）✅" (HS2-AUD:26) and MAD's T1 "ETH-style stake ... committee sampling for voting". No paper (WP included) *requires* dynamic sets or staking for Profile 1; WP:1040 defers economics. | SILENT gap, already acknowledged (AM5 reopens E2 before M3). Note as a Profile-1 limitation; committee sampling for voting (MAD:102) is a paper-level goal beyond Profile 1 and the standard should say so. |
| 2.4 | Scale: PL asks for "7 or more" validators and re-checking quorum, vote cost, leader change, timeouts and sync when scaling; the standard has n >= 4, evidence on 4-7, and AM11(b) adds a 100+ round "before production-ready". | CONSISTENT (AM11(b) covers it). Recommendation: make the 100+ round a numbered gate (M4) rather than prose. |
| 2.5 | Who validates: in the standard only the HotStuff set votes; phones attest outside consensus (I1). Matches MAD:20-28 and WP:1220 (consensus must work with every model -- by analogy every phone -- unavailable). | CONSISTENT. |

## 3. Consensus safety vs HotStuff-2

**Paper text [via review doc].** HS2-MAP states the paper's rules as: SR1 vote only if
`proposal.justify_qc.view >= locked_qc.view` (HS2-MAP:50); SR2 "Whenever a validator sees a PrepareQC,
it updates `locked_qc` (monotonically)" (:74); SR3 "A block is committed when, in the same view, both
PrepareQC and CommitQC have formed. No third phase." (:96); SR4 "The new leader uses the highest
`high_qc` from the TC as its `justify_qc`" (:113); SR5 `n = 3f+1, quorum = 2f+1` (:142); SR8
equivocation (:216); SR9 one vote per (view, round) (:233). Liveness: "The paper relies on the
*responsiveness* property: a correct leader can drive the protocol forward at network speed" (:254-255).
HS2-MAP §3 item 3 (:291-298): voting "before it has executed the block ... The paper does not mandate
this". HS2-AUD:24: "Dual leader regime（响应式/等待式）⚠️ 部分 — 等待 O(delta) 逻辑需确认". The paper
itself could not be checked for its treatment of stable leaders / tenure.

**Standard.** E1/A3 quorum 2f+1 with f = floor((n-1)/3); E6 `justify.view >= locked.view`; E7 one vote
of each kind per view, journalled; E11 QC/TC wire forms by reference to SYNC §1.2; E12 CommitQC commits a
block and its ancestors; A15 tenure T = 8; A22/E4 rotate-on-timeout (SYNC §10.2); A13 Round-1 vote on
static validity, CommitVote after own import; A10 deferred depth 1; E14 finality tags; E15 evidence only.

| # | Finding | Severity |
| --- | --- | --- |
| 3.1 | SR1, SR3, SR5, SR8, SR9 map onto E6, E12, A3/E1, E15, E7. f = floor((n-1)/3) for any n >= 4 is the paper's n >= 3f+1 (HS2-MAP:159-164). | CONSISTENT. |
| 3.2 | **The lock rule (SR2) and the view-change rule (SR4) are not stated in the standard.** E6 uses `locked.view` but no item says when `locked` changes; E11 cites only *wire forms*; nothing says the TC carries 2f+1 high QCs and the new leader's justify is the highest. These are presumably in N42-SYNC-SPEC, but the standard calls itself "self-contained as a rule set" (Std:5-6). A client that locks on CommitQC instead of PrepareQC, or picks a non-highest high QC, conforms to the standard's text and breaks safety/liveness. | SILENT gap (safety-critical). Recommendation: change the standard -- add E6a "lock := highest PrepareQC seen, monotone (SR2)" and E11a "TC = 2f+1 timeout messages each carrying a high QC; the next leader's justify is the highest of them (SR4)", each with a vector in V6/V7. |
| 3.3 | **Round-1 votes on blocks whose import can still fail, combined with the lock rule, can stall the chain permanently** (inference from SR1/SR2 + A13 + E6). A13 lets an honest node vote Round 1 on "static validity" and only gates the CommitVote on import. If a Byzantine leader proposes a block that passes E6's static checks but fails import on every honest node (e.g. a transaction that is not includable against the parent post-state), 2f+1 Round-1 votes form a PrepareQC, honest nodes lock on it (SR2), nobody CommitVotes, and every later proposal must extend the locked block (SR1, F5) -- whose child must carry the failed block's execution (A10/B13), which does not exist. The paper's model assumes a vote is cast only for a block that satisfies the validity predicate [via review doc: HS2-MAP:295-298 "if execution later fails, the validator's vote was for a block that won't be applied locally, which is benign as long as 2f+1 honest validators reach the same conclusion" -- that note covers safety, not this liveness case]. PHD's own vote rule has the missing piece and the standard dropped it: PHD:199-201 "a proposal for H is voted for once the follower has imported the parent, H's execution fields equal the follower's own result for the parent, and H's transactions pass the includability check against that post-state"; std A13/E6 require only the B13 fields. PHD:275-279 also admits a residual hole even with the check: "A block whose execution then fails here (an intrinsic-gas or state-dependent failure the includability pass does not see, EIP-8037's state gas among them) leaves this node without a recorded result for it, so it refuses to vote on the child" -- which, once that block is locked, is the stall described here. | DEVIATION (from the paper's validity assumption and from PHD's vote rule; the standard does not define "static validity" tightly enough to exclude it). Recommendation: change the standard -- put PHD's includability check into E6/A13 as a normative Round-1 condition (with its exact list, PHD:255-258), and close the residual hole by rule: either import of a block that passes it never fails (a transaction that fails for a reason the check does not see is executed as a defined no-op/fee-only failure, never a block failure), or the check is extended until that holds. Add a V5 case and an M3d negative-leader case for it. |
| 3.4 | **What a CommitQC certifies under deferred execution is stated two different ways.** A13's reason: the gate "keeps 'a CommitQC proves 2f+1 executions'". E14: `safe` = "committed (CommitQC) and executed". PHD 17.7 (:658): "**safe**: the newest certified block. A commit of N+1 under deferred execution certifies N (N+1's header carries N's fields and its quorum checked them)". With k = 1 a CommitQC on N shows that 2f+1 nodes *imported* N, not that they *agree* on N's state root -- agreement exists only when the QC on N+1 (whose header carries N's root) forms. The standard also marks n42-rs's `split` mode as the rule (E14), but `split` implements PHD's definition, one block behind E14's. | DEVIATION (standard vs PHD design doc; and an overstatement in A13's reason). Recommendation: change E14 -- `safe` = highest N such that a CommitQC exists on a descendant whose header carries N's execution fields (N+k) and the local execution matches; reword A13's reason to "2f+1 imports of N; agreement on N's result is certified by the CommitQC on N+k". |
| 3.5 | **"Import" is undefined.** FVM (n42-26's "approved target architecture", FVM:3) makes the default follower path "cache-hit": applying the leader's state diff, which "is not full replay" (FVM:14-15); PL:19 describes the performance route as "同机多个验证者独立投票，同一块执行一次并共享结果". If the CommitVote gate (A13) is satisfied by applying a leader-provided diff or a co-located shared execution, a CommitQC does not prove 2f+1 *independent* executions. | SILENT gap. Recommendation: change A13 -- "own import" means independent execution of the block's transactions against the node's own parent state; diff application and shared execution across validators are not Profile 1. |
| 3.6 | Responsiveness: A17's 500 ms minimum pacing and the n42-rs straggler grace (F8, local) mean a correct leader deliberately does not proceed "at network speed". The paper's responsiveness is an upper-bound property, so pacing does not break safety or liveness; the dual-leader / wait-Δ regime after a view change (HS2-AUD:24, "partial") is not addressed by the standard; E5's pacemaker is SHOULD only. | SILENT (liveness, not safety). Recommendation: note in E5 that Profile 1 trades the paper's optimistic responsiveness for fixed pacing and state the post-TC leader behaviour (propose immediately with the TC's highest QC, or wait) explicitly; it is in SYNC §10.2 if anywhere. |
| 3.7 | Tenure T = 8 with rotate-on-timeout: no safety effect (leader choice is outside the safety argument). Liveness: rotate-on-timeout bounds a *crashed* leader's cost; a Byzantine leader that proposes just inside the timeout keeps its 8 views (paces the chain at up to `baseTimeoutMs` per block for 8 views). The paper's treatment of stable leaders could not be checked locally. | SILENT (liveness under a slow Byzantine leader). Note as a Profile-1 limitation; M3a tests only a killed leader -- add a "slow leader" case to M3d. |
| 3.8 | Equivocation evidence only (E15, O5): SR8 defines the faulty behaviour, not a penalty. | CONSISTENT. |

## 4. State commitment vs QMDB (and the whitepaper's QMDB)

**Paper text [via review doc].** QMDB-REV:29-30: "Entry: Id, Key, Value, NextKey, OldId, OldNextKeyId,
Version. NextKey makes exclusion proofs (`E.Key < K < E.NextKey`); OldId/Version make historical proofs."
QMDB-REV:39-41: compaction "re-appends old live entries ... old twigs become inactive and are pruned".
QMDB-REV:42: sharding by the top bits of the key hash. QMDB-REV:43-44: "N+1 serializability"; write only
finalized data. QMDB-REV:57 (side by side): paper proofs = "inclusion, exclusion, historical"; gov5
"inclusion; historical bits"; n42-rs "inclusion at the head only". QMDB-REV:61: gov5 compaction "moving
live entries changes the root". QMDB-REV:62: gov5 `ShardedTree` "opt-in, new chains: its root differs".
QMDB-REV:94-97: "Without NextKey there is no exclusion proof (a light client cannot prove an account does
not exist) ... The format is frozen by the gov5 fixtures, so this is a fork-gated, cross-client change".
WP:797-799 only says QMDB is being validated as data support for the Decision Registry, Receipt Index and
reputation state. ARCH:13, :112-114: "a default QMDB-style binary twig state-proof backend ... maintain
the QMDB-style binary twig root and proofs ... expose proof queries via RPC". FVM:10-13, :74-75: the target
commitment is "QMDB root + LtHash summary committed by the proposal/header" (status "Missing").
HS2-AUD:205-210: stateless validation "手机验证场景需要".

**Standard.** A5 QMDB only; D6 "gov5 `lib/qmdb` twig tree with `qmdb_compat` encodings, ops sorted by key
hash"; A9 unchanged-account no-op; D5 storage net change; D4 EIP-161 deletion; J1 "witness/proof methods
refused on QMDB"; §3 state sync servers `qmdb_status/manifest/twigs` with portable `0x03` records; P2
lists `ltHashTime` among the activation fields that do not exist on Profile 1.

| # | Finding | Severity |
| --- | --- | --- |
| 4.1 | A9 / D5 define the write set (what an "update" is). The paper [via review doc] counts the cost of update/create/delete (QMDB-REV:35-37) but leaves the write set to the application; a positional root needs it defined. | CONSISTENT (the standard fills a gap the paper leaves). |
| 4.2 | **No state proof of any kind for a light client or phone.** D6 freezes gov5's entry format (no NextKey, OldId, Version: no exclusion or historical proof), and J1 refuses witness/proof RPCs. The paper's proof set, ARCH's "proof queries via RPC", and the mobile/stateless motivation in HS2-AUD are all absent. | SILENT gap. Paper-level goal beyond Profile 1 -- but the standard should say so in J1/D6 ("Profile 1 offers no state proofs; inclusion proofs over the D6 root are a P7 addition with a proof-format vector"). |
| 4.3 | **Compaction is not mentioned.** The paper compacts by active ratio; gov5's compaction "changes the root" (QMDB-REV:61); n42-rs has merged file-level compaction stages. On a positional root, a client that compacts by its own schedule forks. | SILENT gap (consensus-critical). Recommendation: change D6 -- "no operation other than the D4/D5/A9 write set may change the tree; root-changing compaction is not Profile 1; file-level compaction MUST be root-neutral (vector V3)". |
| 4.4 | **Sharded vs single tree is not named.** D6 says "gov5 `lib/qmdb` twig tree", but gov5 has both a single tree and an opt-in `ShardedTree` with a different root (QMDB-REV:62); the paper shards. | SILENT gap. Recommendation: D6 names the unsharded tree explicitly (V3 pins it). |
| 4.5 | **LtHash.** n42-26's approved target puts "QMDB root + LtHash summary" in the header (FVM:3, :28, :75); P2 lists `ltHashTime` as a field Profile 1 does not have, so Profile 1 has no LtHash. | DEVIATION (from n42-26's approved target architecture; not from any paper). Recommendation: note as a Profile-1 limitation and a P7 candidate, and have n42-26 mark FVM's LtHash item "not Profile 1". |
| 4.6 | Finalized-only writes / N+1 serializability (paper) vs n42-rs's forest of non-final blocks (QMDB-REV:86-92): a local implementation choice; nothing consensus-visible. | CONSISTENT (not a standard matter). |
| 4.7 | State sync (§3) with portable `0x03` records and the anchored ranges: no paper speaks to it. | CONSISTENT. |

## 5. Signature schemes / post-quantum

**Paper text.** WP: nothing about signature algorithms; only that cryptographic verification stays
deterministic (WP:103-116) and "Replay | nonce + expiry + chain/domain separation" (WP:1092, for DDN
messages). PL:18 makes the compatibility mainline "兼容 ETH ECDSA（secp256k1）交易" and PL:19 and PL:61-62 put
0x50 Ed25519 on the separate performance route: "与第一条路线的 ETH ECDSA 交易配置分别维护和验收；跨实现互通须
选择相同交易及帧配置". SIG:31: Falcon-512 verification at CPU parity with ecrecover; SIG:68-69: "Falcon-512 是唯一
CPU 成本与现状持平的方案，但 1.5 KB/笔的字节成本在 16 万笔/块下不可承受".

**Standard.** A11/O3: 0x50 not in Profile 1; reservation table: `0x51` reserved for a post-quantum
(Falcon / FN-DSA) type, opt-in; every `0x50-0x5F` type refused; E10 BLS12-381 POP for consensus; mobile
receipts BLS (MV3:122).

| # | Finding | Severity |
| --- | --- | --- |
| 5.1 | Profile 1 = PL's compatibility mainline (secp256k1 transactions); 0x50 on the performance route behind a separate protocol configuration. | CONSISTENT. |
| 5.2 | 0x51 opt-in, never default, citing the ~1.5 KB size cost. | CONSISTENT with SIG:68-69. |
| 5.3 | Post-quantum covers only a future transaction type. Consensus signatures (BLS12-381: proposals, votes, QCs, seal B2), mobile receipts and the committee evidence are all pairing-based and not post-quantum; no document sets a PQ goal for them, and the standard does not say so. | SILENT. Paper-level goal beyond Profile 1 (no paper requires it); recommend one line in the reservation section: "a PQ transaction type does not make consensus or mobile attestations PQ". |
| 5.4 | E10 domains `(chainId, genesisHash, phase, view)` match WP:1092's "chain/domain separation" principle (stated for DDN, not consensus). | CONSISTENT. |

## 6. Economics

**Paper text.** WP:1040: "v0.1 **does not predefine reward ratios, inflation models, or node yield**.
These should be specified in a separate economic proposal only after real cost data has been
established." WP's fees (WP:1009-1017) are DDN service fees, not chain fees. FLOWS (reward settlement):
"Bridge finalizes attestation → Reward manager records verifier pubkeys → Epoch boundary reached →
Compute logarithmic reward allocation → Inject EIP-4895 withdrawals"; FLOWS security invariant: "reward
emission should happen only after finalized aggregate attestation". MV3:11 and :383: "the reward model
(gov5 item 8)" open for the owner. HS2-AUD:34: "HIGH — Finalize 无区块奖励——验证者零经济激励". MAD:42:
"a future reputation/reward layer. Never BFT safety." HS2-MAP:223: gov5 has a slashing hook
(`slashing.go`).

**Standard.** A8 `devBlockReward` 1 ETH to coinbase and to `devFaucetAddress` per block as withdrawals
(AM8, AM12, AM16); B14 EIP-1559 base fee; E15/O5 evidence only, no slashing; no stake.

| # | Finding | Severity |
| --- | --- | --- |
| 6.1 | Dev reward + faucet: a testnet mechanism; WP explicitly defers economics. | CONSISTENT with WP (testnet premise). |
| 6.2 | Mobile verifier rewards (n42-26's logarithmic allocation, gov5 item 8) are absent; certificates earn nothing. | SILENT gap. Paper-level goal beyond Profile 1; recommend I1 say "no mobile reward in Profile 1; a reward rule is a P7 change". |
| 6.3 | No slashing (O5) while gov5's code has a slashing hook: the standard makes it unreachable implicitly. | SILENT. Recommend E15 say "slashing hooks MUST NOT change state on Profile 1". |
| 6.4 | EIP-1559 base fee (B14) is computed from the parent header's `gasUsed`, which under A10 is the grandparent's execution; the standard states this. Fee destination (burn) follows Amsterdam implicitly. No paper speaks to chain fees. | CONSISTENT (consider stating "base fee burned, as Ethereum" in B14 for completeness). |

## 7. Throughput

**Paper text.** WP:1166: "Project test records for N42 show n42-rs reaching 3.13M tx/s. This figure
reflects a project test methodology and does not represent sustained throughput on a public mainnet under
real-world network conditions." PL:71: n42-rs target 4.32M; PL:68-69: n42-26's best committed record
170,546 TPS (with verification bypass), the strict A1 record 37,952 TPS (PL:69). PL:18-19: extreme
throughput is the performance route (0x50, frames), separately configured.

**Standard.** AM11: "At 480M gas and 500 ms a block holds at most 480M / 21,000 ≈ 22,857 plain
transfers, about 46k TPS, so a Profile-1 round is never compared with a single-client performance figure."

| # | Finding | Severity |
| --- | --- | --- |
| 7.1 | Profile 1's ceiling (~46k TPS) is ~68x below WP's 3.13M; WP hedges its figure and PL puts high throughput on the performance route. The 3.13M runs were single-client n42-rs bench chains with features AM9 lists as outside the profile (I did not verify each run's exact configuration). | CONSISTENT, but a public-claims risk. Recommendation: note in AM11 that WP:1166 does not apply to a Profile-1 chain, and that any public figure for a mixed chain is Profile 1's. |
| 7.2 | 46k is above n42-26's strict A1 record (37,952 TPS, PL:69), so the M2a gate (">= 50% full blocks at 480M gas" while each client leads) is a real target for n42-26, not a formality. | SILENT (risk to milestone 2). Note it in O9/M2a. |

## 8. Data availability, blobs, EVM compatibility

**Paper text.** WP:44 lists PeerDAS among "existing technical foundation"; WP:1358 draws "Deterministic
Trust: Consensus / EVM / QMDB / PeerDAS / Crypto"; but WP:803: PeerDAS adaptation "remains an experimental
extension and has not been published as a stable interface", for "large Model Manifests, dataset
commitments" -- not blobs. WP:79: the deterministic layer is "Conventional code, EVM, cryptography".
PL:18-19, PL:117-118: the native chain's H2/QMDB header and roots "不能直接视为 Ethereum 共识网络已兼容"; the ETH
EL+CL route is separate.

**Standard.** O2 / C2: type 3 invalid ("no data-availability layer on a native chain"); B9 blob gas 0;
A4/AM1 Amsterdam as implemented by gov5 and n42-rs (not the upstream bundle); B7 receipts root =
`keccak(concat(...))` (not a trie); B6 withdrawals root likewise; AM3 requestsHash = empty-trie root (not
EIP-7685); O7 equal timestamps; J1 no `eth_getProof`.

| # | Finding | Severity |
| --- | --- | --- |
| 8.1 | Blobs off while WP places PeerDAS in the deterministic trust layer. WP's PeerDAS is for DDN artefacts and experimental; the standard's "no DA layer" is a statement about blobs. | SILENT tension. Paper-level goal beyond Profile 1; recommend O2 say "PeerDAS (WP:801-803) is not part of Profile 1" so the two documents do not read as contradicting. |
| 8.2 | EVM execution is Ethereum's (Amsterdam subset, AM1); header commitments are not (QMDB state root, concat receipts/withdrawals roots, non-EIP-7685 requestsHash, equal timestamps, no state proofs). WP claims only "EVM"; PL already says the native chain is not Ethereum-consensus compatible. | CONSISTENT. Recommend a short "EVM-compatible, not Ethereum-header-compatible" note listing B6, B7, AM3, O7, J1 for tool and bridge authors. |
| 8.3 | Block-STM (WP:44, :1251) and consensus-execution separation (WP:44) | CONSISTENT: execution strategy is local; A10 is the separation. |
| 8.4 | AI outside the critical path (WP:1192-1224): nothing in the standard involves models. | CONSISTENT. |

---

## Summary

**DEVIATIONS (must be resolved)**

1. 2.1 A19 makes the seed-derived, simulated 200,000/512 committee pool -- by gov5's own definition a
   replay-continuity artefact -- mandatory from block 0, against P5 and the design docs' "transitional".
2. 2.2 I2 couples leadership to the mobileverify service, against MAD:7-9 and ARCH:203.
3. 3.3 Round-1 votes on blocks whose import can fail + the lock rule can stall the chain permanently;
   "static validity" must cover includability, or import of a statically valid block must never fail.
4. 3.4 E14/A13 say a CommitQC on N means N is certified/executed; PHD 17.7 (and n42-rs `split`) certify N
   only with the QC on N+1.
5. 4.5 No LtHash in Profile 1 vs n42-26's approved target architecture (resolve by noting it, not by adding it).

**SILENT gaps**

1.2 mobile cohort windows at 500 ms (unproven; mv4h4b2 ran ~2.3 s blocks) · 1.3 canonical registry
membership · 2.3 staking / dynamic sets / committee sampling (acknowledged) · 3.2 lock rule SR2 and TC
high-QC rule SR4 not stated · 3.5 "import" undefined (diff application / shared execution) · 3.6
responsiveness and post-TC leader behaviour · 3.7 slow Byzantine leader with T = 8 · 4.2 no state proofs ·
4.3 compaction · 4.4 sharded vs single tree · 5.3 consensus and mobile signatures not PQ · 6.2 mobile
rewards · 6.3 slashing hooks · 7.2 46k vs n42-26's 38k strict record · 8.1 PeerDAS.

**Answer to AM11(a):** the "8-second slot" is n42-26's former block interval (ORCH:547, SLOT:45), not a
whitepaper requirement and not a mobile window; 500 ms replaces it. What the change does break is the
mobile cohort timing, which is counted in blocks (1.2).

**Three most important recommendations**

1. Make the consensus core self-contained and safe under deferred execution: add the lock rule (SR2) and
   the TC high-QC rule (SR4); define E6 static validity to include every check that can make import fail
   (or make import infallible); define "own import" as independent execution; redefine `safe`/the A13
   reason so a CommitQC on N+k is what certifies N's execution.
2. Decouple mobile verification from block production and timing: I2 becomes SHOULD with a fallback root;
   cohort windows in milliseconds (or scaled by `blockIntervalMs`); gate M1' on certification at 500 ms.
3. Re-examine A19: drop the simulated committee pool from Profile 1 or state plainly that its evidence
   has no security meaning; at the same time pin D6 (unsharded tree, no root-changing compaction) and
   state the Profile-1 limitations explicitly (no state proofs, no LtHash, no PQ consensus, no rewards for
   phones, WP:1166's 3.13M does not apply).
