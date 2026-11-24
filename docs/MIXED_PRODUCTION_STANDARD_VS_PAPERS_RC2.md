# Mixed production standard v1.0-rc2 against the primary sources (HotStuff-2, QMDB, EIPs)

2026-11-24. Read-only audit. Subject: `docs/MIXED_PRODUCTION_STANDARD_V1_RC.md` (v1.0-rc2, commit
`f6c2fd6aa`; "rc2" below, cited as `rc2:<line>` and by item id). History: `docs/MIXED_PRODUCTION_STANDARD.md`
(AM1-AM24). Predecessor: `docs/MIXED_PRODUCTION_STANDARD_VS_PAPERS.md` ("VSP", checked v0.3). Nothing in
rc2 or in any client was changed by this audit.

Labels: **CONFORMS** · **DEVIATES-STATED** (deliberate, written in rc2) · **DEVIATES-UNSTATED** ·
**GAP** (the source requires it, rc2 is silent) · **NOT-CHECKED**.

---

## 0. Sources actually read

| Source | URL | Obtained |
| --- | --- | --- |
| HotStuff-2 (Malkhi, Nayak), ePrint 2023/397 | https://eprint.iacr.org/2023/397 and `.../2023/397.pdf` | **Abstract page only** (title "Extended Abstract: HotStuff-2: Optimal Two-Phase Responsive BFT", received 2023-03-20, last revision 2023-04-17, abstract). The PDF and the versions page answer HTTP 403 / a Cloudflare challenge to both fetch paths. **The paper text was NOT read.** Every HotStuff-2 rule below therefore comes, as in VSP, from gov5's rule map `n42-gov5/docs/consensus/hotstuff2-spec.md` ("HS2-MAP", 371 lines, read in full) and the audit summary `n42-gov5/docs/HotStuff-2.txt` ("HS2-AUD") and is marked **[via review doc]**. |
| QMDB (LayerZero Labs), arXiv 2501.05262 | https://arxiv.org/html/2501.05262 | **Full text, v3 (01 Feb 2025)**, read through the fetch tool's extractor (it returns quoted excerpts, each under 125 characters, not the raw page). The PDF (https://arxiv.org/pdf/2501.05262) was downloaded but no PDF text tool exists on this host, so it was not read. Cited as "QMDB §x". |
| EIP-7685 | https://eips.ethereum.org/EIPS/eip-7685 | Full (Final). |
| EIP-1559 | https://eips.ethereum.org/EIPS/eip-1559 | Full. |
| EIP-4844 | https://eips.ethereum.org/EIPS/eip-4844 | Full. |
| EIP-4895 | https://eips.ethereum.org/EIPS/eip-4895 | Full. |
| EIP-4788 | https://eips.ethereum.org/EIPS/eip-4788 | Full. |
| EIP-2935 | https://eips.ethereum.org/EIPS/eip-2935 | Full. |
| EIP-3675 (header constants after the merge) | https://eips.ethereum.org/EIPS/eip-3675 | Full. |
| EIP-4399 (mixHash = prevRandao) | https://eips.ethereum.org/EIPS/eip-4399 | Full. |
| EIP-7843 (slotNumber) | https://eips.ethereum.org/EIPS/eip-7843 | Full (Last Call, deadline 2026-11-01). |
| EIP-7702, EIP-7928, EIP-7934, Yellow Paper | — | **Not fetched** (rc2 adopts 7702 by reference only; 7928/7934 are excluded by rc2 explicitly). |

Local documents: `docs/QMDB_PAPER_REVIEW.md` ("QMDB-REV"), `docs/PHASE_D_DEFERRED_EXECUTION.md` ("PHD"),
`docs/GLAMSTERDAM_EXECUTION_PARITY.md` ("GXP"), the V1 genesis
`/data/blockchain/wr-logs/qs-scratch/profile1/vectors/V1/genesis_8s.json`, and the code cited in §7.

---

## 1. HotStuff-2 safety

All paper statements in this section are **[via review doc]** (HS2-MAP), because the paper text could not be fetched.

| # | Rule (paper, via HS2-MAP) | rc2 | Label |
| --- | --- | --- | --- |
| 1.1 | **Vote rule** SR1: vote only if `justify_qc.view ≥ locked_qc.view` (HS2-MAP:48-50). | E6 (rc2:281-283): "votes only for a proposal whose justification is not below its lock (`justify.view ≥ locked.view`)", plus "block parent = the justify QC's block" (rc2:280) and F5. AM19's longer form ("extending its lock unless the justification is higher", STANDARD:831-833) is equivalent under one QC per view. | CONFORMS |
| 1.2 | **Lock rule** SR2: lock = highest PrepareQC seen, monotone (HS2-MAP:72-89). VSP 3.2 flagged it as unstated. | E6 (rc2:281-282): "a node locks on the block of the highest PrepareQC it has seen". Monotonicity is implied by "highest". | CONFORMS (VSP 3.2 resolved by AM19) |
| 1.3 | **Commit rule** SR3: committed when PrepareQC and CommitQC form in the same view; no third phase (HS2-MAP:94-96). | E12 (rc2:300): "A CommitQC on a block commits it and its ancestors (its order …)". A CommitQC presupposes the PrepareQC of the same view (CommitVote is cast on a PrepareQC, A13, rc2:114-116). | CONFORMS |
| 1.4 | **View change** SR4: the TC carries the highest `high_qc`; the new leader uses it as `justify_qc`; replicas lock on it (HS2-MAP:111-138). VSP 3.2 flagged it as unstated. | E6 (rc2:282-283): "A leader that enters a view by a TC proposes on the highest QC the TC carries." Replicas are not told to lock on the TC's QC, but it is "a QC seen", so the lock rule covers it; the replica-side check is then the vote rule itself. | CONFORMS (VSP 3.2 resolved by AM19) |
| 1.5 | **Quorum** SR5: `n = 3f+1`, `quorum = 2f+1` (HS2-MAP:140-142). Safety needs any two quorums to intersect in ≥ f+1 nodes: `2q − n ≥ f+1`. | A3 (rc2:63-64): "`f = ⌊(n−1)/3⌋`, quorum `2f+1`, `n ≥ 4`". With `n = 3f+1+r`, `r ∈ {0,1,2}`, two `2f+1` quorums intersect in `f+1−r` nodes: **for n = 5, 8, 11, … (r = 1) the intersection can be f Byzantine nodes; for n = 6, 9, … (r = 2) it can be f−1** — a Byzantine leader that equivocates gets two conflicting QCs. All three clients already use `q = n − f`: n42-rs `crates/n42/h2-consensus/src/validator/set.rs:105-114` ("Unlike `2f + 1`, this remains safe when … greater than `3f + 1`"), gov5 `internal/consensus/hotstuff/validator.go:60-75` (the comment works the n = 8 counterexample), n42-26 `crates/n42-chainspec/src/lib.rs:168-169`. HS2-MAP:159-164 ("correct for any n ≥ 3f+1") is wrong, and VSP 3.1 repeated it. The two formulas agree only at n = 3f+1 (the 4-validator V1 genesis, 7, 100). | **DEVIATES-UNSTATED** (rc2's text is unsafe for n ≠ 3f+1 and disagrees with every client) |
| 1.6 | **Signed content and domains**: QCs bind `(view, block_hash)`; N42's separate Round-1/Round-2 domains are a hardening the paper does not have (HS2-MAP:166-197, :307-313). | E10 (rc2:293-296): `"N42H2V4" ‖ phase ‖ chainId ‖ genesisHash ‖ view ‖ payload`, vote = `blockHash`, proposal/commit = `blockHash ‖ changesHash`, timeout/newview = empty payload; POP DST. Chain- and genesis-bound. | CONFORMS |
| 1.7 | Timeout messages: the timeout signature (phase 4) covers only the view (E10; n42-rs `protocol/quorum.rs:99` `timeout_message(view)`), so a TC does not authenticate that its `high_qc` is the highest its signers hold. Safety does not depend on it (the vote rule rejects a lower justify); a Byzantine TC builder can only cost a view. | E10/E11 as above; not discussed. | CONFORMS (safety); liveness effect in 2.4 |
| 1.8 | One vote per (view, round) SR9; equivocation SR8 (HS2-MAP:214-248). | E7 (journalled one Round-1 + one CommitVote per view), E15, F6. | CONFORMS |

## 2. HotStuff-2 liveness and pacemaker

| # | Topic | Paper side | rc2 | Label |
| --- | --- | --- | --- | --- |
| 2.1 | Timeout growth, cap, dead leader | HS2-MAP:327-330: "The paper only requires *eventual* synchrony"; N42's exponential backoff is "adaptive" [via review doc]. | E5 (rc2:275-277, SHOULD): `min(eff·2^k, maxTimeoutMs)`, k reset "on QC/commit **or TC adoption**". A crashed leader's view ends in a TC formed by all live members, so k resets every view: gov5's "no backoff growth for a dead leader with rotate-on-timeout" is the rule working as written. After GST a fixed 24 s view exceeds slot + build + two hops (A16, rc2:125-126), which is the known-Δ form of eventual synchrony; the 96 s cap means liveness assumes post-GST delays fit in it. | CONFORMS [via review doc]; the paper's own pacemaker (view synchronisation) NOT-CHECKED |
| 2.2 | Leader rotation, rotate-on-timeout, slow leader | HS2-MAP:261 round-robin. | A15 tenure 1 (rc2:120-122), A22 no-op at T = 1. A slow Byzantine leader costs at most one view of ≤ 24 s (VSP 3.7's T = 8 concern is gone with AM22). | CONFORMS |
| 2.3 | Optimistic responsiveness | Paper title and HS2-MAP:254-255: a correct leader proceeds "at network speed" [via review doc]. | A17 (rc2:128-129) paces at 8000 ms; §1 (rc2:22) makes the 8 s slot the profile. Pacing gives up responsiveness deliberately; rc2 does not say that it does (VSP 3.6 asked for one sentence). | DEVIATES-STATED (the pacing); the missing sentence is documentation, see 2.4 |
| 2.4 | **Post-TC leader: wait for locks vs Δ** | HS2-AUD:24: "Dual leader regime（响应式/等待式）⚠️ 部分 — 等待 O(delta) 逻辑需确认" [via review doc]: HotStuff-2's leader that enters a view without the previous view's certificate must learn the highest lock of every honest replica (by waiting) before proposing. The exact rule (Δ multiple, "n−f messages or Δ") could not be read in the paper. | E6 (rc2:282-283): the leader proposes on the highest QC of the TC, with no wait. A TC needs only `q` timeouts. A replica locked on a PrepareQC that a Byzantine leader showed to it alone ("hidden lock") may not be among the TC's signers; the honest leader then proposes below that lock, the replica refuses (1.1), and with f Byzantine silent the proposal can miss its quorum. Neither client waits (no wait or lock-forwarding found in n42-rs `protocol/{state_machine,timeout,proposal}.rs` or gov5 `hotstuff/{proposal,timeout}.go`). Safety is not affected. | **GAP** (liveness; paper rule itself not verified against the text) |
| 2.5 | View synchronisation | HS2-MAP:264: a node fast-forwards on f+1 future-view timeouts [via review doc]. | Not in rc2 (E5 is local and SHOULD); the TC and the embedded TC (SYNC) carry nodes forward. | NOT-CHECKED (the paper's synchroniser could not be read) |

## 3. N42 additions the paper does not have

The paper's safety proof uses only the vote and lock rules: a vote **withheld** can cost liveness, never
safety; a vote **released** outside 1.1 would cost safety. Each addition is checked for both.

| # | Addition | Withheld forever? (liveness) | Released early? (safety) | Label |
| --- | --- | --- | --- | --- |
| 3.1 | **Deferred execution, depth 1** (A10, rc2:97-99; E14, rc2:309-311): header N+1 carries N's stateRoot/receiptsRoot/logsBloom/gasUsed; a CommitQC on N fixes N's order; N's execution is certified by the commit of N+1. | Only if honest nodes' executions of N differ (a client bug): Round-1 on N+1 then never gathers q, by design. | No: a Round-1 vote on N+1 requires the carried fields to equal the voter's own execution of N (A13 (2)), so a CommitQC on N+1 contains ≥ f+1 honest agreements on N. | CONFORMS (VSP 3.4 resolved: E14 and A13's reason were rewritten by AM19) |
| 3.2 | **AM19 Round-1 gate** (A13, rc2:108-113): static checks incl. seal and clock bound, the deferred check (carried fields + includability), the parent's import. | An honest leader's block passes all three on every honest node, so no. **But** A13 rc2:112-113: "A block that passes the check MUST be importable; a case where it is not is a bug, never a rule" is not achievable with a pre-execution check, and once q Round-1 votes form a PrepareQC on such a block, every honest node locks on it, nobody can CommitVote it, and every later proposal must extend it (1.1, F5) and carry its execution fields, which do not exist: **a permanent stall**. PHD:275-279 lists the hole ("an intrinsic-gas or state-dependent failure the includability pass does not see, EIP-8037's state gas among them"); EIP-7702 delegation (C3) adds another (a delegated EOA's balance can be moved by an earlier transaction of the same block). **rc2 itself creates a reachable case:** B8 (rc2:189): "A block whose execution produces a request is invalid", while the profile-1 alloc deploys the EIP-7002 and EIP-7251 contracts (`genesis_8s.json` contains `0x00000961Ef480Eb55e80D19ad83579A64c007002` and `0x0000BBdDc7CE488642fb579F8B00f3a590007251`; rc2 §4 rc2:478) and both clients run their end-of-block system calls (GXP:76, "same"). Any user transaction that pays the 7002 contract's fee enqueues a request, the same block's dequeue returns it, and n42-rs refuses the block after execution (`crates/n42/engine-types/src/hotstuff_consensus.rs:706`, `!result.requests.is_empty()`). The includability check (PHD:255-259: nonces, balance, chain id, fee caps, gas limits) does not look at call targets. Under F7 (seal before own execution) even an honest leader can propose such a block. No vector (V3/V4) covers it. | No. | **GAP** (liveness; user-triggerable chain halt). VSP 3.3 is therefore only partly resolved. |
| 3.3 | **CommitVote gate** (A13, rc2:114-116): after own independent execution; the leader's build counts. | No (an honest node executes a valid block). | No: the paper places no execution condition on the second vote; the gate only delays it. | CONFORMS (VSP 3.5 resolved: "own independent execution (not a diff …)") |
| 3.4 | **Conflicting-commit halt** (E12, rc2:301-304): stop importing, voting, producing; keep evidence; operator resumes. | Only after a proof of two conflicting commits, which under ≤ f faults cannot exist (the paper's safety theorem [via review doc]); single-peer data that is not a proof never halts. | No. | CONFORMS |
| 3.5 | **Progress votes / straggler grace** (E9, rc2:290-291; F8): no progress votes on profile 1; a grace sends none. | A grace only delays the leader's own QC within its view; the view timeout bounds it. | n42-rs: progress votes forced off under profile 1 (`state_machine.rs:1112-1122`, `vote_rules.rs:51-53`); received ones ignored (`voting.rs:46`, `vote_batch.rs:439-442`). | CONFORMS |
| 3.6 | **Timestamp** (B4, rc2:170-173): `parent.time ≤ time` on import; `time ≤ floor(now)+2` only before voting; leader stamps `max(parent.time, floor(now))`. | A vote waits at most until the voter's clock passes `time − 2`; bounded if honest clocks are within a few seconds (an assumption rc2 does not state; the paper needs no clocks [via review doc: HS2-MAP has no clock rule]). | No. | CONFORMS (note: the clock-skew assumption is implicit) |
| 3.7 | Committee evidence in `parentBeaconRoot` (A19/B5) | Not a vote condition. | — | CONFORMS (A19 rc2:136-138 states it has no security meaning) |

## 4. State commitment vs the QMDB paper

| # | Topic | Paper (arXiv 2501.05262v3) | rc2 | Label |
| --- | --- | --- | --- | --- |
| 4.1 | Hash function, leaf hashing, twig-root and global-root combination | **Not specified**: "does not name SHA-256, Keccak, Blake3"; only "The twig root is determined by the sequence of entries, making it path-dependent" (§3.1) and "a single global root that connects a set of shard roots" (§3). | D6 (rc2:259-260) pins gov5 `lib/qmdb` + `qmdb_compat` (Blake3, QMDB-REV:57-58) and V3 pins bytes. | CONFORMS (rc2 fills what the paper leaves open) |
| 4.2 | Entry layout | §3.1 Table 1: Id, Key, Value, NextKey, OldId, OldNextKeyId, Version. Create appends the new entry **and** a rewritten predecessor (§3.3, "1 SSD read and 2 entry writes"). | D6 freezes gov5's entry (key, value; no NextKey/OldId/Version, QMDB-REV:59). A5 calls the scheme "QMDB" without saying its entries and its create/delete ops are not the paper's. | **GAP** (documentation: rc2's "QMDB" is a twig tree in the paper's shape, not the paper's entry construction) |
| 4.3 | Proofs (VSP 4.2) | §3.4: inclusion, exclusion (`Key < K < NextKey`), historical (via OldId). | §7 non-goals (rc2:550-551) "state proofs as a consensus object"; J1 refuses witness/proof methods. | DEVIATES-STATED (VSP 4.2 resolved by AM20) |
| 4.4 | Compaction (VSP 4.3) | §3.1: a worker "duplicates old valid entries into the fresh twig"; "The compaction logic must be deterministic when used in a consensus system or for stateless validation." Re-appending changes the path-dependent root. | D6: "compaction and any storage maintenance MUST be root-neutral". Stricter than the paper (forbids the deterministic root-changing compaction the paper allows). Consequence not stated: a twig that keeps one live entry can never become Inactive/Pruned (§3.1 Table 2), so the committed tree's entry count only grows. | DEVIATES-STATED (VSP 4.3 resolved by AM20); growth consequence is documentation only |
| 4.5 | Sharding (VSP 4.4) | §3.5: shards "using the most significant bits" (16 as the example). | D6: "one unsharded tree". | DEVIATES-STATED (VSP 4.4 resolved by AM20) |
| 4.6 | Write set (A6 genesis root, A7, A9, D4, D5) | The paper defines update/create/delete costs (§3.3) and leaves what counts as an update to the application. | A9/D4/D5 define it; A6 genesis root = QMDB root of the alloc. | CONFORMS |
| 4.7 | Finalized-only writes, N+1 serializability | §5: "only write finalized data"; "N+1 serializability". | Silent (local storage matter). | CONFORMS (not a standard matter) |

## 5. Header fields against the EIPs (AM24's principle)

AM24 (STANDARD:891-892): "wherever Ethereum defines a value, N42 takes Ethereum's". Checked field by field;
nothing changed.

| # | Field | Ethereum's definition | rc2 | Label |
| --- | --- | --- | --- | --- |
| 5.1 | `requestsHash` | EIP-7685 Rationale: "For a block with no requests data, the `requests_hash` is simply `sha256("")`." | B8 (rc2:186-188): `sha256("")`, checked. | CONFORMS (AM24). The second sentence of B8, "a block whose execution produces a request is invalid", deviates from EIP-7685 (Ethereum commits the requests) and is the trigger of 3.2. |
| 5.2 | `ommersHash` | EIP-3675: `0x1dcc4de8…d49347` = "Keccak256(RLP([]))". | A6 (rc2:77) and B3 (rc2:166-167): zero, "the empty-list hash is refused". | DEVIATES-STATED, but **against AM24's own principle**: Ethereum defines this value and rc2 explicitly refuses it. No reason is written in rc2 (history: "gov5 02:55 readings … ommers zero in genesis", rc2:613). Compatibility: any Ethereum header validator rejects every profile-1 header. |
| 5.3 | `mixHash` | EIP-4399: "client software MUST set the value of the mixHash … to the latest RANDAO mix"; `PREVRANDAO` returns it. (EIP-3675's zero constant is superseded.) | A6/B3: zero. `PREVRANDAO` is therefore constant 0 on profile 1. | DEVIATES-STATED (value written); the EVM consequence (`PREVRANDAO` = 0) is unstated. No beacon RANDAO exists on a native chain, so Ethereum's value is not available; HS2-AUD:75 notes gov5 has a CommitQC-derived block randomness that profile 1 does not use. |
| 5.4 | `difficulty`, `nonce` | EIP-3675: 0 and `0x0000000000000000`. | B3: 0, 0. | CONFORMS |
| 5.5 | `extraData` | EIP-3675: `MAX_EXTRA_DATA_BYTES` = 32. | B1 (rc2:154): up to 4096 bytes (QC + seal). | DEVIATES-STATED (necessary for QC/seal; the 32-byte limit is not named as departed from) |
| 5.6 | `withdrawalsRoot` / withdrawals | EIP-4895: withdrawal = `[index, validator_index, address, amount]` (Gwei); root = Merkle-Patricia trie "keyed by index in the list". | B6 (rc2:178-181): `keccak256(concat(rlp([address, amount])))`, `keccak256("")` when empty; used for block rewards (A8); genesis uses the empty-trie root (A6). | DEVIATES-STATED (formula written; it is neither EIP-4895's encoding nor its trie). Not reconciled with AM24. |
| 5.7 | `receiptsRoot` | Ethereum: trie of receipts (not among the fetched EIPs; Yellow Paper not fetched). | B7: `keccak256(concat(rlp([status, cumulativeGas, logs])))`, describing N−1 (A10). | DEVIATES-STATED (Ethereum side NOT-CHECKED against a fetched text) |
| 5.8 | `stateRoot` | Ethereum: MPT root. | A5/A6/D6: QMDB root, describing N−1. | DEVIATES-STATED (core design) |
| 5.9 | `parentBeaconRoot` | EIP-4788: "exactly the hash tree root of the parent beacon block"; genesis "must be `0x0`"; stored by the system call at `timestamp % 8191`. | B5 (rc2:175-176): `Blake3(committee evidence)`, zero for block 1; A6: zero at genesis; D3 runs EIP-4788. | DEVIATES-STATED (no beacon chain; A19 says no security meaning). Unstated side effect: with equal timestamps (B4) the second block overwrites the first's ring-buffer slot, so `get(t)` answers only the later root (EIP-4788 `set()` semantics). Deterministic; documentation. |
| 5.10 | `blobGasUsed`, `excessBlobGas` | EIP-4844: `excess_blob_gas == calc_excess_blob_gas(parent)`, which is 0 when `parent.excess + parent.used < target`. | B9 (rc2:192): both 0, checked; C2 refuses type 3. With no blob gas ever used, 0 is exactly Ethereum's value. | CONFORMS |
| 5.11 | `baseFeePerGas`, `gasLimit`, `gasUsed` | EIP-1559: elasticity 2, denominator 8, from `parent_gas_used`; gas limit within ±parent/1024; `gas_used ≤ gas_limit`. | B14 (rc2:206-207): same formula from the parent's `gasUsed` field "as written (under A10 the grandparent's execution)"; A23 constant limit (satisfies ±1/1024); B13 `gasUsed ≤ parent.gasLimit`. | CONFORMS in formula; DEVIATES-STATED in input (deferred field) |
| 5.12 | Element 22, block access list hash | EIP-7928 (not fetched): a 32-byte hash. | B12 (rc2:200-201): the `0x80` gap; "A real EIP-7928 hash is not in profile 1." | DEVIATES-STATED |
| 5.13 | Element 23, `slotNumber` | EIP-7843: "equal to the corresponding slot number for this block", "calculated in the consensus layer"; no validity rule. | B10 (rc2:194): the block number. The consensus-layer analogue on profile 1 is the view (block number and view diverge after every TC). | DEVIATES-STATED (Ethereum defines it only via a beacon slot; the choice of number over view is not argued) |
| 5.14 | Element 24, `mobileRegistryRoot` | Not an Ethereum field. | B11. | N42-only (out of scope) |
| 5.15 | Timestamp strictness | Ethereum: strictly increasing (Yellow Paper, not fetched). | B4: "Equal timestamps are valid (Ethereum's strict `>` does not apply)." | DEVIATES-STATED |
| 5.16 | System contracts | EIP-2935: parent hash at `(number−1) % 8191`, nothing written at genesis. | D3 (rc2:249-250): EIP-2935 and EIP-4788 run every block. | CONFORMS |
| 5.17 | `coinbase` | Fee recipient, any address. | B3: the proposer's address. | CONFORMS |

Remaining header fields where rc2 differs from an Ethereum-defined value: `ommersHash` (5.2, contrary to
AM24's principle), `mixHash`/`PREVRANDAO` (5.3), `extraData` length (5.5), withdrawals encoding and root (5.6),
`receiptsRoot` construction (5.7), `stateRoot` (5.8), `parentBeaconRoot` (5.9), element 22 (5.12), `slotNumber`
(5.13), timestamp strictness (5.15), and the request rule of B8 (5.1). All are written in rc2 as values; only
5.2 is in direct contradiction with the AM24 principle as phrased; rc2 has no list of "N42 departs from
Ethereum here, and why" (VSP 8.2 recommended one).

## 6. The predecessor's findings

| VSP item | Status in rc2 | Where |
| --- | --- | --- |
| D1 (2.1) committee pool mandatory, simulated | Resolved by statement: kept, "no security meaning". | A19 rc2:135-138; AM21, AM23 |
| D2 (2.2) I2 couples leadership to mobileverify | Resolved: SHOULD; a leader without it repeats the parent's root. | I2 rc2:366-368; B11 rc2:198; AM21, AM23 |
| D3 (3.3) Round-1 on importable-only blocks, lock stall | **Partly resolved**: deferred check + includability + parent import are now the Round-1 gate; the residual hole is declared "a bug", and B8 + the 7002/7251 contracts make it reachable (3.2 here). | A13 rc2:108-113; AM19, AM23 |
| D4 (3.4) what a CommitQC certifies | Resolved. | E14 rc2:309-311; AM19 |
| D5 (4.5) no LtHash | Resolved as a non-goal. | §7 rc2:551; AM20 |
| Rec. 1 (consensus core) | Resolved except "static validity covers everything that can make import fail" (3.2). | E6, A13, E14 |
| Rec. 2 (decouple mobile) | Resolved for leadership; cohort-window timing is moot at the 8 s slot (AM17); gate-2's registry-root criterion is still a consolidation question (rc2:642-645). | I2, B11, §6 |
| Rec. 3 (A19, D6, limits) | Resolved. | A19, D6, §7 |
| VSP 3.1 "f = ⌊(n−1)/3⌋ … CONSISTENT" | **Wrong in VSP**; see 1.5. | A3 |

## 7. n42-rs spot check of the safety rules (`crates/n42/h2-consensus`, commit `f6c2fd6aa`)

| Rule | Code | Verdict |
| --- | --- | --- |
| Vote rule | `protocol/round.rs:202-204` `justify_qc.view >= self.locked_qc.view`; called after the justify QC's signature check, `protocol/proposal.rs:380-401`. Extends rule (parent = justify block) `proposal.rs:800-826`. | Matches E6 / SR1. Note: `proposal.rs:816` lets a zero parent hash pass; unreachable on profile 1 because Round 1 also needs the EL check with the parent imported. |
| Lock rule | `round.rs:194-198` monotone `update_locked_qc`; called on the proposal's justify (`proposal.rs:402`), a piggybacked PrepareQC (`:418`), a PrepareQC (`:579`), a formed QC (`voting.rs:207`), a Decide (`decision.rs:91`), a TC's high QC (`timeout.rs:509, 548, 585`); `round.rs:162-163` also locks on a CommitQC. | Matches E6 / SR2 (locking on any genuine QC only raises the lock; safe). |
| TC rule | TC builder keeps the highest high QC (`quorum.rs:491, 531`); NewView checks leader, signature, TC view, TC signatures against the exact set, the embedded QC (`timeout.rs:448-512`). | Matches E6 / SR4. The timeout signature covers the view only (`quorum.rs:99`), as E10 says (1.7). |
| Commit rule | CommitQC formation commits (`voting.rs:432`); a Decide's CommitQC is verified in the commit domain before commit (`decision.rs:57`, then `:146`). | Matches E12 / SR3. |
| Quorum | `validator/set.rs:105-114`: `n − f`. | Safe; **differs from rc2 A3's text** for n ≠ 3f+1 (1.5). |
| AM19 Round-1 gate | Under `VoteRules::PROFILE1` (`vote_rules.rs:38-48`) Round 1 is held until a `BlockChecked`/`BlockImported` event (`proposal.rs:477-494`, released at `:752-761`), never on the header alone (`try_header_vote` refuses, `:528`). What the check contains lives in the execution layer (PHD:250-262), not in this crate. | Matches A13 (content of the EL check NOT-CHECKED in code). |
| AM19 CommitVote gate | Held until `executed_blocks` holds the block (`proposal.rs:605-612`); only an `executed` import releases it (`:732-739`). | Matches A13. The leader's "build counts" path NOT-CHECKED. |

---

## Summary: DEVIATES-UNSTATED and GAP items only

| # | Finding | Severity | Smallest fix |
| --- | --- | --- | --- |
| 1.5 | A3 says quorum `2f+1` with `f = ⌊(n−1)/3⌋` for any `n ≥ 4`; that is unsafe for n ≠ 3f+1 (two quorums can intersect in ≤ f nodes). All three clients implement `n − f`. | **safety** (for any client implementing the text) and compatibility (n = 5, 6, 8, …) | A3: "quorum `q = n − f` (equal to `2f+1` when `n = 3f+1`)"; add a V6 verdict at n = 5 or 8. |
| 3.2 | A13's "a block that passes the check MUST be importable" is not achievable by a pre-execution check; a PrepareQC on an unimportable block stalls the chain for good. Concrete, user-triggerable case: a transaction to the EIP-7002/7251 contract (deployed in the profile-1 alloc, system calls run by both clients) makes the block produce a request, which B8 makes invalid. Other cases: EIP-8037 state gas, EIP-7702 delegated balance moves. | **liveness** (permanent halt) | For the request case, either drop B8's "a block that produces a request is invalid" and let requests be Ethereum's (moving `requestsHash` into the A10 deferred fields), or remove the 7002/7251 code and their system calls from profile 1, stated as a deviation; plus a V3/V4 case. For the general case: state a rule for a locked block whose import fails (e.g. its execution result is defined as "all transactions after the failing one are dropped", or Round 1 requires the block's own execution). |
| 2.4 | A leader entering a view by a TC proposes at once on the TC's highest QC. HotStuff-2's waiting leader (HS2-AUD:24, not verified in the paper text) is absent, so a hidden lock can cost views. | liveness (bounded per Byzantine leader; not safety) | E6: the post-TC leader waits until it holds timeouts from all n members or a fixed wait (a stated fraction of `baseTimeoutMs`) before proposing; or a node that refuses a proposal by the lock rule broadcasts its locked QC. Verify the paper's exact rule first. |
| 4.2 | rc2's "QMDB" uses gov5's entry (key, value), not the paper's Entry (NextKey, OldId, OldNextKeyId, Version) or its create/delete ops; rc2 does not say so. | documentation | One sentence in D6: "the twig tree of arXiv 2501.05262 without its NextKey/OldId/Version fields; no exclusion or historical proof". |

Not in the table but worth one line each in rc2 (documentation, all DEVIATES-STATED): `ommersHash` zero
contradicts AM24's own principle (5.2); `PREVRANDAO` is constant 0 (5.3); equal timestamps overwrite EIP-4788
ring slots (5.9); pacing gives up optimistic responsiveness (2.3); root-neutral compaction means twigs with one
live entry are never pruned (4.4); B4's vote bound assumes honest clocks within about 2 s (3.6).
