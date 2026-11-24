# n42-rs against the common N42 sync standard: audit

Date: 2026-11-23. Read-only audit. No source edits, builds, tests or runs.

- **Audited tree:** n42-rs `main` = `3c25a2381` in `/data/n42-build/wt-docs`. All paths below are relative to that
  tree, and all line numbers come from it.
- **Spec read:** `/data/blockchain/wr-logs/qs-scratch/sync/N42-SYNC-SPEC.md` (961 lines, owner-approved, including §10
  rotate-on-timeout), `NOTICE-to-n42-rs.md`, `sync-v2-design.md` §4-§5, and the HANDOFF posts of 2026-11-22..23
  addressed to n42-rs.
- **gov5 reference:** `origin/main` `47e219a1`. This is S1 anchored catch-up (`5eddf2da`) plus S2/S5 pipeline
  `c4014fd0..47e219a1` (`N42_SYNC_PIPELINE`, default off). Rotate-on-timeout is on `feat/hotstuff-rotate-on-timeout`.

**What changed between the spec's tree and current main.** The spec read the detached `0f3cb36e7` and cites
`b669e11f0` as main. `b669e11f0` is an ancestor of `3c25a2381`. Since then, the sync-relevant changes are:
- `h2-net`: redial only (`5b4ea41a5`, `894db9408`). A configured fleet member is dialled again, with a 10 s dial
  timeout. No protocol id, format or cap changed.
- `h2-consensus/header_profile.rs`: a payload move instead of a clone (`c34e04876`). The format is the same.
- Other recent work, not wire: `h2-node/service.rs` own-import fast path; QMDB history (`207df50b9`);
  `n42_getProof` at past blocks (`aab734ae6`); the portable `0x03` export and import.
- No unmerged branch touches the sync wire. The only catch-up-named branch, `origin/feat/research-catch-up-20261030`,
  holds PQ/mempool research scripts.

Legend: **C** = conformant, **P** = partially conformant, **N** = not conformant, **–** = not applicable or not yet
due.

---

## 1. Rule by rule

### 1.1 Wire v1, caps, access

| # | Rule (spec §) | n42-rs main (file:line) | Status | Change needed |
|---|---|---|---|---|
| 1 | Status: exactly 72 B, frozen (§1.2, §4.1) | `h2-net/src/status.rs` (spec cites 24-38, 114-135; the file is unchanged since the spec, not re-read). Chunk cap `MAX_CHUNK_SIZE` 1 MiB (`status.rs:55`) | C | none |
| 2 | Status height = committed head; receivers treat it as unauthenticated (§4.1) | Set at each commit (`h2-node/src/service.rs:3278`) **and** after every catch-up to the *pulled, unproven* height (`service.rs:4853-4856`) | P (MAY) | Advertise only the committed height (drop `:4855`). Recommended, not required. |
| 3 | block_by_hash: 64 MiB decoded; any non-zero code is a miss (§4.2, B9) | `MAX_BLOCK_CHUNK = 64 << 20` (`h2-net/src/rpc.rs:396`); frame cap 64 MiB + 1/6 + 32 (`rpc.rs:398`); a non-zero code reads the message with `unwrap_or_default`, so a bare `0x01` is a miss (`rpc.rs:443-447`). Serve budgets 16 per peer, 64 in total, 512 MiB (`service.rs:719-729`) | C | none |
| 4 | block_push: 64 MiB (§4.4) | Same `read_framed_limit(…, MAX_BLOCK_CHUNK)` (`rpc.rs:779`). Acks `0x00` before decoding (spec cites `transport.rs:1138-1150`; `transport.rs` moved by 78 lines of redial code, not re-read) | C | none |
| 5 | bodies_by_range/1 request: 52 B; client sends step = 1; server MAY ignore step (§4.3) | Strict decode (`rpc.rs:982-998`). Client uses `step: 1` (`service.rs:4527`). Server clamps count to 1024 and ignores step (`service.rs:6091`) | C | none |
| 6 | Server early stop = clean EOF, never an error chunk after a prefix (§4.3, W2) | `serve_range` stops at a missing block, an EL error, the byte cap or the shared budget, and writes the chunks then closes (`service.rs:6096-6130`, `rpc.rs:1076-1087`) | C | none |
| 7 | Server byte cap ≤ 128 MiB, SHOULD 64 (§4.3) | `MAX_RANGE_REPLY_BYTES = 128 MiB` (`rpc.rs:945,950`). The reply is fully materialised as a `Vec` (`service.rs:6092-6131`) inside a 512 MiB shared budget (`service.rs:712`) | P | Optionally lower to 64 MiB (SHOULD). Streaming arrives with v2 (W9). |
| 8 | Client accepts 128 MiB, keeps the prefix at its budget (§4.3) | Stops reading at 128 MiB and returns the prefix (`rpc.rs:1029-1031`) | C | none |
| 9 | **Client keeps the prefix on an error chunk after ≥ 1 block** (§4.3, W3) | Discards it: `return Ok(Err(…))` (`rpc.rs:1038-1041`). It also loses the prefix on any I/O error mid-stream (`?` at `rpc.rs:1043-1044`) and on a request timeout (`OutboundFailure` → `Err`, `transport.rs:1266-1280`). The catch-up then stops (`service.rs:2880-2888`, `4547-4553`) | **N** | Codec: after ≥ 1 chunk, a non-zero code or a read error returns `Ok(Ok(chunks))`. The service treats it as a short reply and asks on. gov5 did this in `c1d25e7a`. |
| 10 | Timeouts: v1 range whole request 30 s; first chunk 10 s (§6.2) | `request_response::Config::default()` (`rpc.rs:1098`): **10 s for the whole request** (libp2p-request-response 0.30 per `Cargo.lock`; the 0.29 source sets `request_timeout: 10 s`). Reading 128 MiB inside 10 s needs > 13 MB/s, otherwise the reply is lost (row 9) | **N** | `with_request_timeout(30 s)` on the ranges behaviour now; per-chunk deadlines with v2. The spec lists this as "Unverified": it is 10 s. |
| 11 | Range access: any statused peer, under quotas (§4.3, §6.3, B3) | Refuses only peers without a status (`transport.rs:1240-1246`). Serve slots 4 per peer and 32 in total, 512 MiB (`service.rs:703-712`) | P | Add a per-peer byte token bucket of 64 MiB/s, burst 256 MiB (W4, XS). |
| 12 | Do not score "ahead" requests (B8, W5) | n42-rs scores no requester. An ahead request gets an empty reply | C | none |
| 13 | **v1 serves committed blocks only** (Q-S5 yes; B4) | `serve_range` reads `el.block_by_number` = reth canonical, which includes the uncommitted head and pulled, unproven blocks (`service.rs:6097`) | **N** | Clamp `count` so that `start+count-1 ≤ committed`. Committed = `committed_height`, or, before the first live commit, the EL number of `engine.last_committed_qc().block_hash`. The service passes it to `serve_range` (W-RS2). |
| 14 | 64 MiB chain block cap; `Extra` ≤ 4096 (§3.1) | `rpc.rs:396`; `MAX_HEADER_EXTRA_LEN` 4096 (`h2-consensus/src/header_profile.rs`, spec ref). Gossip default 1 MiB, `N42_MAX_GOSSIP_MB` (`h2-net/src/config.rs:37,67`) | C | none |
| 15 | Gossip message id (§1.2) | `keccak(genesis ‖ topic ‖ data)[:20]` (`h2-net/src/message_id.rs:6`) | C | none |
| 16 | `hotstuff_direct/1` | not implemented (gossip plus `/n42/vote/1`, `rpc.rs:1182`) | – | none (not a sync protocol) |

### 1.2 Authentication, anchors, catch-up procedure

| # | Rule (spec §) | n42-rs main (file:line) | Status | Change needed |
|---|---|---|---|---|
| 17 | Producers embed the last CommitQC in `Extra` (§3.2, W6) | `refresh_header_qc` (`service.rs:1774-1811`) reads `engine.last_committed_qc()`, which is commit-domain only (doc at `:1776-1786`). View 0 embeds nothing. `HeaderQc::for_block` pins the bytes per (number, view) (`service.rs:947-965`), used at `:1749-1753` and `:3497-3505`. A committed block is always an ancestor of the block being built | C | none |
| 18 | Decoders accept the legacy `Extra` layouts; QC view ≤ header view (§3.2) | `check_header_qc` (`service.rs:4742-4776`): QC then seal, or legacy QC-alone fallback (`:4751-4757`); view check (`:4758`) | C | none |
| 19 | **Anchor = commit-domain H2-v4 QC only** (§3.3 item 3, Q-S4 yes) | `verify_header_qc` → `verify_qc_any_domain_or_known` (`h2-consensus/src/protocol/state_machine.rs:2091-2108`, `2044-2059`): prepare **or** commit domain. It also short-circuits when the QC equals the locked QC or the last committed QC | **N** | New sync-path verifier: commit message `H2V4Commit(chainId, genesis, view, hash, 0)` only. A prepare-domain or vote-domain QC is "not an anchor" (not a fault). Leave the live proposal path alone. |
| 20 | **Unknown set → fail closed, no fallback** (§3.3 item 4) | `known_validator_set_for_view` → `None` → `Ok(None)` "unchecked" (`state_machine.rs:2101-2103`; `service.rs:4765-4773`). With `epoch_length == 0` the current set always answers (`h2-consensus/src/validator/epoch.rs:302-305`), which is correct for a single epoch. History is kept for 32 epochs in memory (`epoch.rs:20`) | **N** | Return `UnknownSet`. The importer parks above the last anchor and raises an alert. |
| 21 | **Execute only blocks authenticated down from a verified anchor; do not execute the unanchored tail** (§3.4 items 4-6, W7) | `import_ranges` executes every block that is parent-linked to the previous pulled block, after an optional QC check (`service.rs:4594-4641`), and marks it unproven afterwards. Unproven execution is capped at `MAX_UNPROVEN_PAST_COMMITTED = 64` (`service.rs:1067`, `4603-4614`) **only when `committed_height` is `Some`**. `committed_height` is set only by a live commit (`service.rs:3279`), so a restarted or fresh node executes an unbounded unproven range until its first live commit. Pulled blocks become reth head via `import_pulled` (newPayload + FCU, `h2-execution/src/driver.rs:2977-3016`) and are then served onward (row 13) | **N (most severe)** | Reorder buffer, then anchor harvest from header QCs, then downward authentication by parent hash, then execute only `buffer[committed+1]` once authenticated. Tail ≤ 64 blocks and ≤ 512 MiB, not executed, evicted highest-first. The fetcher keeps going up to find the next anchor. Also seed `committed_height` at start from the persisted QC. |
| 22 | Do not penalise an unanchored tail (§3.5) | A tail > 64 past committed with no proof puts the peer in `refused_range_peers` and stops the pull (`service.rs:4603-4613`). An honest server of an n42-26-led stretch, which carries no QCs, is refused | **N** | Remove this. Under row 21 the tail is simply not executed. |
| 23 | Provable fault: a QC that decodes but fails against a known set (§3.5) | Refuses the peer for this gap (`service.rs:4594-4601`). No 3-in-10-min disconnect | P | Add the fault counter and the 1 h back-off (with the multi-peer work). |
| 24 | Gap sizing: (f+1)-th highest status height, never the single max; never gates production (§3.4.1, §6.4) | The single max of `peer_heights` (`service.rs:4447-4456`). Heights come from statuses and from every gossiped or served block number (`note_peer_height`, `service.rs:5181-5184`, `4578`). The first window is capped at `latest + 8·N42_FAR_AHEAD_BLOCKS` (`service.rs:832-842`, `4499`), then probes window by window. It does **not** gate production: no leader path reads `catch_up` | P | Target = max(highest verified anchor, (f+1)-th highest height). Keep the cap. |
| 25 | Screening before buffering: contiguity, parent link, `Extra`, tx and rewards roots (§3.4.3) | Number and parent link (`service.rs:4570-4575`, `4720-4724`), `Extra` (`:4743-4747`). Tx root and body binding are left to reth's `newPayload` validation, i.e. after the block is in the importer | P | Check the roots in the fetch stage (`decode_block_rlp_raw` plus a tx root check) before buffering. |
| 26 | Conflict or equivocation of anchors → halt and alert; never rewrite committed history (§3.3) | Not implemented for the sync path. An FCU to a sibling would be a reth reorg (refused below finalized) | **N** | Halt the importer and producer, and alert (with W7). |
| 27 | Handover: in sync mode, no other path inserts heights ≤ range end; leave sync on gap ≤ 2 for 3 commits (§3.4.7) | The live path (gossip, fetch-on-miss, held bodies) imports concurrently, and the pull skips what was already imported (`service.rs:4579-4589`) | P | Add a Live/Range mode (the S5 equivalent). Cache live bodies into the buffer while in Range mode. |
| 28 | Long gap → state sync (§3.4.8) | none | – | W13 |

### 1.3 New protocols, state sync, checkpoint, genesis

| # | Rule (spec §) | n42-rs main (file:line) | Status | Change needed |
|---|---|---|---|---|
| 29 | `bodies_by_range/2` server + client (§5.1, W9/W11) | absent | – | Needs a streamed handler. The libp2p request-response codec returns only a whole `Vec`, so use a `libp2p-stream` or custom handler. Capability comes from identify. |
| 30 | `commit_qc/1` (§5.2, W10) | absent | – | Small: persisted QC plus header `Extra` reads. n42-rs also owes the fixture `commit_qc_v1.json`. |
| 31 | `qmdb_status/1`, `qmdb_manifest/1`, `qmdb_twigs/1`, `code_by_hash/1` (§5.3, W12) | absent. **The building blocks exist:** `twig_bits_hash`, `twig_root_of`, `twig_leaf_tree` (`twig-core/src/qmdb_compat.rs:1606-1620`); `QmdbProof { twig_path, active_bits, upper_path }` (`qmdb_compat.rs:748-755`); **past-height state** via `QmdbHistory` (`qmdb-reth/src/history.rs:1256-1524`, opt-in `N42_QMDB_HISTORY` / `--qmdb.history`, `:71`), with a per-segment `ForestCheckpoint` (cursor + active bits) plus deltas and a `twigs.idx` of full-twig leaf roots; `n42_getProof` at past blocks with the deferral anchor (`bin/n42/src/qmdb_proof_ext.rs`) | – | Missing: the manifest page and range proof, twig record paging, code paging, and a keyHash → preimage source. **The spec is out of date here:** it says "no client can read twig bits at a past height through an API". n42-rs can, behind `N42_QMDB_HISTORY`. |
| 32 | Pivot window ≥ 64 (Q-S6) | `DEFAULT_RETAIN_DEPTH = 16` (`qmdb-state/src/forest.rs:44`, `1152`) without history | N (without history) | Serve pivots from `QmdbHistory` (keep ≥ 64). Alternatively, retain 64 in the forest, at a memory cost. |
| 33 | Key preimages on the wire, kind 4 (Q-S3 yes) | No keyHash → address/slot index in `twig-core`, `qmdb-state` or `qmdb-reth` (grep "preimage": no hits). Keys are BLAKE3 of the preimage | – | Server: derive from reth `PlainAccountState`/`PlainStorageState` by hashing, or record preimages in the entry store. Client: verify `BLAKE3(preimage) = keyHash`. |
| 34 | Portable `0x01`/`0x03` formats (§1.5) | Import and verify both (`twig-core/src/qmdb_compat/portable_v2.rs`; `init_snapshot` → `verify_portable_stream`, `bin/n42/src/init_snapshot.rs:262`). Fixtures `twig-core/testdata/portable_v2/SHA256SUMS` | C | n42-rs owes `qmdb_twigs_*.json` |
| 35 | Snapshot labelling under deferral; QC check (§5.3.1, W15) | `init_snapshot` compares the snapshot with `header(N).state_root` (`init_snapshot.rs:192,227,268,279`). It does not adjust for deferral and checks no QC. The header comes from a local file | **N** (as a sync source) | Label the state N-k, or check against `header(N+k)`; accept and verify a CommitQC (or `n42-sync.json`). The `n42_getProof` anchor logic already does the deferral mapping. |
| 36 | `n42-sync.json` + weak-subjectivity checkpoint; set provider order (§3.6, W8) | No loader. `EpochManager::from_schedule[_with_history]` (`h2-consensus/src/validator/epoch.rs:164`) has no caller outside that file. `consensus-checkpoint.json` (`h2-node/src/persistence.rs:62`) is the node's own consensus state, not a weak-subjectivity checkpoint | **N** | New loader with unknown fields denied, fed into `from_schedule_with_history`. Enforce the checkpoint in the importer. Hash-only checkpoints need an operator flag (Q-S9). |
| 37 | Genesis: reject an alloc entry with nonce 0, balance 0, no code and storage (Q-S1) | Not checked. `changes_from_alloc` writes the storage, and `ops()` deletes the account (`qmdb-state/src/alloc.rs:22-45`; `lib.rs:83-87`, `176-178`). Callers: `crates/chainspec/src/qmdb.rs:296`, `qmdb-reth/src/node_state.rs:2881,3001`, `changes.rs:461,538`; gov5 genesis folding at `bin/n42/src/gov5_genesis.rs:112` | **N** | One `validate_alloc()` in `qmdb-state`, called at every genesis entry point; error = config error. |
| 38 | B10 deletion predicate | `is_empty` = nonce 0 ∧ balance 0 ∧ empty code (`qmdb-state/src/lib.rs:83-87`). Touched accounts stay live through `initialised` (`lib.rs:176-178`). gov5 verified that there is no live divergence (HANDOFF 11-22) | C | Add the `account_value_rule.json` vector when gov5 publishes it. |
| 39 | Signing domain H2-v4, POP DST (§1.2, §3.1) | `H2_V4_DST` POP (`h2-primitives/src/bls/mod.rs:12`). The legacy `_NUL_` DST is at `:8`, for the non-v4 profile only | C | Mixed chains must run the H2-v4 profile (they already do). |

### 1.4 Leader tenure and rotate-on-timeout (§10)

| # | Rule | n42-rs main | Status | Change needed |
|---|---|---|---|---|
| 40 | Tenure comes from genesis `hotstuff.leaderTenure` | `HotStuffGenesisConfig.leader_tenure` (`qmdb-reth/src/hotstuff.rs:47-57`, default 1 at `:165`) → `h2_validator.rs:281-283` → `engine.set_leader_tenure` (`h2_validator.rs:496`; `state_machine.rs:1144`). No environment override | C | Optionally add the bench override with gov5's variable name. |
| 41 | `view_after_tc` and `rotateOnTimeoutView` | Not implemented. `next_view = view + 1` at `h2-consensus/src/protocol/timeout.rs:56` (future-timeout TC; `next_leader` follows), `:272`, `:381-382`. NewView check `nv.view - 1` at `:474-485`. Embedded/piggybacked TC target `tc.view + 1` at `:524`. Shadow verifier `checked_add(1)` at `h2_finality.rs:268-275`. **The spec's §10.5 line references are all still valid on main.** | **N** (dormant) | Implement per §10.2 behind the genesis field, with the §10.4 vectors and sequences S1-S11. |
| 42 | All members flip at the same view | `HotStuffGenesisConfig` silently ignores unknown fields (doc at `hotstuff.rs:33-38`), so a genesis carrying `rotateOnTimeoutView` today starts an n42-rs node that does **not** rotate. That is a liveness split from gov5 | **N** | Immediate guard: refuse to start when `rotateOnTimeoutView` is present until the rule is implemented. |

### 1.5 Where the spec is out of date or understated (for gov5)

1. **Tree.** The spec says main is `b669e11f0`; main is now `3c25a2381`. The sync wire is unchanged: `h2-net` gained only redial.
2. **"No client exposes twig bits at a past height" (§1.5, §5.3.4):** wrong for n42-rs. `N42_QMDB_HISTORY` reconstructs cursor and bits at any retained block, and `n42_getProof` serves proofs at past blocks against the deferral anchor header.
3. **§1.3 timeouts "Unverified":** they are 10 s for the whole request (default request-response config, `rpc.rs:1098`).
4. **§1.3 client:** n42-rs also loses the prefix on an I/O error or a timeout, not only on an error chunk.
5. **§1.4 "executes up to 64 unproven blocks past committed":** there is no cap at all until the node's first live commit after a (re)start (`committed_height` is `None`). This understates the risk.
6. **§1.4 behind detection:** peer heights also come from gossiped and served block numbers, not only from Status.
7. **§4.1:** n42-rs advertises its pulled (unproven) height after a catch-up, not only its committed height.
8. **§3.5:** n42-rs penalises an unanchored tail longer than 64 (`refused_range_peers`).
9. **Line drift:** the spec's `service.rs:4590-4602` is now `4594-4614`. `serve_range:6086/6097`, `state_machine.rs:2044-2108`, `forest.rs:44`, `qmdb-state/lib.rs:83-87` and all of the §10.5 references still match.

---

## 2. Draft answers to the five questions of the notice

**Q1. Do you depend on gov5's "highest advertised height" or future-queue branch switching?**
No, on both counts.
- n42-rs uses peer heights only to choose whom to pull from and how far. It takes the single highest of Status and
  gossiped or served block numbers (`service.rs:4447-4456`, `5181`), caps the first window at the tip + 8
  (`service.rs:832-842`, `4499`), and then probes window by window until a peer serves short or refuses.
- It never gates production on a peer height. It does not rely on gov5's future queue: pulled blocks go to its own
  execution layer as head-only (`driver.rs:2977-3016`), and safe/finalized move only on its own commits.
- gov5 stage A changes are all harmless to us:
  - a prefix instead of an error past the stored chain;
  - no scoring of refusals;
  - ahead-of-head answered with code 1.
  n42-rs reads both an empty or short reply and a refusal of a probe as the end of the peer's chain
  (`service.rs:2880-2888`, `4547-4553`).
- One dependency the other way: until n42-rs keeps the prefix (W3), a gov5 main server older than `8eaae4f9` that
  writes an error chunk after a prefix stops our catch-up (`rpc.rs:1038-1041`).
- We will move to the (f+1)-th height or anchor target of §3.4.1.

**Q2. Caps for block_by_hash and push?**
- 64 MiB decoded on block_by_hash, push and every range chunk (`MAX_BLOCK_CHUNK = 64 << 20`, `rpc.rs:396`).
- Encoded frame cap 64 MiB + 64/6 MiB + 32 B (`rpc.rs:398`).
- A whole range reply is read up to 128 MiB (`rpc.rs:945`); `block_txns` is 32 MiB (`rpc.rs:542`); gossip defaults
  to 1 MiB, settable with `N42_MAX_GOSSIP_MB` (`config.rs:37,67`).
- Serve budgets:
  - by-hash/fill: 16 per peer, 64 in total, 512 MiB (`service.rs:719-729`);
  - ranges: 4 per peer, 32 in total, 512 MiB (`service.rs:703-712`).
- A ~33 MB block therefore passes on every n42-rs path.
- Caveat: a range request times out after 10 s in total (`rpc.rs:1098`). We will raise it to 30 s.

**Q3. Can qmdb-state / twig-core produce twig leaves, active bits and upper-tree proofs at a pivot height with gov5's hashing?**
- **Hashing: yes, byte-identical.** The relevant functions are:
  - leaf, bits and twig root: `twig_leaf_tree`, `twig_bits_hash`, `twig_root_of` (`qmdb_compat.rs:1606-1620`);
  - upper path with zero padding: `QmdbProof`, gov5's v2 proof codec (`qmdb_compat.rs:748`).
  The portable `v1.bin` / `v2.bin` / `v2-tombstones.bin` / `root.hex` files are sha256-identical in both repos
  (`twig-core/testdata/portable_v2/SHA256SUMS`).
- **At a past pivot: yes, but only with history on.** `N42_QMDB_HISTORY` / `--qmdb.history` keeps a segmented
  `ForestCheckpoint` (append cursor + every active bit) plus per-block deltas and a `twigs.idx` of full-twig leaf
  roots (`qmdb-reth/src/history.rs:1-30,71,1256-1524`). `n42_getProof` already rebuilds a past block's root,
  checks it against the anchoring header (deferral-aware) and serves twig + upper proofs (`bin/n42/src/qmdb_proof_ext.rs`).
- Without history, the forest keeps 16 blocks (`forest.rs:44`).
- **Not built yet:**
  - the manifest page (leaf_root, bits_root per twig) with a multi-twig range proof;
  - paged twig records (LIVE / DEAD leafHash / HOLLOW);
  - a keyHash → preimage source for kind-4 records.
  These are W12.

**Q4. Does init_snapshot verify a snapshot against anything?**
- **What it checks against the local header file:**
  - the portable stream's trailer, chain id and genesis (`verify_portable_stream`, `init_snapshot.rs:262`);
  - the snapshot's (number, hash) equals the header's (`:266`, `:274`);
  - the rebuilt QMDB root equals `header.state_root` (`:268`, `:279`);
  - the JSONL root line equals the header root (`:227`);
  - every JSONL account and storage row is proven against the QMDB tree, and the dump covers the tree fully
    (`:307-345`);
  - the target datadir is empty (`:208`).
- **What it does not do:**
  - It checks no QC. The header itself comes unauthenticated from a file.
  - It applies no deferred-depth correction: it compares state "at N" with `header(N).state_root`, which is wrong
    when k ≥ 1.
- So it is a consistency check, not a sync source. W15 fixes this.

**Q5. Is a newer n42-rs branch than `0f3cb36e7` changing the gov5-facing wire?**
- No. Main is now `3c25a2381`. Since `0f3cb36e7`, `h2-net` changed only by fleet redial (`5b4ea41a5`, `894db9408`:
  dial a configured member again, with a 10 s dial timeout).
- `h2-wire` gained a test only. `header_profile.rs` moves the payload instead of cloning it, with the same bytes.
- Header QC embedding (`design/qc-embed`) was already in `0f3cb36e7`.
- No unmerged branch touches the sync wire.
- Wire changes will come only as the agreed `/2`, `commit_qc/1` and state protocols, versioned with v1 fallback.

---

## 3. How n42-rs catches up today

### 3.1 Path, end to end

1. **Trigger** (`consider_catch_up`, `service.rs:4424-4515`):
   - The trigger is a peer height above the execution layer's latest block, after removing pulled blocks that are
     still unproven (`:4483-4491`). Peer heights come from Status at connect and from block numbers seen since.
   - It picks the single highest peer, skipping the one that failed last.
   - A finished pull may restart after `CATCH_UP_RETRY = 3 s` (`service.rs:927`).
   - On restart, `unproven_after_restart` starts the pull above the persisted commit (`:4807-4816`).
2. **Fetch**:
   - one peer, one `bodies_by_range/1` request at a time;
   - `count = min(target-next+1, 1024)` (`request_next_range`, `:4517-4530`);
   - the first target is capped at the tip + 8, after which it probes in 1024-block windows (`:4661-4684`).
   - The codec buffers the whole reply, up to 128 MiB, before the service sees any of it (`rpc.rs:1022-1051`).
   - The request timeout is 10 s.
3. **Import** (`import_ranges`, `:4536-4686`):
   - It runs **on the service loop**, 32 blocks per step (`PULLED_BLOCKS_PER_STEP`, `:1060`), with the transport
     polled between steps. That limit came from a fix after gov5 dropped the peer during 50 s unpolled imports
     (`docs/N42_26_PORT.md:760-768`).
   - Per block: decode, then the number and parent-link check, then the header QC check (any domain; unknown set =
     unchecked), then the unproven cap.
   - Then `driver.import_pulled`: one `newPayload` (`ExecutionPath::HISTORICAL_SEQUENTIAL`), then one FCU to that
     block as head (`driver.rs:2977-3016`).
   - Execution and the QMDB root happen in reth (`bin/n42`), synchronously, one block at a time.
   - The next range is requested only after the whole reply has been imported. **Fetch and import never overlap.**
4. **Finish**: Status is set to the pulled height, then a 3 s back-off, then the next probe (`:4848-4867`). The pulled
   blocks become safe/finalized when live consensus commits a descendant.
5. **Live interplay**:
   - Gossiped and fetched bodies are held when more than 32 past the tip, to avoid reth's peerless backfill
     (`N42_26_PORT.md:735-745`), and imported as the pull closes in.
   - The pull skips blocks that are already imported (`service.rs:4579-4589`).
6. **Devnet shapes** (`scripts/devnet-fleet.sh:6-7,71-111,161-166`):
   - `LATE_VALIDATOR`: a fresh EL pulls from 0.
   - `ABSENT_VALIDATOR` / `ABSENT_AT` / `ABSENT_FOR`: the same datadirs come back and pull the gap.
   - `LATE_SNAPSHOT`: `n42-init-snapshot init` from a gov5 JSONL dump + header + portable QMDB, then a pull of only
     the remainder.

### 3.2 Measured (all on a near-empty devnet; none at bench block size)

- **One hour away:** 883 blocks imported in 44.9 s = **19.7 blocks/s** (debug build).
- **Three hours away:** 1143 → 2800 in 65.4 s = **25 blocks/s**, against a Rust server.
- **gov5 as the server:** 1024 blocks took ~50 s, because the import loop was unpolled. 370 blocks were served in
  3.5 s after the 32-per-step fix.
- **Rejoin cost:** first commit 15-126 s after return (`docs/N42_26_PORT.md:705-768`).
- **Short absences:** absent 52 → 82, range pull 52 → 60 then catch-up in 74 ms (`docs/MATURITY_HARDENING_2026_10.md:385-386`).
- **Fleet7 crash test:** a 44-block pull after a crash (`docs/NATIVE_FLEET7.md:2864`).
- **Not measured:** catch-up rate at bench size. For comparison, gov5 measured 3.2 blocks/s at 163k-tx blocks with a
  152 ms import, and S2/S5 is designed for 5.5-6.5 (`sync-v2-design.md` §1.6, §4.3). gov5 runs 97 and 98 did not yet
  yield a pipeline number.

### 3.3 Bottlenecks (biggest first) against gov5 S2/S5 and geth/reth

1. **Serial fetch then import, one peer.**
   - n42-rs: the next request goes out only after the previous reply is fully imported (`service.rs:4661-4684`).
     Download time therefore adds to import time. gov5 measured 36% of wall time outside import.
   - gov5 S2: N slots in flight, 2 per peer, EWMA sizing, plus a reorder buffer of 1 GiB.
   - reth: pipelined headers, then concurrent bodies, then execution. geth: skeleton plus concurrent bodies and
     receipts.
2. **Import runs on the consensus loop, and 32 blocks per step is a count, not a time budget.**
   - At bench size (~0.3-0.6 s per block import, `CLAUDE.md` follower import numbers), one step holds the loop for
     10-20 s. Consensus messages, Decides (anchors) and transport events wait behind it.
   - gov5 S5 runs one importer goroutine with Live/Range modes.
3. **Per-block Engine API cost.**
   - Every pulled block costs a full `newPayload`, i.e. the whole body over the Engine API, plus its own FCU.
   - The live follower's cheaper roads are not used: compact or by-header bodies, the parallel follower, graft, the
     sender cache (`driver.rs:914-956`).
   - reth runs the execution stage over large batches with one commit, and computes one state root per batch.
4. **Whole-reply buffering and a 10 s timeout.**
   - Nothing imports until 128 MiB has arrived.
   - A slow link loses the whole reply, because the prefix is dropped.
5. **No authentication pipeline.**
   - QCs are checked inline per block. There is no anchor harvest or cache beyond `VerifiedHeaderQcs`.
   - This is correctness work (row 21), but it also defines the buffer that speed work needs.
6. **Ceiling.**
   - A sequential replayer at follower speed is at best as fast as production under load: the fleet produces at
     about the follower's import cycle. So a gap under sustained load never closes.
   - gov5 reached the same conclusion (S6 is required). Only state sync, or replay faster than live, closes it.

### 3.4 Speed-ups that keep the standard, ranked by expected gain per effort

1. **Prefetch ahead of the importer.** Keep 2-4 range requests in flight into a byte-bounded reorder buffer.
   - This hides fetch time completely: on a fast link, up to ~1.5× on devnet-size blocks and the gov5-like 36% at
     bench size.
   - v1-compatible. It shares the buffer with W7.
2. **Take import off the service loop.** Use a time-sliced importer (for example 100-200 ms per step, or a dedicated
   task owning the pulled path) together with Live/Range modes.
   - Speed gain is small, but consensus keeps up and the node can vote the moment it reaches the tip.
3. **One FCU per reply or batch** instead of one per block, plus newPayload only. Measure first.
4. **The live follower's execution roads for authenticated pulled blocks.** These are parallel follower execution,
   graft, and sender recovery and batch Ed25519 verification moved into the fetch stage (gov5 S3).
5. **Multi-peer slots** with EWMA, ≤ 2 per peer and reassignment on timeout. This matters on WAN and when one server
   is slow; little on localhost.
6. **Batched replay with root checks only at anchors** (reth-style).
   - An authenticated chain has its header roots bound by the QC hash chain.
   - The QMDB entry log is append-only, so a matching root at the batch end implies matching intermediate state.
   - Needs a design review: deferred depth k, and per-block roots for `n42_getProof` history.
   - Largest potential gain at bench size.
7. **State sync** (W12/W13) for gaps longer than `G_state`. This is the only fix for "the gap never closes under load".

---

## 4. Work plan (one coding agent and one worktree per package)

The order follows spec §7.2: safety, then tolerance, then the anchor rule (observe, then enforce), then speed, then
new protocols. "Wire" or "consensus" marks packages that need the owner and the other clients first.

| WP | Scope | Files | Tests | Devnet shape that proves it | Wire / consensus | Depends on |
|---|---|---|---|---|---|---|
| **RS0** (XS) | Q-S1 genesis check: reject {nonce 0, balance 0, no code, storage}. Refuse to start on `hotstuff.rotateOnTimeoutView` until RS7 lands | `qmdb-state/src/alloc.rs` (`validate_alloc`); call sites `crates/chainspec/src/qmdb.rs:296`, `qmdb-reth/src/node_state.rs:2881,3001`, `bin/n42/src/gov5_genesis.rs`; `qmdb-reth/src/hotstuff.rs` | unit: rejected / accepted neighbours, as gov5 `8eaae4f9` | default `devnet-fleet.sh` round: genesis hash unchanged | config only (owner decided) | none |
| **RS1** (XS-S) | W3 plus timeouts. The codec keeps the prefix after an error chunk, a cut stream or a timeout; the ranges behaviour gets `with_request_timeout(30 s)`; the service treats these as short replies | `h2-net/src/rpc.rs:1022-1051,1094-1099`, `transport.rs:1266-1280`, `h2-node/src/service.rs:2880-2888,4547-4553` | codec tests: error-after-prefix, mid-chunk EOF, oversize; later gov5 `range_v1_*.json` | M2: `GOV5_DELAY` mixed devnet with a gov5 `bb4be621` member as server, plus `ABSENT_VALIDATOR` pulling past gov5's head | no | none |
| **RS2** (S) | W4 plus Q-S5: serve committed only (clamp to the committed height, seeded from the persisted QC at start); a per-peer byte token bucket; optionally a 64 MiB server cap. Also advertise committed height only (row 2) | `h2-node/src/service.rs` (serve call site near the `RangeRequest` handler, `serve_range:6086`, `:4855`) | serve above committed → short; restart before the first commit; bucket | `ABSENT_VALIDATOR` all-Rust: the pull still completes and the tail arrives by gossip | semantics only (owner approved) | none |
| **RS3** (S) | W15: `init_snapshot` deferral labelling (check against `header(N+k)`) plus an optional CommitQC or `n42-sync.json` anchor | `bin/n42/src/init_snapshot.rs`; reuse the anchor mapping in `qmdb_proof_ext.rs` | unit with k = 1 | `LATE_SNAPSHOT` on a deferred genesis | no | RS6 for the QC input (optional) |
| **RS4** (M) | **W7 anchored import.** Sync verifier: commit domain only, `UnknownSet` fails closed. Reorder buffer, anchor harvest, downward authentication, execute only authenticated `head+1`; tail ≤ 64 / 512 MiB unexecuted with no penalty; keep fetching for the next anchor; conflict → halt and alert; seed `committed_height`. Switch `N42_SYNC_ANCHOR=off\|observe\|enforce` (gov5's name), observe first | `h2-consensus/src/protocol/state_machine.rs:2091-2108` (new fn); `h2-node/src/service.rs:4424-4846` (catch-up split into a `sync/` module) | gov5 `qc_commit_v4.json`, `anchor_chain.json`; forged chain with a copied QC → 0 executions; prepare QC not an anchor; unknown set parks; restart before the first commit | `ABSENT_VALIDATOR`, `LATE_VALIDATOR`, and mixed with gov5 (anchors from gov5-led headers); one observe-only leg, then enforce | sync-path rule (owner approved Q-S4). Not wire | gov5 fixtures; n42-26 W6 for anchors in n42-26-led stretches |
| **RS5** (M) | Pipeline (S2/S5 on v1): 2-4 ranges in flight, multi-peer slots, EWMA, reassignment; a time-sliced or dedicated importer; Live/Range modes with hysteresis; the live path caches bodies ≤ rangeEnd instead of importing them; (f+1)-th height target | `h2-node/src/sync/*` (new), `service.rs` | scheduler and buffer unit tests as in gov5 `2a0288ef`, `5cce2e46`; a speed harness like `b1d5bfcc` | `ABSENT_VALIDATOR ABSENT_FOR=3600`: compare blocks/s with today's 20-25; one fleet7 `roll` under load (the coordinator runs it) | no | RS1, RS4 |
| **RS6** (S) | W8: `n42-sync.json` loader (unknown fields denied) → `from_schedule_with_history`; checkpoint enforcement; hash-only checkpoints need an operator flag | new `h2-node/src/sync_config.rs`; `h2_validator.rs`; `epoch.rs:164` | gov5 `n42-sync.json` fixtures (valid and invalid) | M7: devnet (`epochLength` 20) across a boundary, with and without the file | config format shared (Q-S8) | gov5 field names |
| **RS7** (S-M) | §10 rotate-on-timeout: `view_after_tc`; the five substitution sites; genesis `rotateOnTimeoutView` plus `N42_HOTSTUFF_ROTATE_ON_TIMEOUT` | `validator/selection.rs`, `protocol/timeout.rs:56,272,381,474-485,524`, `h2_finality.rs:268-275`, `state_machine.rs:1144`, `qmdb-reth/src/hotstuff.rs`, `h2_validator.rs:281-496` | §10.4 table, S1-S11 sequences | devnet with tenure 8, activation 0, one validator absent (`ABSENT_VALIDATOR`): stall ≈ one base timeout; then mixed with gov5's branch | **consensus**: the activation view is set by the owner on every client | gov5 branch merged; n42-26 genesis tenure |
| **RS8** (M) | W9/W10: `bodies_by_range/2` (streamed handler, END reasons, HEADERS_ONLY, committed only) and `commit_qc/1` server + client; identify-based fallback to v1 | `h2-net` (a new stream-based handler; `request_response` cannot stream), `h2-node` | `range_v2_*.json`, our own `commit_qc_v1.json`, `extra_qc.json` | M4 / M6 mixed v1↔v2 | **wire** (spec approved; wait for byte fixtures) | spec freeze; gov5 vectors |
| **RS9** (S) | Fixtures n42-rs owes: `extra_qc.json`, `commit_qc_v1.json`, `qmdb_twigs_*.json` | `h2-net/testdata`, `twig-core/testdata` | generate plus self-check | – | no | none (can start at once) |
| **RS10** (L) | W12 state-sync server: `qmdb_status`, `qmdb_manifest` (range proof), `qmdb_twigs` (records, kind 4 preimages), `code_by_hash`; pivots from `QmdbHistory` (keep ≥ 64) | `qmdb-reth/src/history.rs`, `twig-core/src/qmdb_compat.rs`, a new preimage source (reth plain tables), `h2-net` | manifest vectors (gov5), twig vectors (ours), bad proof / tag faults | M8 with a gov5 client | **wire** | RS8 framing; Q-S6 storage choice |
| **RS11** (L-XL) | W13 state-sync client, promotion into reth tables plus the QMDB forest, delta rounds, `--sync.state=force` | `bin/n42` (`init_snapshot` promotion code), `qmdb-reth`, `h2-node` | promotion crash tests; byte-identical tables | `LATE_VALIDATOR` with state sync; `ABSENT_VALIDATOR` long absence under load | **wire** | RS10 (or gov5 servers) |
| **RS12** (M, measure first) | Import speed: FCU per batch; follower roads for authenticated pulled blocks; sender pre-recovery in fetch workers; then a batched-root replay design note | `h2-execution/src/driver.rs:2977-3016`, `bin/n42/src/follower_import.rs` | A/B import ms per block | fleet7 `roll <i>` under load (coordinator) | no (batched-root replay: owner review) | RS5 |

**Order:**
1. RS0 and RS9 (immediately).
2. RS1, RS2, RS3.
3. RS4 in observe mode for one leg, then enforce.
4. RS5, then RS12.
5. RS6.
6. RS7, when the owner schedules activation.
7. RS8, then RS10, then RS11.

---

## 5. Open questions

**For the owner**
1. **Q-S6 storage.** Should n42-rs serve pivots from opt-in `N42_QMDB_HISTORY` (disk, already built), or raise the
   forest retain depth from 16 to 64 (memory)? Should state-serving nodes be required to run with history?
2. **Speculative execution.** May the sync importer execute an unanchored block *speculatively* (no FCU, discarded
   unless anchored)? Or does "MUST NOT execute above the highest anchor" (§3.4.6) forbid that too? Overlapping
   execution with the anchor's arrival is worth about one range of latency.
3. **Batched replay.** Is replay with QMDB roots checked only at anchors acceptable (reth-style), given an authenticated
   hash chain? Or must every header root be recomputed during catch-up?
4. **Server byte cap.** Is a 128 MiB server cap acceptable (conformant MUST), or should all servers use the SHOULD of
   64 MiB?
5. **rotate-on-timeout.** Should every client hard-fail at startup on a genesis field it does not implement (RS0)?
   That is safer than ignoring it.

**For gov5**
1. When will `qc_commit_v4.json`, `anchor_chain.json`, `range_v1_*.json` and `n42-sync.json` (with their field names)
   be published? RS1, RS4 and RS6 test against them.
2. What blocks/s does the S2/S5 pipeline reach, from the `b1d5bfcc` harness and run 98? That number is the target for
   RS5.
3. Is `changesHash` always 0 in every gov5 QC on the native chain, including epoch boundaries? Our sync verifier will
   fail closed otherwise.
4. Does any gov5 server delay the first chunk by more than 10 s (whole sub-batch read)? Until RS1, n42-rs times out
   at 10 s in total.

**For n42-26**
1. When does W6 (QC embedding) land? Until then, RS4 in enforce mode stalls across n42-26-led stretches unless
   `commit_qc/1` exists.
2. W2: when will the error chunk after a prefix stop? And will B3 (serving untrusted statused peers) open ranges to
   n42-rs?
3. Will the leader tenure become a genesis field (`hotstuff.leaderTenure`), as §10.3 requires? Today n42-26 reads
   env only, which forks leader schedules on any shared chain with tenure > 1.
4. Does `/n42/sync/2` stay native-only, or is it retired in favour of `qmdb_*`?
