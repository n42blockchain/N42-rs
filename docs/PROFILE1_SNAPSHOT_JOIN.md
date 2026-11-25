# Profile 1: joining from a state snapshot (gate 4a)

Gate 4 of `docs/MIXED_PRODUCTION_STANDARD_V1_RC.md` §6 ("a member absent ≥ 1 h rejoins by state sync") is
split by agreement of both clients (2026-11-25): **4a** is the offline bundle described here; **4b** is the
p2p state sync of §3 (`qmdb_status/1`, `qmdb_manifest/1`, `qmdb_twigs/1`, `code_by_hash/1`; SYNC §5.3),
not built yet. Pass criteria are gate 3's: the member rejoins at the head with equal hashes and votes.

## What the standard fixes

- **Pivot P is a committed block** (SYNC §5.3.1). Profile 1 runs deferred execution at depth k = 1
  (§3 excludes k > 1): header N carries the execution of N-1 (`stateRoot`, `receiptsRoot`, `logsBloom`,
  `gasUsed`, and `requestsHash` per B8/AM25).
- So **the state after P is certified by header P+1**, not header P. A snapshot labelled P is checked
  against `header(P+1).stateRoot`; the pre-deferral pairing (P against header P) is refused.
- **The anchor**: header P+1 is trusted only once a CommitQC (commit domain, zero changes hash, a quorum of
  the genesis set; E2, E10, E11, E13) names P+1 or a descendant (SYNC §3.3, §5.3.1). B1: every header after
  the first commit embeds the leader's highest CommitQC, so a header a few blocks past P+1 carries one.
- **The fields the joiner needs for its first import and vote** are P's executed result, which P+1
  carries (SYNC §5.3.1 "ExecutedResult for P-k+1 … P is taken from header(P+1 … P+k)"): state root,
  receipts root, logs bloom, gas used (the block's, not the receipts' cumulative gas; cf. 07b3e7ed3),
  requests hash. Without them it cannot check P+1's carried fields or build on P.
- P5 + §3: the portable snapshot is the `0x03` tombstone layout only; `0x01` is unreachable on profile 1.
  D6: one unsharded tree.

## The bundle (gov5's layout, both directions)

| File | Content |
| --- | --- |
| `state.jsonl` | reth `init-state` JSONL: `{"root": header(P+1).stateRoot}`, then one account per line, ascending address, non-zero slots, code |
| `state.jsonl.header.rlp` | header P, raw RLP |
| `qmdb.bin` | portable QMDB `N42QMDB\x03`, labelled (chain, genesis, P, hash P), root = header(P+1).stateRoot |
| `next-header.rlp` | header P+1, raw RLP |
| `commit-qc.bin` | SYNC §5.2 `commit_qc/1` payload, LE: `qc_len u32 ‖ QC ‖ count u16 ‖ count × (u32 len ‖ header RLP)`, headers from the QC's block down to max(P-255, 1) |
| `block.rlp` | block P in gov5's `[header, txs, verifiers, rewards]` (gov5's importer stores it; ours ignores it) |
| `bundle.json` | manifest `n42-profile1-snapshot-bundle/1`: chain, genesis, pivot, post-state root, depth, anchor, sha256 of every file |

Codec and manifest: `bin/n42/src/snapshot_bundle.rs`.

## Procedure (n42-rs, `scripts/profile1-round.sh snapshot-join <i> <from>`)

1. **Export** from a stopped member: `n42-init-snapshot export --bundle <dir>`
   (`bin/n42/src/init_snapshot.rs:720`). The forest's persisted head must equal the database's (`:760`;
   a running node's forest settles ahead of MDBX), so the member is stopped for ~5 s and restarted. The
   JSONL comes from `write_state_dump` (`:894`): state is kept hashed, so address and slot preimages come
   from the genesis alloc plus every account/storage changeset 1..P, values from the state at P. The
   snapshot is `0x03` on profile 1 (`profile1_format`, `:322`).
2. **Anchor**: headers max(P-255,1)..P+4 from any running member (`debug_getRawHeader`), then
   `n42-init-snapshot anchor --bundle <dir> --headers <file>` (`:785`) finds the first header embedding a
   CommitQC on P+1 or later, verifies it, writes `next-header.rlp`, `commit-qc.bin`, `bundle.json`.
3. **Init** the joiner's empty datadir: `n42-init-snapshot init --bundle <dir>` (`:225`, `bundle_anchor`
   `:372`): manifest format/chain/genesis/depth/pivot and every sha256; the payload's headers link down
   from the QC's block (to the genesis at block 1) and hold header P and `next-header` as P+1;
   `check_anchor_chain` (`:458`): P+1 is P's child, the anchor headers link and pass the chain's header
   rules (fields, the proposer's seal, any embedded QC), and the QC verifies on one of them. Every root
   check uses P+1's root (`:248`): the dump's root line, each dump row against the portable tree (and its
   coverage), the rebuilt forest. The forest of a `0x03` snapshot is restored in QMDB file mode (`:305`),
   the only layout that holds tombstones; `QmdbNodeState::new` keeps a directory holding `forest.ckpt` in
   file mode (`crates/n42/qmdb-reth/src/node_state.rs:1285`). The anchor is kept as
   `<datadir>/qmdb/snapshot-anchor.rlp` (`bin/n42/src/snapshot_anchor.rs`).
   Without a bundle: `init --state --header --qmdb --anchor <headers P+1..> [--commit-qc <qc>]`.
4. **Start** EL and validator. The node files P's executed fields from the stored anchor
   (`bin/n42/src/main.rs:458-475`, after checking the forest's root of P equals the anchor's): it has no
   body, receipts or parent state for P. The validator pulls P+1.. by range, the EL's import of P+1
   compares its carried fields with those filed, and the member votes and leads.

## Other chains

The k = 1 anchor applies wherever deferred execution is active (a deferred chain could not be joined
before: its snapshot never matched header P's root); the `0x03`-only rule and the file-mode restore apply
to profile-1 chains only. On a native chain without deferral (`n42_devnet.json`, devnet-fleet
`LATE_SNAPSHOT`) `init`/`export` behave as before, except that `export` now writes the state JSONL itself.

## Defects found on the way (each fixed with a test)

- init compared the snapshot with header(P).stateRoot (k = 0) and checked no QC (SYNC W15).
- A snapshot head has no receipts: the start-up seeding failed with "missing receipts for deferred
  recovery head" for any P with transactions; now seeded from the anchor.
- export wrote no state JSONL (it needed gov5's dump) and defaulted to `0x01`.
- Every `0x03` restore failed in the default heap mode ("tombstoned slots … only a node with the QMDB
  entry file can hold"), gov5's bundle included.
- export dumped zero-balance genesis entries reth keeps but QMDB has no leaf for (native devnet).
- `--anchor` was parsed as a positional argument; the round script's join function had its member number
  overwritten by `cmd_stop`/`cmd_up` (bash dynamic scope) and wiped the source member's datadir.

## Known limits

- **Headers below P.** `init` stores the headers the bundle carries (`commit-qc.bin`, max(P-255,1)..P-1;
  `--ancestors` without a bundle) with their own hashes and indexes them by hash, so `BLOCKHASH` over the
  last 256 blocks reads what a full node reads (test
  `init_writes_the_real_ancestor_headers_so_blockhash_reads_them`). Below them the headers stay reth's
  zero-hash dummies.
- **No history below P** (SYNC §5.3.8): the joiner serves bodies only from P+1.
