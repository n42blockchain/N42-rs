# n42-rs: peer-to-peer state sync feasibility (2026-11-26)

Owner direction (2026-11-26): a joining node syncs every block by range and executes it; peer-to-peer state sync
(`qmdb_status/manifest/twigs/1`, `code_by_hash/1`) is deferred unless shown feasible. This records the assessment.

Work kept: branch `feat/p1-sync-v11-state` (not merged) — wire codecs and a pivot server core in
`crates/n42/h2-net/src/sync_v11/{qmdb.rs,code.rs}`, gov5's sync-v11 vectors in `crates/n42/h2-net/testdata/sync-v11/`
(SHA-256 equal to gov5's README); every vector case decodes and re-encodes byte for byte, servers over pivots rebuilt
from the vectors emit gov5's exact chunks, corrupted twigs / wrong roots / damaged proofs are refused (10/10 tests).
Not built: node-side server, libp2p handlers, client, streaming importer.

## What n42-rs's QMDB keeps for sealed twigs

1. DEAD leaf hashes: yes for every slot (`entries.log` append-only; compacted twigs keep dead slots as leaf hashes
   in `entries.relocated`; trimmed fully dead twigs keep their leaf root = HOLLOW). n42-rs and gov5 can be full twig
   servers; n42-26 cannot (it keeps sealed twigs as {leaf_root, bits}).
2. Bits at a past pivot: not stored (current bits, 16 blocks of undo, optional `QmdbHistory`). Fix: copy the bits
   when a pivot is pinned (1 bit per slot).
3. LIVE_P preimages: missing — the main gap. Keys are BLAKE3 hashes and reth storage v2 keeps keccak-hashed state
   only. Needs a persistent BLAKE3-key -> preimage table written at import (~90 B per key). Without it gov5's client
   refuses n42-rs's LIVE records.

## Design at chain-94 scale (assumed ~300M slots, ~100M live, ~150k twigs; gov5 numbers pending)

- Server: pinned pivot = next_slot + bits (~37 MB) + 96 B per twig (~14 MB) ≈ 50 MB; keep 3 pivots; twigs read on
  demand from the append-only entry files and checked against the manifest before sending; compaction floored at the
  oldest kept pivot; QMDB is in the EL while libp2p is in the validator, so serving needs an EL relay.
- Client: light libp2p host + status handshake; anchor via `commit_qc/1` and header-only ranges; parallel twig
  batches across peers; verified twigs streamed to a staging dir with a per-twig progress file (resume); on a newer
  pivot keep twigs whose manifest entry is unchanged; disk check first; one rename to promote. `init --bundle` reads
  `qmdb.bin` whole and must be rewritten to stream.
- Estimates (not measured): 15-25 GB on the wire; 4-8 min download at 50-100 MB/s; a few CPU-minutes verifying;
  30-90 min writing reth tables (dominant); < 1 GB RSS with streaming; disk ≈ 2.5x final state.
- Effort ≈ 4-5 engineer-weeks (server 1-1.5, client + importer 1.5-2, at-scale test 1).

## Risks

Preimage table changes the import path; compaction vs a pinned pivot; importer rewrite; header labelling under
deferred execution (state after N is checked against header N+1); gov5's own server/client are being reworked.

## Recommendation

Later (v1.2), not v1.1. Range sync + execution needs none of this. Revisit once full catch-up is measured on
chain-94-length history, or sooner if catch-up cannot outrun the chain under load. Start with the preimage table.
