# Proof and attestation trust inventory (phone / light client)

Status: 2026-11-18, n42-rs `main` at 2a512ef7a plus this branch (`docs/proof-budget-and-trust`).
Question it answers: *can a proof-system upgrade revoke old trust (old verification keys, cached
receipts, phone clients, historical state proofs), and is there one consistent expiry/migration
rule?* Short answer: **no**. Each format carries its own marker (a version byte, a magic, a domain
string, or nothing), each decoder refuses unknown versions of its own marker, but nothing ties the
markers to a fork time or height, and nothing retires an old version once a new one exists. The
only activation switches are genesis flags and fork timestamps on the *header* side.

**No zk proofs.** As of 2026-11-18 neither `Cargo.lock` of this repo nor gov5's `go.sum` contains
risc0, sp1, groth16 (or plonky/halo2): the node neither produces nor verifies zk receipts or
verification keys. "Old verification keys" in this inventory therefore means BLS public keys
(validator set, mobile verifier registry), not SNARK keys.

## Inventory

"Refused" = an old or unknown version marker is rejected by the decoder today; the test named is
the evidence. Tests marked **new** were added on this branch.

| # | Format | Encoded / verified (file : function) | Version marker | Root of trust | Activation / retirement | Old/unknown version refused? |
|---|---|---|---|---|---|---|
| 1 | QMDB membership proof (account / storage slot), what `n42_getProof` and `mobile_getProof` return | `crates/n42/twig-core/src/qmdb_compat.rs` : `QmdbProof::encode` / `decode` / `verify_for_key`; served by `bin/n42/src/qmdb_proof_ext.rs` : `get_proof`, `crates/n42/mobile-service/src/service.rs` : `MobileService::prove`, past heights by `crates/n42/qmdb-reth/src/history.rs` : `QmdbHistory::prove` | byte 0 = `PROOF_CODEC_VERSION` 0x02; JSON `proofFormat: "gov5-qmdb-v2"` on `n42_getProof` only (`mobile_getProof`'s `StateProofReport` has no format field) | `stateRoot` of the *anchor* header (the block's own header without deferred execution, a later one with it: `anchorNumber`) | Activation: genesis `stateScheme: qmdb`. Retirement: nothing. Past heights expire for availability only (`N42_QMDB_HISTORY` window, error 4444), not for trust: a saved proof verifies against its root forever | Yes. **new** `qmdb_compat::tests::proof_codec_refuses_every_other_version_byte` (all 255 other bytes) |
| 2 | QMDB portable snapshot v1 / v2 (init a node or light state from a head) | `twig-core/src/qmdb_compat.rs` : `verify_portable_stream`, `QmdbPortableSnapshot::decode`; `qmdb_compat/portable_v2.rs` : `QmdbPortableTree::decode`, `PortableFormat::of_magic` | 8-byte magic `N42QMDB\x01` (v1) / `N42QMDB\x03` (v2) | chain id + genesis hash + the root the operator supplies (from a header it trusts), checked before decode since 392a78c3c | Activation: none (tooling). Retirement: nothing, v1 still accepted beside v2 | Yes. v1 reader refuses v2: `portable_v2::tests` (`QmdbPortableSnapshot::decode(&v2)`); **new** `portable_v2::tests::an_unknown_magic_is_refused_by_every_reader` (stream verifier and both decoders refuse version bytes 0x00, 0x02, 0x04, 0xFF) |
| 3 | H2-v4 `Decide` (finality: commit QC over a block hash), what `mobile_finality` serves | `crates/n42/h2-wire/src/h2_v4.rs` : `encode_envelope` / `decode_envelope` / `decode_gossip`; `crates/n42/h2-consensus/src/h2_finality.rs` : `verify_h2_v4_decide` | 7-byte prefix `N42H2V4` on the envelope **and** inside the signed message (`h2-primitives/src/consensus/h2_v4.rs` : `base`, plus phase byte, chain id, genesis hash); BLS DST is the generic `..._POP_` | validator set BLS keys (genesis `hotstuff.validators`; epochs: `h2-consensus/src/validator/epoch.rs` `EpochManager`), quorum n - f | Activation: genesis `hotstuff.interopV4: true`. Retirement: nothing; a key that left the set is never expired for old views | Yes. Identity/length/snappy/canonical: `h2_v4::tests::envelope_decoding_rejects_all_five_documented_paths`; **new** `h2_v4::tests::envelope_of_another_protocol_version_is_refused` (`N42H2V3` prefix, raw and gossip) |
| 4 | gov5 header (binds decided block hash -> `stateRoot`, `receiptsRoot`, `mobileRegistryRoot`) | RLP + keccak (alloy); HotStuff extra data: `h2-consensus/src/header_profile.rs` (`GOV5_HEADER_EXTRA_MAGIC` `N42H` + view + 96-byte seal); packet form `mobileverify/src/packet/header.rs` : `marshal_header` (trailer `N42H` + flags) | no version byte; the field set is selected by fork timestamps in the chain config (`glamsterdamTime`, `mobileAnchorTime`, ...); extra-data magic `N42H` | keccak(RLP) = the hash a `Decide` signs | Activation: fork timestamps. Retirement: forks only add fields | Layout: `header_profile::tests::gov5_layouts_decode_and_others_are_refused` |
| 5 | StreamPacket V2 (block + read log + bytecodes a phone re-executes) | `crates/n42/mobileverify/src/packet/stream.rs` : `StreamPacket::encode` / `decode` | `"N2"` + wire version 0x01 (the "V2" in the name is gov5's, not the byte) | `block_hash == keccak(header)` only. The read log's values are **not authenticated** (no witness against `stateRoot`; gov5 `ExecuteAndVerifyV2` does not check the state root, `docs/MOBILEVERIFY_V3_PARITY.md` 1.4) | Activation: node flag `--mobileverify.http`. Retirement: nothing | Yes. `packet::stream::tests::rejections` (`N3` magic -> `BadMagic`; version 2 -> `BadVersion`) |
| 6 | Mobile receipt (device signs block hash, number, receipts root) | `mobileverify/src/receipt.rs` : `signing_message`, `Receipt::verify_signature` | none: 72-byte message, generic DST `BLS_SIG_..._POP_` (same DST as H2-v4 consensus; separated only by message layout); no chain id | the device key, registered with PoP (`pop.rs`, tag `n42/mobileverify/pop/v1`) and PoW (`pow.rs`, tag `.../pow/v1`) | Activation: `--mobileverify.http`. Retirement: key revocation in the registry forces rotation (`registry::tests::revoked_key_must_rotate`); receipts themselves never expire | n/a (no marker). PoP/PoW tags carry `v1` but there is no `v2` to refuse |
| 7 | Cohort certificate (aggregate of receipts over a registry mask) | `mobileverify/src/cert.rs` : `MobileAttestationCert::verify` | none (same 72-byte message and DST as 6) | the registry's keys at `reg.index_bound()`; the registry root is anchored in the header field `mobileRegistryRoot` | Activation: `mobileAnchorTime` (header carries the root). Retirement: nothing; a cert is verified against the *current* registry, not the one of its block | n/a |
| 8 | Registry root accumulator (gov5 `lib/bmt`) | `mobileverify/src/accumulator.rs` : `leaf_hash` / `node_hash` | leaf tag byte `0x4C` (structural, not a version) | header `mobileRegistryRoot` | `mobileAnchorTime` / nothing | n/a |
| 9 | Registry snapshot (a late node imports the committed registry) | `mobileverify/src/registry.rs` : `export_committed` / `import_committed` | magic `MVRS` (`0x4d565253`) + `SNAPSHOT_VERSION` 0x01 | caller checks the returned root against the anchored root | none / nothing | Yes. **new** `registry::tests::snapshot_of_another_version_is_refused` |
| 10 | Committee evidence (`parentBeaconRoot = Blake3(parent's evidence)`, 512 of 200,000 keys on fleet7) | `h2-consensus/src/committee_pool.rs` : `build_evidence`, `parent_beacon_root` | none | **none**: every pool key is `keygen(sha256(seed ‖ i))` with the seed in the genesis, so anyone can sign it. It is a header-consistency rule, not evidence a phone can trust | genesis `committeePool.enabled` / nothing | n/a |
| 11 | Old-design mobile receipt (`n42-mobile-service`, `mobile_submitReceipt`) | `crates/n42/mobile-verify/src/receipt.rs` : `encode_receipt` / `decode_receipt` / `verify_signature` | `"N2"` + version 0x01 (`wire.rs`); DST `N42_MOBILE_RECEIPT_V1_...`, PoP DST `N42_MOBILE_V1_...` | the device key in `VerifierRegistry` (node-local) | none / nothing | Yes. `wire::tests::test_unsupported_version`, `test_version_zero_rejected`; `receipt::tests::test_receipt_versioned_header_check` |
| 12 | Old-design aggregated attestation | `mobile-verify/src/attestation.rs` : `AggregatedAttestation::verify` (bincode) | none | `VerifierRegistry` (node-local, never anchored on chain) | none / nothing | n/a |
| 13 | Code-cache sync message | `mobile-verify/src/code_cache.rs` : `encode_cache_sync` / `decode_cache_sync` | `"N2"` + 0x01 | none in the message (a code entry is keyed by its hash; whether the phone rehashes is the caller's) | none / nothing | Yes. `code_cache::tests::test_cache_sync_versioned_header_check` |
| 14 | SBMT / sharded-twig proofs (`ShardedBmtProof`, `ShardedTwigProof`) | `mobile-verify/src/state_proof.rs` : `verify_account_proof`, `verify_twig_account_proof` | none (serde structs) | a "combined" SBMT/twig root that is **not** any header's `stateRoot` on a QMDB chain | none / nothing. No RPC serves them (ported from N42-26; `mobile-service` serves format 1) | n/a |

## Gaps

Formats with no version marker: 6, 7, 8, 10, 12, 14. Formats with a marker but no retirement rule:
all of them. The minimal rule for each, without changing any gov5 byte contract:

1. **No retirement anywhere (all rows).** Proposed rule: a format version is accepted only inside
   a window named in the chain config (`<format>ActiveFrom` / `<format>RetiredAt`, block
   timestamps, the way forks are), and a verifier refuses a proof whose *anchor header* is past
   the retirement time of the proof's version. Proofs anchored before the retirement stay valid
   (they are statements about old roots); only new issuance stops.
2. **QMDB proofs have no exclusion (row 1).** `found: false` from `n42_getProof` /
   `mobile_getProof` is the node's word, which the RPC docs already say. A phone must not treat it
   as proof of absence. Minimal rule: a client that needs absence asks two independent nodes or
   waits for a format that proves non-membership; nothing to change in v2.
3. **`mobile_getProof` does not name its format (row 1).** Minimal rule: add the same
   `proofFormat` string `n42_getProof` has (a JSON field, not a wire change).
4. **Validator keys never expire (row 3).** A key that left the set keeps verifying `Decide`s for
   views of its epoch indefinitely, and a phone has no served artefact that hands it from one
   validator set to the next (the node keeps at most `MAX_HISTORICAL_EPOCHS_LIMIT` = 256 past sets
   for itself). Minimal rule: a phone accepts a `Decide` only against the set of the epoch its view
   falls in, and learns each new set only from a `Decide` of the previous epoch whose
   `changes_hash` commits to it (the field already exists); a phone further behind than its weak
   subjectivity window re-bootstraps from a checkpoint.
5. **Mobile receipts and cohort certificates carry no domain or chain id (rows 6, 7).** They share
   the generic POP DST with H2-v4 consensus and are separated only by message length (72 vs 56/88/
   120 bytes). The block hash binds the chain in practice. Minimal rule: a v2 receipt prefixes the
   message with `n42/mobileverify/receipt/v2` and the chain identity; v1 is refused after a named
   timestamp. Certificates verify against the registry anchored in *their* block's header, not the
   current one.
6. **StreamPacket read log is unauthenticated (row 5).** A phone re-executing a packet trusts the
   node for every value it reads; its receipt attests "receipts root follows from these reads",
   not "from the chain's state". Minimal rule: state that in the receipt semantics today; a future
   packet version carries QMDB proofs (row 1) for the read set (see `docs/MOBILE_PROOF_BUDGET.md`
   for what that costs per read).
7. **Committee evidence is not a trust anchor (row 10).** Documented here so nobody counts it as
   one. No rule needed until real mobile validators replace pool slots.
8. **Rows 12 and 14 are unanchored legacy.** Attestations of row 12 verify against a registry no
   header commits to; row 14's roots are not this chain's roots. Minimal rule: mark both as
   not-for-phones in their crate docs, or delete them when `mobile-service` is retired.
