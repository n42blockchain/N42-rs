# gov5 vector V1 (profile 1 header profile), copied byte-exact

Source: `/data/blockchain/wr-logs/qs-scratch/profile1/vectors/V1/` (gov5
`internal/profile1_header_vectors_test.go`, TestProfile1HeaderVectorV1), copied 2026-11-24.
Do not edit; compare by SHA-256 of the raw bytes.

| File | SHA-256 |
| --- | --- |
| `README.md` | `d07ddc23bf39615c77a24b020ccb7993382150e461c12b0f0f86b90b1c01cd75` |
| `genesis_8s.json` | `effc8f8abde676bda14ad8e86d6ac616ac3a653fa4db1a1b789cbe695807ca73` |
| `header_profile_v1.json` | `e0d94b92b1e5cf4577584d2f7c429f7d23d3176dffb9af8749c3bbad57f5451e` |

Tests: `header_rules_v1_tests.rs` (h2-consensus: RLP, hash, sealHash, seal, the 25
refusals) and the genesis-hash test in `n42-qmdb-reth`.
