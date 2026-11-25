# gov5 vector V1 (profile 1 header profile), copied byte-exact

Source: `/data/blockchain/wr-logs/qs-scratch/profile1/vectors/V1/` (gov5
`internal/profile1_header_vectors_test.go`, TestProfile1HeaderVectorV1), copied 2026-11-24.
Do not edit; compare by SHA-256 of the raw bytes.

| File | SHA-256 |
| --- | --- |
| `README.md` | `c0a2ff06aa4f038c01da51d64d8fdf1be58dc8ae059eebc47d4fb1d91b5204ca` |
| `genesis_8s.json` | `effc8f8abde676bda14ad8e86d6ac616ac3a653fa4db1a1b789cbe695807ca73` |
| `header_profile_v1.json` | `13e5389771463aa2dd988875ea52d0008b07b077d0dd28bd70598ed3a8be890c` |

Tests: `header_rules_v1_tests.rs` (h2-consensus: RLP, hash, sealHash, seal, the 25
refusals) and the genesis-hash test in `n42-qmdb-reth`.
