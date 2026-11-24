# gov5 vector V1 (profile 1 header profile), copied byte-exact

Source: `/data/blockchain/wr-logs/qs-scratch/profile1/vectors/V1/` (gov5
`internal/profile1_header_vectors_test.go`, TestProfile1HeaderVectorV1), copied 2026-11-24.
Do not edit; compare by SHA-256 of the raw bytes.

| File | SHA-256 |
| --- | --- |
| `README.md` | `c69c8fc2d38e3aaa9b5e27f9f017e98c95796b808f350da0a7fec0e134898f8d` |
| `genesis_8s.json` | `effc8f8abde676bda14ad8e86d6ac616ac3a653fa4db1a1b789cbe695807ca73` |
| `header_profile_v1.json` | `4d5d78bb56105f08f877bce742487cbee0b0407483d3ea7d06c673aeebd42d66` |

Tests: `header_rules_v1_tests.rs` (h2-consensus: RLP, hash, sealHash, seal, the 25
refusals) and the genesis-hash test in `n42-qmdb-reth`.
