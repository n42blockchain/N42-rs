# gov5 vector V1 (profile 1 header profile), copied byte-exact

Source: `/data/blockchain/wr-logs/qs-scratch/profile1/vectors/V1/` (gov5
`internal/profile1_header_vectors_test.go`, TestProfile1HeaderVectorV1), copied 2026-11-24.
Do not edit; compare by SHA-256 of the raw bytes.

| File | SHA-256 |
| --- | --- |
| `README.md` | `8fe4c193b27662005484d1c5ade50df455e18b8823254afda01978b9b34081b6` |
| `genesis_8s.json` | `effc8f8abde676bda14ad8e86d6ac616ac3a653fa4db1a1b789cbe695807ca73` |
| `header_profile_v1.json` | `a4ac9cffee8675ba33375ff0e855d48e277a419fd83358538a3ffb18e29cebcf` |

Tests: `header_rules_v1_tests.rs` (h2-consensus: RLP, hash, sealHash, seal, the 25
refusals) and the genesis-hash test in `n42-qmdb-reth`.
