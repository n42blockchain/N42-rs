# gov5 profile-1 vectors (byte-exact copies)

Copied unchanged from `/data/blockchain/wr-logs/qs-scratch/profile1/vectors/` on 2026-11-24:
V8 (gov5 branch feat/profile1 at 015bd9f6: the closed key list and 14 refused geneses,
each `{"case", "expectedError", "genesis"}`) and V1's test genesis `genesis_8s.json`
(gov5 genesis hash `0x6f733745517957b421dcea37f6c879db89501aac0715f769fbc76ec54efe7e4f`).
Byte-exact contracts: compare by SHA-256 of the raw bytes, never edit. Checked by
`n42_qmdb_reth::profile1::tests` (`gov5_*`).

| SHA-256 | File |
| --- | --- |
| `effc8f8abde676bda14ad8e86d6ac616ac3a653fa4db1a1b789cbe695807ca73` | `V1/genesis_8s.json` |
| `8fe4c193b27662005484d1c5ade50df455e18b8823254afda01978b9b34081b6` | `V1/README.md` |
| `d4994e7b82b14c9824bec2473971109a6319072a9db87169ee715b921fa77e7a` | `V8/allowed-keys.json` |
| `7a0d47d25e8c76640284bca827ea3eff1649d7c81da4c2b0edcac337519040cf` | `V8/README.md` |
| `f0c5f138fab35d30d3176748f8c80d13aab673afbee53d1cc611484afc2255cd` | `V8/refused/committee_pool_enabled.json` |
| `f8ba0f7f0c3465a70a1c4f556e580a37e9e326cfbd4419b42072422bc30795cc` | `V8/refused/deferred_depth_2.json` |
| `225dc33a129ff0f651e1d43cd762b8b00c03728fa52c586b3183a9b583af5e07` | `V8/refused/gas_limit_mismatch.json` |
| `a6785d449bf90921c1e6dd21463cb9661e98d7b7a0cf49814a8bed664b6a8d42` | `V8/refused/json_number_reward.json` |
| `3107079a14d03ed37a52b66efc88043b236b2a613bf5a9948bc4b036b0dfc7c4` | `V8/refused/legacy_activation_field.json` |
| `0835b69084d20a5db02e1bcbda2bf7e498e198316fed33b800f12eb9241292c6` | `V8/refused/legacy_field_period.json` |
| `600a1931984a8c4d696b3fc6daab28a05c09ba9667a18c10d4f35e4b49863d81` | `V8/refused/missing_mandatory_field.json` |
| `00a3a94a324526955a3a5ca22d62f75838f9bcab6e19af3f8b655e3bc8f3adc4` | `V8/refused/reward_not_whole_gwei.json` |
| `ac1d74bd9d84c66b9d98c6558f58f79ed2e7b01593bbfe1b0f5915f0a7f5ca70` | `V8/refused/reward_over_u64_gwei.json` |
| `a3f9630516681bb02a04ee634f4cb28c06af559e7a379eb3f4f73848b8013cd4` | `V8/refused/storage_only_alloc_entry.json` |
| `238ef5e77053baf91a82186d8747771fbd2c0cfc8ef894056b555fd3e1d1465a` | `V8/refused/unknown_key.json` |
| `8940aa471b5c8c240c5edde7aa1afe926556ebc80c8ca94d9285c0604a035e95` | `V8/refused/zero_epoch_length.json` |
| `959a977d6d017566e312a6c87d86dfe98491bce366a9d0a6e30d33dfd16e14aa` | `V8/refused/zero_faucet.json` |
| `9aef83796d027e0a66b861c28c304f1a89acde99763c84aa139b77362462810e` | `V8/refused/zero_leader_tenure.json` |
