# N42-rs 定制修改清单

## 升级任务: reth v1.4.3 → v1.9.3

### 1. N42 专有模块 (无需与 reth 合并)

这些是完全自定义的模块，升级时保持不变：

| 模块 | 路径 |
|-----|------|
| n42-primitives | crates/n42/primitives/ |
| n42-clique | crates/n42/clique/ |
| n42-engine-types | crates/n42/engine-types/ |
| n42-engine-primitives | crates/n42/engine-primitives/ |
| consensus-client | crates/n42/consensus-client/ |
| mobile-sdk | crates/n42/mobile-sdk/ |
| merkle_db_rs | crates/n42/merkle_db_rs/ |
| pubsub-mem | crates/n42/pubsub-mem/ |
| n42-testing | crates/n42/n42-testing/ |
| alloy-rpc-types-beacon | crates/n42/alloy-rpc-types-beacon/ |
| alloy-rpc-types-engine | crates/n42/alloy-rpc-types-engine/ |

### 2. Fork 修改的 reth 模块

这些模块需要与上游 reth 合并，保留定制修改：

#### 2.1 primitives-traits (定制: clique_utils)
- crates/primitives-traits/src/header/clique_utils.rs [新增]
- crates/primitives-traits/src/header/mod.rs [修改: 导出 clique_utils]

#### 2.2 chainspec (定制: N42 链规范)
- crates/chainspec/src/spec.rs [修改: N42 链规范定义]
- crates/chainspec/src/constants.rs [修改: N42 常量]
- crates/chainspec/src/api.rs [修改: N42 API]
- crates/chainspec/res/genesis/n42.json [新增]
- crates/chainspec/res/genesis/n42_devnet.json [新增]

#### 2.3 ethereum/hardforks (定制: N42 硬分叉)
- crates/ethereum/hardforks/src/hardforks/n42.rs [新增]
- crates/ethereum/hardforks/src/hardforks/mod.rs [修改]

#### 2.4 storage/db-api (定制: Beacon/Snapshot/Validator 表)
- crates/storage/db-api/src/tables/mod.rs [修改: 新增表]
- crates/storage/db-api/src/models/beacon.rs [新增]
- crates/storage/db-api/src/models/snapshot.rs [新增]
- crates/storage/db-api/src/models/validator.rs [新增]
- crates/storage/db-api/src/models/mod.rs [修改]

#### 2.5 storage/storage-api (定制: Beacon/Snapshot/Validator API)
- crates/storage/storage-api/src/beacon.rs [新增]
- crates/storage/storage-api/src/snapshot.rs [新增]
- crates/storage/storage-api/src/validator.rs [新增]
- crates/storage/storage-api/src/lib.rs [修改]

#### 2.6 storage/provider (定制: 数据提供者)
- 多处文件添加 beacon/snapshot/validator 支持

#### 2.7 consensus (定制: APoS 支持)
- crates/consensus/common/src/validation.rs [修改]
- crates/consensus/consensus/src/lib.rs [修改]

#### 2.8 net/peers (定制: N42 引导节点)
- crates/net/peers/src/bootnodes/ast.rs [新增]
- crates/net/peers/src/bootnodes/mod.rs [修改]

#### 2.9 其他修改
- crates/ethereum/evm/ [修改]
- crates/node/builder/ [修改]
- crates/node/core/ [修改]
- crates/net/network/ [修改]
- crates/rpc/rpc-types-compat/ [修改]
- crates/revm/ [修改]
- crates/storage/db/ [修改]

### 3. 升级注意事项

1. 保持所有 n42_primitives 的导入和使用
2. 保持 APoS 共识逻辑不变
3. 保持信标链、快照、验证者相关功能
4. 保持 N42 硬分叉配置
5. 保持自定义 RPC 类型

