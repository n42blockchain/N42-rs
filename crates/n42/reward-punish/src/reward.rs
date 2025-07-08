// // use serde::{Deserialize,Serialize};
//
// use std::{cmp::min, f64::MIN};
//
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct Validator {
//     // 身份标识
//     pub address: String,              // 验证者以太坊地址
//
//     // 质押相关
//     pub stake_amount: BigInt,         // 总质押金额（单位：wei）
//     pub effective_balance: BigInt,    // 有效质押余额（计算奖励用，上限32 ETH）
//
//     // 生命周期状态
//     pub activation_epoch: u64,        // 激活周期（开始参与共识）
//     pub exit_epoch: Option<u64>,      // 退出周期（None表示未退出）
//
//     // 经济状态
//     pub balance: BigInt,              // 当前总余额（质押本金+奖励-惩罚）
//     pub slashed: bool,                // 是否被罚没标记
//
//     // 参与记录
//     pub attestations: HashMap<u64, AttestationStatus>, // 各周期投票记录
//     pub inactivity_score: u64,        // 不活跃评分（惩罚计算依据）
// }
//
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct AttestationStatus {
//     pub source_voted: bool,   // 是否正确投票来源检查点（Source）
//     pub target_voted: bool,   // 是否正确投票目标检查点（Target）
//     pub head_voted: bool,     // 是否正确投票头部区块（Head）
//     pub included: bool,       // 该投票是否被主链收录
// }
//
// #[derive(Debug, Clone)]
// pub struct BeaconState {
//     pub validators: Vec<Validator>,   // 所有验证者列表
//     pub total_stake: BigInt,          // 全网有效质押总量（用于奖励计算）
//
//     // 时间状态
//     pub current_epoch: u64,           // 当前周期编号
//     pub tatal_tast: u64,
//     pub actual_tast: u64,
//     pub finalized_checkpoint: Checkpoint, // 最终确认的检查点
//
//     // 惩罚记录
//     pub slashings: Vec<SlashingEvent>, // 历史罚没事件
//
//     // 协议配置
//     pub config: ChainConfig,          // 动态参数集合
// }
//
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct Checkpoint {
//     pub epoch: u64,       // 检查点对应的周期号
//     pub root: String,     // 状态根哈希（Merkle根）
// }
//
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct SlashingEvent {
//     pub validator_index: usize,   // 被罚没验证者索引
//     pub epoch: u64,               // 罚没发生周期
//     pub slashed_amount: BigInt,   // 罚没总金额（基础+关联惩罚）
// }
//
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct ChainConfig {
//     // 奖励参数
//     pub base_reward_factor: BigInt,   // 基础奖励乘数
//     pub proposer_weight: u64,         // 提议者权重（分子）
//     pub attestation_weights: [u64; 3],// 见证权重[Source,Target,Head]
//
//     // 惩罚参数
//     pub min_slashing_penalty: BigInt, // 最低罚没金额
//     pub inactivity_penalty_quotient: BigInt, // 不活跃惩罚分母
//     pub slashing_penalty_quotient: BigInt,   // 关联惩罚分母
//
//     // 时间参数
//     pub slots_per_epoch: slots_per_epoch,         // 每周期Slot数
//     pub seconds_per_slot: u64,        // 每个Slot秒数
// }
//
//
// impl BeaconState {
//     /// 计算单个验证者的基础奖励
//
//     pub fn calculate_base_reward(&self, validator: &Validator) -> BigInt {
//         // 计算总质押量的平方根（使用大整数运算避免溢出）
//         let total_stake_sqrt = self.total_stake.sqrt();
//         if total_stake_sqrt == BigInt::from(0) {
//             return BigInt::from(0);
//         }
//         // 基础奖励公式
//         (&validator.effective_balance * &self.config.base_reward_factor) / total_stake_sqrt
//     }
//
//
//     /// 在每个周期结束时调用，更新所有活跃验证者的余额
//     pub fn process_epoch_rewards(&mut self) {
//         let current_epoch = self.current_epoch;
//
//         // 遍历所有验证者
//         for validator in &mut self.validators {
//             // 跳过非活跃验证者
//             if !self.is_active(validator, current_epoch) {
//                 continue;
//             }
//
//             let vaild_tast = min(self.total_stake,self.actual_tast);
//
//             // 计算基础奖励
//             let base_reward = self.calculate_base_reward(validator);
//             let attest_reward = (vaild_tast/self.total_stake)*base_reward;
//             validator.balance = &validator.balance + &attest_reward;
//
//
//         }
//     }
//
//
//     /// 当网络处于不活跃泄露状态时触发
//     pub fn apply_inactivity_penalties(&mut self) {
//         // 检查是否进入不活跃泄露期
//         if self.finalized_checkpoint.epoch + self.config.inactivity_leak_epochs < self.current_epoch{
//             for validator in &mut self.validators {
//
//                 if !validator.attestations.contains_key(&self.current_epoch) && !validator.slashed {
//                     // 惩罚公式：effective_balance * inactivity_score / quotient
//                     let penalty = &validator.effective_balance
//                         * BigInt::from(validator.inactivity_score)
//                         / &self.config.inactivity_penalty_quotient;
//
//                     // 扣除惩罚金额
//                     validator.balance -= penalty;
//                 }
//             }
//         }
//     }
//
//
//
//     /// 当检测到双重签名等恶意行为时调用
//     pub fn process_slashing(&mut self, validator_index: usize) {
//         let validator = &mut self.validators[validator_index];
//
//         // 基础罚没
//         let base_penalty = &validator.effective_balance / 32;
//         let slashed_amount = std::cmp::max(
//             base_penalty,
//             self.config.min_slashing_penalty.clone()
//         );
//         validator.balance -= &slashed_amount;
//         validator.slashed = true;
//
//
//     }
//
//     /// 检查验证者是否在指定周期处于活跃状态
//     fn is_active(&self, validator: &Validator, epoch: u64) -> bool {
//         // 激活周期 <= 当前周期 < 退出周期
//         validator.activation_epoch <= epoch
//             && (validator.exit_epoch.is_none() || validator.exit_epoch.unwrap() > epoch)
//     }
//
//     /// 计算全网活跃验证者的总有效余额
//     fn total_active_validators(&self) -> BigInt {
//         self.validators.iter()
//             .filter(|v| self.is_active(v, self.current_epoch))
//             .map(|v| v.effective_balance.clone())
//             .sum()
//     }
//
//
// }
//
