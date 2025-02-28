#![allow(missing_docs)]
use reth_revm::{
    test_utils::StateProviderTest,
    database::StateProviderDatabase,
    db::State,
};
use android_logger::Config;
use log::Level;
use jni::objects::{JObject, JString};
use jni::sys::{jstring, jlong};
use jni::{JNIEnv};
use std::sync::Arc;
use reth_chainspec::{
    ChainSpec, ChainSpecBuilder, EthereumHardfork, EthereumHardforks, ForkCondition, MAINNET, MIN_TRANSACTION_GAS
};
use reth_evm::{
    execute::{
        BasicBlockExecutorProvider, BatchExecutor, BlockExecutionError, BlockExecutionStrategy, BlockExecutionStrategyFactory, BlockExecutorProvider, BlockValidationError, ExecuteOutput, ProviderError
    }, state_change::post_block_balance_increments, system_calls::{
        OnStateHook, SystemCaller
    }, ConfigureEvm
};
use reth_evm_ethereum::{
    EthEvmConfig,
    eip6110,
    dao_fork::{
        DAO_HARDKFORK_ACCOUNTS,
        DAO_HARDFORK_BENEFICIARY,
    },
};
use alloy_consensus::{Header, Transaction as _, TxEip1559};
use revm_primitives::{
    db::{Database,DatabaseCommit}, BlockEnv, CfgEnvWithHandlerCfg, EnvWithHandlerCfg, ResultAndState, B256, U256,
};
use core::fmt::Display;
use reth_primitives::{
    Block, BlockBody, BlockWithSenders, Receipt, TransactionSigned,Transaction,
};
use alloy_eips::eip7685::Requests;
use reth_consensus::ConsensusError;
use reth_ethereum_consensus::validate_block_post_execution;
use alloy_primitives::{Address,Signature,address,hex,Uint};


/// Block execution strategy for Ethereum.
#[allow(missing_debug_implementations)]
pub struct EthExecutionStrategy<DB, EvmConfig>
where
    EvmConfig: Clone,
{
    /// The chainspec
    chain_spec: Arc<ChainSpec>,
    /// How to create an EVM.
    evm_config: EvmConfig,
    /// Current state for block execution.
    state: State<DB>,
    /// Utility to call system smart contracts.
    system_caller: SystemCaller<EvmConfig, ChainSpec>,
}



impl<DB, EvmConfig> EthExecutionStrategy<DB, EvmConfig>
where
    EvmConfig: Clone,
{
    /// Creates a new [`EthExecutionStrategy`]
    pub fn new(state: State<DB>, chain_spec: Arc<ChainSpec>, evm_config: EvmConfig) -> Self {
        let system_caller = SystemCaller::new(evm_config.clone(), chain_spec.clone());
        Self { state, chain_spec, evm_config, system_caller }
    }
}

impl<DB, EvmConfig> EthExecutionStrategy<DB, EvmConfig>
where
    DB: Database<Error: Into<ProviderError> + Display>,
    EvmConfig: ConfigureEvm<Header = alloy_consensus::Header>,
{
    /// Configures a new evm configuration and block environment for the given block.
    ///
    /// # Caution
    ///
    /// This does not initialize the tx environment.
    fn evm_env_for_block(
        &self,
        header: &alloy_consensus::Header,
        total_difficulty: U256,
    ) -> EnvWithHandlerCfg {
        let mut cfg = CfgEnvWithHandlerCfg::new(Default::default(), Default::default());
        let mut block_env = BlockEnv::default();
        self.evm_config.fill_cfg_and_block_env(&mut cfg, &mut block_env, header, total_difficulty);

        EnvWithHandlerCfg::new_with_cfg_env(cfg, block_env, Default::default())
    }
}

impl<DB, EvmConfig> BlockExecutionStrategy<DB> for EthExecutionStrategy<DB, EvmConfig>
where
    DB: Database<Error: Into<ProviderError> + Display>,
    EvmConfig: ConfigureEvm<Header = alloy_consensus::Header>,
{
    type Error = BlockExecutionError;

    fn apply_pre_execution_changes(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<(), Self::Error> {
        // Set state clear flag if the block is after the Spurious Dragon hardfork.
        let state_clear_flag =
            (*self.chain_spec).is_spurious_dragon_active_at_block(block.header.number);
        self.state.set_state_clear_flag(state_clear_flag);

        let env = self.evm_env_for_block(&block.header, total_difficulty);
        let mut evm = self.evm_config.evm_with_env(&mut self.state, env);

        self.system_caller.apply_pre_execution_changes(block, &mut evm)?;

        Ok(())
    }

    fn execute_transactions(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<ExecuteOutput, Self::Error> {
        let env = self.evm_env_for_block(&block.header, total_difficulty);
        let mut evm = self.evm_config.evm_with_env(&mut self.state, env);

        let mut cumulative_gas_used = 0;
        let mut receipts = Vec::with_capacity(block.body.transactions.len());
        for (sender, transaction) in block.transactions_with_sender() {
            // The sum of the transaction’s gas limit, Tg, and the gas utilized in this block prior,
            // must be no greater than the block’s gasLimit.
            let block_available_gas = block.header.gas_limit - cumulative_gas_used;
            if transaction.gas_limit() > block_available_gas {
                return Err(BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit: transaction.gas_limit(),
                    block_available_gas,
                }
                .into())
            }

            self.evm_config.fill_tx_env(evm.tx_mut(), transaction, *sender);

            // Execute transaction.
            let result_and_state = evm.transact().map_err(move |err| {
                let new_err = err.map_db_err(|e| e.into());
                // Ensure hash is calculated for error log, if not already done
                BlockValidationError::EVM {
                    hash: transaction.recalculate_hash(),
                    error: Box::new(new_err),
                }
            })?;
            self.system_caller.on_state(&result_and_state);
            let ResultAndState { result, state } = result_and_state;
            evm.db_mut().commit(state);

            // append gas used
            cumulative_gas_used += result.gas_used();

            // Push transaction changeset and calculate header bloom filter for receipt.
            receipts.push(
                #[allow(clippy::needless_update)] // side-effect of optimism fields
                Receipt {
                    tx_type: transaction.tx_type(),
                    // Success flag was added in `EIP-658: Embedding transaction status code in
                    // receipts`.
                    success: result.is_success(),
                    cumulative_gas_used,
                    // convert to reth log
                    logs: result.into_logs(),
                    ..Default::default()
                },
            );
        }
        Ok(ExecuteOutput { receipts, gas_used: cumulative_gas_used })
    }

    fn apply_post_execution_changes(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
        receipts: &[Receipt],
    ) -> Result<Requests, Self::Error> {
        let env = self.evm_env_for_block(&block.header, total_difficulty);
        let mut evm = self.evm_config.evm_with_env(&mut self.state, env);

        let requests = if self.chain_spec.is_prague_active_at_timestamp(block.timestamp) {
            // Collect all EIP-6110 deposits
            let deposit_requests =
                crate::eip6110::parse_deposits_from_receipts(&self.chain_spec, receipts)?;

            let mut requests = Requests::new(vec![deposit_requests]);
            requests.extend(self.system_caller.apply_post_execution_changes(&mut evm)?);
            requests
        } else {
            Requests::default()
        };
        drop(evm);

        let mut balance_increments =
            post_block_balance_increments(&self.chain_spec, block, total_difficulty);

        // Irregular state change at Ethereum DAO hardfork
        if self.chain_spec.fork(EthereumHardfork::Dao).transitions_at_block(block.number) {
            // drain balances from hardcoded addresses.
            let drained_balance: u128 = self
                .state
                .drain_balances(DAO_HARDKFORK_ACCOUNTS)
                .map_err(|_| BlockValidationError::IncrementBalanceFailed)?
                .into_iter()
                .sum();

            // return balance to DAO beneficiary.
            *balance_increments.entry(DAO_HARDFORK_BENEFICIARY).or_default() += drained_balance;
        }
        // increment balances
        self.state
            .increment_balances(balance_increments)
            .map_err(|_| BlockValidationError::IncrementBalanceFailed)?;

        Ok(requests)
    }

    fn state_ref(&self) -> &State<DB> {
        &self.state
    }

    fn state_mut(&mut self) -> &mut State<DB> {
        &mut self.state
    }

    fn with_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.system_caller.with_state_hook(hook);
    }

    fn validate_block_post_execution(
        &self,
        block: &BlockWithSenders,
        receipts: &[Receipt],
        requests: &Requests,
    ) -> Result<(), ConsensusError> {
        validate_block_post_execution(block, &self.chain_spec.clone(), receipts, requests)
    }
}




/// Factory for [`EthExecutionStrategy`].
#[derive(Debug, Clone)]
pub struct EthExecutionStrategyFactory<EvmConfig = EthEvmConfig> {
    /// The chainspec
    chain_spec: Arc<ChainSpec>,
    /// How to create an EVM.
    evm_config: EvmConfig,
}

impl EthExecutionStrategyFactory {
    /// Creates a new default ethereum executor strategy factory.
    pub fn ethereum(chain_spec: Arc<ChainSpec>) -> Self {
        Self::new(chain_spec.clone(), EthEvmConfig::new(chain_spec))
    }

    /// Returns a new factory for the mainnet.
    pub fn mainnet() -> Self {
        Self::ethereum(MAINNET.clone())
    }
}

impl<EvmConfig> EthExecutionStrategyFactory<EvmConfig> {
    /// Creates a new executor strategy factory.
    pub const fn new(chain_spec: Arc<ChainSpec>, evm_config: EvmConfig) -> Self {
        Self { chain_spec, evm_config }
    }
}

impl<EvmConfig> BlockExecutionStrategyFactory for EthExecutionStrategyFactory<EvmConfig>
where
    EvmConfig:
        Clone + Unpin + Sync + Send + 'static + ConfigureEvm<Header = alloy_consensus::Header>,
{
    type Strategy<DB: Database<Error: Into<ProviderError> + Display>> =
        EthExecutionStrategy<DB, EvmConfig>;

    fn create_strategy<DB>(&self, db: DB) -> Self::Strategy<DB>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        let state =
            State::builder().with_database(db).with_bundle_update().without_state_clear().build();
        EthExecutionStrategy::new(state, self.chain_spec.clone(), self.evm_config.clone())
    }
}


fn executor_provider(
    chain_spec: Arc<ChainSpec>,
) -> BasicBlockExecutorProvider<EthExecutionStrategyFactory> {
    let strategy_factory =
        EthExecutionStrategyFactory::new(chain_spec.clone(), EthEvmConfig::new(chain_spec));

    BasicBlockExecutorProvider::new(strategy_factory)
}
#[no_mangle]
// pub extern "C" fn Java_com_example_rustlibrary_LyTest_lyFunction(
//     env: JNIEnv<'_>,
//     _: JObject<'_>,
// ) -> jstring {
//     let output = "Hello from Rust";
    
//     // 创建 Java 字符串
//     match env.new_string(output) {
//         Ok(java_str) => {
//             // 正确转换 JString 到 jstring
//             java_str.into_raw()
//         }
//         Err(_) => {
//             // 返回空指针给 Java
//             std::ptr::null_mut()
//         }
//     }
// }

#[no_mangle]
// pub extern "C" fn Java_com_example_rustlibrary_LyTest_evmTest(mut env: JNIEnv<'_>, value_origin: jlong) {
pub extern "C" fn evmTest(value_origin: u64) {

    android_logger::init_once(Config::default().with_tag("rustdemo"));
    log::set_max_level(log::LevelFilter::Debug);
    
    log::debug!("Hello from Rust");
    log::debug!("value_origin:{}", value_origin);
    //convert to u64
    // let value_u64: u64 = value_origin as u64;
    // let value=value_u64-140731582808552u64;
    let value=value_origin;
    // log::debug!("Converted value_origin to u64: {}", value);
    // Uint<256, 4>
    let wei_per_eth=1000000000000000000u64;
    let mut db: StateProviderTest = StateProviderTest::default();
    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(1))
            .build(),
    );
    let addr = address!("9b2AFf4ecC9f1e0c3813679B9079Af9836F1852a");
    let tx=TransactionSigned::from_transaction_and_signature(Transaction::Eip1559(TxEip1559{
        chain_id:chain_spec.chain.id(),
        nonce:0,
        gas_limit:MIN_TRANSACTION_GAS,
        to:addr.into(),
        value:U256::from(value)*U256::from(wei_per_eth),
        // value:U256::ZERO,
        ..Default::default()
    }), Signature::test_signature(),);
    let provider=executor_provider(chain_spec);
    let mut executor = provider.batch_executor(StateProviderDatabase::new(&db));
    let mut header=Header{timestamp:1,number:1,excess_blob_gas:Some(0),gas_limit:5000000,gas_used:21000,
        // receipts_root:B256::from_slice(&hex::decode("f78dfb743fbd92ade140711c8bbc542b5e307f0ab7984eff35d751969fe57efa").unwrap()),
        ..Header::default()};
    header.parent_beacon_block_root=Some(B256::with_last_byte(0x69));
    match executor.execute_and_verify_one((
        &BlockWithSenders {
            block: Block {
                header: header.clone(),
                body: BlockBody {
                    transactions: vec![tx],
                    ..Default::default()
                },
            },
            senders: vec![addr],
        },
        U256::ZERO,
    ).into()) {
        Ok(_) => println!(""),
        Err(e) =>println!("Error during execution: {:?}", e),
        // println!("Error during execution: {:?}", e),
    }
    log::debug!("success1");
    let temp=executor.finalize();
    let receipts=temp.receipts();
    if !receipts.receipt_vec.is_empty() && !receipts.receipt_vec[0].is_empty() {
        let txreceipt = receipts.receipt_vec[0][0].as_ref().unwrap();
        println!("{:?}", txreceipt);
        log::debug!("success2");
        log::debug!("{:?}", txreceipt);
    } else {
        println!("No receipts found");
        log::debug!("success3");
    }
    log::debug!("success4");
}
fn main(){
    // Java_com_example_rustdemo_LyTest_evmTest(0);
}