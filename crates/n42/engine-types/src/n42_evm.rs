// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's EVM configuration over [`N42Primitives`].
//!
//! reth's `EthEvmConfig` is pinned to the Ethereum envelope through its
//! receipt builder and its `Primitives`. This is the same configuration
//! (same block environments, same assembler, same executor factory, the
//! node's [`N42EvmFactory`](crate::fast_transfer::N42EvmFactory) with the
//! plain-transfer path) with [`N42TxEnvelope`] as the transaction, so a block
//! may carry 0x50 transactions.

use alloy_consensus::BlockHeader as _;
use n42_header::N42Header as Header;
use alloy_eips::Decodable2718;
use alloy_evm::{
    eth::{receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx}, spec::EthExecutorSpec, EthBlockExecutionCtx, EthBlockExecutorFactory},
    FromRecoveredTx, FromTxWithEncoded,
};
use alloy_primitives::{Bytes, U256};
use alloy_rpc_types_engine::ExecutionData;
use n42_tx_types::{AltSigSenderCache, N42Primitives, N42TxEnvelope, N42TxType, Receipt};
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks, Hardforks};
use reth_evm::{
    eth::NextEvmEnvAttributes, precompiles::PrecompilesMap, ConfigureEngineEvm, ConfigureEvm, Evm,
    EvmEnv, EvmEnvFor, EvmFactory, ExecutableTxIterator, ExecutionCtxFor, NextBlockEnvAttributes,
    SenderRecoveryCache, TransactionEnvMut,
};
use crate::assembler::N42HeaderAssembler;
use reth_evm_ethereum::revm_spec_by_timestamp_and_block_number;
use reth_primitives_traits::{constants::MAX_TX_GAS_LIMIT_OSAKA, SealedBlock, SealedHeader, SignedTransaction, TxTy};
use reth_storage_errors::any::AnyError;
use revm::{
    context::{BlockEnv, CfgEnv},
    context_interface::block::BlobExcessGasAndPrice,
    primitives::hardfork::SpecId,
};
use std::{borrow::Cow, convert::Infallible, fmt::Debug, sync::Arc};

/// Builds [`Receipt`]s (typed by [`N42TxType`]) from execution results.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct N42ReceiptBuilder;

impl ReceiptBuilder for N42ReceiptBuilder {
    type Transaction = N42TxEnvelope;
    type Receipt = Receipt;

    fn build_receipt<E: Evm>(&self, ctx: ReceiptBuilderCtx<'_, N42TxType, E>) -> Self::Receipt {
        let ReceiptBuilderCtx { tx_type, result, cumulative_gas_used, .. } = ctx;
        Receipt { tx_type, success: result.is_success(), cumulative_gas_used, logs: result.into_logs() }
    }
}

/// The block executor factory of [`N42EvmConfig`].
pub type N42BlockExecutorFactory<ChainSpec = reth_chainspec::ChainSpec, EvmF = crate::fast_transfer::N42EvmFactory> =
    EthBlockExecutorFactory<N42ReceiptBuilder, Arc<ChainSpec>, EvmF>;

/// Ethereum's EVM configuration with [`N42TxEnvelope`] as the transaction.
#[derive(Debug, Clone)]
pub struct N42EvmConfig<C = ChainSpec, EvmF = crate::fast_transfer::N42EvmFactory> {
    /// The executor factory.
    pub executor_factory: N42BlockExecutorFactory<C, EvmF>,
    /// The block assembler.
    pub block_assembler: N42HeaderAssembler<C>,
    /// Cache of recovered senders, when the node keeps one.
    pub sender_recovery_cache: Option<SenderRecoveryCache>,
    /// Whether the chain is a HotStuff chain, read from its genesis once.
    hotstuff: std::sync::OnceLock<bool>,
    /// From when blocks execute under the Amsterdam rules on this native
    /// chain (gov5's `glamsterdamTime`), read from its genesis once; `None`
    /// on a chain that never does ([`glamsterdam_execution_time`]).
    glamsterdam_execution: std::sync::OnceLock<Option<u64>>,
}

impl<C, EvmF> N42EvmConfig<C, EvmF> {
    /// Creates the configuration for `chain_spec` with `evm_factory`.
    pub fn new_with_evm_factory(chain_spec: Arc<C>, evm_factory: EvmF) -> Self {
        Self {
            block_assembler: N42HeaderAssembler::new(chain_spec.clone()),
            sender_recovery_cache: None,
            executor_factory: EthBlockExecutorFactory::new(N42ReceiptBuilder, chain_spec, evm_factory),
            hotstuff: std::sync::OnceLock::new(),
            glamsterdam_execution: std::sync::OnceLock::new(),
        }
    }

    /// The chain spec.
    pub const fn chain_spec(&self) -> &Arc<C> {
        self.executor_factory.spec()
    }

    /// The beneficiary an executed block credits: on an APoS chain the signer
    /// recovered from the header's Clique seal, the account the payload
    /// builder credits (`payload.rs`, its coinbase); anywhere else, or when
    /// no seal recovers, the header's beneficiary. An APoS header's
    /// beneficiary is the target of a signer vote (zero, or the proposed
    /// signer), never the fee recipient: executing with it credited the
    /// block's fees to that address while the builder, whose execution the
    /// QMDB forest keeps, had credited them to the signer.
    fn block_beneficiary(&self, header: &Header) -> alloy_primitives::Address
    where
        C: EthChainSpec,
    {
        let hotstuff = *self
            .hotstuff
            .get_or_init(|| n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(self.chain_spec().genesis()).is_ok());
        if hotstuff {
            return header.beneficiary;
        }
        match n42_clique_utils::recover_address(header) {
            Ok(signer) => signer,
            Err(err) => {
                // No seal at all is an Ethereum header (this config also runs
                // the spec tests and non-N42 chains): its beneficiary is the
                // fee recipient. A seal-sized extra data whose seal does not
                // recover is an APoS header consensus should have refused;
                // `evm_env` cannot fail (`Error = Infallible`), so the
                // fallback stays, but it is no longer silent: the fees go to
                // the header's beneficiary, not the signer the builder
                // credited, and the state root will say so.
                if header.extra_data.len() >= n42_clique_utils::SIGNATURE_LENGTH {
                    tracing::warn!(
                        target: "n42::evm",
                        number = header.number,
                        %err,
                        "the APoS seal does not recover; crediting the header's beneficiary"
                    );
                }
                header.beneficiary
            }
        }
    }

    /// Whether blocks are credited to their signer (an APoS chain).
    fn credits_signer(&self) -> bool
    where
        C: EthChainSpec,
    {
        !*self
            .hotstuff
            .get_or_init(|| n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(self.chain_spec().genesis()).is_ok())
    }

    /// Whether a block at `timestamp` executes under the Amsterdam rules
    /// although the chain spec does not schedule reth's Amsterdam: an
    /// N42-native chain past gov5's `glamsterdamTime`
    /// ([`reth_chainspec::qmdb::glamsterdam_execution_active_at`]).
    pub fn glamsterdam_execution_active_at(&self, timestamp: u64) -> bool
    where
        C: EthChainSpec,
    {
        self.glamsterdam_execution
            .get_or_init(|| glamsterdam_execution_time(self.chain_spec().genesis()))
            .is_some_and(|at| timestamp >= at)
    }

    /// Raises `cfg` to [`SpecId::AMSTERDAM`] (with its gas table, EIP-8037
    /// and EIP-2780) for a block at `timestamp` that executes under gov5's
    /// Amsterdam rules; leaves every other block's configuration as it is.
    fn apply_glamsterdam_execution(&self, cfg: &mut CfgEnv<SpecId>, timestamp: u64)
    where
        C: EthChainSpec,
    {
        if self.glamsterdam_execution_active_at(timestamp) && !cfg.spec.is_enabled_in(SpecId::AMSTERDAM) {
            glamsterdam_execution_cfg(cfg);
        }
    }

    /// Uses `cache` for sender recovery on import.
    pub fn with_sender_recovery_cache(mut self, cache: SenderRecoveryCache) -> Self {
        self.sender_recovery_cache = Some(cache);
        self
    }
}

impl<C, EvmF> ConfigureEvm for N42EvmConfig<C, EvmF>
where
    C: EthExecutorSpec + EthChainSpec + Hardforks + 'static,
    EvmF: EvmFactory<
            Tx: TransactionEnvMut + FromRecoveredTx<N42TxEnvelope> + FromTxWithEncoded<N42TxEnvelope>,
            Spec = SpecId,
            BlockEnv = BlockEnv,
            Precompiles = PrecompilesMap,
        > + Clone
        + Debug
        + Send
        + Sync
        + Unpin
        + 'static,
{
    type Primitives = N42Primitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = N42BlockExecutorFactory<C, EvmF>;
    type BlockAssembler = N42HeaderAssembler<C>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnv<SpecId>, Self::Error> {
        let mut env = EvmEnv::for_eth_block(
            header,
            self.chain_spec(),
            self.chain_spec().chain().id(),
            self.chain_spec().blob_params_at_timestamp(header.timestamp),
        );
        env.block_env.beneficiary = self.block_beneficiary(header);
        self.apply_glamsterdam_execution(&mut env.cfg_env, header.timestamp);
        Ok(env)
    }

    fn next_evm_env(&self, parent: &Header, attributes: &NextBlockEnvAttributes) -> Result<EvmEnv, Self::Error> {
        let mut env = EvmEnv::for_eth_next_block(
            parent,
            NextEvmEnvAttributes {
                timestamp: attributes.timestamp,
                suggested_fee_recipient: attributes.suggested_fee_recipient,
                prev_randao: attributes.prev_randao,
                gas_limit: attributes.gas_limit,
                slot_number: attributes.slot_number,
            },
            parent.next_block_base_fee(self.chain_spec().base_fee_params_at_timestamp(attributes.timestamp)).unwrap_or_default(),
            self.chain_spec(),
            self.chain_spec().chain().id(),
            self.chain_spec().blob_params_at_timestamp(attributes.timestamp),
        );
        self.apply_glamsterdam_execution(&mut env.cfg_env, attributes.timestamp);
        // EIP-7843: on a native chain the header's slot number is its block
        // number (`docs/HEADER_FIELD_PARITY.md` section 4), stamped after the
        // build; SLOTNUM in the build reads the same value the header, and so
        // every importer, will carry.
        if attributes.slot_number.is_none() && self.glamsterdam_execution_active_at(attributes.timestamp) {
            env.block_env.slot_num = parent.number.saturating_add(1);
        }
        Ok(env)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<n42_tx_types::Block>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(block.transaction_count()),
            parent_hash: block.header().parent_hash,
            parent_beacon_block_root: block.header().parent_beacon_block_root,
            // Ethereum's ommer rewards read alloy headers; no N42 chain has
            // ommers (APoS has no uncles, HotStuff refuses them in the body
            // check), so none are paid.
            ommers: &[],
            withdrawals: block.body().withdrawals.as_ref().map(|w| Cow::Borrowed(w.as_slice())),
            extra_data: block.header().extra_data.clone(),
            slot_number: block.header().slot_number,
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<Header>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: None,
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            ommers: &[],
            withdrawals: attributes.withdrawals.map(|w| Cow::Owned(w.into_inner())),
            extra_data: attributes.extra_data,
            slot_number: attributes.slot_number,
        })
    }
}

impl<C, EvmF> ConfigureEngineEvm<ExecutionData> for N42EvmConfig<C, EvmF>
where
    C: EthExecutorSpec + EthChainSpec + Hardforks + EthereumHardforks + 'static,
    EvmF: EvmFactory<
            Tx: TransactionEnvMut + FromRecoveredTx<N42TxEnvelope> + FromTxWithEncoded<N42TxEnvelope>,
            Spec = SpecId,
            BlockEnv = BlockEnv,
            Precompiles = PrecompilesMap,
        > + Clone
        + Debug
        + Send
        + Sync
        + Unpin
        + 'static,
{
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        let timestamp = payload.payload.timestamp();
        let block_number = payload.payload.block_number();

        let blob_params = self.chain_spec().blob_params_at_timestamp(timestamp);
        let spec = revm_spec_by_timestamp_and_block_number(self.chain_spec(), timestamp, block_number);

        let mut cfg_env =
            CfgEnv::new().with_chain_id(self.chain_spec().chain().id()).with_spec_and_mainnet_gas_params(spec);

        if let Some(blob_params) = &blob_params {
            cfg_env.set_max_blobs_per_tx(blob_params.max_blobs_per_tx);
        }

        if self.chain_spec().is_osaka_active_at_timestamp(timestamp) {
            cfg_env.tx_gas_limit_cap = Some(MAX_TX_GAS_LIMIT_OSAKA);
        }
        self.apply_glamsterdam_execution(&mut cfg_env, timestamp);

        let blob_excess_gas_and_price =
            payload.payload.excess_blob_gas().zip(blob_params).map(|(excess_blob_gas, params)| {
                let blob_gasprice = params.calc_blob_fee(excess_blob_gas);
                BlobExcessGasAndPrice { excess_blob_gas, blob_gasprice }
            });

        // On an APoS chain the payload's fee recipient is a vote target: the
        // block credits its signer, recovered from the seal over the header
        // the payload rebuilds (raw transactions, no decode).
        let beneficiary = if self.credits_signer() {
            payload
                .payload
                .clone()
                .into_block_with_sidecar_raw(&payload.sidecar)
                .ok()
                .and_then(|block| n42_clique_utils::recover_address(&block.header).ok())
                .unwrap_or_else(|| payload.payload.fee_recipient())
        } else {
            payload.payload.fee_recipient()
        };
        let block_env = BlockEnv {
            number: U256::from(block_number),
            beneficiary,
            timestamp: U256::from(timestamp),
            difficulty: if spec >= SpecId::MERGE { U256::ZERO } else { payload.payload.as_v1().prev_randao.into() },
            prevrandao: (spec >= SpecId::MERGE).then(|| payload.payload.as_v1().prev_randao),
            gas_limit: payload.payload.gas_limit(),
            basefee: payload.payload.saturated_base_fee_per_gas(),
            blob_excess_gas_and_price,
            slot_num: payload.payload.as_v4().map(|v4| v4.slot_number).unwrap_or_default(),
        };

        Ok(EvmEnv { cfg_env, block_env })
    }

    fn context_for_payload<'a>(&self, payload: &'a ExecutionData) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(payload.payload.transactions().len()),
            parent_hash: payload.parent_hash(),
            parent_beacon_block_root: payload.sidecar.parent_beacon_block_root(),
            ommers: &[],
            withdrawals: payload.payload.withdrawals().map(|w| Cow::Borrowed(w.as_slice())),
            extra_data: payload.payload.as_v1().extra_data.clone(),
            slot_number: payload.payload.as_v4().map(|v4| v4.slot_number),
        })
    }

    fn tx_iterator_for_payload(&self, payload: &ExecutionData) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let txs = payload.payload.transactions().clone();
        let sender_recovery_cache = self.sender_recovery_cache.clone();
        let convert = move |tx: Bytes| {
            let tx = TxTy::<Self::Primitives>::decode_2718_exact(tx.as_ref()).map_err(AnyError::new)?;
            let signer = match &tx {
                // Verified in a batch by whoever admitted it; a miss verifies once here.
                N42TxEnvelope::AltSig(alt) => {
                    let cache = AltSigSenderCache::global();
                    match cache.get(alt.hash()) {
                        Some(sender) => Ok(sender),
                        None => tx.try_recover().inspect(|sender| cache.insert(*alt.hash(), *sender)),
                    }
                }
                N42TxEnvelope::Eth(_) => {
                    if let Some(cache) = &sender_recovery_cache { cache.recover(&tx) } else { tx.try_recover() }
                }
            }
            .map_err(AnyError::new)?;
            Ok::<_, AnyError>(tx.with_signer(signer))
        };
        Ok((txs, convert))
    }
}

/// From when a chain with `genesis` executes under gov5's Amsterdam rules:
/// its `glamsterdamTime` on an N42-native chain, `None` otherwise (the time
/// [`reth_chainspec::qmdb::glamsterdam_execution_active_at`] compares with).
/// A chain spec that schedules reth's own Amsterdam already selects
/// [`SpecId::AMSTERDAM`] and is left as it is.
pub fn glamsterdam_execution_time(genesis: &alloy_genesis::Genesis) -> Option<u64> {
    if !reth_chainspec::qmdb::is_n42_native(genesis) {
        return None;
    }
    reth_chainspec::qmdb::glamsterdam_time(genesis)
}

/// Sets `cfg` to gov5's Amsterdam execution on a native chain: revm's
/// [`SpecId::AMSTERDAM`] with its mainnet gas table, EIP-8037 and EIP-2780
/// (`docs/GLAMSTERDAM_EXECUTION_PARITY.md`).
pub fn glamsterdam_execution_cfg(cfg: &mut CfgEnv<SpecId>) {
    cfg.set_spec_and_mainnet_gas_params(SpecId::AMSTERDAM);
}

#[cfg(test)]
mod glamsterdam_execution_tests {
    //! gov5 runs its Amsterdam state transition on a native chain from
    //! `glamsterdamTime` (`docs/GLAMSTERDAM_EXECUTION_PARITY.md`); the EVM
    //! configuration selects revm's Amsterdam there and nowhere else.
    use super::*;
    use crate::fast_transfer::N42EvmFactory;
    use alloy_consensus::Transaction as _;
    use alloy_primitives::{Address, B256};
    use reth_evm::execute::Executor as _;
    use reth_primitives_traits::{RecoveredBlock, SealedBlock};
    use revm::{
        database::{CacheDB, EmptyDB},
        state::{AccountInfo, Bytecode},
    };

    type Config = N42EvmConfig<n42_header::N42ChainSpec, N42EvmFactory>;

    fn config_for(json: &str) -> Config {
        let genesis: alloy_genesis::Genesis = serde_json::from_str(json).expect("genesis");
        let spec = n42_header::N42ChainSpec::from(reth_chainspec::ChainSpec::from_genesis(genesis));
        N42EvmConfig::new_with_evm_factory(Arc::new(spec), N42EvmFactory::default())
    }

    /// A Prague/Osaka chain 1143 with `extra` in its config.
    fn config_with(extra: &str) -> Config {
        config_for(&format!(
            r#"{{"config":{{"chainId":1143,"homesteadBlock":0,"eip150Block":0,"eip155Block":0,"eip158Block":0,"byzantiumBlock":0,"constantinopleBlock":0,"petersburgBlock":0,"istanbulBlock":0,"berlinBlock":0,"londonBlock":0,"mergeNetsplitBlock":0,"terminalTotalDifficulty":0,"terminalTotalDifficultyPassed":true,"shanghaiTime":0,"cancunTime":0,"pragueTime":0,"osakaTime":0{extra}}},"alloc":{{}}}}"#
        ))
    }

    fn header_at(timestamp: u64) -> Header {
        Header::from(alloy_consensus::Header { number: 5, timestamp, gas_limit: 30_000_000, base_fee_per_gas: Some(7), ..Default::default() })
    }

    fn next_at(timestamp: u64) -> NextBlockEnvAttributes {
        NextBlockEnvAttributes {
            timestamp,
            suggested_fee_recipient: Address::repeat_byte(0xcb),
            prev_randao: B256::ZERO,
            gas_limit: 30_000_000,
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals: None,
            extra_data: Default::default(),
            slot_number: None,
        }
    }

    #[test]
    fn a_native_chain_executes_amsterdam_from_its_glamsterdam_time() {
        let c = config_with(r#","consensus":"hotstuff","glamsterdamTime":100"#);
        let before = c.evm_env(&header_at(99)).expect("env");
        assert_eq!(before.cfg_env.spec, SpecId::OSAKA);
        assert!(!before.cfg_env.enable_amsterdam_eip8037);
        let after = c.evm_env(&header_at(100)).expect("env");
        assert_eq!(after.cfg_env.spec, SpecId::AMSTERDAM);
        assert!(after.cfg_env.enable_amsterdam_eip8037 && after.cfg_env.enable_amsterdam_eip2780);
        assert_eq!(after.cfg_env.gas_params, revm::context_interface::cfg::GasParams::new_spec(SpecId::AMSTERDAM));
        // The EIP-7825 cap stays: under EIP-8037 it bounds the regular gas only.
        assert_eq!(after.cfg_env.tx_gas_limit_cap, Some(MAX_TX_GAS_LIMIT_OSAKA));
        // The builder's environment follows, with SLOTNUM at the block number.
        let parent = header_at(99);
        let next = c.next_evm_env(&parent, &next_at(100)).expect("env");
        assert_eq!(next.cfg_env.spec, SpecId::AMSTERDAM);
        assert_eq!(next.block_env.slot_num, 6);
        let next = c.next_evm_env(&parent, &next_at(99)).expect("env");
        assert_eq!(next.cfg_env.spec, SpecId::OSAKA);
        assert_eq!(next.block_env.slot_num, 0);
        // reth's own Amsterdam is not scheduled: the header and payload rules
        // that hang off it stay off.
        assert!(!c.chain_spec().is_amsterdam_active_at_timestamp(u64::MAX));
    }

    #[test]
    fn other_chains_keep_their_spec() {
        // A native chain without the fork, and a non-native chain with it.
        for extra in [r#","consensus":"hotstuff""#, r#","glamsterdamTime":0"#, ""] {
            let c = config_with(extra);
            for ts in [0, 100, u64::MAX / 2] {
                assert_eq!(c.evm_env(&header_at(ts)).expect("env").cfg_env.spec, SpecId::OSAKA, "{extra} at {ts}");
                let next = c.next_evm_env(&header_at(ts), &next_at(ts + 1)).expect("env");
                assert_eq!(next.cfg_env.spec, SpecId::OSAKA);
                assert_eq!(next.block_env.slot_num, 0);
            }
        }
    }

    /// The ungated devnet executes exactly as before: the environment is the
    /// one `EvmEnv::for_eth_block` makes, field for field.
    #[test]
    fn the_ungated_devnet_environment_is_unchanged() {
        let c = config_for(include_str!("../../../chainspec/res/genesis/n42_devnet.json"));
        for ts in [0, 1_000, 1_798_761_600, u64::MAX / 2] {
            let header = header_at(ts);
            let got = c.evm_env(&header).expect("env");
            let mut want = EvmEnv::for_eth_block(
                &header,
                c.chain_spec(),
                c.chain_spec().chain().id(),
                c.chain_spec().blob_params_at_timestamp(ts),
            );
            want.block_env.beneficiary = got.block_env.beneficiary;
            assert_eq!(got.cfg_env.spec, want.cfg_env.spec);
            assert_eq!(got.cfg_env.gas_params, want.cfg_env.gas_params);
            assert_eq!(got.cfg_env.enable_amsterdam_eip8037, want.cfg_env.enable_amsterdam_eip8037);
            assert_eq!(got.cfg_env.enable_amsterdam_eip2780, want.cfg_env.enable_amsterdam_eip2780);
            assert_eq!(got.cfg_env.tx_gas_limit_cap, want.cfg_env.tx_gas_limit_cap);
            assert_eq!(got.block_env, want.block_env);
            assert_eq!(got.cfg_env.spec, SpecId::OSAKA);
        }
    }

    /// gov5's fixture (`internal/glamsterdam_native_fixture_test.go` on gov5
    /// branch `test/glamsterdam-native-fixtures`): one block of the native
    /// chain's transaction shapes on the gated devnet genesis, executed by
    /// gov5. Receipts, gas, logs, the receipts root and the touched accounts
    /// must be the same here, by value.
    #[test]
    fn the_gated_devnet_block_matches_gov5() {
        let fx: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/glamsterdam_native/block1.json")).expect("fixture");
        let c = config_for(include_str!("../../../chainspec/res/genesis/n42_devnet_mobileanchor.json"));
        let u = |v: &serde_json::Value| v.as_u64().expect("a number");
        let s = |v: &serde_json::Value| v.as_str().expect("a string").to_string();
        let addr = |v: &serde_json::Value| s(v).parse::<Address>().expect("an address");
        let bytes = |v: &serde_json::Value| s(v).parse::<alloy_primitives::Bytes>().expect("hex bytes");

        let mut db = CacheDB::new(EmptyDB::default());
        // The genesis system contracts, which the block's pre- and
        // post-execution calls read (gov5's fixture skips them; they touch
        // nothing the fixture compares).
        for (address, account) in &c.chain_spec().genesis().alloc {
            let code = account.code.clone().unwrap_or_default();
            if code.is_empty() {
                continue;
            }
            db.insert_account_info(
                *address,
                AccountInfo { balance: account.balance, nonce: account.nonce.unwrap_or(0), ..Default::default() }
                    .with_code(Bytecode::new_raw(code)),
            );
        }
        for account in fx["pre"].as_array().expect("pre") {
            let code = bytes(&account["code"]);
            let mut info = AccountInfo {
                balance: s(&account["balance"]).parse().expect("balance"),
                nonce: u(&account["nonce"]),
                ..Default::default()
            };
            if !code.is_empty() {
                info = info.with_code(Bytecode::new_raw(code));
            }
            db.insert_account_info(addr(&account["address"]), info);
        }

        let txs: Vec<N42TxEnvelope> = fx["transactions"]
            .as_array()
            .expect("txs")
            .iter()
            .map(|raw| N42TxEnvelope::decode_2718_exact(&bytes(raw)).expect("a transaction"))
            .collect();
        let senders: Vec<Address> = txs.iter().map(|tx| tx.try_recover().expect("signed")).collect();
        let header = Header::from(alloy_consensus::Header {
            number: u(&fx["number"]),
            timestamp: u(&fx["timestamp"]),
            gas_limit: u(&fx["gasLimit"]),
            base_fee_per_gas: Some(u(&fx["baseFee"])),
            beneficiary: addr(&fx["coinbase"]),
            slot_number: Some(u(&fx["slotNumber"])),
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            ..Default::default()
        });
        assert!(c.glamsterdam_execution_active_at(header.timestamp));
        let body = n42_tx_types::BlockBody { transactions: txs.clone(), ommers: Vec::new(), withdrawals: Some(Vec::new().into()) };
        let block = SealedBlock::seal_slow(n42_tx_types::Block { header, body });
        let block = RecoveredBlock::new_sealed(block, senders);
        let out = c.executor(db).execute(&block).expect("the block executes");

        let receipts = fx["receipts"].as_array().expect("receipts");
        assert_eq!(out.result.receipts.len(), receipts.len());
        let mut previous = 0;
        for (i, (got, want)) in out.result.receipts.iter().zip(receipts).enumerate() {
            assert_eq!(got.success, u(&want["status"]) == 1, "tx {i} status");
            assert_eq!(got.cumulative_gas_used, u(&want["cumulativeGasUsed"]), "tx {i} cumulative gas");
            assert_eq!(got.cumulative_gas_used - previous, u(&want["gasUsed"]), "tx {i} gas used");
            previous = got.cumulative_gas_used;
            let logs = want["logs"].as_array().expect("logs");
            assert_eq!(got.logs.len(), logs.len(), "tx {i} log count");
            for (j, (log, want)) in got.logs.iter().zip(logs).enumerate() {
                assert_eq!(log.address, addr(&want["address"]), "tx {i} log {j} emitter");
                let topics: Vec<B256> =
                    want["topics"].as_array().expect("topics").iter().map(|t| s(t).parse().expect("topic")).collect();
                assert_eq!(log.topics(), topics.as_slice(), "tx {i} log {j} topics");
                assert_eq!(log.data.data, bytes(&want["data"]), "tx {i} log {j} data");
            }
        }
        assert_eq!(previous, u(&fx["receiptsCumulativeGasUsed"]));
        assert_eq!(out.result.gas_used, u(&fx["gasUsed"]), "the header's gas used (EIP-8037)");
        let (root, _) = crate::hotstuff_consensus::gov5_receipt_root_bloom(&out.result.receipts);
        assert_eq!(root, s(&fx["receiptsRoot"]).parse::<B256>().expect("root"), "the receipts root");

        for account in fx["post"].as_array().expect("post") {
            let address = addr(&account["address"]);
            let got = out.state.account(&address).and_then(|a| a.info.clone());
            if s(&account["balance"]) == "absent" {
                assert!(got.as_ref().is_none_or(|info| info.is_empty()), "{address} must not exist: {got:?}");
                continue;
            }
            // An account the block left as it was is not in the bundle: its
            // post-state is its pre-state.
            let info = got.unwrap_or_else(|| {
                let pre = fx["pre"]
                    .as_array()
                    .expect("pre")
                    .iter()
                    .find(|pre| addr(&pre["address"]) == address)
                    .unwrap_or_else(|| panic!("{address} is in the pre- or post-state"));
                let code = bytes(&pre["code"]);
                AccountInfo {
                    balance: s(&pre["balance"]).parse().expect("balance"),
                    nonce: u(&pre["nonce"]),
                    ..Default::default()
                }
                .with_code(Bytecode::new_raw(code))
            });
            assert_eq!(info.balance, s(&account["balance"]).parse::<U256>().expect("balance"), "{address} balance");
            assert_eq!(info.nonce, u(&account["nonce"]), "{address} nonce");
            let code = bytes(&account["code"]);
            assert_eq!(info.code.as_ref().map(|c| c.original_bytes()).unwrap_or_default(), code, "{address} code");
            let slot0 = out.state.account(&address).and_then(|a| a.storage.get(&U256::ZERO)).map(|slot| slot.present_value);
            let want = account
                .get("storage")
                .and_then(|storage| storage.as_object())
                .and_then(|storage| storage.values().next())
                .map(|v| s(v).parse::<U256>().expect("slot"));
            assert_eq!(slot0.filter(|v| !v.is_zero()), want, "{address} slot 0");
        }
        // Every transaction's gas limit stayed inside the block's.
        assert!(txs.iter().map(|tx| tx.gas_limit()).sum::<u64>() <= block.header().gas_limit);
    }
}
