// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The transaction rules an N42-native chain (gov5's `IsN42Native`: consensus
//! `hotstuff` or `apos`) runs on top of evm2's Ethereum handlers, as registry
//! handlers on every EVM [`crate::n42_evm::N42BlockExecutorFactory`] makes for
//! such a chain -- so the builders, the follower's imports (serial and
//! parallel) and the RPC's simulation all apply them
//! (`docs/PROTOCOL_CONFORMANCE_2026_11.md`, decisions D4 and D5).
//!
//! - **No blob transactions (D4).** A native chain has no sidecar network,
//!   and gov5's HotStuff producer writes `blobGasUsed = 0` whatever its body
//!   carries, so a type-3 transaction is invalid on a native chain at every
//!   fork, in both clients: the pool, the ingest, the builder, block
//!   validation and execution refuse it. Here: the type-3 handler is replaced
//!   by one that refuses ([`BlobTxOnNativeChain`]).
//! - **No transaction-level initcode cap before Amsterdam (D5, G6).** gov5's
//!   state transition skips EIP-3860's cap on a creation transaction's
//!   initcode on a native chain before `glamsterdamTime`
//!   (`internal/state_transition.go`, `TransitionDb`); everything else of
//!   EIP-3860 stays: the initcode word gas, and the CREATE / CREATE2 cap of
//!   49,152 bytes (`internal/vm/gas_table.go` `gasCreateEip3860`), and so does
//!   EIP-170's 24,576-byte cap on the deployed code. evm2 keeps both caps in
//!   one field, [`evm2::Version::max_initcode_size`], so raising it would lift
//!   the opcode's cap too. Instead, a creation transaction whose initcode is
//!   over the cap is run by [`create_over_cap`]: evm2's stock `prepare` for
//!   its type with only `validate_create_initcode` left out, then the stock
//!   execution. Every other transaction goes to the handler underneath (the
//!   stock one or the fast transfer). From Amsterdam on, gov5 applies
//!   EIP-7954's 131,072-byte cap natively, as evm2's Amsterdam version does,
//!   and nothing is wrapped.

use alloy_consensus::{TxEip1559, TxEip2930, TxLegacy};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use evm2::{
    ethereum::{self, TxEnvelope},
    handler::{DefaultTxHandlerHooks, GasSettlement, TxHandlerHooks},
    interpreter::GasTracker,
    registry::{AnyTxHandler, HandlerError, HandlerResult, TxHandler, TxRegistry, TxRequest},
    Evm, EvmFeatures, EvmTypes, SpecId, TxResult,
};
use reth_primitives_traits::Recovered;

/// The refusal of a type-3 transaction on an N42-native chain.
/// Its message is [`n42_tx_types::BLOB_TX_ON_NATIVE_CHAIN`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", n42_tx_types::BLOB_TX_ON_NATIVE_CHAIN)]
pub struct BlobTxOnNativeChain;

/// Whether a native chain's EVM at `spec` runs creation transactions without
/// EIP-3860's transaction-level initcode cap: from Shanghai (where the cap
/// starts) until Amsterdam (gov5's `glamsterdamTime`, from where its own cap
/// applies).
pub fn initcode_uncapped(spec: SpecId) -> bool {
    spec.enables(SpecId::SHANGHAI) && !spec.enables(SpecId::AMSTERDAM)
}

/// `base` (the registry an EVM at `spec` would get) with a native chain's
/// rules: type 3 refused, and before Amsterdam types 0, 1 and 2 wrapped so a
/// creation with initcode over the cap is not refused for it.
pub fn registry<T: EvmTypes<Tx = TxEnvelope>>(spec: SpecId, base: TxRegistry<T, TxResult<T>>) -> TxRegistry<T, TxResult<T>> {
    let mut registry = base.clone().with_handler(
        3,
        TxEnvelope::as_eip4844,
        evm2::registry::handler(
            |_: &mut TxRequest<'_, '_, T, _>| -> HandlerResult<()> {
                Err(HandlerError::external(BlobTxOnNativeChain))
            },
            |_: TxRequest<'_, '_, T, _>, ()| -> HandlerResult<TxResult<T>> {
                Err(HandlerError::external(BlobTxOnNativeChain))
            },
        ),
    );
    if initcode_uncapped(spec) {
        if let Some(inner) = base.get_by_type(0) {
            registry = registry.with_handler(0, TxEnvelope::as_legacy, InitcodeUncapped { inner });
        }
        if let Some(inner) = base.get_by_type(1) {
            registry = registry.with_handler(1, TxEnvelope::as_eip2930, InitcodeUncapped { inner });
        }
        if let Some(inner) = base.get_by_type(2) {
            registry = registry.with_handler(2, TxEnvelope::as_eip1559, InitcodeUncapped { inner });
        }
    }
    registry
}

/// A creation transaction's fields, as the stock `prepare` of its type reads
/// them.
#[derive(Debug, Clone, Copy)]
struct Creation<'a> {
    caller: Address,
    chain_id: Option<u64>,
    /// Legacy: a transaction without a chain id is accepted (pre-EIP-155).
    chain_id_optional: bool,
    /// The fee caps of a type-2 transaction (max fee, max priority fee).
    dynamic_fee: Option<(U256, U256)>,
    /// The price the transaction pays: its gas price, or the effective one.
    gas_price: U256,
    gas_limit: u64,
    nonce: u64,
    input: &'a Bytes,
    value: U256,
    access_list: Option<&'a AccessList>,
}

/// What a typed transaction gives [`Creation`], `None` when it is not a
/// creation whose initcode is over the version's cap -- the only
/// transactions this module runs itself.
trait AsCreation {
    fn creation(&self, caller: Address, basefee: U256) -> Creation<'_>;
    fn to(&self) -> TxKind;
    fn input(&self) -> &Bytes;
}

impl AsCreation for TxLegacy {
    fn creation(&self, caller: Address, _basefee: U256) -> Creation<'_> {
        Creation {
            caller,
            chain_id: self.chain_id,
            chain_id_optional: true,
            dynamic_fee: None,
            gas_price: U256::from(self.gas_price),
            gas_limit: self.gas_limit,
            nonce: self.nonce,
            input: &self.input,
            value: self.value,
            access_list: None,
        }
    }
    fn to(&self) -> TxKind {
        self.to
    }
    fn input(&self) -> &Bytes {
        &self.input
    }
}

impl AsCreation for TxEip2930 {
    fn creation(&self, caller: Address, _basefee: U256) -> Creation<'_> {
        Creation {
            caller,
            chain_id: Some(self.chain_id),
            chain_id_optional: false,
            dynamic_fee: None,
            gas_price: U256::from(self.gas_price),
            gas_limit: self.gas_limit,
            nonce: self.nonce,
            input: &self.input,
            value: self.value,
            access_list: Some(&self.access_list),
        }
    }
    fn to(&self) -> TxKind {
        self.to
    }
    fn input(&self) -> &Bytes {
        &self.input
    }
}

impl AsCreation for TxEip1559 {
    fn creation(&self, caller: Address, basefee: U256) -> Creation<'_> {
        let max_fee = U256::from(self.max_fee_per_gas);
        let max_priority_fee = U256::from(self.max_priority_fee_per_gas);
        Creation {
            caller,
            chain_id: Some(self.chain_id),
            chain_id_optional: false,
            dynamic_fee: Some((max_fee, max_priority_fee)),
            gas_price: ethereum::effective_gas_price(max_fee, max_priority_fee, basefee),
            gas_limit: self.gas_limit,
            nonce: self.nonce,
            input: &self.input,
            value: self.value,
            access_list: Some(&self.access_list),
        }
    }
    fn to(&self) -> TxKind {
        self.to
    }
    fn input(&self) -> &Bytes {
        &self.input
    }
}

/// Whether evm2's stock `prepare` would refuse this transaction for its
/// initcode alone (`ethereum::validate_create_initcode`).
fn over_cap<T: EvmTypes>(host: &Evm<'_, T>, to: TxKind, input: &Bytes) -> bool {
    let version = host.version();
    version.feature(EvmFeatures::EIP3860) && to.is_create() && input.len() > version.max_initcode_size
}

/// Types 0, 1 and 2 on a native chain before Amsterdam: a creation over the
/// initcode cap through [`create_over_cap`], anything else through `inner`.
struct InitcodeUncapped<T: EvmTypes> {
    inner: AnyTxHandler<T, TxResult<T>>,
}

impl<T, Tx> TxHandler<T, Tx, TxResult<T>> for InitcodeUncapped<T>
where
    T: EvmTypes<Tx = TxEnvelope>,
    Tx: AsCreation,
{
    fn validate(&self, req: TxRequest<'_, '_, T, Tx>) -> HandlerResult<()> {
        if over_cap(req.host, req.tx.inner().to(), req.tx.inner().input()) {
            let creation = req.tx.inner().creation(req.tx.signer(), req.host.block().basefee);
            return prepare(req.host, req.envelope, &creation).map(|_| ());
        }
        self.inner.validate(Recovered::new_unchecked(req.envelope, req.tx.signer()), req.host)
    }

    fn execute(&self, req: TxRequest<'_, '_, T, Tx>) -> HandlerResult<TxResult<T>> {
        if over_cap(req.host, req.tx.inner().to(), req.tx.inner().input()) {
            let creation = req.tx.inner().creation(req.tx.signer(), req.host.block().basefee);
            return create_over_cap(req.host, req.envelope, &creation);
        }
        self.inner.execute(Recovered::new_unchecked(req.envelope, req.tx.signer()), req.host)
    }
}

/// What [`prepare`] hands the execution (evm2's `PreparedTx`, whose fields
/// are private to it).
#[derive(Debug, Clone, Copy)]
struct Prepared {
    intrinsic: u64,
    initial_state_gas: u64,
    floor_gas: u64,
    sender_nonce: u64,
}

/// evm2's stock `prepare_with_hooks` of types 0, 1 and 2 (default hooks), in
/// its order, for a creation, without `validate_create_initcode`: the one
/// check gov5 skips on a native chain before Amsterdam.
fn prepare<T: EvmTypes>(host: &mut Evm<'_, T>, envelope: &T::Tx, tx: &Creation<'_>) -> HandlerResult<Prepared> {
    let version = *host.version();
    if let Some((max_fee, max_priority_fee)) = tx.dynamic_fee {
        ethereum::validate_priority_fee(&version, max_fee, max_priority_fee)?;
    }
    ethereum::validate_gas_price(&version, tx.gas_price, host.block().basefee)?;
    ethereum::validate_chain_id(&version, tx.chain_id, tx.chain_id_optional)?;
    ethereum::validate_tx_gas_limit_cap(&version, tx.gas_limit)?;
    ethereum::validate_block_gas_limit(&version, tx.gas_limit, host.block().gas_limit)?;
    // `validate_create_initcode` is the stock step here: left out.
    ethereum::validate_nonce_not_overflow(tx.nonce)?;
    let (accounts, storage_keys) = tx.access_list.map_or((0, 0), ethereum::access_list_counts);
    let (mut intrinsic, mut floor_gas) =
        ethereum::intrinsic_and_floor_gas(&version, tx.caller, TxKind::Create, tx.input, accounts, storage_keys, tx.value);
    let mut initial_state_gas = 0;
    DefaultTxHandlerHooks::adjust_intrinsic_gas(host, envelope, &mut intrinsic, &mut initial_state_gas, &mut floor_gas)?;
    ethereum::validate_intrinsic_gas(tx.gas_limit, intrinsic, initial_state_gas)?;
    ethereum::validate_floor_gas(tx.gas_limit, floor_gas)?;
    ethereum::validate_execution_gas_limit_cap(&version, tx.gas_limit, intrinsic, floor_gas)?;
    // The balance check is at the fee cap (type 2) or the gas price; the
    // upfront charge at the price paid.
    let max_gas_cost = U256::from(tx.gas_limit) * tx.dynamic_fee.map_or(tx.gas_price, |(max_fee, _)| max_fee);
    let sender_nonce =
        ethereum::validate_sender_and_bump_nonce(host, tx.caller, tx.nonce, max_gas_cost.saturating_add(tx.value))?;
    ethereum::warm_base_accounts(host, TxKind::Create);
    if let Some(access_list) = tx.access_list {
        ethereum::warm_access_list(host, access_list);
    }
    DefaultTxHandlerHooks::before_execution(host, envelope, tx.caller, U256::from(tx.gas_limit) * tx.gas_price)?;
    Ok(Prepared { intrinsic, initial_state_gas, floor_gas, sender_nonce })
}

/// A creation over the initcode cap: [`prepare`], then evm2's stock
/// `execute_prepared` of types 0, 1 and 2 (identical for the three).
fn create_over_cap<T: EvmTypes>(host: &mut Evm<'_, T>, envelope: &T::Tx, tx: &Creation<'_>) -> HandlerResult<TxResult<T>> {
    let Prepared { intrinsic, initial_state_gas, floor_gas, sender_nonce } = prepare(host, envelope, tx)?;
    let (execution_gas_limit, reservoir) =
        ethereum::initial_gas_and_reservoir(host.version(), tx.gas_limit, intrinsic, initial_state_gas);
    *host.tx_env_mut() = evm2::env::TxEnvExt {
        origin: tx.caller,
        gas_price: tx.gas_price,
        chain_id: U256::from(host.version().chain_id),
        ..Default::default()
    };
    let mut tx_gas = GasTracker::new_with_execution_gas_and_reservoir(execution_gas_limit, reservoir);
    let frame =
        ethereum::prepare_initial_frame(host, tx.caller, sender_nonce, TxKind::Create, tx.input, tx.value, &mut tx_gas)?;
    let result = ethereum::execute_initial_frame(host, frame, &mut tx_gas, execution_gas_limit, reservoir)?;
    DefaultTxHandlerHooks::settle_transaction(
        host,
        envelope,
        GasSettlement {
            caller: tx.caller,
            gas_price: tx.gas_price,
            gas_limit: tx.gas_limit,
            floor_gas,
            initial_state_gas,
            state_refund: 0,
            result,
        },
    )
}

#[cfg(test)]
mod tests {
    //! D5 on both sides of `glamsterdamTime`, on a native chain and an
    //! Ethereum one, and D4's execution refusal, through the EVM the node's
    //! configuration makes (`N42EvmConfig::evm_with_env`).
    use super::*;
    use crate::n42_evm::N42EvmConfig;
    use alloy_consensus::{Signed, TxEip4844};
    use alloy_primitives::{Signature, B256};
    use evm2::{
        bytecode::Bytecode,
        evm::{AccountInfo, CacheDB, EmptyDB},
    };
    use n42_tx_types::N42TxEnvelope;
    use reth_evm::ConfigureEvm as _;
    use std::sync::Arc;

    type Config = N42EvmConfig<n42_header::N42ChainSpec>;

    const SENDER: Address = Address::repeat_byte(0x11);
    const CREATOR: Address = Address::repeat_byte(0xc0);
    /// The pre-Amsterdam cap, EIP-3860's 49,152 bytes.
    const CAP: usize = evm2::constants::MAX_INITCODE_SIZE;
    /// EIP-7954's Amsterdam cap, 131,072 bytes.
    const CAP_AMSTERDAM: usize = evm2::constants::MAX_INITCODE_SIZE_AMSTERDAM;

    /// A Prague/Osaka chain 1143 with `extra` in its config.
    fn config(extra: &str) -> Config {
        let genesis: alloy_genesis::Genesis = serde_json::from_str(&format!(
            r#"{{"config":{{"chainId":1143,"homesteadBlock":0,"eip150Block":0,"eip155Block":0,"eip158Block":0,"byzantiumBlock":0,"constantinopleBlock":0,"petersburgBlock":0,"istanbulBlock":0,"berlinBlock":0,"londonBlock":0,"mergeNetsplitBlock":0,"terminalTotalDifficulty":0,"terminalTotalDifficultyPassed":true,"shanghaiTime":0,"cancunTime":0,"pragueTime":0,"osakaTime":0{extra}}},"alloc":{{}}}}"#
        ))
        .expect("genesis");
        N42EvmConfig::new(Arc::new(n42_header::N42ChainSpec::from(reth_chainspec::ChainSpec::from_genesis(genesis))))
    }

    fn native() -> Config {
        config(r#","consensus":"hotstuff","glamsterdamTime":100"#)
    }

    fn header_at(timestamp: u64) -> n42_header::N42Header {
        n42_header::N42Header::from(alloy_consensus::Header {
            number: 5,
            timestamp,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(7),
            ..Default::default()
        })
    }

    /// The sender funded, and a contract that runs CREATE over `size` bytes
    /// of zeroed memory and stores the created address at slot 0.
    fn parent(size: u32) -> CacheDB<EmptyDB> {
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(&SENDER, AccountInfo { balance: U256::from(10u128.pow(20)), ..Default::default() });
        let [_, a, b, c] = size.to_be_bytes();
        // PUSH3 size PUSH1 0 PUSH1 0 CREATE PUSH1 0 SSTORE STOP
        let code = [0x62, a, b, c, 0x60, 0x00, 0x60, 0x00, 0xf0, 0x60, 0x00, 0x55, 0x00];
        db.insert_account_info(&CREATOR, AccountInfo::default().with_code(Bytecode::new_raw(Bytes::copy_from_slice(&code))));
        db
    }

    fn eth(tx: impl Into<reth_ethereum_primitives::TransactionSigned>) -> Recovered<TxEnvelope> {
        let envelope = N42TxEnvelope::from(tx.into());
        Recovered::new_unchecked(envelope, SENDER).map(TxEnvelope::from)
    }

    fn create(initcode_len: usize) -> Recovered<TxEnvelope> {
        let tx = TxEip1559 {
            chain_id: 1143,
            gas_limit: 16_000_000,
            max_fee_per_gas: 100,
            to: TxKind::Create,
            input: Bytes::from(vec![0u8; initcode_len]),
            ..Default::default()
        };
        eth(Signed::new_unchecked(tx, Signature::test_signature(), B256::ZERO))
    }

    fn call_creator() -> Recovered<TxEnvelope> {
        let tx = TxEip1559 {
            chain_id: 1143,
            gas_limit: 5_000_000,
            max_fee_per_gas: 100,
            to: TxKind::Call(CREATOR),
            ..Default::default()
        };
        eth(Signed::new_unchecked(tx, Signature::test_signature(), B256::ZERO))
    }

    /// Runs `tx` alone at `timestamp`: its status, or the refusal.
    fn run(c: &Config, timestamp: u64, create_size: u32, tx: &Recovered<TxEnvelope>) -> Result<bool, String> {
        let env = c.evm_env(&header_at(timestamp)).expect("env");
        let mut evm = c.evm_with_env(parent(create_size), env);
        evm.transact(tx).map(|executed| executed.detach().result.status).map_err(|err| err.to_string())
    }

    #[test]
    fn a_native_chain_runs_oversized_initcode_until_amsterdam() {
        let c = native();
        // Before glamsterdamTime: no transaction-level cap, as gov5.
        assert_eq!(run(&c, 99, 0, &create(CAP)), Ok(true));
        assert_eq!(run(&c, 99, 0, &create(CAP + 1)), Ok(true), "over EIP-3860's cap");
        assert_eq!(run(&c, 99, 0, &create(CAP_AMSTERDAM + 1)), Ok(true), "over EIP-7954's cap too");
        // From glamsterdamTime: EIP-7954's cap, in both clients.
        assert_eq!(run(&c, 100, 0, &create(CAP + 1)), Ok(true), "under EIP-7954's cap");
        assert_eq!(run(&c, 100, 0, &create(CAP_AMSTERDAM)), Ok(true), "at EIP-7954's cap");
        assert!(run(&c, 100, 0, &create(CAP_AMSTERDAM + 1)).is_err(), "over EIP-7954's cap");
    }

    #[test]
    fn an_ethereum_chain_keeps_the_eip3860_cap() {
        for extra in ["", r#","glamsterdamTime":100"#] {
            let c = config(extra);
            assert_eq!(run(&c, 99, 0, &create(CAP)), Ok(true), "{extra}");
            let refused = run(&c, 99, 0, &create(CAP + 1)).expect_err("over the cap");
            assert!(refused.to_lowercase().contains("initcode"), "{extra}: {refused}");
        }
    }

    /// The opcode keeps EIP-3860's cap on a native chain (gov5's
    /// `gasCreateEip3860`): only the transaction-level check is lifted.
    #[test]
    fn the_create_opcode_keeps_its_cap_on_a_native_chain() {
        let c = native();
        assert_eq!(run(&c, 99, CAP as u32, &call_creator()), Ok(true));
        assert_eq!(run(&c, 99, CAP as u32 + 1, &call_creator()), Ok(false), "CREATE over 49,152 bytes halts");
    }

    #[test]
    fn a_blob_transaction_is_refused_on_a_native_chain_only() {
        let blob = || {
            let tx = TxEip4844 {
                chain_id: 1143,
                gas_limit: 100_000,
                max_fee_per_gas: 100,
                max_fee_per_blob_gas: 100,
                to: Address::repeat_byte(0x22),
                blob_versioned_hashes: vec![{
                    let mut kzg = B256::ZERO;
                    kzg.0[0] = 1;
                    kzg
                }],
                ..Default::default()
            };
            eth(Signed::new_unchecked(tx, Signature::test_signature(), B256::ZERO))
        };
        for ts in [99, 100] {
            let refused = run(&native(), ts, 0, &blob()).expect_err("refused");
            assert!(refused.contains(n42_tx_types::BLOB_TX_ON_NATIVE_CHAIN), "{refused}");
        }
        // An Ethereum chain applies EIP-4844's rules: not refused as a type.
        if let Err(err) = run(&config(""), 99, 0, &blob()) {
            assert!(!err.contains(n42_tx_types::BLOB_TX_ON_NATIVE_CHAIN), "{err}");
        }
    }
}
