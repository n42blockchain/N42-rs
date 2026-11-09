// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The plain value transfer as an evm2 transaction handler (F5f).
//!
//! The revm-era fast transfer (removed in F6a) replaced
//! revm's whole transaction pipeline for a transfer between two accounts without
//! code. evm2 already completes a call to an account without code without running
//! the interpreter (`Evm::execute_call_message`), so what is left to save is the
//! first frame around it: the code load, the message, two state checkpoints and
//! the dispatch. This handler wraps the stock Ethereum handlers for types 0, 1 and
//! 2 (0x50 executes as 2): the stock `prepare` validates the transaction, bumps
//! the nonce and charges the upfront fee exactly as before; then, for a
//! transaction that qualifies, the value moves through evm2's own
//! `State::transfer` and the stock settlement (`settle_initial_frame_gas`, the
//! default hooks' `settle_transaction`) refunds the sender and pays the
//! beneficiary. Anything that does not qualify goes to the stock `execute`.
//!
//! What qualifies: a call with no input and no access list, on Prague, Osaka
//! or Amsterdam (EIP-2780's intrinsic, EIP-8037's new-account state gas and
//! EIP-7708's transfer log are applied as the stock path applies them), with no
//! inspector, to an account without code that is not a precompile, where the
//! sender, the recipient and the beneficiary are three accounts, the recipient
//! is not left empty by a zero-value call (EIP-161), and the sender can pay the
//! value after the upfront charge.
//!
//! When it is used: by the parallel batches (F5c builder, F5d follower) unless
//! `N42_BATCH_FAST_TRANSFER=0`, as the revm-era batches always used the fast
//! transfer; and by every EVM this node builds with `N42_FAST_TRANSFER=1`.

use alloy_consensus::{TxEip1559, TxEip2930, TxLegacy};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use evm2::{
    ethereum::{self, TxEnvelope},
    handler::{DefaultTxHandlerHooks, GasSettlement, TxHandlerHooks},
    interpreter::{GasTracker, InstrStop, MessageResultExt},
    registry::{handler, HandlerResult, TxRegistry, TxRequest},
    Evm, EvmTypes, SpecId, TxResult,
};

/// Transfers this handler completed, since start.
static HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Transactions it handed to the stock `execute`, since start.
static DELEGATED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Transfers the handler completed, since start.
pub fn hits() -> u64 {
    HITS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Transactions the handler gave to the stock `execute`, since start.
pub fn delegated() -> u64 {
    DELEGATED.load(std::sync::atomic::Ordering::Relaxed)
}

/// `N42_FAST_TRANSFER=1`: every EVM this node builds carries the handler.
pub fn everywhere() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_FAST_TRANSFER", false))
}

/// `N42_BATCH_FAST_TRANSFER` (default on; `0` turns it off for the data
/// point): the parallel batches' EVMs carry the handler.
pub fn in_batches() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_BATCH_FAST_TRANSFER", true))
}

std::thread_local! {
    static IN_BATCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `make` (an EVM's construction) as a batch's: the factory then gives it
/// the handler when [`in_batches`] is on.
pub fn as_batch<R>(make: impl FnOnce() -> R) -> R {
    IN_BATCH.with(|in_batch| in_batch.set(true));
    let made = make();
    IN_BATCH.with(|in_batch| in_batch.set(false));
    made
}

/// Whether an EVM made now should carry the handler.
pub fn wanted() -> bool {
    everywhere() || (IN_BATCH.with(std::cell::Cell::get) && in_batches())
}

/// Whether the handler is registered on `spec`: Prague, Osaka and
/// Amsterdam (gov5's Amsterdam execution on a native chain; the EIP-2780
/// intrinsic, the EIP-8037 new-account state gas and the EIP-7708 transfer
/// log are modelled, `docs/AMSTERDAM_PARALLEL_STEP.md`).
pub fn covers(spec: SpecId) -> bool {
    spec.enables(SpecId::PRAGUE) && SpecId::AMSTERDAM.enables(spec)
}

/// Whether `version`'s Amsterdam transfer rules are all on or all off: the
/// fast paths model EIP-2780, EIP-8037 and EIP-7708 together and nothing in
/// between.
pub fn amsterdam_features_consistent(version: &evm2::Version) -> bool {
    use evm2::EvmFeatures;
    let eip2780 = version.feature(EvmFeatures::EIP2780);
    eip2780 == version.feature(EvmFeatures::EIP8037) && eip2780 == version.feature(EvmFeatures::EIP7708)
}

/// `base` (the stock registry for `spec`) with types 0, 1 and 2 handled by
/// this module when [`covers`] says so; `base` unchanged otherwise.
pub fn registry<T: EvmTypes<Tx = TxEnvelope>>(spec: SpecId, base: TxRegistry<T, TxResult<T>>) -> TxRegistry<T, TxResult<T>> {
    if !covers(spec) {
        return base;
    }
    base.with_handler(
        0,
        TxEnvelope::as_legacy,
        handler(
            |req: &mut TxRequest<'_, '_, T, TxLegacy>| {
                let tx = req.tx.inner();
                let shape = Shape::of(req.tx.signer(), U256::from(tx.gas_price), tx.gas_limit, tx.to, &tx.input, tx.value, true);
                Ok((ethereum::legacy::prepare_with_hooks::<T, DefaultTxHandlerHooks>(req)?, shape))
            },
            |req: TxRequest<'_, '_, T, TxLegacy>, (prepared, shape)| match transfer(req.host, req.envelope, &shape)? {
                Some(result) => Ok(result),
                None => ethereum::legacy::execute_prepared::<T, DefaultTxHandlerHooks>(req, prepared),
            },
        ),
    )
    .with_handler(
        1,
        TxEnvelope::as_eip2930,
        handler(
            |req: &mut TxRequest<'_, '_, T, TxEip2930>| {
                let tx = req.tx.inner();
                let shape = Shape::of(
                    req.tx.signer(),
                    U256::from(tx.gas_price),
                    tx.gas_limit,
                    tx.to,
                    &tx.input,
                    tx.value,
                    tx.access_list.is_empty(),
                );
                Ok((ethereum::eip2930::prepare_with_hooks::<T, DefaultTxHandlerHooks>(req)?, shape))
            },
            |req: TxRequest<'_, '_, T, TxEip2930>, (prepared, shape)| match transfer(req.host, req.envelope, &shape)? {
                Some(result) => Ok(result),
                None => ethereum::eip2930::execute_prepared::<T, DefaultTxHandlerHooks>(req, prepared),
            },
        ),
    )
    .with_handler(
        2,
        TxEnvelope::as_eip1559,
        handler(
            |req: &mut TxRequest<'_, '_, T, TxEip1559>| {
                let tx = req.tx.inner();
                let gas_price = ethereum::effective_gas_price(
                    U256::from(tx.max_fee_per_gas),
                    U256::from(tx.max_priority_fee_per_gas),
                    req.host.block().basefee,
                );
                let shape =
                    Shape::of(req.tx.signer(), gas_price, tx.gas_limit, tx.to, &tx.input, tx.value, tx.access_list.is_empty());
                Ok((ethereum::eip1559::prepare_with_hooks::<T, DefaultTxHandlerHooks>(req)?, shape))
            },
            |req: TxRequest<'_, '_, T, TxEip1559>, (prepared, shape)| match transfer(req.host, req.envelope, &shape)? {
                Some(result) => Ok(result),
                None => ethereum::eip1559::execute_prepared::<T, DefaultTxHandlerHooks>(req, prepared),
            },
        ),
    )
}

/// What the qualification and the settlement read of a transaction, taken
/// before the stock `prepare` consumes the request.
#[derive(Debug, Clone, Copy)]
struct Shape {
    caller: Address,
    gas_price: U256,
    gas_limit: u64,
    /// The recipient of a call with no input and no access list; `None`
    /// for anything else.
    to: Option<Address>,
    value: U256,
}

impl Shape {
    fn of(caller: Address, gas_price: U256, gas_limit: u64, to: TxKind, input: &Bytes, value: U256, no_access_list: bool) -> Self {
        let to = match to {
            TxKind::Call(to) if input.is_empty() && no_access_list => Some(to),
            _ => None,
        };
        Self { caller, gas_price, gas_limit, to, value }
    }
}

/// The transfer after the stock `prepare`, or `None` (nothing written) when
/// the transaction does not qualify and the stock `execute` must run it.
fn transfer<T: EvmTypes>(host: &mut Evm<'_, T>, envelope: &T::Tx, shape: &Shape) -> HandlerResult<Option<TxResult<T>>> {
    let delegate = || {
        DELEGATED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(None)
    };
    let Some(to) = shape.to else { return delegate() };
    let caller = shape.caller;
    let beneficiary = host.block().beneficiary;
    if !covers(host.spec_id())
        || !amsterdam_features_consistent(host.version())
        || host.inspector().is_some()
        || to == caller
        || to == beneficiary
        || caller == beneficiary
        || host.precompiles().contains(&to)
    {
        return delegate();
    }
    let recipient_empty = {
        let state = host.state_mut();
        let (recipient_empty, recipient_codeless) = {
            let recipient = state.account(&to)?;
            (recipient.get().is_none_or(evm2::AccountInfo::is_empty), recipient.is_empty_code_hash())
        };
        if !recipient_codeless || (shape.value.is_zero() && recipient_empty) {
            return delegate();
        }
        if state.account(&caller)?.balance() < shape.value {
            return delegate();
        }
        recipient_empty
    };
    // The intrinsic gas of a call with no input and no access list, as the
    // stock `prepare` computed it (no hooks: no adjustment, no state gas;
    // EIP-2780's decomposed base on Amsterdam).
    let (intrinsic, floor_gas) =
        ethereum::intrinsic_and_floor_gas(host.version(), caller, TxKind::Call(to), &Bytes::new(), 0, 0, shape.value);
    let (execution_gas_limit, reservoir) = ethereum::initial_gas_and_reservoir(host.version(), shape.gas_limit, intrinsic, 0);
    let mut tx_gas = GasTracker::new_with_execution_gas_and_reservoir(execution_gas_limit, reservoir);
    // EIP-2780's runtime phase (`prepare_initial_frame`): a value to an empty
    // recipient pays EIP-8037's new-account state gas, reservoir first. When
    // it does not fit the stock path makes the out-of-gas halt; nothing has
    // been written yet.
    let mut charged_state_gas = 0;
    if host.version().feature(evm2::EvmFeatures::EIP2780) && !shape.value.is_zero() && recipient_empty {
        let charge = host.version().gas_params.new_account_state_gas();
        if tx_gas.spend_state(charge).is_err() {
            return delegate();
        }
        charged_state_gas = charge;
    }
    if !host.state_mut().transfer(&caller, &to, &shape.value)? {
        // Unreachable: the balance was checked above.
        return delegate();
    }
    // EIP-7708: the transfer's log, as `execute_call_message` emits it.
    if host.version().feature(evm2::EvmFeatures::EIP7708)
        && host.logs_observed()
        && let Some(log) = crate::direct_transfer::eip7708_transfer_log(caller, to, shape.value)
    {
        host.log(log);
    }
    // What `execute_call_message` returns for an account without code: the
    // frame starts with what the runtime phase left.
    let mut result = MessageResultExt {
        stop: InstrStop::Stop,
        gas: GasTracker::new_with_execution_gas_and_reservoir(tx_gas.remaining(), tx_gas.reservoir()),
        ..MessageResultExt::default()
    };
    ethereum::settle_initial_frame_gas(&mut tx_gas, &mut result, charged_state_gas);
    let settled = <DefaultTxHandlerHooks as TxHandlerHooks<T>>::settle_transaction(
        host,
        envelope,
        GasSettlement {
            caller,
            gas_price: shape.gas_price,
            gas_limit: shape.gas_limit,
            floor_gas,
            initial_state_gas: 0,
            state_refund: 0,
            result,
        },
    )?;
    HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(Some(settled))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n42_evm::N42EvmConfig;
    use alloy_consensus::{Signed, TxEip1559, TxEip2930, TxLegacy};
    use alloy_eips::eip2930::{AccessList, AccessListItem};
    use alloy_primitives::{Signature, B256};
    use evm2::{
        bytecode::Bytecode,
        evm::{AccountInfo, CacheDB, EmptyDB},
    };
    use n42_tx_types::N42TxEnvelope;
    use reth_evm::ConfigureEvm as _;
    use reth_primitives_traits::Recovered;
    use std::sync::Arc;

    type Config = N42EvmConfig<n42_header::N42ChainSpec>;

    const FUND: u64 = 1_000_000_000_000_000_000;
    const BENEFICIARY: u64 = 0xbe;
    const CONTRACT: u64 = 0xc0de;
    const FRESH: u64 = 0xf00d;

    fn addr(i: u64) -> Address {
        Address::left_padding_from(&(0x1_0000 + i).to_be_bytes())
    }

    fn config(osaka: bool) -> Config {
        let builder = reth_chainspec::ChainSpecBuilder::mainnet().prague_activated();
        let spec = if osaka { builder.osaka_activated() } else { builder }.build();
        N42EvmConfig::new(Arc::new(n42_header::N42ChainSpec::from(spec)))
    }

    fn parent() -> CacheDB<EmptyDB> {
        let mut db = CacheDB::new(EmptyDB::default());
        for i in 1..=8 {
            db.insert_account_info(&addr(i), AccountInfo { balance: U256::from(FUND), ..Default::default() });
        }
        db.insert_account_info(&alt_sender(), AccountInfo { balance: U256::from(FUND), ..Default::default() });
        // A poor sender: the fee, not the value.
        db.insert_account_info(&addr(9), AccountInfo { balance: U256::from(21_000u64 * 100), ..Default::default() });
        db.insert_account_info(&addr(BENEFICIARY), AccountInfo { balance: U256::from(1u64), ..Default::default() });
        // PUSH1 0 PUSH1 0 SSTORE STOP: writes storage when called.
        let code = Bytecode::new_raw(Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0x55, 0x00]));
        db.insert_account_info(&addr(CONTRACT), AccountInfo::default().with_code(code));
        db
    }

    fn env(config: &Config) -> reth_evm::EvmEnvFor<Config> {
        let header = n42_header::N42Header::from(alloy_consensus::Header {
            number: 5,
            timestamp: 1_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(7),
            beneficiary: addr(BENEFICIARY),
            excess_blob_gas: Some(0),
            blob_gas_used: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            ..Default::default()
        });
        config.evm_env(&header).expect("env")
    }

    fn signed<T: Into<reth_ethereum_primitives::TransactionSigned>>(tx: T, from: Address) -> Recovered<N42TxEnvelope> {
        Recovered::new_unchecked(N42TxEnvelope::from(tx.into()), from)
    }

    fn eip1559(from: u64, nonce: u64, to: Address, value: u64, gas_limit: u64, input: Bytes) -> Recovered<N42TxEnvelope> {
        let tx = TxEip1559 {
            chain_id: 1,
            nonce,
            gas_limit,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 3,
            to: TxKind::Call(to),
            value: U256::from(value),
            input,
            ..Default::default()
        };
        signed(Signed::new_unchecked(tx, Signature::test_signature(), B256::with_last_byte(1)), addr(from))
    }

    fn transfer(from: u64, to: Address, value: u64) -> Recovered<N42TxEnvelope> {
        eip1559(from, 0, to, value, 21_000, Bytes::new())
    }

    fn legacy(from: u64, to: Address, value: u64) -> Recovered<N42TxEnvelope> {
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 0,
            gas_price: 50,
            gas_limit: 21_000,
            to: TxKind::Call(to),
            value: U256::from(value),
            input: Bytes::new(),
        };
        signed(Signed::new_unchecked(tx, Signature::test_signature(), B256::with_last_byte(2)), addr(from))
    }

    fn eip2930(from: u64, to: Address, value: u64, access_list: AccessList) -> Recovered<N42TxEnvelope> {
        let tx = TxEip2930 {
            chain_id: 1,
            nonce: 0,
            gas_price: 50,
            gas_limit: 40_000,
            to: TxKind::Call(to),
            value: U256::from(value),
            access_list,
            input: Bytes::new(),
        };
        signed(Signed::new_unchecked(tx, Signature::test_signature(), B256::with_last_byte(3)), addr(from))
    }

    fn alt_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x50; 32])
    }

    fn alt_transfer() -> Recovered<N42TxEnvelope> {
        let key = alt_key();
        let tx = n42_tx_types::TxAltSig {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 3,
            max_fee_per_gas: 100,
            gas_limit: 21_000,
            to: addr(3),
            value: U256::from(5u64),
            input: Bytes::new(),
            access_list: Default::default(),
            alg_type: n42_tx_types::ALG_ED25519,
            pubkey: Bytes::copy_from_slice(key.verifying_key().as_bytes()),
        }
        .sign_ed25519(&key);
        let sender = tx.sender();
        Recovered::new_unchecked(N42TxEnvelope::AltSig(tx), sender)
    }

    fn alt_sender() -> Address {
        alt_transfer().signer()
    }

    /// The transaction's outcome on one EVM over [`parent`]: the result (or
    /// the error) and the change stream, each account's changes in address
    /// order, as text.
    fn outcome(config: &Config, fast: bool, tx: &Recovered<N42TxEnvelope>) -> (String, Vec<String>) {
        let make = || config.evm_with_env(parent(), env(config));
        let mut evm = if fast { as_batch(make) } else { make() };
        let tx = tx.clone().map(TxEnvelope::from);
        match reth_evm::Evm::transact(&mut evm, &tx) {
            Ok(out) => {
                let mut changes: Vec<String> = out.pending_state.account_changes().map(|c| format!("{c:?}")).collect();
                changes.sort();
                (format!("{:?}", out.result), changes)
            }
            Err(err) => (format!("error: {err}"), Vec::new()),
        }
    }

    /// Each transaction on the stock handler and on the fast one, on Prague
    /// and on Osaka: the same result (gas, refund, status, output) and the
    /// same change stream (balances, nonces, touched and created accounts);
    /// `fast` says whether the handler took it rather than handing it on.
    fn check(cases: &[(&str, Recovered<N42TxEnvelope>, bool)]) {
        for osaka in [false, true] {
            let config = config(osaka);
            for (name, tx, fast) in cases {
                let stock = outcome(&config, false, tx);
                let before = hits();
                let ours = outcome(&config, true, tx);
                assert_eq!(ours, stock, "{name} (osaka {osaka})");
                // Process-wide, and tests run beside each other: a hit is
                // proved by the counter moving, a hand-on only loosely.
                if *fast {
                    assert!(hits() > before, "{name} (osaka {osaka}) did not take the fast path");
                }
            }
        }
    }

    #[test]
    fn qualifying_transfers_equal_the_stock_handler() {
        check(&[
            ("1559 to an existing account", transfer(1, addr(2), 100), true),
            ("1559 creating its recipient", transfer(1, addr(FRESH), 100), true),
            ("1559 over the intrinsic gas", eip1559(1, 0, addr(2), 100, 30_000, Bytes::new()), true),
            ("legacy", legacy(2, addr(3), 7), true),
            ("2930 with an empty access list", eip2930(3, addr(4), 9, AccessList::default()), true),
            ("0x50 as 1559", alt_transfer(), true),
            ("zero value to an existing account", transfer(4, addr(5), 0), true),
        ]);
    }

    #[test]
    fn everything_else_is_handed_to_the_stock_handler_unchanged() {
        let access_list = AccessList(vec![AccessListItem { address: addr(6), storage_keys: vec![B256::ZERO] }]);
        check(&[
            ("zero value to an empty account", transfer(1, addr(FRESH), 0), false),
            ("to a contract", eip1559(1, 0, addr(CONTRACT), 1, 100_000, Bytes::new()), false),
            ("to a precompile", eip1559(1, 0, Address::with_last_byte(4), 1, 30_000, Bytes::new()), false),
            ("to itself", transfer(2, addr(2), 5), false),
            ("to the beneficiary", transfer(3, addr(BENEFICIARY), 5), false),
            ("with input", eip1559(4, 0, addr(5), 1, 30_000, Bytes::from_static(&[1, 2])), false),
            ("2930 with an access list", eip2930(5, addr(6), 1, access_list), false),
            ("value the sender lacks after the fee", transfer(9, addr(2), 1), false),
            ("a nonce ahead", eip1559(6, 3, addr(2), 1, 21_000, Bytes::new()), false),
            ("an intrinsic gas too low", eip1559(7, 0, addr(2), 1, 20_000, Bytes::new()), false),
        ]);
    }

    #[test]
    fn the_handler_covers_prague_osaka_and_amsterdam() {
        assert!(covers(SpecId::PRAGUE));
        assert!(covers(SpecId::OSAKA));
        assert!(covers(SpecId::AMSTERDAM), "gov5's Amsterdam execution on a native chain (stream H)");
        assert!(!covers(SpecId::CANCUN));
        let mut partial = evm2::Version::new(SpecId::AMSTERDAM);
        assert!(amsterdam_features_consistent(&partial));
        partial.features.remove(evm2::EvmFeatures::EIP7708);
        assert!(!amsterdam_features_consistent(&partial), "only some of the Amsterdam transfer rules");
        assert!(amsterdam_features_consistent(&evm2::Version::new(SpecId::OSAKA)));
    }

    /// A native chain (HotStuff, chain id 1) past `glamsterdamTime`: evm2's
    /// Amsterdam, as gov5 runs it (`docs/AMSTERDAM_PARALLEL_STEP.md`).
    fn amsterdam() -> Config {
        let json = r#"{"config":{"chainId":1,"homesteadBlock":0,"eip150Block":0,"eip155Block":0,"eip158Block":0,"byzantiumBlock":0,"constantinopleBlock":0,"petersburgBlock":0,"istanbulBlock":0,"berlinBlock":0,"londonBlock":0,"mergeNetsplitBlock":0,"terminalTotalDifficulty":0,"terminalTotalDifficultyPassed":true,"shanghaiTime":0,"cancunTime":0,"pragueTime":0,"osakaTime":0,"consensus":"hotstuff","glamsterdamTime":0},"alloc":{}}"#;
        let genesis: alloy_genesis::Genesis = serde_json::from_str(json).expect("genesis");
        N42EvmConfig::new(Arc::new(n42_header::N42ChainSpec::from(reth_chainspec::ChainSpec::from_genesis(genesis))))
    }

    /// [`check`] on Amsterdam: the stock Amsterdam handler (EIP-2780,
    /// EIP-8037, EIP-7708) against the fast one, result (gas, state gas,
    /// logs) and change stream.
    fn check_amsterdam(cases: &[(&str, Recovered<N42TxEnvelope>, bool)]) {
        let config = amsterdam();
        assert_eq!(env(&config).spec, SpecId::AMSTERDAM);
        for (name, tx, fast) in cases {
            let stock = outcome(&config, false, tx);
            let before = hits();
            let ours = outcome(&config, true, tx);
            assert_eq!(ours, stock, "{name} (amsterdam)");
            if *fast {
                assert!(hits() > before, "{name} (amsterdam) did not take the fast path");
            }
        }
    }

    #[test]
    fn qualifying_transfers_equal_the_stock_amsterdam_handler() {
        let creating = eip1559(1, 0, addr(FRESH), 100, 210_000, Bytes::new());
        check_amsterdam(&[
            ("1559 to an existing account", transfer(1, addr(2), 100), true),
            ("1559 creating its recipient (EIP-8037)", creating.clone(), true),
            ("1559 creating its recipient, the charge to the gas limit", eip1559(1, 0, addr(FRESH), 100, 204_600, Bytes::new()), true),
            ("1559 over the intrinsic gas", eip1559(1, 0, addr(2), 100, 30_000, Bytes::new()), true),
            ("legacy", legacy(2, addr(3), 7), true),
            ("2930 with an empty access list", eip2930(3, addr(4), 9, AccessList::default()), true),
            ("0x50 as 1559", alt_transfer(), true),
            ("zero value to an existing account (15,000)", transfer(4, addr(5), 0), true),
            ("zero value at its 15,000 intrinsic", eip1559(4, 0, addr(5), 0, 15_000, Bytes::new()), true),
        ]);
        // The stock outcome carries what Prague's does not.
        let (result, _) = outcome(&amsterdam(), false, &creating);
        assert!(result.contains("state_gas_spent: 183600") && result.contains("total_gas_spent: 204600"), "{result}");
        assert!(result.contains("ddf252ad"), "the EIP-7708 log: {result}");
    }

    #[test]
    fn everything_else_is_handed_to_the_stock_amsterdam_handler_unchanged() {
        let access_list = AccessList(vec![AccessListItem { address: addr(6), storage_keys: vec![B256::ZERO] }]);
        check_amsterdam(&[
            ("creating its recipient at 21,000 (a runtime out-of-gas halt)", transfer(1, addr(FRESH), 100), false),
            ("creating its recipient one gas short", eip1559(1, 0, addr(FRESH), 100, 204_599, Bytes::new()), false),
            ("zero value to an empty account", transfer(1, addr(FRESH), 0), false),
            ("to a contract", eip1559(1, 0, addr(CONTRACT), 1, 200_000, Bytes::new()), false),
            ("to a precompile", eip1559(1, 0, Address::with_last_byte(4), 1, 30_000, Bytes::new()), false),
            ("to itself", transfer(2, addr(2), 5), false),
            ("to the beneficiary", transfer(3, addr(BENEFICIARY), 5), false),
            ("with input", eip1559(4, 0, addr(5), 1, 30_000, Bytes::from_static(&[1, 2])), false),
            ("2930 with an access list", eip2930(5, addr(6), 1, access_list), false),
            ("value the sender lacks after the fee", transfer(9, addr(2), 1), false),
            ("a nonce ahead", eip1559(6, 3, addr(2), 1, 21_000, Bytes::new()), false),
            ("an intrinsic gas too low", eip1559(7, 0, addr(2), 1, 20_000, Bytes::new()), false),
            ("zero value under its intrinsic", eip1559(7, 0, addr(2), 0, 14_999, Bytes::new()), false),
        ]);
    }
}
