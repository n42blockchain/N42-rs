// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The plain value transfer applied straight to a batch's accounts (F5g10).
//!
//! [`crate::fast_handler`] still runs a transfer through evm2's `transact`:
//! the registry dispatch, the stock `prepare`, the journal, the pending
//! state and its change stream, and the batch's commit of that stream. On
//! the bench that machinery is about 1.1 us of a transfer's CPU. A batch
//! whose transactions are plain transfers does not need any of it: the
//! transfer is three account updates (the sender debited the value and the
//! fee and its nonce bumped, the recipient credited, the beneficiary paid
//! the tip) and a fixed result.
//!
//! [`DirectTransfers::apply`] does exactly that against the batch's own read
//! layer ([`Layered`]: the accounts the batch has read or written, over the
//! parent's state) and records the three accounts in the batch state, for a
//! transaction that qualifies by the rules the handler uses plus every check
//! the stock `prepare` would make: chain id, fee caps against the base fee,
//! gas limit against the block's and the transaction cap, the sender without
//! code, its nonce, and its balance against the gas limit at the fee cap
//! plus the value. Anything else is [`Step::Fallback`]: nothing has been
//! written and the batch hands the transaction to evm2. A batch's EVM reads
//! through the same [`Layered`] view, so the transfers applied before it was
//! made are what it sees.
//!
//! On Amsterdam (gov5's Amsterdam execution on a native chain) it applies
//! EIP-2780's intrinsic (21,000 with a value, 15,000 without), EIP-8037's
//! new-account state gas for a value to an empty recipient (183,600, paid
//! only when the gas limit covers it; otherwise evm2 makes the halt) and
//! EIP-7708's transfer log (`docs/AMSTERDAM_PARALLEL_STEP.md` 3.3).
//!
//! What it does not model, so falls back on: a version with only some of
//! EIP-2780, EIP-8037 and EIP-7708, any environment whose checks are not the stock ones, a zero
//! value to an empty or missing recipient or a zero tip to an empty or
//! missing beneficiary (EIP-161 touches), a recipient with code (including an EIP-7702 delegation), a sender with
//! code, the precompile range, and a sender, recipient and beneficiary that
//! are not three accounts.
//!
//! `N42_BATCH_DIRECT_TRANSFER` (default on; `0` turns it off, the batches
//! then run every transaction through evm2 with the handler as before).

use alloy_primitives::{map::AddressMap, Address, Bytes, TxKind, U256};
use evm2::{
    ethereum::{self, TxEnvelope},
    evm::{AccountInfo, Database},
    EvmFeatures, SpecId, Version,
};
use reth_primitives_traits::Recovered;

use crate::batch_state::BatchState;

/// The gas a plain transfer uses.
pub const TRANSFER_GAS: u64 = 21_000;

static HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static DELEGATED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Transfers applied directly, since start.
pub fn hits() -> u64 {
    HITS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Transactions a batch offered the direct path ran on evm2 instead, since
/// start.
pub fn delegated() -> u64 {
    DELEGATED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Counts `hits` direct transfers and `delegated` transactions run on evm2.
pub fn count(hits: u64, delegated: u64) {
    if hits > 0 {
        HITS.fetch_add(hits, std::sync::atomic::Ordering::Relaxed);
    }
    if delegated > 0 {
        DELEGATED.fetch_add(delegated, std::sync::atomic::Ordering::Relaxed);
    }
}

/// `N42_BATCH_DIRECT_TRANSFER` (default on).
pub fn enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_BATCH_DIRECT_TRANSFER", true))
}

/// What the direct path reads of a transaction: a call with no input and no
/// access list, with its fee fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxShape {
    /// The sender.
    pub caller: Address,
    /// The recipient.
    pub to: Address,
    /// The value.
    pub value: U256,
    /// The nonce.
    pub nonce: u64,
    /// The gas limit.
    pub gas_limit: u64,
    /// The fee cap: the gas price of a legacy or 2930 transaction, the
    /// maximum fee of a 1559 one.
    pub max_fee: U256,
    /// The 1559 priority fee; `None` for a transaction with a gas price.
    pub priority: Option<U256>,
    /// The chain id; `None` for a pre-155 legacy transaction.
    pub chain_id: Option<u64>,
}

/// The shape of a transfer in evm2's Ethereum envelope (a 0x50 transaction
/// arrives as 1559); `None` for anything that is not a call with no input
/// and no access list.
pub fn shape_of(tx: &Recovered<TxEnvelope>) -> Option<TxShape> {
    let caller = tx.signer();
    let call = |to: TxKind, input: &Bytes| match to {
        TxKind::Call(to) if input.is_empty() => Some(to),
        _ => None,
    };
    match tx.inner() {
        TxEnvelope::Legacy(tx) => Some(TxShape {
            caller,
            to: call(tx.to, &tx.input)?,
            value: tx.value,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            max_fee: U256::from(tx.gas_price),
            priority: None,
            chain_id: tx.chain_id,
        }),
        TxEnvelope::Eip2930(tx) if tx.access_list.is_empty() => Some(TxShape {
            caller,
            to: call(tx.to, &tx.input)?,
            value: tx.value,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            max_fee: U256::from(tx.gas_price),
            priority: None,
            chain_id: Some(tx.chain_id),
        }),
        TxEnvelope::Eip1559(tx) if tx.access_list.is_empty() => Some(TxShape {
            caller,
            to: call(tx.to, &tx.input)?,
            value: tx.value,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            max_fee: U256::from(tx.max_fee_per_gas),
            priority: Some(U256::from(tx.max_priority_fee_per_gas)),
            chain_id: Some(tx.chain_id),
        }),
        _ => None,
    }
}

/// A batch's read layer: the accounts the batch has read or written, over
/// the parent's state. The direct path reads and writes the accounts; the
/// batch's EVM, when one is made, reads through it, so it sees every
/// transfer applied before it.
#[derive(Debug)]
pub struct Layered<D> {
    accounts: AddressMap<Option<AccountInfo>>,
    inner: D,
}

impl<D: Database> Layered<D> {
    /// `inner` with nothing read yet; room for `accounts` without regrowing.
    pub fn new(inner: D, accounts: usize) -> Self {
        Self { accounts: AddressMap::with_capacity_and_hasher(accounts, Default::default()), inner }
    }

    fn account(&mut self, address: &Address) -> Result<Option<AccountInfo>, D::Error> {
        // One probe of the map, hit or miss (a recipient is nearly always a
        // miss on a block of transfers); nothing kept on a read error.
        match self.accounts.entry(*address) {
            alloy_primitives::map::Entry::Occupied(entry) => Ok(entry.get().clone()),
            alloy_primitives::map::Entry::Vacant(entry) => {
                let account = self.inner.get_account(address)?;
                entry.insert(account.clone());
                Ok(account)
            }
        }
    }
}

impl<D: Database> Database for Layered<D> {
    type Error = D::Error;

    fn is_fatal(error: &Self::Error) -> bool {
        D::is_fatal(error)
    }

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.accounts.get(address) {
            Some(account) => Ok(account.clone()),
            None => self.inner.get_account(address),
        }
    }

    fn get_code_by_hash(&mut self, code_hash: &alloy_primitives::B256) -> Result<evm2::bytecode::Bytecode, Self::Error> {
        self.inner.get_code_by_hash(code_hash)
    }

    fn get_storage(&mut self, address: &Address, index: &U256) -> Result<U256, Self::Error> {
        self.inner.get_storage(address, index)
    }

    fn get_block_hash(&mut self, number: &U256) -> Result<alloy_primitives::B256, Self::Error> {
        self.inner.get_block_hash(number)
    }
}

/// What [`DirectTransfers::apply`] did with a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Applied: the accounts and the batch state hold the transfer, which
    /// paid `state_gas` (EIP-8037; 0 off Amsterdam). Its result is
    /// [`DirectTransfers::result_for`].
    Applied {
        /// The EIP-8037 state gas the transfer paid.
        state_gas: u64,
    },
    /// Qualified, but the admission check (the deferred-execution ledger)
    /// refused it; nothing written.
    Refused,
    /// Not a transfer this path applies; nothing written, evm2 runs it.
    Fallback,
}

/// The direct path for one block's batches: the block's values the checks
/// read, and how to see a transaction's shape.
pub struct DirectTransfers<X> {
    shape: fn(&Recovered<X>) -> Option<TxShape>,
    beneficiary: Address,
    basefee: U256,
    block_gas_limit: U256,
    chain_id: u64,
    tx_gas_cap: u64,
    floor_gas: u64,
    /// The intrinsic and floor of a transfer without a value (EIP-2780:
    /// 15,000 on Amsterdam; the same as with one before).
    zero_value_gas: (u64, u64),
    /// EIP-8037's new-account charge; 0 without EIP-8037.
    new_account_state_gas: u64,
    /// Whether a transfer's result carries its EIP-7708 log.
    transfer_logs: bool,
}

impl<X> std::fmt::Debug for DirectTransfers<X> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectTransfers")
            .field("beneficiary", &self.beneficiary)
            .field("basefee", &self.basefee)
            .field("block_gas_limit", &self.block_gas_limit)
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

/// The features the direct path's checks reproduce: every one must be on.
const STOCK_CHECKS: [EvmFeatures; 8] = [
    EvmFeatures::TX_CHAIN_ID_CHECK,
    EvmFeatures::NONCE_CHECK,
    EvmFeatures::BALANCE_CHECK,
    EvmFeatures::BLOCK_GAS_LIMIT_CHECK,
    EvmFeatures::EIP3607,
    EvmFeatures::PRIORITY_FEE_CHECK,
    EvmFeatures::BASE_FEE_CHECK,
    EvmFeatures::FEE_CHARGE,
];
const STOCK_CHECK_NAMES: [&str; 8] = [
    "TX_CHAIN_ID_CHECK",
    "NONCE_CHECK",
    "BALANCE_CHECK",
    "BLOCK_GAS_LIMIT_CHECK",
    "EIP3607",
    "PRIORITY_FEE_CHECK",
    "BASE_FEE_CHECK",
    "FEE_CHARGE",
];

impl<X> DirectTransfers<X> {
    /// The path for a block on `spec` with `version` (the environment's
    /// runtime configuration), crediting `beneficiary`, or `None` when the
    /// block is not one it models: a spec [`crate::fast_handler::covers`]
    /// does not, a check switched off, only some of Amsterdam's transfer
    /// rules, or a transfer with a value whose intrinsic gas is not 21,000.
    pub fn new(
        spec: SpecId,
        version: &Version,
        beneficiary: Address,
        basefee: U256,
        block_gas_limit: U256,
        shape: fn(&Recovered<X>) -> Option<TxShape>,
    ) -> Option<Self> {
        if let Some(why) = refusal(spec, version) {
            tracing::debug!(target: "n42::parallel_build", why, "no direct transfer path for this block");
            return None;
        }
        let (_, floor_gas) = transfer_gas(version);
        let (tx_gas_cap, _) = version.tx_gas_caps();
        let zero_value_gas = transfer_gas_of(version, U256::ZERO);
        let new_account_state_gas =
            if version.feature(EvmFeatures::EIP8037) { version.gas_params.new_account_state_gas() } else { 0 };
        let transfer_logs = version.feature(EvmFeatures::EIP7708) && version.feature(EvmFeatures::LOG_COLLECTION);
        Some(Self {
            shape,
            beneficiary,
            basefee,
            block_gas_limit,
            chain_id: version.chain_id,
            tx_gas_cap,
            floor_gas,
            zero_value_gas,
            new_account_state_gas,
            transfer_logs,
        })
    }

    /// [`Self::new`] over a reth environment, and only with
    /// `N42_BATCH_DIRECT_TRANSFER` on.
    pub fn for_env<T>(env: &reth_evm_ethereum::EthEvmEnv<T>, shape: fn(&Recovered<X>) -> Option<TxShape>) -> Option<Self>
    where
        T: evm2::EvmTypesHost,
    {
        if !enabled() {
            return None;
        }
        Self::of_env(env, shape)
    }

    /// [`Self::for_env`] whatever the knob says (the tests and the bench).
    pub fn of_env<T>(env: &reth_evm_ethereum::EthEvmEnv<T>, shape: fn(&Recovered<X>) -> Option<TxShape>) -> Option<Self>
    where
        T: evm2::EvmTypesHost,
    {
        Self::new(env.spec.into(), &env.version, env.block.beneficiary, env.block.basefee, env.block.gas_limit, shape)
    }

    /// The transaction's shape, when it has one.
    pub fn shape(&self, tx: &Recovered<X>) -> Option<TxShape> {
        (self.shape)(tx)
    }

    /// The result evm2 gives a plain transfer with a value: success, 21,000
    /// gas spent, no refund, the floor, a stop, nothing else (off Amsterdam;
    /// [`Self::result_for`] in general).
    pub fn result<E: Default>(&self) -> evm2::TxResultExt<E> {
        evm2::TxResultExt::<E> {
            status: true,
            total_gas_spent: TRANSFER_GAS,
            floor_gas: self.floor_gas,
            stop: evm2::interpreter::InstrStop::Stop,
            ..Default::default()
        }
    }

    /// The intrinsic and floor gas of a transfer of `value`.
    fn gas_of(&self, value: U256) -> (u64, u64) {
        if value.is_zero() {
            self.zero_value_gas
        } else {
            (TRANSFER_GAS, self.floor_gas)
        }
    }

    /// The result evm2 gives `tx` applied with `state_gas` (its
    /// [`Step::Applied`]): success, the intrinsic of its value plus the
    /// state gas spent, no refund, the floor, a stop, and on Amsterdam its
    /// EIP-7708 log. Off Amsterdam a transfer with a value gets
    /// [`Self::result`].
    pub fn result_for<E: Default>(&self, tx: &TxShape, state_gas: u64) -> evm2::TxResultExt<E> {
        let (intrinsic, floor_gas) = self.gas_of(tx.value);
        let logs = if self.transfer_logs { eip7708_transfer_log(tx.caller, tx.to, tx.value).into_iter().collect() } else { Vec::new() };
        evm2::TxResultExt::<E> {
            status: true,
            total_gas_spent: intrinsic + state_gas,
            state_gas_spent: state_gas,
            floor_gas,
            stop: evm2::interpreter::InstrStop::Stop,
            logs,
            ..Default::default()
        }
    }

    /// Applies `tx` to `layer` and records it in `state` when it qualifies
    /// and `admit` (given the sender's balance before it) lets it in; see
    /// [`Step`]. A read error is a fallback: evm2 reads again and reports it.
    pub fn apply<D: Database>(
        &self,
        tx: &TxShape,
        layer: &mut Layered<D>,
        state: &mut BatchState,
        admit: impl FnOnce(U256) -> bool,
    ) -> Step {
        self.try_apply(tx, layer, state, admit).unwrap_or(Step::Fallback)
    }

    fn try_apply<D: Database>(
        &self,
        tx: &TxShape,
        layer: &mut Layered<D>,
        state: &mut BatchState,
        admit: impl FnOnce(U256) -> bool,
    ) -> Option<Step> {
        let (caller, to, beneficiary) = (tx.caller, tx.to, self.beneficiary);
        if to == caller || to == beneficiary || caller == beneficiary || in_precompile_range(&to) {
            return Some(Step::Fallback);
        }
        if tx.chain_id != Some(self.chain_id) {
            return Some(Step::Fallback);
        }
        // The fee checks of the stock `prepare`, and the price it settles at.
        let price = match tx.priority {
            Some(priority) => {
                if priority > tx.max_fee {
                    return Some(Step::Fallback);
                }
                tx.max_fee.min(self.basefee.saturating_add(priority))
            }
            None => tx.max_fee,
        };
        if price < self.basefee {
            return Some(Step::Fallback);
        }
        let tip = price - self.basefee;
        let (intrinsic, floor_gas) = self.gas_of(tx.value);
        if tx.gas_limit < intrinsic || tx.gas_limit > self.tx_gas_cap || U256::from(tx.gas_limit) > self.block_gas_limit {
            return Some(Step::Fallback);
        }
        let max_upfront = U256::from(tx.gas_limit).checked_mul(tx.max_fee)?.checked_add(tx.value)?;
        let sender = layer.account(&caller).ok()??;
        if !sender.is_empty_code_hash() || sender.nonce != tx.nonce || tx.nonce == u64::MAX || sender.balance < max_upfront {
            return Some(Step::Fallback);
        }
        let recipient = layer.account(&to).ok()?;
        if recipient.as_ref().is_some_and(|r| !r.is_empty_code_hash()) {
            return Some(Step::Fallback);
        }
        // A zero credit touches its account without changing it: nothing
        // to record when the account exists and is not empty, an EIP-161
        // case (left to evm2) when it is.
        let alive = |account: &Option<AccountInfo>| account.as_ref().is_some_and(|a| !a.is_empty());
        if tx.value.is_zero() && !alive(&recipient) {
            return Some(Step::Fallback);
        }
        // EIP-8037: a value to an empty recipient pays the new-account state
        // gas, from what the gas limit leaves over the intrinsic (reservoir
        // and regular gas together); short of it evm2 makes the halt.
        let state_gas = if self.new_account_state_gas > 0 && !tx.value.is_zero() && !alive(&recipient) {
            if tx.gas_limit - intrinsic < self.new_account_state_gas {
                return Some(Step::Fallback);
            }
            self.new_account_state_gas
        } else {
            0
        };
        let used = (intrinsic + state_gas).max(floor_gas);
        let fee = U256::from(used).checked_mul(price)?;
        let reward = U256::from(used).checked_mul(tip)?;
        let paid = layer.account(&beneficiary).ok()?;
        if reward.is_zero() && !alive(&paid) {
            return Some(Step::Fallback);
        }
        let mut sender_after = sender.clone();
        sender_after.balance = sender.balance - tx.value - fee;
        sender_after.nonce += 1;
        let mut recipient_after = recipient.clone().unwrap_or_default();
        recipient_after.balance = recipient_after.balance.checked_add(tx.value)?;
        let mut paid_after = paid.clone().unwrap_or_default();
        paid_after.balance = paid_after.balance.checked_add(reward)?;
        if !admit(sender.balance) {
            return Some(Step::Refused);
        }
        state.commit_info(caller, Some(&sender), &sender_after);
        layer.accounts.insert(caller, Some(sender_after));
        if !tx.value.is_zero() {
            state.commit_info(to, recipient.as_ref(), &recipient_after);
            layer.accounts.insert(to, Some(recipient_after));
        }
        if !reward.is_zero() {
            state.commit_info(beneficiary, paid.as_ref(), &paid_after);
            layer.accounts.insert(beneficiary, Some(paid_after));
        }
        Some(Step::Applied { state_gas })
    }
}

/// EIP-7708's log for `value` moved from `from` to `to` (evm2's
/// `eip7708_transfer_log`): none for a zero value or a self-transfer.
pub fn eip7708_transfer_log(from: Address, to: Address, value: U256) -> Option<alloy_primitives::Log> {
    if value.is_zero() || from == to {
        return None;
    }
    let topics = vec![
        evm2::constants::EIP7708_TRANSFER_TOPIC,
        alloy_primitives::B256::left_padding_from(from.as_slice()),
        alloy_primitives::B256::left_padding_from(to.as_slice()),
    ];
    Some(alloy_primitives::Log {
        address: evm2::evm::SYSTEM_ADDRESS,
        data: alloy_primitives::LogData::new_unchecked(topics, Bytes::copy_from_slice(&value.to_be_bytes::<32>())),
    })
}

/// The intrinsic and floor gas of a plain transfer with a value on `version`.
fn transfer_gas(version: &Version) -> (u64, u64) {
    transfer_gas_of(version, U256::from(1u64))
}

/// The intrinsic and floor gas of a plain transfer of `value` to another
/// account on `version`.
fn transfer_gas_of(version: &Version, value: U256) -> (u64, u64) {
    ethereum::intrinsic_and_floor_gas(version, Address::ZERO, TxKind::Call(Address::with_last_byte(1)), &Bytes::new(), 0, 0, value)
}

/// Why the direct path does not model a block on `spec` with `version`, or
/// `None` when it does.
pub fn refusal(spec: SpecId, version: &Version) -> Option<&'static str> {
    if !crate::fast_handler::covers(spec) {
        return Some("spec");
    }
    if let Some(i) = STOCK_CHECKS.iter().position(|f| !version.feature(*f)) {
        return Some(STOCK_CHECK_NAMES[i]);
    }
    // Amsterdam's transfer rules are modelled together or not at all.
    if !crate::fast_handler::amsterdam_features_consistent(version) {
        return Some("amsterdam features");
    }
    // BALANCE_TOP_UP acts only without BALANCE_CHECK, which is required.
    let (intrinsic, floor_gas) = transfer_gas(version);
    if intrinsic != TRANSFER_GAS || floor_gas > TRANSFER_GAS {
        return Some("transfer gas");
    }
    let (intrinsic, floor_gas) = transfer_gas_of(version, U256::ZERO);
    if intrinsic > TRANSFER_GAS || floor_gas > intrinsic {
        return Some("transfer gas");
    }
    None
}

/// Whether `address` is at or below 0x1ff: every precompile of Prague and
/// Osaka (0x01-0x11, P256VERIFY at 0x100) is, and a transfer to that range
/// is left to evm2.
fn in_precompile_range(address: &Address) -> bool {
    address.0[..18].iter().all(|b| *b == 0) && address.0[18] <= 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_precompile_range_ends_at_0x1ff() {
        assert!(in_precompile_range(&Address::with_last_byte(1)));
        assert!(in_precompile_range(&Address::with_last_byte(0x11)));
        assert!(in_precompile_range(&Address::left_padding_from(&[0x01, 0x00])));
        assert!(in_precompile_range(&Address::left_padding_from(&[0x01, 0xff])));
        assert!(!in_precompile_range(&Address::left_padding_from(&[0x02, 0x00])));
        assert!(!in_precompile_range(&Address::left_padding_from(&[0x01, 0x00, 0x01])));
    }
}
