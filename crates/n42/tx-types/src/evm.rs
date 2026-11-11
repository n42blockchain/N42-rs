// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The EVM's view of the envelope.
//!
//! A 0x50 transaction executes as an EIP-1559 call from the address its key
//! derives: evm2's [`TxEnvelope::Eip1559`] (type byte 2), the caller already
//! authenticated. Nothing in execution knows which algorithm signed it.
//!
//! reth v2.9.0 (evm2) converts a recovered transaction into the EVM's
//! transaction through `reth_evm::execute::FromRecoveredTx`, which is
//! implemented for every `T` with `TxEnvelope: From<T>`. The `From` impls
//! below are therefore the whole mapping: no tx-registry entry is needed,
//! because the 0x50 transaction is an EIP-1559 transaction to the EVM.

use crate::{alt_sig::AltSigTx, envelope::N42TxEnvelope};
use alloy_consensus::TxEip1559;
use alloy_primitives::TxKind;
use evm2::ethereum::TxEnvelope;

/// The EIP-1559 transaction evm2 executes for a 0x50 transaction.
fn alt_sig_as_eip1559(tx: AltSigTx) -> TxEip1559 {
    let inner = tx.into_tx();
    TxEip1559 {
        chain_id: inner.chain_id,
        nonce: inner.nonce,
        gas_limit: inner.gas_limit,
        max_fee_per_gas: inner.max_fee_per_gas,
        max_priority_fee_per_gas: inner.max_priority_fee_per_gas,
        to: TxKind::Call(inner.to),
        value: inner.value,
        access_list: inner.access_list,
        input: inner.input,
    }
}

/// The EIP-1559 transaction evm2 executes for a 0x50 transaction, from a
/// reference (the access list and input cloned).
fn alt_sig_ref_as_eip1559(inner: &crate::alt_sig::TxAltSig) -> TxEip1559 {
    TxEip1559 {
        chain_id: inner.chain_id,
        nonce: inner.nonce,
        gas_limit: inner.gas_limit,
        max_fee_per_gas: inner.max_fee_per_gas,
        max_priority_fee_per_gas: inner.max_priority_fee_per_gas,
        to: TxKind::Call(inner.to),
        value: inner.value,
        access_list: inner.access_list.clone(),
        input: inner.input.clone(),
    }
}

/// The EVM's transaction for `tx`, made from a reference:
/// `TxEnvelope::from(tx.clone())` without cloning the signature and the
/// hash only to drop them. The parallel build converts every candidate on
/// its batches' threads (200,000 a block), so the copy is per transaction
/// on the execution's critical path.
pub fn evm_tx_of(tx: &N42TxEnvelope) -> TxEnvelope {
    use alloy_consensus::EthereumTxEnvelope;
    match tx {
        N42TxEnvelope::Eth(EthereumTxEnvelope::Legacy(tx)) => TxEnvelope::Legacy(tx.tx().clone()),
        N42TxEnvelope::Eth(EthereumTxEnvelope::Eip2930(tx)) => TxEnvelope::Eip2930(tx.tx().clone()),
        N42TxEnvelope::Eth(EthereumTxEnvelope::Eip1559(tx)) => TxEnvelope::Eip1559(tx.tx().clone()),
        // Blob and set-code transactions through the stock conversion.
        N42TxEnvelope::Eth(tx) => tx.clone().into(),
        N42TxEnvelope::AltSig(tx) => TxEnvelope::Eip1559(alt_sig_ref_as_eip1559(tx.tx())),
    }
}

impl From<AltSigTx> for TxEnvelope {
    fn from(tx: AltSigTx) -> Self {
        Self::Eip1559(alt_sig_as_eip1559(tx))
    }
}

impl From<N42TxEnvelope> for TxEnvelope {
    fn from(tx: N42TxEnvelope) -> Self {
        match tx {
            N42TxEnvelope::Eth(tx) => tx.into(),
            N42TxEnvelope::AltSig(tx) => tx.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alt_sig::TxAltSig;
    use alloy_primitives::{Address, Bytes, U256};

    #[test]
    fn a_0x50_transaction_executes_as_its_eip1559_fields() {
        let inner = TxAltSig {
            chain_id: 94,
            nonce: 7,
            max_priority_fee_per_gas: 2,
            max_fee_per_gas: 30,
            gas_limit: 21_000,
            to: Address::with_last_byte(9),
            value: U256::from(5),
            input: Bytes::from_static(&[1, 2]),
            ..Default::default()
        };
        let tx = AltSigTx::new(inner.clone(), Bytes::new());
        let TxEnvelope::Eip1559(got) = TxEnvelope::from(N42TxEnvelope::AltSig(tx)) else {
            panic!("a 0x50 transaction executes as EIP-1559")
        };
        assert_eq!(got.chain_id, 94);
        assert_eq!(got.nonce, 7);
        assert_eq!(got.max_priority_fee_per_gas, 2);
        assert_eq!(got.max_fee_per_gas, 30);
        assert_eq!(got.gas_limit, 21_000);
        assert_eq!(got.to, TxKind::Call(Address::with_last_byte(9)));
        assert_eq!(got.value, U256::from(5));
        assert_eq!(got.input, inner.input);
    }

    #[test]
    fn the_reference_conversion_equals_the_owned_one() {
        use alloy_consensus::{Signed, TxEip1559, TxEip2930, TxLegacy};
        use alloy_primitives::{Signature, B256};
        let to = TxKind::Call(Address::with_last_byte(3));
        let input = Bytes::from_static(&[7, 8, 9]);
        let sig = Signature::test_signature();
        let eth = |tx: reth_ethereum_primitives::TransactionSigned| N42TxEnvelope::Eth(tx);
        let txs = vec![
            eth(Signed::new_unchecked(
                TxLegacy { chain_id: Some(94), nonce: 1, gas_price: 9, gas_limit: 21_000, to, value: U256::from(4), input: input.clone() },
                sig,
                B256::with_last_byte(1),
            )
            .into()),
            eth(Signed::new_unchecked(
                TxEip2930 { chain_id: 94, nonce: 2, gas_price: 9, gas_limit: 30_000, to, value: U256::from(5), input: input.clone(), ..Default::default() },
                sig,
                B256::with_last_byte(2),
            )
            .into()),
            eth(Signed::new_unchecked(
                TxEip1559 {
                    chain_id: 94,
                    nonce: 3,
                    gas_limit: 21_000,
                    max_fee_per_gas: 30,
                    max_priority_fee_per_gas: 2,
                    to,
                    value: U256::from(6),
                    input: input.clone(),
                    ..Default::default()
                },
                sig,
                B256::with_last_byte(3),
            )
            .into()),
            N42TxEnvelope::AltSig(AltSigTx::new(
                TxAltSig {
                    chain_id: 94,
                    nonce: 4,
                    max_priority_fee_per_gas: 2,
                    max_fee_per_gas: 30,
                    gas_limit: 21_000,
                    to: Address::with_last_byte(9),
                    value: U256::from(7),
                    input,
                    ..Default::default()
                },
                Bytes::from_static(&[1; 64]),
            )),
        ];
        for tx in txs {
            assert_eq!(evm_tx_of(&tx), TxEnvelope::from(tx.clone()));
        }
    }
}
