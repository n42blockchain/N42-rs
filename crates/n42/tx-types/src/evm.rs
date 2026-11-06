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
}
