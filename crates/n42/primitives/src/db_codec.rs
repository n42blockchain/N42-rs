// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Database `Compress`/`Decompress` impls for the N42 beacon types.
//!
//! These used to live in `reth-db-api`'s `models/` alongside reth's own impls.
//! reth moved `Compress`/`Decompress` out to the separate `reth-codecs` crate,
//! which made both the trait and these types foreign to `reth-db-api` and put
//! the impls squarely on the wrong side of the orphan rule. They belong here
//! anyway: the types are defined in this crate.

use crate::{BeaconBlock, BeaconState, Snapshot, Validator, ValidatorBeforeTx};
use bytes::BufMut;
use reth_codecs::{Compress, Decompress, DecompressError};

/// JSON is the on-disk encoding these types have always used; keeping it means
/// existing databases stay readable across this move.
macro_rules! json_codec {
    ($($ty:ty),* $(,)?) => {$(
        impl Decompress for $ty {
            fn decompress(value: &[u8]) -> Result<Self, DecompressError> {
                serde_json::from_slice(value).map_err(DecompressError::new)
            }
        }

        impl Compress for $ty {
            type Compressed = Vec<u8>;

            fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
                let encoded = serde_json::to_vec(self).unwrap_or_default();
                buf.put_slice(&encoded);
            }
        }
    )*};
}

json_codec!(BeaconState, BeaconBlock, Validator, ValidatorBeforeTx, Snapshot);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BLSPubkey;
    use alloy_primitives::{Address, B256};

    fn roundtrip<T>(make: impl Fn() -> T)
    where
        T: Compress<Compressed = Vec<u8>> + Decompress + PartialEq + std::fmt::Debug,
    {
        let bytes = make().compress();
        let back = T::decompress(&bytes).unwrap();
        assert_eq!(back, make());
    }

    fn sample_validator() -> Validator {
        Validator {
            pubkey: BLSPubkey::repeat_byte(7),
            withdrawal_credentials: B256::repeat_byte(1),
            effective_balance: 32_000_000_000,
            slashed: true,
            activation_eligibility_epoch: 1,
            activation_epoch: 2,
            exit_epoch: 3,
            withdrawable_epoch: 4,
        }
    }

    #[test]
    fn validator_roundtrips_through_json_codec() {
        roundtrip(sample_validator);
    }

    #[test]
    fn validator_before_tx_roundtrips() {
        roundtrip(|| ValidatorBeforeTx {
            address: Address::repeat_byte(9),
            info: Some(sample_validator()),
        });
        roundtrip(|| ValidatorBeforeTx {
            address: Address::ZERO,
            info: None,
        });
    }

    #[test]
    fn beacon_block_roundtrips() {
        roundtrip(|| {
            let mut block = BeaconBlock::default();
            block.slot = 42;
            block.state_root = B256::repeat_byte(3);
            block
        });
    }

    #[test]
    fn beacon_state_roundtrips_persisted_fields_only() {
        let mut state = BeaconState::new();
        state.slot = 99;
        state.eth1_deposit_index = 5;
        state.randao_mix = B256::repeat_byte(0xaa);
        let bytes = state.compress();
        let back = BeaconState::decompress(&bytes).unwrap();
        assert_eq!(back.slot, 99);
        assert_eq!(back.eth1_deposit_index, 5);
        assert_eq!(back.randao_mix, B256::repeat_byte(0xaa));
        assert_eq!(back.validators_len, 0);
    }

    #[test]
    fn snapshot_type_has_codec() {
        fn assert_codec<T: Compress + Decompress>() {}
        assert_codec::<Snapshot>();
    }

    #[test]
    fn decompress_rejects_garbage() {
        assert!(Validator::decompress(b"not json").is_err());
        assert!(BeaconBlock::decompress(b"").is_err());
        assert!(BeaconState::decompress(b"{\"slot\":\"x\"}").is_err());
    }
}
