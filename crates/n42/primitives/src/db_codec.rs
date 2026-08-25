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
