// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Database `Compress`/`Decompress` for [`Tree`].
//!
//! Previously in `reth-db-api`'s `models/beacon.rs`. reth moved those traits out
//! to `reth-codecs`, which left the impl with neither the trait nor the type
//! local — an orphan-rule violation. `Tree` is defined here, so the impl lives
//! here now.

use crate::tree::Tree;
use bytes::BufMut;
use reth_codecs::{Compress, Decompress, DecompressError};

impl<T> Decompress for Tree<T>
where
    T: crate::Value + core::fmt::Debug + Send + Sync + serde::de::DeserializeOwned,
{
    fn decompress(value: &[u8]) -> Result<Self, DecompressError> {
        serde_json::from_slice(value).map_err(DecompressError::new)
    }
}

impl<T> Compress for Tree<T>
where
    T: crate::Value + core::fmt::Debug + Send + Sync + serde::Serialize,
{
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let json_bytes = serde_json::to_vec(self).expect("Tree serialization should not fail");
        buf.put_slice(&json_bytes);
    }
}
