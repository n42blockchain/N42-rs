// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Additional testing support for `NoopProvider`.

use crate::{providers::{StaticFileProvider, StaticFileProviderRWRefMut}, StaticFileProviderFactory};
use alloy_primitives::BlockNumber;
use reth_primitives_traits::NodePrimitives;
use reth_static_file_types::StaticFileSegment;
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use std::path::PathBuf;

/// Re-exported for convenience
pub use reth_storage_api::noop::NoopProvider;

impl<C: Send + Sync, N: NodePrimitives> StaticFileProviderFactory for NoopProvider<C, N> {
    fn static_file_provider(&self) -> StaticFileProvider<Self::Primitives> {
        StaticFileProvider::read_only(PathBuf::default(), false).unwrap()
    }

    fn get_static_file_writer(
        &self,
        _block: BlockNumber,
        _segment: StaticFileSegment,
    ) -> ProviderResult<StaticFileProviderRWRefMut<'_, Self::Primitives>> {
        Err(ProviderError::UnsupportedProvider)
    }
}
