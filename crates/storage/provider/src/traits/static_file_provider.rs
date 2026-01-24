// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::BlockNumber;
use reth_static_file_types::StaticFileSegment;
use reth_storage_api::NodePrimitivesProvider;
use reth_storage_errors::provider::ProviderResult;

use crate::providers::{StaticFileProvider, StaticFileProviderRWRefMut};

/// Static file provider factory.
pub trait StaticFileProviderFactory: NodePrimitivesProvider {
    /// Create new instance of static file provider.
    fn static_file_provider(&self) -> StaticFileProvider<Self::Primitives>;

    /// Gets a static file writer for the specified block and segment.
    fn get_static_file_writer(
        &self,
        block: BlockNumber,
        segment: StaticFileSegment,
    ) -> ProviderResult<StaticFileProviderRWRefMut<'_, Self::Primitives>>;
}
