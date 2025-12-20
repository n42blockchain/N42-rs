// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use reth_storage_api::NodePrimitivesProvider;

use crate::providers::StaticFileProvider;

/// Static file provider factory.
pub trait StaticFileProviderFactory: NodePrimitivesProvider {
    /// Create new instance of static file provider.
    fn static_file_provider(&self) -> StaticFileProvider<Self::Primitives>;
}
