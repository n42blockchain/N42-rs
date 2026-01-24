// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use reth_primitives_traits::NodePrimitives;

/// Provider implementation that knows configured [`NodePrimitives`].
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait NodePrimitivesProvider {
    /// The node primitive types.
    type Primitives: NodePrimitives;
}
