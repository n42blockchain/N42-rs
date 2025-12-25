// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`StateProvider`](crate::StateProvider) implementations
pub(crate) mod historical;
pub(crate) mod latest;
pub(crate) mod macros;
mod overlay;
pub use overlay::{OverlayStateProvider, OverlayStateProviderFactory};
