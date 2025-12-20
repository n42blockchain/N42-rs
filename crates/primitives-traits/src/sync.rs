// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

//! Lock synchronization primitives

use once_cell as _;

#[cfg(not(feature = "std"))]
pub use once_cell::sync::{Lazy as LazyLock, OnceCell as OnceLock};

#[cfg(feature = "std")]
pub use std::sync::{LazyLock, OnceLock};
