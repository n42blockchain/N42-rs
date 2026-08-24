// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validator set, epoch management, and leader selection for HotStuff-2.

pub mod epoch;
mod selection;
mod set;

pub use epoch::{EpochManager, DEFAULT_MAX_HISTORICAL_EPOCHS, MAX_HISTORICAL_EPOCHS_LIMIT};
pub use selection::LeaderSelector;
pub use set::ValidatorSet;
