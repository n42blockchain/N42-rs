// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

//! n42 primitives
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod snapshot;
pub use snapshot::APosConfig;
pub use snapshot::Snapshot;
pub use snapshot::Tally;
pub use snapshot::Vote;
pub use snapshot::VotingError;
