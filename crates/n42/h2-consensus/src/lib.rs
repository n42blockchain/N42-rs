// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HotStuff-2 consensus: the protocol core, the validator set, and read-only
//! finality verification.
//!
//! This carries both halves of the consensus that do not need an execution
//! engine:
//!
//! - [`protocol`] — the HotStuff-2 state machine: proposal, voting, quorum
//!   assembly, the pacemaker, view changes, and timeout certificates. Enough to
//!   *participate*, not just observe.
//! - [`validator`] — the validator set, epoch management, and leader selection.
//! - [`h2_finality`] — verify a committed gov5 H2-v4 `Decide` without running a
//!   consensus engine, for observers and mobile verifiers.
//!
//! What is deliberately absent is the binding to execution. N42-26's
//! `adapter.rs` (reth `FullConsensus`, header validation, receipts root) and its
//! `n42-consensus-service` orchestrator are not ported, because those are where
//! the reth-version wall actually is. See `docs/N42_26_PORT.md`.

pub mod error;
pub mod h2_finality;
pub mod protocol;
pub mod rotor;
pub mod validator;
mod validator_info;
pub mod vote_log;
pub mod wire_bridge;

pub use error::{ConsensusError, ConsensusResult};
pub use protocol::quorum::{
    validator_changes_hash, verify_commit_qc, verify_commit_qc_with_profile, verify_qc, verify_tc,
};
pub use protocol::state_machine::{AuthenticatedConsensusMessage, FUTURE_VIEW_WINDOW};
pub use protocol::{ConsensusEngine, ConsensusEvent, EngineOutput, Pacemaker, Phase, RoundState,
    TimeoutCollector, ViewTiming, VoteCollector};
pub use validator::{
    EpochManager, LeaderSelector, ValidatorSet, DEFAULT_MAX_HISTORICAL_EPOCHS,
    MAX_HISTORICAL_EPOCHS_LIMIT,
};
pub use validator_info::ValidatorInfo;
pub use vote_log::{NoopVoteLog, VoteLogWriter};
