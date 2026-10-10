// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Execution-layer glue for the HotStuff-2 consensus engine.
//!
//! [`n42_h2_consensus`] can propose, vote, and commit, but on its own it decides
//! about block *hashes* — it never touches a block body. This crate is the part
//! that connects it to something that actually executes: the [`el::ExecutionLayer`]
//! seam (Engine API in alloy types, no reth types) and the [`driver::ExecutionDriver`]
//! that services consensus's requests against it.
//!
//! The seam is deliberately reth-free. A concrete adapter over reth's
//! `ConsensusEngineHandle` / `PayloadBuilderHandle` implements the trait node-side,
//! which keeps the consensus half of this repo independent of the reth version —
//! the thing that made the HotStuff-2 port possible without the reth 2.4.1 upgrade
//! (see `docs/RETH_2_4_1_UPGRADE.md`).

pub mod driver;
pub mod el;
pub mod execution_path;
pub mod mock;
pub mod raw_engine;
pub mod settlement;

pub use driver::{
    answer_layout_only, body_once, check_ahead_queue, parse_check_ahead_queue, CHECK_AHEAD_QUEUE, commit_fcu_async, compact_body, deferred_in_flight, parse_in_flight, take_compact, vote_before_slot, BodyDecoder,
    BuildTiming, CommitReport, DriverAction, ExecutionDriver, ImportReport, ImportVerdict, DEFERRED_IN_FLIGHT,
    DEFERRED_IN_FLIGHT_MAX, FOLLOWER_LAG_CAP, HELD_IMPORT_DROPPED,
};
pub use el::{
    AnswerStamps, BodyOutcome, BuildStart, BuildTrigger, ChainAhead, ChainBlock, ChainSealer, BuiltBlock, ElError, ExecutionLayer,
    ForeignBody, ResolveKind, fill_elided, vouches_for,
};
pub use execution_path::{ExecutionPath, ExecutionScheduling, ExecutionWorkload};
pub use mock::{ElCall, MockBehaviour, MockExecutionLayer};
pub use settlement::{
    parse_settlement_tags, settlement_tags, PersistedHeight, PersistedSource, SettlementTags, Tag, SETTLEMENT_TAGS_ENV,
};
