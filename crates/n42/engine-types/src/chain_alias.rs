// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where a block's QMDB tree was filed, when it was filed under a hash
//! consensus had not sealed yet.
//!
//! A build's tree is computed under the hash the builder gave the block and
//! renamed to the hash consensus seals it with; the forest moves the record
//! rather than copying it, because a record's undo describes what is applied
//! to the tree and two records claiming one application would apply it twice
//! (`QmdbForest::rename`).
//!
//! The build chain (`N42_BUILD_CHAIN`) files the parent's tree under the
//! header this node *expects* to propose -- the built header stamped with the
//! view the caller said it would propose it under, and sealed with the
//! leader's key. That is the hash in all but one case: a view that times out
//! moves the block to another view, the extra data changes, and so does the
//! hash. The rename the ordinary path then makes -- builder hash to the hash
//! consensus really sealed -- finds nothing under the builder hash, and the
//! block's finish behind its seal fails on a chain that is otherwise
//! perfectly correct.
//!
//! So every rename says where it put the record, and a rename that finds
//! nothing looks there. Eight entries: a build is renamed within a view of
//! being built, and a note nobody came back for is not worth keeping.

use alloy_primitives::B256;
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

/// Notes kept. Three builds are alive at once at most
/// (`built_executions::KEEP`); the rest is slack.
const KEEP: usize = 8;

fn notes() -> &'static Mutex<VecDeque<(B256, B256)>> {
    static NOTES: OnceLock<Mutex<VecDeque<(B256, B256)>>> = OnceLock::new();
    NOTES.get_or_init(|| Mutex::new(VecDeque::with_capacity(KEEP)))
}

/// Notes that the tree computed under `built` now sits under `filed_under`.
pub fn remember(built: B256, filed_under: B256) {
    if built == filed_under {
        return;
    }
    let mut notes = notes().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    notes.retain(|(hash, _)| *hash != built);
    while notes.len() >= KEEP {
        notes.pop_front();
    }
    notes.push_back((built, filed_under));
}

/// Where the tree computed under `built` was last filed.
pub fn filed_under(built: B256) -> Option<B256> {
    let notes = notes().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    notes.iter().rev().find(|(hash, _)| *hash == built).map(|(_, under)| *under)
}

/// Files the tree computed under `built` beneath the hash consensus sealed
/// the block with, wherever it is now.
///
/// The plain rename first, which is every block on a node that is not
/// chaining and every block whose view held on one that is. Only when that
/// finds nothing is the note consulted -- and then the record is moved from
/// where the chain put it to where consensus says it belongs.
pub fn rename(
    qmdb: &n42_qmdb_reth::QmdbNodeState,
    built: B256,
    sealed: B256,
) -> Result<(), n42_qmdb_reth::NodeStateError> {
    let first = qmdb.rename(built, sealed);
    if first.is_ok() {
        remember(built, sealed);
        return first;
    }
    match filed_under(built) {
        Some(under) if under != sealed => {
            tracing::warn!(
                target: "n42.payload_serve",
                %built, %under, %sealed,
                "the chain filed this tree under a header the fleet did not seal; moving it"
            );
            qmdb.rename(under, sealed)?;
            remember(built, sealed);
            Ok(())
        }
        _ => first,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_note_survives_until_it_is_replaced_or_crowded_out() {
        let built = B256::repeat_byte(0xa1);
        remember(built, B256::repeat_byte(0xb1));
        assert_eq!(filed_under(built), Some(B256::repeat_byte(0xb1)));
        // The real seal replaces the chain's guess.
        remember(built, B256::repeat_byte(0xb2));
        assert_eq!(filed_under(built), Some(B256::repeat_byte(0xb2)));
        // A rename to the same hash is not a move and leaves no note.
        let same = B256::repeat_byte(0xc1);
        remember(same, same);
        assert_eq!(filed_under(same), None);
        // Bounded.
        for i in 0..(KEEP as u8 + 4) {
            remember(B256::repeat_byte(0x10 + i), B256::repeat_byte(0x80 + i));
        }
        assert!(notes().lock().expect("not poisoned").len() <= KEEP);
    }
}
