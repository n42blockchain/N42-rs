// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The anchor of a node started from a state snapshot under deferred execution.
//!
//! With deferred execution at depth 1 the state after block N is certified by
//! header N+1, not by header N: N+1 carries N's state root, receipts root,
//! logs bloom, gas used and (profile 1, AM25) requests hash. A node
//! initialised at N from a snapshot (`n42-init-snapshot init --anchor`) has
//! neither N's body nor its receipts nor its parent's state, so it cannot
//! re-derive those fields the way a restarted node does. `init` checks the
//! anchor against the snapshot and keeps it next to the forest; the node's
//! start-up files N's executed fields from it
//! (`docs/PROFILE1_SNAPSHOT_JOIN.md`).

use alloy_primitives::B256;
use n42_header::N42Header;
use n42_qmdb_reth::executed_fields::{fields_from_child_header_deferring_requests, ExecutedFields};
use std::path::{Path, PathBuf};

/// The anchor's file name, inside the QMDB directory.
pub const ANCHOR_FILE: &str = "snapshot-anchor.rlp";

/// Where the anchor of the forest in `qmdb_dir` lives.
pub fn anchor_path(qmdb_dir: &Path) -> PathBuf {
    qmdb_dir.join(ANCHOR_FILE)
}

/// Checks that `anchor` is the child of the head `(number, hash)` and carries
/// `root`, the state after the head. The anchor's own seal and QC are not
/// checked here: the first pulled block the node imports is the anchor
/// itself or its descendant, executed only once a `CommitQC` names it (SYNC
/// §3.3), and that import compares the carried fields with the ones filed.
pub fn check(anchor: &N42Header, head: (u64, B256), root: B256) -> eyre::Result<()> {
    check_child(anchor, head)?;
    if anchor.state_root != root {
        eyre::bail!("the anchor carries state root {}, the snapshot's root is {root}", anchor.state_root);
    }
    Ok(())
}

/// Checks that `anchor` is the child of the head `(number, hash)`.
pub fn check_child(anchor: &N42Header, head: (u64, B256)) -> eyre::Result<()> {
    if anchor.number != head.0.wrapping_add(1) || anchor.parent_hash != head.1 {
        eyre::bail!(
            "the anchor is block {} on parent {}; it must be the child of the snapshot head, block {} {}",
            anchor.number,
            anchor.parent_hash,
            head.0,
            head.1
        );
    }
    Ok(())
}

/// Decodes an anchor's RLP (as `init` stores it, or as `debug_getRawHeader`
/// returns it).
pub fn decode(rlp: &[u8]) -> eyre::Result<N42Header> {
    let mut cursor = rlp;
    let header = <N42Header as alloy_rlp::Decodable>::decode(&mut cursor)?;
    if !cursor.is_empty() {
        eyre::bail!("anchor has {} trailing bytes", cursor.len());
    }
    Ok(header)
}

/// The executed fields of the snapshot head `head`, from the anchor stored in
/// `qmdb_dir`: `Ok(None)` when there is no anchor or it is not `head`'s child
/// (the node has moved past its snapshot head; the receipts path serves).
pub fn head_fields(
    qmdb_dir: &Path,
    head: (u64, B256),
    requests_deferred: bool,
) -> eyre::Result<Option<ExecutedFields>> {
    let path = anchor_path(qmdb_dir);
    let rlp = match std::fs::read(&path) {
        Ok(rlp) => rlp,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(eyre::eyre!("{}: {err}", path.display())),
    };
    let anchor = decode(&rlp).map_err(|err| eyre::eyre!("{}: {err}", path.display()))?;
    if anchor.number != head.0.wrapping_add(1) || anchor.parent_hash != head.1 {
        return Ok(None);
    }
    Ok(Some(fields_from_child_header_deferring_requests(&anchor.inner, requests_deferred)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{Bloom, B256};

    fn anchor(number: u64, parent: B256, root: B256) -> N42Header {
        N42Header::from(Header {
            number,
            parent_hash: parent,
            state_root: root,
            receipts_root: B256::repeat_byte(0xaa),
            logs_bloom: Bloom::repeat_byte(0x01),
            gas_used: 183_600,
            requests_hash: Some(B256::repeat_byte(0xcc)),
            // Every optional field up to the requests hash, as on profile 1,
            // so the header round-trips through its RLP.
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(B256::ZERO),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            ..Default::default()
        })
    }

    #[test]
    fn the_child_carrying_the_root_anchors_the_head() {
        let head = (40, B256::repeat_byte(4));
        let root = B256::repeat_byte(7);
        check(&anchor(41, head.1, root), head, root).unwrap();
        let err = |a: N42Header| check(&a, head, root).unwrap_err().to_string();
        assert!(err(anchor(41, head.1, B256::ZERO)).contains("carries state root"));
        assert!(err(anchor(42, head.1, root)).contains("must be the child"));
        assert!(err(anchor(41, B256::ZERO, root)).contains("must be the child"));
        // A header-N "anchor" (the pre-deferral pairing) is refused.
        assert!(err(anchor(40, B256::ZERO, root)).contains("must be the child"));
    }

    #[test]
    fn head_fields_are_the_anchors_carried_fields_and_only_for_its_parent() {
        let dir = tempfile::tempdir().unwrap();
        let head = (40, B256::repeat_byte(4));
        assert_eq!(head_fields(dir.path(), head, true).unwrap(), None);
        let a = anchor(41, head.1, B256::repeat_byte(7));
        let mut rlp = Vec::new();
        alloy_rlp::Encodable::encode(&a, &mut rlp);
        std::fs::write(anchor_path(dir.path()), &rlp).unwrap();
        assert_eq!(decode(&rlp).unwrap(), a);
        let fields = head_fields(dir.path(), head, true).unwrap().unwrap();
        assert_eq!(fields.state_root, B256::repeat_byte(7));
        assert_eq!(fields.receipts_root, B256::repeat_byte(0xaa));
        assert_eq!(fields.logs_bloom, Bloom::repeat_byte(0x01));
        assert_eq!(fields.gas_used, 183_600);
        assert_eq!(fields.requests_hash, B256::repeat_byte(0xcc));
        // Off profile 1 the requests hash is not a carried field.
        assert_eq!(
            head_fields(dir.path(), head, false).unwrap().unwrap().requests_hash,
            n42_qmdb_reth::executed_fields::NO_REQUESTS_HASH
        );
        // Past the snapshot head the anchor says nothing.
        assert_eq!(head_fields(dir.path(), (41, B256::repeat_byte(5)), true).unwrap(), None);
    }
}
