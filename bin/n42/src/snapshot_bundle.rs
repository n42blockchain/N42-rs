// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The profile-1 offline snapshot bundle (gate 4a), in the layout gov5's
//! `n42-reth-state-dump --bundle` writes and its `n42 init-snapshot --bundle`
//! reads (`docs/PROFILE1_SNAPSHOT_JOIN.md`):
//!
//! | file | content |
//! | --- | --- |
//! | `state.jsonl` | reth init-state JSONL, root line = header(P+1).stateRoot |
//! | `state.jsonl.header.rlp` | header(P), raw RLP |
//! | `qmdb.bin` | portable QMDB `0x03` at (P, hash P), root = header(P+1).stateRoot |
//! | `next-header.rlp` | header(P+1), raw RLP |
//! | `commit-qc.bin` | SYNC §5.2 `commit_qc/1` payload: `qc_len u32 ‖ QC ‖ count u16 ‖ count × (u32 len ‖ header RLP)`, little-endian, headers from the QC's block down to max(P-255, 1) |
//! | `block.rlp` | block P, gov5's `[header, txs, verifiers, rewards]` |
//! | `bundle.json` | manifest: chain, pivot, root, anchor, sha256 of every file |

use alloy_primitives::B256;
use n42_header::N42Header;
use sha2::Digest as _;
use std::{collections::BTreeMap, path::Path};

/// The state JSONL.
pub const STATE: &str = "state.jsonl";
/// Header P.
pub const HEADER: &str = "state.jsonl.header.rlp";
/// The portable QMDB snapshot.
pub const QMDB: &str = "qmdb.bin";
/// Header P+1.
pub const NEXT_HEADER: &str = "next-header.rlp";
/// The `commit_qc/1` payload.
pub const COMMIT_QC: &str = "commit-qc.bin";
/// Block P.
pub const BLOCK: &str = "block.rlp";
/// The manifest.
pub const MANIFEST: &str = "bundle.json";
/// The manifest's format tag.
pub const FORMAT: &str = "n42-profile1-snapshot-bundle/1";

/// The bundle's manifest, gov5's field names.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    /// [`FORMAT`].
    pub format: String,
    /// The chain id.
    pub chain_id: u64,
    /// The genesis hash.
    pub genesis_hash: B256,
    /// P.
    pub pivot_number: u64,
    /// hash(P).
    pub pivot_hash: B256,
    /// The state after P = header(P+1).stateRoot.
    pub post_state_root: B256,
    /// 1 on profile 1.
    pub deferred_depth: u64,
    /// The anchoring CommitQC's view.
    pub anchor_qc_view: u64,
    /// The block the QC names.
    pub anchor_block_number: u64,
    /// Its hash.
    pub anchor_block_hash: B256,
    /// The lowest header of `commit-qc.bin`.
    pub anchor_lowest_header: u64,
    /// sha256 (hex, no prefix) of every other file.
    pub files_sha256: BTreeMap<String, String>,
    /// Descriptive fields (`root_label`, `accounts`, ...), kept as read.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// sha256 of a file, hex.
pub fn sha256_file(path: &Path) -> eyre::Result<String> {
    let bytes = std::fs::read(path).map_err(|e| eyre::eyre!("{}: {e}", path.display()))?;
    Ok(alloy_primitives::hex::encode(sha2::Sha256::digest(&bytes)))
}

/// Checks the manifest of the bundle in `dir`: format, chain, genesis and the
/// sha256 of every file it lists (which must include the six data files
/// this importer reads, `block.rlp` excepted).
pub fn check_manifest(dir: &Path, chain_id: u64, genesis_hash: B256) -> eyre::Result<Manifest> {
    let path = dir.join(MANIFEST);
    let manifest: Manifest = serde_json::from_slice(&std::fs::read(&path).map_err(|e| eyre::eyre!("{}: {e}", path.display()))?)
        .map_err(|e| eyre::eyre!("{}: {e}", path.display()))?;
    if manifest.format != FORMAT {
        eyre::bail!("bundle format {:?}, expected {FORMAT:?}", manifest.format);
    }
    if (manifest.chain_id, manifest.genesis_hash) != (chain_id, genesis_hash) {
        eyre::bail!(
            "bundle is for chain {} genesis {}, this chain is {chain_id} genesis {genesis_hash}",
            manifest.chain_id,
            manifest.genesis_hash
        );
    }
    if manifest.deferred_depth != 1 {
        eyre::bail!("bundle deferred depth {}: profile 1 is depth 1", manifest.deferred_depth);
    }
    for name in [STATE, HEADER, QMDB, NEXT_HEADER, COMMIT_QC] {
        if !manifest.files_sha256.contains_key(name) {
            eyre::bail!("bundle manifest lists no sha256 for {name}");
        }
    }
    for (name, want) in &manifest.files_sha256 {
        if name.contains('/') || name.contains("..") {
            eyre::bail!("bundle manifest names {name:?}, not a file of the bundle");
        }
        let got = sha256_file(&dir.join(name))?;
        if !got.eq_ignore_ascii_case(want.trim_start_matches("0x")) {
            eyre::bail!("bundle file {name}: sha256 {got}, manifest says {want}");
        }
    }
    Ok(manifest)
}

/// Decodes a `commit_qc/1` payload: the QC's wire bytes and the headers,
/// from the QC's block down.
pub fn decode_commit_qc_payload(bytes: &[u8]) -> eyre::Result<(Vec<u8>, Vec<N42Header>)> {
    let mut at = 0usize;
    let mut take = |n: usize| -> eyre::Result<&[u8]> {
        let end = at.checked_add(n).filter(|end| *end <= bytes.len()).ok_or_else(|| eyre::eyre!("commit_qc payload truncated"))?;
        let out = &bytes[at..end];
        at = end;
        Ok(out)
    };
    let qc_len = u32::from_le_bytes(take(4)?.try_into()?) as usize;
    let qc = take(qc_len)?.to_vec();
    let count = u16::from_le_bytes(take(2)?.try_into()?) as usize;
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u32::from_le_bytes(take(4)?.try_into()?) as usize;
        let mut rlp = take(len)?;
        let header = <N42Header as alloy_rlp::Decodable>::decode(&mut rlp)?;
        if !rlp.is_empty() {
            eyre::bail!("commit_qc payload: a header with trailing bytes");
        }
        headers.push(header);
    }
    if at != bytes.len() {
        eyre::bail!("commit_qc payload has {} trailing bytes", bytes.len() - at);
    }
    Ok((qc, headers))
}

/// Encodes a `commit_qc/1` payload (headers from the QC's block down).
pub fn encode_commit_qc_payload(qc: &[u8], headers: &[N42Header]) -> eyre::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(qc.len())?.to_le_bytes());
    out.extend_from_slice(qc);
    out.extend_from_slice(&u16::try_from(headers.len())?.to_le_bytes());
    for header in headers {
        let mut rlp = Vec::new();
        alloy_rlp::Encodable::encode(header, &mut rlp);
        out.extend_from_slice(&u32::try_from(rlp.len())?.to_le_bytes());
        out.extend_from_slice(&rlp);
    }
    Ok(out)
}

/// Checks that `headers` (from the QC's block down) link child to parent,
/// and, when the lowest is block 1, that it extends `genesis_hash`.
pub fn check_descending_links(headers: &[N42Header], genesis_hash: B256) -> eyre::Result<()> {
    for pair in headers.windows(2) {
        if pair[0].number != pair[1].number + 1 || pair[0].parent_hash != pair[1].hash_slow() {
            eyre::bail!("commit_qc headers: {} does not extend {}", pair[0].number, pair[1].number);
        }
    }
    if let Some(lowest) = headers.last() {
        if lowest.number == 1 && lowest.parent_hash != genesis_hash {
            eyre::bail!("commit_qc headers: block 1 does not extend the genesis {genesis_hash}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;

    fn chain(genesis: B256, count: u64) -> Vec<N42Header> {
        let mut parent = genesis;
        let mut out: Vec<N42Header> = (1..=count)
            .map(|number| {
                let h = N42Header::from(Header { number, parent_hash: parent, ..Default::default() });
                parent = h.hash_slow();
                h
            })
            .collect();
        out.reverse();
        out
    }

    #[test]
    fn the_commit_qc_payload_round_trips_and_refuses_damage() {
        let headers = chain(B256::repeat_byte(1), 5);
        let qc = vec![7u8; 151];
        let bytes = encode_commit_qc_payload(&qc, &headers).unwrap();
        assert_eq!(decode_commit_qc_payload(&bytes).unwrap(), (qc, headers.clone()));
        assert!(decode_commit_qc_payload(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode_commit_qc_payload(&longer).is_err());
        check_descending_links(&headers, B256::repeat_byte(1)).unwrap();
        assert!(check_descending_links(&headers, B256::ZERO).unwrap_err().to_string().contains("genesis"));
        let mut gap = headers;
        gap.remove(2);
        assert!(check_descending_links(&gap, B256::repeat_byte(1)).is_err());
    }

    #[test]
    fn the_manifest_binds_chain_and_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut files = BTreeMap::new();
        for name in [STATE, HEADER, QMDB, NEXT_HEADER, COMMIT_QC] {
            std::fs::write(dir.path().join(name), name.as_bytes()).unwrap();
            files.insert(name.to_owned(), sha256_file(&dir.path().join(name)).unwrap());
        }
        let manifest = Manifest {
            format: FORMAT.to_owned(),
            chain_id: 1144,
            genesis_hash: B256::repeat_byte(2),
            pivot_number: 21,
            pivot_hash: B256::repeat_byte(3),
            post_state_root: B256::repeat_byte(4),
            deferred_depth: 1,
            anchor_qc_view: 23,
            anchor_block_number: 22,
            anchor_block_hash: B256::repeat_byte(5),
            anchor_lowest_header: 1,
            files_sha256: files,
            extra: BTreeMap::new(),
        };
        std::fs::write(dir.path().join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert_eq!(check_manifest(dir.path(), 1144, B256::repeat_byte(2)).unwrap(), manifest);
        assert!(check_manifest(dir.path(), 1143, B256::repeat_byte(2)).is_err());
        std::fs::write(dir.path().join(QMDB), b"tampered").unwrap();
        assert!(check_manifest(dir.path(), 1144, B256::repeat_byte(2)).unwrap_err().to_string().contains("sha256"));
    }
}
