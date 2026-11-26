// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observed equivocations (mixed-production standard E15): the two
//! conflicting signed messages, kept durably in the validator's datadir and
//! served by the `n42_equivocations` RPC.
//!
//! The file is `<datadir>/equivocations.jsonl`, one [`EquivocationRecord`]
//! a line, appended and synced before the record is counted. One record per
//! (kind, view, validator): a repeat of the same offence is not written again.
//! Evidence only: nothing here slashes or gossips.

use alloy_primitives::{Bytes, B256};
use n42_h2_consensus::{EquivocationEvidence, EquivocationKind, SignedValue};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The evidence file's name inside the datadir.
pub const FILE_NAME: &str = "equivocations.jsonl";

/// The evidence file of `datadir`.
pub fn evidence_path(datadir: &Path) -> PathBuf {
    datadir.join(FILE_NAME)
}

/// One observed equivocation, as persisted and as served over RPC.
///
/// `view`, `validatorIndex`, `hash1`, `hash2` and `detectedAt` are the fields
/// N42-26's `n42_equivocations` serves; `kind`, `publicKey`, `first` and
/// `second` add the signed pair E15 asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EquivocationRecord {
    /// What was signed twice.
    pub kind: EquivocationKind,
    /// The view of both messages.
    pub view: u64,
    /// The validator's index in the view's set.
    pub validator_index: u32,
    /// The first message's block hash.
    pub hash1: B256,
    /// The second message's block hash (for two proposals of one block that
    /// differ only in signed validator changes: the two message commitments).
    pub hash2: B256,
    /// The validator's BLS public key.
    pub public_key: Bytes,
    /// The message seen first: signed bytes and signature.
    pub first: SignedValue,
    /// The conflicting message: signed bytes and signature.
    pub second: SignedValue,
    /// Unix seconds when this node detected it.
    pub detected_at: u64,
}

impl EquivocationRecord {
    /// A record of `evidence` with the engine's reported hashes, detected now.
    pub fn new(evidence: EquivocationEvidence, hash1: B256, hash2: B256) -> Self {
        let detected_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        Self {
            kind: evidence.kind,
            view: evidence.view,
            validator_index: evidence.validator,
            hash1,
            hash2,
            public_key: evidence.public_key,
            first: evidence.first,
            second: evidence.second,
            detected_at,
        }
    }

    /// The (kind, view, validator) the record is unique by.
    const fn key(&self) -> (EquivocationKind, u64, u32) {
        (self.kind, self.view, self.validator_index)
    }
}

/// The `n42_equivocations` RPC result: every record, oldest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EquivocationsResponse {
    /// The number of records.
    pub total: usize,
    /// The records.
    pub evidence: Vec<EquivocationRecord>,
}

/// The observed equivocations: a file in the datadir (or memory only), shared
/// between the consensus loop that records and the RPC that reads.
#[derive(Clone, Debug, Default)]
pub struct EquivocationLog {
    path: Option<PathBuf>,
    records: Arc<RwLock<Vec<EquivocationRecord>>>,
}

impl EquivocationLog {
    /// A log that keeps nothing across a restart (no datadir).
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// The log of `datadir`, with what earlier runs recorded. A line that does
    /// not parse (a write cut short by a crash) is skipped with a warning.
    pub fn open(datadir: &Path) -> std::io::Result<Self> {
        let path = evidence_path(datadir);
        let mut records = Vec::new();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                for (number, line) in text.lines().enumerate().filter(|(_, line)| !line.trim().is_empty()) {
                    match serde_json::from_str::<EquivocationRecord>(line) {
                        Ok(record) => records.push(record),
                        Err(err) => tracing::warn!(target: "n42.h2.node", path = %path.display(), line = number + 1, %err, "unreadable equivocation record skipped"),
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        Ok(Self { path: Some(path), records: Arc::new(RwLock::new(records)) })
    }

    /// Appends `record` (synced to disk when the log has a file). Returns
    /// whether it was new; a repeat of a recorded (kind, view, validator) is
    /// not written again. A write that fails leaves the record out, so a
    /// later repeat is tried again.
    pub fn record(&self, record: EquivocationRecord) -> std::io::Result<bool> {
        let mut records = self.records.write();
        if records.iter().any(|known| known.key() == record.key()) {
            return Ok(false);
        }
        if let Some(path) = &self.path {
            let mut line = serde_json::to_vec(&record).map_err(std::io::Error::other)?;
            line.push(b'\n');
            let created = !path.exists();
            let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
            file.write_all(&line)?;
            file.sync_data()?;
            if created && let Some(dir) = path.parent().and_then(|dir| std::fs::File::open(dir).ok()) {
                let _ = dir.sync_all();
            }
        }
        records.push(record);
        Ok(true)
    }

    /// The number of records.
    pub fn len(&self) -> usize {
        self.records.read().len()
    }

    /// Whether nothing was recorded.
    pub fn is_empty(&self) -> bool {
        self.records.read().is_empty()
    }

    /// The `n42_equivocations` answer.
    pub fn response(&self) -> EquivocationsResponse {
        let evidence = self.records.read().clone();
        EquivocationsResponse { total: evidence.len(), evidence }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n42_h2_consensus::protocol::quorum::ConsensusSigningProfile;
    use n42_h2_primitives::BlsSecretKey;

    fn evidence(view: u64, validator: u32) -> EquivocationEvidence {
        let sk = BlsSecretKey::key_gen(&[7; 32]).expect("key");
        let profile = ConsensusSigningProfile::Native;
        let side = |hash: B256| {
            let message = profile.vote_message(view, hash);
            let signature = profile.sign(&sk, &message);
            SignedValue::new(hash, message, &signature)
        };
        EquivocationEvidence {
            kind: EquivocationKind::Vote,
            view,
            validator,
            public_key: Bytes::copy_from_slice(&sk.public_key().to_bytes()),
            first: side(B256::repeat_byte(1)),
            second: side(B256::repeat_byte(2)),
        }
    }

    fn record(view: u64, validator: u32) -> EquivocationRecord {
        EquivocationRecord::new(evidence(view, validator), B256::repeat_byte(1), B256::repeat_byte(2))
    }

    #[test]
    fn the_signed_pair_survives_a_restart_and_verifies() {
        let dir = std::env::temp_dir().join(format!("n42-equivocations-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let log = EquivocationLog::open(&dir).expect("open");
        assert!(log.record(record(5, 2)).expect("write"));
        assert!(!log.record(record(5, 2)).expect("repeat"), "one record per offence");
        assert!(log.record(record(6, 2)).expect("write"));

        let reopened = EquivocationLog::open(&dir).expect("reopen");
        let response = reopened.response();
        assert_eq!(response.total, 2);
        assert_eq!(response.evidence, log.response().evidence);
        let first = &response.evidence[0];
        let evidence = EquivocationEvidence {
            kind: first.kind,
            view: first.view,
            validator: first.validator_index,
            public_key: first.public_key.clone(),
            first: first.first.clone(),
            second: first.second.clone(),
        };
        assert!(evidence.verify(ConsensusSigningProfile::Native), "the persisted pair verifies");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_rpc_answer_names_the_n42_26_fields() {
        let log = EquivocationLog::in_memory();
        log.record(record(9, 3)).expect("memory");
        let json = serde_json::to_value(log.response()).expect("json");
        assert_eq!(json["total"], 1);
        let entry = &json["evidence"][0];
        for field in ["view", "validatorIndex", "hash1", "hash2", "detectedAt", "kind", "publicKey", "first", "second"] {
            assert!(entry.get(field).is_some(), "missing {field}: {entry}");
        }
        assert_eq!(entry["kind"], "vote");
        assert!(entry["first"]["signature"].as_str().is_some_and(|s| s.len() == 2 + 192));
    }
}
