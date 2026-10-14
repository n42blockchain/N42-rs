//! Durable proposal bodies bridge a consensus vote and batched EL persistence.
//! A QC is not enough to re-execute a block after all execution layers crash.

use alloy_primitives::B256;
use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use n42_h2_execution::ExecutionLayer;
use n42_h2_net::{HeaderProfile, decode_block_rlp_raw};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    sync::Mutex,
};

const MAX_BODY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REPLAY_BLOCKS: usize = 4096;
const MAX_REPLAY_BYTES: usize = 4 * 1024 * 1024 * 1024;

/// Missing local ancestry can be fetched from peers without changing vote watermarks.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// Valid ancestry is unavailable locally; peer synchronization may supply it.
    #[error("certified block {0:#x} is absent from EL and durable recovery bodies")]
    MissingBody(B256),
    /// Invalid data, storage failures, and rejected EL execution remain fatal.
    #[error("{0}")]
    Invalid(String),
}

impl From<String> for RecoveryError {
    fn from(message: String) -> Self {
        Self::Invalid(message)
    }
}

impl From<&str> for RecoveryError {
    fn from(message: &str) -> Self {
        Self::Invalid(message.into())
    }
}

/// A local write-ahead store, enabled for validators with durable consensus state.
#[derive(Debug)]
pub struct RecoveryBodies {
    dir: PathBuf,
    writing: Mutex<()>,
}

impl RecoveryBodies {
    /// Opens the chain-specific directory beneath the validator's consensus data.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, String> {
        let dir = dir.into();
        let mut parents = Vec::new();
        let mut cursor = dir.as_path();
        while !cursor.exists() {
            parents.push(cursor.to_path_buf());
            cursor = cursor
                .parent()
                .ok_or("recovery directory has no existing ancestor")?;
        }
        parents.push(cursor.to_path_buf());
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        for parent in parents {
            File::open(&parent)
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?;
        }
        Ok(Self {
            dir,
            writing: Mutex::new(()),
        })
    }

    fn path(&self, hash: B256) -> PathBuf {
        self.dir.join(format!("{hash:x}.rlp"))
    }

    /// Flushes a complete body before the caller allows a vote to be signed.
    pub fn save(&self, hash: B256, body: &[u8], profile: HeaderProfile) -> Result<(), String> {
        if body.len() as u64 > MAX_BODY_BYTES {
            return Err("recovery body exceeds size bound".into());
        }
        let (actual, _) =
            n42_h2_consensus::decode_block_body_header(body, profile).map_err(|e| e.to_string())?;
        if actual != hash {
            return Err("recovery body hash mismatch".into());
        }
        let _guard = self.writing.lock().map_err(|e| e.to_string())?;
        let path = self.path(hash);
        if path.exists() {
            if self.read(hash)?.as_deref() != Some(body) {
                return Err("conflicting recovery body".into());
            }
            return Ok(());
        }
        let tmp = path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        file.write_all(body)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        File::open(&self.dir)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())
    }

    /// Reads a bounded body. Temporary files from interrupted writes are ignored.
    pub fn read(&self, hash: B256) -> Result<Option<Vec<u8>>, String> {
        let mut file = match File::open(self.path(hash)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        if file.metadata().map_err(|e| e.to_string())?.len() > MAX_BODY_BYTES {
            return Err("recovery body exceeds size bound".into());
        }
        let mut body = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_BODY_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|e| e.to_string())?;
        if body.len() as u64 > MAX_BODY_BYTES {
            return Err("recovery body exceeds size bound".into());
        }
        Ok(Some(body))
    }

    /// Deletes only bodies already covered by durable EL storage. Keep the parent
    /// frontier as well; a read failure stops pruning rather than guessing a height.
    pub fn prune(&self, persisted: u64, profile: HeaderProfile) -> Result<(), String> {
        let _guard = self.writing.lock().map_err(|e| e.to_string())?;
        for entry in std::fs::read_dir(&self.dir).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("rlp") {
                continue;
            }
            let hash: B256 = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or("invalid recovery filename")?
                .parse()
                .map_err(|e| format!("invalid recovery filename: {e}"))?;
            let body = self.read(hash)?.ok_or("recovery body disappeared")?;
            let (actual, header) = n42_h2_consensus::decode_block_body_header(&body, profile)
                .map_err(|e| e.to_string())?;
            if actual != hash {
                return Err("recovery body hash mismatch".into());
            }
            if header.number < persisted.saturating_sub(1) {
                std::fs::remove_file(path).map_err(|e| e.to_string())?;
            }
        }
        File::open(&self.dir)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())
    }
}

/// Replays only the ancestry named by a locally durable QC, through normal EL
/// validation. Never rewinds vote watermarks, invents blocks or lowers finality.
pub async fn recover<E: ExecutionLayer>(
    el: &E,
    bodies: &RecoveryBodies,
    target: B256,
    profile: HeaderProfile,
) -> Result<usize, RecoveryError> {
    let mut pending = Vec::new();
    let mut bytes = 0usize;
    let mut hash = target;
    while el
        .block_by_hash(hash)
        .await
        .map_err(|e| e.to_string())?
        .is_none()
    {
        if pending.len() >= MAX_REPLAY_BLOCKS {
            return Err("recovery ancestry exceeds replay bound".into());
        }
        let body = bodies.read(hash)?.ok_or(RecoveryError::MissingBody(hash))?;
        bytes = bytes
            .checked_add(body.len())
            .ok_or("recovery byte count overflow")?;
        if bytes > MAX_REPLAY_BYTES {
            return Err("recovery ancestry exceeds byte bound".into());
        }
        let block = decode_block_rlp_raw(&body, profile).map_err(|e| e.to_string())?;
        if block.block_hash != hash {
            return Err("recovery body hash mismatch".into());
        }
        if let Some(child) = pending.last() {
            let child: &n42_h2_net::RawGossipBlock = child;
            if block.header.number.checked_add(1) != Some(child.header.number) {
                return Err("non-contiguous recovery ancestry".into());
            }
        }
        hash = block.header.parent_hash;
        pending.push(block);
    }
    let count = pending.len();
    for block in pending.into_iter().rev() {
        let status = el
            .new_payload(block.execution_data())
            .await
            .map_err(|e| e.to_string())?;
        if status.status != PayloadStatusEnum::Valid {
            return Err(format!("EL rejected recovery payload: {:?}", status.status).into());
        }
        let choice = el
            .fork_choice_updated(ForkchoiceState {
                head_block_hash: block.block_hash,
                safe_block_hash: B256::ZERO,
                finalized_block_hash: B256::ZERO,
            })
            .await
            .map_err(|e| e.to_string())?;
        if choice.payload_status.status != PayloadStatusEnum::Valid {
            return Err(format!(
                "EL rejected recovery forkchoice: {:?}",
                choice.payload_status.status
            )
            .into());
        }
    }
    Ok(count)
}

/// Bootstraps a validator upgraded while its EL still holds unpersisted blocks.
/// Starting a journal only at the next proposal would leave a gap behind it.
pub async fn snapshot<E: ExecutionLayer>(
    el: &E,
    bodies: &RecoveryBodies,
    mut hash: B256,
    persisted: u64,
    profile: HeaderProfile,
) -> Result<(), String> {
    for _ in 0..MAX_REPLAY_BLOCKS {
        let block = el
            .block_by_hash(hash)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("EL lost a block during recovery snapshot")?;
        if block.header.number <= persisted {
            return Ok(());
        }
        if bodies.read(hash)?.is_none() {
            if block.header.block_access_list_hash.is_some() {
                return Err(
                    "cannot bootstrap an access-list block without its original full body".into(),
                );
            }
            let rewards = n42_h2_consensus::withdrawals_to_rewards(
                block.withdrawals.as_deref().unwrap_or(&[]),
            );
            let body = n42_h2_net::encode_block_rlp_raw(
                &block.header,
                &block.transactions,
                &rewards,
                None,
            );
            bodies.save(hash, &body, profile)?;
        }
        hash = block.header.parent_hash;
    }
    Err("recovery snapshot exceeds ancestry bound".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use n42_h2_execution::{ElCall, MockBehaviour, MockExecutionLayer};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "n42-recovery-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn store(&self) -> RecoveryBodies {
            RecoveryBodies::open(self.0.clone()).unwrap()
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn body(number: u64, parent: B256) -> (B256, Vec<u8>, alloy_rpc_types_engine::ExecutionData) {
        let built = MockExecutionLayer::built_block_on(number, parent);
        let header = built
            .execution_data
            .clone()
            .into_block_raw()
            .unwrap()
            .header;
        let bytes = n42_h2_net::encode_block_rlp_raw(&header, &[], &[], None);
        (header.hash_slow(), bytes, built.execution_data)
    }

    #[test]
    fn durable_body_survives_reopen_and_failed_write_leaves_no_body() {
        let dir = Scratch::new();
        let (first, bytes, _) = body(1, B256::ZERO);
        dir.store()
            .save(first, &bytes, HeaderProfile::Ethereum)
            .unwrap();
        assert_eq!(dir.store().read(first).unwrap(), Some(bytes.clone()));
        let (second, bytes2, _) = body(2, first);
        std::fs::create_dir(dir.store().path(second).with_extension("tmp")).unwrap();
        assert!(
            dir.store()
                .save(second, &bytes2, HeaderProfile::Ethereum)
                .is_err()
        );
        assert!(dir.store().read(second).unwrap().is_none());
        assert_eq!(dir.store().read(first).unwrap(), Some(bytes));
    }

    #[test]
    fn pruning_keeps_unpersisted_bodies_and_the_persisted_parent() {
        let dir = Scratch::new();
        let mut parent = B256::ZERO;
        let mut hashes = Vec::new();
        for n in 1..=5 {
            let (hash, bytes, _) = body(n, parent);
            dir.store()
                .save(hash, &bytes, HeaderProfile::Ethereum)
                .unwrap();
            hashes.push(hash);
            parent = hash;
        }
        dir.store().prune(4, HeaderProfile::Ethereum).unwrap();
        for (index, hash) in hashes.iter().enumerate() {
            assert_eq!(dir.store().read(*hash).unwrap().is_some(), index >= 2);
        }
    }

    #[test]
    fn wrong_hash_and_oversized_files_are_refused() {
        let dir = Scratch::new();
        let (hash, bytes, _) = body(1, B256::ZERO);
        assert!(
            dir.store()
                .save(B256::repeat_byte(9), &bytes, HeaderProfile::Ethereum)
                .is_err()
        );
        File::create(dir.store().path(hash))
            .unwrap()
            .set_len(MAX_BODY_BYTES + 1)
            .unwrap();
        assert!(dir.store().read(hash).is_err());
    }

    #[tokio::test]
    async fn recovery_reexecutes_only_missing_ancestors_in_order_without_changing_finality() {
        let dir = Scratch::new();
        let el = MockExecutionLayer::new();
        let (base, _, data) = body(0, B256::ZERO);
        el.new_payload(data).await.unwrap();
        let (first, bytes, _) = body(1, base);
        dir.store()
            .save(first, &bytes, HeaderProfile::Ethereum)
            .unwrap();
        let (second, bytes, _) = body(2, first);
        dir.store()
            .save(second, &bytes, HeaderProfile::Ethereum)
            .unwrap();
        assert_eq!(
            recover(&el, &dir.store(), second, HeaderProfile::Ethereum)
                .await
                .unwrap(),
            2
        );
        let calls = el.calls();
        assert_eq!(
            calls
                .iter()
                .filter_map(|c| if let ElCall::NewPayload(h) = c {
                    Some(*h)
                } else {
                    None
                })
                .collect::<Vec<_>>(),
            vec![base, first, second]
        );
        for call in calls {
            if let ElCall::ForkchoiceUpdated(choice) = call {
                assert_eq!(choice.safe_block_hash, B256::ZERO);
                assert_eq!(choice.finalized_block_hash, B256::ZERO);
            }
        }
        assert_eq!(
            recover(&el, &dir.store(), second, HeaderProfile::Ethereum)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn upgrading_a_live_validator_snapshots_every_unpersisted_ancestor() {
        let dir = Scratch::new();
        let el = MockExecutionLayer::new();
        let (base, _, data) = body(0, B256::ZERO);
        el.new_payload(data).await.unwrap();
        let (first, _, data) = body(1, base);
        el.new_payload(data).await.unwrap();
        let (second, _, data) = body(2, first);
        el.new_payload(data).await.unwrap();
        snapshot(&el, &dir.store(), second, 0, HeaderProfile::Ethereum)
            .await
            .unwrap();
        assert!(dir.store().read(base).unwrap().is_none());
        assert!(dir.store().read(first).unwrap().is_some());
        assert!(dir.store().read(second).unwrap().is_some());
    }

    #[tokio::test]
    async fn missing_ancestor_aborts_before_any_replay_and_el_rejection_stops_recovery() {
        let dir = Scratch::new();
        let el = MockExecutionLayer::new();
        let (base, _, data) = body(0, B256::ZERO);
        el.new_payload(data).await.unwrap();
        let (first, bytes1, _) = body(1, base);
        let (second, bytes2, _) = body(2, first);
        dir.store()
            .save(second, &bytes2, HeaderProfile::Ethereum)
            .unwrap();
        assert!(matches!(
            recover(&el, &dir.store(), second, HeaderProfile::Ethereum).await,
            Err(RecoveryError::MissingBody(hash)) if hash == first
        ));
        assert_eq!(
            el.calls().len(),
            1,
            "no partial replay before all ancestry is available"
        );
        dir.store()
            .save(first, &bytes1, HeaderProfile::Ethereum)
            .unwrap();
        el.set_behaviour(MockBehaviour {
            new_payload_status: PayloadStatusEnum::Syncing,
            ..Default::default()
        });
        assert!(matches!(
            recover(&el, &dir.store(), second, HeaderProfile::Ethereum).await,
            Err(RecoveryError::Invalid(message)) if message.contains("EL rejected recovery payload")
        ));
        assert!(
            !el.calls()
                .iter()
                .any(|c| matches!(c, ElCall::ForkchoiceUpdated(_)))
        );
    }
}
