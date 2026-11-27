// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The block journal: AM35's node-local durable copy of a block's raw body.
//!
//! Profile 1 (`docs/MIXED_PRODUCTION_STANDARD.md` AM35) lets a member send its
//! commit vote for a block only once the block's data is durable here, so a
//! commit QC always names a block its voters can serve after any of them
//! restart together. The execution layer persists a block only once it is
//! canonical -- after its commit, under deferred execution -- so the copy the
//! vote waits for is this one: the block's wire body (gov5's RLP
//! `[header, txs, verifiers, rewards(, bal)]`, what peers are served) written
//! to its own file and synced before the vote. A restart re-imports every
//! journalled block the execution layer does not hold before it serves, votes
//! or builds (`H2Service::restore_block_journal`). See
//! `docs/P1_DURABLE_COMMIT_VOTE.md`.
//!
//! One file per block, `<number>-<hash>.blk`, written to a temporary name,
//! synced, renamed and the directory synced: a crash leaves the file whole or
//! absent, never torn. Each file is `MAGIC ++ parent hash ++ body`. Files at
//! or below the execution layer's persisted height are pruned.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use alloy_primitives::B256;

/// The journal's directory under the validator's datadir.
pub const JOURNAL_DIR: &str = "block-journal";

const MAGIC: &[u8; 8] = b"N42BJ001";
const SUFFIX: &str = ".blk";
const TMP_SUFFIX: &str = ".tmp";

/// A journal error: an I/O failure on `path`, or a file that is not a
/// journal record.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The file system refused.
    #[error("block journal {path}: {source}")]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
    /// A record file that does not parse.
    #[error("block journal {path}: not a journal record")]
    Corrupt {
        /// The file.
        path: PathBuf,
    },
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> JournalError + '_ {
    move |source| JournalError::Io { path: path.to_owned(), source }
}

/// One journalled block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    /// The block number.
    pub number: u64,
    /// The block hash.
    pub hash: B256,
    /// The parent's hash.
    pub parent: B256,
    /// The wire body.
    pub body: alloy_primitives::Bytes,
}

/// The journal: what is on disk, indexed by hash.
#[derive(Debug)]
pub struct BlockJournal {
    dir: PathBuf,
    /// Hash -> (number, parent).
    index: HashMap<B256, (u64, B256)>,
    /// Number -> hashes at it, for pruning in height order.
    by_number: BTreeMap<u64, Vec<B256>>,
}

impl BlockJournal {
    /// Opens (creating) the journal in `dir`, indexing what is there and
    /// removing temporary files a crash left behind.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(io(&dir))?;
        let mut journal = Self { dir, index: HashMap::new(), by_number: BTreeMap::new() };
        for entry in fs::read_dir(&journal.dir).map_err(io(&journal.dir))? {
            let entry = entry.map_err(io(&journal.dir))?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            if name.ends_with(TMP_SUFFIX) {
                // An append that did not finish: its vote never went out.
                let _ = fs::remove_file(&path);
                continue;
            }
            let Some((number, hash)) = parse_name(name) else { continue };
            let parent = read_parent(&path)?;
            journal.note(number, hash, parent);
        }
        Ok(journal)
    }

    fn note(&mut self, number: u64, hash: B256, parent: B256) {
        if self.index.insert(hash, (number, parent)).is_none() {
            self.by_number.entry(number).or_default().push(hash);
        }
    }

    /// Where the journal lives.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether `hash` is journalled.
    pub fn contains(&self, hash: &B256) -> bool {
        self.index.contains_key(hash)
    }

    /// The number and parent of a journalled block.
    pub fn get(&self, hash: &B256) -> Option<(u64, B256)> {
        self.index.get(hash).copied()
    }

    /// How many blocks are journalled.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether nothing is journalled.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    fn path_of(&self, number: u64, hash: &B256) -> PathBuf {
        self.dir.join(format!("{number:020}-{hash:x}{SUFFIX}"))
    }

    /// Writes `body` as block `hash` and syncs it (file and directory)
    /// before returning. A block already journalled is not written again.
    pub fn append(&mut self, number: u64, hash: B256, parent: B256, body: &[u8]) -> Result<(), JournalError> {
        if self.contains(&hash) {
            return Ok(());
        }
        let path = self.path_of(number, &hash);
        let tmp = path.with_extension(&TMP_SUFFIX[1..]);
        {
            let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(&tmp).map_err(io(&tmp))?;
            file.write_all(MAGIC).map_err(io(&tmp))?;
            file.write_all(parent.as_slice()).map_err(io(&tmp))?;
            file.write_all(body).map_err(io(&tmp))?;
            file.sync_all().map_err(io(&tmp))?;
        }
        fs::rename(&tmp, &path).map_err(io(&path))?;
        File::open(&self.dir).and_then(|dir| dir.sync_all()).map_err(io(&self.dir))?;
        self.note(number, hash, parent);
        Ok(())
    }

    /// Every journalled block, lowest number first.
    pub fn entries(&self) -> Result<Vec<JournalEntry>, JournalError> {
        let mut out = Vec::with_capacity(self.index.len());
        for (number, hashes) in &self.by_number {
            for hash in hashes {
                let path = self.path_of(*number, hash);
                let bytes = fs::read(&path).map_err(io(&path))?;
                if bytes.len() < MAGIC.len() + 32 || &bytes[..MAGIC.len()] != MAGIC {
                    return Err(JournalError::Corrupt { path });
                }
                let parent = B256::from_slice(&bytes[MAGIC.len()..MAGIC.len() + 32]);
                out.push(JournalEntry {
                    number: *number,
                    hash: *hash,
                    parent,
                    body: alloy_primitives::Bytes::copy_from_slice(&bytes[MAGIC.len() + 32..]),
                });
            }
        }
        Ok(out)
    }

    /// Removes every block at or below `number`: the execution layer has
    /// persisted that height, so a restart finds those blocks there. Returns
    /// how many were removed.
    pub fn prune_at_or_below(&mut self, number: u64) -> usize {
        let keep = self.by_number.split_off(&number.saturating_add(1));
        let gone = std::mem::replace(&mut self.by_number, keep);
        let mut removed = 0;
        for (n, hashes) in gone {
            for hash in hashes {
                let _ = fs::remove_file(self.path_of(n, &hash));
                self.index.remove(&hash);
                removed += 1;
            }
        }
        removed
    }
}

fn parse_name(name: &str) -> Option<(u64, B256)> {
    let stem = name.strip_suffix(SUFFIX)?;
    let (number, hash) = stem.split_once('-')?;
    let number = number.parse().ok()?;
    let hash = hash.parse().ok()?;
    Some((number, hash))
}

fn read_parent(path: &Path) -> Result<B256, JournalError> {
    use std::io::Read;
    let mut head = [0u8; 40];
    let mut file = File::open(path).map_err(io(path))?;
    file.read_exact(&mut head).map_err(|_| JournalError::Corrupt { path: path.to_owned() })?;
    if &head[..MAGIC.len()] != MAGIC {
        return Err(JournalError::Corrupt { path: path.to_owned() });
    }
    Ok(B256::from_slice(&head[MAGIC.len()..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("n42-block-journal-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn appended_blocks_survive_a_reopen_and_prune_by_height() {
        let dir = scratch("reopen");
        let (a, b, c) = (B256::repeat_byte(1), B256::repeat_byte(2), B256::repeat_byte(3));
        {
            let mut j = BlockJournal::open(&dir).expect("open");
            j.append(5, a, B256::ZERO, b"five").expect("append");
            j.append(6, b, a, b"six").expect("append");
            j.append(6, c, a, b"six-sibling").expect("append");
            j.append(6, b, a, b"ignored").expect("a second append is a no-op");
            // A crash mid-append leaves a temporary file only.
            fs::write(dir.join("00000000000000000007-ab.tmp"), b"half").expect("tmp");
        }
        let mut j = BlockJournal::open(&dir).expect("reopen");
        assert_eq!(j.len(), 3);
        assert_eq!(j.get(&b), Some((6, a)));
        let entries = j.entries().expect("entries");
        assert_eq!(entries[0], JournalEntry { number: 5, hash: a, parent: B256::ZERO, body: b"five".to_vec().into() });
        assert_eq!(entries.iter().map(|e| e.number).collect::<Vec<_>>(), vec![5, 6, 6]);
        assert!(entries.iter().any(|e| e.hash == b && e.body.as_ref() == b"six"));
        assert!(!dir.join("00000000000000000007-ab.tmp").exists(), "the torn append is cleaned up");
        assert_eq!(j.prune_at_or_below(5), 1);
        assert!(!j.contains(&a));
        assert_eq!(j.prune_at_or_below(4), 0);
        let j = BlockJournal::open(&dir).expect("reopen after prune");
        assert_eq!(j.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_without_the_magic_is_refused() {
        let dir = scratch("corrupt");
        fs::create_dir_all(&dir).expect("dir");
        let hash = B256::repeat_byte(9);
        fs::write(dir.join(format!("{:020}-{hash:x}{SUFFIX}", 3)), [0u8; 64]).expect("write");
        assert!(matches!(BlockJournal::open(&dir), Err(JournalError::Corrupt { .. })));
        let _ = fs::remove_dir_all(&dir);
    }
}
