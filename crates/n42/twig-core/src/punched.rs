// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `entries.punched`: the byte ranges of the entry files a compaction has
//! punched (`docs/QMDB_COMPACTION_DESIGN.md` 3.5, stage 3).
//!
//! A punched range reads as zeros and the file keeps its length, so a walk of
//! `entries.log` (or of `entries.relocated`) has to know where the holes are
//! to skip them. They are kept in a file of their own beside the entry files,
//! not in the checkpoint: every opening needs them -- a restart, but also a
//! read-only open at an archived checkpoint older than the latest punch --
//! and a record here is made durable before its range is punched, so no
//! opening can meet a hole it was not told about.
//!
//! A record is 29 bytes, little endian:
//!
//! ```text
//! [file u8: 0 entries.log, 1 entries.relocated][twig u64][start u64][end u64][crc32 u32]
//! ```
//!
//! with the CRC-32 (IEEE) over the 25 bytes before it. A torn or failing
//! record ends the list (the punch it announced never happened, or happened
//! to a range nothing points at any more); a writable open cuts it off.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use crate::entry_store::FileRange;

/// One record's length.
const RECORD: usize = 1 + 8 + 8 + 8 + 4;

/// A punched range and the twig whose records it held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Punched {
    /// The twig the range held (its 2048 records in `entries.log`, or one of
    /// its earlier groups in `entries.relocated`).
    pub twig: usize,
    /// The range.
    pub range: FileRange,
}

impl Punched {
    fn encode(&self) -> [u8; RECORD] {
        let mut out = [0u8; RECORD];
        out[0] = u8::from(self.range.relocated);
        out[1..9].copy_from_slice(&(self.twig as u64).to_le_bytes());
        out[9..17].copy_from_slice(&self.range.start.to_le_bytes());
        out[17..25].copy_from_slice(&self.range.end.to_le_bytes());
        let crc = crc32fast::hash(&out[..25]);
        out[25..].copy_from_slice(&crc.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8; RECORD]) -> Option<Self> {
        let crc = u32::from_le_bytes(bytes[25..].try_into().ok()?);
        if crc != crc32fast::hash(&bytes[..25]) || bytes[0] > 1 {
            return None;
        }
        let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        let range = FileRange { relocated: bytes[0] == 1, start: word(9), end: word(17) };
        (range.start < range.end).then_some(Self { twig: usize::try_from(word(1)).ok()?, range })
    }
}

/// `entries.punched` beside the main entry file at `main`.
pub(crate) fn punched_path(main: &Path) -> PathBuf {
    main.with_extension("punched")
}

/// The records of the file at `path` (none if it does not exist), and the
/// length of the good prefix they fill.
pub(crate) fn read(path: &Path) -> io::Result<(Vec<Punched>, u64)> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut out = Vec::new();
    for chunk in bytes.as_chunks::<RECORD>().0 {
        let Some(record) = Punched::decode(chunk) else { break };
        out.push(record);
    }
    let good = (out.len() * RECORD) as u64;
    Ok((out, good))
}

/// The append side of `entries.punched`.
#[derive(Debug)]
pub(crate) struct PunchLog {
    path: PathBuf,
    file: Option<File>,
    len: u64,
}

impl PunchLog {
    /// The log at `path`, holding `len` good bytes (from [`read`]); the file
    /// is opened at the first append.
    pub(crate) fn new(path: PathBuf, len: u64) -> Self {
        Self { path, file: None, len }
    }

    /// Cuts a torn or failing tail off, so the next record follows the good
    /// ones.
    pub(crate) fn cut_to_good(&mut self) -> io::Result<()> {
        match OpenOptions::new().write(true).open(&self.path) {
            Ok(file) => {
                if file.metadata()?.len() > self.len {
                    file.set_len(self.len)?;
                    file.sync_data()?;
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Appends `records` and makes them durable: called before their ranges
    /// are punched.
    pub(crate) fn append(&mut self, records: &[Punched]) -> io::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        if self.file.is_none() {
            let file = OpenOptions::new().create(true).append(true).open(&self.path)?;
            if file.metadata()?.len() != self.len {
                file.set_len(self.len)?;
            }
            self.file = Some(file);
            if let Some(dir) = self.path.parent() {
                // The file's name made durable with its first record.
                File::open(dir).and_then(|dir| dir.sync_all())?;
            }
        }
        let file = self.file.as_mut().expect("opened above");
        let mut bytes = Vec::with_capacity(records.len() * RECORD);
        for record in records {
            bytes.extend_from_slice(&record.encode());
        }
        file.write_all(&bytes)?;
        file.sync_data()?;
        self.len += bytes.len() as u64;
        Ok(())
    }

    /// Replaces the whole log with `records` (an open that dropped twigs
    /// past its kept slots), through a temporary file and a rename.
    pub(crate) fn rewrite(&mut self, records: &[Punched]) -> io::Result<()> {
        let tmp = self.path.with_extension("punched.tmp");
        {
            let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
            for record in records {
                file.write_all(&record.encode())?;
            }
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent() {
            File::open(dir).and_then(|dir| dir.sync_all())?;
        }
        self.file = None;
        self.len = (records.len() * RECORD) as u64;
        Ok(())
    }

    /// Removes the log (a store created afresh).
    pub(crate) fn remove(path: &Path) -> io::Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Frees `range` of `file` and makes it read as zeros, the file's length
/// unchanged (`fallocate(PUNCH_HOLE | KEEP_SIZE)`). Where the filesystem
/// cannot punch, the range is overwritten with zeros instead: nothing is
/// freed, but the contract (zeros, same length) holds.
pub(crate) fn punch_hole(file: &File, range: FileRange) -> io::Result<()> {
    if range.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let (Ok(start), Ok(len)) = (libc::off_t::try_from(range.start), libc::off_t::try_from(range.len())) else {
            return Err(io::Error::other("a punched range past off_t"));
        };
        // SAFETY: a plain syscall on an open descriptor with in-range values.
        let rc = unsafe {
            libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE, start, len)
        };
        if rc == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EOPNOTSUPP)) {
            return Err(error);
        }
    }
    zero_fill(file, range)
}

/// Writes zeros over `range` (the fallback of [`punch_hole`]).
fn zero_fill(file: &File, range: FileRange) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        let zeros = vec![0u8; 1 << 20];
        let mut at = range.start;
        while at < range.end {
            let n = ((range.end - at) as usize).min(zeros.len());
            file.write_all_at(&zeros[..n], at)?;
            at += n as u64;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (file, range);
        Err(io::Error::other("punching needs a unix target"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("n42-punched-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("entries.punched")
    }

    #[test]
    fn records_round_trip_and_a_torn_tail_ends_the_list() {
        let path = scratch("round-trip");
        let records = [
            Punched { twig: 3, range: FileRange { relocated: false, start: 10, end: 900 } },
            Punched { twig: 7, range: FileRange { relocated: true, start: 0, end: 41 } },
        ];
        let mut log = PunchLog::new(path.clone(), 0);
        log.append(&records[..1]).unwrap();
        log.append(&records[1..]).unwrap();
        assert_eq!(read(&path).unwrap(), (records.to_vec(), 2 * RECORD as u64));
        // A torn third record, then a writable open cuts it.
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[1, 2, 3]).unwrap();
        drop(file);
        let (read_back, good) = read(&path).unwrap();
        assert_eq!(read_back, records.to_vec());
        let mut log = PunchLog::new(path.clone(), good);
        log.cut_to_good().unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), good);
        log.rewrite(&records[1..]).unwrap();
        assert_eq!(read(&path).unwrap().0, records[1..].to_vec());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_punched_range_reads_as_zeros_and_keeps_the_length() {
        let path = scratch("hole").with_extension("log");
        std::fs::write(&path, vec![7u8; 3 * 4096 + 100]).unwrap();
        let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        punch_hole(&file, FileRange { relocated: false, start: 100, end: 2 * 4096 + 50 }).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 3 * 4096 + 100);
        assert!(bytes[..100].iter().all(|b| *b == 7));
        assert!(bytes[100..2 * 4096 + 50].iter().all(|b| *b == 0));
        assert!(bytes[2 * 4096 + 50..].iter().all(|b| *b == 7));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
