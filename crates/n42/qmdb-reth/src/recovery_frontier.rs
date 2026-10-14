//! A bounded, checksummed parent-root frontier for compacted depth-two checkpoints.

use alloy_primitives::{B256, keccak256};
use bincode::Options;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Frontier {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub parent_root: B256,
}

#[derive(Serialize, Deserialize)]
struct File {
    version: u32,
    chain_id: u64,
    genesis: B256,
    // Keep the previous checkpoint while its replacement is being written,
    // plus room for an interrupted compaction and startup migration.
    records: [Option<Frontier>; 4],
}

pub(crate) fn decode(bytes: &[u8], chain_id: u64, genesis: B256) -> Result<[Option<Frontier>; 4], String> {
    if bytes.len() < 32 || bytes.len() > 1024 {
        return Err("invalid frontier file size".into());
    }
    let (digest, payload) = bytes.split_at(32);
    if digest != keccak256(payload).as_slice() {
        return Err("frontier checksum mismatch".into());
    }
    let file: File = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(1024)
        .reject_trailing_bytes()
        .deserialize(payload)
        .map_err(|err| err.to_string())?;
    if file.version != 1 || file.chain_id != chain_id || file.genesis != genesis {
        return Err("frontier version or chain identity mismatch".into());
    }
    for (i, record) in file.records.iter().enumerate() {
        if let Some(record) = record {
            if record.number == 0 {
                return Err("frontier has no parent".into());
            }
            if file.records[..i].iter().flatten().any(|other| other.hash == record.hash) {
                return Err("duplicate frontier checkpoint".into());
            }
        }
    }
    Ok(file.records)
}

pub(crate) fn update(previous: Option<&[u8]>, chain_id: u64, genesis: B256, record: Frontier) -> Result<Vec<u8>, String> {
    if record.number == 0 {
        return Err("frontier has no parent".into());
    }
    let mut records = match previous {
        Some(bytes) => decode(bytes, chain_id, genesis)?,
        None => [None; 4],
    };
    if let Some(existing) = records.iter().flatten().find(|other| other.hash == record.hash) {
        if *existing != record {
            return Err("conflicting roots for a checkpoint".into());
        }
        return Ok(previous.expect("existing record has a file").to_vec());
    }
    records.rotate_left(1);
    records[3] = Some(record);
    let payload = bincode::serialize(&File { version: 1, chain_id, genesis, records }).map_err(|err| err.to_string())?;
    let mut bytes = keccak256(&payload).to_vec();
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(n: u8) -> Frontier {
        Frontier {
            number: n.into(),
            hash: B256::repeat_byte(n),
            parent_hash: B256::repeat_byte(n - 1),
            parent_root: B256::repeat_byte(n + 10),
        }
    }

    #[test]
    fn replacing_a_checkpoint_keeps_its_previous_frontier_and_bounds_the_file() {
        let genesis = B256::repeat_byte(99);
        let mut bytes = update(None, 1144, genesis, record(1)).unwrap();
        bytes = update(Some(&bytes), 1144, genesis, record(2)).unwrap();
        assert!(decode(&bytes, 1144, genesis).unwrap().contains(&Some(record(1))));
        for n in 3..20 {
            bytes = update(Some(&bytes), 1144, genesis, record(n)).unwrap();
        }
        assert_eq!(decode(&bytes, 1144, genesis).unwrap(), [Some(record(16)), Some(record(17)), Some(record(18)), Some(record(19))]);
        assert!(bytes.len() <= 1024);
    }

    #[test]
    fn corruption_wrong_chain_and_conflicting_roots_are_rejected() {
        let genesis = B256::repeat_byte(99);
        let bytes = update(None, 1144, genesis, record(1)).unwrap();
        assert!(decode(&bytes, 1144, B256::repeat_byte(100)).is_err());
        assert!(decode(&bytes, 1143, genesis).is_err());
        for end in [0, 31, bytes.len() - 1] {
            assert!(decode(&bytes[..end], 1144, genesis).is_err());
        }
        let mut corrupt = bytes.clone();
        corrupt[40] ^= 1;
        assert!(decode(&corrupt, 1144, genesis).is_err());
        let mut conflicting = record(1);
        conflicting.parent_root = B256::ZERO;
        assert!(update(Some(&bytes), 1144, genesis, conflicting).is_err());
        assert_eq!(update(Some(&bytes), 1144, genesis, record(1)).unwrap(), bytes);
        let mut payload = bytes[32..].to_vec();
        payload.push(0);
        let mut trailing = keccak256(&payload).to_vec();
        trailing.extend_from_slice(&payload);
        assert!(decode(&trailing, 1144, genesis).is_err());
    }
}
