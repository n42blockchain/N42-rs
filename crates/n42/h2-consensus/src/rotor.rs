use sha2::{Digest, Sha256};

/// Default number of relay nodes selected per view.
const DEFAULT_RELAY_COUNT: usize = 3;

/// Assignment of relay nodes and their propagation targets for a given view.
#[derive(Debug, Clone)]
pub struct RelayAssignment {
    /// Each entry is `(relay_index, target_indices)` where `relay_index` is a
    /// validator index acting as relay, and `target_indices` are the validators
    /// it must forward blocks to (including itself).
    pub relays: Vec<(u32, Vec<u32>)>,
}

/// Deterministically select relay nodes and assign propagation targets.
///
/// # Algorithm
///
/// 1. Build a candidate list of all validator indices except the leader.
/// 2. Compute `seed = SHA256(view_le_bytes)`.
/// 3. Fisher-Yates shuffle the candidate list using deterministic randomness
///    derived from the seed.
/// 4. The first `relay_count` candidates become relay nodes.
/// 5. Remaining candidates are round-robin distributed across the relays.
///    Each relay also includes itself in its target list.
pub fn compute_relay_assignment(
    view: u64,
    validator_count: u32,
    leader: u32,
    relay_count: usize,
) -> RelayAssignment {
    // Build candidate list: all validators except the leader.
    let mut candidates: Vec<u32> = (0..validator_count).filter(|&i| i != leader).collect();
    let n = candidates.len();

    if n == 0 {
        return RelayAssignment { relays: vec![] };
    }

    let effective_relay_count = relay_count.min(n);

    // Deterministic seed from view number.
    let seed: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(view.to_le_bytes());
        hasher.finalize().into()
    };

    // Fisher-Yates shuffle with deterministic randomness.
    for i in (1..n).rev() {
        let pos_hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update((i as u64).to_le_bytes());
            hasher.finalize().into()
        };
        let j = u64::from_le_bytes(pos_hash[..8].try_into().expect("SHA256 always 32 bytes"))
            % (i as u64 + 1);
        candidates.swap(i, j as usize);
    }

    // First `effective_relay_count` become relays; rest are non-relay targets.
    let relay_indices: Vec<u32> = candidates[..effective_relay_count].to_vec();
    let remaining: Vec<u32> = candidates[effective_relay_count..].to_vec();

    // Initialise each relay's target list with itself.
    let mut targets: Vec<Vec<u32>> = relay_indices.iter().map(|&r| vec![r]).collect();

    // Round-robin assign remaining candidates to relays.
    for (idx, &candidate) in remaining.iter().enumerate() {
        targets[idx % effective_relay_count].push(candidate);
    }

    RelayAssignment {
        relays: relay_indices.into_iter().zip(targets).collect(),
    }
}

/// Convenience wrapper using the default relay count (3).
pub fn compute_default_relay_assignment(
    view: u64,
    validator_count: u32,
    leader: u32,
) -> RelayAssignment {
    compute_relay_assignment(view, validator_count, leader, DEFAULT_RELAY_COUNT)
}

/// Cached relay assignment using the default relay count (3).
/// Avoids recomputing ~500 SHA256 hashes per call. Caches last 8 views.
pub fn cached_relay_assignment(
    view: u64,
    validator_count: u32,
    leader: u32,
    relay_count: usize,
) -> RelayAssignment {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    type CacheEntry = (u64, u32, u32, usize, RelayAssignment);
    static CACHE: Mutex<Option<VecDeque<CacheEntry>>> = Mutex::new(None);
    const MAX_CACHE: usize = 8;

    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_with(VecDeque::new);

    if let Some(entry) = cache.iter().find(|(v, vc, l, rc, _)| {
        *v == view && *vc == validator_count && *l == leader && *rc == relay_count
    }) {
        return entry.4.clone();
    }

    let assignment = compute_relay_assignment(view, validator_count, leader, relay_count);
    if cache.len() >= MAX_CACHE {
        cache.pop_front();
    }
    cache.push_back((
        view,
        validator_count,
        leader,
        relay_count,
        assignment.clone(),
    ));
    assignment
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_relay_assignment_deterministic() {
        let a = compute_relay_assignment(42, 21, 0, 3);
        let b = compute_relay_assignment(42, 21, 0, 3);

        assert_eq!(a.relays.len(), b.relays.len());
        for (ra, rb) in a.relays.iter().zip(b.relays.iter()) {
            assert_eq!(ra.0, rb.0);
            assert_eq!(ra.1, rb.1);
        }
    }

    #[test]
    fn test_relay_covers_all_validators() {
        let validator_count = 21u32;
        let leader = 5u32;
        let assignment = compute_relay_assignment(100, validator_count, leader, 3);

        // Collect all validator indices that appear in any target list.
        let mut covered: HashSet<u32> = HashSet::new();
        for (_, targets) in &assignment.relays {
            for &t in targets {
                assert!(covered.insert(t), "validator {t} appears more than once");
            }
        }

        // Every non-leader validator must appear exactly once.
        let expected: HashSet<u32> = (0..validator_count).filter(|&i| i != leader).collect();
        assert_eq!(covered, expected);
    }

    #[test]
    fn test_single_node_empty() {
        let assignment = compute_relay_assignment(0, 1, 0, 3);
        assert!(assignment.relays.is_empty());
    }

    #[test]
    fn test_different_views_different_relays() {
        let a = compute_relay_assignment(1, 21, 0, 3);
        let b = compute_relay_assignment(2, 21, 0, 3);

        let relays_a: Vec<u32> = a.relays.iter().map(|(r, _)| *r).collect();
        let relays_b: Vec<u32> = b.relays.iter().map(|(r, _)| *r).collect();

        // With 20 candidates and SHA256-based shuffling, different views should
        // produce different relay selections with overwhelming probability.
        assert_ne!(relays_a, relays_b);
    }

    #[test]
    fn test_leader_excluded() {
        let leader = 7u32;
        let assignment = compute_relay_assignment(999, 21, leader, 3);

        for (relay, targets) in &assignment.relays {
            assert_ne!(*relay, leader, "leader should not be a relay");
            for &t in targets {
                assert_ne!(t, leader, "leader should not appear in target list");
            }
        }
    }
}
