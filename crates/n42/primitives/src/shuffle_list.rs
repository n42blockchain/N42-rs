// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::Hash256;
use ethereum_hashing::hash_fixed;
use std::mem;

const SEED_SIZE: usize = 32;
const ROUND_SIZE: usize = 1;
const POSITION_WINDOW_SIZE: usize = 4;
const PIVOT_VIEW_SIZE: usize = SEED_SIZE + ROUND_SIZE;
const TOTAL_SIZE: usize = SEED_SIZE + ROUND_SIZE + POSITION_WINDOW_SIZE;

/// A helper struct to manage the buffer used during shuffling.
struct Buf([u8; TOTAL_SIZE]);

impl Buf {
    /// Create a new buffer from the given `seed`.
    ///
    /// ## Panics
    ///
    /// Panics if `seed.len() != 32`.
    fn new(seed: &[u8]) -> Self {
        let mut buf = [0; TOTAL_SIZE];
        buf[0..SEED_SIZE].copy_from_slice(seed);
        Self(buf)
    }

    /// Set the shuffling round.
    fn set_round(&mut self, round: u8) {
        self.0[SEED_SIZE] = round;
    }

    /// Returns the new pivot. It is "raw" because it has not modulo the list size (this must be
    /// done by the caller).
    fn raw_pivot(&self) -> u64 {
        let digest = hash_fixed(&self.0[0..PIVOT_VIEW_SIZE]);

        let mut bytes = [0; mem::size_of::<u64>()];
        bytes[..].copy_from_slice(&digest[0..mem::size_of::<u64>()]);
        u64::from_le_bytes(bytes)
    }

    /// Add the current position into the buffer.
    fn mix_in_position(&mut self, position: usize) {
        self.0[PIVOT_VIEW_SIZE..].copy_from_slice(&position.to_le_bytes()[0..POSITION_WINDOW_SIZE]);
    }

    /// Hash the entire buffer.
    fn hash(&self) -> Hash256 {
        Hash256::from(hash_fixed(&self.0))
    }
}

/// Shuffles an entire list in-place.
///
/// Note: this is equivalent to the `compute_shuffled_index` function, except it shuffles an entire
/// list not just a single index. With large lists this function has been observed to be 250x
/// faster than running `compute_shuffled_index` across an entire list.
///
/// Credits to [@protolambda](https://github.com/protolambda) for defining this algorithm.
///
/// Shuffles if `forwards == true`, otherwise un-shuffles.
/// It holds that: shuffle_list(shuffle_list(l, r, s, true), r, s, false) == l
///           and: shuffle_list(shuffle_list(l, r, s, false), r, s, true) == l
///
/// The Eth2.0 spec mostly uses shuffling with `forwards == false`, because backwards
/// shuffled lists are slightly easier to specify, and slightly easier to compute.
///
/// The forwards shuffling of a list is equivalent to:
///
/// `[indices[x] for i in 0..n, where compute_shuffled_index(x) = i]`
///
/// Whereas the backwards shuffling of a list is:
///
/// `[indices[compute_shuffled_index(i)] for i in 0..n]`
///
/// Returns `None` under any of the following conditions:
///  - `list_size == 0`
///  - `list_size > 2**24`
///  - `list_size > usize::MAX / 2`
pub fn shuffle_list(
    mut input: Vec<usize>,
    rounds: u8,
    seed: &[u8],
    forwards: bool,
) -> Option<Vec<usize>> {
    let list_size = input.len();

    if input.is_empty() || list_size > usize::MAX / 2 || list_size > 2_usize.pow(24) || rounds == 0
    {
        return None;
    }

    let mut buf = Buf::new(seed);

    let mut r = if forwards { 0 } else { rounds - 1 };

    loop {
        buf.set_round(r);

        let pivot = buf.raw_pivot() as usize % list_size;

        let mirror = (pivot + 1) >> 1;

        buf.mix_in_position(pivot >> 8);
        let mut source = buf.hash();
        let mut byte_v = source[(pivot & 0xff) >> 3];

        for i in 0..mirror {
            let j = pivot - i;

            if j & 0xff == 0xff {
                buf.mix_in_position(j >> 8);
                source = buf.hash();
            }

            if j & 0x07 == 0x07 {
                byte_v = source[(j & 0xff) >> 3];
            }
            let bit_v = (byte_v >> (j & 0x07)) & 0x01;

            if bit_v == 1 {
                input.swap(i, j);
            }
        }

        let mirror = (pivot + list_size + 1) >> 1;
        let end = list_size - 1;

        buf.mix_in_position(end >> 8);
        let mut source = buf.hash();
        let mut byte_v = source[(end & 0xff) >> 3];

        for (loop_iter, i) in ((pivot + 1)..mirror).enumerate() {
            let j = end - loop_iter;

            if j & 0xff == 0xff {
                buf.mix_in_position(j >> 8);
                source = buf.hash();
            }

            if j & 0x07 == 0x07 {
                byte_v = source[(j & 0xff) >> 3];
            }
            let bit_v = (byte_v >> (j & 0x07)) & 0x01;

            if bit_v == 1 {
                input.swap(i, j);
            }
        }

        if forwards {
            r += 1;
            if r == rounds {
                break;
            }
        } else {
            if r == 0 {
                break;
            }
            r -= 1;
        }
    }

    Some(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_none_for_zero_length_list() {
        assert_eq!(None, shuffle_list(vec![], 90, &[42, 42], true));
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn sanity_check_constants() {
        assert!(TOTAL_SIZE > SEED_SIZE);
        assert!(TOTAL_SIZE > PIVOT_VIEW_SIZE);
        assert!(mem::size_of::<usize>() >= POSITION_WINDOW_SIZE);
    }

    const SEED: [u8; 32] = [7; 32];

    #[test]
    fn returns_none_for_zero_rounds() {
        assert_eq!(None, shuffle_list(vec![1, 2, 3], 0, &SEED, true));
        assert_eq!(None, shuffle_list(vec![1, 2, 3], 0, &SEED, false));
    }

    #[test]
    fn single_element_list_is_unchanged() {
        assert_eq!(Some(vec![5]), shuffle_list(vec![5], 10, &SEED, true));
        assert_eq!(Some(vec![5]), shuffle_list(vec![5], 10, &SEED, false));
    }

    #[test]
    fn shuffle_is_a_permutation_for_all_sizes_around_window_boundaries() {
        // Sizes straddle the 256-entry hash window so the re-hash branches are taken.
        for n in [2usize, 3, 10, 255, 256, 257, 300, 513, 1000] {
            let input: Vec<usize> = (0..n).collect();
            let out = shuffle_list(input.clone(), 10, &SEED, false).unwrap();
            let mut sorted = out.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, input, "not a permutation for n={n}");
        }
    }

    #[test]
    fn forwards_and_backwards_are_inverses() {
        for n in [2usize, 17, 256, 300, 777] {
            let input: Vec<usize> = (0..n).collect();
            let fwd = shuffle_list(input.clone(), 10, &SEED, true).unwrap();
            let back = shuffle_list(fwd, 10, &SEED, false).unwrap();
            assert_eq!(back, input, "forwards then backwards must round trip, n={n}");

            let bwd = shuffle_list(input.clone(), 10, &SEED, false).unwrap();
            let back = shuffle_list(bwd, 10, &SEED, true).unwrap();
            assert_eq!(back, input, "backwards then forwards must round trip, n={n}");
        }
    }

    #[test]
    fn shuffle_actually_moves_elements_and_depends_on_seed_and_rounds() {
        let input: Vec<usize> = (0..100).collect();
        let a = shuffle_list(input.clone(), 10, &SEED, false).unwrap();
        assert_ne!(a, input);

        // Deterministic.
        assert_eq!(a, shuffle_list(input.clone(), 10, &SEED, false).unwrap());

        // Different seed and different round counts produce different permutations.
        let other_seed = shuffle_list(input.clone(), 10, &[8; 32], false).unwrap();
        assert_ne!(a, other_seed);
        let fewer_rounds = shuffle_list(input.clone(), 3, &SEED, false).unwrap();
        assert_ne!(a, fewer_rounds);

        // Forwards and backwards shuffles of the same input differ.
        let fwd = shuffle_list(input, 10, &SEED, true).unwrap();
        assert_ne!(a, fwd);
    }

    #[test]
    fn shuffle_preserves_arbitrary_values() {
        let input = vec![100usize, 7, 3000, 42, 9];
        let out = shuffle_list(input.clone(), 10, &SEED, false).unwrap();
        let mut a = input;
        let mut b = out;
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a, b);
    }
}
