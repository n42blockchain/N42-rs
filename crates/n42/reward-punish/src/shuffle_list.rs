use std::mem;
use ethereum_hashing::hash_fixed;
use crate::Hash256;



const SEED_SIZE: usize = 32;
const ROUND_SIZE: usize = 1;
const POSITION_WINDOW_SIZE: usize = 4;
const PIVOT_VIEW_SIZE: usize = SEED_SIZE + ROUND_SIZE;
const TOTAL_SIZE: usize = SEED_SIZE + ROUND_SIZE + POSITION_WINDOW_SIZE;
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