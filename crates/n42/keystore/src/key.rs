use sha2::{Digest, Sha256};
use zeroize::Zeroize;
use ring::hkdf::{KeyType, Prk, Salt, HKDF_SHA256};
use num_bigint_dig::BigUint;
use crate::keystore::{Error, SecretBytes, HASH_SIZE, MOD_R_L};
// use n42_withdrawals::crypto::ZeroizeHash;
use crate::blst::ZeroizeHash;

pub const LAMPORT_ARRAY_SIZE: u8 = 255;
/// The order of the BLS 12-381 curve.
pub const R: &str = "52435875175126190479447740508185965837690552500527637822603658699938581184513";

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey(ZeroizeHash);
impl DerivedKey {
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        if seed.is_empty() {
            Err(Error::EmptySeed)
        } else {
            Ok(Self(derive_master_sk(seed)))
        }
    }

    /// Returns the secret BLS key in `self`.
    pub fn secret(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Derives a child key from the secret `Self` at some `index`.
    pub fn child(&self, index: u32) -> DerivedKey {
        Self(derive_child_sk(self.0.as_bytes(), index))
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct LamportSecretKey(Vec<[u8; HASH_SIZE]>);
impl LamportSecretKey {
    pub fn zero() -> Self {
        Self(vec![[0; HASH_SIZE]; LAMPORT_ARRAY_SIZE as usize])
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            HASH_SIZE * LAMPORT_ARRAY_SIZE as usize,
            "incorrect byte length"
        );

        let mut this = Self::zero();

        for i in 0..LAMPORT_ARRAY_SIZE {
            let iu = i as usize;
            this.get_mut_chunk(i)
                .copy_from_slice(&bytes[iu * HASH_SIZE..(iu + 1) * HASH_SIZE])
        }

        this
    }

    pub fn get_mut_chunk(&mut self, i: u8) -> &mut [u8] {
        &mut self.0[i as usize]
    }

    pub fn iter_chunks(&self) -> impl Iterator<Item = &[u8; HASH_SIZE]> {
        self.0.iter()
    }
}

/// Derives the "master" BLS secret key from some `seed` bytes.
fn derive_master_sk(seed: &[u8]) -> ZeroizeHash {
    hkdf_mod_r(seed)
}

fn hkdf_mod_r(ikm: &[u8]) -> ZeroizeHash {
    // ikm = ikm + I2OSP(0,1)
    let mut ikm_with_postfix = SecretBytes::zero(ikm.len() + 1);
    ikm_with_postfix.as_mut_bytes()[..ikm.len()].copy_from_slice(ikm);

    // info = "" + I2OSP(L, 2)
    let info = u16::try_from(MOD_R_L)
        .expect("MOD_R_L too large")
        .to_be_bytes();

    let mut output = ZeroizeHash::zero();
    let zero_hash = ZeroizeHash::zero();

    let mut salt = b"BLS-SIG-KEYGEN-SALT-".to_vec();
    while output.as_bytes() == zero_hash.as_bytes() {
        let mut hasher = Sha256::new();
        hasher.update(salt.as_slice());
        salt = hasher.finalize().to_vec();

        let prk = hkdf_extract(&salt, ikm_with_postfix.as_bytes());
        let okm = &hkdf_expand(prk, &info, MOD_R_L);

        output = mod_r(okm.as_bytes());
    }
    output
}

/// From the given `parent_sk`, derives a child key at index`.
fn derive_child_sk(parent_sk: &[u8], index: u32) -> ZeroizeHash {
    let compressed_lamport_pk = parent_sk_to_lamport_pk(parent_sk, index);
    hkdf_mod_r(compressed_lamport_pk.as_bytes())
}

/// Generates a Lamport public key from the given `ikm` (which is assumed to be a BLS secret key).
///
/// Equivalent to `parent_SK_to_lamport_PK` in EIP-2333.
fn parent_sk_to_lamport_pk(ikm: &[u8], index: u32) -> ZeroizeHash {
    let salt = index.to_be_bytes();
    let not_ikm = flip_bits(ikm);

    let lamports = [
        ikm_to_lamport_sk(&salt, ikm),
        ikm_to_lamport_sk(&salt, not_ikm.as_bytes()),
    ];

    let mut lamport_pk = SecretBytes::zero(HASH_SIZE * LAMPORT_ARRAY_SIZE as usize * 2);
    let pk_bytes = lamport_pk.as_mut_bytes();

    lamports
        .iter()
        .flat_map(LamportSecretKey::iter_chunks)
        .enumerate()
        .for_each(|(i, chunk)| {
            let mut hasher = Sha256::new();
            hasher.update(chunk);
            pk_bytes[i * HASH_SIZE..(i + 1) * HASH_SIZE].copy_from_slice(&hasher.finalize());
        });

    let mut compressed_lamport_pk = ZeroizeHash::zero();
    let mut hasher = Sha256::new();
    hasher.update(lamport_pk.as_bytes());
    compressed_lamport_pk
        .as_mut_bytes()
        .copy_from_slice(&hasher.finalize());

    compressed_lamport_pk
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Prk {
    Salt::new(HKDF_SHA256, salt).extract(ikm)
}

fn hkdf_expand(prk: Prk, info: &[u8], l: usize) -> SecretBytes {
    struct ExpandLen(usize);

    impl KeyType for ExpandLen {
        fn len(&self) -> usize {
            self.0
        }
    }

    let mut okm = SecretBytes::zero(l);
    prk.expand(&[info], ExpandLen(l))
        .expect("expand len is constant and cannot be too large")
        .fill(okm.as_mut_bytes())
        .expect("fill len is constant and cannot be too large");
    okm
}

fn mod_r(bytes: &[u8]) -> ZeroizeHash {
    let n = BigUint::from_bytes_be(bytes);
    let r = BigUint::parse_bytes(R.as_bytes(), 10).expect("must be able to parse R");
    let x = SecretBytes::from((n % r).to_bytes_be());

    let x_slice = x.as_bytes();

    debug_assert!(x_slice.len() <= HASH_SIZE);

    let mut output = ZeroizeHash::zero();
    output.as_mut_bytes()[HASH_SIZE - x_slice.len()..].copy_from_slice(x_slice);
    output
}

fn flip_bits(input: &[u8]) -> ZeroizeHash {
    assert_eq!(input.len(), HASH_SIZE);

    let mut output = ZeroizeHash::zero();
    let output_bytes = output.as_mut_bytes();

    for (i, byte) in input.iter().enumerate() {
        output_bytes[i] = !byte
    }

    output
}

/// Generates a Lamport secret key from the `ikm` (initial key material).
///
/// Equivalent to `IKM_to_lamport_SK` in EIP-2333.
fn ikm_to_lamport_sk(salt: &[u8], ikm: &[u8]) -> LamportSecretKey {
    let prk = hkdf_extract(salt, ikm);
    let okm = hkdf_expand(prk, &[], HASH_SIZE * LAMPORT_ARRAY_SIZE as usize);
    LamportSecretKey::from_bytes(okm.as_bytes())
}