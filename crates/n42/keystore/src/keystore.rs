use n42_withdrawals::crypto::{fake_crypto_implementations::{Keypair, SecretKey}, ZeroizeHash};
use std::{fmt,str};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{NewCipher, StreamCipher};
use aes::Aes128Ctr as AesCtr;
use pbkdf2::pbkdf2;
use hmac::Hmac;
use scrypt::{scrypt, Params as ScryptParams};
use scrypt::errors::{InvalidOutputLen, InvalidParams};
use rand::prelude::*;
use serde_repr::*;
use serde_json::{Map, Value};
pub use uuid::Uuid;
use crate::create::{Wallet};



pub const SECRET_KEY_BYTES_LEN: usize = 32;
pub const PURPOSE: u32 = 12381;
pub const COIN_TYPE: u32 = 3600;
pub const HASH_SIZE: usize = 32;
pub const IV_SIZE: usize = 16;
pub const DKLEN: u32 = 32;
pub const DEFAULT_PBKDF2_C: u32 = 262_144;
pub const SALT_SIZE: usize = 32;
pub const MOD_R_L: usize = 48;
const SECRET_KEY_LEN: usize = 32;


pub struct KeystoreBuilder<'a> {
    keypair: &'a Keypair,
    password: &'a [u8],
    kdf: Kdf,
    cipher: Cipher,
    uuid: Uuid,
    path: String,
    description: String,
}

impl<'a> KeystoreBuilder<'a> {
    pub fn new(keypair: &'a Keypair, password: &'a [u8], path: String) -> Result<Self, Error> {
        if password.is_empty() {
            Err(Error::EmptyPassword)
        } else {
            let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>();
            let iv = rand::thread_rng().gen::<[u8; IV_SIZE]>().to_vec().into();

            Ok(Self {
                keypair,
                password,
                kdf: default_kdf(salt.to_vec()),
                cipher: Cipher::Aes128Ctr(Aes128Ctr { iv }),
                uuid: Uuid::new_v4(),
                path,
                description: "".to_string(),
            })
        }
    }

    /// Consumes `self`, returning a `Keystore`.
    pub fn build(self) -> Result<Keystore, Error> {
        Keystore::encrypt(
            self.keypair,
            self.password,
            self.kdf,
            self.cipher,
            self.uuid,
            self.path,
            self.description,
        )
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Cipher {
    Aes128Ctr(Aes128Ctr),
}
impl Cipher {
    pub fn function(&self) -> CipherFunction {
        match &self {
            Cipher::Aes128Ctr(_) => CipherFunction::Aes128Ctr,
        }
    }
}

/// Parameters for AES128 with ctr mode.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aes128Ctr {
    pub iv: HexBytes,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonWallet {
    pub nextaccount: u32,
    pub crypto: Crypto,
}

/// Contains the two keystores required for an eth2 validator.
pub struct ValidatorKeystores {
    /// Contains the secret key used for signing every-day consensus messages (blocks,
    /// attestations, etc).
    pub voting: Keystore,
    /// Contains the secret key that should eventually be required for withdrawing stacked ETH.
    pub withdrawal: Keystore,
}

/// Use `KeystoreBuilder` to create a new keystore.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Keystore {
    json: JsonKeystore,
}
impl Keystore {
    /// Generate `Keystore` object for a BLS12-381 secret key from a
    /// keypair and password.
    fn encrypt(
        keypair: &Keypair,
        password: &[u8],
        kdf: Kdf,
        cipher: Cipher,
        uuid: Uuid,
        path: String,
        description: String,
    ) -> Result<Self, Error> {
        let secret: ZeroizeHash = keypair.sk.serialize();

        let (cipher_text, checksum) = encrypt(secret.as_bytes(), password, &kdf, &cipher)?;

        Ok(Keystore {
            json: JsonKeystore {
                crypto: Crypto {
                    kdf: KdfModule {
                        function: kdf.function(),
                        params: kdf,
                        message: EmptyString,
                    },
                    checksum: ChecksumModule {
                        function: Sha256Checksum::function(),
                        params: EmptyMap,
                        message: checksum.to_vec().into(),
                    },
                    cipher: CipherModule {
                        function: cipher.function(),
                        params: cipher,
                        message: cipher_text.into(),
                    },
                },
                uuid,
                path: Some(path),
                pubkey: keypair.pk.as_hex_string()[2..].to_string(),
                version: Version::four(),
                description: Some(description),
                name: None,
            },
        })
    }

    /// Regenerate a BLS12-381 `Keypair` from `self` and the correct password.
    /// - The provided password is incorrect.
    /// - The keystore is badly formed.
    /// May panic if provided unreasonable crypto parameters.
    pub fn decrypt_keypair(&self, password: &[u8]) -> Result<Keypair, Error> {
        let plain_text = decrypt(password, &self.json.crypto)?;

        // Verify that secret key material is correct length.
        if plain_text.len() != SECRET_KEY_LEN {
            return Err(Error::InvalidSecretKeyLen {
                len: plain_text.len(),
                expected: SECRET_KEY_LEN,
            });
        }

        let keypair = keypair_from_secret(plain_text.as_bytes())?;
        // Verify that the derived `PublicKey` matches `self`.
        if keypair.pk.as_hex_string()[2..] != self.json.pubkey {
            return Err(Error::PublicKeyMismatch);
        }

        Ok(keypair)
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Sha256Checksum(String);
impl Sha256Checksum {
    pub fn function() -> ChecksumFunction {
        ChecksumFunction::Sha256
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonKeystore {
    pub crypto: Crypto,
    pub uuid: Uuid,
    /// EIP-2335 does not declare this field as optional, but Prysm is omitting it so we must
    /// support it.
    pub path: Option<String>,
    pub pubkey: String,
    pub version: Version,
    pub description: Option<String>,
    /// Not part of EIP-2335, but `ethdo` and Prysm have adopted it anyway so we must support it.
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Version {
    V4 = 4,
}
impl Version {
    pub fn four() -> Self {
        Version::V4
    }
}

pub enum KeyType {
    Voting,
    Withdrawal,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPasswordBytes,
    PathExhausted,
    EmptySeed,
    InvalidPassword,
    IncorrectIvSize { expected: usize, len: usize },
    InvalidPbkdf2Param,
    InvalidSaltLength,
    InvalidScryptParam,
    ScryptInvalidParams(InvalidParams),
    ScryptInvaidOutputLen(InvalidOutputLen),
    EmptyPassword,
    InvalidSecretKeyBytes(n42_withdrawals::error::Error),
    InvalidSecretKeyLen { len: usize, expected: usize },
    PublicKeyMismatch,

}


#[derive(Zeroize, Clone, PartialEq)]
#[zeroize(drop)]
pub struct PlainText(Vec<u8>);

impl PlainText {
    /// Returns a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns a mutable reference to the underlying bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// The byte-length of `self`
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<Vec<u8>> for PlainText {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}


pub struct ValidatorPath(Vec<u32>);

impl ValidatorPath {
    pub fn new(index: u32, key_type: KeyType) -> Self {
        let mut vec = vec![PURPOSE, COIN_TYPE, index, 0];

        match key_type {
            KeyType::Voting => vec.push(0),
            KeyType::Withdrawal => {}
        }

        Self(vec)
    }

    pub fn iter_nodes(&self) -> impl Iterator<Item = &u32> {
        self.0.iter()
    }
}
impl fmt::Display for ValidatorPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m")?;

        for node in self.iter_nodes() {
            write!(f, "/{}", node)?;
        }

        Ok(())
    }
}

/// keystore 的加密模块.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Crypto {
    pub kdf: KdfModule,
    pub checksum: ChecksumModule,
    pub cipher: CipherModule,
}

/// Checksum module for `Keystore`.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChecksumModule {
    pub message: HexBytes,
    pub params: EmptyMap,
    pub function: ChecksumFunction,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "Value", into = "Value")]
pub struct EmptyMap;
impl From<EmptyMap> for Value {
    fn from(_from: EmptyMap) -> Value {
        Value::Object(Map::default())
    }
}
impl TryFrom<Value> for EmptyMap {
    type Error = &'static str;

    fn try_from(v: Value) -> Result<Self, Self::Error> {
        match v {
            Value::Object(map) if map.is_empty() => Ok(Self),
            _ => Err("Checksum params must be an empty map"),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum ChecksumFunction {
    Sha256,
}
impl From<ChecksumFunction> for String {
    fn from(from: ChecksumFunction) -> String {
        match from {
            ChecksumFunction::Sha256 => "sha256".into(),
        }
    }
}
impl TryFrom<String> for ChecksumFunction {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_ref() {
            "sha256" => Ok(ChecksumFunction::Sha256),
            other => Err(format!("Unsupported checksum function: {}", other)),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfModule {
    pub function: KdfFunction,
    pub params: Kdf,
    pub message: EmptyString,
}
/// Used for ensuring that serde only decodes valid KDF functions.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum KdfFunction {
    Scrypt,
    Pbkdf2,
}
impl From<KdfFunction> for String {
    fn from(from: KdfFunction) -> String {
        match from {
            KdfFunction::Scrypt => "scrypt".into(),
            KdfFunction::Pbkdf2 => "pbkdf2".into(),
        }
    }
}
impl TryFrom<String> for KdfFunction {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_ref() {
            "scrypt" => Ok(KdfFunction::Scrypt),
            "pbkdf2" => Ok(KdfFunction::Pbkdf2),
            other => Err(format!("Unsupported kdf function: {}", other)),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EmptyString;
impl From<EmptyString> for String {
    fn from(_from: EmptyString) -> String {
        "".into()
    }
}
impl TryFrom<String> for EmptyString {
    type Error = &'static str;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_ref() {
            "" => Ok(Self),
            _ => Err("kdf message must be empty"),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherModule {
    pub message: HexBytes,
    pub params: Cipher,
    pub function: CipherFunction,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum CipherFunction {
    Aes128Ctr,
}
impl From<CipherFunction> for String {
    fn from(from: CipherFunction) -> String {
        match from {
            CipherFunction::Aes128Ctr => "aes-128-ctr".into(),
        }
    }
}
impl TryFrom<String> for CipherFunction {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_ref() {
            "aes-128-ctr" => Ok(CipherFunction::Aes128Ctr),
            other => Err(format!("Unsupported cipher function: {}", other)),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HexBytes(Vec<u8>);
impl HexBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl From<Vec<u8>> for HexBytes {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}
impl From<HexBytes> for String {
    fn from(from: HexBytes) -> String {
        hex::encode(from.0)
    }
}
impl TryFrom<String> for HexBytes {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        // Left-pad with a zero if there is not an even number of hex digits to ensure
        // `hex::decode` doesn't return an error.
        let s = if s.len() % 2 != 0 {
            format!("0{}", s)
        } else {
            s
        };

        hex::decode(s)
            .map(Self)
            .map_err(|e| format!("Invalid hex: {}", e))
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Kdf {
    Scrypt(Scrypt),
    Pbkdf2(Pbkdf2),
}

impl Kdf {
    pub fn function(&self) -> KdfFunction {
        match &self {
            Kdf::Pbkdf2(_) => KdfFunction::Pbkdf2,
            Kdf::Scrypt(_) => KdfFunction::Scrypt,
        }
    }
}


#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scrypt {
    pub dklen: u32,
    pub n: u32,
    pub r: u32,
    pub p: u32,
    pub salt: HexBytes,
}
impl Scrypt {
    pub fn default_scrypt(salt: Vec<u8>) -> Self {
        Self {
            dklen: DKLEN,
            n: 262144,
            p: 1,
            r: 8,
            salt: salt.into(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pbkdf2 {
    pub dklen: u32,
    pub c: u32,
    pub salt: HexBytes,
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey([u8; DKLEN as usize]);

impl DerivedKey {
    /// Instantiates `Self` with an all-zeros byte array.
    pub fn zero() -> Self {
        Self([0; DKLEN as usize])
    }

    /// Returns a reference to the underlying byte array.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns a mutable reference to the underlying byte array.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Instantiates `Self` with an all-zeros byte array of length `len`.
    pub fn zero(len: usize) -> Self {
        Self(vec![0; len])
    }

    /// Returns a mutable reference to the underlying bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl From<Vec<u8>> for SecretBytes {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

/// 生成私钥种子
pub fn recover_validator_secret(
    wallet: &Wallet,
    wallet_password: &[u8],
    index: u32,
    key_type: KeyType,
) -> Result<(PlainText, ValidatorPath), Error> {
    // 构造验证者路径
    let path = ValidatorPath::new(index, key_type);
    // 从密码解密出原始私钥种子
    let secret = wallet.decrypt_seed(wallet_password)?;
    // 由原始私钥种子创建派生密钥对象
    let master = crate::key::DerivedKey::from_seed(secret.as_bytes()).map_err(Error::from)?;
    // 按路径上的节点依次生成子密钥
    let destination = path.iter_nodes().fold(master, |dk, i| dk.child(*i));
    // 返回派生出的私钥种子和路径
    Ok((destination.secret().to_vec().into(), path))
}


/// Regenerate some `plain_text` from the given `password` and `crypto`.
pub fn decrypt(password: &[u8], crypto: &Crypto) -> Result<PlainText, Error> {
    let mut password = normalize(password)?;

    password.retain(|c| !is_control_character(c));

    validate_parameters(&crypto.kdf.params)?;

    let cipher_message = &crypto.cipher.message;

    // Generate derived key
    let derived_key = derive_key(password.as_ref(), &crypto.kdf.params)?;

    // Mismatching checksum indicates an invalid password.
    if &generate_checksum(&derived_key, cipher_message.as_bytes())[..]
        != crypto.checksum.message.as_bytes()
    {
        return Err(Error::InvalidPassword);
    }

    let mut plain_text = PlainText::from(cipher_message.as_bytes().to_vec());
    match &crypto.cipher.params {
        Cipher::Aes128Ctr(params) => {
            // Validate IV
            validate_aes_iv(params.iv.as_bytes())?;

            // AES Decrypt
            let key = GenericArray::from_slice(&derived_key.as_bytes()[0..16]);
            let nonce = GenericArray::from_slice(params.iv.as_bytes());
            let mut cipher = AesCtr::new(key, nonce);
            cipher.apply_keystream(plain_text.as_mut_bytes());
        }
    };
    Ok(plain_text)
}

fn normalize(bytes: &[u8]) -> Result<Zeroizing<String>, Error> {
    Ok(str::from_utf8(bytes)
        .map_err(|_| Error::InvalidPasswordBytes)?
        .nfkd()
        .collect::<String>()
        .into())
}

/// Returns true if the given char is a control character as specified by EIP 2335 and false otherwise.
fn is_control_character(c: char) -> bool {
    // Note: The control codes specified in EIP 2335 are same as the unicode control characters.
    // (0x00 to 0x1F) + (0x80 to 0x9F) + 0x7F
    c.is_control()
}

// Validates the kdf parameters to ensure they are sufficiently secure, in addition to
// preventing DoS attacks from excessively large parameters.
fn validate_parameters(kdf: &Kdf) -> Result<(), Error> {
    match kdf {
        Kdf::Pbkdf2(params) => {
            // We always compute a derived key of 32 bytes so reject anything that
            // says otherwise.
            if params.dklen != DKLEN {
                return Err(Error::InvalidPbkdf2Param);
            }

            // NIST Recommends suggests potential use cases where `c` of 10,000,000 is desireable.
            // As it is 10 years old this has been increased to 80,000,000. Larger values will
            // take over 1 minute to execute on an average machine.
            //
            // Reference:
            //
            // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
            if params.c > 80_000_000 {
                return Err(Error::InvalidPbkdf2Param);
            }

            // RFC2898 declares that `c` must be a "positive integer" and the `crypto` crate panics
            // if it is `0`.
            //
            // Reference:
            //
            // https://www.ietf.org/rfc/rfc2898.txt
            if params.c < DEFAULT_PBKDF2_C {
                if params.c == 0 {
                    return Err(Error::InvalidPbkdf2Param);
                }
                eprintln!(
                    "WARN: PBKDF2 parameters are too weak, 'c' is {}, we recommend using {}",
                    params.c, DEFAULT_PBKDF2_C,
                );
            }

            // Validate `salt` length.
            validate_salt(params.salt.as_bytes())?;

            Ok(())
        }
        Kdf::Scrypt(params) => {
            // RFC7914 declares that all these parameters must be greater than 1:
            //
            // - `N`: costParameter.
            // - `r`: blockSize.
            // - `p`: parallelizationParameter
            //
            // Reference:
            //
            // https://tools.ietf.org/html/rfc7914
            if params.n <= 1 || params.r == 0 || params.p == 0 {
                return Err(Error::InvalidScryptParam);
            }

            // We always compute a derived key of 32 bytes so reject anything that
            // says otherwise.
            if params.dklen != DKLEN {
                return Err(Error::InvalidScryptParam);
            }

            // Ensure that `n` is power of 2.
            if params.n != 2u32.pow(log2_int(params.n)) {
                return Err(Error::InvalidScryptParam);
            }

            // Maximum Parameters
            //
            // Uses a u32 to store value thus maximum memory usage is 4GB.
            //
            // Note: Memory requirements = 128*n*p*r
            let mut npr: u32 = params
                .n
                .checked_mul(params.p)
                .ok_or(Error::InvalidScryptParam)?;
            npr = npr.checked_mul(params.r).ok_or(Error::InvalidScryptParam)?;
            npr = npr.checked_mul(128).ok_or(Error::InvalidScryptParam)?;

            // Minimum Parameters
            let default_kdf = Scrypt::default_scrypt(vec![0u8; 32]);
            let default_npr = 128 * default_kdf.n * default_kdf.p * default_kdf.r;
            if npr < default_npr {
                eprintln!("WARN: Scrypt parameters are too weak (n: {}, p: {}, r: {}), we recommend (n: {}, p: {}, r: {})", params.n, params.p, params.r, default_kdf.n, default_kdf.p, default_kdf.r);
            }

            // Validate `salt` length.
            validate_salt(params.salt.as_bytes())?;

            Ok(())
        }
    }
}

/// Derive a private key from the given `password` using the given `kdf` (key derivation function).
fn derive_key(password: &[u8], kdf: &Kdf) -> Result<DerivedKey, Error> {
    let mut dk = DerivedKey::zero();

    match &kdf {
        Kdf::Pbkdf2(params) => {
            pbkdf2::<Hmac<Sha256>>(
                password,
                params.salt.as_bytes(),
                params.c,
                dk.as_mut_bytes(),
            );
        }
        Kdf::Scrypt(params) => {
            scrypt(
                password,
                params.salt.as_bytes(),
                &ScryptParams::new(log2_int(params.n) as u8, params.r, params.p)
                    .map_err(Error::ScryptInvalidParams)?,
                dk.as_mut_bytes(),
            )
                .map_err(Error::ScryptInvaidOutputLen)?;
        }
    }

    Ok(dk)
}

// Compute floor of log2 of a u32.
fn log2_int(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    31 - x.leading_zeros()
}

fn validate_salt(salt: &[u8]) -> Result<(), Error> {
    // Validate `salt` length
    if salt.is_empty() {
        return Err(Error::InvalidSaltLength);
    } else if salt.len() < SALT_SIZE / 2 {
        eprintln!(
            "WARN: Salt is too short {}, we recommend {}",
            salt.len(),
            SALT_SIZE
        );
    } else if salt.len() > SALT_SIZE * 2 {
        eprintln!(
            "WARN: Salt is too long {}, we recommend {}",
            salt.len(),
            SALT_SIZE
        );
    }
    Ok(())
}

/// Instantiates a BLS keypair from the given `secret`.
pub fn keypair_from_secret(secret: &[u8]) -> Result<Keypair, Error> {
    let sk = SecretKey::deserialize(secret).map_err(Error::InvalidSecretKeyBytes)?;
    let pk = sk.public_key();
    Ok(Keypair::from_components(pk, sk))
}

/// Generates a checksum to indicate that the `derived_key` is associated with the
fn generate_checksum(derived_key: &DerivedKey, cipher_message: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(&derived_key.as_bytes()[16..32]);
    hasher.update(cipher_message);

    let mut digest = [0; HASH_SIZE];
    digest.copy_from_slice(&hasher.finalize());
    digest
}

fn validate_aes_iv(iv: &[u8]) -> Result<(), Error> {
    if iv.is_empty() {
        return Err(Error::IncorrectIvSize {
            expected: IV_SIZE,
            len: iv.len(),
        });
    } else if iv.len() != IV_SIZE {
        eprintln!(
            "WARN: AES IV length incorrect is {}, should be {}",
            iv.len(),
            IV_SIZE
        );
    }
    Ok(())
}

/// Returns `Kdf` used by default when creating keystores.
///
/// Currently this is set to scrypt due to its memory hardness properties.
pub fn default_kdf(salt: Vec<u8>) -> Kdf {
    Kdf::Scrypt(Scrypt::default_scrypt(salt))
}

/// Returns `(cipher_text, checksum)` for the given `plain_text` encrypted with `Cipher` using a
/// key derived from `password` via the `Kdf` (key derivation function).
/// Normalizes the password into NFKD form and removes control characters as specified in EIP-2335
/// before encryption.
///
/// ## Errors
///
/// - If `kdf` is badly formed (e.g., has some values set to zero).
pub fn encrypt(
    plain_text: &[u8],
    password: &[u8],
    kdf: &Kdf,
    cipher: &Cipher,
) -> Result<(Vec<u8>, [u8; HASH_SIZE]), Error> {
    validate_parameters(kdf)?;
    let mut password = normalize(password)?;

    password.retain(|c| !is_control_character(c));

    let derived_key = derive_key(password.as_ref(), kdf)?;

    // Encrypt secret.
    let mut cipher_text = plain_text.to_vec();
    match &cipher {
        Cipher::Aes128Ctr(params) => {
            // Validate IV
            validate_aes_iv(params.iv.as_bytes())?;

            // AES Encrypt
            let key = GenericArray::from_slice(&derived_key.as_bytes()[0..16]);
            let nonce = GenericArray::from_slice(params.iv.as_bytes());
            let mut cipher = AesCtr::new(key, nonce);
            cipher.apply_keystream(&mut cipher_text);
        }
    };

    let checksum = generate_checksum(&derived_key, &cipher_text);

    Ok((cipher_text, checksum))
}