//! N42 0x05 full-key padded Falcon-512 transaction. See docs/spec/N42_TX_0x05.md.

use alloc::vec::Vec;
use alloy_consensus::{
    crypto::RecoveryError,
    transaction::{SignerRecoverable, TxHashRef},
    InMemorySize, Transaction, Typed2718,
};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{keccak256, Address, Bytes, ChainId, Keccak256, TxKind, B256, U256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header};
use serde::{Deserialize, Serialize};
use pqcrypto_falcon::falconpadded512 as falcon;
use pqcrypto_traits::sign::{PublicKey, DetachedSignature};

/// N42 extended transaction discriminator.
pub const FALCON_TX_TYPE_ID: u8 = 0x05;
/// Padded Falcon-512 algorithm discriminator.
pub const ALG_FALCON512: u8 = 0;
/// Invalid transaction shape, key or signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid Falcon-512 transaction signature or key")]
pub struct FalconError;
impl From<FalconError> for RecoveryError {
    fn from(err: FalconError) -> Self { Self::from_source(err) }
}
/// The unsigned fields of a 0x05 transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxFalcon {
    /// EIP-155 chain id; required.
    #[serde(with = "alloy_serde::quantity")]
    pub chain_id: ChainId,
    /// Sender nonce.
    #[serde(with = "alloy_serde::quantity")]
    pub nonce: u64,
    /// EIP-1559 priority fee.
    #[serde(with = "alloy_serde::quantity")]
    pub max_priority_fee_per_gas: u128,
    /// EIP-1559 fee cap.
    #[serde(with = "alloy_serde::quantity")]
    pub max_fee_per_gas: u128,
    /// Gas limit.
    #[serde(with = "alloy_serde::quantity")]
    pub gas_limit: u64,
    /// Recipient. Contract creation is not supported by this type.
    pub to: Address,
    /// Value transferred.
    pub value: U256,
    /// Call data.
    pub input: Bytes,
    /// EIP-2930 access list.
    pub access_list: AccessList,
    /// Signature algorithm ([`ALG_FALCON512`]).
    #[serde(with = "alloy_serde::quantity")]
    pub alg_type: u8,
    /// The signer's public key, in the algorithm's encoding.
    pub pubkey: Bytes,
    /// Full keys only; hash references require a separately activated registry.
    #[serde(with = "alloy_serde::quantity")]
    pub pubkey_mode: u8,
}

impl TxFalcon {
    /// RLP length of the unsigned fields, without a list header.
    fn fields_len(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.input.0.length()
            + self.access_list.length()
            + self.alg_type.length()
            + self.pubkey_mode.length()
            + self.pubkey.0.length()
    }

    fn encode_fields(&self, out: &mut dyn BufMut) {
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.input.0.encode(out);
        self.access_list.encode(out);
        self.alg_type.encode(out);
        self.pubkey_mode.encode(out);
        self.pubkey.0.encode(out);
    }

    /// Decodes the unsigned fields from the front of a list payload.
    /// The unsigned fields with `pubkey` left empty, and the public key's raw
    /// bytes (what `Bytes`' RLP decoding would copy): the caller places the
    /// key ([`shared_key_and_signature`]).
    fn decode_fields<'a>(buf: &mut &'a [u8]) -> alloy_rlp::Result<(Self, &'a [u8])> {
        let tx = Self {
            chain_id: Decodable::decode(buf)?,
            nonce: Decodable::decode(buf)?,
            max_priority_fee_per_gas: Decodable::decode(buf)?,
            max_fee_per_gas: Decodable::decode(buf)?,
            gas_limit: Decodable::decode(buf)?,
            to: Decodable::decode(buf)?,
            value: Decodable::decode(buf)?,
            input: Decodable::decode(buf)?,
            access_list: Decodable::decode(buf)?,
            alg_type: Decodable::decode(buf)?,
            pubkey_mode: Decodable::decode(buf)?,
            pubkey: Bytes::new(),
        };
        let pubkey = Header::decode_bytes(buf, false)?;
        Ok((tx, pubkey))
    }

    /// The hash the signature is over:
    /// `keccak256(0x05 || rlp([unsigned fields ..., alg_type, pubkey_mode, pubkey]))`.
    pub fn signing_hash(&self) -> B256 {
        let payload_length = self.fields_len();
        let mut buf = Vec::with_capacity(1 + Header { list: true, payload_length }.length() + payload_length);
        buf.put_u8(FALCON_TX_TYPE_ID);
        Header { list: true, payload_length }.encode(&mut buf);
        self.encode_fields(&mut buf);
        keccak256(&buf)
    }

    /// The account this key controls: `keccak256(pubkey)[12..]`.
    pub fn sender(&self) -> Address {
        Address::from_slice(&keccak256(&self.pubkey)[12..])
    }

    /// Sign the exact typed preimage using padded Falcon-512 (666 bytes).
    pub fn sign_falcon(self, key: &falcon::SecretKey) -> FalconTx {
        let sig = falcon::detached_sign(self.signing_hash().as_slice(), key);
        FalconTx::new(self, Bytes::copy_from_slice(sig.as_bytes()))
    }
}

/// A signed 0x05 transaction: the fields, the signature, and the cached hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FalconTx {
    #[serde(flatten)]
    tx: TxFalcon,
    signature: Bytes,
    hash: B256,
}

impl FalconTx {
    /// Builds the signed transaction and computes its hash.
    pub fn new(tx: TxFalcon, signature: Bytes) -> Self {
        let mut this = Self { tx, signature, hash: B256::ZERO };
        this.hash = keccak256(this.encoded_2718());
        this
    }

    /// Builds from parts with a hash the caller already knows to be right
    /// (storage decode).
    pub const fn new_unchecked(tx: TxFalcon, signature: Bytes, hash: B256) -> Self {
        Self { tx, signature, hash }
    }

    /// The unsigned fields.
    pub const fn tx(&self) -> &TxFalcon {
        &self.tx
    }

    /// The signature bytes.
    pub const fn signature(&self) -> &Bytes {
        &self.signature
    }

    /// The transaction hash.
    pub const fn hash(&self) -> &B256 {
        &self.hash
    }

    /// Splits into the fields, the signature and the hash.
    pub fn into_parts(self) -> (TxFalcon, Bytes, B256) {
        (self.tx, self.signature, self.hash)
    }

    /// The account the key controls. Cheap; does not verify anything.
    pub fn sender(&self) -> Address {
        self.tx.sender()
    }

    /// Verify shape and the actual Falcon signature before deriving the sender.
    pub fn verify(&self) -> Result<Address, FalconError> {
        if self.tx.alg_type != ALG_FALCON512 || self.tx.pubkey_mode != 0 || self.tx.chain_id == 0 ||
            self.tx.max_priority_fee_per_gas > self.tx.max_fee_per_gas ||
            self.tx.pubkey.len() != 897 || self.signature.len() != 666 { return Err(FalconError); }
        let key = falcon::PublicKey::from_bytes(&self.tx.pubkey).map_err(|_| FalconError)?;
        let sig = falcon::DetachedSignature::from_bytes(&self.signature).map_err(|_| FalconError)?;
        falcon::verify_detached_signature(&sig, self.tx.signing_hash().as_slice(), &key).map_err(|_| FalconError)?;
        Ok(self.tx.sender())
    }
    fn signed_fields_len(&self) -> usize {
        self.tx.fields_len() + self.signature.0.length()
    }

    fn header(&self) -> Header {
        Header { list: true, payload_length: self.signed_fields_len() }
    }

    /// Decodes the typed payload (after the 0x05 byte), returning the parts and
    /// the hash of the bytes consumed.
    fn decode_payload(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let original = *buf;
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();
        let (mut tx, pubkey) = TxFalcon::decode_fields(buf)?;
        let signature = Header::decode_bytes(buf, false)?;
        if remaining - buf.len() != header.payload_length {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        if pubkey.len() != 897 || signature.len() != 666 || tx.alg_type != 0 || tx.pubkey_mode != 0 {
            return Err(alloy_rlp::Error::Custom("invalid Falcon shape"));
        }
        let (pubkey, signature) = shared_key_and_signature(pubkey, signature);
        tx.pubkey = pubkey;
        let consumed = original.len() - buf.len();
        let mut hasher = Keccak256::new();
        hasher.update([FALCON_TX_TYPE_ID]);
        hasher.update(&original[..consumed]);
        Ok(Self { tx, signature, hash: hasher.finalize() })
    }
}

/// A decoded transaction's public key and signature, copied into one
/// reference-counted buffer and handed out as two slices of it.
///
/// Decoded one at a time each would be a `Vec`-backed `Bytes`, whose first
/// clone allocates a shared header and swaps it in (`bytes`'
/// `shallow_clone_vec`): the block body's copy of every pooled transaction
/// paid two of those on the build pool (8% of it in the loop314 profile).
/// Here the buffer is shared from the start, one allocation for both parts,
/// and every clone is a reference-count increment. The contents, and so
/// equality, hashing and encoding, are unchanged.
fn shared_key_and_signature(pubkey: &[u8], signature: &[u8]) -> (Bytes, Bytes) {
    if pubkey.is_empty() && signature.is_empty() {
        return (Bytes::new(), Bytes::new());
    }
    let mut joint = Vec::with_capacity(pubkey.len() + signature.len());
    joint.extend_from_slice(pubkey);
    joint.extend_from_slice(signature);
    let joint = bytes::Bytes::from_owner(joint);
    (Bytes(joint.slice(..pubkey.len())), Bytes(joint.slice(pubkey.len()..)))
}

impl Typed2718 for FalconTx {
    fn ty(&self) -> u8 {
        FALCON_TX_TYPE_ID
    }
}

impl Transaction for FalconTx {
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.tx.chain_id)
    }

    fn nonce(&self) -> u64 {
        self.tx.nonce
    }

    fn gas_limit(&self) -> u64 {
        self.tx.gas_limit
    }

    fn gas_price(&self) -> Option<u128> {
        None
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.tx.max_fee_per_gas
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(self.tx.max_priority_fee_per_gas)
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.tx.max_priority_fee_per_gas
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        match base_fee {
            None => self.tx.max_fee_per_gas,
            Some(base_fee) => {
                let tip = self.tx.max_fee_per_gas.saturating_sub(base_fee as u128);
                if tip > self.tx.max_priority_fee_per_gas {
                    self.tx.max_priority_fee_per_gas + base_fee as u128
                } else {
                    self.tx.max_fee_per_gas
                }
            }
        }
    }

    fn is_dynamic_fee(&self) -> bool {
        true
    }

    fn kind(&self) -> TxKind {
        TxKind::Call(self.tx.to)
    }

    fn is_create(&self) -> bool {
        false
    }

    fn value(&self) -> U256 {
        self.tx.value
    }

    fn input(&self) -> &Bytes {
        &self.tx.input
    }

    fn access_list(&self) -> Option<&AccessList> {
        Some(&self.tx.access_list)
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        None
    }
}

impl Encodable2718 for FalconTx {
    fn encode_2718_len(&self) -> usize {
        1 + self.header().length_with_payload()
    }

    fn encode_2718(&self, out: &mut dyn BufMut) {
        out.put_u8(FALCON_TX_TYPE_ID);
        self.header().encode(out);
        self.tx.encode_fields(out);
        self.signature.0.encode(out);
    }

    fn trie_hash(&self) -> B256 {
        self.hash
    }
}

impl Decodable2718 for FalconTx {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        if ty != FALCON_TX_TYPE_ID {
            return Err(Eip2718Error::UnexpectedType(ty));
        }
        Ok(Self::decode_payload(buf)?)
    }

    fn fallback_decode(_buf: &mut &[u8]) -> Eip2718Result<Self> {
        Err(Eip2718Error::UnexpectedType(0))
    }
}

impl Encodable for FalconTx {
    fn encode(&self, out: &mut dyn BufMut) {
        self.network_encode(out)
    }

    fn length(&self) -> usize {
        self.network_len()
    }
}

impl Decodable for FalconTx {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self::network_decode(buf)?)
    }
}

impl InMemorySize for FalconTx {
    fn size(&self) -> usize {
        core::mem::size_of::<Self>()
            + self.tx.input.len()
            + self.tx.access_list.size()
            + self.tx.pubkey.len()
            + self.signature.len()
    }
}

impl TxHashRef for FalconTx {
    fn tx_hash(&self) -> &B256 {
        &self.hash
    }
}

impl SignerRecoverable for FalconTx {
    fn recover_signer(&self) -> Result<Address, RecoveryError> {
        Ok(self.verify()?)
    }

    fn recover_signer_unchecked(&self) -> Result<Address, RecoveryError> {
        Ok(self.verify()?)
    }
}


static ENABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// Process-wide admission flag initialized from this node's genesis.
pub fn pq_tx_enabled() -> bool { ENABLED.load(core::sync::atomic::Ordering::Acquire) }
/// Initialize only from the chain configuration, never from incoming traffic.
pub fn set_pq_tx_enabled(value: bool) { ENABLED.store(value, core::sync::atomic::Ordering::Release); }
