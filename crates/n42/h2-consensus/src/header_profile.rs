// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's HotStuff-2 block header profile — what a block looks like when a
//! Go fleet member produced it, and what this node must produce for a Go
//! member to accept.
//!
//! The Ethereum header layout is kept field for field (gov5's `block.Header`
//! is "100% Ethereum Pectra compatible"), but four fields carry HotStuff
//! rather than proof-of-work or beacon-chain meaning
//! (`internal/consensus/hotstuff/adapter.go` `Prepare`, `header_extra.go`):
//!
//! - `extra_data` is `"N42H" ‖ view (u64 little-endian) ‖ [QC] ‖ seal`, the
//!   seal being 96 reserved bytes that `Seal` fills with the leader's BLS
//!   signature over the header hashed *without* those 96 bytes.
//! - `difficulty` is 0 (a legacy range carries 1). Ordering is by view.
//! - `beneficiary` is the leader's address.
//! - `ommers_hash` is whatever the producer left there. gov5's miner leaves
//!   the Go zero value, so live headers commit to `B256::ZERO`; its genesis
//!   uses the Ethereum empty-list hash. Neither side checks it, both sides
//!   hash it, so a decoder must reconstruct exactly what was there.
//!
//! And one commitment differs: gov5 computes the **receipts root** as the
//! keccak of the concatenated receipt encodings (`hash.DeriveSha`, keccak of
//! nothing for an empty block), not as a Merkle-Patricia root. The
//! transactions root is the ordinary trie root on a QMDB chain
//! (`block.UseEthereumTxRoot`).
//!
//! Everything here is checked against bytes produced by gov5's own code.
//! `VerifyHeader` on the Go side checks the extra layout, timestamp > parent,
//! gas used ≤ gas limit, and that no parent beacon root is set while no
//! committee evidence exists; it does not verify the seal. This node signs it
//! anyway.

use alloy_consensus::{Block, BlockBody, Header, TxEnvelope, EMPTY_OMMER_ROOT_HASH};
use alloy_eips::eip7685::{Requests, RequestsOrHash, EMPTY_REQUESTS_HASH};
use alloy_eips::eip4895::{Withdrawal, Withdrawals};
use alloy_primitives::{b256, keccak256, Address, Bloom, Bytes, Log, B256, B64, U256};
use alloy_rlp::{Decodable, Encodable, Header as RlpHeader, RlpEncodable};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar,
    PraguePayloadFields,
};
use n42_h2_primitives::bls::{BlsPublicKey, BlsSecretKey, BlsSignature};

/// Which header shape a chain's blocks have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum N42HeaderProfile {
    /// The header is exactly what the execution payload says: empty-list
    /// ommers hash, whatever extra data the builder sealed. An APoS chain.
    #[default]
    Ethereum,
    /// gov5's HotStuff-2 header, described in this module. A chain whose
    /// genesis names a `hotstuff` validator set.
    Gov5H2,
}

/// The four bytes every HotStuff header's extra data starts with.
pub const GOV5_HEADER_EXTRA_MAGIC: [u8; 4] = *b"N42H";

/// gov5's header fields beyond Ethereum's — what an `alloy` header cannot
/// carry and what the Engine API cannot say.
///
/// gov5's header is Ethereum's 21 fields followed by two of its own:
/// `BlockAccessListHash` (its EIP-7928 fork, never active on its chains so
/// far) and `MobileRegistryRoot`, stamped by every leader once the
/// `mobileAnchor` fork is active (`params/config_rules.go`
/// `IsMobileAnchor`; `miner/worker.go`), the root of a registry that is
/// empty on chain 94, so the value is zero — but present, and hashed. gov5's
/// header codec (`common/block/header.go`, "the struct codec emits every
/// field up to the last non-zero one, writing an empty-string placeholder
/// for any nil gap") makes such a header a 23-item list whose 21st item —
/// `requestsHash`, which its producer leaves nil — and 22nd are empty
/// strings. `alloy`'s decoder refuses the empty `requestsHash`, and its
/// encoder cannot write the tail, so the hash of every such header is
/// computed here, not by `Header::hash_slow`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gov5HeaderExtension {
    /// `MobileRegistryRoot`, the 23rd field, when the header carries one.
    pub mobile_registry_root: Option<B256>,
}

impl Gov5HeaderExtension {
    /// No extra field: an Ethereum-shaped header.
    pub const NONE: Self = Self {
        mobile_registry_root: None,
    };

    /// Whether the header carries anything beyond Ethereum's fields.
    pub const fn is_none(&self) -> bool {
        self.mobile_registry_root.is_none()
    }

    /// The extension a header at `hash` must carry, tried from the values
    /// gov5 stamps: none, or the zero root the empty registry commits to.
    /// `None` when neither hashes to it — the header is not the block that
    /// was hashed, or the registry has a root this node does not know.
    pub fn recover(header: &Header, hash: B256) -> Option<Self> {
        [Self::NONE, Self { mobile_registry_root: Some(B256::ZERO) }]
            .into_iter()
            .find(|extension| gov5_header_hash(header, extension) == hash)
    }
}

/// gov5's own fork schedule, the part that changes the header: what a chain's
/// genesis carries as `mobileAnchorTime`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gov5ForkSchedule {
    /// When headers start carrying `MobileRegistryRoot`; `None` never.
    pub mobile_anchor_time: Option<u64>,
}

impl Gov5ForkSchedule {
    /// Reads the schedule from a genesis's `config`, where gov5's own forks
    /// are carried through untranslated.
    pub fn from_genesis(genesis: &alloy_genesis::Genesis) -> Self {
        let mobile_anchor_time = genesis
            .config
            .extra_fields
            .get("mobileAnchorTime")
            .and_then(|value| value.as_u64().or_else(|| value.as_str().and_then(|s| s.parse().ok())));
        Self { mobile_anchor_time }
    }

    /// Whether a header stamped at `timestamp` carries `MobileRegistryRoot`.
    pub fn mobile_anchor_active(&self, timestamp: u64) -> bool {
        self.mobile_anchor_time.is_some_and(|at| timestamp >= at)
    }

    /// The extension a leader stamps at `timestamp`: the zero root under
    /// the fork (chain 94's registry is empty), nothing before it.
    pub fn extension_at(&self, timestamp: u64) -> Gov5HeaderExtension {
        Gov5HeaderExtension {
            mobile_registry_root: self.mobile_anchor_active(timestamp).then_some(B256::ZERO),
        }
    }

    /// Whether `extension` is what the schedule says a header at
    /// `timestamp` carries — gov5's `VerifyHeader` refuses a missing root
    /// under the fork and a present one before it.
    pub fn allows(&self, timestamp: u64, extension: &Gov5HeaderExtension) -> bool {
        extension.mobile_registry_root.is_some() == self.mobile_anchor_active(timestamp)
    }
}

/// One item of gov5's optional header tail: a value, or the empty-string
/// placeholder its codec writes for a nil pointer inside the tail.
enum TailItem {
    Absent,
    U64(u64),
    Hash(B256),
}

impl TailItem {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::Absent => out.put_u8(alloy_rlp::EMPTY_STRING_CODE),
            Self::U64(value) => value.encode(out),
            Self::Hash(hash) => hash.encode(out),
        }
    }

    fn length(&self) -> usize {
        match self {
            Self::Absent => 1,
            Self::U64(value) => value.length(),
            Self::Hash(hash) => hash.length(),
        }
    }
}

/// gov5's optional tail for a header: the fields from `baseFee` on, each
/// either a value or a placeholder, cut after the last value.
fn gov5_header_tail(header: &Header, extension: &Gov5HeaderExtension) -> Vec<TailItem> {
    let hash = |value: Option<B256>| value.map_or(TailItem::Absent, TailItem::Hash);
    let mut tail = vec![
        header.base_fee_per_gas.map_or(TailItem::Absent, TailItem::U64),
        hash(header.withdrawals_root),
        header.blob_gas_used.map_or(TailItem::Absent, TailItem::U64),
        header.excess_blob_gas.map_or(TailItem::Absent, TailItem::U64),
        hash(header.parent_beacon_block_root),
        hash(header.requests_hash),
        // `BlockAccessListHash` is gov5's 22nd field as it is alloy's; alloy's
        // 23rd (`slot_number`) has no gov5 counterpart and stays unset.
        hash(header.block_access_list_hash),
        hash(extension.mobile_registry_root),
    ];
    while matches!(tail.last(), Some(TailItem::Absent)) {
        tail.pop();
    }
    tail
}

/// Writes the header as gov5's codec does — the form its hash is taken
/// over. Byte-identical to `alloy`'s encoding for a header whose optional
/// fields are contiguous and that carries no extension, which is every
/// header before gov5's `mobileAnchor` fork.
pub fn encode_gov5_header(header: &Header, extension: &Gov5HeaderExtension, out: &mut Vec<u8>) {
    let tail = gov5_header_tail(header, extension);
    let payload_length = header.parent_hash.length()
        + header.ommers_hash.length()
        + header.beneficiary.length()
        + header.state_root.length()
        + header.transactions_root.length()
        + header.receipts_root.length()
        + header.logs_bloom.length()
        + header.difficulty.length()
        + header.number.length()
        + header.gas_limit.length()
        + header.gas_used.length()
        + header.timestamp.length()
        + header.extra_data.length()
        + header.mix_hash.length()
        + header.nonce.length()
        + tail.iter().map(TailItem::length).sum::<usize>();
    RlpHeader {
        list: true,
        payload_length,
    }
    .encode(out);
    header.parent_hash.encode(out);
    header.ommers_hash.encode(out);
    header.beneficiary.encode(out);
    header.state_root.encode(out);
    header.transactions_root.encode(out);
    header.receipts_root.encode(out);
    header.logs_bloom.encode(out);
    header.difficulty.encode(out);
    header.number.encode(out);
    header.gas_limit.encode(out);
    header.gas_used.encode(out);
    header.timestamp.encode(out);
    header.extra_data.encode(out);
    header.mix_hash.encode(out);
    header.nonce.encode(out);
    for item in &tail {
        item.encode(out);
    }
}

/// The header's RLP in gov5's form.
pub fn gov5_header_rlp(header: &Header, extension: &Gov5HeaderExtension) -> Vec<u8> {
    let mut out = Vec::with_capacity(640 + header.extra_data.len());
    encode_gov5_header(header, extension, &mut out);
    out
}

/// The header's hash as gov5 computes it: keccak of [`encode_gov5_header`].
/// Equal to `Header::hash_slow` whenever the extension is empty.
pub fn gov5_header_hash(header: &Header, extension: &Gov5HeaderExtension) -> B256 {
    if extension.is_none() {
        return header.hash_slow();
    }
    keccak256(gov5_header_rlp(header, extension))
}

/// Reads a header in gov5's form: Ethereum's fields, the optional tail with
/// gov5's placeholders, and the two fields beyond Ethereum's. A placeholder
/// for a gas quantity reads as zero — what `alloy` reads too, and what
/// gov5's producer means when it leaves the pointer nil on a Cancun chain;
/// a placeholder for a hash reads as none. A `BlockAccessListHash` is
/// refused: no chain this node joins has that fork.
pub fn decode_gov5_header(rlp: &[u8]) -> Result<(Header, Gov5HeaderExtension), HeaderProfileError> {
    let malformed = |what: &str| HeaderProfileError::Reconstruction(format!("header RLP: {what}"));
    let mut cursor = rlp;
    let list = RlpHeader::decode(&mut cursor).map_err(|e| malformed(&e.to_string()))?;
    if !list.list || list.payload_length != cursor.len() {
        return Err(malformed("not one list"));
    }
    let mut items: Vec<&[u8]> = Vec::with_capacity(23);
    while !cursor.is_empty() {
        let mut probe = cursor;
        let item = RlpHeader::decode(&mut probe).map_err(|e| malformed(&e.to_string()))?;
        let header_len = cursor.len() - probe.len();
        let total = header_len + item.payload_length;
        if total > cursor.len() {
            return Err(malformed("item past the list"));
        }
        items.push(&cursor[..total]);
        cursor = &cursor[total..];
    }
    if items.len() < 15 {
        return Err(malformed(&format!("{} items, fewer than a header's 15", items.len())));
    }
    if items.len() > 23 {
        return Err(malformed(&format!("{} items, more than gov5's 23", items.len())));
    }
    fn field<T: Decodable>(item: &[u8], what: &str) -> Result<T, HeaderProfileError> {
        let mut cursor = item;
        let value = T::decode(&mut cursor)
            .map_err(|e| HeaderProfileError::Reconstruction(format!("header RLP: {what}: {e}")))?;
        if !cursor.is_empty() {
            return Err(HeaderProfileError::Reconstruction(format!("header RLP: {what}: trailing bytes")));
        }
        Ok(value)
    }
    let is_placeholder = |item: &[u8]| item == [alloy_rlp::EMPTY_STRING_CODE];
    let optional_hash = |index: usize, what: &str| -> Result<Option<B256>, HeaderProfileError> {
        match items.get(index) {
            None => Ok(None),
            Some(item) if is_placeholder(item) => Ok(None),
            Some(item) => field::<B256>(item, what).map(Some),
        }
    };
    let optional_u64 = |index: usize, what: &str| -> Result<Option<u64>, HeaderProfileError> {
        match items.get(index) {
            None => Ok(None),
            Some(item) if is_placeholder(item) => Ok(Some(0)),
            Some(item) => field::<u64>(item, what).map(Some),
        }
    };
    let header = Header {
        parent_hash: field(items[0], "parentHash")?,
        ommers_hash: field(items[1], "ommersHash")?,
        beneficiary: field(items[2], "beneficiary")?,
        state_root: field(items[3], "stateRoot")?,
        transactions_root: field(items[4], "transactionsRoot")?,
        receipts_root: field(items[5], "receiptsRoot")?,
        logs_bloom: field::<Bloom>(items[6], "logsBloom")?,
        difficulty: field(items[7], "difficulty")?,
        number: field(items[8], "number")?,
        gas_limit: field(items[9], "gasLimit")?,
        gas_used: field(items[10], "gasUsed")?,
        timestamp: field(items[11], "timestamp")?,
        extra_data: field(items[12], "extraData")?,
        mix_hash: field(items[13], "mixHash")?,
        nonce: field::<B64>(items[14], "nonce")?,
        base_fee_per_gas: match items.get(15) {
            None => None,
            Some(item) if is_placeholder(item) => None,
            Some(item) => Some(field::<u64>(item, "baseFeePerGas")?),
        },
        withdrawals_root: optional_hash(16, "withdrawalsRoot")?,
        blob_gas_used: optional_u64(17, "blobGasUsed")?,
        excess_blob_gas: optional_u64(18, "excessBlobGas")?,
        parent_beacon_block_root: optional_hash(19, "parentBeaconBlockRoot")?,
        requests_hash: optional_hash(20, "requestsHash")?,
        block_access_list_hash: None,
        slot_number: None,
    };
    if optional_hash(21, "blockAccessListHash")?.is_some() {
        return Err(HeaderProfileError::Reconstruction(
            "header carries a BlockAccessListHash, a gov5 fork this node does not have".into(),
        ));
    }
    let extension = Gov5HeaderExtension {
        mobile_registry_root: optional_hash(22, "mobileRegistryRoot")?,
    };
    // gov5 cuts the tail after the last value; a trailing placeholder is
    // not a form it writes, and would re-encode to a different hash.
    if let Some(last) = items.last()
        && items.len() > 15
        && is_placeholder(last)
    {
        return Err(malformed("trailing placeholder"));
    }
    Ok((header, extension))
}
/// Magic plus the little-endian view.
pub const EXTRA_MIN_LEN: usize = 12;
/// The BLS seal gov5 reserves at the end of the extra data.
pub const EXTRA_SEAL_LEN: usize = 96;
/// Bound shared with gov5's high-TC envelope limit.
pub const MAX_HEADER_EXTRA_LEN: usize = 4096;

/// `keccak256("")`: gov5's receipts root for a block with no receipts
/// (`hash.NilHash`), and its withdrawals root for a block with no rewards.
pub const GOV5_NIL_HASH: B256 =
    b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

/// What gov5 writes in `requestsHash` when a Prague block carried no
/// EIP-7685 requests: `keccak256(RLP([]))`, the empty trie root — not the
/// EIP's `sha256("")`, which gov5 uses only at genesis
/// (`hotstuff/adapter.go` `FinalizeAndAssemble`).
pub const GOV5_EMPTY_REQUESTS_HASH: B256 = alloy_consensus::EMPTY_ROOT_HASH;

/// gov5's `withdrawalsRoot`: not a withdrawals commitment at all but
/// `hash.DeriveSha(rewards)` — keccak over the concatenated
/// `rlp([address, amount])` of the block's validator rewards, keccak of
/// nothing when there are none. A chain where rewards are paid needs the
/// rewards list to reproduce it; this node pays none and produces the empty
/// value.
pub fn gov5_rewards_root(rewards: impl IntoIterator<Item = (Address, U256)>) -> B256 {
    let mut concatenated = Vec::new();
    for (address, amount) in rewards {
        #[derive(RlpEncodable)]
        struct Reward {
            address: Address,
            amount: U256,
        }
        Reward { address, amount }.encode(&mut concatenated);
    }
    keccak256(&concatenated)
}

/// Wei per gwei: an Engine API withdrawal's amount is in gwei.
const GWEI: u64 = 1_000_000_000;

/// gov5's rewards as the Engine API's withdrawals, which is how this node's
/// execution layer credits them: a withdrawal's amount is in gwei and is
/// credited after the transactions, exactly as gov5's `Finalize` credits a
/// reward. The withdrawal index is the reward's position and the validator
/// index zero; neither reaches the state or the header, whose withdrawals
/// root is gov5's rewards commitment, not the withdrawals trie.
///
/// A reward that is not a whole number of gwei has no withdrawal and is
/// refused; gov5's dev rewards are whole ether.
pub fn rewards_to_withdrawals(
    rewards: &[(Address, U256)],
) -> Result<Vec<Withdrawal>, HeaderProfileError> {
    let gwei = U256::from(GWEI);
    rewards
        .iter()
        .enumerate()
        .map(|(index, (address, amount))| {
            if *amount % gwei != U256::ZERO {
                return Err(HeaderProfileError::Reconstruction(format!(
                    "reward of {amount} wei to {address} is not a whole number of gwei"
                )));
            }
            let amount = u64::try_from(*amount / gwei).map_err(|_| {
                HeaderProfileError::Reconstruction(format!(
                    "reward of {amount} wei to {address} does not fit a withdrawal"
                ))
            })?;
            Ok(Withdrawal { index: index as u64, validator_index: 0, address: *address, amount })
        })
        .collect()
}

/// The rewards a block's withdrawals stand for; see [`rewards_to_withdrawals`].
pub fn withdrawals_to_rewards(withdrawals: &[Withdrawal]) -> Vec<(Address, U256)> {
    withdrawals
        .iter()
        .map(|withdrawal| (withdrawal.address, U256::from(withdrawal.amount) * U256::from(GWEI)))
        .collect()
}

/// Whether a `requestsHash` says "no requests" in either convention.
pub fn is_empty_requests_hash(hash: B256) -> bool {
    hash == EMPTY_REQUESTS_HASH || hash == GOV5_EMPTY_REQUESTS_HASH
}

/// What a header's extra data says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderExtra {
    /// The view the block was proposed in.
    pub view: u64,
    /// The committed QC the leader embedded, in gov5's own encoding, or empty.
    /// Carried opaquely: this node authenticates blocks through the
    /// proposal and commit certificates on the wire, not through this copy.
    pub qc: Vec<u8>,
    /// The trailing 96-byte seal, when the layout reserves one. All zeros
    /// before `Seal`, the leader's BLS signature after.
    pub seal: Option<[u8; EXTRA_SEAL_LEN]>,
}

impl HeaderExtra {
    /// The extra data a leader writes before sealing: view, no QC, seal
    /// reserved. What gov5's `buildHeaderExtra(view, nil)` produces.
    pub const fn for_view(view: u64) -> Self {
        Self {
            view,
            qc: Vec::new(),
            seal: Some([0; EXTRA_SEAL_LEN]),
        }
    }

    /// The bytes.
    pub fn encode(&self) -> Bytes {
        let mut out = Vec::with_capacity(EXTRA_MIN_LEN + self.qc.len() + EXTRA_SEAL_LEN);
        out.extend_from_slice(&GOV5_HEADER_EXTRA_MAGIC);
        out.extend_from_slice(&self.view.to_le_bytes());
        out.extend_from_slice(&self.qc);
        if let Some(seal) = &self.seal {
            out.extend_from_slice(seal);
        }
        out.into()
    }

    /// Reads the layouts gov5's `decodeHeaderExtra` accepts.
    ///
    /// After magic and view: nothing; a seal alone; a QC followed by a seal;
    /// or, in the legacy layout, a QC alone. gov5 tells the last two apart by
    /// trying to decode the QC; this node does not decode QCs, so a payload
    /// longer than a seal is read as QC-then-seal, which is every header a
    /// current gov5 produces.
    pub fn decode(extra: &[u8]) -> Result<Self, HeaderProfileError> {
        if extra.len() > MAX_HEADER_EXTRA_LEN {
            return Err(HeaderProfileError::ExtraTooLong(extra.len()));
        }
        if extra.len() < EXTRA_MIN_LEN {
            return Err(HeaderProfileError::ExtraTooShort(extra.len()));
        }
        if extra[..4] != GOV5_HEADER_EXTRA_MAGIC {
            return Err(HeaderProfileError::MissingMagic);
        }
        let view = u64::from_le_bytes(
            extra[4..EXTRA_MIN_LEN]
                .try_into()
                .expect("length checked before fixed-width conversion"),
        );
        let payload = &extra[EXTRA_MIN_LEN..];
        let (qc, seal) = if payload.len() >= EXTRA_SEAL_LEN {
            let (qc, seal) = payload.split_at(payload.len() - EXTRA_SEAL_LEN);
            let mut fixed = [0u8; EXTRA_SEAL_LEN];
            fixed.copy_from_slice(seal);
            (qc.to_vec(), Some(fixed))
        } else {
            (payload.to_vec(), None)
        };
        Ok(Self { view, qc, seal })
    }
}

/// Why a header is not a gov5 HotStuff header.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeaderProfileError {
    /// Shorter than magic plus view.
    #[error("extra data is {0} bytes, shorter than magic + view")]
    ExtraTooShort(usize),
    /// Past gov5's bound.
    #[error("extra data is {0} bytes, past the 4096-byte bound")]
    ExtraTooLong(usize),
    /// Does not start with `N42H`.
    #[error("extra data does not start with N42H")]
    MissingMagic,
    /// Neither 0 nor the legacy 1.
    #[error("difficulty {0} is neither 0 nor the legacy 1")]
    Difficulty(U256),
    /// Post-merge headers carry a zero nonce.
    #[error("nonce is not zero")]
    Nonce,
    /// Neither gov5's zero nor Ethereum's empty-list hash.
    #[error("ommers hash {0} is neither zero nor the empty-list hash")]
    OmmersHash(B256),
    /// The layout reserves no seal to sign into.
    #[error("extra data reserves no seal")]
    NoSeal,
    /// The seal does not verify under the given key.
    #[error("seal does not verify: {0}")]
    Seal(String),
    /// A payload could not be turned back into a block.
    #[error("execution payload cannot reconstruct a block: {0}")]
    Reconstruction(String),
}

/// The view a header was proposed in.
pub fn header_view(header: &Header) -> Result<u64, HeaderProfileError> {
    HeaderExtra::decode(&header.extra_data).map(|extra| extra.view)
}

/// Checks the HotStuff-specific fields and returns the decoded extra data.
///
/// Fork-dependent fields (withdrawals root, blob gas, requests hash) are the
/// execution layer's business and are not looked at here.
pub fn validate_gov5_h2_header(header: &Header) -> Result<HeaderExtra, HeaderProfileError> {
    let extra = HeaderExtra::decode(&header.extra_data)?;
    if header.difficulty != U256::ZERO && header.difficulty != U256::from(1) {
        return Err(HeaderProfileError::Difficulty(header.difficulty));
    }
    if !header.nonce.is_zero() {
        return Err(HeaderProfileError::Nonce);
    }
    if header.ommers_hash != B256::ZERO && header.ommers_hash != EMPTY_OMMER_ROOT_HASH {
        return Err(HeaderProfileError::OmmersHash(header.ommers_hash));
    }
    Ok(extra)
}

/// The hash the leader signs: the header with the trailing seal removed
/// (gov5 `sealHash`, which strips 96 bytes only when there is more than a
/// seal's worth of extra data), in gov5's form.
pub fn seal_hash(header: &Header, extension: &Gov5HeaderExtension) -> B256 {
    let mut unsealed = header.clone();
    if unsealed.extra_data.len() > EXTRA_SEAL_LEN {
        let keep = unsealed.extra_data.len() - EXTRA_SEAL_LEN;
        unsealed.extra_data = Bytes::copy_from_slice(&unsealed.extra_data[..keep]);
    }
    gov5_header_hash(&unsealed, extension)
}

/// Signs the seal into the header's reserved trailing bytes, as gov5's `Seal`
/// does. The header's hash changes; re-hash after.
pub fn seal_header(
    header: &mut Header,
    extension: &Gov5HeaderExtension,
    key: &BlsSecretKey,
) -> Result<(), HeaderProfileError> {
    let extra = HeaderExtra::decode(&header.extra_data)?;
    if extra.seal.is_none() {
        return Err(HeaderProfileError::NoSeal);
    }
    // gov5 seals under the proof-of-possession ciphersuite, the same one its
    // consensus votes use.
    let signature = key.sign_h2_v4(seal_hash(header, extension).as_slice());
    let mut bytes = header.extra_data.to_vec();
    let start = bytes.len() - EXTRA_SEAL_LEN;
    bytes[start..].copy_from_slice(&signature.to_bytes());
    header.extra_data = bytes.into();
    Ok(())
}

/// Checks the seal against a leader's public key.
pub fn verify_seal(
    header: &Header,
    extension: &Gov5HeaderExtension,
    leader: &BlsPublicKey,
) -> Result<(), HeaderProfileError> {
    let extra = HeaderExtra::decode(&header.extra_data)?;
    let seal = extra.seal.ok_or(HeaderProfileError::NoSeal)?;
    let signature =
        BlsSignature::from_bytes(&seal).map_err(|e| HeaderProfileError::Seal(e.to_string()))?;
    leader
        .verify_h2_v4_prevalidated(seal_hash(header, extension).as_slice(), &signature)
        .map_err(|e| HeaderProfileError::Seal(e.to_string()))
}

/// The parts of a receipt gov5's receipts root commits to.
#[derive(Clone, Copy, Debug)]
pub struct ReceiptView<'a> {
    /// EIP-658 status.
    pub success: bool,
    /// Gas used by the block up to and including this transaction.
    pub cumulative_gas_used: u64,
    /// The logs.
    pub logs: &'a [Log],
}

#[derive(RlpEncodable)]
struct StoredLog {
    address: Address,
    topics: Vec<B256>,
    data: Bytes,
}

#[derive(RlpEncodable)]
struct StoredReceipt {
    status: u64,
    cumulative_gas_used: u64,
    logs: Vec<StoredLog>,
}

/// gov5's receipts root: `hash.DeriveSha(receipts)` — keccak over the
/// concatenation of `rlp([status, cumulativeGasUsed, [[address, topics,
/// data]…]])` per receipt, and keccak of nothing when there are none. Not a
/// trie; no bloom, no transaction type.
pub fn gov5_receipts_root<'a>(receipts: impl IntoIterator<Item = ReceiptView<'a>>) -> B256 {
    let mut concatenated = Vec::new();
    for receipt in receipts {
        StoredReceipt {
            status: u64::from(receipt.success),
            cumulative_gas_used: receipt.cumulative_gas_used,
            logs: receipt
                .logs
                .iter()
                .map(|log| StoredLog {
                    address: log.address,
                    topics: log.data.topics().to_vec(),
                    data: log.data.data.clone(),
                })
                .collect(),
        }
        .encode(&mut concatenated);
    }
    keccak256(&concatenated)
}

/// The Engine API payload for a block whose header is already final.
///
/// Everything the Engine API needs is in the header and transactions, with
/// one exception: execution requests are carried by hash only, since neither
/// gov5's block form nor a header lists them. A block with the empty requests
/// hash gets the empty list, which every `newPayload` version accepts; one
/// with real requests is handed over by hash, which an execution layer
/// accepts only where its API allows it.
pub fn execution_data_for_block(
    block_hash: B256,
    block: &Block<TxEnvelope>,
    extension: &Gov5HeaderExtension,
) -> ExecutionData {
    let mut payload = ExecutionPayload::from_block_unchecked(block_hash, block).0;
    // The one field a payload cannot describe as Ethereum: carried in the
    // payload's own slot for it, so the execution layer hashes the header
    // gov5 hashed.
    payload.as_v1_mut().mobile_registry_root = extension.mobile_registry_root;
    let sidecar = match block.header.parent_beacon_block_root {
        None => ExecutionPayloadSidecar::none(),
        Some(parent_beacon_block_root) => {
            let cancun = CancunPayloadFields {
                parent_beacon_block_root,
                versioned_hashes: block
                    .body
                    .transactions
                    .iter()
                    .flat_map(|tx| {
                        alloy_consensus::Transaction::blob_versioned_hashes(tx)
                            .map(<[B256]>::to_vec)
                            .unwrap_or_default()
                    })
                    .collect(),
            };
            match block.header.requests_hash {
                None => ExecutionPayloadSidecar::v3(cancun),
                Some(hash) if is_empty_requests_hash(hash) => ExecutionPayloadSidecar::v4(
                    cancun,
                    PraguePayloadFields {
                        requests: RequestsOrHash::Requests(Requests::default()),
                    },
                ),
                Some(hash) => ExecutionPayloadSidecar::v4(
                    cancun,
                    PraguePayloadFields {
                        requests: RequestsOrHash::Hash(hash),
                    },
                ),
            }
        }
    };
    ExecutionData::new(payload, sidecar)
}

/// The block a payload describes, with the header fields a payload cannot
/// carry (`ommers_hash`, `difficulty`) restored by trying gov5's variants
/// and letting the payload's block hash pick one, and the extension the
/// payload names.
///
/// A payload whose header is already the gov5 shape reconstructs; one
/// whose hash matches none of the variants is refused — the header on the
/// wire is not the block that was hashed.
pub fn reconstruct_gov5_h2_block<T: alloy_eips::Decodable2718>(
    execution: &ExecutionData,
) -> Result<(Block<T>, Gov5HeaderExtension), HeaderProfileError> {
    let expected = execution.block_hash();
    let extension = Gov5HeaderExtension {
        mobile_registry_root: execution.payload.as_v1().mobile_registry_root,
    };
    let mut block = execution
        .clone()
        .try_into_block::<T>()
        .map_err(|e| HeaderProfileError::Reconstruction(e.to_string()))?;
    validate_gov5_h2_header(&block.header)?;
    // Two more fields a payload cannot carry as gov5 wrote them: the
    // withdrawals root, which gov5 fills with its rewards commitment (the
    // payload's empty withdrawals list reconstructs to the trie's empty
    // root), and the requests hash, whose "none" gov5 spells differently
    // from EIP-7685. Each has the value the payload implies and the value
    // gov5 would have written; the hash picks.
    let withdrawals_roots: Vec<Option<B256>> = match block.header.withdrawals_root {
        Some(root) => {
            let rewards = withdrawals_to_rewards(block.body.withdrawals.as_ref().map_or(&[][..], |w| w.as_slice()));
            vec![Some(root), Some(gov5_rewards_root(rewards))]
        }
        None => vec![None],
    };
    // "No requests" has three spellings, and a fourth on a chain whose
    // producer leaves the field nil under Prague (chain 94): a payload with
    // empty requests reconstructs to any of them.
    let requests_hashes: Vec<Option<B256>> = match block.header.requests_hash {
        Some(hash) if is_empty_requests_hash(hash) => {
            vec![Some(hash), Some(GOV5_EMPTY_REQUESTS_HASH), Some(EMPTY_REQUESTS_HASH), None]
        }
        other => vec![other],
    };
    for ommers_hash in [B256::ZERO, EMPTY_OMMER_ROOT_HASH] {
        for difficulty in [U256::ZERO, U256::from(1)] {
            for withdrawals_root in &withdrawals_roots {
                for requests_hash in &requests_hashes {
                    block.header.ommers_hash = ommers_hash;
                    block.header.difficulty = difficulty;
                    block.header.withdrawals_root = *withdrawals_root;
                    block.header.requests_hash = *requests_hash;
                    if gov5_header_hash(&block.header, &extension) == expected {
                        return Ok((block, extension));
                    }
                }
            }
        }
    }
    Err(HeaderProfileError::Reconstruction(
        "no gov5 header variant hashes to the payload's block hash".into(),
    ))
}

/// Turns a locally built payload into the block this node proposes.
///
/// The execution layer builds a block for a view it does not know, with the
/// seal unsigned; this stamps the view, seals with the leader's key when one
/// is given, forces the two fields gov5's producer sets (`ommers_hash` zero,
/// `difficulty` zero), and forms the new block hash. Execution outputs —
/// state root, receipts root, gas — are untouched: they were computed for
/// exactly these transactions and stay valid under the new header.
///
/// A payload built under the Ethereum profile is accepted as input: the
/// point is to make one that was not into one that is.
pub fn normalize_to_gov5_h2(
    execution: &ExecutionData,
    view: u64,
    sealer: Option<&BlsSecretKey>,
    schedule: &Gov5ForkSchedule,
) -> Result<ExecutionData, HeaderProfileError> {
    let mut block = execution
        .clone()
        .try_into_block::<TxEnvelope>()
        .map_err(|e| HeaderProfileError::Reconstruction(e.to_string()))?;
    // gov5's own field, as its leaders stamp it at this timestamp.
    let extension = schedule.extension_at(block.header.timestamp);
    block.header.ommers_hash = B256::ZERO;
    block.header.difficulty = U256::ZERO;
    block.header.nonce = Default::default();
    block.header.extra_data = HeaderExtra::for_view(view).encode();
    // gov5's two non-Ethereum roots. The withdrawals field carries the
    // rewards commitment; the block's withdrawals are its rewards (see
    // `rewards_to_withdrawals`), keccak of nothing when there are none.
    if block.header.withdrawals_root.is_some() {
        let rewards = withdrawals_to_rewards(block.body.withdrawals.as_ref().map_or(&[][..], |w| w.as_slice()));
        block.header.withdrawals_root = Some(gov5_rewards_root(rewards));
    }
    if block.header.requests_hash.is_some_and(is_empty_requests_hash) {
        // What gov5's producers write for "no requests": the empty trie
        // root on chains whose miner fills the field, nothing on chain 94,
        // whose miner leaves it nil — which is what it does under the
        // mobile-anchor fork, the only place this node can tell the two
        // apart. Either way the execution layer accepts the block: it
        // validates an absent hash against empty requests.
        block.header.requests_hash = if extension.is_none() {
            Some(GOV5_EMPTY_REQUESTS_HASH)
        } else {
            None
        };
    }
    if let Some(key) = sealer {
        seal_header(&mut block.header, &extension, key)?;
    }
    let hash = gov5_header_hash(&block.header, &extension);
    Ok(execution_data_for_block(hash, &block, &extension))
}

/// A block body with these transactions and, on a post-Shanghai header, the
/// block's rewards as its withdrawals; a header without a withdrawals root
/// gets no withdrawals list, and its rewards must be none.
pub fn block_for_header_with_rewards(
    header: Header,
    transactions: Vec<TxEnvelope>,
    rewards: &[(Address, U256)],
) -> Result<Block<TxEnvelope>, HeaderProfileError> {
    let withdrawals = match header.withdrawals_root {
        Some(_) => Some(Withdrawals(rewards_to_withdrawals(rewards)?)),
        None if rewards.is_empty() => None,
        None => {
            return Err(HeaderProfileError::Reconstruction(
                "rewards on a header without a withdrawals root".into(),
            ))
        }
    };
    Ok(Block {
        header,
        body: alloy_consensus::BlockBody { transactions, ommers: Vec::new(), withdrawals },
    })
}

/// A block body with these transactions and, on a post-Shanghai header, the
/// empty withdrawals list that its empty withdrawals root implies.
pub fn block_for_header(header: Header, transactions: Vec<TxEnvelope>) -> Block<TxEnvelope> {
    let withdrawals = header
        .withdrawals_root
        .map(|_| alloy_eips::eip4895::Withdrawals::default());
    Block {
        header,
        body: BlockBody {
            transactions,
            ommers: Vec::new(),
            withdrawals,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::EMPTY_ROOT_HASH;
    use alloy_primitives::{address, hex, LogData};

    // Every expected value below was printed by gov5's own code
    // (`hash.DeriveSha`, `buildHeaderExtra`, `sealHash`, `Header.Hash`) run
    // over the same inputs.

    #[test]
    fn rewards_round_trip_through_withdrawals() {
        let one_ether = U256::from(1_000_000_000_000_000_000u128);
        let rewards = vec![
            (address!("d2a316a1cd3a777141cb7e5aace46fb01df90eac"), one_ether),
            (address!("42e9819036f61bf665d5f727e8c03121f12f586e"), one_ether),
        ];
        let withdrawals = rewards_to_withdrawals(&rewards).unwrap();
        assert_eq!(withdrawals.len(), 2);
        assert_eq!(withdrawals[0].index, 0);
        assert_eq!(withdrawals[1].index, 1);
        assert_eq!(withdrawals[0].amount, 1_000_000_000, "one ether is 1e9 gwei");
        assert_eq!(withdrawals_to_rewards(&withdrawals), rewards);
        assert!(rewards_to_withdrawals(&[(rewards[0].0, U256::from(1))]).is_err(), "a wei is not a withdrawal");
        assert_eq!(gov5_rewards_root(withdrawals_to_rewards(&[])), GOV5_NIL_HASH);
    }

    #[test]
    fn a_normalized_block_commits_to_its_rewards_and_reconstructs() {
        let one_ether = U256::from(1_000_000_000_000_000_000u128);
        let leader = address!("d2a316a1cd3a777141cb7e5aace46fb01df90eac");
        let mut header = fixture_header();
        header.withdrawals_root = Some(EMPTY_ROOT_HASH);
        let withdrawals = rewards_to_withdrawals(&[(leader, one_ether)]).unwrap();
        let block = Block {
            header,
            body: alloy_consensus::BlockBody {
                transactions: Vec::<TxEnvelope>::new(),
                ommers: Vec::new(),
                withdrawals: Some(Withdrawals(withdrawals.clone())),
            },
        };
        let hash = block.header.hash_slow();
        let normalized = normalize_to_gov5_h2(&execution_data_for_block(hash, &block, &Gov5HeaderExtension::NONE), 7, None, &Gov5ForkSchedule::default()).unwrap();
        let (rebuilt, _) = reconstruct_gov5_h2_block::<TxEnvelope>(&normalized).unwrap();
        assert_eq!(rebuilt.header.withdrawals_root, Some(gov5_rewards_root([(leader, one_ether)])));
        assert_eq!(rebuilt.body.withdrawals.as_deref(), Some(&withdrawals));
        assert_eq!(rebuilt.header.hash_slow(), normalized.block_hash());
    }

    #[test]
    fn empty_receipts_root_is_keccak_of_nothing() {
        assert_eq!(gov5_receipts_root([]), GOV5_NIL_HASH);
        assert_eq!(GOV5_NIL_HASH, keccak256([]));
    }

    #[test]
    fn receipts_root_matches_gov5_derive_sha() {
        let log = Log {
            address: address!("1111111111111111111111111111111111111111"),
            data: LogData::new_unchecked(
                vec![
                    b256!("2222222222222222222222222222222222222222222222222222222222222222"),
                    b256!("0000000000000000000000000000000000000000000000000000000000000033"),
                ],
                Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            ),
        };
        let logs = [log];
        let root = gov5_receipts_root([
            ReceiptView {
                success: true,
                cumulative_gas_used: 21_000,
                logs: &[],
            },
            ReceiptView {
                success: false,
                cumulative_gas_used: 63_000,
                logs: &logs,
            },
        ]);
        assert_eq!(root, GOV5_RECEIPTS_TWO);
    }

    fn fixture_header() -> Header {
        Header {
            parent_hash: B256::repeat_byte(1),
            ommers_hash: B256::ZERO,
            beneficiary: address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
            state_root: B256::repeat_byte(2),
            transactions_root: EMPTY_ROOT_HASH,
            receipts_root: GOV5_NIL_HASH,
            difficulty: U256::ZERO,
            number: 7,
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            extra_data: HeaderExtra::for_view(7).encode(),
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: Some(EMPTY_REQUESTS_HASH),
            ..Default::default()
        }
    }

    #[test]
    fn extra_data_matches_gov5_build_header_extra() {
        let extra = HeaderExtra::for_view(7).encode();
        assert_eq!(hex::encode(&extra), GOV5_EXTRA_VIEW7);
        let decoded = HeaderExtra::decode(&extra).unwrap();
        assert_eq!(decoded.view, 7);
        assert!(decoded.qc.is_empty());
        assert_eq!(decoded.seal, Some([0; 96]));
    }

    #[test]
    fn header_hash_and_seal_hash_match_gov5() {
        let header = fixture_header();
        assert_eq!(header.hash_slow(), GOV5_HEADER_HASH);
        assert_eq!(seal_hash(&header, &Gov5HeaderExtension::NONE), GOV5_SEAL_HASH);
        assert_eq!(validate_gov5_h2_header(&header).unwrap().view, 7);
    }

    #[test]
    fn a_seal_signs_the_unsealed_header_and_verifies() {
        let key = BlsSecretKey::random().unwrap();
        let mut header = fixture_header();
        let before = seal_hash(&header, &Gov5HeaderExtension::NONE);
        seal_header(&mut header, &Gov5HeaderExtension::NONE, &key).unwrap();
        // Sealing changes the block hash but not what was signed.
        assert_ne!(header.hash_slow(), GOV5_HEADER_HASH);
        assert_eq!(seal_hash(&header, &Gov5HeaderExtension::NONE), before);
        verify_seal(&header, &Gov5HeaderExtension::NONE, &key.public_key()).unwrap();
        let other = BlsSecretKey::random().unwrap();
        assert!(verify_seal(&header, &Gov5HeaderExtension::NONE, &other.public_key()).is_err());
    }

    #[test]
    fn gov5_layouts_decode_and_others_are_refused() {
        // QC then seal: what a gov5 leader with a committed QC writes.
        let with_qc = HeaderExtra {
            view: 3,
            qc: vec![0xAB; 40],
            seal: Some([1; 96]),
        };
        assert_eq!(HeaderExtra::decode(&with_qc.encode()).unwrap(), with_qc);
        // Bare view.
        let bare = HeaderExtra {
            view: 9,
            qc: vec![],
            seal: None,
        };
        assert_eq!(HeaderExtra::decode(&bare.encode()).unwrap(), bare);
        assert!(matches!(
            HeaderExtra::decode(b"N42"),
            Err(HeaderProfileError::ExtraTooShort(3))
        ));
        assert!(matches!(
            HeaderExtra::decode(&[0u8; 12]),
            Err(HeaderProfileError::MissingMagic)
        ));
        assert!(matches!(
            HeaderExtra::decode(&vec![0u8; 4097]),
            Err(HeaderProfileError::ExtraTooLong(4097))
        ));
    }

    #[test]
    fn normalizing_a_payload_gives_a_gov5_header_that_round_trips() {
        let key = BlsSecretKey::random().unwrap();
        let mut ethereum = fixture_header();
        ethereum.ommers_hash = EMPTY_OMMER_ROOT_HASH;
        ethereum.extra_data = Bytes::from(vec![0u8; 97]);
        let block = block_for_header(ethereum, vec![]);
        let built = execution_data_for_block(block.header.hash_slow(), &block, &Gov5HeaderExtension::NONE);

        let proposed = normalize_to_gov5_h2(&built, 42, Some(&key), &Gov5ForkSchedule::default()).unwrap();
        let (reconstructed, _) = reconstruct_gov5_h2_block::<TxEnvelope>(&proposed).unwrap();
        assert_eq!(reconstructed.header.hash_slow(), proposed.block_hash());
        assert_eq!(reconstructed.header.ommers_hash, B256::ZERO);
        assert_eq!(header_view(&reconstructed.header).unwrap(), 42);
        verify_seal(&reconstructed.header, &Gov5HeaderExtension::NONE, &key.public_key()).unwrap();
        // Execution outputs survived, and the two roots gov5 spells its own
        // way took gov5's spelling.
        assert_eq!(reconstructed.header.state_root, B256::repeat_byte(2));
        assert_eq!(reconstructed.header.receipts_root, GOV5_NIL_HASH);
        assert_eq!(reconstructed.header.withdrawals_root, Some(GOV5_NIL_HASH));
        assert_eq!(reconstructed.header.requests_hash, Some(GOV5_EMPTY_REQUESTS_HASH));
        assert!(proposed.sidecar.requests().is_some());
    }

    #[test]
    fn gov5_roots_for_nothing_are_what_gov5_writes() {
        assert_eq!(gov5_rewards_root([]), GOV5_NIL_HASH);
        assert_eq!(GOV5_EMPTY_REQUESTS_HASH, alloy_consensus::EMPTY_ROOT_HASH);
        assert!(is_empty_requests_hash(EMPTY_REQUESTS_HASH));
        assert!(is_empty_requests_hash(GOV5_EMPTY_REQUESTS_HASH));
        assert!(!is_empty_requests_hash(B256::ZERO));
    }

    #[test]
    fn a_payload_that_lies_about_its_hash_does_not_reconstruct() {
        let block = block_for_header(fixture_header(), vec![]);
        let mut payload = execution_data_for_block(block.header.hash_slow(), &block, &Gov5HeaderExtension::NONE);
        payload.payload.as_v1_mut().block_hash = B256::repeat_byte(0xEE);
        assert!(reconstruct_gov5_h2_block::<TxEnvelope>(&payload).is_err());
    }

    include!("header_profile_fixture.rs");
}

#[cfg(test)]
mod chain94_tests {
    //! Against a header gov5 produced on chain 94 under its `mobileAnchor`
    //! fork: block 13,560,300, taken from a node's database with
    //! `qs-block-rlp`, hash `0x9f117dba…` as the node reports it.
    use super::*;
    use alloy_primitives::{b256, hex};

    /// The whole block in gov5's wire form, `[header, [tx bytes…],
    /// verifiers, rewards]`.
    const BLOCK_HEX: &str = include_str!("../testdata/chain94_block_13560300.hex");
    const HASH: B256 = b256!("9f117dbafd6bdf0c74549bca6f2e26cbec668af4981ec36fbd7a41bae55c7a19");

    /// The items of the outer list, each with its RLP header.
    fn block_items() -> Vec<Vec<u8>> {
        let block = hex::decode(BLOCK_HEX.trim()).unwrap();
        let mut cursor = block.as_slice();
        let outer = RlpHeader::decode(&mut cursor).unwrap();
        assert!(outer.list);
        let mut items = Vec::new();
        while !cursor.is_empty() {
            let mut probe = cursor;
            let item = RlpHeader::decode(&mut probe).unwrap();
            let total = cursor.len() - probe.len() + item.payload_length;
            items.push(cursor[..total].to_vec());
            cursor = &cursor[total..];
        }
        items
    }

    fn header_rlp() -> Vec<u8> {
        block_items()[0].clone()
    }

    fn transactions() -> Vec<TxEnvelope> {
        let items = block_items();
        let mut cursor = items[1].as_slice();
        let list = RlpHeader::decode(&mut cursor).unwrap();
        assert!(list.list);
        let mut transactions = Vec::new();
        while !cursor.is_empty() {
            let bytes = Bytes::decode(&mut cursor).unwrap();
            transactions.push(<TxEnvelope as alloy_eips::Decodable2718>::decode_2718_exact(&bytes).unwrap());
        }
        transactions
    }

    #[test]
    fn alloy_refuses_the_header_and_this_codec_reads_it() {
        let rlp = header_rlp();
        assert!(<Header as alloy_rlp::Decodable>::decode(&mut rlp.as_slice()).is_err());
        let (header, extension) = decode_gov5_header(&rlp).unwrap();
        assert_eq!(header.number, 13_560_300);
        assert_eq!(header.ommers_hash, B256::ZERO);
        assert_eq!(header.difficulty, U256::ZERO);
        assert_eq!(header.base_fee_per_gas, Some(7));
        // gov5's producer leaves the blob gas pointers nil and the requests
        // hash nil under Prague; the placeholders read as zero gas and no
        // requests hash.
        assert_eq!(header.blob_gas_used, Some(0));
        assert_eq!(header.excess_blob_gas, Some(0));
        assert!(header.parent_beacon_block_root.is_some());
        assert_eq!(header.requests_hash, None);
        assert_eq!(header.block_access_list_hash, None);
        assert_eq!(extension.mobile_registry_root, Some(B256::ZERO));
        assert_eq!(HeaderExtra::decode(&header.extra_data).unwrap().view, 0x2aca);
    }

    #[test]
    fn the_codec_reproduces_the_bytes_and_the_hash() {
        let rlp = header_rlp();
        let (header, extension) = decode_gov5_header(&rlp).unwrap();
        assert_eq!(gov5_header_rlp(&header, &extension), rlp);
        assert_eq!(gov5_header_hash(&header, &extension), HASH);
        assert_ne!(header.hash_slow(), HASH, "alloy's hash omits the extension");
        assert_eq!(Gov5HeaderExtension::recover(&header, HASH), Some(extension));
        assert_eq!(Gov5HeaderExtension::recover(&header, B256::ZERO), None);
    }

    #[test]
    fn a_payload_round_trip_keeps_the_extension() {
        let (header, extension) = decode_gov5_header(&header_rlp()).unwrap();
        // The block's rewards: 1 ETH to the leader and 1 ETH to the faucet,
        // which the withdrawals root commits to.
        let one_ether = U256::from(1_000_000_000_000_000_000u128);
        let rewards = [
            (header.beneficiary, one_ether),
            (alloy_primitives::address!("42e9819036f61bf665d5f727e8c03121f12f586e"), one_ether),
        ];
        assert_eq!(header.withdrawals_root, Some(gov5_rewards_root(rewards)));
        let transactions = transactions();
        assert!(!transactions.is_empty());
        let block = block_for_header_with_rewards(header, transactions, &rewards).unwrap();
        let payload = execution_data_for_block(HASH, &block, &extension);
        assert_eq!(payload.payload.as_v1().mobile_registry_root, Some(B256::ZERO));
        let (rebuilt, rebuilt_extension) = reconstruct_gov5_h2_block::<TxEnvelope>(&payload).unwrap();
        assert_eq!(rebuilt_extension, extension);
        assert_eq!(gov5_header_hash(&rebuilt.header, &rebuilt_extension), HASH);
        assert_eq!(rebuilt.header.requests_hash, None);
    }

    #[test]
    fn the_schedule_says_when_the_field_is_stamped() {
        let schedule = Gov5ForkSchedule {
            mobile_anchor_time: Some(1_784_372_000),
        };
        assert_eq!(schedule.extension_at(1_784_371_999), Gov5HeaderExtension::NONE);
        assert_eq!(
            schedule.extension_at(1_784_372_000).mobile_registry_root,
            Some(B256::ZERO)
        );
        let (header, extension) = decode_gov5_header(&header_rlp()).unwrap();
        assert!(schedule.allows(header.timestamp, &extension));
        assert!(!schedule.allows(header.timestamp, &Gov5HeaderExtension::NONE));
        assert!(Gov5ForkSchedule::default().allows(header.timestamp, &Gov5HeaderExtension::NONE));

        let genesis: alloy_genesis::Genesis = serde_json::from_str(
            r#"{"config":{"chainId":94,"mobileAnchorTime":1784372000},"alloc":{},"difficulty":"0x0","gasLimit":"0x0"}"#,
        )
        .unwrap();
        assert_eq!(Gov5ForkSchedule::from_genesis(&genesis), schedule);
    }

    #[test]
    fn a_leader_stamps_the_field_under_the_fork() {
        let (header, extension) = decode_gov5_header(&header_rlp()).unwrap();
        // A builder's Ethereum-shaped payload for the same block: no
        // extension, the empty requests hash in EIP-7685's spelling.
        let mut ethereum = header.clone();
        ethereum.requests_hash = Some(EMPTY_REQUESTS_HASH);
        ethereum.ommers_hash = EMPTY_OMMER_ROOT_HASH;
        let block = block_for_header_with_rewards(ethereum, Vec::new(), &[]).unwrap();
        let built = execution_data_for_block(block.header.hash_slow(), &block, &Gov5HeaderExtension::NONE);
        let schedule = Gov5ForkSchedule {
            mobile_anchor_time: Some(1_784_372_000),
        };
        let proposed = normalize_to_gov5_h2(&built, 0x2aca, None, &schedule).unwrap();
        let (rebuilt, rebuilt_extension) = reconstruct_gov5_h2_block::<TxEnvelope>(&proposed).unwrap();
        assert_eq!(rebuilt_extension, extension);
        assert_eq!(rebuilt.header.requests_hash, None);
        assert_eq!(rebuilt.header.ommers_hash, B256::ZERO);
        // Everything but the seal (unsigned here) and the withdrawals root
        // (no rewards given) is the header gov5 wrote.
        assert_eq!(rebuilt.header.extra_data[..EXTRA_MIN_LEN], header.extra_data[..EXTRA_MIN_LEN]);
        assert_eq!(rebuilt.header.state_root, header.state_root);
    }
}
