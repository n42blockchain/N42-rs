use std::error::Error;
use std::hash::Hash;
use std::io::Write;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::thread;
use alloy_primitives::{U256, hex, Bloom, BlockNumber, keccak256, B64, B256, Address, Bytes, FixedBytes};
use alloy_rlp::{length_of_length, Encodable};
use bytes::{BufMut, BytesMut};
use itertools::Itertools;
use rand::prelude::SliceRandom;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_primitives::{SealedBlock, SealedHeader, BlockWithSenders, public_key_to_address};
use reth_primitives_traits::{Header, header::clique_utils::{recover_address, SIGNATURE_LENGTH, seal_hash}};
use reth_provider::{HeaderProvider, SnapshotProvider, TdProvider};
use tracing::{info, warn, debug, error};
use n42_primitives::{APosConfig, Snapshot};

use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use k256::ecdsa::SigningKey;
use alloy_signer::SignerSync;
use reth_consensus::{PostExecutionInput, Consensus, ConsensusError, HeaderConsensusError};
use reth_storage_api::{SnapshotProviderWriter, TdProviderWriter};
use std::str::FromStr;

//
const CHECKPOINT_INTERVAL: u64 = 2048; // Number of blocks after which to save the vote snapshot to the database
const INMEMORY_SNAPSHOTS: u32 = 128; // Number of recent vote snapshots to keep in memory

const WIGGLE_TIME: Duration = Duration::from_millis(500); // Random delay (per signer) to allow concurrent signers
const MERGE_SIGN_MIN_TIME: u64 = 4; // min time for merge sign


// APos proof-of-authority protocol constants
pub const EPOCH_LENGTH: u64 = 30000; // Default number of blocks after which to checkpoint and reset the pending votes

pub const EXTRA_VANITY: usize = 32; // Fixed number of extra-data prefix bytes reserved for signer vanity
pub const EXTRA_SEAL: usize = 65;

pub const NONCE_AUTH_VOTE: [u8; 8] = hex!("ffffffffffffffff"); // Magic nonce number to vote on adding a new signer
pub const NONCE_DROP_VOTE: [u8; 8] = hex!("0000000000000000"); // Magic nonce number to vote on removing a signer
// Difficulty constants
pub const DIFF_IN_TURN: U256 = U256::from_limbs([2u64, 0, 0, 0]);  // Block difficulty for in-turn signatures
pub const DIFF_NO_TURN: U256 = U256::from_limbs([1u64, 0, 0, 0]);  // Block difficulty for out-of-turn signatures

pub const FULL_IMMUTABILITY_THRESHOLD: usize= 90000;



#[derive(Debug, Clone)]
pub enum AposError {
    UnknownBlock,
    InvalidCheckpointBeneficiary,
    InvalidVote,
    InvalidCheckpointVote,
    MissingVanity,
    MissingSignature,
    ExtraSigners,
    InvalidCheckpointSigners,
    MismatchingCheckpointSigners,
    InvalidMixDigest,
    InvalidUncleHash,
    InvalidDifficulty,
    WrongDifficulty,
    InvalidTimestamp,
    InvalidVotingChain,
    UnauthorizedSigner,
    RecentlySigned,
    UnTransion,
}

impl std::fmt::Display for AposError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::UnknownBlock => "unknown block",
                Self::InvalidCheckpointBeneficiary => "beneficiary in checkpoint block non-zero",
                Self::InvalidVote => "vote nonce not 0x00..0 or 0xff..f",
                Self::InvalidCheckpointVote => "vote nonce in checkpoint block non-zero",
                Self::MissingVanity => "extra-data 32 byte vanity prefix missing",
                Self::MissingSignature => "extra-data 65 byte signature suffix missing",
                Self::ExtraSigners => "non-checkpoint block contains extra signer list",
                Self::InvalidCheckpointSigners => "invalid signer list on checkpoint block",
                Self::MismatchingCheckpointSigners => "mismatching signer list on checkpoint block",
                Self::InvalidMixDigest => "non-zero mix digest",
                Self::InvalidUncleHash => "non-empty uncle hash",
                Self::InvalidDifficulty => "invalid difficulty",
                Self::WrongDifficulty => "wrong difficulty",
                Self::InvalidTimestamp => "invalid timestamp",
                Self::InvalidVotingChain => "invalid voting chain",
                Self::UnauthorizedSigner => "unauthorized signer",
                Self::RecentlySigned => "recently signed",
                Self::UnTransion => "sealing paused while waiting for transactions",
            }
        )
    }
}

impl Error for AposError {}

// APos is the proof-of-authority consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
pub struct APos<Provider, ChainSpec>
where
    Provider: HeaderProvider + TdProvider + TdProviderWriter +SnapshotProvider + SnapshotProviderWriter + Clone + Unpin + 'static,
    ChainSpec: EthChainSpec + EthereumHardforks
{
    config: APosConfig,          // Consensus engine configuration parameters
    /// Chain spec
    chain_spec: Arc<ChainSpec>,
    recents: RwLock<schnellru::LruMap<B256, Snapshot>>,    // Snapshots for recent block to speed up reorgs
    proposals: Arc<RwLock<HashMap<Address, bool>>>,   // Current list of proposals we are pushing
    signer: RwLock<Option<Address>>, // Ethereum address of the signing key
    eth_signer: RwLock<Option<LocalSigner<SigningKey>>>,
    //  Provider,
    provider: Provider,
    recent_headers: RwLock<schnellru::LruMap<B256, Header>>,    // Recent headers for snapshot
}


// New creates a APos proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
impl<Provider, ChainSpec> APos<Provider, ChainSpec>
where
    Provider: HeaderProvider + TdProvider + TdProviderWriter +SnapshotProvider + SnapshotProviderWriter + Clone + Unpin + 'static,
    ChainSpec: EthChainSpec + EthereumHardforks
{
    pub fn new(
        provider: Provider,
        chain_spec: Arc<ChainSpec>,
        signer_private_key: Option<String>,
    ) -> Self
    {
        let recents = RwLock::new(schnellru::LruMap::new(schnellru::ByLength::new(INMEMORY_SNAPSHOTS)));
        let recent_headers = RwLock::new(schnellru::LruMap::new(schnellru::ByLength::new(CHECKPOINT_INTERVAL as u32 * 2)));

        // signer_pk.sign_hash_sync();
        let eth_signer: Option<PrivateKeySigner> = signer_private_key.map(|key| { key.parse().unwrap() });
        //let eth_signer = PrivateKeySigner::random();

        let eth_signer_address = eth_signer.clone().map(|signer| {signer.address()});
        info!(target: "consensus::apos", "apos set signer address {:?}", eth_signer_address);

        let mut config = APosConfig::default();
        if let Some(clique) = chain_spec.genesis().config.clique {
            if let Some(period) = clique.period {
                config.period = period;
            }
            if let Some(epoch) = clique.epoch {
                config.epoch = epoch;
            }
        }
        Self {
            config,
            chain_spec,
            recents,
            recent_headers,
            proposals: Arc::new(RwLock::new(HashMap::new())),
            signer: RwLock::new(eth_signer_address),
            eth_signer: RwLock::new(eth_signer),
            provider,
        }
    }

    fn set_signer(&self, eth_signer: Option<LocalSigner<SigningKey>>) {
        let eth_signer_address = eth_signer.clone().map(|signer| {signer.address()});
        info!(target: "consensus::apos", "set_signer, new signer={:?}", eth_signer_address);
        let mut signer_guard = self.signer.write().unwrap();
        let mut eth_signer_guard = self.eth_signer.write().unwrap();
        *signer_guard = eth_signer_address;
        *eth_signer_guard = eth_signer;
    }

    /// verifySeal checks whether the signature contained in the header satisfies the
    /// consensus protocol requirements. The method accepts an optional list of parent
    /// headers that aren't yet part of the local blockchain to generate the snapshots
    /// from.
    pub fn verify_seal(
        &self,
        snap: &Snapshot,
        header: &Header,
        _parents: Option<Vec<Header>>,
    ) -> Result<(), Box<dyn std::error::Error>> {

        // Verifying the genesis block is not supported
        if header.number == 0 {
            return Err(AposError::UnknownBlock.into());
        }
        info!(target: "consensus::apos", "header number: {}", header.number);

        //Analyze the signer and check if they are in the signer list
        let signer = recover_address(header)?;
        if !snap.signers.contains(&signer) {
            info!(target: "consensus::apos", "err signer not in list: {}", signer);
            return Err(AposError::UnauthorizedSigner.into());
        }
        info!(target: "consensus::apos", "recovered address: {}", signer);

       //Check the list of recent signatories
        for (seen, recent) in &snap.recents {
            if *recent == signer {
                //If the signer is in the recent list, ensure that the current block can be removed
                let limit = (snap.signers.len() as u64 / 2) + 1;
                if *seen > header.number - limit {
                    return Err(AposError::RecentlySigned.into());
                }
            }
        }

       //Ensure that the difficulty corresponds to the signer's round
        let in_turn = snap.inturn(header.number, &signer);
        if in_turn && header.difficulty != DIFF_IN_TURN {
            return Err(AposError::WrongDifficulty.into());
        }
        if !in_turn && header.difficulty == DIFF_IN_TURN {
            return Err(AposError::WrongDifficulty.into());
        }

        Ok(())
    }

    // fn finalize(
    //     &self,
    //     chain: &dyn ChainHeaderReader,
    //     header: &mut SealedHeader,
    //     state: &mut IntraBlockState,
    //     txs: Vec<Transaction>,
    //     uncles: Vec<Box<dyn IHeader>>,
    // ) -> Result<(Vec<Reward>, HashMap<Address, U256>), Box<dyn std::error::Error>> {
    //     // No block rewards in PoA, so the state remains as is and uncles are dropped
    //     // chain.config().is_eip158(header.number())
    
    //     let (rewards, unpay_map, err) = do_reward(self.chain_config.clone(), state, header, chain)?;
    //     if err.is_some() {
    //         return Err(err.unwrap().into());
    //     }
    
    //     let raw_header = header;
    //     raw_header.root = state.intermediate_root();
    //     // Todo can not verify author
    //     raw_header.mix_digest = state.before_state_root();
    //     // Todo
    //     // raw_header.uncle_hash = types::calc_uncle_hash(None);
    
    //     Ok((rewards, unpay_map))
    // }
    

    // // FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
    // // nor block rewards given, and returns the final block.
    // fn finalize_and_assemble(
    //     &self,
    //     chain: &dyn ChainHeaderReader,
    //     header: &mut SealedHeader,
    //     state: &mut IntraBlockState,
    //     txs: Vec<Transaction>,
    //     uncles: Vec<Box<dyn IHeader>>,
    //     receipts: Vec<Receipt>,
    // ) -> Result<(Box<dyn IBlock>, Vec<Reward>, HashMap<Address, U256>), Box<dyn std::error::Error>> {
    //     // Finalize block
    //     let (rewards, unpay, err) = self.finalize(chain, header, state, txs.clone(), uncles.clone())?;
    //     if err.is_some() {
    //         return Err(err.unwrap().into());
    //     }

    //     // Assemble and return the final block for sealing
    //     let block = Block::new_block_from_receipt(header, txs, uncles, receipts, rewards.clone());
    //     Ok((Box::new(block), rewards, unpay))
    // }

    // // Authorize injects a private key into the consensus engine to mint new blocks
    // // with.
    // fn authorize(&mut self, signer: Address, sign_fn: SignerFn) {
    //     let _lock = self.lock.lock().unwrap(); // Acquire the lock, automatically releases at the end of the scope

    //     self.signer = signer;
    //     self.sign_fn = Some(sign_fn);
    // }

    // CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have:
// * DIFF_NOTURN(2) if BLOCK_NUMBER % SIGNER_COUNT != SIGNER_INDEX
// * DIFF_INTURN(1) if BLOCK_NUMBER % SIGNER_COUNT == SIGNER_INDEX
    pub fn calc_difficulty(
        &mut self,
        parent: Header,          // assuming IHeader is a trait
    ) -> U256 {
        let Ok(snap) = self.snapshot(
            parent.number,
            parent.hash_slow(),
            None,
        ) else { todo!() };

        let signer_guard = self.signer.read().unwrap();
        //calc_difficulty(&snap, &self.signer.get())
        if let Some(signer) = *signer_guard {
            calc_difficulty(&snap, &signer)
        } else {
            warn!(target: "consensus::apos",
                "calc_difficulty() called when no signer is set",
            );
            DIFF_NO_TURN
        }
    }


    // SealHash returns the hash of a block prior to it being sealed.
    pub fn seal_hash(&self, header: &Header) -> B256 {
        seal_hash(header)
    }

     // Close implements consensus.Engine. It's a noop for Apoa as there are no background threads.
    pub fn close(&self) -> Result<(), ()> {
        Ok(())
    }

    // APIs implements consensus.Engine, returning the user facing RPC API to allow
    // controlling the signer voting.

    fn save_total_difficulty(&self, header: &Header) {
        let total_difficulty = if header.number == 1 {
            header.difficulty
        } else {
            if let Ok(Some(parent_td)) = self.provider.load_td(&header.parent_hash) {
                parent_td + header.difficulty
            } else {
                warn!(target: "consensus::apos", "td not found for hash {:?}", header.parent_hash);
                U256::from(0)
            }
        };
        self.provider.save_td(&header.hash_slow(), total_difficulty).unwrap();
        info!(target: "consensus::apos", "saved total_difficulty {}", total_difficulty);
    }
}


 

fn calc_difficulty(snap: &Snapshot, signer: &Address) -> U256 {
    if snap.inturn(snap.number + 1, signer) {
        DIFF_IN_TURN
    } else {
        DIFF_NO_TURN
    }
}




impl<Provider, ChainSpec> Debug for APos<Provider, ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks,
    Provider: 'static + Clone + HeaderProvider + TdProvider + TdProviderWriter + SnapshotProvider + SnapshotProviderWriter + Unpin,
{
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl<Provider, ChainSpec> Consensus for APos<Provider, ChainSpec>
where
    Provider: HeaderProvider + TdProvider + TdProviderWriter +SnapshotProvider + SnapshotProviderWriter + Clone + Unpin + 'static,
    ChainSpec: EthChainSpec + EthereumHardforks
{

    fn validate_header(&self,header: &SealedHeader) -> Result<(), ConsensusError> {

        let header = header.header();
        if header.number == 0 {
            return Err(ConsensusError::UnknownBlock);
        }
        let number = header.number;

        // Don't waste time checking blocks from the future
        let present_timestamp =
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        if header.timestamp > present_timestamp {
            return Err(ConsensusError::TimestampIsInFuture {
                timestamp: header.timestamp,
                present_timestamp,
            })
        }

        // Checkpoint blocks need to enforce zero beneficiary
        let checkpoint = (number % self.config.epoch) == 0;
        if checkpoint && header.beneficiary != Address::ZERO {
            return Err(ConsensusError::InvalidCheckpointBeneficiary);
        }


        // Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
        if header.nonce != NONCE_AUTH_VOTE && header.nonce != NONCE_DROP_VOTE {
            return Err(ConsensusError::InvalidVote);
        }

        if checkpoint && header.nonce != NONCE_DROP_VOTE {
            return Err(ConsensusError::InvalidCheckpointVote);
        }

        // Check that the extra-data contains both the vanity and signature
        if header.extra_data.len() < EXTRA_VANITY {
            return Err(ConsensusError::MissingVanity);
        }

        if header.extra_data.len() < EXTRA_VANITY + EXTRA_SEAL {
            return Err(ConsensusError::MissingSignature);
        }

        // Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
        let signers_bytes = header.extra_data.len() - EXTRA_VANITY - EXTRA_SEAL;
        if !checkpoint && signers_bytes != 0 {
            return Err(ConsensusError::ErrExtraSigners);
        }

        //todo
        if checkpoint && signers_bytes % 20 != 0 {
            return Err(ConsensusError::InvalidCheckpointSigners);
        }

        // Ensure that the block's difficulty is meaningful (may not be correct at this point)
        if number > 0 {
            if header.difficulty.is_zero() ||
                (header.difficulty != DIFF_IN_TURN && header.difficulty != DIFF_NO_TURN) {
                return Err(ConsensusError::InvalidDifficulty);
            }
        }

        //todo All basic checks passed, verify cascading fields
        Ok(())
    }

    fn validate_header_against_parent(
        &self,header: &SealedHeader,
        parent: &SealedHeader,
        ) -> Result<(),ConsensusError>  {
        info!(target: "consensus::apos", ?header, "in validate_header_against_parent");
        //self.validate_header(header)?;
        let header_hash = header.hash();
        let header = header.header();
        let number = header.number;
        if number == 0 {
            return Ok(());
        }

        let snap = self.snapshot(number - 1, header.parent_hash,
Some(vec![parent.header().clone()]))?;
        if number % self.config.epoch == 0 {
            let signers: Vec<u8> = snap.signers
                .iter()
                .flat_map(|signer| signer.as_slice().to_vec())
                .collect();
            let extra_suffix = header.extra_data.len() - EXTRA_SEAL;
            if header.extra_data[EXTRA_VANITY..extra_suffix] != signers[..] {
                return Err(ConsensusError::InvalidCheckpointSigners);
            }
        }

        self.verify_seal(&snap, header, None).map_err(|e| {ConsensusError::AposErrorDetail {detail: e.to_string()}})?;
        let mut recent_headers = self.recent_headers.write().unwrap();
        recent_headers.insert(header_hash, header.clone());

        self.save_total_difficulty(header);

        Ok(())
    }

    #[doc = " Validates the given headers"]
    #[doc = ""]
    #[doc = " This ensures that the first header is valid on its own and all subsequent headers are valid"]
    #[doc = " on its own and valid against its parent."]
    #[doc = ""]
    #[doc = " Note: this expects that the headers are in natural order (ascending block number)"]
    fn validate_header_range(&self, _headers: &[SealedHeader]) -> Result<(),HeaderConsensusError>{
        Ok(())
    }


    fn validate_header_with_total_difficulty(&self,header: &Header,_total_difficulty:U256,) -> Result<(),ConsensusError>  {
        Ok(())
    }


    fn validate_block_pre_execution(&self, _block: &SealedBlock) -> Result<(),ConsensusError>  {
        Ok(())
    }

    fn validate_block_post_execution(&self, _block: &BlockWithSenders,_input:PostExecutionInput<'_> ,) -> Result<(),ConsensusError>  {
        Ok(())
    }

    /// Prepare implements consensus.Engine, preparing all the consensus fields of the
    /// header for running the transactions on top.
    fn prepare(&self, parent_header: &SealedHeader) -> Result<Header, ConsensusError> {

        let mut header = Header::default(); 
        //If the block is not a checkpoint, vote randomly
        header.beneficiary = Address::ZERO;
        header.nonce = B64::from(0u64);
        header.number = parent_header.number + 1;
        header.parent_hash = parent_header.hash();



        //Assemble voting snapshots to check which votes are meaningful
        let snap = self.snapshot(parent_header.number, parent_header.hash(), None).map_err(|_| ConsensusError::UnknownBlock)?;

        if header.number %self.config.epoch != 0 {
            //Collect all proposals to be voted on
            let proposals_lock = self.proposals.read().unwrap();
            let addresses: Vec<Address> = proposals_lock.iter()
                //.filter(|(&address, &authorize)| snap.valid_vote(address, authorize))
                .map(|(address, _)| *address)
                .collect();

            //If there are proposals to be voted on, proceed with the vote
            if !addresses.is_empty() {
                header.beneficiary = *addresses.choose(&mut rand::thread_rng()).unwrap();
                if let Some(&authorize) = proposals_lock.get(&header.beneficiary) {
                    if authorize {
                        header.nonce = NONCE_AUTH_VOTE.into();
                    } else {
                        header.nonce = NONCE_DROP_VOTE.into();
                    }
                }
            }
        }

        //Copy the signer to prevent data competition
        let signer_guard = self.signer.read().unwrap();
        if let Some(signer) = *signer_guard {
            //Set the correct difficulty level
            header.difficulty = calc_difficulty(&snap, &signer);
        } else {
            return Err(ConsensusError::NoSignerSet);
        }

        let mut extra_data_mut = BytesMut::from(&header.extra_data[..]);
        //Ensure that the additional data has all its components
        extra_data_mut.resize(EXTRA_VANITY, 0x00);

        if header.number % self.config.epoch == 0 {
            for signer in snap.signers {
                extra_data_mut.extend(signer.iter());
            }
        }
        extra_data_mut.resize(extra_data_mut.len() + SIGNATURE_LENGTH, 0x00);
        header.extra_data = Bytes::from(extra_data_mut.freeze());

        header.mix_hash = Default::default();

        // Ensure the timestamp has the correct delay
        if let Ok(Some(parent)) = self.provider.header_by_hash_or_number(header.parent_hash.into()) {
            let parent_time = parent.timestamp;
            header.timestamp = parent_time + self.config.period;
        }

        Ok(header)
    }

    fn seal(&self, header: &mut Header) -> Result<(), ConsensusError> {

        // Sealing the genesis block is not supported
        if header.number == 0 {
            return Err(ConsensusError::UnknownBlock);
        }

        // For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
        // if self.config.period == 0 && header.body.transactions.is_empty() {
        //     return Err(AposError::UnTransion.into());
        // }
        //todo


        let signer = self.signer.read().unwrap().ok_or(ConsensusError::NoSignerSet)?;
        info!(target: "consensus::apos", "seal() signer={:?}", signer);
        // Bail out if we're unauthorized to sign a block
        let snap = self.snapshot(header.number - 1, header.parent_hash, None)?;
        if !snap.signers.contains(&signer) {
            error!(target: "consensus::pos", "err signer not in list: {}", signer);
            return Err(ConsensusError::UnauthorizedSigner)
        }

        // If we're amongst the recent signers, wait for the next block
        for (seen, recent) in &snap.recents {
            if *recent == signer {
                let limit = (snap.signers.len() as u64 / 2) + 1;
                if header.number < limit || *seen > header.number - limit {
                    error!(target: "consensus::engine", "Signed recently, must wait for others: limit: {}, seen: {}, number: {}, signer: {}", limit, seen, header.number, signer);
                    return Err(ConsensusError::RecentlySigned);
                }
            }
        }

        // Sweet, the protocol permits us to sign the block, wait for our time
        let delay = std::cmp::max(
            UNIX_EPOCH + Duration::from_secs(header.timestamp),
            SystemTime::now() + Duration::from_secs(MERGE_SIGN_MIN_TIME),
            )
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::from_secs(0));
        let mut delay_with_wiggle = delay;
        if header.difficulty == DIFF_NO_TURN {
            let wiggle = Duration::from_millis((snap.signers.len() as u64 / 2 + 1) * WIGGLE_TIME.as_millis() as u64);
            delay_with_wiggle = delay + Duration::from_millis(rand::random::<u64>() % wiggle.as_millis() as u64);

            info!(target: "consensus::apos",
                "wiggle {:?}, time {:?}, number {}",
                wiggle, delay_with_wiggle, header.number
            );
        }

        // // Beijing hard fork logic (if applicable)
        // if self.chain_spec.is_beijing_active_at_block(block.number) 
        //
        // }

        let eth_signer_guard = self.eth_signer.read().unwrap();
        let eth_signer = eth_signer_guard.as_ref().ok_or(ConsensusError::NoSignerSet)?;
        // Sign all the things!
        let header_bytes = seal_hash(header);
        let sighash = eth_signer.sign_hash_sync(&header_bytes).map_err(|_| ConsensusError::SignHeaderError)?;


        let mut extra_data_mut = BytesMut::from(&header.extra_data[..]);
        extra_data_mut[header.extra_data.len().saturating_sub(SIGNATURE_LENGTH)..].copy_from_slice(&sighash.as_bytes());
        header.extra_data = Bytes::from(extra_data_mut.freeze());

        // Wait until sealing is terminated or delay timeout
        info!(target: "consensus::apos", "Waiting for slot to sign and propagate, delay: {:?}", delay);
        //
        // thread::sleep(delay);
        //tokio::time::sleep(delay_with_wiggle);

        self.save_total_difficulty(header);

        Ok(())
    }

    fn set_eth_signer_by_key(&self, eth_signer_key: Option<String>) -> Result<(), ConsensusError> {
        let eth_signer = eth_signer_key.map(|key| {
            PrivateKeySigner::from_bytes(&FixedBytes::from_str(&key).unwrap()).unwrap()
        });
        self.set_signer(eth_signer);
        Ok(())
    }

    /// snapshot retrieves the authorization snapshot at a given point in time.
    fn snapshot(
        &self,
        number: u64,
        hash: B256,
        parents: Option<Vec<Header>>,
    ) -> Result<Snapshot, ConsensusError> {

        let mut headers: Vec<Header> = Vec::new();
        let mut snap: Option<Snapshot> = None;
        let mut hash = hash;
        let mut number = number;
        let mut parents = parents;

        let mut recents = self.recents.write().unwrap(); //
        let mut recent_headers = self.recent_headers.write().unwrap();

        while snap.is_none() {
            //Attempt to retrieve a snapshot from memory
            if let Some(cached_snap) = recents.get(&hash) {
                snap = Some(cached_snap.clone());
                break;
            }

            // Attempt to obtain a snapshot from the disk
            if number != 0 && number % CHECKPOINT_INTERVAL == 0 {
                if let Ok(Some(s)) = self.provider.load_snapshot(number.into()) {
                    snap = Some(s);
                    break;
                } else {
                    debug!(target: "consensus::apos", "Snapshot not found for hash: {}, at number: {}", hash, number);
                }
            }

            // If we're at the genesis, snapshot the initial state. Alternatively if we're
            // at a checkpoint block without a parent (light client CHT), or we have piled
            // up more headers than allowed to be reorged (chain reinit from a freezer),
            // consider the checkpoint trusted and snapshot it.
            if number == 0 || (number % self.config.epoch == 0 && (headers.len() > FULL_IMMUTABILITY_THRESHOLD || self.provider.header_by_number(number -1).unwrap().is_none())) {
                if let Ok(Some(checkpoint)) = self.provider.header_by_number(number) {
                    //info!(target: "consensus::apos", "checkpoint={:?}", checkpoint);
                    let hash = checkpoint.hash_slow();
                    //info!(target: "consensus::apos", "snapshot() : number={}, hash_slow hash={:?}", number, hash);
            
                    //Calculate the list of signatories
                    let signers_count = (checkpoint.extra_data.len() - EXTRA_VANITY - SIGNATURE_LENGTH) /  Address::len_bytes();

                    let mut signers = Vec::with_capacity(signers_count);
            
                    for i in 0..signers_count {
                        let start = EXTRA_VANITY + i * Address::len_bytes();
                        let end = start + Address::len_bytes();
                        signers.push(Address::from_slice(&checkpoint.extra_data[start..end]));
                    }
                    info!(target: "consensus::apos", ?signers,
                        "genesis signers:"
                    );
                   
                    let s = Snapshot::new_snapshot(self.config.clone(), number, hash, signers);
                    // todo
                    self.provider.save_snapshot(number, s.clone()).map_err(|_| ConsensusError::UnknownBlock)?;
                    snap = Option::from(s);

                    info!(target: "consensus::apos",
                        "Stored checkpoint snapshot to disk, number: {}, hash: {}",
                        number,
                        hash
                    );
                    break;
                }
            }

            // No snapshot for this header, gather the header and move backward
            let header = if parents.is_some() && !parents.as_ref().unwrap().is_empty() {
                let header = parents.as_mut().unwrap().pop().unwrap();
                if header.hash_slow() != hash || header.number != number {
                    error!(target: "consensus::apos", "parent hash check failed: {:?}, {:?}, {:?}, {:?}", header.hash_slow(), hash, header.number, number);
                    return Err(ConsensusError::UnknownBlock);
                }
                header
            } else {
                let header_opt = self.provider.header_by_hash_or_number(hash.into()).map_err(|_| ConsensusError::UnknownBlock)?;
                if let Some(header) = header_opt {
                    header
                } else {
                    if let Some(v) = recent_headers.get(&hash) {
                        v.clone()
                    } else {
                        info!(target: "consensus::apos", "hash not found: {:?}", hash);
                        return Err(ConsensusError::UnknownBlock);
                    }
                }
            };

            hash = header.parent_hash;
            headers.push(header);
            number -= 1;

        }

        //Find the previous snapshot and apply any pending headers to it
        let headers_len = headers.len();
        let half_len = headers_len / 2;
        for i in 0..half_len {
            headers.swap(i, headers_len - 1 - i);
        }

        let snap = snap.unwrap().apply(headers, |header| {
            let signer = recover_address(&header)?;
            Ok(signer)
        }).map_err(|_| ConsensusError::InvalidDifficulty)?;

        recents.insert(snap.hash, snap.clone());

        ///If a new checkpoint snapshot is generated, save it to disk
        if snap.number % CHECKPOINT_INTERVAL == 0 && headers_len > 0 {
            self.provider.save_snapshot(snap.number, snap.clone()).map_err(|_|ConsensusError::SaveSnapshotError)?;
            debug!(
                "Stored voting snapshot to disk, number: {}, hash: {}",
                snap.number,
                snap.hash
            );
        }

        Ok(snap)
    }

    fn propose(
        &self,
        address: Address,
        auth: bool,
    ) -> Result<(), ConsensusError> {
        info!(target: "consensus::apos", "propose(), address={}, auth={}", address, auth);
        let mut proposals_guard = self.proposals.write().unwrap();
        proposals_guard.insert(address, auth);
        Ok(())
    }

    fn discard(
        &self,
        address: Address,
    ) -> Result<(), ConsensusError> {
        info!(target: "consensus::apos", "discard(), address={}", address);
        let mut proposals_guard = self.proposals.write().unwrap();
        proposals_guard.remove(&address);
        Ok(())
    }

    fn proposals(
        &self,
    ) -> Result<HashMap<Address, bool>, ConsensusError> {
        info!(target: "consensus::apos", "proposals()");
        let mut proposals_guard = self.proposals.read().unwrap();
        Ok(proposals_guard.clone())
    }

    fn total_difficulty(
        &self,
        hash: B256,
    ) -> U256 {
        let total_difficulty = if let Ok(Some(td)) = self.provider.load_td(&hash) {
            td
        } else {
            warn!(target: "consensus::apos", "td not found for hash {:?}", hash);
            U256::from(0)
        };
        info!(target: "consensus::apos", ?hash, ?total_difficulty, "get total_difficulty");
        total_difficulty
    }
}
