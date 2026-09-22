// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The builder's check of a claimed sender.
//!
//! Under `N42_INGEST_VERIFY=leader` a node's ingest queues a transaction
//! under the sender its frame claimed and checks no signature: the supply is
//! ~11 us of CPU a transaction on every member, and a follower meets every
//! transaction again inside a block, where the vote road resolves senders
//! anyway. What that leaves is one place where a sender is *used* without a
//! block to check it against -- this node's own build, on the tenure it
//! leads -- and a block must never carry a transaction whose sender was only
//! claimed.
//!
//! So the selection the build is handed is wrapped here. It pulls a batch
//! ahead of what the build asks for, verifies every claim in it on the
//! worker pool (0x50 through the same batch equation the ingest used, in
//! chunks of `N42_ED25519_BATCH`; secp256k1 by recovery, which *is* the
//! verification), compares each answer with the claim, and hands on only
//! what agrees. A transaction that does not is forgotten -- not given back,
//! because nothing could ever mine it under the lane it sits in, and a
//! transaction offered to every later build is the sink section 2af of the
//! fleet plan took apart -- and counted.
//!
//! With the mode off the wrapper is not built at all: the build takes the
//! queue's iterator exactly as it did before.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use alloy_primitives::Address;
use n42_tx_types::{AltSigSenderCache, N42TxEnvelope};
use reth_primitives_traits::SignerRecoverable as _;
use reth_transaction_pool::{
    error::InvalidPoolTransactionError, BestTransactions, PoolTransaction, ValidPoolTransaction,
};

/// Transactions a build verified the claimed sender of, and transactions it
/// dropped because the signature named someone else (or named nobody at
/// all). Cumulative for the process; the build line reports the difference
/// over one build, as it does for the fast-transfer hits.
static VERIFIED: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
/// Nanoseconds the builds spent in the verification itself.
static VERIFY_NS: AtomicU64 = AtomicU64::new(0);

/// Claims this node's builds have checked against the signature.
pub fn verified() -> u64 {
    VERIFIED.load(Ordering::Relaxed)
}

/// Transactions this node's builds refused because the claim was wrong.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// Milliseconds this node's builds have spent verifying claims.
pub fn verify_ms() -> u64 {
    VERIFY_NS.load(Ordering::Relaxed) / 1_000_000
}

/// How many transactions a build verifies at a time: `N42_BUILD_VERIFY_BATCH`
/// (4,096 by default).
///
/// Large enough that the worker pool is filled by one batch -- 4,096 at
/// ~11 us each is ~45 ms of CPU, a few milliseconds over sixteen threads --
/// and small enough that what a build pulls past its gas limit and hands
/// back at the end is a fraction of a block.
fn verify_batch_size() -> usize {
    static SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SIZE.get_or_init(|| {
        std::env::var("N42_BUILD_VERIFY_BATCH")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(4_096)
    })
}

/// The transaction inside a pooled one, borrowed rather than cloned: at
/// 163,000 a block the copy is the expensive part of looking at it.
fn envelope_of<T>(transaction: &ValidPoolTransaction<T>) -> &N42TxEnvelope
where
    T: PoolTransaction<Consensus = N42TxEnvelope>,
{
    transaction.transaction.consensus_ref().into_parts().0
}

/// What one transaction's check came to.
enum Verdict {
    /// The signature names this sender.
    Signed(Address),
    /// The signature names nobody: it did not recover, or did not verify.
    Unsigned,
    /// A 0x50 transaction no cache held: it goes through the batch.
    Batch,
}

/// The queue's selection with every claimed sender checked before the build
/// can see it. See the module docs.
#[derive(Debug)]
pub struct VerifyClaims<T: PoolTransaction, I> {
    queue: n42_tx_queue::TxQueue<T>,
    inner: I,
    /// Verified and waiting for the build to ask for them.
    ready: VecDeque<Arc<ValidPoolTransaction<T>>>,
    /// How many are taken and checked at a time. A tenure's first build
    /// meets a queue of half a million claims and must not wait for all of
    /// them: it waits for a batch, builds it, and asks for the next.
    batch: usize,
}

/// The queue's selection for a build, with every claimed sender checked
/// first when this node runs `N42_INGEST_VERIFY=leader`, and untouched when
/// it does not -- where the mode is off this is `Box::new(best)` and nothing
/// else.
pub fn selection<T>(
    queue: &n42_tx_queue::TxQueue<T>,
    best: n42_tx_queue::QueueBest<T>,
) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<T>>>>
where
    T: PoolTransaction<Consensus = N42TxEnvelope> + 'static,
{
    if n42_tx_types::senders_claimed_at_ingest() {
        Box::new(VerifyClaims::new(queue.clone(), best))
    } else {
        Box::new(best)
    }
}

impl<T, I> VerifyClaims<T, I>
where
    T: PoolTransaction<Consensus = N42TxEnvelope> + 'static,
    I: BestTransactions<Item = Arc<ValidPoolTransaction<T>>>,
{
    /// Wraps `inner`, giving anything it takes and does not use back to
    /// `queue`.
    pub fn new(queue: n42_tx_queue::TxQueue<T>, inner: I) -> Self {
        Self { queue, inner, ready: VecDeque::new(), batch: verify_batch_size() }
    }

    /// Takes the next batch out of the inner selection and checks it on the
    /// worker pool. Returns false when the selection is exhausted.
    ///
    /// The check goes through rayon from this thread rather than onto a task
    /// this thread then waits for: a build's pull can itself be running on a
    /// worker, and a worker blocked on a channel cannot help with the work
    /// it is blocked for.
    fn fill(&mut self) -> bool {
        let mut taken: Vec<Arc<ValidPoolTransaction<T>>> = Vec::with_capacity(self.batch);
        for _ in 0..self.batch {
            match self.inner.next() {
                Some(transaction) => taken.push(transaction),
                None => break,
            }
        }
        if taken.is_empty() {
            return false;
        }
        let at = std::time::Instant::now();
        let verdicts = verify(&taken);
        VERIFY_NS.fetch_add(at.elapsed().as_nanos() as u64, Ordering::Relaxed);
        let mut verified = 0u64;
        let mut dropped = 0u64;
        for (transaction, signed) in taken.into_iter().zip(verdicts) {
            match signed {
                Some(signer) if signer == transaction.sender() => {
                    verified += 1;
                    self.ready.push_back(transaction);
                }
                signed => {
                    dropped += 1;
                    warn_once(&transaction, signed);
                    self.queue.forget_taken(&transaction);
                }
            }
        }
        VERIFIED.fetch_add(verified, Ordering::Relaxed);
        if dropped != 0 {
            DROPPED.fetch_add(dropped, Ordering::Relaxed);
        }
        true
    }
}

impl<T: PoolTransaction, I> VerifyClaims<T, I> {
    /// Everything this iterator is still holding, back to the lanes.
    fn give_back(&mut self) {
        self.queue.untake(self.ready.drain(..).collect());
    }
}

/// One line a second at most, whatever the rate: a generator claiming wrongly
/// claims wrongly for every transaction it sends, and the counter on the
/// build line is the complete record.
fn warn_once<T: PoolTransaction>(transaction: &Arc<ValidPoolTransaction<T>>, signed: Option<Address>) {
    static NEXT_MS: AtomicU64 = AtomicU64::new(0);
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let now = START.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64;
    let next = NEXT_MS.load(Ordering::Acquire);
    if now < next || NEXT_MS.compare_exchange(next, now + 1_000, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return;
    }
    tracing::warn!(
        target: "payload_builder",
        hash = ?transaction.hash(),
        claimed = ?transaction.sender(),
        signed = ?signed,
        "a build dropped a transaction whose signature does not name the sender its frame claimed"
    );
}

/// The signer of each transaction, `None` where the signature names nobody.
///
/// Two passes on the worker pool: what can be settled one at a time
/// (secp256k1's recovery, a 0x50 sender this node has already verified once),
/// then the 0x50 remainder through the batch equation in chunks.
fn verify<T>(taken: &[Arc<ValidPoolTransaction<T>>]) -> Vec<Option<Address>>
where
    T: PoolTransaction<Consensus = N42TxEnvelope> + 'static,
{
    use rayon::prelude::*;
    let senders = AltSigSenderCache::global();
    let mut verdicts: Vec<Verdict> = taken
        .par_iter()
        .map(|transaction| {
            match envelope_of(transaction) {
                N42TxEnvelope::AltSig(alt) => match senders.get(alt.hash()) {
                    // This node verified that signature already; the answer
                    // it kept is as good as verifying it again.
                    Some(signer) => Verdict::Signed(signer),
                    None => Verdict::Batch,
                },
                // ecrecover is the verification: a signature that names an
                // address at all names the one that signed.
                N42TxEnvelope::Eth(tx) => {
                    tx.recover_signer().map_or(Verdict::Unsigned, Verdict::Signed)
                }
            }
        })
        .collect();
    let batched: Vec<usize> = verdicts
        .iter()
        .enumerate()
        .filter(|(_, verdict)| matches!(verdict, Verdict::Batch))
        .map(|(at, _)| at)
        .collect();
    if !batched.is_empty() {
        let batch = n42_tx_types::ed25519_batch_size();
        let checked: Vec<(usize, Option<Address>)> = batched
            .par_chunks(batch)
            .flat_map_iter(|chunk| {
                let refs: Vec<&n42_tx_types::AltSigTx> = chunk
                    .iter()
                    .filter_map(|&at| match envelope_of(&taken[at]) {
                        N42TxEnvelope::AltSig(alt) => Some(alt),
                        N42TxEnvelope::Eth(_) => None,
                    })
                    .collect();
                // One verdict per transaction or none is used: `refs`
                // filters, and a short list would shift every later
                // transaction of the chunk onto the wrong verdict.
                let verdicts = if refs.len() == chunk.len() {
                    n42_tx_types::verify_batch(&refs)
                } else {
                    Vec::new()
                };
                chunk
                    .iter()
                    .copied()
                    .zip(verdicts.into_iter().map(Result::ok).chain(std::iter::repeat(None)))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (at, signer) in checked {
            if let Some(signer) = signer {
                // Kept, so a build that meets the same transaction again --
                // and the vote road behind it -- does not pay for it twice.
                if let N42TxEnvelope::AltSig(alt) = envelope_of(&taken[at]) {
                    senders.insert(*alt.hash(), signer);
                }
                verdicts[at] = Verdict::Signed(signer);
            } else {
                verdicts[at] = Verdict::Unsigned;
            }
        }
    }
    verdicts
        .into_iter()
        .map(|verdict| match verdict {
            Verdict::Signed(signer) => Some(signer),
            // A `Batch` left over is a 0x50 whose chunk returned nothing: it
            // is unverified, which is the same as refused.
            Verdict::Unsigned | Verdict::Batch => None,
        })
        .collect()
}

impl<T: PoolTransaction, I> Drop for VerifyClaims<T, I> {
    fn drop(&mut self) {
        // What a build pulled ahead and never asked for goes back to the
        // lanes, exactly as the queue's own iterator does with its buffer.
        self.give_back();
    }
}

impl<T, I> Iterator for VerifyClaims<T, I>
where
    T: PoolTransaction<Consensus = N42TxEnvelope> + 'static,
    I: BestTransactions<Item = Arc<ValidPoolTransaction<T>>>,
{
    type Item = Arc<ValidPoolTransaction<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(transaction) = self.ready.pop_front() {
                return Some(transaction);
            }
            // A batch in which every claim was wrong leaves nothing ready;
            // the next one is asked for rather than the build ended.
            if !self.fill() {
                return None;
            }
        }
    }
}

impl<T, I> BestTransactions for VerifyClaims<T, I>
where
    T: PoolTransaction<Consensus = N42TxEnvelope> + 'static,
    I: BestTransactions<Item = Arc<ValidPoolTransaction<T>>>,
{
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        // The build's verdict is about the transaction, not about the check
        // here: it goes to the queue unchanged, and the queue still holds it
        // in the build's taken list, so it finds it where it always did.
        let stale = matches!(&kind, InvalidPoolTransactionError::Consensus(err) if err.is_nonce_too_low());
        self.inner.mark_invalid(transaction, kind);
        // A nonce the chain is past says nothing against the sender's later
        // ones; any other refusal takes the sender out of this build, in the
        // queue and here alike.
        if stale {
            return;
        }
        // A refused sender's transactions this wrapper is still holding go
        // back with it: the queue skips that sender for the rest of the
        // build, and handing on what it already skipped would make the
        // build refuse them one at a time.
        let sender = transaction.sender();
        if self.ready.iter().any(|held| held.sender() == sender) {
            let (back, keep): (Vec<_>, Vec<_>) =
                self.ready.drain(..).partition(|held| held.sender() == sender);
            self.ready = keep.into();
            self.queue.untake(back);
        }
    }

    fn no_updates(&mut self) {
        self.inner.no_updates();
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        self.inner.set_skip_blobs(skip_blobs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559};
    use alloy_primitives::{address, keccak256, Bytes, Signature, TxKind, U256};
    use reth_primitives_traits::Recovered;
    use reth_transaction_pool::{
        identifier::{SenderId, TransactionId},
        TransactionOrigin,
    };

    fn ed_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    /// A signed 0x50 transfer and the address that signed it.
    fn alt_sig(seed: u8, nonce: u64) -> (N42TxEnvelope, Address) {
        let key = ed_key(seed);
        let tx = n42_tx_types::TxAltSig {
            chain_id: 94,
            nonce,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 10_000_000_000,
            gas_limit: 21_000,
            to: address!("00000000000000000000000000000000000000aa"),
            value: U256::from(1u64),
            input: Bytes::new(),
            access_list: Default::default(),
            alg_type: n42_tx_types::ALG_ED25519,
            pubkey: Bytes::copy_from_slice(key.verifying_key().as_bytes()),
        }
        .sign_ed25519(&key);
        let sender = tx.sender();
        (N42TxEnvelope::AltSig(tx), sender)
    }

    /// A signed EIP-1559 transfer and the address that signed it.
    fn eth_sig(seed: u8, nonce: u64) -> (N42TxEnvelope, Address) {
        let mut bytes = keccak256([seed; 32]);
        let key = loop {
            match secp256k1::SecretKey::from_slice(bytes.as_slice()) {
                Ok(key) => break key,
                Err(_) => bytes = keccak256(bytes),
            }
        };
        let tx = TxEip1559 {
            chain_id: 94,
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 10_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(address!("00000000000000000000000000000000000000bb")),
            value: U256::from(1u64),
            ..Default::default()
        };
        let message = secp256k1::Message::from_digest(tx.signature_hash().0);
        let (recovery_id, compact) =
            secp256k1::SECP256K1.sign_ecdsa_recoverable(&message, &key).serialize_compact();
        let signature = Signature::new(
            U256::from_be_slice(&compact[..32]),
            U256::from_be_slice(&compact[32..]),
            i32::from(recovery_id) != 0,
        );
        let signed: reth_ethereum_primitives::TransactionSigned = tx.into_signed(signature).into();
        let sender = signed.recover_signer().expect("the signature recovers");
        (N42TxEnvelope::Eth(signed), sender)
    }

    /// A pooled transaction filed under `claimed`, whatever the signature
    /// says -- which is exactly what the ingest does in the claimed mode.
    fn pooled(tx: N42TxEnvelope, claimed: Address) -> crate::N42PooledTransaction {
        let encoded = alloy_eips::eip2718::Encodable2718::encode_2718_len(&tx);
        crate::N42PooledTransaction::new(Recovered::new_unchecked(tx, claimed), encoded)
    }

    /// The same, as a lane holds it.
    fn queued(tx: N42TxEnvelope, claimed: Address) -> Arc<ValidPoolTransaction<crate::N42PooledTransaction>> {
        let nonce = alloy_consensus::Transaction::nonce(&tx);
        let pooled = pooled(tx, claimed);
        Arc::new(ValidPoolTransaction {
            transaction: pooled,
            transaction_id: TransactionId::new(SenderId::from(1u64), nonce),
            propagate: false,
            timestamp: std::time::Instant::now(),
            origin: TransactionOrigin::External,
            authority_ids: None,
        })
    }

    /// The batch is what the environment says, and a value that says nothing
    /// leaves the default in place.
    #[test]
    fn the_verify_batch_has_a_default() {
        assert!(verify_batch_size() >= 1);
    }

    /// A true claim is confirmed by the signature, of either scheme, and the
    /// verdicts line up with the transactions they belong to.
    #[test]
    fn a_true_claim_is_what_the_signature_says() {
        let (alt, alt_sender) = alt_sig(3, 0);
        let (eth, eth_sender) = eth_sig(4, 1);
        let taken = vec![queued(alt, alt_sender), queued(eth, eth_sender)];
        assert_eq!(verify(&taken), vec![Some(alt_sender), Some(eth_sender)]);
    }

    /// A claim the signature contradicts comes back as the signer, not as
    /// the claim: what the caller compares and refuses on.
    #[test]
    fn a_false_claim_is_not_confirmed() {
        let liar = address!("00000000000000000000000000000000000000ff");
        let (alt, alt_sender) = alt_sig(5, 0);
        let (eth, eth_sender) = eth_sig(6, 0);
        let taken = vec![queued(alt, liar), queued(eth, liar)];
        let verdicts = verify(&taken);
        assert_eq!(verdicts, vec![Some(alt_sender), Some(eth_sender)]);
        assert!(verdicts.iter().all(|signed| *signed != Some(liar)));
    }

    /// A 0x50 signature that does not verify names nobody, so the claim
    /// cannot be confirmed by it either.
    #[test]
    fn a_broken_signature_names_nobody() {
        let (alt, sender) = alt_sig(7, 0);
        let N42TxEnvelope::AltSig(alt) = alt else { return };
        let mut broken = alt.signature().to_vec();
        // The R half, so the shape and the scalar check still pass and the
        // batch equation is what refuses it.
        broken[0] ^= 0xff;
        let alt = n42_tx_types::AltSigTx::new(alt.tx().clone(), broken.into());
        assert_eq!(verify(&[queued(N42TxEnvelope::AltSig(alt), sender)]), vec![None]);
    }

    /// The whole wrapper over a real queue: a build sees only what the
    /// signature confirms, the transaction with the false claim leaves the
    /// queue for good, and what the build never asked for goes back.
    #[test]
    fn a_build_sees_only_verified_claims() {
        use alloy_primitives::B256;
        let liar = address!("00000000000000000000000000000000000000fe");
        let queue = n42_tx_queue::TxQueue::<crate::N42PooledTransaction>::with_run_length(64)
            .with_hash_index(64);
        let (first, first_sender) = alt_sig(11, 0);
        let (second, second_sender) = alt_sig(11, 1);
        let (forged, _) = eth_sig(12, 0);
        let forged_hash = *alloy_consensus::transaction::TxHashRef::tx_hash(&forged);
        assert_eq!(first_sender, second_sender, "one sender's two nonces");
        queue.push(vec![pooled(first, first_sender), pooled(second, second_sender), pooled(forged, liar)]);
        queue.drain_now();

        let best = queue.best_for_build(B256::repeat_byte(1));
        let mut verifying = VerifyClaims::new(queue.clone(), best);
        let dropped_before = dropped();
        let first_out = verifying.next().expect("the first verified transaction");
        assert_eq!((first_out.sender(), first_out.nonce()), (first_sender, 0));
        // The forged one never reaches the build, and it is gone from the
        // queue rather than waiting for the next build to meet it again.
        assert_eq!(dropped(), dropped_before + 1);
        assert_eq!(queue.sender_of(&forged_hash), None);
        // The build ends, and a build on another parent is offered the two
        // the signature confirmed -- the one it used and the one it did
        // not, both back in their lane -- and never the forged one again.
        drop(verifying);
        let mut after = queue.best_for_build(B256::repeat_byte(2));
        let offered: Vec<(Address, u64)> =
            std::iter::from_fn(|| after.next()).map(|t| (t.sender(), t.nonce())).collect();
        drop(after);
        assert_eq!(offered, vec![(first_sender, 0), (second_sender, 1)], "{offered:?}");
        assert!(!offered.iter().any(|(sender, _)| *sender == liar), "the forged claim came back");
    }
}
