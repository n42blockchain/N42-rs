use super::keys::{BlsError, BlsPublicKey, BlsSignature};
use super::{DST, H2_V4_DST};
use blst::BLST_ERROR;
use blst::blst_scalar;
use blst::min_pk::Signature;

/// Creates a blst_scalar from a 64-bit little-endian value.
/// The scalar is stored in a 256-bit field (32 bytes), with the
/// lower 8 bytes containing the value and upper bytes zeroed.
fn scalar_from_u64(val: u64) -> blst_scalar {
    let mut s = blst_scalar { b: [0u8; 32] };
    s.b[..8].copy_from_slice(&val.to_le_bytes());
    s
}

const MAX_BATCH_SIZE: usize = 10_000;

/// One ciphersuite's domain tag plus the matching single-signature check.
///
/// The two travel together on purpose: batch verification and the fallback that
/// localizes a bad signature must agree on the domain, or a batch failure would
/// be "confirmed" by a fallback that verifies against a different message
/// encoding and reports every signature as valid.
#[derive(Clone, Copy)]
struct Ciphersuite {
    dst: &'static [u8],
    verify_one: fn(&BlsPublicKey, &[u8], &BlsSignature) -> Result<(), BlsError>,
}

/// Native N42 consensus (NUL). The single-signature path revalidates the public
/// key, which the batch path does not — the batch protects itself with random
/// scalars instead.
const NATIVE: Ciphersuite = Ciphersuite {
    dst: DST,
    verify_one: BlsPublicKey::verify,
};

/// Gov5-compatible H2-v4 (POP). Keys reach this path only through the validator
/// set, which validates them at `ValidatorSet::try_new`, so the single-signature
/// check stays on the prevalidated variant used by the rest of the H2-v4 paths.
const H2_V4: Ciphersuite = Ciphersuite {
    dst: H2_V4_DST,
    verify_one: BlsPublicKey::verify_h2_v4_prevalidated,
};

/// Batch-verify multiple (message, signature, public_key) tuples.
/// Uses blst's multi-pairing with random 64-bit scalars for rogue-key attack protection.
/// Significantly faster than individual verification (~50% savings with many signatures).
pub fn batch_verify(
    messages: &[&[u8]],
    signatures: &[&BlsSignature],
    public_keys: &[&BlsPublicKey],
) -> Result<(), BlsError> {
    batch_verify_with_suite(messages, signatures, public_keys, NATIVE)
}

/// [`batch_verify`] for gov5-compatible H2-v4 signatures.
pub fn batch_verify_h2_v4(
    messages: &[&[u8]],
    signatures: &[&BlsSignature],
    public_keys: &[&BlsPublicKey],
) -> Result<(), BlsError> {
    batch_verify_with_suite(messages, signatures, public_keys, H2_V4)
}

fn batch_verify_with_suite(
    messages: &[&[u8]],
    signatures: &[&BlsSignature],
    public_keys: &[&BlsPublicKey],
    suite: Ciphersuite,
) -> Result<(), BlsError> {
    if messages.len() != signatures.len() || signatures.len() != public_keys.len() {
        return Err(BlsError::VerificationFailed(BLST_ERROR::BLST_BAD_ENCODING));
    }

    if messages.len() > MAX_BATCH_SIZE {
        return Err(BlsError::BatchTooLarge {
            size: messages.len(),
            max: MAX_BATCH_SIZE,
        });
    }

    if messages.is_empty() {
        return Ok(());
    }

    // Single signature: use direct verification (no overhead from random scalars).
    if messages.len() == 1 {
        return (suite.verify_one)(public_keys[0], messages[0], signatures[0]);
    }

    let mut rands: Vec<blst_scalar> = Vec::with_capacity(messages.len());
    for _ in 0..messages.len() {
        let mut rand_bytes = [0u8; 8];
        getrandom::fill(&mut rand_bytes).map_err(|_| BlsError::RandomGenerationFailed)?;
        let mut val = u64::from_le_bytes(rand_bytes);
        if val == 0 {
            val = 1;
        }
        rands.push(scalar_from_u64(val));
    }

    let sigs: Vec<&Signature> = signatures.iter().map(|s| s.inner()).collect();
    let pks: Vec<&blst::min_pk::PublicKey> = public_keys.iter().map(|pk| pk.inner()).collect();

    let result = Signature::verify_multiple_aggregate_signatures(
        messages, suite.dst, &pks, false, &sigs, true, &rands, 64,
    );

    if result != BLST_ERROR::BLST_SUCCESS {
        return Err(BlsError::VerificationFailed(result));
    }

    Ok(())
}

/// Batch-verify with fallback: if the batch fails, falls back to individual
/// verification to identify which signatures are invalid.
///
/// Returns `Ok(())` if all signatures are valid, or `Err` with the indices
/// of invalid signatures.
pub fn batch_verify_with_fallback(
    messages: &[&[u8]],
    signatures: &[&BlsSignature],
    public_keys: &[&BlsPublicKey],
) -> Result<(), Vec<usize>> {
    batch_verify_with_fallback_suite(messages, signatures, public_keys, NATIVE)
}

/// [`batch_verify_with_fallback`] for gov5-compatible H2-v4 signatures.
pub fn batch_verify_h2_v4_with_fallback(
    messages: &[&[u8]],
    signatures: &[&BlsSignature],
    public_keys: &[&BlsPublicKey],
) -> Result<(), Vec<usize>> {
    batch_verify_with_fallback_suite(messages, signatures, public_keys, H2_V4)
}

fn batch_verify_with_fallback_suite(
    messages: &[&[u8]],
    signatures: &[&BlsSignature],
    public_keys: &[&BlsPublicKey],
    suite: Ciphersuite,
) -> Result<(), Vec<usize>> {
    if messages.len() != signatures.len() || signatures.len() != public_keys.len() {
        // Input length mismatch is a programming error. Mark every message
        // position bad so callers that use this index set as a filter cannot
        // accidentally accept an unmatched tail.
        return Err((0..messages.len()).collect());
    }

    if messages.len() > MAX_BATCH_SIZE {
        return Err((0..messages.len()).collect());
    }

    if messages.is_empty() {
        return Ok(());
    }

    // Try batch verification first.
    if batch_verify_with_suite(messages, signatures, public_keys, suite).is_ok() {
        return Ok(());
    }

    // Batch failed: fall back to individual verification to find bad signatures.
    let mut bad_indices = Vec::new();
    for i in 0..messages.len() {
        if (suite.verify_one)(public_keys[i], messages[i], signatures[i]).is_err() {
            bad_indices.push(i);
        }
    }

    if bad_indices.is_empty() {
        Ok(())
    } else {
        Err(bad_indices)
    }
}

/// What [`verify_same_message_with_fallback`] found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SameMessageOutcome {
    /// Positions whose signature did not verify. Empty: every one did.
    pub bad: Vec<usize>,
    /// The batch check failed and every position was then verified on its
    /// own (the fallback ran).
    pub fell_back: bool,
    /// Pairing checks spent: 1 for a batch that passed, 1 + n after a
    /// fallback (n individual verifications).
    pub checks: usize,
}

/// Verifies `signatures[i]` by `public_keys[i]` over one `message`, all at
/// once, under the native ciphersuite.
///
/// Randomised same-message batch: with random non-zero 64-bit `r_i`, checks
/// `e(sum r_i sig_i, g1) == e(H(m), sum r_i pk_i)`. The message is hashed to
/// G2 once and the check is one verification (two Miller loops and one final
/// exponentiation) whatever n is; the per-signature cost is a G2 subgroup
/// check and a share of two multi-scalar multiplications. Unlike a plain
/// aggregate (`fast_aggregate_verify` over the sum), the random weights mean a
/// batch passes only if every signature is valid on its own (up to 2^-64), so
/// two invalid signatures cannot cancel each other and a subset of an
/// accepted batch is as valid as the batch. Public keys must have been
/// validated at the trust boundary (the validator set), as for
/// `verify_prevalidated`.
pub fn verify_same_message_batch(
    message: &[u8],
    signatures: &[&BlsSignature],
    public_keys: &[&BlsPublicKey],
) -> Result<(), BlsError> {
    same_message_batch_with_suite(message, signatures, public_keys, NATIVE)
}

/// [`verify_same_message_batch`] for gov5-compatible H2-v4 signatures.
pub fn verify_same_message_batch_h2_v4(
    message: &[u8],
    signatures: &[&BlsSignature],
    public_keys: &[&BlsPublicKey],
) -> Result<(), BlsError> {
    same_message_batch_with_suite(message, signatures, public_keys, H2_V4)
}

/// [`verify_same_message_batch`], and when the batch fails, each position on
/// its own to name the bad ones without losing the good ones.
///
/// Bound: one batch check plus, after a failure, exactly n individual
/// verifications -- never more than verifying every signature on its own
/// (today's cost) plus one batch.
pub fn verify_same_message_with_fallback(
    message: &[u8],
    signatures: &[&BlsSignature],
    public_keys: &[&BlsPublicKey],
) -> SameMessageOutcome {
    same_message_with_fallback_suite(message, signatures, public_keys, NATIVE)
}

/// [`verify_same_message_with_fallback`] for gov5-compatible H2-v4 signatures.
pub fn verify_same_message_h2_v4_with_fallback(
    message: &[u8],
    signatures: &[&BlsSignature],
    public_keys: &[&BlsPublicKey],
) -> SameMessageOutcome {
    same_message_with_fallback_suite(message, signatures, public_keys, H2_V4)
}

fn same_message_with_fallback_suite(
    message: &[u8],
    signatures: &[&BlsSignature],
    public_keys: &[&BlsPublicKey],
    suite: Ciphersuite,
) -> SameMessageOutcome {
    if signatures.len() != public_keys.len() {
        // A programming error: refuse every position rather than accept an
        // unmatched tail.
        return SameMessageOutcome {
            bad: (0..signatures.len().max(public_keys.len())).collect(),
            fell_back: false,
            checks: 0,
        };
    }
    if signatures.is_empty() {
        return SameMessageOutcome::default();
    }
    if same_message_batch_with_suite(message, signatures, public_keys, suite).is_ok() {
        return SameMessageOutcome {
            bad: Vec::new(),
            fell_back: false,
            checks: 1,
        };
    }
    if signatures.len() == 1 {
        // The batch of one was already the individual check.
        return SameMessageOutcome {
            bad: vec![0],
            fell_back: false,
            checks: 1,
        };
    }
    let bad = (0..signatures.len())
        .filter(|&i| (suite.verify_one)(public_keys[i], message, signatures[i]).is_err())
        .collect();
    SameMessageOutcome {
        bad,
        fell_back: true,
        checks: 1 + signatures.len(),
    }
}

fn same_message_batch_with_suite(
    message: &[u8],
    signatures: &[&BlsSignature],
    public_keys: &[&BlsPublicKey],
    suite: Ciphersuite,
) -> Result<(), BlsError> {
    let n = signatures.len();
    if n != public_keys.len() {
        return Err(BlsError::VerificationFailed(BLST_ERROR::BLST_BAD_ENCODING));
    }
    if n > MAX_BATCH_SIZE {
        return Err(BlsError::BatchTooLarge {
            size: n,
            max: MAX_BATCH_SIZE,
        });
    }
    if n == 0 {
        return Ok(());
    }
    if n == 1 {
        return (suite.verify_one)(public_keys[0], message, signatures[0]);
    }
    // Every signature must lie in G2 on its own: the random weights do not
    // remove a small-order component with certainty (G2's cofactor has small
    // prime factors), and a QC aggregated from such a signature would fail
    // on every receiver.
    for signature in signatures {
        if !signature.inner().subgroup_check() {
            return Err(BlsError::VerificationFailed(
                BLST_ERROR::BLST_POINT_NOT_IN_GROUP,
            ));
        }
    }
    let mut scalars = vec![0u8; 8 * n];
    getrandom::fill(&mut scalars).map_err(|_| BlsError::RandomGenerationFailed)?;
    for chunk in scalars.chunks_exact_mut(8) {
        if chunk.iter().all(|b| *b == 0) {
            chunk[0] = 1;
        }
    }
    let sig_points: Vec<blst::blst_p2_affine> = signatures
        .iter()
        .map(|s| blst::blst_p2_affine::from(*s.inner()))
        .collect();
    let pk_points: Vec<blst::blst_p1_affine> = public_keys
        .iter()
        .map(|pk| blst::blst_p1_affine::from(*pk.inner()))
        .collect();
    let weighted_sig = weighted_sum_p2(&sig_points, &scalars);
    let weighted_pk = weighted_sum_p1(&pk_points, &scalars);
    let signature = blst::min_pk::AggregateSignature::from(weighted_sig).to_signature();
    let public_key = blst::min_pk::AggregatePublicKey::from(weighted_pk).to_public_key();
    // The weighted sum of group members is a group member; the subgroup
    // checks above and the validated keys cover what `verify` would check.
    let result = signature.verify(false, message, suite.dst, &[], &public_key, false);
    if result != BLST_ERROR::BLST_SUCCESS {
        return Err(BlsError::VerificationFailed(result));
    }
    Ok(())
}

/// `sum scalars_i * points_i` in G2 (64-bit little-endian scalars), single
/// threaded: blst's `MultiPoint::mult` would spread a small batch over its
/// process-wide pool, and the caller is a pinned consensus loop.
fn weighted_sum_p2(points: &[blst::blst_p2_affine], scalars: &[u8]) -> blst::blst_p2 {
    let mut ret = blst::blst_p2::default();
    if points.is_empty() || scalars.len() < 8 * points.len() {
        return ret;
    }
    let point_ptrs: [*const blst::blst_p2_affine; 2] = [points.as_ptr(), std::ptr::null()];
    let scalar_ptrs: [*const u8; 2] = [scalars.as_ptr(), std::ptr::null()];
    // SAFETY: `points` holds `points.len()` affine points and `scalars` at
    // least 8 bytes per point (checked above); the two-element pointer arrays
    // with a null terminator are blst's "one contiguous array" form, the same
    // call blst's own single-threaded `mult` makes. The scratch is sized by
    // blst's own `scratch_sizeof` for this point count.
    unsafe {
        let words = blst::blst_p2s_mult_pippenger_scratch_sizeof(points.len()) / 8 + 1;
        let mut scratch: Vec<u64> = vec![0; words];
        blst::blst_p2s_mult_pippenger(
            &mut ret,
            point_ptrs.as_ptr(),
            points.len(),
            scalar_ptrs.as_ptr(),
            64,
            scratch.as_mut_ptr(),
        );
    }
    ret
}

/// [`weighted_sum_p2`] in G1.
fn weighted_sum_p1(points: &[blst::blst_p1_affine], scalars: &[u8]) -> blst::blst_p1 {
    let mut ret = blst::blst_p1::default();
    if points.is_empty() || scalars.len() < 8 * points.len() {
        return ret;
    }
    let point_ptrs: [*const blst::blst_p1_affine; 2] = [points.as_ptr(), std::ptr::null()];
    let scalar_ptrs: [*const u8; 2] = [scalars.as_ptr(), std::ptr::null()];
    // SAFETY: as in `weighted_sum_p2`.
    unsafe {
        let words = blst::blst_p1s_mult_pippenger_scratch_sizeof(points.len()) / 8 + 1;
        let mut scratch: Vec<u64> = vec![0; words];
        blst::blst_p1s_mult_pippenger(
            &mut ret,
            point_ptrs.as_ptr(),
            points.len(),
            scalar_ptrs.as_ptr(),
            64,
            scratch.as_mut_ptr(),
        );
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::super::aggregate::AggregateSignature;
    use super::super::keys::BlsSecretKey;
    use super::*;

    fn test_key(seed: u8) -> BlsSecretKey {
        BlsSecretKey::key_gen(&[seed; 32]).expect("deterministic test key should be valid")
    }

    fn same_message_set(n: u8, msg: &[u8]) -> (Vec<BlsPublicKey>, Vec<BlsSignature>) {
        let sks: Vec<_> = (0..n).map(|i| test_key(0xB0u8.wrapping_add(i))).collect();
        let pks = sks.iter().map(|sk| sk.public_key()).collect();
        let sigs = sks.iter().map(|sk| sk.sign(msg)).collect();
        (pks, sigs)
    }

    /// The batch agrees with one-by-one verification on valid votes, for
    /// every size from the trivial one to a 99-key set's quorum and beyond.
    #[test]
    fn same_message_batch_equals_sequential_on_valid_votes() {
        let msg = b"view=7||block=0x11";
        for n in [1u8, 2, 3, 5, 20, 67, 98] {
            let (pks, sigs) = same_message_set(n, msg);
            let sig_refs: Vec<_> = sigs.iter().collect();
            let pk_refs: Vec<_> = pks.iter().collect();
            for (pk, sig) in pks.iter().zip(&sigs) {
                pk.verify_prevalidated(msg, sig).expect("sequential");
            }
            verify_same_message_batch(msg, &sig_refs, &pk_refs).expect("batch");
            assert_eq!(
                verify_same_message_with_fallback(msg, &sig_refs, &pk_refs),
                SameMessageOutcome { bad: vec![], fell_back: false, checks: 1 },
                "n = {n}"
            );
            // A different message fails as a batch, as it does one by one.
            assert!(verify_same_message_batch(b"other", &sig_refs, &pk_refs).is_err());
        }
    }

    /// One bad vote in a batch of 20: the batch fails, the fallback names it
    /// and only it, and the cost is the stated bound (1 + n checks).
    #[test]
    fn one_bad_vote_in_twenty_is_named_and_nineteen_pass() {
        let msg = b"view=9||block=0x22";
        let (pks, mut sigs) = same_message_set(20, msg);
        sigs[13] = test_key(0xB0 + 13).sign(b"something else");
        let sig_refs: Vec<_> = sigs.iter().collect();
        let pk_refs: Vec<_> = pks.iter().collect();
        assert!(verify_same_message_batch(msg, &sig_refs, &pk_refs).is_err());
        let outcome = verify_same_message_with_fallback(msg, &sig_refs, &pk_refs);
        assert_eq!(outcome.bad, vec![13]);
        assert!(outcome.fell_back);
        assert_eq!(outcome.checks, 1 + 20, "the fallback bound");
        // The nineteen survivors pass again as a batch.
        let good_sigs: Vec<_> = (0..20).filter(|i| *i != 13).map(|i| &sigs[i]).collect();
        let good_pks: Vec<_> = (0..20).filter(|i| *i != 13).map(|i| &pks[i]).collect();
        verify_same_message_batch(msg, &good_sigs, &good_pks).expect("19 good");
    }

    /// Two invalid signatures whose sum is the sum of two valid ones pass a
    /// plain aggregate check but not the weighted batch.
    #[test]
    fn cancelling_signatures_do_not_pass_the_weighted_batch() {
        let msg = b"view=3||block=0x33";
        let (pks, sigs) = same_message_set(2, msg);
        // The cancelling pair sig0 + d, sig1 - d with d = sig1 - sig0 is the
        // two signatures swapped: each invalid for its key, same sum.
        let swapped = [&sigs[1], &sigs[0]];
        let pk_refs: Vec<_> = pks.iter().collect();
        let plain = AggregateSignature::aggregate(&swapped).expect("aggregate");
        AggregateSignature::verify_aggregate(msg, &plain, &pk_refs)
            .expect("a plain aggregate cannot tell the swap");
        assert!(verify_same_message_batch(msg, &swapped, &pk_refs).is_err());
        let outcome = verify_same_message_with_fallback(msg, &swapped, &pk_refs);
        assert_eq!(outcome.bad, vec![0, 1]);
    }

    /// Timing, not a check: `cargo test --release -p n42-h2-primitives
    /// same_message_batch_timing -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn same_message_batch_timing() {
        let msg = b"view=1||block=0x44";
        for n in [4u8, 14, 66] {
            let (pks, sigs) = same_message_set(n, msg);
            let sig_refs: Vec<_> = sigs.iter().collect();
            let pk_refs: Vec<_> = pks.iter().collect();
            let at = std::time::Instant::now();
            for (pk, sig) in pks.iter().zip(&sigs) {
                pk.verify_prevalidated(msg, sig).expect("sequential");
            }
            let sequential = at.elapsed();
            let at = std::time::Instant::now();
            verify_same_message_batch(msg, &sig_refs, &pk_refs).expect("batch");
            let batch = at.elapsed();
            println!("n={n} sequential={sequential:?} batch={batch:?}");
        }
    }

    #[test]
    fn same_message_batch_keeps_the_ciphersuites_apart() {
        let msg = b"domain";
        let sks: Vec<_> = (0..4).map(|i| test_key(0xC0 + i as u8)).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();
        let pk_refs: Vec<_> = pks.iter().collect();
        let h2: Vec<_> = sks.iter().map(|sk| sk.sign_h2_v4(msg)).collect();
        let h2_refs: Vec<_> = h2.iter().collect();
        verify_same_message_batch_h2_v4(msg, &h2_refs, &pk_refs).expect("H2-v4 batch");
        assert!(verify_same_message_batch(msg, &h2_refs, &pk_refs).is_err());
        assert_eq!(
            verify_same_message_h2_v4_with_fallback(msg, &h2_refs, &pk_refs).bad,
            Vec::<usize>::new()
        );
    }

    #[test]
    fn test_batch_verify_success() {
        let msg1 = b"message one";
        let msg2 = b"message two";
        let msg3 = b"message three";

        let sk1 = test_key(0x11);
        let sk2 = test_key(0x12);
        let sk3 = test_key(0x13);

        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let pk3 = sk3.public_key();

        let sig1 = sk1.sign(msg1);
        let sig2 = sk2.sign(msg2);
        let sig3 = sk3.sign(msg3);

        let messages: Vec<&[u8]> = vec![msg1.as_ref(), msg2.as_ref(), msg3.as_ref()];
        let signatures = vec![&sig1, &sig2, &sig3];
        let public_keys = vec![&pk1, &pk2, &pk3];

        batch_verify(&messages, &signatures, &public_keys)
            .expect("batch verification should succeed for correct inputs");
    }

    #[test]
    fn test_batch_verify_mismatched_lengths() {
        let sk1 = test_key(0x21);
        let sk2 = test_key(0x22);
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let sig1 = sk1.sign(b"a");
        let sig2 = sk2.sign(b"b");

        // Two messages but three signatures => mismatched lengths
        let messages: Vec<&[u8]> = vec![b"a".as_ref(), b"b".as_ref()];
        let signatures = vec![&sig1, &sig2, &sig1];
        let public_keys = vec![&pk1, &pk2];

        let result = batch_verify(&messages, &signatures, &public_keys);
        assert!(
            result.is_err(),
            "batch verify should fail for mismatched lengths"
        );
    }

    #[test]
    fn test_batch_verify_empty() {
        let messages: Vec<&[u8]> = vec![];
        let signatures: Vec<&BlsSignature> = vec![];
        let public_keys: Vec<&BlsPublicKey> = vec![];

        batch_verify(&messages, &signatures, &public_keys)
            .expect("batch verify on empty arrays should succeed");
    }

    #[test]
    fn test_batch_verify_single() {
        let sk = test_key(0x31);
        let pk = sk.public_key();
        let msg = b"single message";
        let sig = sk.sign(msg);

        batch_verify(&[msg.as_ref()], &[&sig], &[&pk])
            .expect("single-element batch should succeed");
    }

    #[test]
    fn test_batch_verify_same_message_different_signers() {
        // Common in consensus: all validators sign the same message.
        let msg = b"view=5||block_hash=0xAA";
        let sks: Vec<_> = (0..10).map(|i| test_key(0x40 + i as u8)).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();
        let sigs: Vec<_> = sks.iter().map(|sk| sk.sign(msg)).collect();

        let messages: Vec<&[u8]> = vec![msg.as_ref(); 10];
        let sig_refs: Vec<_> = sigs.iter().collect();
        let pk_refs: Vec<_> = pks.iter().collect();

        batch_verify(&messages, &sig_refs, &pk_refs)
            .expect("batch verify with same message should succeed");
    }

    #[test]
    fn test_batch_verify_detects_invalid() {
        let sk1 = test_key(0x51);
        let sk2 = test_key(0x52);
        let sk3 = test_key(0x53);

        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let pk3 = sk3.public_key();

        let msg = b"consensus vote";
        let sig1 = sk1.sign(msg);
        let sig2 = sk2.sign(b"wrong message"); // Invalid!
        let sig3 = sk3.sign(msg);

        let messages: Vec<&[u8]> = vec![msg.as_ref(), msg.as_ref(), msg.as_ref()];
        let result = batch_verify(&messages, &[&sig1, &sig2, &sig3], &[&pk1, &pk2, &pk3]);
        assert!(
            result.is_err(),
            "batch should fail when one signature is invalid"
        );
    }

    #[test]
    fn test_batch_verify_with_fallback_all_valid() {
        let msg = b"test message";
        let sks: Vec<_> = (0..5).map(|i| test_key(0x60 + i as u8)).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();
        let sigs: Vec<_> = sks.iter().map(|sk| sk.sign(msg)).collect();

        let messages: Vec<&[u8]> = vec![msg.as_ref(); 5];
        let sig_refs: Vec<_> = sigs.iter().collect();
        let pk_refs: Vec<_> = pks.iter().collect();

        batch_verify_with_fallback(&messages, &sig_refs, &pk_refs)
            .expect("all valid should return Ok");
    }

    #[test]
    fn test_batch_verify_with_fallback_identifies_bad() {
        let msg = b"consensus vote";
        let sks: Vec<_> = (0..5).map(|i| test_key(0x70 + i as u8)).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();

        let mut sigs: Vec<_> = sks.iter().map(|sk| sk.sign(msg)).collect();
        // Corrupt signatures at index 1 and 3
        sigs[1] = sks[1].sign(b"wrong");
        sigs[3] = sks[3].sign(b"also wrong");

        let messages: Vec<&[u8]> = vec![msg.as_ref(); 5];
        let sig_refs: Vec<_> = sigs.iter().collect();
        let pk_refs: Vec<_> = pks.iter().collect();

        let result = batch_verify_with_fallback(&messages, &sig_refs, &pk_refs);
        assert!(result.is_err());
        let bad_indices = result.unwrap_err();
        assert!(bad_indices.contains(&1), "should identify index 1 as bad");
        assert!(bad_indices.contains(&3), "should identify index 3 as bad");
        assert_eq!(bad_indices.len(), 2, "should find exactly 2 bad signatures");
    }

    #[test]
    fn test_batch_verify_with_fallback_rejects_unmatched_tail() {
        let sk = test_key(0x75);
        let pk = sk.public_key();
        let sig = sk.sign(b"first");
        let messages: Vec<&[u8]> = vec![b"first".as_ref(), b"unmatched".as_ref()];

        assert_eq!(
            batch_verify_with_fallback(&messages, &[&sig], &[&pk]),
            Err(vec![0, 1])
        );
    }

    #[test]
    fn h2_v4_batch_accepts_h2_v4_signatures() {
        let msg = b"h2-v4 chain-bound vote";
        let sks: Vec<_> = (0..5).map(|i| test_key(0x80 + i as u8)).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();
        let sigs: Vec<_> = sks.iter().map(|sk| sk.sign_h2_v4(msg)).collect();

        let messages: Vec<&[u8]> = vec![msg.as_ref(); 5];
        let sig_refs: Vec<_> = sigs.iter().collect();
        let pk_refs: Vec<_> = pks.iter().collect();

        batch_verify_h2_v4(&messages, &sig_refs, &pk_refs).expect("H2-v4 batch should verify");
        batch_verify_h2_v4_with_fallback(&messages, &sig_refs, &pk_refs)
            .expect("H2-v4 fallback path should agree");
    }

    /// The whole point of separate entry points: a batch verified under the
    /// wrong domain must fail, and the fallback must localize every position
    /// rather than silently "confirming" the batch by checking a different
    /// message encoding.
    #[test]
    fn the_two_ciphersuites_reject_each_other_in_batch() {
        let msg = b"cross-domain replay";
        let sks: Vec<_> = (0..3).map(|i| test_key(0x90 + i as u8)).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();
        let pk_refs: Vec<_> = pks.iter().collect();
        let messages: Vec<&[u8]> = vec![msg.as_ref(); 3];

        let native: Vec<_> = sks.iter().map(|sk| sk.sign(msg)).collect();
        let native_refs: Vec<_> = native.iter().collect();
        assert_eq!(
            batch_verify_h2_v4_with_fallback(&messages, &native_refs, &pk_refs),
            Err(vec![0, 1, 2]),
            "native signatures must not pass the H2-v4 batch"
        );

        let h2: Vec<_> = sks.iter().map(|sk| sk.sign_h2_v4(msg)).collect();
        let h2_refs: Vec<_> = h2.iter().collect();
        assert_eq!(
            batch_verify_with_fallback(&messages, &h2_refs, &pk_refs),
            Err(vec![0, 1, 2]),
            "H2-v4 signatures must not pass the native batch"
        );
    }

    /// A single-element batch takes a different code path than the
    /// multi-pairing one, so it needs its own domain check.
    #[test]
    fn h2_v4_single_element_batch_uses_the_h2_v4_domain() {
        let sk = test_key(0x9F);
        let pk = sk.public_key();
        let msg = b"single";

        let h2 = sk.sign_h2_v4(msg);
        batch_verify_h2_v4(&[msg.as_ref()], &[&h2], &[&pk]).expect("H2-v4 single must verify");
        assert!(
            batch_verify(&[msg.as_ref()], &[&h2], &[&pk]).is_err(),
            "native single must reject an H2-v4 signature"
        );

        let native = sk.sign(msg);
        batch_verify(&[msg.as_ref()], &[&native], &[&pk]).expect("native single must verify");
        assert!(
            batch_verify_h2_v4(&[msg.as_ref()], &[&native], &[&pk]).is_err(),
            "H2-v4 single must reject a native signature"
        );
    }

    /// Bad-signature localization must survive the domain switch: only the
    /// corrupted positions come back, not the whole batch.
    #[test]
    fn h2_v4_fallback_identifies_exactly_the_bad_positions() {
        let msg = b"h2-v4 quorum";
        let sks: Vec<_> = (0..5).map(|i| test_key(0xA0 + i as u8)).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();

        let mut sigs: Vec<_> = sks.iter().map(|sk| sk.sign_h2_v4(msg)).collect();
        sigs[1] = sks[1].sign_h2_v4(b"wrong");
        // A native signature over the right message is just as invalid here.
        sigs[3] = sks[3].sign(msg);

        let messages: Vec<&[u8]> = vec![msg.as_ref(); 5];
        let sig_refs: Vec<_> = sigs.iter().collect();
        let pk_refs: Vec<_> = pks.iter().collect();

        assert_eq!(
            batch_verify_h2_v4_with_fallback(&messages, &sig_refs, &pk_refs),
            Err(vec![1, 3])
        );
    }
}
