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

#[cfg(test)]
mod tests {
    use super::super::keys::BlsSecretKey;
    use super::*;

    fn test_key(seed: u8) -> BlsSecretKey {
        BlsSecretKey::key_gen(&[seed; 32]).expect("deterministic test key should be valid")
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
