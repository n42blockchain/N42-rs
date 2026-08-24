use super::keys::{BlsError, BlsPublicKey, BlsSignature};
use super::{DST, H2_V4_DST};
use blst::BLST_ERROR;
use blst::min_pk::AggregateSignature as BlstAggSig;

pub struct AggregateSignature;

impl AggregateSignature {
    /// Aggregate multiple BLS signatures into a single signature.
    pub fn aggregate(signatures: &[&BlsSignature]) -> Result<BlsSignature, BlsError> {
        if signatures.is_empty() {
            return Err(BlsError::SigningFailed);
        }

        let sigs: Vec<&blst::min_pk::Signature> = signatures.iter().map(|s| s.inner()).collect();

        let agg = BlstAggSig::aggregate(&sigs, true).map_err(|_| BlsError::SigningFailed)?;

        Ok(BlsSignature(agg.to_signature()))
    }

    /// Verify an aggregated signature against multiple (message, public_key) pairs.
    /// All messages must be the same for this use case (quorum voting).
    pub fn verify_aggregate(
        message: &[u8],
        signature: &BlsSignature,
        public_keys: &[&BlsPublicKey],
    ) -> Result<(), BlsError> {
        let pks: Vec<&blst::min_pk::PublicKey> = public_keys.iter().map(|pk| pk.inner()).collect();

        let result = signature
            .inner()
            .fast_aggregate_verify(true, message, DST, &pks);

        if result != BLST_ERROR::BLST_SUCCESS {
            return Err(BlsError::VerificationFailed(result));
        }
        Ok(())
    }

    /// Verifies a gov5-compatible H2-v4 aggregate signature. This explicit
    /// entry point prevents the POP ciphersuite from leaking into native Rust
    /// consensus signatures, which remain on [`super::DST`].
    pub fn verify_h2_v4_aggregate(
        message: &[u8],
        signature: &BlsSignature,
        public_keys: &[&BlsPublicKey],
    ) -> Result<(), BlsError> {
        let pks: Vec<&blst::min_pk::PublicKey> = public_keys.iter().map(|pk| pk.inner()).collect();
        let result = signature
            .inner()
            .fast_aggregate_verify(true, message, H2_V4_DST, &pks);
        if result != BLST_ERROR::BLST_SUCCESS {
            return Err(BlsError::VerificationFailed(result));
        }
        Ok(())
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
    fn test_aggregate_and_verify() {
        let message = b"consensus vote";

        let sk1 = test_key(0x11);
        let sk2 = test_key(0x12);
        let sk3 = test_key(0x13);

        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let pk3 = sk3.public_key();

        let sig1 = sk1.sign(message);
        let sig2 = sk2.sign(message);
        let sig3 = sk3.sign(message);

        let agg_sig = AggregateSignature::aggregate(&[&sig1, &sig2, &sig3])
            .expect("aggregation should succeed");

        AggregateSignature::verify_aggregate(message, &agg_sig, &[&pk1, &pk2, &pk3])
            .expect("aggregate verification should succeed");
    }

    #[test]
    fn test_aggregate_wrong_message() {
        let sk1 = test_key(0x21);
        let sk2 = test_key(0x22);
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let sig1 = sk1.sign(b"correct message");
        let sig2 = sk2.sign(b"correct message");
        let agg_sig = AggregateSignature::aggregate(&[&sig1, &sig2]).unwrap();
        assert!(
            AggregateSignature::verify_aggregate(b"wrong message", &agg_sig, &[&pk1, &pk2])
                .is_err()
        );
    }

    #[test]
    fn test_aggregate_empty_signatures() {
        let result = AggregateSignature::aggregate(&[]);
        assert!(
            result.is_err(),
            "aggregating zero signatures should return error"
        );
    }

    #[test]
    fn test_aggregate_single_signature() {
        let message = b"single signer";
        let sk = test_key(0x31);
        let pk = sk.public_key();
        let sig = sk.sign(message);
        let agg_sig = AggregateSignature::aggregate(&[&sig]).expect("aggregation should succeed");
        AggregateSignature::verify_aggregate(message, &agg_sig, &[&pk])
            .expect("single-sig verification should succeed");
    }

    #[test]
    fn h2_v4_pop_domain_is_explicit_and_separate() {
        let sk1 = test_key(0x41);
        let sk2 = test_key(0x42);
        let message = b"h2-v4-domain";
        let sig1 = sk1.sign_h2_v4(message);
        let sig2 = sk2.sign_h2_v4(message);
        let aggregate = AggregateSignature::aggregate(&[&sig1, &sig2]).unwrap();
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let public_keys = [&pk1, &pk2];

        AggregateSignature::verify_h2_v4_aggregate(message, &aggregate, &public_keys).unwrap();
        assert!(
            AggregateSignature::verify_aggregate(message, &aggregate, &public_keys).is_err(),
            "native NUL and H2-v4 POP ciphersuites must remain separated"
        );
    }
}
