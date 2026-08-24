//! Chain-bound signing domains for the cross-client H2-v4 protocol.

use crate::h2_wire::{H2Message, H2WireError, decode_message, encode_message};
use alloy_primitives::B256;
pub use n42_h2_primitives::consensus::{
    H2V4ChainIdentity, h2_v4_commit_signing_message as commit_signing_message,
    h2_v4_new_view_signing_message as new_view_signing_message,
    h2_v4_proposal_signing_message as proposal_signing_message,
    h2_v4_timeout_signing_message as timeout_signing_message,
    h2_v4_vote_signing_message as vote_signing_message,
};

const PREFIX: &[u8; 7] = b"N42H2V4";
const MAX_WIRE_SIZE: usize = 8192;
const HEADER_SIZE: usize = 7 + 8 + 32 + 32 + 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2V4Envelope {
    pub identity: H2V4ChainIdentity,
    pub changes_hash: B256,
    pub message: H2Message,
}

#[derive(Debug, thiserror::Error)]
pub enum H2V4Error {
    #[error("truncated H2-v4 envelope")]
    Truncated,
    #[error("invalid H2-v4 magic")]
    InvalidMagic,
    #[error("H2-v4 chain identity mismatch")]
    ChainIdentityMismatch,
    #[error("invalid H2-v4 message length")]
    InvalidLength,
    #[error("invalid H2-v4 snappy payload: {0}")]
    InvalidSnappy(String),
    #[error("non-canonical H2-v4 payload")]
    NonCanonicalPayload,
    #[error(transparent)]
    Wire(#[from] H2WireError),
}

pub fn encode_envelope(envelope: &H2V4Envelope) -> Result<Vec<u8>, H2V4Error> {
    let wire = encode_message(&envelope.message)?;
    if wire.len() > MAX_WIRE_SIZE {
        return Err(H2V4Error::InvalidLength);
    }
    let mut out = Vec::with_capacity(HEADER_SIZE + wire.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(&envelope.identity.chain_id.to_le_bytes());
    out.extend_from_slice(envelope.identity.genesis_hash.as_slice());
    out.extend_from_slice(envelope.changes_hash.as_slice());
    out.extend_from_slice(&(wire.len() as u32).to_le_bytes());
    out.extend_from_slice(&wire);
    Ok(out)
}

pub fn decode_envelope(
    data: &[u8],
    expected: H2V4ChainIdentity,
) -> Result<H2V4Envelope, H2V4Error> {
    if data.len() < HEADER_SIZE {
        return Err(H2V4Error::Truncated);
    }
    if &data[..7] != PREFIX {
        return Err(H2V4Error::InvalidMagic);
    }
    let chain_id = u64::from_le_bytes(data[7..15].try_into().expect("fixed range"));
    let genesis_hash = B256::from_slice(&data[15..47]);
    let identity = H2V4ChainIdentity {
        chain_id,
        genesis_hash,
    };
    if identity != expected {
        return Err(H2V4Error::ChainIdentityMismatch);
    }
    let changes_hash = B256::from_slice(&data[47..79]);
    let wire_len = u32::from_le_bytes(data[79..83].try_into().expect("fixed range")) as usize;
    if wire_len > MAX_WIRE_SIZE || wire_len != data.len() - HEADER_SIZE {
        return Err(H2V4Error::InvalidLength);
    }
    let wire = &data[HEADER_SIZE..];
    let message = decode_message(wire)?;
    // gov5 re-encodes and compares here, so accepting a byte string it would
    // reject is a cross-client disagreement about what is even a valid
    // message — and this is consensus traffic, so the two clients must agree
    // exactly. Structural strictness in the decoders is not the same
    // guarantee: it rejects malformed input, while this rejects input that is
    // well-formed but is not what our own encoder would produce. Cheap enough
    // (one re-encode plus a compare) to keep as a standing invariant rather
    // than a claim to re-derive whenever either side's codec changes.
    let canonical = encode_message(&message)?;
    if canonical != wire {
        return Err(H2V4Error::NonCanonicalPayload);
    }
    Ok(H2V4Envelope {
        identity,
        changes_hash,
        message,
    })
}

pub fn encode_gossip(envelope: &H2V4Envelope) -> Result<Vec<u8>, H2V4Error> {
    let wire = encode_envelope(envelope)?;
    snap::raw::Encoder::new()
        .compress_vec(&wire)
        .map_err(|error| H2V4Error::InvalidSnappy(error.to_string()))
}

pub fn decode_gossip(data: &[u8], expected: H2V4ChainIdentity) -> Result<H2V4Envelope, H2V4Error> {
    let len = snap::raw::decompress_len(data)
        .map_err(|error| H2V4Error::InvalidSnappy(error.to_string()))?;
    if len > HEADER_SIZE + MAX_WIRE_SIZE {
        return Err(H2V4Error::InvalidLength);
    }
    let wire = snap::raw::Decoder::new()
        .decompress_vec(data)
        .map_err(|error| H2V4Error::InvalidSnappy(error.to_string()))?;
    decode_envelope(&wire, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixture {
        schema: String,
        chain_id: u64,
        genesis_hash: String,
        view: u64,
        block_hash: String,
        changes_hash: String,
        proposal_hex: String,
        vote_hex: String,
        commit_hex: String,
        timeout_hex: String,
        new_view_hex: String,
    }

    #[derive(Deserialize)]
    struct EnvelopeFixture {
        schema: String,
        envelope_hex: String,
        gossip_hex: String,
    }

    #[test]
    fn matches_gov5_domains_and_binds_chain_identity() {
        let fixture: Fixture =
            serde_json::from_str(include_str!("../testdata/h2_v4_domains_v1.json")).unwrap();
        assert_eq!(fixture.schema, "n42-h2-v4-domains-v1");
        let identity = H2V4ChainIdentity {
            chain_id: fixture.chain_id,
            genesis_hash: B256::from_slice(&hex::decode(fixture.genesis_hash).unwrap()),
        };
        let block_hash = B256::from_slice(&hex::decode(fixture.block_hash).unwrap());
        let changes_hash = B256::from_slice(&hex::decode(fixture.changes_hash).unwrap());
        assert_eq!(
            hex::encode(proposal_signing_message(
                identity,
                fixture.view,
                block_hash,
                changes_hash
            )),
            fixture.proposal_hex
        );
        assert_eq!(
            hex::encode(vote_signing_message(identity, fixture.view, block_hash)),
            fixture.vote_hex
        );
        assert_eq!(
            hex::encode(commit_signing_message(
                identity,
                fixture.view,
                block_hash,
                changes_hash
            )),
            fixture.commit_hex
        );
        assert_eq!(
            hex::encode(timeout_signing_message(identity, fixture.view)),
            fixture.timeout_hex
        );
        assert_eq!(
            hex::encode(new_view_signing_message(identity, fixture.view)),
            fixture.new_view_hex
        );

        let mut other = identity;
        other.chain_id += 1;
        assert_ne!(
            commit_signing_message(identity, fixture.view, block_hash, changes_hash),
            commit_signing_message(other, fixture.view, block_hash, changes_hash)
        );
    }

    #[test]
    fn decodes_and_reencodes_gov5_v4_envelope_and_snappy() {
        let fixture: EnvelopeFixture =
            serde_json::from_str(include_str!("../testdata/h2_v4_envelope_v1.json")).unwrap();
        assert_eq!(fixture.schema, "n42-h2-v4-envelope-v1");
        let identity = H2V4ChainIdentity {
            chain_id: 94,
            genesis_hash: B256::repeat_byte(0x11),
        };
        let wire = hex::decode(fixture.envelope_hex).unwrap();
        let envelope = decode_envelope(&wire, identity).unwrap();
        assert_eq!(envelope.changes_hash, B256::repeat_byte(0x33));
        assert_eq!(envelope.message.kind() as u8, 3);
        assert_eq!(encode_envelope(&envelope).unwrap(), wire);

        let gossip = hex::decode(fixture.gossip_hex).unwrap();
        assert_eq!(decode_gossip(&gossip, identity).unwrap(), envelope);
        let mut wrong = identity;
        wrong.chain_id += 1;
        assert!(matches!(
            decode_envelope(&wire, wrong),
            Err(H2V4Error::ChainIdentityMismatch)
        ));
        let mut trailing = wire;
        trailing.push(0);
        assert!(matches!(
            decode_envelope(&trailing, identity),
            Err(H2V4Error::InvalidLength)
        ));
    }

    /// The fixtures are a byte-exact contract with gov5, which pins the same
    /// SHA-256 values on its side (`docs/H2_V4_RUST_SYNC_BRIEF.md`). Parsing
    /// them as JSON, which every other test here does, would not notice a
    /// vendored copy drifting from gov5's — serde ignores whitespace and line
    /// endings, so a re-generated or hand-edited fixture reads fine while no
    /// longer describing the same wire contract.
    ///
    /// Hash the raw bytes for that reason. A failure means either gov5 revised
    /// the vectors (re-vendor and update these constants together) or the local
    /// copy was rewritten — most likely by a Windows checkout converting them
    /// to CRLF, which `.gitattributes` now prevents.
    #[test]
    fn vendored_fixtures_match_the_gov5_contract() {
        fn sha256_hex(bytes: &[u8]) -> String {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            hex::encode(hasher.finalize())
        }

        for (name, bytes, expected) in [
            (
                "cross_client_h2_v1.json",
                include_bytes!("../testdata/cross_client_h2_v1.json").as_slice(),
                "0c5877432b8d7adb3fc60c5226564ad1d0e099b6c73f39b823703926e82d2aee",
            ),
            (
                "h2_v4_domains_v1.json",
                include_bytes!("../testdata/h2_v4_domains_v1.json").as_slice(),
                "f3f20d4641455eaf7ea6c96641fc4674134080aefcb300c219ab34a53d4d9510",
            ),
            (
                "h2_v4_envelope_v1.json",
                include_bytes!("../testdata/h2_v4_envelope_v1.json").as_slice(),
                "09a98f549fcfa1b4185b78b975fa680608c73e169758cb0c052c72efbff4ff83",
            ),
        ] {
            assert_eq!(
                sha256_hex(bytes),
                expected,
                "{name} no longer matches the fixture gov5 pins"
            );
        }
    }

    /// The brief lists five mandatory rejection paths for the v4 envelope
    /// codec. Each one is a way two clients could disagree about whether a
    /// byte string is a valid consensus message, so each gets a case here.
    #[test]
    fn envelope_decoding_rejects_all_five_documented_paths() {
        let identity = H2V4ChainIdentity {
            chain_id: 94,
            genesis_hash: B256::repeat_byte(0x11),
        };
        let fixture: EnvelopeFixture =
            serde_json::from_str(include_str!("../testdata/h2_v4_envelope_v1.json")).unwrap();
        let valid = hex::decode(fixture.envelope_hex).unwrap();
        assert!(
            decode_envelope(&valid, identity).is_ok(),
            "baseline decodes"
        );

        // 1. Chain identity mismatch — a message from another chain replayed here.
        let foreign = H2V4ChainIdentity {
            chain_id: identity.chain_id + 1,
            genesis_hash: identity.genesis_hash,
        };
        assert!(matches!(
            decode_envelope(&valid, foreign),
            Err(H2V4Error::ChainIdentityMismatch)
        ));
        let mut wrong_genesis = valid.clone();
        wrong_genesis[15] ^= 0xFF;
        assert!(matches!(
            decode_envelope(&wrong_genesis, identity),
            Err(H2V4Error::ChainIdentityMismatch)
        ));

        // 2. Declared length disagreeing with the payload actually present.
        let mut bad_len = valid.clone();
        let declared = u32::from_le_bytes(bad_len[79..83].try_into().unwrap());
        bad_len[79..83].copy_from_slice(&(declared + 1).to_le_bytes());
        assert!(matches!(
            decode_envelope(&bad_len, identity),
            Err(H2V4Error::InvalidLength)
        ));

        // 3. Trailing bytes after a correctly declared payload. The length
        //    field still says the original size, so this is caught as a
        //    length disagreement rather than silently ignored.
        let mut trailing = valid.clone();
        trailing.push(0x00);
        assert!(matches!(
            decode_envelope(&trailing, identity),
            Err(H2V4Error::InvalidLength)
        ));

        // 4. A Snappy frame that expands past the ceiling: rejected from the
        //    declared length alone, without allocating the output.
        let bomb = vec![0u8; HEADER_SIZE + MAX_WIRE_SIZE + 1];
        let compressed = snap::raw::Encoder::new().compress_vec(&bomb).unwrap();
        assert!(matches!(
            decode_gossip(&compressed, identity),
            Err(H2V4Error::InvalidLength)
        ));

        // 5. A non-canonical inner message: structurally decodable, but not
        //    the encoding our own encoder produces. Built by giving the inner
        //    envelope's length prefix a payload one byte longer than the
        //    message needs, which the inner decoder tolerates but a re-encode
        //    does not reproduce.
        let truncated_header = &valid[..HEADER_SIZE];
        let inner = &valid[HEADER_SIZE..];
        let message = decode_message(inner).unwrap();
        let mut padded_inner = encode_message(&message).unwrap();
        padded_inner.push(0x00);
        let inner_len = u32::from_le_bytes(padded_inner[1..5].try_into().unwrap());
        padded_inner[1..5].copy_from_slice(&(inner_len + 1).to_le_bytes());
        let mut non_canonical = truncated_header.to_vec();
        non_canonical[79..83].copy_from_slice(&(padded_inner.len() as u32).to_le_bytes());
        non_canonical.extend_from_slice(&padded_inner);
        let result = decode_envelope(&non_canonical, identity);
        assert!(
            matches!(
                result,
                Err(H2V4Error::NonCanonicalPayload) | Err(H2V4Error::Wire(_))
            ),
            "a payload our encoder would not produce must not decode: {result:?}"
        );
    }
}
