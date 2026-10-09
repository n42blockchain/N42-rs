// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The hello of the direct vote protocol (`N42_VOTE_TRANSPORT`): a validator
//! tells its peers which libp2p peer id its votes are to be sent to, signed
//! by its consensus key. The signed bytes are fixed here (and mirrored by
//! `n42_h2_net::vote_hello_message`): a 16-byte ASCII prefix that no
//! consensus signing message starts with, the chain's genesis hash, and the
//! peer id's bytes. The engine signs only this shape, never caller bytes.

use alloy_primitives::B256;
use n42_h2_primitives::BlsSignature;

use super::state_machine::ConsensusEngine;

/// The prefix of a vote hello's signed bytes.
pub const VOTE_HELLO_PREFIX: &[u8; 16] = b"n42/vote-hello/1";

/// The bytes a vote hello signs.
pub fn vote_hello_signing_message(genesis_hash: B256, peer_id: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(VOTE_HELLO_PREFIX.len() + 32 + peer_id.len());
    message.extend_from_slice(VOTE_HELLO_PREFIX);
    message.extend_from_slice(genesis_hash.as_slice());
    message.extend_from_slice(peer_id);
    message
}

impl ConsensusEngine {
    /// This validator's hello for the libp2p peer id `peer_id` (bytes).
    pub fn sign_vote_hello(&self, genesis_hash: B256, peer_id: &[u8]) -> BlsSignature {
        self.secret_key
            .sign(&vote_hello_signing_message(genesis_hash, peer_id))
    }

    /// Whether `signature` is validator `index`'s hello for `peer_id` under
    /// the current view's validator set.
    pub fn verify_vote_hello(
        &self,
        index: u32,
        genesis_hash: B256,
        peer_id: &[u8],
        signature: &BlsSignature,
    ) -> bool {
        let set = self.validator_set_for_view(self.round_state.current_view());
        set.get_public_key(index).is_ok_and(|pk| {
            pk.verify_prevalidated(&vote_hello_signing_message(genesis_hash, peer_id), signature)
                .is_ok()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hello_bytes_are_prefix_genesis_peer() {
        let message = vote_hello_signing_message(B256::repeat_byte(7), &[1, 2, 3]);
        assert_eq!(&message[..16], b"n42/vote-hello/1");
        assert_eq!(&message[16..48], B256::repeat_byte(7).as_slice());
        assert_eq!(&message[48..], &[1, 2, 3]);
    }
}
