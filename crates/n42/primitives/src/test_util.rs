// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared fixtures for the unit tests of this crate.

use crate::{beacon_chain_spec, BLSPubkey, BeaconState, ChainSpec, Validator};
use alloy_primitives::B256;
use blst::min_pk::SecretKey;
use std::sync::atomic::{AtomicU64, Ordering};

/// Deterministic BLS secret key for validator `i`.
pub(crate) fn secret_key(i: usize) -> SecretKey {
    let mut ikm = [0u8; 32];
    ikm[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
    SecretKey::key_gen(&ikm, &[]).expect("32 byte ikm is valid")
}

/// Public key bytes of validator `i` (a real, parseable BLS key).
pub(crate) fn pubkey(i: usize) -> BLSPubkey {
    BLSPubkey::from_slice(&secret_key(i).sk_to_pk().to_bytes())
}

/// Eth1 style withdrawal credentials (`0x01` prefix) for an address made of `byte`.
pub(crate) fn eth1_credentials(byte: u8) -> B256 {
    let mut c = [0u8; 32];
    c[0] = 0x01;
    c[12..].fill(byte);
    B256::from(c)
}

/// An active validator (activated at genesis, never exits) with a full effective balance.
pub(crate) fn active_validator(i: usize, spec: &ChainSpec) -> Validator {
    let mut v = Validator::from_deposit(
        pubkey(i),
        eth1_credentials((i % 250) as u8 + 1),
        spec.max_effective_balance,
        spec,
    );
    v.activation_eligibility_epoch = 0;
    v.activation_epoch = 0;
    v
}

/// A fresh, never repeated randao mix.
pub(crate) fn unique_mix() -> B256 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    b[31] = 0xee;
    B256::from(b)
}

/// A state at `slot` with `n` active validators, matching balances and zero inactivity scores.
pub(crate) fn state_with_validators(n: usize, slot: u64) -> BeaconState {
    let spec = beacon_chain_spec();
    let mut state = BeaconState::new();
    state.slot = slot;
    // The shuffle cache is process-global and keyed by (epoch, seed), so give every fixture its
    // own randao mix to keep tests from sharing cache entries.
    state.randao_mix = unique_mix();
    for i in 0..n {
        state
            .validators_store
            .push(active_validator(i, &spec))
            .expect("push validator");
        state
            .balances_store
            .push(spec.max_effective_balance)
            .expect("push balance");
        state.inactivity_scores_store.push(0).expect("push score");
    }
    state
}
