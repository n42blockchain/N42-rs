// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which commitment a chain uses, and the genesis header that follows from it.
//!
//! gov5 declares the scheme in the chain config as `"stateScheme": "qmdb"`
//! (`params.ChainConfig.StateScheme`), and a chain without the field is a
//! Merkle-Patricia chain. This reads the same field from the same place in
//! the genesis JSON, so one file describes the chain to both clients.
//!
//! The genesis header is where the scheme first matters. reth computes the
//! genesis state root as the Merkle-Patricia root of the alloc; gov5, on a
//! QMDB chain, seeds the twig forest from the alloc and writes *that* root
//! into the header (`internal/genesis_qmdb.go`). Two nodes that disagree on
//! the genesis state root disagree on the genesis hash, and never connect. So
//! for a QMDB chain the genesis header is rebuilt here before anything reads
//! it.

use std::sync::Arc;

use alloy_genesis::Genesis;
use alloy_primitives::B256;
use n42_qmdb_state::{QmdbForest, StateError};
use reth_chainspec::ChainSpec;
use reth_cli::chainspec::ChainSpecParser;
use reth_ethereum_cli::chainspec::{chain_value_parser, SUPPORTED_CHAINS};
use reth_primitives_traits::SealedHeader;

use crate::changes::changes_from_alloc;

/// The genesis config key gov5 reads the scheme from.
pub const STATE_SCHEME_KEY: &str = "stateScheme";

/// The value that selects QMDB.
pub const STATE_SCHEME_QMDB: &str = "qmdb";

/// How a chain commits to its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateScheme {
    /// Merkle-Patricia trie: Ethereum's, and what an unlabelled chain uses.
    Mpt,
    /// QMDB twig forest: the native chain's.
    Qmdb,
}

/// Reads the scheme a genesis declares.
///
/// Absent means MPT, matching gov5's default; a present value that is not
/// `"qmdb"` also means MPT, since gov5's other presets are all trie-shaped.
pub fn state_scheme(genesis: &Genesis) -> StateScheme {
    let declared: Option<String> = genesis
        .config
        .extra_fields
        .get_deserialized(STATE_SCHEME_KEY)
        .and_then(Result::ok);
    match declared.as_deref() {
        Some(STATE_SCHEME_QMDB) => StateScheme::Qmdb,
        _ => StateScheme::Mpt,
    }
}

/// The QMDB root of a genesis allocation.
pub fn qmdb_genesis_root(genesis: &Genesis) -> Result<B256, StateError> {
    // The hash the forest is filed under does not affect the root; the real
    // genesis hash is not known until this root is in the header.
    let forest = QmdbForest::genesis(B256::ZERO, &changes_from_alloc(&genesis.alloc))?;
    Ok(forest.root())
}

/// Rewrites a chain spec's genesis header for the scheme it declares.
///
/// An MPT chain is returned untouched. A QMDB chain gets a genesis header whose
/// state root is the forest root of the alloc, which changes the genesis hash —
/// as it must, since that is the hash a gov5 node on the same chain has.
pub fn with_declared_state_scheme(spec: ChainSpec) -> Result<ChainSpec, StateError> {
    if state_scheme(&spec.genesis) != StateScheme::Qmdb {
        return Ok(spec);
    }
    let root = qmdb_genesis_root(&spec.genesis)?;
    let mut spec = spec;
    let mut header = spec.genesis_header.clone_header();
    header.state_root = root;
    spec.genesis_header = SealedHeader::new_unhashed(header);
    Ok(spec)
}

/// The chain spec parser for this node.
///
/// Everything `reth`'s parser accepts, with one difference: a genesis that
/// declares `"stateScheme": "qmdb"` gets a QMDB genesis header. Named chains
/// (`mainnet`, `dev`, …) are untouched, since none of them declares a scheme.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct N42ChainSpecParser;

impl ChainSpecParser for N42ChainSpecParser {
    type ChainSpec = ChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<ChainSpec>> {
        let spec = chain_value_parser(s)?;
        if state_scheme(&spec.genesis) != StateScheme::Qmdb {
            return Ok(spec);
        }
        let spec = Arc::try_unwrap(spec).unwrap_or_else(|shared| (*shared).clone());
        Ok(Arc::new(with_declared_state_scheme(spec)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis(scheme: Option<&str>) -> Genesis {
        let scheme_field = scheme
            .map(|s| format!(r#", "stateScheme": "{s}""#))
            .unwrap_or_default();
        let json = format!(
            r#"{{
                "config": {{ "chainId": 1143, "shanghaiTime": 0, "cancunTime": 0{scheme_field} }},
                "alloc": {{
                    "0x0000000000000000000000000000000000000001": {{ "balance": "0x64" }}
                }},
                "difficulty": "0x0", "gasLimit": "0x1c9c380", "timestamp": "0x0",
                "extraData": "0x", "nonce": "0x0",
                "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "coinbase": "0x0000000000000000000000000000000000000000",
                "number": "0x0", "gasUsed": "0x0",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }}"#
        );
        serde_json::from_str(&json).expect("a genesis")
    }

    #[test]
    fn the_scheme_is_read_from_where_gov5_puts_it() {
        assert_eq!(state_scheme(&genesis(None)), StateScheme::Mpt);
        assert_eq!(state_scheme(&genesis(Some("qmdb"))), StateScheme::Qmdb);
        // gov5's other presets are trie-shaped.
        assert_eq!(state_scheme(&genesis(Some("mpt"))), StateScheme::Mpt);
    }

    /// The reason the genesis header is rewritten at all: the two schemes give
    /// the same alloc different roots, and therefore different genesis hashes.
    #[test]
    fn a_qmdb_chain_has_a_different_genesis_than_the_same_alloc_on_mpt() {
        let mpt: ChainSpec = genesis(None).into();
        let qmdb = with_declared_state_scheme(genesis(Some("qmdb")).into()).unwrap();

        assert_ne!(mpt.genesis_header.state_root, qmdb.genesis_header.state_root);
        assert_ne!(mpt.genesis_hash(), qmdb.genesis_hash());
        assert_eq!(
            qmdb.genesis_header.state_root,
            qmdb_genesis_root(&qmdb.genesis).unwrap(),
            "the header carries the forest root of the alloc",
        );
    }

    #[test]
    fn an_mpt_chain_is_left_exactly_as_reth_built_it() {
        let before: ChainSpec = genesis(None).into();
        let after = with_declared_state_scheme(before.clone()).unwrap();
        assert_eq!(before.genesis_hash(), after.genesis_hash());
    }

    #[test]
    fn the_genesis_root_is_deterministic() {
        let g = genesis(Some("qmdb"));
        assert_eq!(qmdb_genesis_root(&g).unwrap(), qmdb_genesis_root(&g).unwrap());
    }
}
