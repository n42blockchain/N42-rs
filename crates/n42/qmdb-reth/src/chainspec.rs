// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The chain spec parser for this node, and the scheme helpers it builds on.
//!
//! The scheme detection and the QMDB genesis header live in `reth-chainspec`
//! (`reth_chainspec::qmdb`), where every path that builds a genesis header —
//! `--chain <file>`, the `N42_DEVNET` constant, tests — goes through them. They
//! are re-exported here for callers that already depend on this crate.

use std::sync::Arc;

use n42_qmdb_state::StateError;
use reth_chainspec::ChainSpec;
use reth_cli::chainspec::ChainSpecParser;
use reth_ethereum_cli::chainspec::{chain_value_parser, SUPPORTED_CHAINS};

pub use reth_chainspec::qmdb::{
    genesis_header, qmdb_genesis_root, state_scheme, StateScheme, STATE_SCHEME_KEY,
    STATE_SCHEME_QMDB,
};

/// Rebuilds a chain spec's genesis header for the scheme it declares.
///
/// Kept for callers that assembled a `ChainSpec` some other way; a spec built
/// from a `Genesis` already has the right header.
pub fn with_declared_state_scheme(spec: ChainSpec) -> Result<ChainSpec, StateError> {
    if state_scheme(&spec.genesis) != StateScheme::Qmdb {
        return Ok(spec);
    }
    let root = qmdb_genesis_root(&spec.genesis)?;
    let mut spec = spec;
    let mut header = spec.genesis_header.clone_header();
    header.state_root = root;
    spec.genesis_header = reth_primitives_traits::SealedHeader::new_unhashed(header);
    Ok(spec)
}

/// The chain spec parser for this node: everything reth's accepts, with the
/// genesis header built for the scheme the genesis declares.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct N42ChainSpecParser;

impl ChainSpecParser for N42ChainSpecParser {
    type ChainSpec = ChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<ChainSpec>> {
        // `From<Genesis>` already applies the scheme; this is a belt over those
        // braces for a spec assembled by any other route.
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
    use alloy_genesis::Genesis;

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
        assert_eq!(state_scheme(&genesis(Some("mpt"))), StateScheme::Mpt);
    }

    /// The reason the genesis header is rewritten at all: the two schemes give
    /// the same alloc different roots, and therefore different genesis hashes.
    #[test]
    fn a_qmdb_chain_has_a_different_genesis_than_the_same_alloc_on_mpt() {
        let mpt: ChainSpec = genesis(None).into();
        let qmdb: ChainSpec = genesis(Some("qmdb")).into();

        assert_ne!(mpt.genesis_header.state_root, qmdb.genesis_header.state_root);
        assert_ne!(mpt.genesis_hash(), qmdb.genesis_hash());
        assert_eq!(
            qmdb.genesis_header.state_root,
            qmdb_genesis_root(&qmdb.genesis).unwrap(),
            "From<Genesis> already carries the forest root of the alloc",
        );
        // And the explicit rewrite is a no-op on it.
        assert_eq!(
            with_declared_state_scheme(qmdb.clone()).unwrap().genesis_hash(),
            qmdb.genesis_hash()
        );
    }

    #[test]
    fn an_mpt_chain_is_left_exactly_as_reth_built_it() {
        let before: ChainSpec = genesis(None).into();
        let after = with_declared_state_scheme(before.clone()).unwrap();
        assert_eq!(before.genesis_hash(), after.genesis_hash());
    }
}
