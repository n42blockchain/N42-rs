// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `n42_getProof`: QMDB membership proofs at a persisted block
//! (`docs/QMDB_HISTORY.md`), and the `eth_getProof` refusal on a QMDB chain.
//!
//! On a QMDB chain the header's state root is the QMDB root. The proofs here
//! are QMDB twig proofs in gov5's v2 byte layout
//! ([`n42_twig_core::qmdb_compat::QmdbProof::encode`]): entry leaf -> twig
//! leaf tree (11 levels) -> twig root with the active-bits hash -> upper
//! binary tree -> root. The node rebuilds the root of the asked block from its
//! QMDB history, compares it with the root the committing header carries, and
//! returns proofs only when they agree; every proof is verified against that
//! root before it leaves.
//!
//! Under deferred execution a header carries the state root of an ancestor
//! (its parent at depth 1), so the state after block `N` is committed by a
//! later header, the *anchor*: the response names it, and a client checks the
//! proof against the anchor header's `stateRoot`.

use std::sync::Arc;

use alloy_consensus::BlockHeader;
use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_primitives::{Address, Bytes, B256, U64};
use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    types::{ErrorObject, ErrorObjectOwned},
};
use n42_qmdb_reth::{
    history::{HistoryError, KeyAtHeight},
    QmdbNodeState,
};
use n42_twig_core::qmdb_compat::{gov5_account_key, gov5_storage_key};
use reth_provider::{BlockNumReader, HeaderProvider};
use serde::{Deserialize, Serialize};

/// The error code of a block outside what this node can prove: the code
/// `eth_getProof` uses for a pruned height (EIP-4444 history expiry).
pub const PRUNED_HISTORY_CODE: i32 = 4444;
/// A block the node will be able to prove but cannot yet (not persisted, or
/// its root not yet carried by a persisted header).
pub const NOT_YET_CODE: i32 = -32001;
/// The node keeps no history, or a request it cannot serve.
pub const UNSUPPORTED_CODE: i32 = -32004;
/// The rebuilt root disagrees with the header, or a history file is unreadable.
pub const INTERNAL_CODE: i32 = -32603;
/// The most storage keys one request may ask for.
pub const MAX_STORAGE_KEYS: usize = 1024;

/// The proof byte layout every `proof` field carries.
pub const PROOF_FORMAT: &str = "gov5-qmdb-v2";

/// One key's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QmdbKeyProof {
    /// The raw QMDB key (gov5's account or storage key hash).
    pub key: B256,
    /// Whether the key had a live entry after the block. `false` is the
    /// node's statement, not a proof: QMDB proofs prove membership only.
    pub found: bool,
    /// The entry's value in gov5's encoding, when found.
    pub value: Option<Bytes>,
    /// The gov5 v2 proof bytes, when found.
    pub proof: Option<Bytes>,
}

/// One storage slot's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QmdbStorageProof {
    /// The slot asked for.
    pub slot: B256,
    /// Its answer.
    #[serde(flatten)]
    pub proof: QmdbKeyProof,
}

/// `n42_getProof`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QmdbAccountProof {
    /// The block whose post-state is proved.
    pub block_number: U64,
    /// Its hash.
    pub block_hash: B256,
    /// The QMDB root after it.
    pub state_root: B256,
    /// The header that carries `state_root` (the block itself without
    /// deferred execution).
    pub anchor_number: U64,
    /// Its hash.
    pub anchor_hash: B256,
    /// The account.
    pub address: Address,
    /// The account's answer.
    pub account: QmdbKeyProof,
    /// One answer per storage slot asked.
    pub storage_proof: Vec<QmdbStorageProof>,
    /// The proof byte layout ([`PROOF_FORMAT`]).
    pub proof_format: String,
}

/// `n42_proofWindow`'s result: what this node can prove now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QmdbProofWindow {
    /// Whether the node keeps QMDB history.
    pub history: bool,
    /// The history mode (`off`, `all`, or the kept block count).
    pub mode: String,
    /// The earliest provable block.
    pub earliest: Option<U64>,
    /// The newest provable block (persisted, with its root carried by a
    /// persisted header).
    pub latest: Option<U64>,
    /// Why recording stopped, if it did.
    pub broken: Option<String>,
}

/// The `n42` QMDB proof namespace.
#[cfg_attr(not(test), rpc(server, namespace = "n42"))]
#[cfg_attr(test, rpc(server, client, namespace = "n42"))]
pub trait QmdbProofApi {
    /// Proves an account and storage slots as they stood after a block.
    #[method(name = "getProof")]
    async fn get_proof(&self, address: Address, storage_keys: Vec<B256>, block: Option<BlockId>) -> RpcResult<QmdbAccountProof>;

    /// What this node can prove.
    #[method(name = "proofWindow")]
    fn proof_window(&self) -> RpcResult<QmdbProofWindow>;
}

/// The offset from a header to the block whose post-state root it carries:
/// 0 without deferred execution, the depth with it.
pub type RootOffset = Arc<dyn Fn(u64) -> u64 + Send + Sync>;
/// The database's persisted block (the `Finish` checkpoint).
pub type PersistedHead = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// The namespace's implementation.
pub struct QmdbProofExt<Provider> {
    /// The node's QMDB state.
    pub state: QmdbNodeState,
    /// Canonical headers.
    pub provider: Provider,
    /// The root offset of a header by its timestamp.
    pub root_offset: RootOffset,
    /// The persisted head.
    pub persisted: PersistedHead,
}

impl<Provider> std::fmt::Debug for QmdbProofExt<Provider> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QmdbProofExt").finish_non_exhaustive()
    }
}

fn error(code: i32, message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObject::owned(code, message.into(), Option::<()>::None)
}

fn history_error(err: HistoryError) -> ErrorObjectOwned {
    let code = match &err {
        HistoryError::Pruned { .. } | HistoryError::Rewound { .. } => PRUNED_HISTORY_CODE,
        HistoryError::NotYet { .. } | HistoryError::Retry(_) => NOT_YET_CODE,
        HistoryError::Disabled | HistoryError::NotRecorded { .. } | HistoryError::LookupBudget(_) => UNSUPPORTED_CODE,
        HistoryError::RootMismatch { .. } | HistoryError::Io(_) => INTERNAL_CODE,
    };
    error(code, err.to_string())
}

fn provider_error(err: impl std::fmt::Display) -> ErrorObjectOwned {
    error(INTERNAL_CODE, format!("provider: {err}"))
}

fn key_proof(answer: &KeyAtHeight) -> Result<QmdbKeyProof, ErrorObjectOwned> {
    Ok(match &answer.proof {
        Some(proof) => QmdbKeyProof {
            key: B256::from(answer.key),
            found: true,
            value: Some(Bytes::from(proof.value.clone())),
            proof: Some(Bytes::from(proof.encode().map_err(|e| error(INTERNAL_CODE, e.to_string()))?)),
        },
        None => QmdbKeyProof { key: B256::from(answer.key), found: false, value: None, proof: None },
    })
}

impl<Provider> QmdbProofExt<Provider>
where
    Provider: HeaderProvider + BlockNumReader + Clone + Send + Sync + 'static,
    Provider::Header: BlockHeader,
{
    /// The canonical header at `number`: `(hash, state_root, timestamp)`.
    fn header(&self, number: u64) -> Result<Option<(B256, B256, u64)>, ErrorObjectOwned> {
        Ok(self
            .provider
            .sealed_header(number)
            .map_err(provider_error)?
            .map(|header| (header.hash(), header.state_root(), header.timestamp())))
    }

    /// The persisted header that carries the post-state root of block
    /// `number`: `(anchor number, anchor hash, root)`, or `None` when no
    /// persisted header carries it yet.
    fn anchor(&self, number: u64, persisted: u64) -> Result<Option<(u64, B256, B256)>, ErrorObjectOwned> {
        // A header at `m` carries the root of `m - offset(m)`; the offset is
        // at most the deferred depth (2).
        for m in number..=number.saturating_add(2).min(persisted) {
            let Some((hash, root, timestamp)) = self.header(m)? else { return Ok(None) };
            let offset = if m == 0 { 0 } else { (self.root_offset)(timestamp) };
            if m.checked_sub(offset) == Some(number) {
                return Ok(Some((m, hash, root)));
            }
        }
        Ok(None)
    }

    /// The block `id` names, as a canonical persisted `(number, hash)`.
    fn resolve(&self, id: Option<BlockId>, persisted: u64) -> Result<(u64, B256), ErrorObjectOwned> {
        let history = self.state.history().ok_or_else(|| history_error(HistoryError::Disabled))?;
        let (earliest, latest) = history.range();
        let number = match id.unwrap_or(BlockId::Number(BlockNumberOrTag::Latest)) {
            BlockId::Hash(hash) => {
                let number = self
                    .provider
                    .block_number(hash.block_hash)
                    .map_err(provider_error)?
                    .ok_or_else(|| error(UNSUPPORTED_CODE, format!("unknown block {}", hash.block_hash)))?;
                match self.header(number)? {
                    Some((canonical, _, _)) if canonical == hash.block_hash => number,
                    _ => return Err(error(UNSUPPORTED_CODE, format!("block {} is not canonical", hash.block_hash))),
                }
            }
            BlockId::Number(BlockNumberOrTag::Number(number)) => number,
            BlockId::Number(BlockNumberOrTag::Earliest) => earliest,
            BlockId::Number(_) => {
                // The newest block whose root a persisted header carries.
                let top = latest.min(persisted);
                let mut found = None;
                for number in (top.saturating_sub(2)..=top).rev() {
                    if number >= earliest && self.anchor(number, persisted)?.is_some() {
                        found = Some(number);
                        break;
                    }
                }
                found.ok_or_else(|| error(NOT_YET_CODE, "no persisted block is provable yet"))?
            }
        };
        if number > persisted {
            return Err(error(NOT_YET_CODE, format!("block {number} is not persisted yet (persisted head {persisted})")));
        }
        let (hash, _, _) = self.header(number)?.ok_or_else(|| error(NOT_YET_CODE, format!("no canonical header at {number}")))?;
        Ok((number, hash))
    }

    /// What [`QmdbProofApiServer::proof_window`] reports.
    pub fn window(&self) -> Result<QmdbProofWindow, ErrorObjectOwned> {
        let Some(history) = self.state.history() else {
            return Ok(QmdbProofWindow { history: false, mode: "off".into(), earliest: None, latest: None, broken: None });
        };
        let (earliest, latest) = history.range();
        let persisted = (self.persisted)().unwrap_or(0);
        let top = latest.min(persisted);
        let mut provable = None;
        for number in (top.saturating_sub(2)..=top).rev() {
            if number >= earliest && self.anchor(number, persisted)?.is_some() {
                provable = Some(U64::from(number));
                break;
            }
        }
        let mode = match history.mode() {
            n42_qmdb_reth::history::HistoryMode::Off => "off".to_owned(),
            n42_qmdb_reth::history::HistoryMode::All => "all".to_owned(),
            n42_qmdb_reth::history::HistoryMode::Keep(n) => n.to_string(),
        };
        Ok(QmdbProofWindow {
            history: true,
            mode,
            earliest: provable.map(|_| U64::from(earliest)),
            latest: provable,
            broken: history.broken(),
        })
    }

    /// The whole request, on a blocking thread.
    pub fn prove(&self, address: Address, storage_keys: &[B256], block: Option<BlockId>) -> Result<QmdbAccountProof, ErrorObjectOwned> {
        if storage_keys.len() > MAX_STORAGE_KEYS {
            return Err(error(UNSUPPORTED_CODE, format!("at most {MAX_STORAGE_KEYS} storage keys a request")));
        }
        let persisted = (self.persisted)().ok_or_else(|| error(NOT_YET_CODE, "the database has persisted nothing yet"))?;
        let (number, hash) = self.resolve(block, persisted)?;
        let (anchor_number, anchor_hash, expected_root) = self
            .anchor(number, persisted)?
            .ok_or_else(|| error(NOT_YET_CODE, format!("no persisted header carries the state root of block {number} yet")))?;
        let mut keys = Vec::with_capacity(1 + storage_keys.len());
        keys.push(gov5_account_key(&address.0 .0));
        keys.extend(storage_keys.iter().map(|slot| gov5_storage_key(&address.0 .0, &slot.0)));
        let proved = self.state.prove_historical((number, hash), expected_root, &keys).map_err(history_error)?;
        let account = key_proof(&proved.keys[0])?;
        let storage_proof = storage_keys
            .iter()
            .zip(&proved.keys[1..])
            .map(|(slot, answer)| Ok(QmdbStorageProof { slot: *slot, proof: key_proof(answer)? }))
            .collect::<Result<Vec<_>, ErrorObjectOwned>>()?;
        Ok(QmdbAccountProof {
            block_number: U64::from(number),
            block_hash: hash,
            state_root: proved.root,
            anchor_number: U64::from(anchor_number),
            anchor_hash,
            address,
            account,
            storage_proof,
            proof_format: PROOF_FORMAT.to_owned(),
        })
    }
}

#[jsonrpsee::core::async_trait]
impl<Provider> QmdbProofApiServer for QmdbProofExt<Provider>
where
    Provider: HeaderProvider + BlockNumReader + Clone + Send + Sync + 'static,
    Provider::Header: BlockHeader,
{
    async fn get_proof(&self, address: Address, storage_keys: Vec<B256>, block: Option<BlockId>) -> RpcResult<QmdbAccountProof> {
        let this = Self {
            state: self.state.clone(),
            provider: self.provider.clone(),
            root_offset: self.root_offset.clone(),
            persisted: self.persisted.clone(),
        };
        tokio::task::spawn_blocking(move || this.prove(address, &storage_keys, block))
            .await
            .map_err(|e| error(INTERNAL_CODE, e.to_string()))?
    }

    fn proof_window(&self) -> RpcResult<QmdbProofWindow> {
        self.window()
    }
}

/// The `eth_getProof` a QMDB chain answers with: a refusal naming
/// `n42_getProof`. The Merkle-Patricia trie is not maintained on a QMDB chain
/// (`n42_qmdb_reth::strategy`), so its proofs would not verify against any
/// header's state root.
pub fn eth_get_proof_refusal() -> jsonrpsee::RpcModule<()> {
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_method("eth_getProof", |_, _, _| -> Result<(), ErrorObjectOwned> {
            Err(error(
                UNSUPPORTED_CODE,
                "eth_getProof is not served on a QMDB chain: the Merkle-Patricia trie is not maintained and its proofs \
                 would not verify against the header's state root; use n42_getProof (QMDB twig proofs, gov5 v2 layout)",
            ))
        })
        .expect("one method on a fresh module");
    module
}
