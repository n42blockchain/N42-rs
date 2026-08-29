// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's EVM configuration: reth's Ethereum one, with every block
//! executor watched for the writes gov5 records and revm forgets, and every
//! EVM refusing the one thing it cannot execute the way gov5 does.
//!
//! **Restored slots.** gov5 commits a block's state to QMDB by writing every
//! dirty account and storage slot of the block — dirty meaning written, not
//! changed. A slot that one transaction moves and a later one moves back is
//! dirty with its original value, and gov5 writes it
//! (`BufferedPlainStateWriter`, which refuses to short-circuit on
//! `original == value`); QMDB appends a fresh slot for the key and the root
//! moves. revm's bundle, which is all reth hands the state-root job, drops
//! exactly that slot (`TransitionAccount::update`). Every transaction's
//! result passes through here before it is committed, so the slots each one
//! changes are seen with their values at the start of that transaction; the
//! first sighting of a slot in a block is its value at the block's start,
//! and that is the value gov5 rewrites when the slot ends up back there. The
//! root job looks them up by parent hash and transaction hashes.
//!
//! The same within one transaction: gov5's `stateObject.SetState` marks a
//! slot dirty on the first `SSTORE` of a value other than the one it holds,
//! and the mark survives a later store of the old value and the revert of
//! the frame that stored (`storageChange.revert` calls `setState`, which
//! keeps the key in `dirtyKeys`). revm reports such a transaction's net
//! effect, in which the slot is unchanged. So every `SSTORE` that succeeds is
//! recorded as it executes (the instruction table's `SSTORE` entry is
//! wrapped), and a slot some store moved off its value at the transaction's
//! start is filed like a changed one, with that value.
//!
//! **EOF.** Chain 94 runs with gov5's `eofTime` active: an EOF container
//! (`0xEF00`-prefixed code) is executed as EOF there — an initcode
//! container by a creation, a deployed one by a call — while revm has no
//! EOF at all and would run the same bytes as legacy code, halting on the
//! `0xEF` byte. The instruction table's entry for opcode `0xEF` is replaced
//! with one that, when the frame's code is a container, records the frame
//! before halting as revm would; a transaction that recorded one fails the
//! block with [`EofRequired`], which is logged at error level with the
//! block, the transaction and the address, and counted in
//! `n42_evm_eof_required_total`. Refusing the block keeps this node from
//! voting for, or proposing, state it cannot compute. Not caught: code
//! inspected but not executed (`EXTCODESIZE` of an EOF contract answers
//! differently under EOF rules) — no EOF code exists on chain 94.
//!
//! **Transaction gas cap.** revm enforces EIP-7825 (a 2^24 gas limit per
//! transaction) once Osaka is active; gov5 has the check but calls it only
//! from its Engine API payload validator, never on the chain it produces
//! and validates itself. On a gov5 chain the cap is lifted here — the block
//! gas limit is the only bound, as it is for gov5.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    convert::Infallible,
    sync::Arc,
};

use alloy_consensus::{transaction::TxHashRef, Header};
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        ExecutableTx, GasOutput, StateDB, TxResult,
    },
    eth::{EthBlockExecutionCtx, EthBlockExecutorFactory, EthEvm, EthEvmContext, EthEvmFactory},
    precompiles::PrecompilesMap,
    Database, EvmEnv, EvmFactory, RecoveredTx,
};
use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_engine::ExecutionData;
use n42_qmdb_reth::{record_restored_slots, restored_slots_key, RestoredSlot};
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::{Block, EthPrimitives};
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
    NextBlockEnvAttributes,
};
use reth_evm_ethereum::{EthEvmConfig, RethReceiptBuilder};
use reth_primitives_traits::{SealedBlock, SealedHeader, SignedTransaction};
use revm::{
    bytecode::opcode,
    context::{
        result::{EVMError, HaltReason},
        BlockEnv, TxEnv,
    },
    database_interface::DBErrorMarker,
    inspector::NoOpInspector,
    interpreter::{
        instructions::{control, host},
        interpreter::EthInterpreter,
        interpreter_types::{InputsTr, LegacyBytecode, StackTr},
        Host, Instruction, InstructionContext, InstructionExecResult,
    },
    primitives::hardfork::SpecId,
    Inspector,
};

use crate::consensus::is_gov5_chain;

/// The metric counting transactions refused because they execute EOF.
pub const EOF_REQUIRED_METRIC: &str = "n42_evm_eof_required_total";

/// reth's Ethereum EVM configuration with the tracking executor factory.
#[derive(Clone, Debug)]
pub struct N42EvmConfig {
    inner: EthEvmConfig,
    factory: TrackingBlockExecutorFactory,
    /// Whether the EIP-7825 transaction gas cap is lifted: on a gov5 chain
    /// the block gas limit is the only bound gov5 applies.
    lift_tx_gas_cap: bool,
}

impl N42EvmConfig {
    /// The configuration for `chain_spec`.
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        let lift_tx_gas_cap = is_gov5_chain(&chain_spec);
        let inner = EthEvmConfig::new(chain_spec);
        let factory = TrackingBlockExecutorFactory {
            inner: inner.block_executor_factory().clone(),
            evm_factory: EofGuardEvmFactory,
        };
        Self { inner, factory, lift_tx_gas_cap }
    }

    /// The chain.
    pub fn chain_spec(&self) -> &Arc<ChainSpec> {
        self.inner.chain_spec()
    }

    /// Whether transactions above EIP-7825's cap are executed, as gov5
    /// executes them.
    pub const fn lifts_tx_gas_cap(&self) -> bool {
        self.lift_tx_gas_cap
    }

    /// An environment with the chain's bounds rather than Ethereum's.
    fn align(&self, mut env: EvmEnv<SpecId>) -> EvmEnv<SpecId> {
        if self.lift_tx_gas_cap {
            env.cfg_env.tx_gas_limit_cap = Some(u64::MAX);
        }
        env
    }
}

impl ConfigureEvm for N42EvmConfig {
    type Primitives = EthPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = TrackingBlockExecutorFactory;
    type BlockAssembler = <EthEvmConfig as ConfigureEvm>::BlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env(header).map(|env| self.align(env))
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.next_evm_env(parent, attributes).map(|env| self.align(env))
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<Header>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<ExecutionCtxFor<'_, Self>, Self::Error> {
        self.inner.context_for_next_block(parent, attributes)
    }
}

impl ConfigureEngineEvm<ExecutionData> for N42EvmConfig {
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env_for_payload(payload).map(|env| self.align(env))
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        self.inner.context_for_payload(payload)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        self.inner.tx_iterator_for_payload(payload)
    }
}

// ---------------------------------------------------------------------------
// What the instructions see, per thread and per transaction.
// ---------------------------------------------------------------------------

/// What an EOF sighting was executing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EofFrame {
    /// The initcode of a creation — a transaction's or a `CREATE`'s.
    Initcode,
    /// Code deployed at, or delegated to by, the called account.
    Code,
}

impl std::fmt::Display for EofFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Initcode => "initcode",
            Self::Code => "code",
        })
    }
}

/// A frame that started executing an EOF container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EofSighting {
    /// The account whose storage the frame runs against: the created
    /// address for initcode, the called account for code.
    pub address: Address,
    /// What the container was.
    pub frame: EofFrame,
    /// The container's length in bytes.
    pub len: usize,
}

/// What the wrapped instructions recorded while a transaction ran.
#[derive(Debug, Default)]
struct TxSightings {
    /// The first EOF container a frame started executing, if any.
    eof: Option<EofSighting>,
    /// Every `SSTORE` that succeeded: the account, the slot, the value.
    sstores: Vec<(Address, U256, U256)>,
}

thread_local! {
    /// The instructions run on the executor's thread and have no other way
    /// to reach it; the executor clears this before every transaction and
    /// takes it after. Other threads executing the same transactions (the
    /// engine's prewarming) fill their own copy, which nothing reads.
    static SIGHTINGS: RefCell<TxSightings> = RefCell::new(TxSightings::default());
}

/// Opcode `0xEF`: no instruction in legacy code. When the frame's code is an
/// EOF container — which starts with `0xEF 0x00` and is therefore executing
/// this byte first — note the frame, then halt as revm halts.
fn eof_guard<H: Host + ?Sized>(ctx: InstructionContext<'_, H, EthInterpreter>) -> InstructionExecResult {
    let code = ctx.interpreter.bytecode.bytecode_slice();
    if is_eof_container(code) {
        let sighting = EofSighting {
            address: ctx.interpreter.input.target_address(),
            frame: if ctx.interpreter.input.bytecode_address().is_none() {
                EofFrame::Initcode
            } else {
                EofFrame::Code
            },
            len: code.len(),
        };
        SIGHTINGS.with(|sightings| {
            sightings.borrow_mut().eof.get_or_insert(sighting);
        });
    }
    control::unknown(ctx)
}

/// `SSTORE`, recorded when it succeeds: gov5 marks the slot dirty on the
/// store, whatever the transaction's net effect turns out to be.
fn recording_sstore<H: Host + ?Sized>(ctx: InstructionContext<'_, H, EthInterpreter>) -> InstructionExecResult {
    let store = match ctx.interpreter.stack.data().as_slice() {
        [.., value, key] => Some((ctx.interpreter.input.target_address(), *key, *value)),
        _ => None,
    };
    let result = host::sstore(ctx);
    if result.is_ok() {
        if let Some(store) = store {
            SIGHTINGS.with(|sightings| sightings.borrow_mut().sstores.push(store));
        }
    }
    result
}

/// Whether `code` is an EOF container: the EIP-3540 magic, `0xEF 0x00`.
pub fn is_eof_container(code: &[u8]) -> bool {
    code.starts_with(&[0xEF, 0x00])
}

/// reth's Ethereum EVM factory, with the instruction table watched: see the
/// module documentation.
#[derive(Clone, Copy, Debug, Default)]
pub struct EofGuardEvmFactory;

impl EofGuardEvmFactory {
    fn watch<DB: Database, I>(evm: EthEvm<DB, I, PrecompilesMap>, inspect: bool) -> EthEvm<DB, I, PrecompilesMap> {
        let mut inner = evm.into_inner();
        let sstore_gas = inner.instruction.gas_table()[opcode::SSTORE as usize];
        inner.instruction.insert_instruction(0xEF, Instruction::new(eof_guard), 0);
        inner.instruction.insert_instruction(opcode::SSTORE, Instruction::new(recording_sstore), sstore_gas);
        EthEvm::new(inner, inspect)
    }
}

impl EvmFactory for EofGuardEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>>> = EthEvm<DB, I, PrecompilesMap>;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Tx = TxEnv;
    type Error<DBError: DBErrorMarker> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        Self::watch(EthEvmFactory::default().create_evm(db, input), false)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        Self::watch(EthEvmFactory::default().create_evm_with_inspector(db, input, inspector), true)
    }
}

// ---------------------------------------------------------------------------
// The block executor.
// ---------------------------------------------------------------------------

/// reth's Ethereum block executor factory.
type EthFactory = EthBlockExecutorFactory<RethReceiptBuilder, Arc<ChainSpec>, EthEvmFactory>;

/// A block executor factory whose executors record restored slots and refuse
/// EOF.
#[derive(Clone, Debug)]
pub struct TrackingBlockExecutorFactory {
    inner: EthFactory,
    evm_factory: EofGuardEvmFactory,
}

impl BlockExecutorFactory for TrackingBlockExecutorFactory {
    type EvmFactory = EofGuardEvmFactory;
    type TxExecutionResult = <EthFactory as BlockExecutorFactory>::TxExecutionResult;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = <EthFactory as BlockExecutorFactory>::Transaction;
    type Receipt = <EthFactory as BlockExecutorFactory>::Receipt;
    type Executor<'a, DB: StateDB, I: Inspector<EthEvmContext<DB>>> =
        TrackingExecutor<<EthFactory as BlockExecutorFactory>::Executor<'a, DB, I>>;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EthEvm<DB, I, PrecompilesMap>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I>
    where
        DB: StateDB,
        I: Inspector<EthEvmContext<DB>>,
    {
        let parent_hash = ctx.parent_hash;
        TrackingExecutor {
            inner: self.inner.create_executor(evm, ctx),
            parent_hash,
            tx_hashes: Vec::new(),
            first_seen: HashMap::new(),
            pending: None,
        }
    }
}

/// A transaction that executes an EOF container, which this node cannot
/// execute the way gov5 does. The block that carries it is refused.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "EOF_REQUIRED: block {block} transaction {tx} executes an EOF container \
     ({frame}, {len} bytes, magic 0xEF00) at {address}; revm has no EOF and \
     would diverge from gov5, so the block is refused"
)]
pub struct EofRequired {
    /// The block.
    pub block: u64,
    /// The transaction.
    pub tx: B256,
    /// The account the frame ran against.
    pub address: Address,
    /// What the container was.
    pub frame: EofFrame,
    /// The container's length.
    pub len: usize,
}

/// A block executor that notes, for every slot a transaction changes — or
/// stores to and restores — the value the slot had when the block began,
/// files the block's list at the end, and refuses a transaction that
/// executes EOF.
#[derive(Debug)]
pub struct TrackingExecutor<E> {
    inner: E,
    parent_hash: B256,
    /// The committed transactions, in order.
    tx_hashes: Vec<B256>,
    /// Each slot changed so far, with its value at the block's start.
    first_seen: HashMap<(Address, U256), U256>,
    /// The transaction executed but not yet committed: its hash and the
    /// slots it changed, with their values before it ran.
    pending: Option<(B256, Vec<RestoredSlot>)>,
}

impl<E> BlockExecutor for TrackingExecutor<E>
where
    E: BlockExecutor,
    E::Transaction: SignedTransaction + TxHashRef,
{
    type Transaction = E::Transaction;
    type Receipt = E::Receipt;
    type Evm = E::Evm;
    type Result = E::Result;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<Self::Result, BlockExecutionError> {
        let (tx_env, recovered) = tx.into_parts();
        let hash = *recovered.tx().tx_hash();
        SIGHTINGS.with(|sightings| *sightings.borrow_mut() = TxSightings::default());
        let result = self.inner.execute_transaction_without_commit((tx_env, recovered))?;
        let TxSightings { eof, sstores } = SIGHTINGS.with(|sightings| std::mem::take(&mut *sightings.borrow_mut()));

        if let Some(sighting) = eof {
            let block: u64 = revm::context::Block::number(alloy_evm::Evm::block(self.inner.evm())).saturating_to();
            let error = EofRequired {
                block,
                tx: hash,
                address: sighting.address,
                frame: sighting.frame,
                len: sighting.len,
            };
            tracing::error!(target: "n42::evm", %error, "EOF_REQUIRED: refusing the block");
            metrics::counter!(EOF_REQUIRED_METRIC).increment(1);
            return Err(BlockExecutionError::other(error));
        }

        // Every slot this transaction changed, with the value it saw at its
        // start — the state it was loaded from, which is the block's start
        // for the first transaction to touch it.
        let state = &result.result().state;
        let mut changed = Vec::new();
        let mut listed = HashSet::new();
        for (address, account) in state {
            if account.is_selfdestructed() {
                continue;
            }
            for (slot, value) in &account.storage {
                if value.is_changed() {
                    changed.push((*address, *slot, value.original_value()));
                    listed.insert((*address, *slot));
                }
            }
        }
        // And every slot a store moved off that value, whatever it holds
        // now: dirty in gov5's journal, unchanged in revm's report.
        for (address, slot, written) in sstores {
            if listed.contains(&(address, slot)) {
                continue;
            }
            let Some(account) = state.get(&address) else {
                continue;
            };
            if account.is_selfdestructed() {
                continue;
            }
            let Some(entry) = account.storage.get(&slot) else {
                tracing::warn!(target: "n42::evm", %address, %slot, tx = %hash, "a stored slot is missing from the transaction's state");
                continue;
            };
            if written != entry.original_value() {
                changed.push((address, slot, entry.original_value()));
                listed.insert((address, slot));
            }
        }
        self.pending = Some((hash, changed));
        Ok(result)
    }

    fn commit_transaction(&mut self, output: Self::Result) -> GasOutput {
        if let Some((hash, changed)) = self.pending.take() {
            self.tx_hashes.push(hash);
            for (address, slot, original) in changed {
                self.first_seen.entry((address, slot)).or_insert(original);
            }
        }
        self.inner.commit_transaction(output)
    }

    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        // Filed whole; the root job keeps the ones the bundle lost.
        let mut restored: Vec<RestoredSlot> = self
            .first_seen
            .into_iter()
            .map(|((address, slot), original)| (address, slot, original))
            .collect();
        restored.sort_unstable();
        record_restored_slots(restored_slots_key(self.parent_hash, self.tx_hashes.iter().copied()), restored);
        self.inner.finish()
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }

    fn receipts(&self) -> &[Self::Receipt] {
        self.inner.receipts()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{transaction::TxHashRef, Header, Transaction as _, TxLegacy};
    use alloy_genesis::Genesis;
    use alloy_primitives::{address, bytes, Bytes, Signature, TxKind};
    use reth_chainspec::{ChainSpec, EthChainSpec};
    use reth_ethereum_primitives::{BlockBody, TransactionSigned};
    use reth_evm::execute::Executor;
    use reth_primitives_traits::{Block as _, RecoveredBlock};
    use revm::{
        database::{CacheDB, EmptyDB, State},
        state::{AccountInfo, Bytecode},
    };

    const SENDER: Address = address!("0x1000000000000000000000000000000000000001");
    const CONTRACT: Address = address!("0x2000000000000000000000000000000000000002");
    const CHILD: Address = address!("0x3000000000000000000000000000000000000003");
    const PARENT_HASH: B256 = B256::repeat_byte(0x42);
    const SLOT: U256 = U256::from_limbs([1, 0, 0, 0]);

    /// A gov5-shaped chain with every fork, Osaka and EOF included, live
    /// from genesis; the validator set is chain 94's slot 6.
    fn gov5_chain() -> Arc<ChainSpec> {
        let genesis: Genesis = serde_json::from_str(
            r#"{
                "config": {
                    "chainId": 94, "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0,
                    "byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0, "istanbulBlock": 0,
                    "berlinBlock": 0, "londonBlock": 0, "mergeNetsplitBlock": 0, "terminalTotalDifficulty": 0,
                    "terminalTotalDifficultyPassed": true,
                    "shanghaiTime": 0, "cancunTime": 0, "pragueTime": 0, "osakaTime": 0,
                    "consensus": "hotstuff",
                    "hotstuff": { "validators": [ { "address": "0x1ccde065f222f44709797be2908fc72b7801eda5",
                        "blsKey": "0x9825e1ffc2471f5946445de41ee5dfe0d55eaaf7e48c04bbf5f70888d21dea121d044373459424cc44b895c89b18681a" } ] }
                },
                "alloc": {},
                "difficulty": "0x0", "gasLimit": "0x1c9c380", "timestamp": "0x0", "extraData": "0x", "nonce": "0x0",
                "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "coinbase": "0x0000000000000000000000000000000000000000", "number": "0x0", "gasUsed": "0x0",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }"#,
        )
        .unwrap();
        Arc::new(genesis.into())
    }

    /// The same chain under the `interopV4` profile: not gov5's.
    fn interop_chain() -> Arc<ChainSpec> {
        let mut genesis = gov5_chain().genesis().clone();
        let mut hotstuff: serde_json::Value = genesis.config.extra_fields.get_deserialized("hotstuff").unwrap().unwrap();
        hotstuff["interopV4"] = serde_json::Value::Bool(true);
        genesis.config.extra_fields.insert("hotstuff".into(), hotstuff);
        Arc::new(genesis.into())
    }

    fn header() -> Header {
        Header {
            parent_hash: PARENT_HASH,
            number: 1,
            timestamp: 1_800_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals_root: Some(alloy_consensus::constants::EMPTY_WITHDRAWALS),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            ..Default::default()
        }
    }

    /// A block of one transaction. `nonce` keeps the transactions of the
    /// tests apart: the restored-slot registry is global and keyed by
    /// transaction hash, and the tests run in parallel.
    fn block_with(nonce: u64, to: TxKind, input: Bytes) -> RecoveredBlock<Block> {
        let tx = TransactionSigned::new_unhashed(
            reth_ethereum_primitives::Transaction::Legacy(TxLegacy {
                chain_id: None,
                nonce,
                gas_price: 0,
                gas_limit: 1_000_000,
                to,
                value: U256::ZERO,
                input,
            }),
            Signature::test_signature(),
        );
        let body = BlockBody {
            transactions: vec![tx],
            ommers: vec![],
            withdrawals: Some(Default::default()),
        };
        RecoveredBlock::new_unhashed(Block::new(header(), body), vec![SENDER])
    }

    fn contract(code: Bytes) -> AccountInfo {
        let bytecode = Bytecode::new_raw(code);
        AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: bytecode.hash_slow(),
            code: Some(bytecode),
            ..Default::default()
        }
    }

    /// Executes `block` against a state with `accounts` and their storage.
    fn execute(
        chain: Arc<ChainSpec>,
        accounts: Vec<(Address, AccountInfo, Vec<(U256, U256)>)>,
        block: &RecoveredBlock<Block>,
    ) -> Result<(), BlockExecutionError> {
        let mut cache = CacheDB::new(EmptyDB::default());
        let nonce = block.body().transactions[0].nonce();
        cache.insert_account_info(SENDER, AccountInfo { balance: U256::from(1u64 << 60), nonce, ..Default::default() });
        for (address, info, storage) in accounts {
            cache.insert_account_info(address, info);
            for (slot, value) in storage {
                cache.insert_account_storage(address, slot, value).unwrap();
            }
        }
        let mut state = State::builder().with_database(cache).with_bundle_update().build();
        let config = N42EvmConfig::new(chain);
        config.executor(&mut state).execute_one(block).map(|_| ())
    }

    fn restored_for(block: &RecoveredBlock<Block>) -> Vec<RestoredSlot> {
        let key = restored_slots_key(PARENT_HASH, block.body().transactions.iter().map(|tx| *tx.tx_hash()));
        n42_qmdb_reth::restored_slots(key).map(|slots| slots.to_vec()).unwrap_or_default()
    }

    #[test]
    fn a_creation_with_eof_initcode_is_refused_loudly() {
        // A minimal container: magic, version 1, a type section header.
        let block = block_with(1, TxKind::Create, bytes!("ef0001010004020001000104000000008000000000"));
        let error = execute(gov5_chain(), vec![], &block).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("EOF_REQUIRED"), "{message}");
        assert!(message.contains("block 1"), "{message}");
        assert!(message.contains(&format!("{}", block.body().transactions[0].tx_hash())), "{message}");
        assert!(message.contains("initcode"), "{message}");
    }

    #[test]
    fn calling_deployed_eof_code_is_refused_and_names_the_account() {
        let block = block_with(2, TxKind::Call(CONTRACT), Bytes::new());
        let error = execute(gov5_chain(), vec![(CONTRACT, contract(bytes!("ef00010100040200010001040000000080000000fe")), vec![])], &block)
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("EOF_REQUIRED"), "{message}");
        assert!(message.contains(&format!("{CONTRACT}")), "{message}");
        assert!(message.contains("code, 21 bytes"), "{message}");
    }

    #[test]
    fn a_stray_ef_byte_in_legacy_code_is_only_an_invalid_opcode() {
        // `0xEF 0x01`: not a container (that is EIP-7702's designator
        // prefix); revm halts on it and so does gov5, and the block stands.
        let block = block_with(3, TxKind::Create, bytes!("ef01"));
        execute(gov5_chain(), vec![], &block).unwrap();
        let block = block_with(4, TxKind::Call(CONTRACT), Bytes::new());
        execute(gov5_chain(), vec![(CONTRACT, contract(bytes!("600060ef")), vec![])], &block).unwrap();
    }

    #[test]
    fn a_slot_stored_and_restored_within_a_transaction_is_filed_with_its_value() {
        // SSTORE(1, 7); SSTORE(1, 5); STOP — the slot held 5 at the start.
        let code = bytes!("6007600155600560015500");
        let block = block_with(5, TxKind::Call(CONTRACT), Bytes::new());
        execute(gov5_chain(), vec![(CONTRACT, contract(code), vec![(SLOT, U256::from(5))])], &block).unwrap();
        assert_eq!(restored_for(&block), vec![(CONTRACT, SLOT, U256::from(5))]);
    }

    #[test]
    fn a_store_of_the_value_the_slot_holds_is_not_dirty() {
        // SSTORE(1, 5); STOP — gov5's SetState returns before journaling.
        let code = bytes!("600560015500");
        let block = block_with(6, TxKind::Call(CONTRACT), Bytes::new());
        execute(gov5_chain(), vec![(CONTRACT, contract(code), vec![(SLOT, U256::from(5))])], &block).unwrap();
        assert_eq!(restored_for(&block), vec![]);
    }

    #[test]
    fn a_store_in_a_reverted_frame_still_dirties_the_slot() {
        // Parent: CALL(child) with no value, POP, STOP.
        // Child: SSTORE(1, 7); REVERT(0, 0) — the store is undone, the
        // mark in gov5's journal is not.
        let parent = Bytes::from(
            [
                &[0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73][..],
                CHILD.as_slice(),
                &[0x61, 0xff, 0xff, 0xf1, 0x50, 0x00][..],
            ]
            .concat(),
        );
        let child = bytes!("600760015560006000fd");
        let block = block_with(7, TxKind::Call(CONTRACT), Bytes::new());
        execute(
            gov5_chain(),
            vec![(CONTRACT, contract(parent), vec![]), (CHILD, contract(child), vec![(SLOT, U256::from(5))])],
            &block,
        )
        .unwrap();
        assert_eq!(restored_for(&block), vec![(CHILD, SLOT, U256::from(5))]);
    }

    #[test]
    fn a_changed_slot_is_filed_once_with_the_value_before_the_transaction() {
        // SSTORE(1, 7); STOP — changed, listed by the bundle path.
        let code = bytes!("600760015500");
        let block = block_with(8, TxKind::Call(CONTRACT), Bytes::new());
        execute(gov5_chain(), vec![(CONTRACT, contract(code), vec![(SLOT, U256::from(5))])], &block).unwrap();
        assert_eq!(restored_for(&block), vec![(CONTRACT, SLOT, U256::from(5))]);
    }

    #[test]
    fn the_transaction_gas_cap_is_lifted_on_a_gov5_chain_only() {
        let gov5 = N42EvmConfig::new(gov5_chain());
        assert!(gov5.lifts_tx_gas_cap());
        let env = gov5.evm_env(&header()).unwrap();
        assert_eq!(env.cfg_env.tx_gas_limit_cap, Some(u64::MAX));
        assert_eq!(revm::context::Cfg::tx_gas_limit_cap(&env.cfg_env), u64::MAX);

        let interop = N42EvmConfig::new(interop_chain());
        assert!(!interop.lifts_tx_gas_cap());
        let env = interop.evm_env(&header()).unwrap();
        assert_eq!(env.cfg_env.tx_gas_limit_cap, Some(alloy_eips::eip7825::MAX_TX_GAS_LIMIT_OSAKA));
    }

    #[test]
    fn a_transaction_above_the_eip7825_cap_executes_on_a_gov5_chain() {
        let tx = TransactionSigned::new_unhashed(
            reth_ethereum_primitives::Transaction::Legacy(TxLegacy {
                chain_id: None,
                nonce: 9,
                gas_price: 0,
                gas_limit: 20_000_000,
                to: TxKind::Call(CONTRACT),
                value: U256::ZERO,
                input: Bytes::new(),
            }),
            Signature::test_signature(),
        );
        assert!(tx.gas_limit() > alloy_eips::eip7825::MAX_TX_GAS_LIMIT_OSAKA);
        let body = BlockBody { transactions: vec![tx], ommers: vec![], withdrawals: Some(Default::default()) };
        let block = RecoveredBlock::new_unhashed(Block::new(header(), body), vec![SENDER]);
        let accounts = || vec![(CONTRACT, contract(bytes!("00")), vec![])];
        execute(gov5_chain(), accounts(), &block).unwrap();
        let error = execute(interop_chain(), accounts(), &block).unwrap_err().to_string();
        assert!(error.contains("cap") || error.contains("Cap"), "{error}");
    }

    #[test]
    fn is_eof_container_wants_the_two_byte_magic() {
        assert!(is_eof_container(&[0xEF, 0x00]));
        assert!(is_eof_container(&[0xEF, 0x00, 0x01]));
        assert!(!is_eof_container(&[0xEF, 0x01, 0x00]));
        assert!(!is_eof_container(&[0xEF]));
        assert!(!is_eof_container(&[]));
    }
}
