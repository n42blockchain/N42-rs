//! N42: tests of the persistence switches in `providers::n42_persist`
//! (`N42_PERSIST_QMDB_IN_SCOPE`, `N42_ACCOUNT_HISTORY`).

use super::*;
use crate::{
    providers::n42_persist, test_utils::create_test_provider_factory, DatabaseProviderFactory,
    ProviderFactory, RocksDBProviderFactory, StaticFileProviderFactory,
};
use alloy_consensus::Header;
use alloy_primitives::{
    map::{FbBuildHasher, HashMap},
    U256,
};
use reth_chain_state::ExecutedBlock;
use reth_db_api::models::StorageSettings;
use reth_execution_types::{BlockExecutionOutput, BlockExecutionResult};
use reth_primitives_traits::SealedBlock;
use reth_trie::{HashedPostState, KeccakKeyHasher, SortedTrieData};
use revm::{database::BundleState, state::AccountInfo};

type TestFactory = ProviderFactory<crate::test_utils::MockNodeTypesWithDB>;

/// Addresses the test chain touches.
const ACCOUNTS: u64 = 6;

fn address(k: u64) -> Address {
    Address::with_last_byte(0x40 + k as u8)
}

/// Whether account `k` changes in block `b`: account 0 in every block, account `k` every `k + 1`
/// blocks, and account 5 only from block 7 on (created inside a later batch).
fn changes(k: u64, b: u64) -> bool {
    if k == ACCOUNTS - 1 {
        return b >= 7 && b % 2 == 1
    }
    b % (k + 1) == 0
}

fn info(k: u64, b: u64) -> AccountInfo {
    AccountInfo { nonce: b, balance: U256::from(b * 1000 + k), ..Default::default() }
}

/// The account `k` after block `b` according to the schedule (`None` before its first change).
fn expected_after(k: u64, b: u64) -> Option<Account> {
    (1..=b).rev().find(|&x| changes(k, x)).map(|x| Account::from(info(k, x)))
}

fn empty_output(state: BundleState) -> Arc<BlockExecutionOutput<reth_ethereum_primitives::Receipt>> {
    Arc::new(BlockExecutionOutput {
        result: BlockExecutionResult {
            receipts: vec![],
            requests: Default::default(),
            gas_used: 0,
            blob_gas_used: 0,
        },
        state,
    })
}

/// A v2 factory with block 0 saved (no state).
fn factory_with_genesis() -> TestFactory {
    let factory = create_test_provider_factory();
    factory.set_storage_settings_cache(StorageSettings::v2());
    let genesis = SealedBlock::<reth_ethereum_primitives::Block>::from_sealed_parts(
        SealedHeader::new(
            Header { number: 0, difficulty: U256::from(1), ..Default::default() },
            B256::ZERO,
        ),
        Default::default(),
    );
    let genesis: ExecutedBlock = ExecutedBlock::new(
        Arc::new(genesis.try_recover().expect("genesis recovers")),
        empty_output(Default::default()),
        ComputedTrieData::default(),
    );
    let provider_rw = factory.provider_rw().expect("provider_rw");
    provider_rw
        .save_blocks_inner(
            std::slice::from_ref(&genesis),
            std::slice::from_ref(&genesis),
            &[],
            None,
            SaveBlocksMode::Full,
        )
        .expect("genesis saved");
    provider_rw.commit().expect("genesis committed");
    factory
}

/// Blocks `1..=n` following the schedule, chained by parent hash.
fn chain(n: u64) -> Vec<ExecutedBlock> {
    let mut blocks = Vec::new();
    let mut parent_hash = B256::ZERO;
    for b in 1..=n {
        let mut builder = BundleState::builder(b..=b);
        for k in 0..ACCOUNTS {
            if !changes(k, b) {
                continue
            }
            let before = expected_after(k, b - 1).map(|account| AccountInfo {
                nonce: account.nonce,
                balance: account.balance,
                ..Default::default()
            });
            let storage: HashMap<U256, (U256, U256), FbBuildHasher<32>> = Default::default();
            builder = builder
                .state_present_account_info(address(k), info(k, b))
                .revert_account_info(b, address(k), Some(before))
                .state_storage(address(k), storage);
        }
        let bundle = builder.build();
        let hashed_state =
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle.state()).into_sorted();
        let header =
            Header { number: b, parent_hash, difficulty: U256::from(1), ..Default::default() };
        let block =
            SealedBlock::<reth_ethereum_primitives::Block>::seal_parts(header, Default::default());
        parent_hash = block.hash();
        blocks.push(ExecutedBlock::new(
            Arc::new(block.try_recover().expect("block recovers")),
            empty_output(bundle),
            ComputedTrieData {
                sorted: SortedTrieData::new(Arc::new(hashed_state), Default::default()),
            },
        ));
    }
    blocks
}

/// Saves `blocks[from..to]` (block numbers `from + 1..=to`) as one batch and commits it.
fn save_batch(factory: &TestFactory, blocks: &[ExecutedBlock], from: u64, to: u64) {
    let provider_rw = factory.provider_rw().expect("provider_rw");
    let input = SaveBlocksInput::new(blocks[from as usize..to as usize].to_vec(), from, from, to, to);
    provider_rw.save_blocks(&input).expect("save_blocks");
    provider_rw.commit().expect("commit");
}

/// Every `AccountsHistory` row, in key order.
fn account_history_rows(factory: &TestFactory) -> Vec<(Address, u64, Vec<u64>)> {
    let rocksdb = factory.rocksdb_provider();
    (0..ACCOUNTS)
        .flat_map(|k| {
            rocksdb
                .account_history_shards(address(k))
                .expect("shards")
                .into_iter()
                .map(move |(key, list)| (key.key, key.highest_block_number, list.iter().collect()))
        })
        .collect()
}

/// The account changesets of blocks `1..=n` from static files.
fn account_changesets(factory: &TestFactory, n: u64) -> Vec<(u64, Vec<(Address, Option<Account>)>)> {
    let sf = factory.static_file_provider();
    (1..=n)
        .map(|b| {
            let entries = sf
                .account_block_changeset(b)
                .expect("changeset")
                .into_iter()
                .map(|entry| (entry.address, entry.info))
                .collect();
            (b, entries)
        })
        .collect()
}

/// Every stage checkpoint row, including N42's.
fn checkpoints(factory: &TestFactory) -> Vec<(String, StageCheckpoint)> {
    factory.provider().expect("provider").get_all_checkpoints().expect("checkpoints")
}

/// The latest account as the database holds it (the hashed state).
fn latest_account(factory: &TestFactory, k: u64) -> Option<Account> {
    factory
        .provider()
        .expect("provider")
        .tx_ref()
        .get::<tables::HashedAccounts>(keccak256(address(k)))
        .expect("hashed account")
}

/// What a run leaves behind, as rows.
struct Run {
    factory: TestFactory,
    history: Vec<(Address, u64, Vec<u64>)>,
    changesets: Vec<(u64, Vec<(Address, Option<Account>)>)>,
    checkpoints: Vec<(String, StageCheckpoint)>,
}

/// Runs the chain `1..=10` in batches `1..=4`, `5..=7`, `8..=10` with `N42_PERSIST_QMDB_IN_SCOPE`
/// as given and `N42_ACCOUNT_HISTORY=off` per batch as given, on this thread.
fn run_chain(qmdb_in_scope: bool, account_history_off: [bool; 3]) -> Run {
    n42_persist::set_qmdb_in_scope_override(Some(qmdb_in_scope));
    let factory = factory_with_genesis();
    let blocks = chain(10);
    for ((from, to), off) in [(0, 4), (4, 7), (7, 10)].into_iter().zip(account_history_off) {
        n42_persist::set_account_history_off_override(Some(off));
        save_batch(&factory, &blocks, from, to);
    }
    n42_persist::set_qmdb_in_scope_override(None);
    n42_persist::set_account_history_off_override(None);
    let history = account_history_rows(&factory);
    let changesets = account_changesets(&factory, 10);
    let checkpoints = checkpoints(&factory);
    Run { factory, history, changesets, checkpoints }
}

const ON: [bool; 3] = [false; 3];
const OFF: [bool; 3] = [true; 3];
/// Off for the middle batch only: the gap opens at block 5 and `on` resumes at block 8.
const MIDDLE_OFF: [bool; 3] = [false, true, false];

fn gap_marker(checkpoints: &[(String, StageCheckpoint)]) -> Option<u64> {
    checkpoints
        .iter()
        .find(|(key, _)| key == n42_persist::ACCOUNT_HISTORY_GAP_KEY)
        .map(|(_, checkpoint)| checkpoint.block_number)
}

/// The account at the start of block `q` (after block `q - 1`) the way the historical state
/// provider resolves it: through `HistoryReader::account_history_info` and then the changeset or
/// the latest state.
fn historical_account(factory: &TestFactory, k: u64, q: u64) -> ProviderResult<Option<Account>> {
    let provider = factory.provider()?;
    Ok(match provider.account_history_info(address(k), q, None)? {
        HistoryInfo::NotYetWritten => None,
        HistoryInfo::InChangeset(block) => {
            provider
                .get_account_before_block(block, address(k))?
                .ok_or(ProviderError::AccountChangesetNotFound { block_number: block, address: address(k) })?
                .info
        }
        HistoryInfo::InPlainState | HistoryInfo::MaybeInPlainState => latest_account(factory, k),
    })
}

/// Every historical account read at `1..=tip` matches the schedule.
fn assert_history_exact(factory: &TestFactory, tip: u64) {
    for k in 0..ACCOUNTS {
        for q in 1..=tip {
            let read = historical_account(factory, k, q).expect("historical read");
            assert_eq!(read, expected_after(k, q - 1), "account {k} at block {q}");
        }
    }
}

#[test]
fn qmdb_in_scope_switch_writes_the_same_database() {
    for history_mode in [ON, MIDDLE_OFF] {
        let after = run_chain(false, history_mode);
        let beside = run_chain(true, history_mode);
        assert_eq!(after.history, beside.history);
        assert_eq!(after.changesets, beside.changesets);
        assert_eq!(after.checkpoints, beside.checkpoints);
        for k in 0..ACCOUNTS {
            assert_eq!(latest_account(&after.factory, k), latest_account(&beside.factory, k));
            assert_eq!(latest_account(&beside.factory, k), expected_after(k, 10));
        }
    }
}

#[test]
fn account_history_off_skips_only_the_index() {
    let on = run_chain(false, ON);
    let off = run_chain(false, OFF);

    assert!(!on.history.is_empty(), "on writes the index");
    assert!(off.history.is_empty(), "off writes no index entry");
    // The changesets (the rollback source) and the latest state are written exactly as before.
    assert_eq!(on.changesets, off.changesets);
    assert!(on.changesets.iter().all(|(_, entries)| !entries.is_empty()));
    for k in 0..ACCOUNTS {
        assert_eq!(latest_account(&on.factory, k), latest_account(&off.factory, k));
    }
    // Every stage checkpoint is the same (IndexAccountHistory included); off adds the marker.
    assert_eq!(gap_marker(&on.checkpoints), None);
    assert_eq!(gap_marker(&off.checkpoints), Some(1));
    let without_marker: Vec<_> = off
        .checkpoints
        .iter()
        .filter(|(key, _)| key != n42_persist::ACCOUNT_HISTORY_GAP_KEY)
        .cloned()
        .collect();
    assert_eq!(on.checkpoints, without_marker);

    // Off for the middle batch: the marker records its first block, the batches around it write
    // the index as before.
    let middle = run_chain(false, MIDDLE_OFF);
    assert_eq!(gap_marker(&middle.checkpoints), Some(5));
    assert_eq!(middle.changesets, on.changesets);
    let indexed: Vec<u64> = middle.history.iter().flat_map(|(_, _, blocks)| blocks.clone()).collect();
    assert!(indexed.iter().all(|b| !(5..=7).contains(b)), "no entry for the off batch: {indexed:?}");
    assert!(indexed.iter().any(|b| (8..=10).contains(b)), "on resumes writing: {indexed:?}");
}

#[test]
fn historical_account_reads_are_exact_with_the_index_off() {
    for history_mode in [ON, OFF, MIDDLE_OFF] {
        let run = run_chain(false, history_mode);
        assert_history_exact(&run.factory, 10);
    }
}

#[test]
fn historical_account_read_errors_rather_than_guess_when_the_scan_is_capped() {
    let run = run_chain(false, OFF);
    n42_persist::set_account_history_scan_max_override(Some(3));
    // Account 1 at block 2: the scan from block 2 finds its change at block 3 within the cap.
    let short = historical_account(&run.factory, 1, 2);
    // Account 4 at block 1: no change before block 5 would need more than three blocks.
    let long = historical_account(&run.factory, 4, 1);
    n42_persist::set_account_history_scan_max_override(None);
    assert_eq!(short.expect("short scan"), expected_after(1, 1));
    let message = long.expect_err("a capped scan is an error").to_string();
    assert!(message.contains("N42_ACCOUNT_HISTORY=off"), "{message}");
}

/// Lowers `IndexAccountHistory` to `checkpoint` and puts an index row above it for account 0,
/// the shape a crash between the static-file/RocksDB commit and the MDBX commit leaves.
fn crash_shape(factory: &TestFactory, checkpoint: u64, stale: &[u64]) {
    let provider_rw = factory.provider_rw().expect("provider_rw");
    provider_rw
        .save_stage_checkpoint(StageId::IndexAccountHistory, StageCheckpoint::new(checkpoint))
        .expect("checkpoint");
    provider_rw.commit().expect("commit");
    if !stale.is_empty() {
        factory
            .rocksdb_provider()
            .put::<tables::AccountsHistory>(
                ShardedKey::new(address(0), u64::MAX),
                &BlockNumberList::new(stale.iter().copied()).expect("list"),
            )
            .expect("stale row");
    }
}

#[test]
fn restart_with_the_index_off_unwinds_nothing() {
    // The ordinary restart: checkpoints agree with the static files, nothing to do.
    let off = run_chain(false, OFF);
    let provider = off.factory.database_provider_rw().expect("provider_rw");
    assert_eq!(off.factory.rocksdb_provider().check_consistency(&provider).expect("check"), None);
    drop(provider);

    // The crash shape inside the gap: the healer leaves the range alone and asks for no unwind.
    crash_shape(&off.factory, 7, &[8, 9]);
    let before = account_history_rows(&off.factory);
    let provider = off.factory.database_provider_rw().expect("provider_rw");
    assert_eq!(off.factory.rocksdb_provider().check_consistency(&provider).expect("check"), None);
    provider.commit().expect("commit");
    assert_eq!(account_history_rows(&off.factory), before, "nothing unwound inside the gap");
    assert_history_exact(&off.factory, 10);

    // The same shape without a gap is healed as before: entries above the checkpoint go.
    let on = run_chain(false, ON);
    crash_shape(&on.factory, 7, &[]);
    let provider = on.factory.database_provider_rw().expect("provider_rw");
    assert_eq!(on.factory.rocksdb_provider().check_consistency(&provider).expect("check"), None);
    provider.commit().expect("commit");
    let indexed: Vec<u64> =
        account_history_rows(&on.factory).into_iter().flat_map(|(_, _, blocks)| blocks).collect();
    assert!(indexed.iter().all(|b| *b <= 7), "on: entries above the checkpoint healed away");
}
