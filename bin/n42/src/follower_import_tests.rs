// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Branch tests for the follower import's helpers: the layers a child reads
//! its parent through, the waits for a parent, the stores of kept outputs and
//! shards, the late-made owned block, and the fork-to-spec mapping.
//!
//! The kept-output and kept-shards stores are process-wide queues that evict;
//! every test that writes to them takes [`publishing`] (the lock the parent
//! output tests use), and every hash here is unique to its test.

use super::parent_output_tests::publishing;
use super::*;
use alloy_primitives::U256;
use reth_provider::test_utils::MockEthProvider;
use reth_revm::db::BundleState;
use reth_revm::primitives::hardfork::SpecId;
use reth_revm::state::AccountInfo;

fn info(nonce: u64, balance: u64) -> AccountInfo {
    AccountInfo { nonce, balance: U256::from(balance), ..Default::default() }
}

fn bundle_of(accounts: &[(Address, Option<AccountInfo>)]) -> BundleState {
    BundleState::new(
        accounts.iter().map(|(address, after)| (*address, Some(info(0, 1)), after.clone(), Default::default())),
        Vec::<Vec<(Address, Option<Option<AccountInfo>>, Vec<(U256, U256)>)>>::new(),
        Vec::new(),
    )
}

fn output_of(accounts: &[(Address, Option<AccountInfo>)]) -> ParentOutput {
    Arc::new(reth_provider::BlockExecutionOutput { result: Default::default(), state: bundle_of(accounts) })
}

/// A sealed header unique to `tag`.
fn header(number: u64, parent: B256, tag: &str) -> reth_primitives_traits::SealedHeader {
    reth_primitives_traits::SealedHeader::seal_slow(alloy_consensus::Header {
        number,
        parent_hash: parent,
        extra_data: tag.as_bytes().to_vec().into(),
        ..Default::default()
    })
}

// --- ParentLayer ---------------------------------------------------------------

#[test]
fn a_merged_layer_answers_from_its_bundle_and_reports_code_one() {
    let (touched, gone, other) = (Address::with_last_byte(1), Address::with_last_byte(2), Address::with_last_byte(3));
    let layer = ParentLayer::Merged(output_of(&[(touched, Some(info(4, 40))), (gone, None)]));
    assert_eq!(layer.account(&touched).map(|a| (a.nonce, a.balance)), Some((4, U256::from(40))));
    assert_eq!(layer.account(&gone).map(|a| (a.nonce, a.balance)), Some((0, U256::ZERO)), "destroyed reads empty");
    assert!(layer.account(&other).is_none());
    assert_eq!(layer.code(), 1);
}

#[test]
fn a_shard_layer_answers_from_its_residual_and_leaves_the_rest_to_the_shards() {
    let (residual_account, other) = (Address::with_last_byte(5), Address::with_last_byte(6));
    let shards = Arc::new(n42_engine_types::output_shards::FrozenShards::default());
    let layer = ParentLayer::Shards(shards, output_of(&[(residual_account, Some(info(2, 20)))]));
    assert_eq!(layer.account(&residual_account).map(|a| (a.nonce, a.balance)), Some((2, U256::from(20))));
    assert!(layer.account(&other).is_none(), "neither the residual nor the (empty) shards touched it");
    assert_eq!(layer.code(), 2);
}

#[test]
fn the_parent_read_names_follow_the_layer_codes() {
    assert_eq!(parent_read_name(1), "merged");
    assert_eq!(parent_read_name(2), "shards");
    assert_eq!(parent_read_name(0), "engine");
    assert_eq!(parent_read_name(77), "engine");
}

// --- the kept stores -----------------------------------------------------------

fn keep(number: u64, parent: B256, tag: &str) -> reth_primitives_traits::SealedHeader {
    let header = header(number, parent, tag);
    keep_follower_shards(
        header.hash(),
        header.clone(),
        Arc::new(n42_engine_types::output_shards::FrozenShards::default()),
        output_of(&[]),
    );
    header
}

#[test]
fn only_the_last_two_blocks_keep_their_shards() {
    let _one_at_a_time = publishing();
    let a = keep(1, B256::ZERO, "shards-a");
    let b = keep(2, a.hash(), "shards-b");
    assert!(follower_shards_of(a.hash()).is_some());
    let c = keep(3, b.hash(), "shards-c");
    assert!(follower_shards_of(a.hash()).is_none(), "the oldest is evicted past {FOLLOWER_SHARDS_KEPT}");
    let (kept, layer) = follower_shards_of(b.hash()).expect("b is kept");
    assert_eq!(kept.hash(), b.hash());
    assert_eq!(layer.code(), 2);
    assert!(follower_shards_of(c.hash()).is_some());
    // Keeping a block again replaces its entry rather than costing a slot.
    keep_follower_shards(
        c.hash(),
        c,
        Arc::new(n42_engine_types::output_shards::FrozenShards::default()),
        output_of(&[]),
    );
    assert!(follower_shards_of(b.hash()).is_some());
    assert!(follower_shards_of(B256::repeat_byte(0xAA)).is_none());
}

#[test]
fn a_layer_is_the_blocks_shards_when_held_else_its_published_output() {
    let _one_at_a_time = publishing();
    let both = header(10, B256::ZERO, "layer-both");
    keep_follower_shards(
        both.hash(),
        both.clone(),
        Arc::new(n42_engine_types::output_shards::FrozenShards::default()),
        output_of(&[]),
    );
    publish_parent_output(both.hash(), both.clone(), output_of(&[]));
    assert_eq!(layer_of(both.hash()).expect("held").1.code(), 2, "shards win over the published output");

    let published_only = header(11, B256::ZERO, "layer-published");
    publish_parent_output(published_only.hash(), published_only.clone(), output_of(&[]));
    let (found, layer) = layer_of(published_only.hash()).expect("published");
    assert_eq!(found.hash(), published_only.hash());
    assert_eq!(layer.code(), 1);

    assert!(layer_of(B256::repeat_byte(0xAB)).is_none());
}

#[test]
fn publishing_an_output_again_replaces_it_and_old_ones_age_out() {
    let _one_at_a_time = publishing();
    let first = header(20, B256::ZERO, "pub-first");
    let again = output_of(&[(Address::with_last_byte(9), Some(info(1, 1)))]);
    publish_parent_output(first.hash(), first.clone(), output_of(&[]));
    publish_parent_output(first.hash(), first.clone(), Arc::clone(&again));
    let (_, kept) = published_output(first.hash()).expect("kept");
    assert!(Arc::ptr_eq(&kept, &again), "the second publication replaced the first");
    for n in 0..PARENT_OUTPUTS_KEPT as u64 {
        let later = header(21 + n, first.hash(), &format!("pub-later-{n}"));
        publish_parent_output(later.hash(), later, output_of(&[]));
    }
    assert!(published_output(first.hash()).is_none(), "aged out after {PARENT_OUTPUTS_KEPT} newer blocks");
}

// --- the waits -----------------------------------------------------------------

#[test]
fn a_wait_returns_what_is_already_there_without_waiting() {
    let started = std::time::Instant::now();
    let found = wait_for_layer_within(B256::ZERO, || false, std::time::Duration::from_secs(5), Some);
    assert_eq!(found, Some(B256::ZERO));
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn a_wait_ends_with_none_at_its_deadline() {
    let started = std::time::Instant::now();
    let wait = std::time::Duration::from_millis(80);
    let found = wait_for_layer_within(B256::ZERO, || false, wait, |_| None::<u8>);
    assert_eq!(found, None);
    assert!(started.elapsed() >= wait, "waited {:?}", started.elapsed());
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn a_wait_ends_at_once_when_the_parent_is_already_in_the_engine() {
    let started = std::time::Instant::now();
    let found = wait_for_layer_within(B256::ZERO, || true, std::time::Duration::from_secs(5), |_| None::<u8>);
    assert_eq!(found, None);
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn a_wait_is_woken_by_a_landing_and_finds_what_landed() {
    let landed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&landed);
    let found = std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(60));
            landed.store(true, std::sync::atomic::Ordering::SeqCst);
            note_import_landed();
        });
        wait_for_layer_within(
            B256::ZERO,
            || false,
            std::time::Duration::from_secs(5),
            move |_| flag.load(std::sync::atomic::Ordering::SeqCst).then_some(7u8),
        )
    });
    assert_eq!(found, Some(7));
}

#[test]
fn the_output_wait_finds_a_published_output_and_gives_up_without_one() {
    let _one_at_a_time = publishing();
    let block = header(30, B256::ZERO, "wait-output");
    publish_parent_output(block.hash(), block.clone(), output_of(&[]));
    let (found, _) = wait_for_output_within(block.hash(), || false, std::time::Duration::from_millis(50)).expect("published");
    assert_eq!(found.hash(), block.hash());
    assert!(wait_for_output_within(B256::repeat_byte(0xC1), || false, std::time::Duration::from_millis(30)).is_none());
}

#[test]
fn the_parents_fields_are_waited_for_until_both_halves_are_filed() {
    let parent = B256::repeat_byte(0xD1);
    n42_engine_types::executed_fields::remember_state_root(parent, B256::repeat_byte(1));
    let filer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(60));
        n42_engine_types::executed_fields::remember_receipts(parent, B256::repeat_byte(2), Default::default(), 21_000);
    });
    wait_for_parent_fields(parent).expect("the receipt half arrives");
    filer.join().unwrap();
    let fields = n42_engine_types::executed_fields::get(&parent).expect("complete");
    assert_eq!((fields.state_root, fields.receipts_root, fields.gas_used), (B256::repeat_byte(1), B256::repeat_byte(2), 21_000));
}

// --- the parent in the engine ----------------------------------------------------

fn deferred_genesis(at: u64) -> alloy_genesis::Genesis {
    let mut genesis = alloy_genesis::Genesis::default();
    genesis.config.extra_fields.insert("deferredExecutionTime".to_owned(), serde_json::json!(at));
    genesis
}

#[test]
fn an_unknown_parent_is_not_in() {
    let provider = MockEthProvider::default();
    let genesis = alloy_genesis::Genesis::default();
    assert!(parent_in(&provider, B256::repeat_byte(0xE0), &genesis, false).unwrap().is_none());
    assert!(parent_in(&provider, B256::repeat_byte(0xE0), &genesis, true).unwrap().is_none());
}

#[test]
fn a_known_parent_is_in_unless_its_execution_is_owed_here() {
    let provider = MockEthProvider::default();
    // Before the fork a header carries its own result.
    let before = header(5, B256::ZERO, "in-before-fork");
    provider.add_header(before.hash(), before.header().clone());
    let genesis = deferred_genesis(1_000);
    assert_eq!(parent_in(&provider, before.hash(), &genesis, true).unwrap().map(|p| p.hash()), Some(before.hash()));

    // Past the fork, a parent counts once its fields are recorded here.
    let past = reth_primitives_traits::SealedHeader::seal_slow(alloy_consensus::Header {
        number: 6,
        timestamp: 2_000,
        extra_data: b"in-past-fork".to_vec().into(),
        ..Default::default()
    });
    provider.add_header(past.hash(), past.header().clone());
    assert!(parent_in(&provider, past.hash(), &genesis, true).unwrap().is_none(), "executed here is owed");
    assert!(parent_in(&provider, past.hash(), &genesis, false).unwrap().is_some(), "not deferred: the provider's word");
    n42_engine_types::executed_fields::remember(
        past.hash(),
        n42_engine_types::executed_fields::ExecutedFields {
            state_root: B256::repeat_byte(1),
            receipts_root: B256::repeat_byte(2),
            logs_bloom: Default::default(),
            gas_used: 0,
        },
    );
    assert!(parent_in(&provider, past.hash(), &genesis, true).unwrap().is_some());

    // The genesis block carries no deferred result of its own.
    let genesis_block = reth_primitives_traits::SealedHeader::seal_slow(alloy_consensus::Header {
        number: 0,
        timestamp: 3_000,
        extra_data: b"in-genesis".to_vec().into(),
        ..Default::default()
    });
    provider.add_header(genesis_block.hash(), genesis_block.header().clone());
    assert!(parent_in(&provider, genesis_block.hash(), &genesis, true).unwrap().is_some());
}

#[test]
fn waiting_for_a_parent_returns_once_the_provider_learns_of_it() {
    let provider = MockEthProvider::default();
    let parent = header(7, B256::ZERO, "late-parent");
    let genesis = alloy_genesis::Genesis::default();
    let found = std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(60));
            provider.add_header(parent.hash(), parent.header().clone());
            note_import_landed();
        });
        wait_for_parent(&provider, parent.hash(), &genesis, false)
    });
    assert_eq!(found.expect("the parent arrives").hash(), parent.hash());
}

// --- ancestry --------------------------------------------------------------------

#[test]
fn one_published_block_over_an_ancestor_in_the_engine_is_a_one_deep_ancestry() {
    let provider = MockEthProvider::default();
    let anchor = header(10, B256::ZERO, "anc-anchor");
    provider.add_header(anchor.hash(), anchor.header().clone());
    let parent = header(11, anchor.hash(), "anc-parent");
    let layer = ParentLayer::Merged(output_of(&[]));
    let genesis = alloy_genesis::Genesis::default();
    let ancestry = ancestry_of(&provider, &parent, &layer, &genesis, false, 12).expect("the grandparent is in");
    assert_eq!(ancestry.outputs.len(), 1);
    assert_eq!(ancestry.anchor, anchor.hash());
    assert_eq!(ancestry.layers().len(), 1);
}

#[test]
fn an_ancestry_is_refused_when_an_ancestor_is_neither_in_the_engine_nor_published() {
    let provider = MockEthProvider::default();
    let parent = header(11, B256::repeat_byte(0xF1), "anc-lost");
    let genesis = alloy_genesis::Genesis::default();
    assert!(ancestry_of(&provider, &parent, &ParentLayer::Merged(output_of(&[])), &genesis, false, 12).is_none());
}

#[test]
fn the_overlay_and_the_published_ancestry_follow_the_hashed_state_setting() {
    let anchor = B256::repeat_byte(0x21);
    let ancestry = Ancestry { outputs: vec![(header(1, anchor, "overlay"), ParentLayer::Merged(output_of(&[])))], anchor };
    let overlay = overlay_parent(&ancestry, 1);
    let published = published_ancestry(B256::repeat_byte(0x22), std::time::Duration::from_millis(10));
    if hashed_state_enabled() {
        assert!(overlay.is_none(), "the hashed post-state pass has no overlay to read");
        let err = published.expect_err("refused while the pass is on");
        assert!(err.contains("hashed post-state"), "{err}");
    } else {
        let (base, layers) = overlay.expect("the overlay is available with the pass off");
        assert_eq!(base, anchor);
        assert_eq!(layers.len(), 1);
        assert!(published.is_err(), "nothing is published for that parent");
    }
}

// --- the foreign block and its late copy -----------------------------------------

fn empty_sealed_block(number: u64) -> SealedBlock<Block> {
    SealedBlock::seal_slow(Block {
        header: alloy_consensus::Header { number, ..Default::default() },
        body: n42_tx_types::BlockBody { transactions: Vec::new(), ommers: Vec::new(), withdrawals: None },
    })
}

fn recovered(number: u64) -> RecoveredBlock<Block> {
    RecoveredBlock::new_sealed(empty_sealed_block(number), Vec::new())
}

#[test]
fn a_sealed_foreign_block_counts_its_transactions() {
    let block: ForeignBlock = empty_sealed_block(3).into();
    assert!(matches!(block, ForeignBlock::Sealed(_)));
    assert_eq!(block.tx_count(), 0);
}

#[test]
fn a_described_foreign_block_counts_the_transactions_it_describes() {
    let (_made_tx, made) = std::sync::mpsc::channel();
    let aside = DescribedAside {
        header: header(4, B256::ZERO, "aside"),
        withdrawals: None,
        transactions: Arc::new(Vec::new()),
        senders: Arc::new(Vec::new()),
        made,
    };
    assert_eq!(ForeignBlock::Aside(aside).tx_count(), 0);
}

#[test]
fn a_late_block_that_is_ready_is_handed_out_without_a_wait() {
    let late = LateBlock::ready(Arc::new(recovered(1)));
    assert_eq!(late.get().expect("ready").number, 1);
    assert_eq!(late.times(), (0, 0));
}

#[test]
fn a_late_block_waits_for_its_maker_and_remembers_the_copy_cost() {
    let (made_tx, made_rx) = std::sync::mpsc::channel();
    let late = LateBlock::waiting(made_rx);
    made_tx.send(Ok((recovered(9), 1_234))).unwrap();
    assert_eq!(late.get().expect("made").number, 9);
    assert_eq!(late.times().0, 1_234);
    // A second reader gets the same block, and the cost is not re-measured.
    assert_eq!(late.get().expect("cached").number, 9);
    assert_eq!(late.times().0, 1_234);
}

#[test]
fn a_late_block_whose_maker_failed_or_vanished_says_so_every_time() {
    let (made_tx, made_rx) = std::sync::mpsc::channel();
    let late = LateBlock::waiting(made_rx);
    made_tx.send(Err("copy refused".to_owned())).unwrap();
    assert_eq!(late.get().unwrap_err(), "copy refused");
    assert_eq!(late.get().unwrap_err(), "copy refused", "the failure is cached");

    let (gone_tx, gone_rx) = std::sync::mpsc::channel::<MadeAside>();
    let late = LateBlock::waiting(gone_rx);
    drop(gone_tx);
    assert_eq!(late.get().unwrap_err(), "the owned block's maker went away");
}

#[test]
fn the_exec_split_takes_the_phases_the_executor_reports() {
    let phases = n42_engine_types::parallel_transfer::Phases {
        partition_ms: 1,
        groups_ms: 2,
        merge_ms: 3,
        batches: 4,
        threads: 5,
        ..Default::default()
    };
    let split = ExecSplit::of(&phases);
    assert_eq!(
        (split.part_ms, split.batches_ms, split.graft_ms, split.batches, split.threads),
        (1, 2, 3, 4, 5)
    );
    assert_eq!((split.batch_max_ms, split.batch_median_ms), (0, 0));
}

// --- the intrinsic-gas spec ------------------------------------------------------

#[test]
fn the_intrinsic_gas_spec_follows_the_latest_active_fork() {
    let spec = &*reth_chainspec::MAINNET;
    // Mainnet's activation times: Shanghai, Cancun, Prague, Osaka.
    assert_eq!(spec_for_intrinsic_gas(spec, 0), SpecId::LONDON);
    assert_eq!(spec_for_intrinsic_gas(spec, 1_681_338_455), SpecId::SHANGHAI);
    assert_eq!(spec_for_intrinsic_gas(spec, 1_710_338_135), SpecId::CANCUN);
    assert_eq!(spec_for_intrinsic_gas(spec, 1_746_612_311), SpecId::PRAGUE);
    assert_eq!(spec_for_intrinsic_gas(spec, u64::MAX), SpecId::OSAKA);
}

// --- the timed check -------------------------------------------------------------

#[test]
fn a_timed_check_of_an_empty_block_passes_with_and_without_the_header_comparison() {
    let provider = MockEthProvider::default();
    let block = RecoveredBlock::new_sealed(
        SealedBlock::new_unhashed(Block {
            header: alloy_consensus::Header { number: 2, gas_limit: 30_000_000, base_fee_per_gas: Some(7), ..Default::default() },
            body: n42_tx_types::BlockBody { transactions: Vec::new(), ommers: Vec::new(), withdrawals: None },
        }),
        Vec::new(),
    );
    let mut times = CheckTimes::default();
    timed_check(None, &provider, B256::repeat_byte(1), None, &block, 1, SpecId::CANCUN, &mut times).expect("includable");

    let consensus = reth_consensus::noop::NoopConsensus::default();
    let sealed = header(2, B256::repeat_byte(1), "timed-header");
    let parent = header(1, B256::ZERO, "timed-parent");
    timed_check(
        Some((&consensus, &sealed, &parent)),
        &provider,
        B256::repeat_byte(1),
        None,
        &block,
        1,
        SpecId::CANCUN,
        &mut times,
    )
    .expect("the noop consensus accepts the header");
}

// ---- held executions (`N42_VOTE_BEFORE_SLOT`) --------------------------------

#[test]
fn an_execution_without_a_hold_starts_at_once() {
    assert_eq!(wait_for_release(B256::repeat_byte(0xe0)), Ok(()));
}

#[test]
fn a_held_execution_waits_for_its_release() {
    let hash = B256::repeat_byte(0xe1);
    let release = hold_execution(hash);
    let waiter = std::thread::spawn(move || wait_for_release(hash));
    std::thread::sleep(std::time::Duration::from_millis(30));
    assert!(!waiter.is_finished(), "held until released");
    release.send(true).expect("the waiter listens");
    assert_eq!(waiter.join().expect("joins"), Ok(()));
    // Taken once: a second import of the same hash is not held.
    assert_eq!(wait_for_release(hash), Ok(()));
}

#[test]
fn a_dropped_or_abandoned_hold_ends_the_execution() {
    let dropped = B256::repeat_byte(0xe2);
    let release = hold_execution(dropped);
    release.send(false).expect("listens");
    assert_eq!(wait_for_release(dropped), Err(HELD_DROPPED.to_owned()));

    // No CHECKED frame went out, so no release byte will come: the sender is
    // dropped and an execution already waiting ends instead of hanging.
    let abandoned = B256::repeat_byte(0xe3);
    drop(hold_execution(abandoned));
    assert_eq!(wait_for_release(abandoned), Err(HELD_DROPPED.to_owned()));

    // A hold whose import ended before its execution is forgotten.
    let forgotten = B256::repeat_byte(0xe4);
    let _release = hold_execution(forgotten);
    forget_hold(forgotten);
    assert_eq!(wait_for_release(forgotten), Ok(()));
}
