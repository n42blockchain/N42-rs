use reth_testing_utils::generators::{self, Rng};

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let mut rng = generators::rng();
/*
    let chain_spec = Arc::new(
	ChainSpecBuilder::default()
	    .chain(MAINNET.chain)
	    .genesis(MAINNET.genesis.clone())
	    .paris_activated()
	    .build(),
    );

    let (consensus_engine, env) = TestConsensusEngineBuilder::new(chain_spec.clone())
	.with_pipeline_exec_outputs(VecDeque::from([Ok(ExecOutput {
	    checkpoint: StageCheckpoint::new(0),
	    done: true,
	})]))
	.build();

    let genesis = random_block(
	&mut rng,
	0,
	BlockParams { ommers_count: Some(0), ..Default::default() },
    );
    let block1 = random_block(
	&mut rng,
	1,
	BlockParams {
	    parent: Some(genesis.hash()),
	    ommers_count: Some(0),
	    ..Default::default()
	},
    );
    let (_static_dir, static_dir_path) = create_test_static_files_dir();

    insert_blocks(
	ProviderFactory::<MockNodeTypesWithDB>::new(
	    env.db.clone(),
	    chain_spec.clone(),
	    StaticFileProvider::read_write(static_dir_path).unwrap(),
	),
	[&genesis, &block1].into_iter(),
    );
    env.db
	.update(|tx| {
	    tx.put::<tables::StageCheckpoints>(
		StageId::Finish.to_string(),
		StageCheckpoint::new(block1.number),
	    )
	})
	.unwrap()
	.unwrap();

    let mut engine_rx = spawn_consensus_engine(consensus_engine);

    let forkchoice = ForkchoiceState {
	head_block_hash: block1.hash(),
	finalized_block_hash: block1.hash(),
	..Default::default()
    };

    let result = env.send_forkchoice_updated(forkchoice).await.unwrap();
    let expected_result = ForkchoiceUpdated::new(PayloadStatus::new(
	PayloadStatusEnum::Valid,
	Some(block1.hash()),
    ));
    assert_eq!(result, expected_result);
    assert_matches!(engine_rx.try_recv(), Err(TryRecvError::Empty));
*/
}

