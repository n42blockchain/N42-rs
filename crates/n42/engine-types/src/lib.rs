mod addons;
pub use addons::N42NodeAddOns;

mod engine_type;
pub use engine_type::N42EngineTypes;

mod attributes;
pub use attributes::N42PayloadAttributes;

mod engine_validator;
pub use engine_validator::N42EngineValidator;

mod node;
pub use node::N42Node;

mod payload;
pub use payload::N42PayloadBuilder;
pub use payload::N42PayloadServiceBuilder;





//
// #[tokio::main]
// async fn main() -> eyre::Result<()> {
//     let _guard = RethTracer::new().init()?;
//
//     let tasks = TaskManager::current();
//
//     // create optimism genesis with canyon at block 2
//     let spec = ChainSpec::builder()
//         .chain(Chain::mainnet())
//         .genesis(Genesis::default())
//         .london_activated()
//         .paris_activated()
//         .shanghai_activated()
//         .build();
//
//     // create node config
//     let node_config =
//         NodeConfig::test().with_rpc(RpcServerArgs::default().with_http()).with_chain(spec);
//
//     let handle = NodeBuilder::new(node_config)
//         .testing_node(tasks.executor())
//         .launch_node(MyCustomNode::default())
//         .await
//         .unwrap();
//
//     println!("Node started");
//
//     handle.node_exit_future.await
// }
