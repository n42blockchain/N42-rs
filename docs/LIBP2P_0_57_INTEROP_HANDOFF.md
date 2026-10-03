# libp2p 0.57 gov5 interop hand-off

Branch `deps/libp2p-0.57`, 4 commits on `feat/native-fleet7` 9c81faaa6 (tip: a454ed77a).
`cargo test -p n42-h2-net --lib --tests` passes on the rebased branch (47 + 2 + 1 + 6 tests).
Cargo.lock was rebased by taking the base lock and running `cargo update -p libp2p`, so
ed25519-dalek 3.0 / curve25519-dalek 5.0 are kept (older 2.2 / 4.1 remain as transitive copies).

## Binaries (release, built from the branch)
Dir `/data/n42-build/libp2p-0.57/` (build log `build.log`):
`release/n42`, `release/examples/{h2_validator,h2_observer,h2_keygen,send_tx}`.

## Binaries for the comparison (current build)
`/home/n42/src/n42/n42-rs/target/native/release/{n42,examples/h2_validator,...}`, built 2026-10-02 23:18-23:19
on `feat/native-fleet7` at or just after 80d5e92f3 (reth v2.7.0 merge 8b4704f4c era; the exact commit is not
recorded in the binary). It is libp2p 0.56. Rebuild at 9c81faaa6 for a strict A/B if in doubt.

## Genesis
Use `crates/chainspec/res/genesis/n42_devnet.json` (chain id 1143, `consensus: hotstuff`, four dev validators;
secrets in `n42_devnet_validators.json`, public seed, dev only). It is the file a gov5 node is initialised from
(`n42 init --chain private --profile n42 --data.dir <dir> <genesis>`). Alternative: `crates/chainspec/res/genesis/gov5/`
(chain 94 / 95, `mainnet_qmdb_staggered.json`); its README requires the `--fork-time shanghai=<ts> --fork-time cancun=<ts>`
step before running on them.

## Starting one Rust node + validator against one gov5 peer
(shapes from `scripts/devnet-fleet.sh --gov5`, which is the reference; do not copy its pkill lines)
```
B=/data/n42-build/libp2p-0.57/release; G=crates/chainspec/res/genesis/n42_devnet.json; F=<workdir>
$B/examples/h2_keygen --count 4 --seed n42-devnet-validator --out-dir $F/keys
$B/n42 node --chain $G --datadir $F/datadir --authrpc.port 18551 --authrpc.jwtsecret $F/jwt.hex \
  --http --http.port 18545 --port 30313 --disable-discovery --ipcdisable
$B/examples/h2_validator --chain $G --index 0 --bls-key $(cat $F/keys/validator-0.key) \
  --el http://127.0.0.1:18551 --el-rpc http://127.0.0.1:18545 --jwt $F/jwt.hex \
  --listen /ip4/127.0.0.1/tcp/19000 --propose --datadir $F/consensus-0 \
  --peer /ip4/127.0.0.1/tcp/30393/p2p/<gov5 peer id>
```
gov5 member (validator 3; copy `keys/validator-3.key` to `<gov5>/keystore/bls_<addr>.key`, write a hex libp2p key to `network-keys`):
```
n42 --chain private --profile n42 --data.dir $F/gov5 --mine --etherbase <validators[3].address> --http --http.port 28545 \
  --port 30393 --p2p.no-discovery --p2p.min-sync-peers 0 --p2p.peer /ip4/127.0.0.1/tcp/19000/p2p/<rust peer id, "node peer id" in the validator log>
```
Peer id of a gov5 key: `h2_keygen --libp2p-peer-id <hex key>`. Run only three Rust validators (indices 0-2) with gov5 as index 3.
`send_tx` submits signed transfers to either client's RPC. Protocols that must work: the
`/rpc/status/1/ssz_snappy` handshake (gov5 drops the peer without it), block bodies on
`/n42/<fork digest>/block/ssz_snappy` (RLP `[header, txs, verifiers, rewards]`), the `transaction_v2` topic
(on with `--el-rpc`), `block_by_hash` and `bodies_by_range`.

## Transport
TCP + Noise + Yamux only (`crates/n42/h2-net/src/transport.rs`, `with_tcp`). gov5 also listens on QUIC-v1; h2-net does
not enable QUIC (a dial to a TCP-only node fails misleadingly). Use `/ip4/.../tcp/...` addresses.

## What the test must watch
(a) The yamux receive window is no longer fixed at 16 MiB (`N42_YAMUX_WINDOW_MB` is gone; yamux 0.14 auto-tunes from 256 KiB). Block-body transfer time for 163k-tx bodies (~26 MB) must be compared with the current build.
(b) gossipsub 0.50 sends all subscriptions in one hello RPC and the subscription filter was pinned to allow-all, `max_control_message_size` pinned to our max gossip wire size. Confirm gov5 meshes and delivers on both topics (consensus and block body; also `transaction_v2`).

## Fixtures the wire codec must still match (SHA-256 of raw bytes)
```
0c5877432b8d7adb3fc60c5226564ad1d0e099b6c73f39b823703926e82d2aee  cross_client_h2_v1.json
f3f20d4641455eaf7ea6c96641fc4674134080aefcb300c219ab34a53d4d9510  h2_v4_domains_v1.json
09a98f549fcfa1b4185b78b975fa680608c73e169758cb0c052c72efbff4ff83  h2_v4_envelope_v1.json
feacd6d0d2dc3babcbe3440384021ee9291b68103baaf7d47cd0ff1c6b703488  h2_v4_finality_v1.json
```
(`crates/n42/h2-wire/testdata/`, finality in `crates/n42/h2-consensus/testdata/`.) Cross-client rules: `docs/N42_26_PORT.md` "Joining a Go fleet".
