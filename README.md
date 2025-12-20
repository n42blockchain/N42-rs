<div align="center">

# N42

**A modular, high-performance blockchain client built in Rust**

[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange.svg)](https://www.rust-lang.org)
[![Build Status](https://github.com/n42blockchain/N42-rs/actions/workflows/devskim.yml/badge.svg)](https://github.com/n42blockchain/N42-rs/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Discord](https://img.shields.io/discord/n42?label=Discord&logo=discord)](https://discord.gg/n42)

[Website](https://n42.world) | [Documentation](https://docs.n42.world) | [Developer Portal](https://developers.n42.world)

</div>

---

## Overview

N42 is a next-generation blockchain execution client implemented in Rust, designed for high performance, modularity, and security. Built on top of [reth](https://github.com/paradigmxyz/reth), N42 extends the Ethereum execution layer with custom consensus mechanisms and domain-specific optimizations.

### Key Features

- **APoS Consensus**: Authority Proof of Stake consensus mechanism based on Clique
- **Modular Architecture**: Composable components for flexible deployment scenarios
- **High Performance**: Optimized for throughput with efficient state management
- **EVM Compatible**: Full Ethereum Virtual Machine compatibility
- **Cross-Chain Ready**: Designed for interoperability across blockchain ecosystems

## Installation

### Requirements

- [Rust](https://www.rust-lang.org/tools/install) 1.86+
- Clang/LLVM (for building dependencies)
- Linux / macOS / Windows (WSL)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/n42blockchain/N42-rs.git
cd N42-rs

# Build in release mode
cargo build --release
```

The binary will be available at `target/release/n42`.

### Docker

```bash
docker pull n42blockchain/n42:latest
docker run -d n42blockchain/n42 node --chain mainnet
```

## Quick Start

### Running a Node

```bash
# Run a mainnet node
./target/release/n42 node --chain mainnet

# Run a development node
./target/release/n42 node --dev

# Run with custom data directory
./target/release/n42 node --chain mainnet --datadir /path/to/data
```

### Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `--chain` | Chain specification (mainnet, testnet, dev) | `mainnet` |
| `--datadir` | Data directory for the node | Platform default |
| `--http` | Enable HTTP-RPC server | Disabled |
| `--ws` | Enable WebSocket-RPC server | Disabled |
| `--port` | Network listening port | `30303` |

For a complete list of options:

```bash
./target/release/n42 node --help
```

## Project Structure

```
N42-rs/
├── bin/
│   └── n42/                    # Main node binary
├── crates/
│   ├── chainspec/              # Chain specification definitions
│   ├── consensus/              # Consensus implementations
│   ├── ethereum/               # Ethereum compatibility layer
│   │   ├── cli/                # CLI commands
│   │   ├── evm/                # EVM execution
│   │   ├── hardforks/          # Hardfork configurations
│   │   └── node/               # Node implementation
│   ├── n42/                    # N42-specific modules
│   │   ├── clique/             # APoS consensus (Clique-based)
│   │   ├── consensus-client/   # Consensus client
│   │   ├── engine-primitives/  # Engine API primitives
│   │   ├── engine-types/       # Engine types
│   │   └── primitives/         # Core primitives
│   ├── net/                    # Networking
│   │   ├── network/            # P2P network implementation
│   │   ├── network-api/        # Network API
│   │   └── peers/              # Peer discovery
│   ├── node/                   # Node builder
│   ├── primitives-traits/      # Primitive trait definitions
│   ├── rpc/                    # RPC interfaces
│   └── storage/                # Storage layer
│       ├── db/                 # Database implementation (MDBX)
│       ├── db-api/             # Database API
│       ├── provider/           # Data providers
│       └── storage-api/        # Storage API
├── Cargo.toml                  # Workspace configuration
└── LICENSE                     # MIT License
```

## Documentation

- **[User Guide](https://docs.n42.world/guide)**: Getting started with N42
- **[API Reference](https://docs.n42.world/api)**: JSON-RPC API documentation
- **[Architecture](https://docs.n42.world/architecture)**: Technical design documentation

### Generate Local Documentation

```bash
cargo doc --no-deps --all-features --document-private-items --open
```

## Development

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p n42-clique

# Run with logging
RUST_LOG=debug cargo test
```

### Code Formatting

```bash
cargo fmt --all
```

### Linting

```bash
cargo clippy --workspace --all-features
```

## Networks

| Network | Chain ID | Status |
|---------|----------|--------|
| Mainnet | 42 | Production |
| Testnet | 4242 | Testing |
| Devnet | 424242 | Development |

### Bootnodes

Mainnet bootnodes are included in the default configuration. For custom networks, specify bootnodes via the `--bootnodes` flag.

## RPC Endpoints

N42 supports standard Ethereum JSON-RPC methods:

- `eth_*` - Ethereum namespace
- `net_*` - Network namespace
- `web3_*` - Web3 namespace
- `debug_*` - Debug namespace (optional)
- `trace_*` - Trace namespace (optional)

### Engine API

The Engine API is available for consensus layer communication:

```bash
./target/release/n42 node --authrpc.port 8551 --authrpc.jwtsecret /path/to/jwt.hex
```

## Contributing

We welcome contributions from the community. Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a pull request.

### Development Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## Security

If you discover a security vulnerability, please report it via our [Security Policy](SECURITY.md). Do not open a public issue.

## License

N42 is licensed under the [MIT License](LICENSE).

```
Copyright (c) 2017-2025 N42 Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
```

## Acknowledgments

N42 is built on the shoulders of giants. We extend our gratitude to:

- [Reth](https://github.com/paradigmxyz/reth) - The modular Ethereum execution client
- [Alloy](https://github.com/alloy-rs/alloy) - Ethereum library suite
- [Revm](https://github.com/bluealloy/revm) - Rust EVM implementation
- The Ethereum community and all open-source contributors

---

<div align="center">

**[Website](https://n42.world)** · **[Discord](https://discord.gg/n42)** · **[Twitter](https://twitter.com/n42blockchain)**

</div>
