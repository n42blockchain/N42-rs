// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::vec;

use alloy_primitives::U256;

use once_cell as _;
#[cfg(not(feature = "std"))]
use once_cell::sync::Lazy as LazyLock;
#[cfg(feature = "std")]
use std::sync::LazyLock;

use crate::{ChainHardforks, EthereumHardfork, ForkCondition, Hardfork};

#[derive(Debug, Clone, Default)]
pub struct BeijingFork;

pub const beijing_fork: BeijingFork = BeijingFork {};

impl Hardfork for BeijingFork {
    fn name(&self) -> &'static str {
        "beijing"
    }
}

/// N42 Fusaka hardfork timestamps
///
/// Fusaka = Prague (EL) + Osaka (CL)
///
/// Timeline (N42 Mainnet):
/// - Shanghai: 2025-05-07 00:00:00 UTC (1746576000)
/// - Cancun:   2025-05-07 00:00:00 UTC (1746576000)
/// - Prague:   2025-06-03 06:00:00 UTC (1748930400)
/// - Osaka:    2099-01-01 00:00:00 UTC (4070908800) - Fusaka CL upgrade (delayed for devnet)
///
/// Note: Osaka enables:
/// - EIP-2537: BLS12-381 precompiles
/// - EIP-7594: PeerDAS (data availability sampling)
/// - Increased blob capacity (target: 6, max: 9)
/// - MAX_TX_GAS_LIMIT_OSAKA: 16,777,216 (2^24) - limits transaction gas
///
/// For devnet testing, Osaka is delayed to avoid the 16M gas limit restriction.
pub const N42_OSAKA_TIMESTAMP: u64 = 4070908800;

/// N42 hardforks
pub static N42_HARDFORKS: LazyLock<ChainHardforks> = LazyLock::new(|| {
    ChainHardforks::new(vec![
        (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Dao.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::SpuriousDragon.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Constantinople.boxed(),
            ForkCondition::Block(0),
        ),
        (
            EthereumHardfork::Petersburg.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::ArrowGlacier.boxed(),
            ForkCondition::Block(0),
        ),
        //(beijing_fork.boxed(), ForkCondition::Timestamp(1761621577)),
        (beijing_fork.boxed(), ForkCondition::Never),
        (
            EthereumHardfork::Paris.boxed(),
            ForkCondition::TTD {
                activation_block_number: 0,
                fork_block: Some(0),
                total_difficulty: U256::ZERO,
            },
        ),
        (
            EthereumHardfork::Shanghai.boxed(),
            ForkCondition::Timestamp(1746576000),
        ),
        (
            EthereumHardfork::Cancun.boxed(),
            ForkCondition::Timestamp(1746576000),
        ),
        (
            EthereumHardfork::Prague.boxed(),
            ForkCondition::Timestamp(1748930400),
        ),
        // Osaka (Fusaka CL) - enables BLS precompiles (EIP-2537) and PeerDAS (EIP-7594)
        (
            EthereumHardfork::Osaka.boxed(),
            ForkCondition::Timestamp(N42_OSAKA_TIMESTAMP),
        ),
    ])
});

pub static N42_HARDFORKS_FOR_CLIQUE_TEST: LazyLock<ChainHardforks> = LazyLock::new(|| {
    ChainHardforks::new(vec![
        (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Dao.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::SpuriousDragon.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Constantinople.boxed(),
            ForkCondition::Block(0),
        ),
        (
            EthereumHardfork::Petersburg.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::ArrowGlacier.boxed(),
            ForkCondition::Block(0),
        ),
        //(EthereumHardfork::Beijing.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Paris.boxed(),
            ForkCondition::TTD {
                activation_block_number: 0,
                fork_block: Some(0),
                total_difficulty: U256::ZERO,
            },
        ),
        (
            EthereumHardfork::Shanghai.boxed(),
            ForkCondition::Timestamp(1746576000),
        ),
        (
            EthereumHardfork::Cancun.boxed(),
            ForkCondition::Timestamp(1746576000),
        ),
    ])
});
