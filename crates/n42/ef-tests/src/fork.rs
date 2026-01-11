//! Fork specification handling for EF tests
//!
//! This module provides conversion between EF test fork names and reth chain specifications.

use crate::error::{EfTestError, EfTestResult};
use alloy_hardforks::EthereumHardfork;
use reth_chainspec::{ChainSpec, ChainSpecBuilder, MAINNET};
use std::sync::Arc;

/// Fork specification enum representing all supported Ethereum forks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForkSpec {
    /// Frontier (block 0)
    Frontier,
    /// Homestead (block 1,150,000)
    Homestead,
    /// DAO Fork
    DaoFork,
    /// Tangerine Whistle (EIP-150)
    TangerineWhistle,
    /// Spurious Dragon (EIP-158)
    SpuriousDragon,
    /// Byzantium
    Byzantium,
    /// Constantinople
    Constantinople,
    /// Petersburg (Constantinople fix)
    Petersburg,
    /// Istanbul
    Istanbul,
    /// Muir Glacier
    MuirGlacier,
    /// Berlin
    Berlin,
    /// London
    London,
    /// Arrow Glacier
    ArrowGlacier,
    /// Gray Glacier
    GrayGlacier,
    /// Paris (The Merge)
    Paris,
    /// Shanghai
    Shanghai,
    /// Cancun
    Cancun,
    /// Prague
    Prague,
    /// Osaka (future)
    Osaka,
}

impl ForkSpec {
    /// Parse a fork name string into a ForkSpec
    pub fn from_name(name: &str) -> EfTestResult<Self> {
        match name.to_lowercase().as_str() {
            "frontier" => Ok(Self::Frontier),
            "homestead" => Ok(Self::Homestead),
            "daofork" | "dao_fork" => Ok(Self::DaoFork),
            "tangerinewhistle" | "tangerine_whistle" | "eip150" => Ok(Self::TangerineWhistle),
            "spuriousdragon" | "spurious_dragon" | "eip158" => Ok(Self::SpuriousDragon),
            "byzantium" => Ok(Self::Byzantium),
            "constantinople" => Ok(Self::Constantinople),
            "constantinoplefix" | "petersburg" => Ok(Self::Petersburg),
            "istanbul" => Ok(Self::Istanbul),
            "muirglacier" | "muir_glacier" => Ok(Self::MuirGlacier),
            "berlin" => Ok(Self::Berlin),
            "london" => Ok(Self::London),
            "arrowglacier" | "arrow_glacier" => Ok(Self::ArrowGlacier),
            "grayglacier" | "gray_glacier" => Ok(Self::GrayGlacier),
            "merge" | "paris" => Ok(Self::Paris),
            "shanghai" => Ok(Self::Shanghai),
            "cancun" => Ok(Self::Cancun),
            "prague" => Ok(Self::Prague),
            "osaka" => Ok(Self::Osaka),
            _ => Err(EfTestError::UnsupportedFork(name.to_string())),
        }
    }

    /// Get the fork name as a string
    pub fn name(&self) -> &'static str {
        match self {
            Self::Frontier => "Frontier",
            Self::Homestead => "Homestead",
            Self::DaoFork => "DaoFork",
            Self::TangerineWhistle => "TangerineWhistle",
            Self::SpuriousDragon => "SpuriousDragon",
            Self::Byzantium => "Byzantium",
            Self::Constantinople => "Constantinople",
            Self::Petersburg => "Petersburg",
            Self::Istanbul => "Istanbul",
            Self::MuirGlacier => "MuirGlacier",
            Self::Berlin => "Berlin",
            Self::London => "London",
            Self::ArrowGlacier => "ArrowGlacier",
            Self::GrayGlacier => "GrayGlacier",
            Self::Paris => "Paris",
            Self::Shanghai => "Shanghai",
            Self::Cancun => "Cancun",
            Self::Prague => "Prague",
            Self::Osaka => "Osaka",
        }
    }

    /// Check if this fork is supported for testing
    pub fn is_supported(&self) -> bool {
        // All forks up to Cancun are supported, Prague/Osaka may have partial support
        match self {
            Self::Osaka => false, // Future fork, not yet supported
            _ => true,
        }
    }

    /// Check if this fork uses PoS (post-merge)
    pub fn is_pos(&self) -> bool {
        matches!(
            self,
            Self::Paris | Self::Shanghai | Self::Cancun | Self::Prague | Self::Osaka
        )
    }

    /// Check if this fork has EIP-1559
    pub fn has_eip1559(&self) -> bool {
        matches!(
            self,
            Self::London
                | Self::ArrowGlacier
                | Self::GrayGlacier
                | Self::Paris
                | Self::Shanghai
                | Self::Cancun
                | Self::Prague
                | Self::Osaka
        )
    }

    /// Check if this fork has EIP-4844 (blob transactions)
    pub fn has_blob_txs(&self) -> bool {
        matches!(self, Self::Cancun | Self::Prague | Self::Osaka)
    }

    /// Convert to a ChainSpec with all forks up to and including this one enabled at block 0
    pub fn to_chain_spec(&self, chain_id: u64) -> Arc<ChainSpec> {
        let mut builder = ChainSpecBuilder::default()
            .chain(chain_id.into())
            .genesis(MAINNET.genesis.clone());

        // Enable forks based on the target fork
        builder = match self {
            Self::Frontier => builder.frontier_activated(),
            Self::Homestead => builder.homestead_activated(),
            Self::DaoFork => builder.homestead_activated(), // DAO fork is homestead + dao
            Self::TangerineWhistle => builder.tangerine_whistle_activated(),
            Self::SpuriousDragon => builder.spurious_dragon_activated(),
            Self::Byzantium => builder.byzantium_activated(),
            Self::Constantinople | Self::Petersburg => builder.petersburg_activated(),
            Self::Istanbul => builder.istanbul_activated(),
            Self::MuirGlacier => builder.istanbul_activated(), // Muir Glacier is Istanbul + difficulty bomb delay
            Self::Berlin => builder.berlin_activated(),
            Self::London | Self::ArrowGlacier | Self::GrayGlacier => builder.london_activated(),
            Self::Paris => builder.paris_activated(),
            Self::Shanghai => builder.shanghai_activated(),
            Self::Cancun => builder.cancun_activated(),
            Self::Prague => builder.prague_activated(),
            Self::Osaka => builder.prague_activated(), // Osaka not yet defined, use Prague as base
        };

        Arc::new(builder.build())
    }

    /// Get the corresponding Hardfork enum value
    pub fn to_hardfork(&self) -> EthereumHardfork {
        match self {
            Self::Frontier => EthereumHardfork::Frontier,
            Self::Homestead | Self::DaoFork => EthereumHardfork::Homestead,
            Self::TangerineWhistle => EthereumHardfork::Tangerine,
            Self::SpuriousDragon => EthereumHardfork::SpuriousDragon,
            Self::Byzantium => EthereumHardfork::Byzantium,
            Self::Constantinople | Self::Petersburg => EthereumHardfork::Petersburg,
            Self::Istanbul | Self::MuirGlacier => EthereumHardfork::Istanbul,
            Self::Berlin => EthereumHardfork::Berlin,
            Self::London | Self::ArrowGlacier | Self::GrayGlacier => EthereumHardfork::London,
            Self::Paris => EthereumHardfork::Paris,
            Self::Shanghai => EthereumHardfork::Shanghai,
            Self::Cancun => EthereumHardfork::Cancun,
            Self::Prague | Self::Osaka => EthereumHardfork::Prague,
        }
    }
}

impl std::fmt::Display for ForkSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for ForkSpec {
    type Err = EfTestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s)
    }
}

/// Get a list of all supported forks
pub fn supported_forks() -> Vec<ForkSpec> {
    vec![
        ForkSpec::Frontier,
        ForkSpec::Homestead,
        ForkSpec::TangerineWhistle,
        ForkSpec::SpuriousDragon,
        ForkSpec::Byzantium,
        ForkSpec::Constantinople,
        ForkSpec::Petersburg,
        ForkSpec::Istanbul,
        ForkSpec::Berlin,
        ForkSpec::London,
        ForkSpec::Paris,
        ForkSpec::Shanghai,
        ForkSpec::Cancun,
        ForkSpec::Prague,
    ]
}

/// Check if a fork name is supported
pub fn is_fork_supported(name: &str) -> bool {
    ForkSpec::from_name(name)
        .map(|f| f.is_supported())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fork_from_name() {
        assert_eq!(ForkSpec::from_name("Berlin").unwrap(), ForkSpec::Berlin);
        assert_eq!(ForkSpec::from_name("berlin").unwrap(), ForkSpec::Berlin);
        assert_eq!(ForkSpec::from_name("BERLIN").unwrap(), ForkSpec::Berlin);
        assert_eq!(ForkSpec::from_name("Shanghai").unwrap(), ForkSpec::Shanghai);
        assert_eq!(ForkSpec::from_name("Cancun").unwrap(), ForkSpec::Cancun);
    }

    #[test]
    fn test_fork_unsupported() {
        assert!(ForkSpec::from_name("NonExistent").is_err());
    }

    #[test]
    fn test_fork_is_pos() {
        assert!(!ForkSpec::Berlin.is_pos());
        assert!(!ForkSpec::London.is_pos());
        assert!(ForkSpec::Paris.is_pos());
        assert!(ForkSpec::Shanghai.is_pos());
        assert!(ForkSpec::Cancun.is_pos());
    }

    #[test]
    fn test_fork_has_eip1559() {
        assert!(!ForkSpec::Berlin.has_eip1559());
        assert!(ForkSpec::London.has_eip1559());
        assert!(ForkSpec::Paris.has_eip1559());
    }

    #[test]
    fn test_fork_to_chain_spec() {
        let spec = ForkSpec::Berlin.to_chain_spec(1);
        assert_eq!(spec.chain.id(), 1);
    }
}
