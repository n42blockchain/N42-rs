use crate::spec::DepositContract;
use alloy_eips::eip6110::MAINNET_DEPOSIT_CONTRACT_ADDRESS;
use alloy_primitives::b256;
use alloy_primitives::address;
use alloy_primitives::Address;

/// Gas per transaction not creating a contract.
pub const MIN_TRANSACTION_GAS: u64 = 21_000u64;

/// Mainnet prune delete limit.
pub const MAINNET_PRUNE_DELETE_LIMIT: usize = 20000;

/// Deposit contract address: `0x00000000219ab540356cbb839cbe05303d7705fa`
pub(crate) const MAINNET_DEPOSIT_CONTRACT: DepositContract = DepositContract::new(
    MAINNET_DEPOSIT_CONTRACT_ADDRESS,
    11052984,
    b256!("0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"),
);

pub const DEVNET_DEPOSIT_CONTRACT_ADDRESS: Address =
    address!("0x5FbDB2315678afecb367f032d93F642f64180aa3");
pub const TESTNET_DEPOSIT_CONTRACT_ADDRESS: Address =
    address!("0x0dcAE65dDB5df8f1817D35286beAC32b8994962B");

pub(crate) const N42_DEVNET_DEPOSIT_CONTRACT: DepositContract = DepositContract::new(
    DEVNET_DEPOSIT_CONTRACT_ADDRESS,
    0,
    b256!("0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"),
);

pub(crate) const N42_TESTNET_DEPOSIT_CONTRACT: DepositContract = DepositContract::new(
    TESTNET_DEPOSIT_CONTRACT_ADDRESS,
    0,
    b256!("0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"),
);
