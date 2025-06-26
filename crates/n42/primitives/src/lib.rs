//! n42 primitives

mod snapshot;
pub use snapshot::Snapshot;
pub use snapshot::APosConfig;

mod beacon;
pub use beacon::{VoluntaryExit, VoluntaryExitWithSig, Epoch};
