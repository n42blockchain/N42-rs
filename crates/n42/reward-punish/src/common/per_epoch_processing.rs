use crate::beaconstate::BeaconState;
use crate::spec::{Spec,EthSpec};
use crate::errors::EpochProcessingError as Error;
use crate::common::epoch_processing_summary::EpochProcessingSummary;
use crate::relative_epoch::RelativeEpoch;
use crate::common::single_pass::SinglePassConfig;
use crate::common::single_pass::process_epoch_single_pass;




/// Performs per-epoch processing on some BeaconState.
///
/// Mutates the given `BeaconState`, returning early if an error is encountered. If an error is
/// returned, a state might be "half-processed" and therefore in an invalid state.
pub fn process_epoch<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &Spec,
) -> Result<EpochProcessingSummary<E>, Error> {

    // Ensure the required caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;
    state.build_committee_cache(RelativeEpoch::Next, spec)?;
    state.build_total_active_balance_cache(spec)?;
    // initialize_epoch_cache(state, spec)?;
    // initialize_progressive_balances_cache::<E>(state, spec)?;

    // let sync_committee = state.current_sync_committee()?.clone();

    // // Justification and finalization.
    // let justification_and_finalization_state = process_justification_and_finalization(state)?;
    // justification_and_finalization_state.apply_changes_to_state(state);

    // In a single pass:
    // - Inactivity updates
    // - Rewards and penalties
    // - Registry updates
    // - Slashings
    // - Effective balance updates
    //
    // The `process_eth1_data_reset` is not covered in the single pass, but happens afterwards
    // without loss of correctness.
    let current_epoch_progressive_balances = state.progressive_balances_cache().clone();
    let current_epoch_total_active_balance = state.get_total_active_balance()?;
    let participation_summary =
        process_epoch_single_pass(state, spec, SinglePassConfig::default())?;





    // // Reset eth1 data votes.
    // process_eth1_data_reset(state)?;
    //
    // // Reset slashings
    // process_slashings_reset(state)?;
    //
    // // Set randao mix
    // process_randao_mixes_reset(state)?;
    //
    // // Set historical summaries accumulator
    // if state.historical_summaries().is_ok() {
    //     // Post-Capella.
    //     process_historical_summaries_update(state)?;
    // } else {
    //     // Pre-Capella
    //     process_historical_roots_update(state)?;
    // }
    //
    // // Rotate current/previous epoch participation
    // process_participation_flag_updates(state)?;
    //
    // process_sync_committee_updates(state, spec)?;
    //
    // // Rotate the epoch caches to suit the epoch transition.
    // state.advance_caches()?;
    // update_progressive_balances_on_epoch_transition(state, spec)?;



    Ok(EpochProcessingSummary::Altair {
        progressive_balances: current_epoch_progressive_balances,
        current_epoch_total_active_balance,
        participation: participation_summary,
        // sync_committee,
    })
}