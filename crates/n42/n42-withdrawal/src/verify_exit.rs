use std::borrow::Cow;
use crate::beacon_state::{BeaconState, EthSpec};
use crate::chain_spec::ChainSpec;
use crate::crypto::BlsPublicKey as PublicKey;
use crate::error::{BlockOperationError, ExitInvalid};
use crate::safe_aitrh::SafeArith;
use crate::signature_set::exit_signature_set;
use crate::slot_epoch::Epoch;
use crate::withdrawal::{SignedVoluntaryExit, VerifySignatures};

type Result<T> = std::result::Result<T, BlockOperationError<ExitInvalid>>;
fn error(reason: ExitInvalid) -> BlockOperationError<ExitInvalid> {
    BlockOperationError::invalid(reason)
}

/// Indicates if an `Exit` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `Exit` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.12.1
pub fn verify_exit<E: EthSpec>(
    state: &BeaconState<E>,
    current_epoch: Option<Epoch>,
    signed_exit: &SignedVoluntaryExit,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<()> {
    let current_epoch = current_epoch.unwrap_or(state.current_epoch());
    let exit = &signed_exit.message;

    let validator = state
        .validators()
        .get(exit.validator_index as usize)
        .ok_or_else(|| error(ExitInvalid::ValidatorUnknown(exit.validator_index)))?;

    // Verify the validator is active.
    verify!(
        validator.is_active_at(current_epoch),
        ExitInvalid::NotActive(exit.validator_index)
    );

    // Verify that the validator has not yet exited.
    verify!(
        validator.exit_epoch == spec.far_future_epoch,
        ExitInvalid::AlreadyExited(exit.validator_index)
    );

    // Exits must specify an epoch when they become valid; they are not valid before then.
    verify!(
        current_epoch >= exit.epoch,
        ExitInvalid::FutureEpoch {
            state: current_epoch,
            exit: exit.epoch
        }
    );

    // Verify the validator has been active long enough.
    let earliest_exit_epoch = validator
        .activation_epoch
        .safe_add(spec.shard_committee_period)?;
    verify!(
        current_epoch >= earliest_exit_epoch,
        ExitInvalid::TooYoungToExit {
            current_epoch,
            earliest_exit_epoch,
        }
    );

    if verify_signatures.is_true() {
        verify!(
            exit_signature_set(
                state,
                |i| get_pubkey_from_state(state, i),
                signed_exit,
                spec
            )?
            .verify(),
            ExitInvalid::BadSignature
        );
    }

    // [New in Electra:EIP7251]
    // Only exit validator if it has no pending withdrawals in the queue
    if let Ok(pending_balance_to_withdraw) =
        state.get_pending_balance_to_withdraw(exit.validator_index as usize)
    {
        verify!(
            pending_balance_to_withdraw == 0,
            ExitInvalid::PendingWithdrawalInQueue(exit.validator_index)
        );
    }

    Ok(())
}

/// Helper function to get a public key from a `state`.
pub fn get_pubkey_from_state<E>(
    state: &BeaconState<E>,
    validator_index: usize,
) -> Option<Cow<'_, PublicKey>>
where
    E: EthSpec,
{
    state
        .validators()
        .get(validator_index)
        .and_then(|v| {
            let pk: Option<PublicKey> = v.pubkey.decompress().ok();
            pk
        })
        .map(Cow::Owned)
}