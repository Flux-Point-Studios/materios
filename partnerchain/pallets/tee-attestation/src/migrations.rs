//! Storage migrations.

use frame_support::{
    migrations::VersionedMigration,
    traits::{Get, UncheckedOnRuntimeUpgrade},
    weights::Weight,
};

use crate::{CompositeTrustScores, Config, Pallet, VerifiedEntries};

/// Clears every evidence entry and trust score recorded at storage version 0.
/// None is bound to its receipt: that verifier accepted any Google-rooted
/// chain for any receipt.
pub struct ClearUnboundEvidenceInner<T>(core::marker::PhantomData<T>);

impl<T: Config> UncheckedOnRuntimeUpgrade for ClearUnboundEvidenceInner<T> {
    fn on_runtime_upgrade() -> Weight {
        let entries = VerifiedEntries::<T>::clear(u32::MAX, None);
        let scores = CompositeTrustScores::<T>::clear(u32::MAX, None);
        T::DbWeight::get().reads_writes(
            u64::from(entries.loops.saturating_add(scores.loops)),
            u64::from(entries.unique.saturating_add(scores.unique)),
        )
    }

    #[cfg(feature = "try-runtime")]
    fn post_upgrade(_: alloc::vec::Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
        frame_support::ensure!(
            VerifiedEntries::<T>::iter_keys().next().is_none(),
            "evidence recorded before receipt binding remains"
        );
        frame_support::ensure!(
            CompositeTrustScores::<T>::iter_keys().next().is_none(),
            "a trust score recorded before receipt binding remains"
        );
        Ok(())
    }
}

/// Moves the pallet from storage version 0 to 1, clearing unbound evidence
/// once.
pub type ClearUnboundEvidence<T> = VersionedMigration<
    0,
    1,
    ClearUnboundEvidenceInner<T>,
    Pallet<T>,
    <T as frame_system::Config>::DbWeight,
>;
