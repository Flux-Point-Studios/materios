//! Benchmarking stubs for pallet_motra.

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::v2::*;

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn set_delegatee() {
        let caller: T::AccountId = whitelisted_caller();
        #[extrinsic_call]
        _(frame_system::RawOrigin::Signed(caller.clone()), None);
    }

    #[benchmark]
    fn set_params() {
        let params = crate::types::MotraParams::default();
        #[extrinsic_call]
        _(frame_system::RawOrigin::Root, params);
    }

    #[benchmark]
    fn claim_motra() {
        let caller: T::AccountId = whitelisted_caller();
        #[extrinsic_call]
        _(frame_system::RawOrigin::Signed(caller));
    }
}
