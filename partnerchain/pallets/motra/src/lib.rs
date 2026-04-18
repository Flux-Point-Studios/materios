#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
pub mod fee;
pub mod types;
pub mod weights;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_runtime::{Perbill, Saturating};

    use crate::types::MotraParams;
    use crate::weights::WeightInfo;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_balances::Config {
        /// The overarching runtime event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// MOTRA balance per account.
    #[pallet::storage]
    #[pallet::getter(fn motra_balance)]
    pub type MotraBalances<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u128, ValueQuery>;

    /// Delegation: where newly generated MOTRA flows. None = self.
    #[pallet::storage]
    #[pallet::getter(fn delegatee)]
    pub type Delegatees<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, T::AccountId, OptionQuery>;

    /// Last block at which account's MOTRA was reconciled (for lazy accounting).
    #[pallet::storage]
    #[pallet::getter(fn last_touched)]
    pub type LastTouched<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, BlockNumberFor<T>, ValueQuery>;

    /// Global MOTRA parameters.
    #[pallet::storage]
    #[pallet::getter(fn params)]
    pub type Params<T: Config> = StorageValue<_, MotraParams, ValueQuery>;

    /// Total MOTRA issued (for metrics).
    #[pallet::storage]
    #[pallet::getter(fn total_issued)]
    pub type TotalIssued<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Total MOTRA burned as fees (cumulative, never decreases).
    #[pallet::storage]
    #[pallet::getter(fn total_burned)]
    pub type TotalBurned<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Count of transactions that failed due to insufficient MOTRA.
    #[pallet::storage]
    #[pallet::getter(fn insufficient_motra_failures)]
    pub type InsufficientMotraFailures<T: Config> = StorageValue<_, u64, ValueQuery>;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// MOTRA balance reconciled for account (after decay + generation).
        BalanceReconciled {
            account: T::AccountId,
            new_balance: u128,
            decayed: u128,
            generated: u128,
        },
        /// Delegation set or cleared.
        DelegateeUpdated {
            delegator: T::AccountId,
            delegatee: Option<T::AccountId>,
        },
        /// MOTRA burned for transaction fee.
        FeeBurned { who: T::AccountId, amount: u128 },
        /// Global params updated.
        ParamsUpdated { params: MotraParams },
        /// Congestion rate adjusted at end of block.
        CongestionRateAdjusted {
            old_rate: u128,
            new_rate: u128,
            block_fullness: Perbill,
        },
    }

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        /// Insufficient MOTRA to pay fee.
        InsufficientMotra,
        /// Cannot transfer MOTRA -- it is non-transferable.
        NonTransferable,
        /// Cannot delegate to self (use None instead).
        CannotDelegateToSelf,
        /// Arithmetic overflow in balance computation.
        ArithmeticOverflow,
    }

    // -----------------------------------------------------------------------
    // Hooks
    // -----------------------------------------------------------------------

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        /// At end of each block, adjust congestion_rate based on block fullness.
        fn on_finalize(_n: BlockNumberFor<T>) {
            Self::adjust_congestion_rate();
        }
    }

    // -----------------------------------------------------------------------
    // Genesis
    // -----------------------------------------------------------------------

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub min_fee: u128,
        pub congestion_rate: u128,
        pub target_fullness_ppm: u32,
        pub decay_rate_per_block_ppm: u32,
        pub generation_per_matra_per_block: u128,
        pub max_balance: u128,
        pub max_congestion_step: u128,
        pub length_fee_per_byte: u128,
        pub congestion_smoothing_ppm: u32,
        #[serde(skip)]
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let params = MotraParams {
                min_fee: self.min_fee,
                congestion_rate: self.congestion_rate,
                target_fullness: Perbill::from_parts(self.target_fullness_ppm),
                decay_rate_per_block: Perbill::from_parts(self.decay_rate_per_block_ppm),
                generation_per_matra_per_block: self.generation_per_matra_per_block,
                max_balance: self.max_balance,
                max_congestion_step: self.max_congestion_step,
                length_fee_per_byte: self.length_fee_per_byte,
                congestion_smoothing: Perbill::from_parts(self.congestion_smoothing_ppm),
            };
            Params::<T>::put(params);
        }
    }

    // -----------------------------------------------------------------------
    // Extrinsics
    // -----------------------------------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T>
    where
        T::AccountId: core::fmt::Debug,
    {
        /// Set or clear MOTRA delegation.
        ///
        /// If `delegatee` is `Some(account)`, newly generated MOTRA goes to that account.
        /// If `None`, generated MOTRA goes to self.
        ///
        /// NOTE: This does NOT transfer existing MOTRA -- it only affects future generation.
        #[pallet::call_index(0)]
        #[pallet::weight(<T as crate::pallet::Config>::WeightInfo::set_delegatee())]
        pub fn set_delegatee(
            origin: OriginFor<T>,
            delegatee: Option<T::AccountId>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Reconcile caller's balance first.
            Self::reconcile(&who)?;

            if let Some(ref d) = delegatee {
                ensure!(d != &who, Error::<T>::CannotDelegateToSelf);
                Delegatees::<T>::insert(&who, d);
            } else {
                Delegatees::<T>::remove(&who);
            }

            Self::deposit_event(Event::DelegateeUpdated {
                delegator: who,
                delegatee,
            });

            Ok(())
        }

        /// Update MOTRA parameters. Root-only for MVP.
        #[pallet::call_index(1)]
        #[pallet::weight(<T as crate::pallet::Config>::WeightInfo::set_params())]
        pub fn set_params(origin: OriginFor<T>, params: MotraParams) -> DispatchResult {
            ensure_root(origin)?;
            Params::<T>::put(params.clone());
            Self::deposit_event(Event::ParamsUpdated { params });
            Ok(())
        }

        /// Explicitly reconcile (accrue + decay) MOTRA for the caller.
        ///
        /// This is optional -- reconciliation also happens automatically during fee payment.
        #[pallet::call_index(2)]
        #[pallet::weight(<T as crate::pallet::Config>::WeightInfo::claim_motra())]
        pub fn claim_motra(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::reconcile(&who)?;
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Internal logic
    // -----------------------------------------------------------------------

    impl<T: Config> Pallet<T> {
        /// Read-only projection of what the MOTRA balance would be if reconciled now.
        ///
        /// Unlike `reconcile()`, this does NOT write to storage. Used by RPC queries
        /// so that freshly funded accounts show their projected balance immediately.
        pub fn projected_balance(who: &T::AccountId) -> u128 {
            let current_block = frame_system::Pallet::<T>::block_number();
            let last = LastTouched::<T>::get(who);
            let params = Params::<T>::get();

            let elapsed: u64 = current_block
                .saturating_sub(last)
                .try_into()
                .unwrap_or(u64::MAX);

            let stored = MotraBalances::<T>::get(who);
            if elapsed == 0 {
                return stored;
            }

            // Apply decay
            let decayed = Self::apply_decay_iterative(stored, params.decay_rate_per_block, elapsed);

            // Generate from MATRA holdings
            let matra_balance: u128 = Self::get_matra_balance(who);
            let generated = matra_balance
                .saturating_mul(params.generation_per_matra_per_block)
                .saturating_mul(elapsed as u128)
                / 1_000_000u128; // Normalize: MATRA is 6 decimals

            // Check delegation
            let generation_target = Delegatees::<T>::get(who).unwrap_or_else(|| who.clone());
            if &generation_target == who {
                decayed.saturating_add(generated).min(params.max_balance)
            } else {
                decayed
            }
        }

        /// Core lazy accounting: apply decay since last touch, add generated MOTRA,
        /// respect max cap. Returns the new balance.
        ///
        /// This is called on every fee payment and explicit claim.
        pub fn reconcile(who: &T::AccountId) -> Result<u128, DispatchError> {
            let current_block = frame_system::Pallet::<T>::block_number();
            let last = LastTouched::<T>::get(who);
            let params = Params::<T>::get();

            // How many blocks since last reconciliation.
            let elapsed: u64 = current_block
                .saturating_sub(last)
                .try_into()
                .unwrap_or(u64::MAX);

            if elapsed == 0 {
                return Ok(MotraBalances::<T>::get(who));
            }

            let old_balance = MotraBalances::<T>::get(who);

            // 1) Apply decay: balance * (decay_rate ^ elapsed)
            let decayed_balance =
                Self::apply_decay_iterative(old_balance, params.decay_rate_per_block, elapsed);

            let decay_amount = old_balance.saturating_sub(decayed_balance);

            // 2) Generate MOTRA based on MATRA (free balance) holdings.
            //    Using pallet_balances free balance as "stake proxy".
            let matra_balance: u128 = Self::get_matra_balance(who);
            let generated = matra_balance
                .saturating_mul(params.generation_per_matra_per_block)
                .saturating_mul(elapsed as u128)
                / 1_000_000u128; // Normalize: MATRA is 6 decimals

            // 3) Route generated MOTRA.
            let generation_target = Delegatees::<T>::get(who).unwrap_or_else(|| who.clone());

            // 4) Apply to balances.
            let new_self_balance = if &generation_target == who {
                // No delegation: apply to self.
                decayed_balance
                    .saturating_add(generated)
                    .min(params.max_balance)
            } else {
                // Delegated: generation goes to delegatee, self only gets decay.
                decayed_balance
            };

            MotraBalances::<T>::insert(who, new_self_balance);
            LastTouched::<T>::insert(who, current_block);

            // If delegated, add generated amount to delegatee.
            if &generation_target != who && generated > 0 {
                let delegatee_balance = MotraBalances::<T>::get(&generation_target);
                let new_delegatee_balance = delegatee_balance
                    .saturating_add(generated)
                    .min(params.max_balance);
                MotraBalances::<T>::insert(&generation_target, new_delegatee_balance);
                // Note: we don't recursively reconcile the delegatee to avoid complexity.
            }

            TotalIssued::<T>::mutate(|total| {
                *total = total.saturating_add(generated);
                // Subtract decayed amount from total.
                *total = total.saturating_sub(decay_amount);
            });

            Self::deposit_event(Event::BalanceReconciled {
                account: who.clone(),
                new_balance: new_self_balance,
                decayed: decay_amount,
                generated,
            });

            Ok(new_self_balance)
        }

        /// Apply multiplicative decay: balance * (rate ^ elapsed).
        ///
        /// Uses iterative multiplication of Perbill. For very large elapsed values
        /// the iteration is capped at 100_000 to prevent DoS.
        fn apply_decay_iterative(balance: u128, rate: Perbill, elapsed: u64) -> u128 {
            if balance == 0 {
                return 0;
            }

            let iterations = elapsed.min(100_000);
            let mut result = balance;
            let mut remaining = iterations;

            while remaining > 0 {
                // Apply in chunks of up to 64 blocks at a time.
                let chunk = remaining.min(64);
                for _ in 0..chunk {
                    result = rate * result; // Perbill * u128 -> u128
                }
                remaining -= chunk;
                if result == 0 {
                    break;
                }
            }

            result
        }

        /// Get MATRA (native token) free balance for an account.
        fn get_matra_balance(who: &T::AccountId) -> u128 {
            use frame_support::traits::fungible::Inspect;
            let bal = pallet_balances::Pallet::<T>::balance(who);
            // Convert Balance to u128. Balance in our runtime IS u128.
            // Use TryInto in case it's a different type.
            bal.try_into().unwrap_or(0u128)
        }

        /// Burn MOTRA from an account (used by fee payment).
        ///
        /// Reconciles first, then subtracts.
        pub fn burn_fee(who: &T::AccountId, amount: u128) -> Result<(), DispatchError> {
            Self::reconcile(who)?;
            let balance = MotraBalances::<T>::get(who);
            ensure!(balance >= amount, Error::<T>::InsufficientMotra);
            MotraBalances::<T>::insert(who, balance.saturating_sub(amount));

            TotalBurned::<T>::mutate(|total| *total = total.saturating_add(amount));

            Self::deposit_event(Event::FeeBurned {
                who: who.clone(),
                amount,
            });

            Ok(())
        }

        /// Compute the fee for a transaction given its weight and encoded length.
        ///
        /// TxFee = min_fee + congestion_rate * (ref_time / 1_000_000) + length_fee_per_byte * len
        pub fn compute_fee(weight: frame_support::weights::Weight, len: usize) -> u128 {
            let params = Params::<T>::get();
            let weight_component =
                params.congestion_rate.saturating_mul(weight.ref_time() as u128) / 1_000_000u128;
            let length_fee = params.length_fee_per_byte.saturating_mul(len as u128);
            params.min_fee.saturating_add(weight_component).saturating_add(length_fee)
        }

        /// Adjust congestion rate based on block fullness using EMA smoothing.
        ///
        /// Called at `on_finalize`.
        fn adjust_congestion_rate() {
            let consumed = frame_system::Pallet::<T>::block_weight();
            let max_weight = <T as frame_system::Config>::BlockWeights::get()
                .get(frame_support::dispatch::DispatchClass::Normal)
                .max_total
                .unwrap_or(frame_support::weights::Weight::from_parts(1, 0));

            let consumed_normal = consumed
                .get(frame_support::dispatch::DispatchClass::Normal)
                .ref_time();
            let max_normal = max_weight.ref_time().max(1);
            let fullness = Perbill::from_rational(consumed_normal, max_normal);

            Params::<T>::mutate(|params| {
                let old_rate = params.congestion_rate;
                let target = params.target_fullness;
                let step = params.max_congestion_step;
                let smoothing = params.congestion_smoothing;

                // Compute target congestion rate based on how far above/below target fullness
                let target_rate = if fullness > target {
                    // Above target: rate should increase. Proportional to overshoot.
                    let overshoot = fullness.saturating_sub(target);
                    let increase = Perbill::from_rational(
                        overshoot.deconstruct() as u64,
                        Perbill::one().deconstruct() as u64,
                    ) * step;
                    old_rate.saturating_add(increase)
                } else {
                    // Below target: rate should decrease. Proportional to undershoot.
                    let undershoot = target.saturating_sub(fullness);
                    let decrease = Perbill::from_rational(
                        undershoot.deconstruct() as u64,
                        Perbill::one().deconstruct() as u64,
                    ) * step;
                    old_rate.saturating_sub(decrease)
                };

                // EMA smoothing: new_rate = (1 - alpha) * old_rate + alpha * target_rate
                let complement = Perbill::one().saturating_sub(smoothing);
                let smoothed = (complement * old_rate).saturating_add(smoothing * target_rate);
                params.congestion_rate = smoothed;

                if params.congestion_rate != old_rate {
                    Self::deposit_event(Event::CongestionRateAdjusted {
                        old_rate,
                        new_rate: params.congestion_rate,
                        block_fullness: fullness,
                    });
                }
            });
        }
    }
}
