//! Prepaid MATRA balance + per-request billing.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;
pub mod types;
pub mod weights;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_support::traits::{Currency, ExistenceRequirement, Imbalance};
    use frame_system::pallet_prelude::*;
    use sp_core::H256;
    use sp_runtime::{traits::Zero, Saturating};
    use sp_std::vec::Vec;

    use crate::types::{PricingModel, MAX_ENDPOINT_CLASS_LEN, WITHDRAWAL_COOLDOWN_BLOCKS};
    use crate::weights::WeightInfo;

    type BalanceOf<T> = <<T as Config>::MatraCurrency as Currency<
        <T as frame_system::Config>::AccountId,
    >>::Balance;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching runtime event type.
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// The MATRA currency used as escrow source for topups and mint target
        /// for withdrawals.
        type MatraCurrency: Currency<Self::AccountId>;

        /// Origin that can set endpoint prices and toggle the kill-switch.
        type GovernanceOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        /// How many blocks a `PaidRequests[(payer, request_id)]` entry is kept
        /// around for idempotency replay protection.
        #[pallet::constant]
        type RequestIdRetentionBlocks: Get<BlockNumberFor<Self>>;

        /// Maximum batch size for `prune_paid_requests`, bounding per-call
        /// weight against the per-block normal-class budget.
        #[pallet::constant]
        type MaxPruneBatch: Get<u32>;

        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// Per-account prepaid MATRA balance in base units (15 decimals).
    #[pallet::storage]
    #[pallet::getter(fn balance_of)]
    pub type Balances<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u128, ValueQuery>;

    /// Per-endpoint-class pricing model. An unset class returns
    /// `PricingModel::FREE` via ValueQuery's Default impl.
    ///
    /// Canonical `endpoint_class` form: lowercase snake_case ASCII, no
    /// whitespace, no path separators, <= 64 bytes. The gateway normalizes
    /// inbound request paths into this form before calling `pay_request`.
    #[pallet::storage]
    #[pallet::getter(fn endpoint_price)]
    pub type EndpointPrices<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, ConstU32<MAX_ENDPOINT_CLASS_LEN>>,
        PricingModel,
        ValueQuery,
    >;

    /// Idempotency guard for `pay_request`. Maps `(payer, request_id)` to the
    /// block at which it was first paid. Namespacing by payer prevents
    /// cross-account slot squatting.
    #[pallet::storage]
    #[pallet::getter(fn paid_request)]
    pub type PaidRequests<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        H256,
        BlockNumberFor<T>,
        OptionQuery,
    >;

    /// Pending withdrawals. Maps account to (amount, executable_at_block).
    /// One pending withdrawal per account; a second `request_withdrawal`
    /// replaces the first and resets the cooldown.
    #[pallet::storage]
    #[pallet::getter(fn pending_withdrawal)]
    pub type PendingWithdrawals<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        (u128, BlockNumberFor<T>),
        OptionQuery,
    >;

    /// Debit kill-switch. While `false`, `pay_request` emits its event with
    /// `dry_run: true` but leaves `Balances` untouched.
    #[pallet::storage]
    #[pallet::getter(fn debits_enabled)]
    pub type DebitsEnabled<T: Config> = StorageValue<_, bool, ValueQuery>;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// MATRA burned from `from` and credited to `to`'s billing balance.
        TopupSucceeded {
            from: T::AccountId,
            to: T::AccountId,
            amount: u128,
        },
        /// A billed request was paid. `dry_run` is true when `DebitsEnabled`
        /// is false (event emitted, balance unchanged).
        RequestPaid {
            payer: T::AccountId,
            request_id: H256,
            endpoint_class: Vec<u8>,
            amount: u128,
            dry_run: bool,
        },
        /// Endpoint price set or updated by governance.
        EndpointPriceSet {
            endpoint_class: Vec<u8>,
            model: PricingModel,
        },
        /// User requested a withdrawal; it will be executable at the given block.
        WithdrawalRequested {
            who: T::AccountId,
            amount: u128,
            executable_at_block: BlockNumberFor<T>,
        },
        /// A pending withdrawal was cancelled (e.g. by initiating a new one).
        WithdrawalCancelled { who: T::AccountId },
        /// A pending withdrawal was executed — MATRA minted back to caller.
        WithdrawalExecuted { who: T::AccountId, amount: u128 },
        /// Governance flipped the debit kill-switch.
        DebitsEnabledChanged { enabled: bool },
        /// `prune_paid_requests` removed `count` stale idempotency entries.
        PaidRequestsPruned { count: u32 },
    }

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        /// Caller asked to debit more MATRA than they have in `Balances`.
        InsufficientBalance,
        /// `max_charge` is below the computed price for this endpoint.
        ChargeExceedsMaxCharge,
        /// Endpoint class string exceeded `MAX_ENDPOINT_CLASS_LEN`.
        EndpointClassTooLong,
        /// Pending withdrawal exists but cooldown has not elapsed yet.
        WithdrawalCooldownActive,
        /// `execute_withdrawal` called with nothing pending.
        NoPendingWithdrawal,
        /// `topup_self` / `topup_for` could not move MATRA from caller —
        /// either insufficient pallet-balances funds or below ED.
        TopupTransferFailed,
        /// Withdrawal exceeds the BalanceOf representable range, or the
        /// `deposit_creating` saturated. The pending entry is preserved so
        /// the caller can retry.
        WithdrawalAmountOverflow,
        /// `request_withdrawal` was called with `amount = 0`. Use
        /// `cancel_withdrawal` to clear a prior pending entry instead.
        ZeroWithdrawal,
        /// `prune_paid_requests` was called with more entries than
        /// `MaxPruneBatch`.
        PruneBatchTooLarge,
    }

    // -----------------------------------------------------------------------
    // Calls
    // -----------------------------------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Burn `amount` MATRA from caller's pallet-balances account, credit
        /// caller's billing balance by the same amount.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::topup_self())]
        pub fn topup_self(origin: OriginFor<T>, amount: u128) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::do_topup(who.clone(), who, amount)
        }

        /// Burn `amount` MATRA from caller, credit `target`'s billing balance.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::topup_for())]
        pub fn topup_for(
            origin: OriginFor<T>,
            target: T::AccountId,
            amount: u128,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::do_topup(who, target, amount)
        }

        /// Charge the signed origin for one billed request.
        ///
        /// Idempotent on `(payer, request_id)` — re-submitting the same key
        /// returns Ok without re-charging. While `DebitsEnabled` is false,
        /// emits the event with `dry_run: true` but leaves `Balances` untouched.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::pay_request())]
        pub fn pay_request(
            origin: OriginFor<T>,
            endpoint_class: Vec<u8>,
            request_bytes: u64,
            max_charge: u128,
            request_id: H256,
        ) -> DispatchResult {
            let payer = ensure_signed(origin)?;

            if PaidRequests::<T>::contains_key(&payer, request_id) {
                return Ok(());
            }

            let class_bounded: BoundedVec<u8, ConstU32<MAX_ENDPOINT_CLASS_LEN>> =
                endpoint_class
                    .clone()
                    .try_into()
                    .map_err(|_| Error::<T>::EndpointClassTooLong)?;

            let price = EndpointPrices::<T>::get(&class_bounded).compute(request_bytes);
            ensure!(price <= max_charge, Error::<T>::ChargeExceedsMaxCharge);

            let dry_run = !DebitsEnabled::<T>::get();
            if !dry_run {
                let current = Balances::<T>::get(&payer);
                ensure!(current >= price, Error::<T>::InsufficientBalance);
                Balances::<T>::insert(&payer, current.saturating_sub(price));
            }

            let current_block = frame_system::Pallet::<T>::block_number();
            PaidRequests::<T>::insert(&payer, request_id, current_block);

            Self::deposit_event(Event::RequestPaid {
                payer,
                request_id,
                endpoint_class,
                amount: price,
                dry_run,
            });

            Ok(())
        }

        /// Governance sets the pricing model for a single endpoint class.
        /// Setting a class to `PricingModel::FREE` produces zero charge but
        /// is kept distinct from absence for the governance audit trail.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::governance_set_endpoint_price())]
        pub fn governance_set_endpoint_price(
            origin: OriginFor<T>,
            endpoint_class: Vec<u8>,
            model: PricingModel,
        ) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;

            let class_bounded: BoundedVec<u8, ConstU32<MAX_ENDPOINT_CLASS_LEN>> =
                endpoint_class
                    .clone()
                    .try_into()
                    .map_err(|_| Error::<T>::EndpointClassTooLong)?;

            EndpointPrices::<T>::insert(&class_bounded, model.clone());

            Self::deposit_event(Event::EndpointPriceSet {
                endpoint_class,
                model,
            });

            Ok(())
        }

        /// Request a withdrawal. Debits `Balances[caller]` immediately,
        /// records the pending withdrawal, and sets the cooldown clock.
        ///
        /// Calling again before execution atomically cancels and replaces the
        /// prior pending withdrawal: the prior amount is credited back to
        /// Balances first, then the new amount is debited.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::request_withdrawal())]
        pub fn request_withdrawal(origin: OriginFor<T>, amount: u128) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(amount > 0, Error::<T>::ZeroWithdrawal);

            if let Some((prev_amount, _)) = PendingWithdrawals::<T>::take(&who) {
                Balances::<T>::mutate(&who, |b| *b = b.saturating_add(prev_amount));
                Self::deposit_event(Event::WithdrawalCancelled { who: who.clone() });
            }

            let current = Balances::<T>::get(&who);
            ensure!(current >= amount, Error::<T>::InsufficientBalance);
            Balances::<T>::insert(&who, current.saturating_sub(amount));

            let current_block = frame_system::Pallet::<T>::block_number();
            let executable_at = current_block
                .saturating_add(BlockNumberFor::<T>::from(WITHDRAWAL_COOLDOWN_BLOCKS));
            PendingWithdrawals::<T>::insert(&who, (amount, executable_at));

            Self::deposit_event(Event::WithdrawalRequested {
                who,
                amount,
                executable_at_block: executable_at,
            });

            Ok(())
        }

        /// Execute a previously-requested withdrawal. Errors if the cooldown
        /// has not elapsed, or if no withdrawal is pending. On success, mints
        /// MATRA back to the caller's pallet-balances account.
        ///
        /// Saturation-safety: `deposit_creating` can saturate silently if
        /// `TotalIssuance` would overflow. We snapshot `free_balance` before
        /// the deposit and require both the imbalance and the post-delta to
        /// equal the requested amount; otherwise we re-burn any partial credit
        /// and leave the pending entry intact for retry.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::execute_withdrawal())]
        pub fn execute_withdrawal(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let (amount, executable_at) =
                PendingWithdrawals::<T>::get(&who).ok_or(Error::<T>::NoPendingWithdrawal)?;

            let current_block = frame_system::Pallet::<T>::block_number();
            ensure!(
                current_block >= executable_at,
                Error::<T>::WithdrawalCooldownActive
            );

            let amount_balance: BalanceOf<T> = amount
                .try_into()
                .map_err(|_| Error::<T>::WithdrawalAmountOverflow)?;

            let pre_balance = T::MatraCurrency::free_balance(&who);

            let imbalance = T::MatraCurrency::deposit_creating(&who, amount_balance);
            let credited_issuance = imbalance.peek();
            drop(imbalance);

            let post_balance = T::MatraCurrency::free_balance(&who);
            let credited_free = post_balance.saturating_sub(pre_balance);

            if credited_issuance < amount_balance || credited_free < amount_balance {
                if credited_free > Zero::zero() {
                    let _ = T::MatraCurrency::withdraw(
                        &who,
                        credited_free,
                        frame_support::traits::WithdrawReasons::TRANSFER,
                        ExistenceRequirement::AllowDeath,
                    );
                }
                return Err(Error::<T>::WithdrawalAmountOverflow.into());
            }

            PendingWithdrawals::<T>::remove(&who);

            Self::deposit_event(Event::WithdrawalExecuted { who, amount });

            Ok(())
        }

        /// Cancel a pending withdrawal: credit any prior pending amount back
        /// to the caller's billing balance. No-op if nothing is pending.
        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::cancel_withdrawal())]
        pub fn cancel_withdrawal(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            if let Some((prev_amount, _)) = PendingWithdrawals::<T>::take(&who) {
                Balances::<T>::mutate(&who, |b| *b = b.saturating_add(prev_amount));
                Self::deposit_event(Event::WithdrawalCancelled { who });
            }
            Ok(())
        }

        /// Permissionless prune: drop `PaidRequests` entries older than
        /// `Config::RequestIdRetentionBlocks`. Caller pays the gas.
        ///
        /// Entries past the cutoff are removed; younger and non-existent
        /// entries are silently skipped.
        #[pallet::call_index(8)]
        #[pallet::weight(T::WeightInfo::prune_paid_requests(ids.len() as u32))]
        pub fn prune_paid_requests(
            origin: OriginFor<T>,
            ids: Vec<(T::AccountId, H256)>,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            ensure!(
                (ids.len() as u32) <= T::MaxPruneBatch::get(),
                Error::<T>::PruneBatchTooLarge,
            );
            let current_block = frame_system::Pallet::<T>::block_number();
            let retention = T::RequestIdRetentionBlocks::get();
            let cutoff = current_block.saturating_sub(retention);

            let mut removed: u32 = 0;
            for (payer, request_id) in ids.iter() {
                if let Some(paid_at) = PaidRequests::<T>::get(payer, request_id) {
                    if paid_at <= cutoff {
                        PaidRequests::<T>::remove(payer, request_id);
                        removed = removed.saturating_add(1);
                    }
                }
            }

            if removed > 0 {
                Self::deposit_event(Event::PaidRequestsPruned { count: removed });
            }

            Ok(())
        }

        /// Governance flips `DebitsEnabled` to make `pay_request` actually
        /// debit. Idempotent.
        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::governance_set_debits_enabled())]
        pub fn governance_set_debits_enabled(
            origin: OriginFor<T>,
            enabled: bool,
        ) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;
            DebitsEnabled::<T>::put(enabled);
            Self::deposit_event(Event::DebitsEnabledChanged { enabled });
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    impl<T: Config> Pallet<T> {
        fn do_topup(
            from: T::AccountId,
            to: T::AccountId,
            amount: u128,
        ) -> DispatchResult {
            let amount_balance: BalanceOf<T> = amount
                .try_into()
                .map_err(|_| Error::<T>::TopupTransferFailed)?;

            let _imbalance = T::MatraCurrency::withdraw(
                &from,
                amount_balance,
                frame_support::traits::WithdrawReasons::TRANSFER,
                ExistenceRequirement::KeepAlive,
            )
            .map_err(|_| Error::<T>::TopupTransferFailed)?;

            Balances::<T>::mutate(&to, |b| *b = b.saturating_add(amount));

            Self::deposit_event(Event::TopupSucceeded { from, to, amount });
            Ok(())
        }

        /// Read-only price quote.
        pub fn quote_price(endpoint_class: &[u8], request_bytes: u64) -> Option<u128> {
            let class_bounded: BoundedVec<u8, ConstU32<MAX_ENDPOINT_CLASS_LEN>> =
                endpoint_class.to_vec().try_into().ok()?;
            Some(EndpointPrices::<T>::get(&class_bounded).compute(request_bytes))
        }
    }
}
