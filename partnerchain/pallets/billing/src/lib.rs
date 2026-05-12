//! # `pallet-billing` — prepaid MATRA balance + per-request billing
//!
//! Implements the on-chain side of Materios pay-per-use. See
//! `/home/deci/work/phase-2-prepaid-balance-design.md` for the full design.
//!
//! **Phase 2.A** (this file) lands the scaffold: storage, extrinsics, events,
//! errors, and the `DebitsEnabled` kill-switch defaulting to `false`. With
//! the switch off, `pay_request` succeeds and emits its event but does NOT
//! actually debit `Balances` — giving us a measurement window to validate
//! header formats + 402 rates against real traffic before charging anything.
//!
//! **Phase 2.B** flips the kill-switch via governance call. No code change.
//!
//! ## Sponsor model
//!
//! There is no on-chain "sponsorship" extrinsic. The pallet only knows one
//! payer per request: the AccountId in the signed origin of `pay_request`.
//! Sponsorship is operational, not on-chain:
//! - Gateway api-key authed request → gateway signs `pay_request` with the
//!   FPS treasury account → treasury Balances debited.
//! - Self-pay sr25519 request → caller's relayed extrinsic carries their own
//!   origin → caller Balances debited.
//! Either way the pallet just debits `Balances[origin]`. Permissioning of
//! "which api-key can be sponsored" lives in gateway sqlite, not here.
//!
//! ## Idempotency
//!
//! `pay_request` records `PaidRequests[(payer, request_id)] = current_block`
//! after a successful debit. Re-submitting the same `(payer, request_id)`
//! succeeds without re-charging. This makes the gateway's retry-on-network-
//! error safe.
//!
//! **Why double-map keyed by `(payer, request_id)`:** an earlier single-map
//! keyed only by `request_id` allowed cross-account squatting — Bob could
//! front-run by paying for a `request_id` he saw in Alice's mempool, then
//! Alice's subsequent submit would be a no-op success because the slot was
//! already occupied. Namespacing by payer means each account has its own
//! idempotency lane and cannot interfere with another's.
//!
//! ## Storage growth
//!
//! `PaidRequests` is the only unbounded storage in this pallet. We bound it
//! via `Config::RequestIdRetentionBlocks` + a permissionless
//! `prune_paid_requests` extrinsic — any account can pay gas to drop entries
//! older than the retention window. This keeps the prune cost off the
//! consensus weight budget; a keeper script runs it.

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

        /// The MATRA currency (typically `pallet_balances::Pallet<T>`).
        /// Used as the escrow source for topups and the mint target for
        /// withdrawals. The pallet does not hold a sovereign account — it
        /// burns + tracks credits in `Balances` directly, so MATRA total
        /// supply stays in sync with what's actually spendable.
        type MatraCurrency: Currency<Self::AccountId>;

        /// Origin that can set endpoint prices, fund/drain the kill-switch,
        /// and override balances in emergencies. Typically `EnsureRoot` (=
        /// governance) on production; in tests `EnsureSignedBy<Alice>`.
        type GovernanceOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        /// How many blocks a `PaidRequests[(payer, request_id)]` entry is
        /// kept around for idempotency replay protection. After this window
        /// elapses, anyone can call `prune_paid_requests` to drop the entry.
        ///
        /// Default suggested by the runtime: 14_400 blocks (~1 day at 6s
        /// blocks). Long enough that a retry storm from a gateway can still
        /// hit the idempotency check; short enough that storage doesn't grow
        /// unbounded with traffic.
        #[pallet::constant]
        type RequestIdRetentionBlocks: Get<BlockNumberFor<Self>>;

        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// Per-account prepaid MATRA balance, denominated in MATRA base units
    /// (15 decimals). Includes the FPS treasury account, which is just a
    /// regular AccountId chosen operationally to act as the api-key
    /// sponsor — no special status in the pallet itself.
    #[pallet::storage]
    #[pallet::getter(fn balance_of)]
    pub type Balances<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u128, ValueQuery>;

    /// Per-endpoint-class pricing model. Governance-set via
    /// `governance_set_endpoint_price`. An unset class returns
    /// `PricingModel::FREE` (PerCall(0)) via ValueQuery's Default impl.
    ///
    /// **Canonical endpoint_class form:** lowercase snake_case ASCII, no
    /// whitespace, no path separators, ≤ 64 bytes. Examples: `receipt_submit`,
    /// `chunk_upload`, `anchor_query`. The pallet does NOT enforce this — the
    /// gateway is the trust boundary that normalizes inbound request paths
    /// into endpoint_class before calling `pay_request`. Operators adding new
    /// endpoint classes via governance MUST follow this convention so the
    /// gateway can hash-table-lookup without ambiguity.
    #[pallet::storage]
    #[pallet::getter(fn endpoint_price)]
    pub type EndpointPrices<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, ConstU32<MAX_ENDPOINT_CLASS_LEN>>,
        PricingModel,
        ValueQuery,
    >;

    /// Idempotency guard for `pay_request`. Maps `(payer, request_id)` → block
    /// at which it was first paid. Re-submission of a known
    /// `(payer, request_id)` is a no-op success. We bound this map's growth
    /// via `Config::RequestIdRetentionBlocks` — the permissionless
    /// `prune_paid_requests` extrinsic drops entries older than that.
    ///
    /// **Why `(payer, request_id)` and not bare `request_id`:** a single-key
    /// map let any signed account pre-occupy a slot they observed in another
    /// payer's mempool tx — Bob signs `pay_request(req_id_X)`, lands first,
    /// and Alice's subsequent `pay_request(req_id_X)` becomes a no-op success
    /// without ever debiting her account. Double-map per-payer namespacing
    /// closes the squatting hole: each account has its own slot for any
    /// given request_id, and cross-account interference is impossible.
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

    /// Pending withdrawals — must wait `WITHDRAWAL_COOLDOWN_BLOCKS` after
    /// `request_withdrawal` before `execute_withdrawal` can mint MATRA back.
    /// Maps account → (amount, executable_at_block). Only one pending
    /// withdrawal per account at a time — a second request_withdrawal call
    /// replaces the first (and resets the cooldown).
    #[pallet::storage]
    #[pallet::getter(fn pending_withdrawal)]
    pub type PendingWithdrawals<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        (u128, BlockNumberFor<T>),
        OptionQuery,
    >;

    /// Phase 2.A → 2.B kill-switch. While `false`, `pay_request` is a no-op
    /// debit (event emitted, balance unchanged) so we can measure 402 rates
    /// against real traffic without charging anyone. Governance flips to
    /// `true` in Phase 2.B with a single extrinsic.
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
        /// A billed request was paid (or would have been paid, if
        /// `DebitsEnabled` is false). `dry_run` is true during 2.A measurement.
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
        /// Withdrawal would mint more MATRA than was held in escrow — should
        /// be impossible if invariants hold; defense-in-depth.
        ///
        /// **Also raised by `execute_withdrawal`** when
        /// `MatraCurrency::deposit_creating` saturates (i.e. total issuance
        /// would overflow) and the free-balance post-condition fails. In that
        /// case the pending withdrawal entry is restored so the caller can
        /// retry without losing their escrowed balance.
        WithdrawalAmountOverflow,
        /// `request_withdrawal` was called with `amount = 0`. Use
        /// `cancel_withdrawal` to clear a prior pending entry instead.
        ZeroWithdrawal,
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
        /// Used to fund the FPS treasury account, or to gift a self-pay user.
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
        /// Idempotent on `request_id` — re-submitting the same id returns Ok
        /// without re-charging. While `DebitsEnabled` is false (2.A
        /// measurement mode), this emits the event with `dry_run: true` but
        /// leaves `Balances` untouched.
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

            // Idempotency check first — if this (payer, request_id) has
            // already been paid, return success without re-emitting or
            // re-charging. Namespacing by payer prevents cross-account
            // squatting: another account paying for the same request_id
            // does NOT consume this payer's slot.
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
        /// Setting a class to `PricingModel::FREE` is equivalent to deleting
        /// it (both produce zero charge); we keep the explicit set as a
        /// governance audit trail.
        ///
        /// **Canonical `endpoint_class` form:** lowercase snake_case ASCII,
        /// no whitespace, no path separators, ≤ 64 bytes. Examples:
        /// `receipt_submit`, `chunk_upload`, `anchor_query`. The pallet does
        /// NOT enforce this — the gateway is the trust boundary that
        /// normalizes inbound request paths into endpoint_class before
        /// calling `pay_request`. Operators submitting this extrinsic via
        /// governance MUST follow this convention so the gateway's
        /// hash-table-lookup is unambiguous.
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

        /// Request a withdrawal. Debits `Balances[caller]` immediately (so
        /// the funds can't be double-spent by simultaneous `pay_request`s),
        /// records the pending withdrawal, sets the cooldown clock.
        ///
        /// Calling again before execution replaces the prior pending
        /// withdrawal AND credits the prior amount back to Balances first
        /// (so the new call effectively cancels + replaces atomically).
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::request_withdrawal())]
        pub fn request_withdrawal(origin: OriginFor<T>, amount: u128) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // Zero-amount makes no sense — would just cancel any pending entry
            // silently. Force the caller to use `cancel_withdrawal` for that.
            ensure!(amount > 0, Error::<T>::ZeroWithdrawal);

            // Cancel any prior pending withdrawal: credit its amount back.
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
        /// **Saturation-safety:** `deposit_creating` can saturate silently
        /// if pallet-balances' `TotalIssuance` would overflow. The user's
        /// billing `Balances[who]` was already debited at `request_withdrawal`
        /// time, so if the mint silently no-ops the MATRA disappears from
        /// both ledgers. We defend by snapshotting `free_balance` before the
        /// deposit, comparing afterward, and on mismatch:
        ///   (a) re-burn whatever partial credit landed (keeps total issuance
        ///       consistent),
        ///   (b) leave `PendingWithdrawals[who]` intact so the caller can
        ///       immediately retry,
        ///   (c) return `Error::WithdrawalAmountOverflow`.
        /// The pending entry is removed only after we have proven the deposit
        /// landed in full.
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

            // Convert the u128 amount to the currency Balance type up-front
            // so we can fail cleanly before mutating any state.
            let amount_balance: BalanceOf<T> = amount
                .try_into()
                .map_err(|_| Error::<T>::WithdrawalAmountOverflow)?;

            // Snapshot pre-deposit free balance for defense-in-depth.
            let pre_balance = T::MatraCurrency::free_balance(&who);

            // Mint MATRA back to the caller's pallet-balances account.
            // `deposit_creating` returns a PositiveImbalance whose `peek()`
            // tells us how much TotalIssuance was actually increased. On
            // saturation, the imbalance is zero (or short of the requested
            // amount) and TotalIssuance is left at its cap — while the user's
            // free_balance MAY have been incremented anyway, leaving the
            // (sum-of-balances == TotalIssuance) invariant violated.
            //
            // We do NOT touch PendingWithdrawals here yet. If anything in the
            // mint path falls short of the full amount, we want the pending
            // entry intact so the caller can retry.
            let imbalance = T::MatraCurrency::deposit_creating(&who, amount_balance);
            let credited_issuance = imbalance.peek();
            // Drop the imbalance — its existence is what bumps TotalIssuance.
            drop(imbalance);

            let post_balance = T::MatraCurrency::free_balance(&who);
            let credited_free = post_balance.saturating_sub(pre_balance);

            // Two defense layers: both the imbalance returned AND the free-
            // balance delta must equal the requested amount. Any short-fall
            // means the mint saturated somewhere and we must bail to keep
            // sum(free_balances) == TotalIssuance.
            if credited_issuance < amount_balance || credited_free < amount_balance {
                // Re-burn whatever partial credit may have landed in the
                // user's account, so we don't hand them free MATRA on top of
                // their preserved pending withdrawal entry.
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

            // Deposit succeeded fully — now safe to clear the pending entry.
            PendingWithdrawals::<T>::remove(&who);

            Self::deposit_event(Event::WithdrawalExecuted { who, amount });

            Ok(())
        }

        /// Cancel a pending withdrawal: credit any prior pending amount back
        /// to the caller's billing balance. No-op if nothing is pending.
        ///
        /// This is the explicit form of the cancel-side-effect baked into
        /// `request_withdrawal`. Use this when you simply want your funds
        /// back in billing — without immediately starting a new withdrawal.
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
        /// Each `(payer, request_id)` in `ids` is checked: if the stored
        /// block is older than `current_block - retention`, the entry is
        /// removed; otherwise it is silently skipped (no error — keepers
        /// over-eagerly batching is fine). Non-existent entries are no-ops.
        ///
        /// This is intentionally NOT an `on_initialize` hook: we don't want
        /// to pay this cost out of the consensus weight budget, and we don't
        /// want sudden traffic spikes to back up the prune queue. A keeper
        /// script can target the oldest entries it observes via storage
        /// iteration and amortize the work at its own pace.
        #[pallet::call_index(8)]
        #[pallet::weight(T::WeightInfo::prune_paid_requests(ids.len() as u32))]
        pub fn prune_paid_requests(
            origin: OriginFor<T>,
            ids: Vec<(T::AccountId, H256)>,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
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

        /// Phase 2.A → 2.B switch. Governance flips this to `true` to make
        /// `pay_request` actually debit. Idempotent.
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

            // Burn from caller's MATRA account.
            let _imbalance = T::MatraCurrency::withdraw(
                &from,
                amount_balance,
                frame_support::traits::WithdrawReasons::TRANSFER,
                ExistenceRequirement::KeepAlive,
            )
            .map_err(|_| Error::<T>::TopupTransferFailed)?;

            // Credit recipient's billing balance.
            Balances::<T>::mutate(&to, |b| *b = b.saturating_add(amount));

            Self::deposit_event(Event::TopupSucceeded { from, to, amount });
            Ok(())
        }

        /// Read-only price quote — used by a future custom RPC for the
        /// gateway-side cache so the gateway doesn't need to know about
        /// `PricingModel`'s enum shape.
        pub fn quote_price(endpoint_class: &[u8], request_bytes: u64) -> Option<u128> {
            let class_bounded: BoundedVec<u8, ConstU32<MAX_ENDPOINT_CLASS_LEN>> =
                endpoint_class.to_vec().try_into().ok()?;
            Some(EndpointPrices::<T>::get(&class_bounded).compute(request_bytes))
        }
    }
}
