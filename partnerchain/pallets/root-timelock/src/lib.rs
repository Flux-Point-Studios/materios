//! Holds Root calls for a delay before they may run.
//!
//! `schedule` records only the hash of a call together with the block from
//! which it may run; the call itself is public in the scheduling extrinsic.
//! After the delay of the call's class, anyone may `enact` it by resubmitting
//! the same call, which then dispatches as Root. Until then the guardian may
//! `cancel` it, and may `fast_track` a `Recovery`-class call.
//!
//! Root cannot cancel. A compromised sudo key holds Root, and a Root veto
//! would let it cancel every attempt to replace it. For the same reason the
//! guardian cannot veto a scheduled `set_guardian`, which waits the long delay
//! instead, so a compromised guardian can be replaced but not faster than
//! the public can see it coming.
//!
//! The pallet does not stop Root from being used directly. The runtime's call
//! filter must admit the sudo key's Root only for its exempt calls and for
//! `schedule`, and its classifier must map every call to the class whose delay
//! it has to wait, using [`Call::class`] for this pallet's own calls.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::boxed::Box;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use frame_support::pallet_prelude::*;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

pub use pallet::*;

/// How long a call waits, ordered from shortest to longest wait.
#[derive(
    Encode,
    Decode,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    RuntimeDebug,
    TypeInfo,
    MaxEncodedLen,
)]
pub enum CallClass {
    /// A finality or committee recovery call that can change who holds
    /// authority. The guardian may fast-track it.
    Recovery,
    /// Everything not classified otherwise.
    Standard,
    /// Loosening a bridge or supply-valve parameter, changing the guardian,
    /// or lowering the long delay itself.
    Long,
}

/// The delay of each class, in blocks.
#[derive(
    Encode,
    Decode,
    Clone,
    Copy,
    PartialEq,
    Eq,
    RuntimeDebug,
    TypeInfo,
    MaxEncodedLen,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct DelayTable<BlockNumber> {
    pub recovery: BlockNumber,
    pub standard: BlockNumber,
    pub long: BlockNumber,
}

impl<BlockNumber: Copy + Ord + Default> DelayTable<BlockNumber> {
    pub fn of(&self, class: CallClass) -> BlockNumber {
        match class {
            CallClass::Recovery => self.recovery,
            CallClass::Standard => self.standard,
            CallClass::Long => self.long,
        }
    }

    pub fn with(mut self, class: CallClass, blocks: BlockNumber) -> Self {
        match class {
            CallClass::Recovery => self.recovery = blocks,
            CallClass::Standard => self.standard = blocks,
            CallClass::Long => self.long = blocks,
        }
        self
    }

    /// Non-zero, `recovery <= standard <= long <= max`. The ceiling bounds how
    /// long a sudo key can freeze governance by raising a delay, which it may
    /// do without waiting.
    pub fn is_valid(&self, max: BlockNumber) -> bool {
        self.recovery > BlockNumber::default()
            && self.recovery <= self.standard
            && self.standard <= self.long
            && self.long <= max
    }
}

/// Maps a call to the class whose delay it must wait.
pub trait ClassifyCall<Call> {
    fn class_of(call: &Call) -> CallClass;

    /// Whether `call` is a wrapper, such as a batch, that dispatches this
    /// pallet's `set_guardian` in turn. The guardian cannot veto a guardian
    /// change, so one is scheduled only on its own: a wrapper would either
    /// hand the guardian a veto over its replacement or carry other calls
    /// past the veto.
    fn wraps_guardian_change(call: &Call) -> bool;
}

pub type TaskId = u32;

/// Fixed execution cost of a timelock call, in picoseconds.
const BASE_REF_TIME: u64 = 20_000_000;
/// Execution cost of hashing one byte of an encoded call, in picoseconds.
const HASH_REF_TIME_PER_BYTE: u64 = 2_000;

fn call_hash_weight(call: &impl Encode) -> Weight {
    Weight::from_parts(
        BASE_REF_TIME
            .saturating_add(HASH_REF_TIME_PER_BYTE.saturating_mul(call.encoded_size() as u64)),
        0,
    )
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct Task<Hash, BlockNumber> {
    pub call_hash: Hash,
    pub class: CallClass,
    /// First block in which the call may be enacted.
    pub ready_at: BlockNumber,
    /// Whether the guardian may cancel it.
    pub vetoable: bool,
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{
        dispatch::{GetDispatchInfo, PostDispatchInfo},
        traits::IsSubType,
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::{
        traits::{Dispatchable, Hash, Saturating},
        ArithmeticError,
    };

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type RuntimeCall: Parameter
            + Dispatchable<RuntimeOrigin = Self::RuntimeOrigin, PostInfo = PostDispatchInfo>
            + GetDispatchInfo
            + IsSubType<Call<Self>>;

        type Classifier: ClassifyCall<<Self as Config>::RuntimeCall>;

        /// Delays used until genesis or a migration stores others.
        type DefaultDelays: Get<DelayTable<BlockNumberFor<Self>>>;

        /// No delay may exceed this.
        type MaxDelay: Get<BlockNumberFor<Self>>;

        /// Blocks after `ready_at` during which a call may still be enacted.
        /// A task left unenacted longer than this can no longer run.
        type EnactmentWindow: Get<BlockNumberFor<Self>>;
    }

    #[pallet::storage]
    pub type Delays<T: Config> =
        StorageValue<_, DelayTable<BlockNumberFor<T>>, ValueQuery, T::DefaultDelays>;

    #[pallet::storage]
    pub type Guardian<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    #[pallet::storage]
    pub type NextTaskId<T: Config> = StorageValue<_, TaskId, ValueQuery>;

    #[pallet::storage]
    pub type Tasks<T: Config> =
        StorageMap<_, Twox64Concat, TaskId, Task<T::Hash, BlockNumberFor<T>>, OptionQuery>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub delays: DelayTable<BlockNumberFor<T>>,
        pub guardian: Option<T::AccountId>,
    }

    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                delays: T::DefaultDelays::get(),
                guardian: None,
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            assert!(
                self.delays.is_valid(T::MaxDelay::get()),
                "root-timelock genesis delays must be non-zero, ordered and at most MaxDelay"
            );
            Delays::<T>::put(self.delays);
            if let Some(guardian) = &self.guardian {
                Guardian::<T>::put(guardian);
            }
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        Scheduled {
            id: TaskId,
            call_hash: T::Hash,
            class: CallClass,
            ready_at: BlockNumberFor<T>,
        },
        Cancelled {
            id: TaskId,
        },
        FastTracked {
            id: TaskId,
        },
        Enacted {
            id: TaskId,
        },
        DelaySet {
            class: CallClass,
            blocks: BlockNumberFor<T>,
        },
        GuardianSet {
            guardian: Option<T::AccountId>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        UnknownTask,
        CallHashMismatch,
        NotReady,
        Expired,
        NotFastTrackable,
        InvalidDelays,
        NotVetoable,
        /// The call now classifies into a longer class than the one it
        /// waited; schedule it again.
        ClassRaised,
        /// A `set_guardian` inside a wrapper; schedule it on its own.
        GuardianChangeNotAlone,
        /// The task is already ready or has expired. A fast-track only brings
        /// a pending task forward; it never extends or revives one.
        AlreadyReady,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn integrity_test() {
            assert!(
                T::DefaultDelays::get().is_valid(T::MaxDelay::get()),
                "DefaultDelays must be non-zero, ordered and at most MaxDelay"
            );
            assert!(
                T::EnactmentWindow::get() > BlockNumberFor::<T>::default(),
                "EnactmentWindow must be non-zero"
            );
        }

        #[cfg(feature = "try-runtime")]
        fn try_state(_n: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
            ensure!(
                Delays::<T>::get().is_valid(T::MaxDelay::get()),
                "stored delays are zero, out of order or above MaxDelay"
            );
            Ok(())
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Record `call` to run as Root once its class's delay has passed.
        #[pallet::call_index(0)]
        #[pallet::weight(
            T::DbWeight::get().reads_writes(3, 2).saturating_add(call_hash_weight(call.as_ref()))
        )]
        pub fn schedule(
            origin: OriginFor<T>,
            call: Box<<T as Config>::RuntimeCall>,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(
                !T::Classifier::wraps_guardian_change(&call),
                Error::<T>::GuardianChangeNotAlone
            );
            let class = T::Classifier::class_of(&call);
            let vetoable = !matches!(call.is_sub_type(), Some(Call::set_guardian { .. }));
            let ready_at = frame_system::Pallet::<T>::block_number()
                .saturating_add(Delays::<T>::get().of(class));
            let id = NextTaskId::<T>::get();
            NextTaskId::<T>::put(id.checked_add(1).ok_or(ArithmeticError::Overflow)?);
            let call_hash = T::Hashing::hash_of(&call);
            Tasks::<T>::insert(
                id,
                Task {
                    call_hash,
                    class,
                    ready_at,
                    vetoable,
                },
            );
            Self::deposit_event(Event::Scheduled {
                id,
                call_hash,
                class,
                ready_at,
            });
            Ok(())
        }

        /// The guardian's veto. Operational so a full block cannot keep it out.
        #[pallet::call_index(1)]
        #[pallet::weight((
            T::DbWeight::get().reads_writes(2, 1).saturating_add(Weight::from_parts(BASE_REF_TIME, 0)),
            DispatchClass::Operational,
        ))]
        pub fn cancel(origin: OriginFor<T>, id: TaskId) -> DispatchResult {
            Self::ensure_guardian(origin)?;
            let task = Tasks::<T>::get(id).ok_or(Error::<T>::UnknownTask)?;
            ensure!(task.vetoable, Error::<T>::NotVetoable);
            Tasks::<T>::remove(id);
            Self::deposit_event(Event::Cancelled { id });
            Ok(())
        }

        /// The guardian's co-signature: a pending `Recovery` task becomes
        /// ready now.
        #[pallet::call_index(2)]
        #[pallet::weight((
            T::DbWeight::get().reads_writes(2, 1).saturating_add(Weight::from_parts(BASE_REF_TIME, 0)),
            DispatchClass::Operational,
        ))]
        pub fn fast_track(origin: OriginFor<T>, id: TaskId) -> DispatchResult {
            Self::ensure_guardian(origin)?;
            Tasks::<T>::try_mutate(id, |task| {
                let task = task.as_mut().ok_or(Error::<T>::UnknownTask)?;
                ensure!(
                    task.class == CallClass::Recovery,
                    Error::<T>::NotFastTrackable
                );
                let now = frame_system::Pallet::<T>::block_number();
                ensure!(now < task.ready_at, Error::<T>::AlreadyReady);
                task.ready_at = now;
                Ok::<(), DispatchError>(())
            })?;
            Self::deposit_event(Event::FastTracked { id });
            Ok(())
        }

        /// Run a ready task's call as Root. Anyone may submit it. A call that
        /// fails leaves the task in place, so it can be retried until it
        /// expires. The call is classified again, because a class that depends
        /// on state (whether a threshold change lowers it) may have risen
        /// since it was scheduled.
        #[pallet::call_index(3)]
        #[pallet::weight({
            let info = call.get_dispatch_info();
            (enact_overhead::<T>(call.as_ref()).saturating_add(info.weight), info.class)
        })]
        pub fn enact(
            origin: OriginFor<T>,
            id: TaskId,
            call: Box<<T as Config>::RuntimeCall>,
        ) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;
            let task = Tasks::<T>::get(id).ok_or(Error::<T>::UnknownTask)?;
            ensure!(
                T::Hashing::hash_of(&call) == task.call_hash,
                Error::<T>::CallHashMismatch
            );
            let now = frame_system::Pallet::<T>::block_number();
            ensure!(now >= task.ready_at, Error::<T>::NotReady);
            ensure!(
                now <= task.ready_at.saturating_add(T::EnactmentWindow::get()),
                Error::<T>::Expired
            );
            ensure!(
                T::Classifier::class_of(&call) <= task.class,
                Error::<T>::ClassRaised
            );
            Tasks::<T>::remove(id);
            let overhead = enact_overhead::<T>(call.as_ref());
            let post = call
                .dispatch(frame_system::RawOrigin::Root.into())
                .map_err(|e| e.error)?;
            Self::deposit_event(Event::Enacted { id });
            Ok(post
                .actual_weight
                .map(|w| w.saturating_add(overhead))
                .into())
        }

        /// Takes effect at once. The runtime's filter lets the sudo key raise
        /// a delay immediately; lowering one has to be scheduled, and waits
        /// at least the class's current delay.
        #[pallet::call_index(4)]
        #[pallet::weight(
            T::DbWeight::get().reads_writes(1, 1).saturating_add(Weight::from_parts(BASE_REF_TIME, 0))
        )]
        pub fn set_delay(
            origin: OriginFor<T>,
            class: CallClass,
            blocks: BlockNumberFor<T>,
        ) -> DispatchResult {
            ensure_root(origin)?;
            let delays = Delays::<T>::get().with(class, blocks);
            ensure!(
                delays.is_valid(T::MaxDelay::get()),
                Error::<T>::InvalidDelays
            );
            Delays::<T>::put(delays);
            Self::deposit_event(Event::DelaySet { class, blocks });
            Ok(())
        }

        #[pallet::call_index(5)]
        #[pallet::weight(T::DbWeight::get().writes(1).saturating_add(Weight::from_parts(BASE_REF_TIME, 0)))]
        pub fn set_guardian(
            origin: OriginFor<T>,
            guardian: Option<T::AccountId>,
        ) -> DispatchResult {
            ensure_root(origin)?;
            Guardian::<T>::set(guardian.clone());
            Self::deposit_event(Event::GuardianSet { guardian });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn ensure_guardian(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                Guardian::<T>::get().as_ref() == Some(&who),
                DispatchError::BadOrigin
            );
            Ok(())
        }
    }

    impl<T: Config> Call<T> {
        /// The class this pallet's own call waits when scheduled. Lowering
        /// the recovery delay waits the standard delay so the guardian cannot
        /// fast-track it.
        pub fn class(&self) -> CallClass {
            match self {
                Call::set_guardian { .. }
                | Call::set_delay {
                    class: CallClass::Long,
                    ..
                } => CallClass::Long,
                _ => CallClass::Standard,
            }
        }
    }

    /// The task read and removal, the classifier's reads, and hashing.
    fn enact_overhead<T: Config>(call: &<T as Config>::RuntimeCall) -> Weight {
        T::DbWeight::get()
            .reads_writes(3, 1)
            .saturating_add(call_hash_weight(call))
    }
}
