use crate as pallet_root_timelock;
use crate::{CallClass, ClassifyCall, DelayTable};
use frame_support::{derive_impl, parameter_types, traits::ConstU64};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        RootTimelock: pallet_root_timelock,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

pub const GUARDIAN: u64 = 7;
pub const ANYONE: u64 = 9;
pub const MAX_DELAY: u64 = 100;

parameter_types! {
    pub const TestDelays: DelayTable<u64> = DelayTable { recovery: 2, standard: 10, long: 30 };
    pub storage RemarkIsLong: bool = false;
}

/// `remark` stands in for a recovery call whose class depends on state (it
/// becomes long while `RemarkIsLong` is set), `kill_storage` for a long-delay
/// call, and everything else is standard.
pub struct TestClassifier;
impl ClassifyCall<RuntimeCall> for TestClassifier {
    fn class_of(call: &RuntimeCall) -> CallClass {
        match call {
            RuntimeCall::System(frame_system::Call::remark { .. }) if RemarkIsLong::get() => {
                CallClass::Long
            }
            RuntimeCall::System(frame_system::Call::remark { .. }) => CallClass::Recovery,
            RuntimeCall::System(frame_system::Call::kill_storage { .. }) => CallClass::Long,
            RuntimeCall::RootTimelock(call) => call.class(),
            _ => CallClass::Standard,
        }
    }
}

impl pallet_root_timelock::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type Classifier = TestClassifier;
    type DefaultDelays = TestDelays;
    type MaxDelay = ConstU64<MAX_DELAY>;
    type EnactmentWindow = ConstU64<5>;
}

pub fn genesis_ext(delays: DelayTable<u64>) -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_root_timelock::GenesisConfig::<Test> {
        delays,
        guardian: Some(GUARDIAN),
    }
    .assimilate_storage(&mut storage)
    .unwrap();
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    genesis_ext(TestDelays::get())
}
