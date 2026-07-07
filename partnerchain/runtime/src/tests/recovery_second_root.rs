//! `pallet_recovery` wiring — the SECOND, independent path to Root (#492).
//!
//! `pallet_sudo` alone is the bootstrap paradox: lose the sudo key and every
//! governance lever is closed forever, a reset-class outcome no forkless upgrade
//! can reach. Social recovery gives an independent, geo-distributed friend set a
//! delayed path to recover the sudo ACCOUNT and re-key sudo. These tests prove
//! the wiring is (1) inert by default — no account is recoverable at genesis, so
//! governance behaviour is byte-identical to pre-#492 — and (2) functional: the
//! ceremony's core action, `create_recovery` on the account to be protected,
//! installs a recovery config. The pallet's own recover-flow correctness is
//! covered upstream; this asserts MY runtime wiring.

use crate::*;
use frame_support::assert_ok;
use sp_io::TestExternalities;
use sp_keyring::Sr25519Keyring::{Alice, Bob, Charlie, Dave};
use sp_runtime::BuildStorage;

const FUND: Balance = 1_000_000_000;

fn acct(k: sp_keyring::Sr25519Keyring) -> AccountId {
    k.to_account_id()
}

fn new_test_ext() -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis builds");
    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![
            (acct(Alice), FUND),
            (acct(Bob), FUND),
            (acct(Charlie), FUND),
            (acct(Dave), FUND),
        ],
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis builds");
    storage.into()
}

#[test]
fn recovery_inert_by_default() {
    new_test_ext().execute_with(|| {
        // pallet_recovery has no genesis: no account is recoverable until an
        // operator arms it, so the second path adds zero behaviour at launch.
        assert_eq!(pallet_recovery::Recoverable::<Runtime>::iter().count(), 0);
        assert!(pallet_recovery::Recoverable::<Runtime>::get(acct(Alice)).is_none());
    });
}

#[test]
fn second_root_path_configurable_via_create_recovery() {
    new_test_ext().execute_with(|| {
        // The ceremony's core action: an account (stand-in for the sudo key)
        // configures a geo-distributed friend set that can socially-recover it.
        // create_recovery requires the friends list sorted and unique.
        let mut friends = vec![acct(Bob), acct(Charlie), acct(Dave)];
        friends.sort();
        assert_ok!(Recovery::create_recovery(
            RuntimeOrigin::signed(acct(Alice)),
            friends,
            2,   // threshold: 2-of-3 friends must vouch
            100, // delay_period (blocks): the on-chain veto window
        ));
        // The independent recovery path now EXISTS for this account.
        assert!(pallet_recovery::Recoverable::<Runtime>::get(acct(Alice)).is_some());
    });
}
