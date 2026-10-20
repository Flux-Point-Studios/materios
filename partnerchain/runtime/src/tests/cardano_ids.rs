//! Settlement binds the Cardano network genesis stores in `CardanoIds`.
//! Preprod's genesis predates the item, so the upgrade stores the ids
//! preprod's settlement has bound since its genesis, and every digest and
//! evidence check it computes afterwards is the one spec 242 computed over the
//! same state.

use super::{
    chain_identity::seat_committee,
    root_timelock::{alice_committee, build_chain_spec},
    settlement_bonds::{chain, settlement_events, settlement_storage},
};
use crate::{migrations::PREPROD_GENESIS_HASH, *};
use frame_support::{assert_noop, assert_ok};
use pallet_intent_settlement::{
    attest_batch_settle_payload, expire_policy_attested_payload, request_voucher_payload,
    settle_claim_attested_payload,
    types::{
        CardanoIdentity, ExpiryEvidence, IntentStatus, SettlementEvidence,
        CARDANO_MAINNET_NETWORK_MAGIC, CARDANO_MAINNET_SHELLEY_GENESIS_HASH,
    },
    voucher_canonicalize::split_type0_address_bytes,
    BatchAttestEntryBytes, CardanoIds, Claims, Error, Intents, SettlementStorageVersion, Vouchers,
    NAMED_RESERVE_VERSION, SETTLEMENT_STORAGE_VERSION,
};
use sp_core::{sr25519, Pair};

/// Preprod's published Cardano environment
/// (book.world.dev.cardano.org/environments/preprod): its node config's
/// `ShelleyGenesisHash` is the blake2b-256 of its `shelley-genesis.json`,
/// whose `networkMagic` is 1.
#[test]
fn the_preprod_ids_are_those_of_preprods_published_shelley_genesis() {
    let shelley = include_bytes!("cardano-preprod-shelley-genesis.json");
    let config: serde_json::Value =
        serde_json::from_str(include_str!("cardano-preprod-config.json")).expect("JSON");
    let published: serde_json::Value = serde_json::from_slice(shelley).expect("JSON");
    assert_eq!(
        published["networkMagic"],
        serde_json::json!(CARDANO_PREPROD.network_magic)
    );
    assert_eq!(
        sp_io::hashing::blake2_256(shelley),
        CARDANO_PREPROD.mainchain_genesis_hash
    );
    assert_eq!(
        config["ShelleyGenesisHash"],
        serde_json::json!(sp_core::hexdisplay::HexDisplay::from(
            &CARDANO_PREPROD.mainchain_genesis_hash
        )
        .to_string())
    );
    assert_eq!(CARDANO_PREPROD.aegis_policy_v1_script_hash, [0; 28]);
}

fn hex(field: &serde_json::Value) -> Vec<u8> {
    sp_core::bytes::from_hex(field.as_str().expect("a hex string")).expect("valid hex")
}

/// Preprod's settlement state at a finalized spec-242 block, read from a
/// node: storage version 4, and no Cardano ids stored.
fn preprod_settlement_state() -> (BlockNumber, Vec<(Vec<u8>, Vec<u8>)>) {
    let snapshot: serde_json::Value =
        serde_json::from_str(include_str!("preprod-settlement-2362775.json"))
            .expect("the snapshot is JSON");
    let entries = snapshot["entries"]
        .as_array()
        .expect("snapshot entries")
        .iter()
        .map(|entry| (hex(&entry["key"]), hex(&entry["value"])))
        .collect();
    let block = snapshot["block_number"].as_u64().expect("a block number");
    (block as BlockNumber, entries)
}

/// The block after the snapshot on a chain whose genesis is `genesis`,
/// holding preprod's settlement state and `balances`.
fn holding_preprods_settlement(
    genesis: H256,
    balances: Vec<(AccountId, Balance)>,
) -> sp_io::TestExternalities {
    let (block, entries) = preprod_settlement_state();
    let mut ext = chain(balances);
    ext.execute_with(|| {
        frame_system::BlockHash::<Runtime>::insert(0, genesis);
        System::set_block_number(block + 1);
        for (key, value) in &entries {
            sp_io::storage::set(key, value);
        }
        assert_eq!(
            SettlementStorageVersion::<Runtime>::get(),
            NAMED_RESERVE_VERSION
        );
        assert_eq!(CardanoIds::<Runtime>::get(), None);
    });
    ext
}

#[test]
fn upgrading_preprod_stores_the_cardano_ids_it_has_bound_and_changes_nothing_else() {
    holding_preprods_settlement(PREPROD_GENESIS_HASH, Vec::new()).execute_with(|| {
        let before = settlement_storage();

        Executive::execute_on_runtime_upgrade();

        assert_eq!(CardanoIds::<Runtime>::get(), Some(CARDANO_PREPROD));
        assert_eq!(
            SettlementStorageVersion::<Runtime>::get(),
            SETTLEMENT_STORAGE_VERSION
        );
        let touched = [
            SettlementStorageVersion::<Runtime>::hashed_key().to_vec(),
            CardanoIds::<Runtime>::hashed_key().to_vec(),
        ];
        let untouched = |entries: Vec<(Vec<u8>, Vec<u8>)>| {
            entries
                .into_iter()
                .filter(|(key, _)| !touched.contains(key))
                .collect::<Vec<_>>()
        };
        let upgraded = settlement_storage();
        assert_eq!(untouched(upgraded.clone()), untouched(before));
        assert!(settlement_events().is_empty());

        Executive::execute_on_runtime_upgrade();
        assert_eq!(settlement_storage(), upgraded);
    });
}

/// The upgrade knows only preprod's ids. A version-4 chain with another
/// genesis keeps version 4 and stores none, so its settlement refuses rather
/// than bind Cardano preprod.
#[test]
fn upgrading_a_version_4_chain_other_than_preprod_stores_no_cardano_ids() {
    let requester = AccountId::from([0x31; 32]);
    let funded = IntentSettlementMinSettlementBond::get() + ExistentialDeposit::get();
    holding_preprods_settlement(H256::repeat_byte(0x0b), vec![(requester.clone(), funded)])
        .execute_with(|| {
            let before = settlement_storage();

            Executive::execute_on_runtime_upgrade();

            assert_eq!(settlement_storage(), before);
            let (claim_id, evidence) =
                unsettled_claim_evidence(CARDANO_PREPROD.mainchain_genesis_hash);
            assert_noop!(
                IntentSettlement::request_settle(
                    RuntimeOrigin::signed(requester),
                    claim_id,
                    evidence.cardano_tx_hash,
                    false,
                    evidence,
                    IntentSettlementMinSettlementBond::get(),
                ),
                Error::<Runtime>::CardanoIdsMissing
            );
        });
}

/// What spec 242 computed over the snapshot's state, recorded with that
/// runtime's own code (materios 37dd387, pinning settlement 0757de3): each
/// voucher's digest, its voucher request payload and its settlement
/// attestation payloads, the batch attestation over every voucher, and each
/// policy's expiry attestation, all over the evidence `inputs` names.
fn recorded() -> serde_json::Value {
    serde_json::from_str(include_str!("preprod-settlement-vectors-2362775.json"))
        .expect("the vectors are JSON")
}

/// Evidence of the snapshot's one unsettled claim, as the recorded payloads
/// take it, naming `shelley`.
fn unsettled_claim_evidence(shelley: [u8; 32]) -> (H256, SettlementEvidence) {
    let recorded = recorded();
    let mut unsettled = Claims::<Runtime>::iter().filter(|(_, claim)| !claim.settled);
    let (claim_id, claim) = unsettled.next().expect("one claim is unsettled");
    assert!(unsettled.next().is_none());
    let voucher = Vouchers::<Runtime>::get(claim_id).expect("its voucher");
    let (payment, _) = split_type0_address_bytes(voucher.beneficiary_cardano_addr.as_slice())
        .expect("a type-0 address");
    let inputs = &recorded["inputs"];
    let evidence = SettlementEvidence {
        cardano_tx_hash: hex(&inputs["cardano_tx_hash"])
            .try_into()
            .expect("32 bytes"),
        observed_at_depth: inputs["observed_at_depth"].as_u64().expect("a depth") as u32,
        observed_slot: inputs["observed_slot"].as_u64().expect("a slot"),
        beneficiary_addr_hash: payment,
        amount_lovelace: claim.amount_ada,
        mainchain_genesis_hash: shelley,
    };
    (claim_id, evidence)
}

/// After the upgrade preprod's settlement computes, from the ids it now
/// stores, every digest spec 242 computed: the voucher digests and payloads
/// equal the recorded ones, the unsettled claim settles on a bundle signed
/// over its recorded settlement payload, and the evidence checks accept
/// preprod's Shelley genesis and refuse mainnet's, as spec 242's did.
#[test]
fn upgraded_preprod_computes_every_digest_and_evidence_check_spec_242_did() {
    let recorded = recorded();
    let signers = [
        sr25519::Pair::from_seed(&[19; 32]),
        sr25519::Pair::from_seed(&[20; 32]),
    ];
    let requester = AccountId::from([0x31; 32]);
    let bond = IntentSettlementMinSettlementBond::get();
    let funded = bond + ExistentialDeposit::get();
    holding_preprods_settlement(PREPROD_GENESIS_HASH, vec![(requester.clone(), funded)])
        .execute_with(|| {
            Executive::execute_on_runtime_upgrade();
            let chain_id = IntentSettlementMateriosChainId::get().0;
            let cardano = IntentSettlement::cardano_ids().expect("the upgrade stored them");
            assert_eq!(hex(&recorded["materios_chain_id"]), chain_id.to_vec());
            assert_eq!(
                recorded["network_magic"],
                serde_json::json!(cardano.network_magic)
            );
            assert_eq!(
                hex(&recorded["mainchain_genesis_hash"]),
                cardano.mainchain_genesis_hash.to_vec()
            );
            assert_eq!(
                hex(&recorded["aegis_policy_v1_script_hash"]),
                cardano.aegis_policy_v1_script_hash.to_vec()
            );

            let (unsettled, evidence) = unsettled_claim_evidence(cardano.mainchain_genesis_hash);
            let vouchers = recorded["vouchers"].as_array().expect("vouchers");
            assert_eq!(vouchers.len(), Vouchers::<Runtime>::iter().count());
            let mut entries = Vec::new();
            let mut unsettled_payload = None;
            for recorded_voucher in vouchers {
                let claim_id = H256::from_slice(&hex(&recorded_voucher["claim_id"]));
                let voucher = Vouchers::<Runtime>::get(claim_id).expect("a recorded voucher");
                let claim = Claims::<Runtime>::get(claim_id).expect("its claim");
                let digest = IntentSettlement::compute_canonical_voucher_digest(&voucher)
                    .expect("the voucher digest");
                assert_eq!(digest.to_vec(), hex(&recorded_voucher["voucher_digest"]));
                assert_eq!(
                    request_voucher_payload(
                        &chain_id,
                        &claim_id,
                        &claim.intent_id,
                        &digest,
                        &voucher.batch_fairness_proof_digest,
                    )
                    .to_vec(),
                    hex(&recorded_voucher["request_voucher_payload"])
                );
                let (payment, _) =
                    split_type0_address_bytes(voucher.beneficiary_cardano_addr.as_slice())
                        .expect("a type-0 address");
                let payloads = recorded_voucher["attest_settle_payloads"]
                    .as_array()
                    .expect("both settlement modes");
                for (settled_direct, payload) in [false, true].into_iter().zip(payloads) {
                    assert_eq!(
                        settle_claim_attested_payload(
                            &chain_id,
                            &claim_id,
                            &digest,
                            &evidence.cardano_tx_hash,
                            settled_direct,
                            &payment,
                            claim.amount_ada,
                            evidence.observed_at_depth,
                            evidence.observed_slot,
                            &cardano.mainchain_genesis_hash,
                        )
                        .to_vec(),
                        hex(payload)
                    );
                }
                if claim_id == unsettled {
                    unsettled_payload = Some(hex(&payloads[0]));
                }
                entries.push(BatchAttestEntryBytes {
                    claim_id,
                    voucher_digest: digest,
                    cardano_tx_hash: evidence.cardano_tx_hash,
                    settled_direct: false,
                    beneficiary_hash: payment,
                    amount_ada: claim.amount_ada,
                    depth: evidence.observed_at_depth,
                    slot: evidence.observed_slot,
                    mc_genesis: cardano.mainchain_genesis_hash,
                });
            }
            assert_eq!(
                attest_batch_settle_payload(&chain_id, &entries).to_vec(),
                hex(&recorded["attest_batch_settle_payload"])
            );
            let mut expired = None;
            for recorded_expiry in recorded["expiries"].as_array().expect("expiries") {
                let intent_id = H256::from_slice(&hex(&recorded_expiry["intent_id"]));
                let intent = Intents::<Runtime>::get(intent_id).expect("a recorded intent");
                let policy =
                    IntentSettlement::resolve_intent_policy_id(&intent).expect("a policy intent");
                assert_eq!(
                    expire_policy_attested_payload(
                        &chain_id,
                        &intent_id,
                        &policy,
                        &evidence.cardano_tx_hash,
                        evidence.observed_at_depth,
                        evidence.observed_slot,
                        &cardano.mainchain_genesis_hash,
                    )
                    .to_vec(),
                    hex(&recorded_expiry["attest_expire_policy_payload"])
                );
                if intent.status == IntentStatus::Expired {
                    expired = Some((intent_id, policy));
                }
            }

            let mainnet_evidence = SettlementEvidence {
                mainchain_genesis_hash: CARDANO_MAINNET_SHELLEY_GENESIS_HASH,
                ..evidence
            };
            assert_noop!(
                IntentSettlement::request_settle(
                    RuntimeOrigin::signed(requester.clone()),
                    unsettled,
                    evidence.cardano_tx_hash,
                    false,
                    mainnet_evidence,
                    bond,
                ),
                Error::<Runtime>::WrongMainchainGenesis
            );
            assert_ok!(IntentSettlement::request_settle(
                RuntimeOrigin::signed(requester),
                unsettled,
                evidence.cardano_tx_hash,
                false,
                evidence,
                bond,
            ));
            let member = seat_committee(&[&signers[0], &signers[1]]);
            let payload = unsettled_payload.expect("the unsettled claim's payload");
            let bundle = signers
                .iter()
                .map(|pair| (pair.public().0, pair.sign(&payload).0))
                .collect();
            assert_ok!(IntentSettlement::attest_settle(
                RuntimeOrigin::signed(member.clone()),
                unsettled,
                bundle
            ));
            assert!(
                Claims::<Runtime>::get(unsettled)
                    .expect("the claim stays")
                    .settled
            );

            let (intent_id, policy) = expired.expect("a recorded policy intent has expired");
            let expiry = ExpiryEvidence {
                cardano_tx_hash: evidence.cardano_tx_hash,
                observed_at_depth: evidence.observed_at_depth,
                observed_slot: evidence.observed_slot,
                mainchain_genesis_hash: cardano.mainchain_genesis_hash,
                policy_id_witness: policy,
            };
            assert_noop!(
                IntentSettlement::request_expire_policy(
                    RuntimeOrigin::signed(member.clone()),
                    intent_id,
                    expiry.cardano_tx_hash,
                    ExpiryEvidence {
                        mainchain_genesis_hash: CARDANO_MAINNET_SHELLEY_GENESIS_HASH,
                        ..expiry
                    },
                ),
                Error::<Runtime>::WrongMainchainGenesis
            );
            assert_ok!(IntentSettlement::request_expire_policy(
                RuntimeOrigin::signed(member),
                intent_id,
                expiry.cardano_tx_hash,
                expiry,
            ));
        });
}

/// Settlement's pre- and post-upgrade checks, and the seeding migration's,
/// pass over preprod's state. Every other pallet stands at its in-code
/// storage version, as genesis leaves it.
#[cfg(feature = "try-runtime")]
#[test]
fn preprods_settlement_state_passes_the_upgrade_checks() {
    use frame_support::traits::OnGenesis;
    holding_preprods_settlement(PREPROD_GENESIS_HASH, Vec::new()).execute_with(|| {
        AllPalletsWithSystem::on_genesis();
        Executive::try_runtime_upgrade(frame_try_runtime::UpgradeCheckSelect::PreAndPost)
            .expect("every pre- and post-upgrade check passes");
        assert_eq!(CardanoIds::<Runtime>::get(), Some(CARDANO_PREPROD));
        assert_eq!(
            SettlementStorageVersion::<Runtime>::get(),
            SETTLEMENT_STORAGE_VERSION
        );
    });
}

/// The genesis builder refuses a chain spec that names no Cardano network
/// for settlement, names none with a zero network magic or Shelley genesis
/// hash, or names Cardano mainnet in part or with no Aegis policy; it builds
/// preprod's ids and mainnet's with its deployed policy.
#[test]
fn a_chain_spec_must_name_the_cardano_network_settlement_binds() {
    let spec = |cardano_ids: serde_json::Value| {
        build_chain_spec(serde_json::json!({
            "rootTimelock": { "unguarded": true },
            "sessionCommitteeManagement": alice_committee(),
            "intentSettlement": { "cardanoIds": cardano_ids },
        }))
    };
    let mainnet = CardanoIdentity {
        network_magic: CARDANO_MAINNET_NETWORK_MAGIC,
        mainchain_genesis_hash: CARDANO_MAINNET_SHELLEY_GENESIS_HASH,
        aegis_policy_v1_script_hash: [0x5a; 28],
    };
    assert_eq!(spec(serde_json::json!(CARDANO_PREPROD)), Ok(()));
    assert_eq!(spec(serde_json::json!(mainnet)), Ok(()));
    for (ids, reason) in [
        (serde_json::Value::Null, "names no Cardano network"),
        (
            serde_json::json!(CardanoIdentity {
                network_magic: 0,
                ..CARDANO_PREPROD
            }),
            "network magic 0",
        ),
        (
            serde_json::json!(CardanoIdentity {
                mainchain_genesis_hash: [0; 32],
                ..CARDANO_PREPROD
            }),
            "all-zero Shelley genesis hash",
        ),
        (
            serde_json::json!(CardanoIdentity {
                mainchain_genesis_hash: CARDANO_PREPROD.mainchain_genesis_hash,
                ..mainnet
            }),
            "name it only together",
        ),
        (
            serde_json::json!(CardanoIdentity {
                aegis_policy_v1_script_hash: [0; 28],
                ..mainnet
            }),
            "no aegis_policy_v1 script hash",
        ),
    ] {
        let refused = spec(ids.clone()).expect_err("refused");
        assert!(refused.contains(reason), "{ids}: {refused}");
    }
}
