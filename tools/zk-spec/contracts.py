import hashlib
import random
import unittest

from check import Driver, ROOT


DRIVER = Driver(ROOT)


class RuntimeCase(unittest.TestCase):
    def query(self, operation, **payload):
        result = DRIVER.query(operation, payload)
        self.assertEqual(result["executor"], "wasm")
        self.assertRegex(result["runtime_sha256"], r"^[0-9a-f]{64}$")
        return result

    def rejected_without_value_effects(self, result):
        self.assertIs(result["accepted"], False)
        self.assertEqual(result["value_before"], result["value_after"])
        self.assertEqual(result["nullifiers_before"], result["nullifiers_after"])


class MainnetIsolation(RuntimeCase):
    def test_reviewed_post_aj_launch_artifacts_are_identical(self):
        result = self.query("mainnet-isolation", baseline="reviewed-launch-after-aj-66")
        for name in ("node", "runtime", "genesis", "metadata", "imports"):
            self.assertRegex(result["baseline"][name], r"^[0-9a-f]{64}$")
            self.assertEqual(result["baseline"][name], result["candidate"][name])
        self.assertEqual(result["baseline_issue66_tests"], 8)
        self.assertEqual(result["genesis_zk_pallets"], [])
        self.assertEqual(result["node_extra_host_imports"], [])
        self.assertGreater(result["preprod_zk_pallet_count"], 0)

    def test_gate_rejects_each_contaminated_launch_artifact(self):
        for name in ("node", "runtime", "genesis", "metadata", "imports"):
            with self.subTest(name=name):
                result = self.query("mainnet-isolation-mutant", artifact=name)
                self.assertNotEqual(result["gate_exit"], 0)
                self.assertEqual(result["changed_artifacts"], [name])


class SaplingWasm(RuntimeCase):
    def test_pinned_no_std_build_and_imports(self):
        result = self.query("sapling-build")
        self.assertEqual(result["rustc"], "1.85.0")
        self.assertEqual(result["target"], "wasm32-unknown-unknown")
        self.assertIn("--no-default-features", result["argv"])
        self.assertEqual(result["sdk"], "polkadot-stable2409-4")
        self.assertGreater(result["wasm_bytes"], 0)
        self.assertLessEqual(result["runtime_bytes"], 5 * 1024 * 1024)
        self.assertTrue(result["baseline_substrate_imports"])
        self.assertLessEqual(set(result["imports"]), set(result["baseline_substrate_imports"]))

    def test_real_proofs_and_every_proof_bit_mutation(self):
        result = self.query("sapling-vectors", min_proofs=20, mutate="every-proof-bit")
        vectors = result["vectors"]
        self.assertGreaterEqual(len(vectors), 20)
        self.assertEqual(len({v["sha256"] for v in vectors}), len(vectors))
        for vector in vectors:
            proof = bytes.fromhex(vector["proof_hex"])
            self.assertEqual(len(proof), 192)
            self.assertEqual(hashlib.sha256(proof).hexdigest(), vector["sha256"])
            self.assertEqual(vector["source_network"], "zcash-mainnet")
            self.assertRegex(vector["transaction_id"], r"^[0-9a-f]{64}$")
            self.assertIs(vector["accepted"], True)
            mutations = vector["mutations"]
            self.assertEqual([m["bit"] for m in mutations], list(range(len(proof) * 8)))
            self.assertTrue(all(m["accepted"] is False for m in mutations))

    def test_full_bundle_on_slowest_supported_validator(self):
        result = self.query("sapling-benchmark", spends=1, outputs=2, samples=100)
        self.assertEqual(result["bundle"], {"spends": 1, "outputs": 2, "signatures": "all"})
        self.assertEqual(result["hardware"], result["reviewed_slowest_validator"])
        samples = result["milliseconds"]
        self.assertEqual(len(samples), 100)
        self.assertTrue(all(isinstance(x, (int, float)) and 0 < x <= 400 for x in samples))
        expected_cap = max(1, int(750 // max(samples)))
        self.assertLessEqual(result["bundle_cap"], expected_cap)
        if max(samples) > 150:
            self.assertEqual(result["next_phase"], "host-acceleration-before-value-activation")
        self.assertGreaterEqual(result["declared_weight_ms"], max(samples))


class SupplyInvariant(RuntimeCase):
    def test_ten_thousand_mixed_runtime_transitions(self):
        rng = random.Random(66)
        operations = []
        for _ in range(2000):
            amount = rng.randint(1, 100)
            operations.extend({"route": route, "amount": amount} for route in
                              ("a-u", "u-s", "invalid-double-spend", "s-u", "u-a"))
        result = self.query("hybrid-sequence", operations=operations, initial=1_000_000,
                            seed=66, reward_emission=False, wallets="test-viewing-keys")
        states = result["states"]
        self.assertEqual(len(states), 10001)
        a, u, s = 1_000_000, 0, 0
        for i, state in enumerate(states):
            if i:
                operation = operations[i - 1]
                amount = operation["amount"]
                route = operation["route"]
                self.assertEqual(state["accepted"], route != "invalid-double-spend")
                if route == "a-u":
                    a, u = a - amount, u + amount
                elif route == "u-s":
                    u, s = u - amount, s + amount
                elif route == "s-u":
                    s, u = s - amount, u + amount
                elif route == "u-a":
                    u, a = u - amount, a + amount
                else:
                    self.assertEqual(state["value_root"], states[i - 1]["value_root"])
            self.assertEqual(sum(state["accounts_excluding_escrows"].values()), a)
            self.assertEqual(sum(state["utxos"].values()), u)
            self.assertEqual(sum(state["decrypted_unspent_notes"].values()), s)
            self.assertEqual(state["u_escrow"], u)
            self.assertEqual(state["s_escrow"], s)
            self.assertEqual(state["shielded_in"] - state["shielded_out"], s)
            self.assertEqual(state["issuance"], a + u + s)
            self.assertEqual(state["issuance"], 1_000_000)
            self.assertEqual(state["escrow_motra_generated"], 0)

    def test_boundary_amounts_and_atomic_rejection(self):
        for scenario in ("u64-overflow", "negative-value-balance", "escrow-drain",
                         "reserved-balance-spend", "dust-reaping", "failure-after-debit"):
            with self.subTest(scenario=scenario):
                self.rejected_without_value_effects(self.query("hybrid-invalid", scenario=scenario))


class MidnightBlackhole(RuntimeCase):
    def test_core_runs_in_network_namespace_with_no_egress(self):
        result = self.query("midnight-blackhole", profile="no-midnight", network="isolated-netns")
        self.assertNotEqual(result["host_netns_inode"], result["test_netns_inode"])
        self.assertEqual(result["external_routes"], [])
        self.assertTrue(result["denied_probes"])
        self.assertEqual(set(result["denied_probes"]), {"srs.midnight.network", "node.midnight.network", "direct-ip"})
        self.assertTrue(all(code != 0 for code in result["denied_probes"].values()))
        self.assertEqual(result["midnight_dependencies"], [])
        expected = {"shield-transfer-unshield", "hybrid-roundtrip", "grandpa-offline-finality", "motra-sponsor"}
        self.assertEqual(set(result["scenarios"]), expected)
        for scenario in result["scenarios"].values():
            self.assertGreater(scenario["transitions"], 0)
            self.assertEqual(scenario["failures"], 0)


class MetadataAppendOnly(RuntimeCase):
    def test_actual_metadata_preserves_old_encoding(self):
        result = self.query("metadata-diff", gate="494", baseline="captured-preprod-code")
        self.assertGreater(len(result["old_pallets"]), 0)
        self.assertGreater(len(result["new_pallets"]), len(result["old_pallets"]))
        for name, old in result["old_pallets"].items():
            new = result["new_pallets"][name]
            self.assertEqual(old["index"], new["index"])
            for category in ("calls", "events", "errors", "storage"):
                for key, value in old[category].items():
                    self.assertEqual(value, new[category][key])
        indices = [p["index"] for p in result["new_pallets"].values()]
        self.assertEqual(len(indices), len(set(indices)))
        for name in set(result["new_pallets"]) - set(result["old_pallets"]):
            self.assertGreaterEqual(result["new_pallets"][name]["index"], 26)
        self.assertEqual(result["old_signed_extra"], result["new_signed_extra"])
        self.assertEqual(result["old_transaction_version"], result["new_transaction_version"])
        self.assertEqual(result["gate_exit"], 0)
        self.assertGreater(result["migration_entries_checked"], 0)

    def test_shifted_errors_and_stale_manifest_fail_gate(self):
        for mutation in ("insert-error-in-middle", "insert-event-in-middle", "reuse-pallet-index",
                         "change-signed-extra", "stale-manifest", "shrink-bound-without-review"):
            with self.subTest(mutation=mutation):
                self.assertNotEqual(self.query("metadata-mutant", mutation=mutation)["gate_exit"], 0)


class BridgeDatum(RuntimeCase):
    def test_rust_aiken_cbor_roundtrip(self):
        recipients = [{"variant": "Account", "key": "11" * 32},
                      {"variant": "Utxo", "lock": {"type": "Ed25519", "key": "22" * 32}}]
        for recipient in recipients:
            result = self.query("bridge-datum", version=1, recipient=recipient)
            self.assertEqual(result["rust_decoded"], recipient)
            self.assertEqual(result["aiken_decoded"], recipient)
            self.assertGreater(len(bytes.fromhex(result["cbor"])), 32)
            self.assertEqual(result["cbor"], result["rust_reencoded"])
            self.assertEqual(result["cbor"], result["aiken_reencoded"])

    def test_reserved_unknown_and_malformed_never_fall_back(self):
        for case in ("Shielded-reserved", "unknown-version", "unknown-variant", "short-account",
                     "trailing-bytes", "noncanonical-integer", "unknown-lock"):
            result = self.query("bridge-datum-invalid", case=case)
            self.assertIs(result["rust_accepted"], False)
            self.assertIs(result["aiken_accepted"], False)


class HubOtherChains(RuntimeCase):
    def test_finality_and_inclusion_require_pinned_context(self):
        result = self.query("hub-finality", fixture="offline-grandpa-authority-transition")
        self.assertIs(result["accepted"], True)
        self.assertGreater(result["verified_authority_changes"], 0)
        self.assertEqual(result["statement"]["trust"], "ConsensusVerified")
        self.assertEqual(result["statement"]["chain_genesis"], result["pinned_genesis"])
        self.assertEqual(result["statement"]["checkpoint"], result["pinned_checkpoint"])
        self.assertEqual(result["statement"]["inclusion_root"], result["verified_inclusion_root"])
        for mutation in ("wrong-genesis", "wrong-set-id", "duplicate-signer", "insufficient-weight",
                         "forged-authority-change", "tampered-inclusion", "stale-checkpoint",
                         "excess-authority-changes", "forced-change"):
            self.assertIs(self.query("hub-finality", fixture=mutation)["accepted"], False)

    def test_consumer_pins_backend_vk_version_domain_and_trust(self):
        for mutation in ("attested-as-trustless", "foreign-vk", "deprecated-backend", "wrong-consumer",
                         "wrong-chain", "wrong-height", "wrong-root", "wrong-public-inputs",
                         "oversize-vk", "too-many-public-inputs", "unknown-backend"):
            result = self.query("hub-consumer", mutation=mutation)
            self.assertIs(result["accepted"], False)
        result = self.query("hub-consumer", mutation="valid")
        self.assertIs(result["accepted"], True)
        self.assertEqual(len(set(result["statement_hashes_for_distinct_domains"])), 4)
        self.assertEqual(result["legacy_bn254_before"], result["legacy_bn254_after"])
        self.assertGreater(result["legacy_receipts_checked"], 0)

    def test_same_groth16_proof_on_both_preprod_chains(self):
        result = self.query("dual-groth16", fixture="production-parameters")
        self.assertEqual(result["materios_proof_sha256"], result["cardano_proof_sha256"])
        self.assertIs(result["materios_accepted"], True)
        self.assertIs(result["aiken_accepted"], True)
        self.assertIs(result["tampered_materios_accepted"], False)
        self.assertIs(result["tampered_aiken_accepted"], False)
        self.assertNotEqual(result["parameter_origin"], "unsafe-setup")
        self.assertEqual(result["networks"], ["materios-preprod", "cardano-preprod"])
        self.assertRegex(result["materios_finalized_block"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["cardano_confirmed_tx"], r"^[0-9a-f]{64}$")
        self.assertGreaterEqual(result["cardano_confirmations"], result["required_cardano_confirmations"])
        self.assertGreater(result["required_cardano_confirmations"], 0)


class Fees(RuntimeCase):
    def test_zero_congestion_still_prices_verification(self):
        result = self.query("fees", congestion=0, same_encoded_length=True)
        self.assertGreater(result["zk_fee_motra"], result["transfer_fee_motra"])
        self.assertGreater(result["invalid_proof_fee_motra"], 0)
        self.assertEqual(result["matra_fee"], 0)
        self.assertEqual(result["fresh_owner_motra"], 0)
        self.assertIs(result["sponsored_transfer_accepted"], True)
        self.assertGreater(result["sponsor_motra_burned"], 0)
        self.assertIs(result["unauthorized_sponsor_accepted"], False)

    def test_cap_and_cheap_admission_before_crypto(self):
        result = self.query("admission-flood", attempts=10000)
        self.assertEqual(result["attempts"], 10000)
        self.assertEqual(result["crypto_calls_on_malformed"], 0)
        self.assertLessEqual(result["accepted_weight"], result["configured_zk_weight_cap"])
        self.assertLessEqual(result["configured_zk_weight_cap"], result["normal_weight_budget"] // 2)
        self.assertLess(result["max_block_ms"], result["slot_ms"])


class HybridUtxo(RuntimeCase):
    def test_nonced_account_intents_and_outpoint_conflicts(self):
        result = self.query("utxo-pool", processes=4, independent_spends=200)
        self.assertEqual(result["included_unique_spends"], 200)
        self.assertEqual(result["priority_1014_errors"], 0)
        self.assertEqual(result["double_spend_inclusions"], 1)
        self.assertEqual(result["same_cardano_outpoint_credits"], 1)
        self.assertEqual(result["account_only_replay_inclusions"], 1)
        for name in ("expired", "wrong-genesis", "wrong-network", "wrong-key-hash", "invalid-cip8"):
            self.assertIs(result["mutants"][name], False)

    def test_cardano_wallet_lock_and_full_lane_roundtrip(self):
        result = self.query("wallet-hybrid-roundtrip", network="preprod", signer="cip30-test-wallet")
        self.assertEqual(result["visited_lanes"], ["A", "U", "S", "U", "A"])
        self.assertEqual(result["initial_amount"], result["final_amount"])
        self.assertRegex(result["wallet_signature_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(result["initial_issuance"], result["final_issuance"])


class ShieldedE2E(RuntimeCase):
    def test_recipient_decrypts_and_viewing_key_reconstructs_history(self):
        result = self.query("shielded-e2e", amount=100_000_000, sender="A", recipient="B", exit="C")
        self.assertEqual(result["c_credit"], 100_000_000)
        self.assertEqual(result["issuance_before"], result["issuance_after"])
        self.assertEqual(result["recipient_decrypted_amount"], 100_000_000)
        self.assertEqual(result["viewing_key_history"], result["wallet_history"])
        self.assertTrue(result["viewing_key_history"])
        self.assertNotIn("B", result["public_signers"])
        self.assertEqual(result["final_escrow"], 0)

    def test_replays_roots_signatures_caps_and_pause(self):
        for scenario in ("double-spend", "stale-root", "wrong-genesis", "bad-spend-auth",
                         "bad-binding-signature", "unshield-cap", "pool-paused", "unbound-recipient",
                         "non-matra-asset"):
            self.rejected_without_value_effects(self.query("shielded-invalid", scenario=scenario))

    def test_unrelated_upgrade_preserves_spendable_notes(self):
        result = self.query("shielded-upgrade", change="unrelated-pallet-append")
        self.assertNotEqual(result["old_spec_version"], result["new_spec_version"])
        self.assertEqual(result["old_note_protocol_version"], result["new_note_protocol_version"])
        self.assertIs(result["old_note_spend_accepted"], True)
        self.assertEqual(result["value_before"], result["value_after"])

    def test_preprod_soak_has_positive_traffic(self):
        result = self.query("preprod-soak", min_days=7, min_bundles=500)
        self.assertGreaterEqual(result["end_unix"] - result["start_unix"], 7 * 86400)
        self.assertGreaterEqual(result["finalized_bundles"], 500)
        self.assertEqual(result["invariant_violations"], 0)
        self.assertEqual(result["import_failures"], 0)
        self.assertIn("arm64", result["architectures"])
        self.assertGreater(result["finalized_blocks"], 0)


class HostCoverage(RuntimeCase):
    def test_one_lagging_node_or_stale_attestation_blocks(self):
        for fault in ("one-author-old", "one-voter-old", "rpc-old", "external-spo-old", "arm64-old",
                      "stale-inventory", "self-reported-version-only"):
            result = self.query("host-coverage", fault=fault)
            self.assertIs(result["enactment_allowed"], False)

    def test_differential_results_and_dark_rollout(self):
        result = self.query("host-differential", cases=10000, network="isolated-devnet")
        self.assertEqual(result["cases"], 10000)
        self.assertEqual(result["mismatches"], 0)
        self.assertEqual(set(result["architectures"]), {"x86_64", "arm64", "emulated-arm64"})
        self.assertEqual(result["ledger_host_functions"], [])
        self.assertEqual(result["curve_abi"], "RFC-163")
        self.assertGreaterEqual(result["full_coverage_seconds"], 7 * 86400)
        self.assertGreaterEqual(result["post_swap_seconds"], 86400)
        self.assertEqual(result["post_swap_import_failures"], 0)


class ActivationGates(RuntimeCase):
    def test_authority_and_evidence_absence_deny_activation(self):
        for absent in ("ceo-authorization", "audit", "counsel", "approved-budget", "thirty-day-soak",
                       "reviewed-caps", "metadata-gate", "timelock", "multisig"):
            result = self.query("activation-gate-simulation", absent=absent)
            self.assertIs(result["allowed"], False)
            self.assertEqual(result["broadcasts"], 0)
        for severity in ("HIGH", "MEDIUM"):
            result = self.query("activation-gate-simulation", open_audit_finding=severity)
            self.assertIs(result["allowed"], False)
            self.assertEqual(result["broadcasts"], 0)


SUITES = {
    "c-mainnet-isolation": MainnetIsolation,
    "c-sapling-wasm": SaplingWasm,
    "c-supply-invariant": SupplyInvariant,
    "c-midnight-blackhole": MidnightBlackhole,
    "c-metadata-append-only": MetadataAppendOnly,
    "c-bridge-datum": BridgeDatum,
    "c-hub-other-chains": HubOtherChains,
    "c-fees": Fees,
    "c-hybrid-utxo": HybridUtxo,
    "c-shielded-e2e": ShieldedE2E,
    "c-host-coverage": HostCoverage,
    "c-activation-gates": ActivationGates,
}
