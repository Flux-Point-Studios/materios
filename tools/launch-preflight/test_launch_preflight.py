"""Tests for the mainnet launch preflight.

The preprod v6 fixture is the raw chain spec the preprod network publishes; its
genesis hash was read from a live node, so the genesis-hash test checks this
implementation against the reference one.
"""
import copy
import gzip
import hashlib
import json
import os
import shutil
from pathlib import Path

import base58
import pytest
import zstandard
from nacl import signing

import launch_preflight as lp

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
PREPROD_GENESIS = "0e46e33f639a56cc8780fd871d9a15e16d99af248526f907cb560cb40849f7bf"
MATRA = 1_000_000

# sp-keyring's hard-coded public keys (substrate/primitives/keyring/src/{sr25519,ed25519}.rs).
SP_KEYRING = {
    "sr25519": {
        "//Alice": "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
        "//Bob": "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48",
        "//Charlie": "90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22",
        "//Dave": "306721211d5404bd9da88e0204360a1a9ab8b87c66c1bc2fcdd37f3c2222cc20",
        "//Eve": "e659a7a1628cdd93febc04a4e0646ea20e9f5f0ce097d9a05290d4a9e054df4e",
        "//Ferdie": "1cbd2d43530a44705ad088af313e18f80b53ef16b36177cd4b77b846f2a5f07c",
        "//Alice//stash": "be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f",
        "//Bob//stash": "fe65717dad0447d715f660a0a58411de509b42e6efb8375f562f58a554d5860e",
        "//Charlie//stash": "1e07379407fecc4b89eb7dbd287c2c781cfb1907a96947a3eb18e4f8e7198625",
        "//Dave//stash": "e860f1b1c7227f7c22602f53f15af80747814dffd839719731ee3bba6edc126c",
        "//Eve//stash": "8ac59e11963af19174d0b94d5d78041c233f55d2e19324665bafdfb62925af2d",
        "//Ferdie//stash": "101191192fc877c24d725b337120fa3edc63d227bbc92705db1e2cb65f56981a",
        "//One": "ac859f8a216eeb1b320b4c76d118da3d7407fa523484d0a980126d3b4d0d220a",
        "//Two": "1254f7017f0b8347ce7ab14f96d818802e7e9e0c0d1b7c9acb3c726b080e7a03",
    },
    "ed25519": {
        "//Alice": "88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee",
        "//Bob": "d17c2d7823ebf260fd138f2d7e27d114c0145d968b5ff5006125f2414fadae69",
        "//Charlie": "439660b36c6c03afafca027b910b4fecf99801834c62a5e6006f27d978de234f",
        "//Dave": "5e639b43e0052c47447dac87d6fd2b6ec50bdd4d0f614e4299c665249bbd09d9",
        "//Eve": "1dfe3e22cc0d45c70779c1095f7489a8ef3cf52d62fbd8c2fa38c9f1723502b5",
        "//Ferdie": "568cb4a574c6d178feb39c27dfc8b3f789e5f5423e19c71633c748b9acf086b5",
        "//Alice//stash": "451781cd0c5504504f69ceec484cc66e4c22a2b6a9d20fb1a426d91ad074a2a8",
        "//Bob//stash": "292684abbb28def63807c5f6e84e9e8689769eb37b1ab130d79dbfbf1b9a0d44",
        "//Charlie//stash": "dd6a6118b6c11c9c9e5a4f34ed3d545e2c74190f90365c60c230fa82e9423bb9",
        "//Dave//stash": "1d0432d75331ab299065bee79cdb1bdc2497c597a3087b4d955c67e3c000c1e2",
        "//Eve//stash": "c833bdd2e1a7a18acc1c11f8596e2e697bb9b42d6b6051e474091a1d43a294d7",
        "//Ferdie//stash": "199d749dbf4b8135cb1f3c8fd697a390fc0679881a8a110c1d06375b3b62cd09",
        "//One": "16f97016bbea8f7b45ae6757b49efc1080accc175d8f018f9ba719b60b0815e4",
        "//Two": "5079bcd20fd97d7d2f752c4607012600b401950260a91821f73e692071c82bf5",
    },
}
# //Alice's ECDSA key as published in polkadot-sdk's zombienet chain specs.
ALICE_ECDSA = "020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1"


def ss58(account: bytes, prefix: int = 42) -> str:
    body = bytes([prefix]) + account
    return base58.b58encode(body + hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:2]).decode()


ALICE = bytes.fromhex(SP_KEYRING["sr25519"]["//Alice"])


@pytest.fixture(scope="session")
def preprod_path(tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("spec") / "preprod-v6-raw.json"
    with gzip.open(FIXTURES / "preprod-v6-raw.json.gz") as src:
        path.write_bytes(src.read())
    return path


@pytest.fixture
def spec(preprod_path) -> lp.Spec:
    return lp.load_spec(str(preprod_path))


@pytest.fixture(scope="session")
def metadata_v14() -> dict:
    return json.loads((FIXTURES / "preprod-v6-metadata.json").read_text())["V14"]


@pytest.fixture
def meta(metadata_v14) -> lp.Metadata:
    return lp.Metadata.from_v14(metadata_v14)


@pytest.fixture(scope="session")
def known():
    return lp.load_well_known()


def fresh_account() -> bytes:
    return signing.SigningKey.generate().verify_key.encode()


def put(spec: lp.Spec, pallet: str, item: str, value: bytes) -> None:
    spec.storage[lp.storage_key(pallet, item)] = value


def account_key(account: bytes) -> bytes:
    return lp.storage_key("System", "Account") + hashlib.blake2b(account, digest_size=16).digest() + account


def endow(spec: lp.Spec, account: bytes, free: int) -> None:
    spec.storage[account_key(account)] = bytes(16) + free.to_bytes(16, "little") + bytes(48)


def messages(findings) -> list[str]:
    return [str(f) for f in findings]


# ---------------------------------------------------------------------------
# The well-known key table
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scheme", ["sr25519", "ed25519"])
def test_table_holds_every_sp_keyring_key(scheme, known):
    keys, _ = known
    table = {(k.label, k.scheme): k.needle.hex() for k in keys}
    for label, public in SP_KEYRING[scheme].items():
        assert table[(label, scheme)] == public


def test_table_holds_published_ecdsa_alice_and_its_account(known):
    keys, _ = known
    needles = {k.needle.hex(): str(k) for k in keys}
    assert needles[ALICE_ECDSA] == "//Alice (ecdsa)"
    account = hashlib.blake2b(bytes.fromhex(ALICE_ECDSA), digest_size=32).hexdigest()
    assert needles[account] == "//Alice (ecdsa)"


def test_table_holds_retired_published_keys(known):
    keys, _ = known
    retired = [k for k in keys if k.label.startswith("retired")]
    assert {k.scheme for k in retired} == {"sr25519", "ed25519"}


# orynq-sdk commits this observer's seed as a test fixture; its SS58 is published next to it.
ORYNQ_TEST_OBSERVER = "5CfCr47V5Dte6bwxNBE8K9oNnQd9fiay6aDEEkgYtFv7w4Fq"


def test_table_holds_keys_whose_seed_is_committed_to_a_public_repo(known):
    keys, _ = known
    committed = {k.scheme: k for k in keys if "orynq-sdk" in k.label}
    assert set(committed) == {"sr25519", "ed25519", "ecdsa"}
    assert committed["sr25519"].needle == lp.decode_public_key(ORYNQ_TEST_OBSERVER)


def extra_table(tmp_path, entries) -> Path:
    path = tmp_path / "exposed.json"
    path.write_text(json.dumps({"keys": entries}))
    return path


def test_extra_well_known_keys_are_named_with_their_label(spec, meta, tmp_path):
    exposed = fresh_account()
    ecdsa_pub = bytes([2]) + fresh_account()
    path = extra_table(tmp_path, [
        {"label": "exposed multisig member", "scheme": "sr25519", "public": exposed.hex()},
        {"label": "exposed cross-chain key", "scheme": "ecdsa", "public": ecdsa_pub.hex()},
    ])
    keys, phrase_hash = lp.load_well_known([path])
    launch = {"roles": {"multisig_members": [ss58(exposed)],
                        "committee": [ss58(hashlib.blake2b(ecdsa_pub, digest_size=32).digest())]}}
    found = messages(lp.check_dev_keys(spec, meta, launch, pub(signing.SigningKey.generate()), keys, phrase_hash))
    assert "[1 dev-keys] roles.multisig_members[0]: exposed multisig member (sr25519)" in found
    assert "[1 dev-keys] roles.committee[0]: exposed cross-chain key (ecdsa)" in found


@pytest.mark.parametrize("entries, error", [
    ([{"label": "x", "scheme": "sr25519"}], "keys\\[0\\] needs"),
    ([{"label": "x", "scheme": "sr25519", "public": "zz"}], "keys\\[0\\] public is not hex"),
    ([{"label": "x", "scheme": "sr25519", "public": "00" * 31}], "keys\\[0\\] public is 31 bytes"),
])
def test_malformed_extra_table_is_an_input_error(tmp_path, entries, error):
    with pytest.raises(lp.InputError, match=error):
        lp.load_well_known([extra_table(tmp_path, entries)])


# ---------------------------------------------------------------------------
# Rule 6: checkpoint canary (genesis hash, code hash, chain-spec hash)
# ---------------------------------------------------------------------------

def test_genesis_hash_matches_the_live_preprod_genesis(spec):
    wasm = lp.decompressed_code(spec.code)
    assert lp.runtime_state_version(wasm) == 1
    assert lp.genesis_hash(spec.storage, 1).hex() == PREPROD_GENESIS


def pub(key: signing.SigningKey) -> bytes:
    return key.verify_key.encode()


def test_signed_manifest_for_this_spec_passes(spec):
    key = signing.SigningKey.generate()
    assert lp.check_checkpoint(spec, lp.signed_manifest(spec, key), pub(key)) == []


def test_changed_genesis_storage_breaks_genesis_and_spec_hash(preprod_path, tmp_path):
    key = signing.SigningKey.generate()
    signed = lp.signed_manifest(lp.load_spec(str(preprod_path)), key)
    doc = json.loads(preprod_path.read_text())
    alice_key = "0x" + account_key(ALICE).hex()
    doc["genesis"]["raw"]["top"][alice_key] = "0x" + (bytes(16) + (1).to_bytes(16, "little") + bytes(48)).hex()
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(doc))
    found = messages(lp.check_checkpoint(lp.load_spec(str(tampered)), signed, pub(key)))
    assert any("genesis_hash is 0x" in m for m in found)
    assert any("chain_spec_hash is 0x" in m for m in found)
    assert not any("code_hash" in m for m in found)


def test_changed_runtime_code_breaks_code_hash(spec):
    key = signing.SigningKey.generate()
    signed = lp.signed_manifest(spec, key)
    signed["code_hash"] = "0x" + bytes(32).hex()
    found = messages(lp.check_checkpoint(spec, signed, pub(key)))
    assert any("code_hash is 0x" in m for m in found)
    assert any("signature does not verify" in m for m in found)


def test_manifest_signed_by_another_key_is_refused(spec):
    signed = lp.signed_manifest(spec, signing.SigningKey.generate())
    found = messages(lp.check_checkpoint(spec, signed, pub(signing.SigningKey.generate())))
    assert found == ["[6 checkpoint] signed manifest signature does not verify under the pinned launch key"]


def test_code_substitutes_are_refused(spec):
    key = signing.SigningKey.generate()
    signed = lp.signed_manifest(spec, key)
    spec.doc["codeSubstitutes"] = {"1": "0x00"}
    found = messages(lp.check_checkpoint(spec, signed, pub(key)))
    assert "[6 checkpoint] chain spec carries codeSubstitutes" in found


def ntm_scripts(address: bytes) -> bytes:
    return bytes(28) + lp.compact(0) + lp.compact(len(address)) + address


def test_placeholder_observation_with_no_address_is_not_live(spec):
    put(spec, "NativeTokenManagement", "MainChainScriptsConfiguration", ntm_scripts(b""))
    assert lp.check_observation(spec) == []


def test_preprod_genesis_does_not_turn_on_the_cardano_observation(spec):
    assert lp.check_observation(spec) == []


def test_genesis_that_turns_on_the_cardano_observation_is_refused(spec):
    address = b"addr1wxlockscriptaddressfortheilliquidsupply"
    put(spec, "NativeTokenManagement", "MainChainScriptsConfiguration", ntm_scripts(address))
    assert messages(lp.check_observation(spec)) == [
        "[6 checkpoint] genesis turns on the Cardano deposit observation for "
        "addr1wxlockscriptaddressfortheilliquidsupply, and this runtime has no observation "
        "checkpoint: its first observation counts every transfer to that address since "
        "Cardano genesis, the genesis lock included"]


def test_truncated_observation_config_is_an_input_error(spec):
    truncated = bytes(28) + lp.compact(0) + lp.compact(9) + b"addr"
    put(spec, "NativeTokenManagement", "MainChainScriptsConfiguration", truncated)
    with pytest.raises(lp.InputError, match="MainChainScriptsConfiguration"):
        lp.check_observation(spec)


def test_malformed_manifest_is_refused(spec):
    found = messages(lp.check_checkpoint(spec, {"genesis_hash": "0x00"}, pub(signing.SigningKey.generate())))
    assert len(found) == 1 and "signed manifest is malformed" in found[0]


# ---------------------------------------------------------------------------
# Rule 1: well-known keys
# ---------------------------------------------------------------------------

def dev_key_findings(spec, meta, known, launch=None, manifest_key=None):
    keys, phrase_hash = known
    launch = {"roles": {}} if launch is None else launch
    return messages(lp.check_dev_keys(spec, meta, launch, manifest_key or pub(signing.SigningKey.generate()),
                                      keys, phrase_hash))


def test_preprod_genesis_names_alice_as_an_endowed_account(spec, meta, known):
    found = dev_key_findings(spec, meta, known)
    assert "[1 dev-keys] System.Account: //Alice (sr25519) is in genesis" in found
    assert all("//Alice (sr25519)" in m for m in found)


def test_dev_key_in_sudo_and_authorities_is_named_by_storage_item(spec, meta, known):
    bob_ed = bytes.fromhex(SP_KEYRING["ed25519"]["//Bob"])
    put(spec, "Sudo", "Key", bytes.fromhex(SP_KEYRING["sr25519"]["//Charlie"]))
    put(spec, "Grandpa", "Authorities", lp.compact(1) + bob_ed + (1).to_bytes(8, "little"))
    found = dev_key_findings(spec, meta, known)
    assert "[1 dev-keys] Sudo.Key: //Charlie (sr25519) is in genesis" in found
    assert "[1 dev-keys] Grandpa.Authorities: //Bob (ed25519) is in genesis" in found


def test_dev_anchor_signer_role_is_named(spec, meta, known):
    launch = {"roles": {"anchor_signer": [ss58(ALICE)], "oracle": ["0x" + ALICE_ECDSA]}}
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] roles.anchor_signer[0]: //Alice (sr25519)" in found
    assert "[1 dev-keys] roles.oracle[0]: //Alice (ecdsa)" in found


def test_ecdsa_account_form_and_retired_key_are_named(spec, meta, known):
    ecdsa_account = hashlib.blake2b(bytes.fromhex(ALICE_ECDSA), digest_size=32).digest()
    retired = bytes.fromhex("7e27bb13fd6fb62cc0e7c59916952c8c214960904208295a0d70c4c48e2a9a29")
    launch = {"roles": {"cert_daemons": [ss58(ecdsa_account)], "committee": [ss58(retired)]}}
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] roles.cert_daemons[0]: //Alice (ecdsa)" in found
    assert any(m.startswith("[1 dev-keys] roles.committee[0]: retired validator key") for m in found)


def test_secret_uri_or_garbage_in_a_role_is_refused_without_echoing_it(spec, meta, known):
    launch = {"roles": {"multisig_members": ["//Bob//stash", "not a key", 7]}}
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] roles.multisig_members[0]: well-known secret URI //Bob//stash" in found
    assert any(m.startswith("[1 dev-keys] roles.multisig_members[1]:") for m in found)
    assert "[1 dev-keys] roles.multisig_members[2]: not a public key string" in found
    assert not any("not a key" in m.split(":", 1)[1] for m in found)


def test_bad_ss58_checksum_is_refused(spec, meta, known):
    good = ss58(fresh_account())
    broken = good[:-1] + ("A" if good[-1] != "A" else "B")
    found = dev_key_findings(spec, meta, known, {"roles": {"oracle": [broken]}})
    assert any("roles.oracle[0]" in m and "checksum" in m for m in found)


def test_fresh_role_keys_add_no_findings(spec, meta, known):
    base = dev_key_findings(spec, meta, known)
    launch = {"roles": {"anchor_signer": [ss58(fresh_account())], "oracle": ["0x" + fresh_account().hex()]}}
    assert dev_key_findings(spec, meta, known, launch) == base


def test_dev_keyring_flags_and_dev_uris_in_node_launch_are_named(spec, meta, known):
    launch = {"roles": {}, "nodes": [
        {"name": "v1", "host": "h1", "argv": "materios-node --validator --alice --chain mainnet.json"},
        {"name": "v2", "host": "h2", "argv": ["materios-node", "--dev"]},
        {"name": "cd", "host": "h3", "argv": [], "env": {"SIGNER_URI": "//Ferdie"}},
    ]}
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] node v1: --alice loads the dev keyring" in found
    assert "[1 dev-keys] node v2: --dev loads the dev keyring" in found
    assert "[1 dev-keys] node cd: launch config names //Ferdie" in found


def test_dev_mnemonic_in_a_launch_config_is_detected_by_hash(spec, meta):
    keys, _ = lp.load_well_known()
    phrase = "one two three four five six seven eight nine ten eleven twelve"
    phrase_hash = lp.blake2_256(phrase.encode()).hex()
    launch = {"roles": {}, "nodes": [{"name": "v1", "host": "h1", "argv": [],
                                      "env": {"SEED": f"  {phrase.replace(' ', '   ')}//Alice"}}]}
    found = messages(lp.check_dev_keys(spec, meta, launch, pub(signing.SigningKey.generate()), keys, phrase_hash))
    assert "[1 dev-keys] node v1: launch config holds the dev mnemonic" in found


def test_dev_manifest_signing_key_is_refused(spec, meta, known):
    found = dev_key_findings(spec, meta, known, manifest_key=bytes.fromhex(SP_KEYRING["ed25519"]["//Eve"]))
    assert "[1 dev-keys] manifest signing key: //Eve (ed25519)" in found


def test_dev_key_embedded_in_runtime_code_is_named(spec, meta, known):
    spec.storage[lp.CODE_KEY] = lp.ZSTD_PREFIX + zstandard.ZstdCompressor().compress(
        b"\0asm" + bytes(4) + bytes.fromhex(SP_KEYRING["sr25519"]["//Dave"]))
    found = dev_key_findings(spec, meta, known)
    assert "[1 dev-keys] :code (runtime WASM): //Dave (sr25519) is in genesis" in found


# ---------------------------------------------------------------------------
# Rule 2: explicit attestor rewards
# ---------------------------------------------------------------------------

TUNED = {"attestation_reward_per_signer": 1 * MATRA, "era_cap_base": 50_000 * MATRA,
         "era_cap_baseline_attestor_count": 32}


def test_undeclared_rewards_are_refused(spec):
    found = messages(lp.check_rewards(spec, {"economics": {}}))
    assert len(found) == 3
    assert all("is not declared as an integer" in m for m in found)


def test_genesis_that_dropped_the_tuned_rewards_is_refused(spec):
    found = messages(lp.check_rewards(spec, {"economics": TUNED}))
    assert found == [
        "[2 rewards] OrinqReceipts.AttestationRewardPerSigner stores 10000000, declared 1000000",
        "[2 rewards] OrinqReceipts.EraCapBaselineAttestorCount stores 16, declared 32",
    ]


def test_rewards_missing_from_genesis_are_refused(spec):
    for _, item, _ in lp.REWARD_ITEMS:
        del spec.storage[lp.storage_key("OrinqReceipts", item)]
    found = messages(lp.check_rewards(spec, {"economics": TUNED}))
    assert found == [f"[2 rewards] OrinqReceipts.{item} is not set in genesis (declared {TUNED[field]})"
                     for field, item, _ in lp.REWARD_ITEMS]


def test_stored_rewards_equal_to_declared_pass(spec):
    put(spec, "OrinqReceipts", "AttestationRewardPerSigner", (1 * MATRA).to_bytes(16, "little"))
    put(spec, "OrinqReceipts", "EraCapBaselineAttestorCount", (32).to_bytes(4, "little"))
    assert lp.check_rewards(spec, {"economics": TUNED}) == []


def test_zero_baseline_is_refused(spec):
    put(spec, "OrinqReceipts", "EraCapBaselineAttestorCount", bytes(4))
    economics = dict(TUNED, era_cap_baseline_attestor_count=0)
    found = messages(lp.check_rewards(spec, {"economics": economics}))
    assert "[2 rewards] economics.era_cap_baseline_attestor_count is zero" in found


# ---------------------------------------------------------------------------
# Rule 3: unsafe RPC on authorities
# ---------------------------------------------------------------------------

def rpc_findings(tmp_path, nodes, nginx=None, proxy_host="edge"):
    proxies = []
    if nginx is not None:
        conf = tmp_path / "nginx.conf"
        conf.write_text(nginx)
        proxies = [{"name": "public-rpc", "host": proxy_host, "config": str(conf)}]
    return messages(lp.check_rpc({"nodes": nodes, "rpc_proxies": proxies}))


def authority(argv, host="val1", name="val1"):
    return {"name": name, "host": host, "authority": True, "argv": argv}


def test_unsafe_methods_on_an_external_listener_are_refused(tmp_path):
    found = rpc_findings(tmp_path, [authority("node --validator --rpc-methods unsafe --unsafe-rpc-external")])
    assert found == ["[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


def test_unsafe_methods_behind_a_loopback_proxy_on_the_same_host_are_refused(tmp_path):
    nginx = "location /rpc { proxy_pass http://127.0.0.1:9945; }"
    found = rpc_findings(tmp_path, [authority("node --rpc-methods=Unsafe --rpc-port 9945")], nginx, "val1")
    assert found == ["[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_default_methods_on_loopback_are_unsafe_so_a_proxy_is_refused(tmp_path):
    nginx = "upstream chain { server val1:9944; }\nlocation / { proxy_pass http://chain; }"
    found = rpc_findings(tmp_path, [authority(["node", "--validator"])], nginx)
    assert found == ["[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


@pytest.mark.parametrize("argv", [
    "node --validator --rpc-external",
    "node --validator --rpc-methods safe --unsafe-rpc-external",
    "node --validator --rpc-methods safe --rpc-port 9945",
])
def test_safe_methods_pass_even_when_exposed(tmp_path, argv):
    nginx = "location / { proxy_pass http://127.0.0.1:9945; }"
    assert rpc_findings(tmp_path, [authority(argv)], nginx, "val1") == []


def test_proxy_to_another_host_or_port_does_not_implicate_the_authority(tmp_path):
    nginx = "location / { proxy_pass http://rpc-node:9944; } location /b { proxy_pass http://127.0.0.1:9944; }"
    assert rpc_findings(tmp_path, [authority("node --rpc-methods unsafe")], nginx, "edge") == []


def test_proxy_to_another_address_of_the_authority_is_refused(tmp_path):
    node = dict(authority("node --rpc-methods unsafe --rpc-port 9945"), addresses=["172.18.0.1", "val1.lan"])
    nginx = "location /rpc { proxy_pass http://172.18.0.1:9945/; }"
    assert rpc_findings(tmp_path, [node], nginx) == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_non_authority_nodes_are_out_of_scope(tmp_path):
    node = {"name": "rpc", "host": "r", "authority": False, "argv": "node --rpc-methods unsafe --rpc-external"}
    assert rpc_findings(tmp_path, [node]) == []


def test_unknown_rpc_methods_value_is_refused(tmp_path):
    found = rpc_findings(tmp_path, [authority("node --rpc-methods everything")])
    assert found == ["[3 rpc] node val1: unknown --rpc-methods everything"]


def test_variable_proxy_target_cannot_be_checked(tmp_path):
    with pytest.raises(lp.InputError, match="is a variable"):
        rpc_findings(tmp_path, [authority("node")], "location / { proxy_pass http://$backend; }")


# ---------------------------------------------------------------------------
# Rule 4: endowments and supply
# ---------------------------------------------------------------------------

# A preprod cert-daemon account. Its chain-spec source endows BondRequirement +
# 100 MATRA; the genesis preprod actually launched with gave it 100 MATRA.
PREPROD_ATTESTOR = bytes.fromhex("44f3bafbc393f24fcfabbf57d4ca73a6a6b5df358cdaa9480a517a97f189964b")
SUPPLY = {"cardano_backing": 210_100_000 * MATRA}
FLOOR = 1_000 * MATRA + 500 + 100 * MATRA
RESERVES = {"ValidatorEmissionReserve": 150_000_000 * MATRA, "AttestationRewardReserve": 50_000_000 * MATRA}


def with_reserves(metadata_v14: dict, reserves=RESERVES) -> dict:
    """The fixture metadata plus the emission-reserve constants a runtime
    that declares them exposes on OrinqReceipts."""
    v14 = copy.deepcopy(metadata_v14)
    pallet = next(p for p in v14["pallets"] if p["name"] == "OrinqReceipts")
    pallet["constants"] = list(pallet.get("constants") or []) + [
        {"name": name, "value": list(value.to_bytes(16, "little"))} for name, value in reserves.items()]
    return v14


@pytest.fixture
def reserve_meta(metadata_v14) -> lp.Metadata:
    return lp.Metadata.from_v14(with_reserves(metadata_v14))


def supply_findings(spec, meta, attestors, fee_buffer, supply=SUPPLY):
    launch = {"roles": {"attestors": attestors}, "economics": {"fee_buffer": fee_buffer}, "supply": supply}
    return messages(lp.check_supply(spec, meta, launch))


def test_attestor_endowed_at_bond_plus_ed_plus_buffer_passes(spec, reserve_meta):
    attestor = fresh_account()
    endow(spec, attestor, FLOOR)
    assert supply_findings(spec, reserve_meta, [ss58(attestor)], 100 * MATRA) == []


def test_attestor_endowed_one_unit_below_the_floor_is_refused(spec, reserve_meta):
    attestor = fresh_account()
    endow(spec, attestor, FLOOR - 1)
    found = supply_findings(spec, reserve_meta, [ss58(attestor)], 100 * MATRA)
    assert found == [f"[4 supply] roles.attestors[0] is endowed {FLOOR - 1}, below "
                     f"bond + existential deposit + fee buffer = {FLOOR}"]


def test_preprod_genesis_endowed_its_attestors_below_the_bond(spec, reserve_meta):
    found = supply_findings(spec, reserve_meta, [ss58(PREPROD_ATTESTOR)], 0)
    assert found == ["[4 supply] roles.attestors[0] is endowed 100000000, below "
                     "bond + existential deposit + fee buffer = 1000000500"]


def test_unendowed_attestor_is_refused(spec, reserve_meta):
    found = supply_findings(spec, reserve_meta, [ss58(fresh_account())], 0)
    assert len(found) == 1 and "is endowed 0" in found[0]


def test_endowment_floor_needs_every_input(spec, reserve_meta):
    found = supply_findings(spec, reserve_meta, [ss58(PREPROD_ATTESTOR)], None)
    assert found[0].startswith("[4 supply] cannot size attestor endowments")


def test_runtime_emission_reserves_on_top_of_a_cardano_backed_genesis_are_refused(spec, reserve_meta):
    issuance = int.from_bytes(spec.value("Balances", "TotalIssuance"), "little")
    backing = issuance
    found = supply_findings(spec, reserve_meta, [], 0, {"cardano_backing": backing})
    assert found == [f"[4 supply] Materios can issue {issuance + 200_000_000 * MATRA} (genesis {issuance} "
                     f"+ runtime emission reserves {200_000_000 * MATRA}) against {backing} locked on "
                     "Cardano: the difference is reserve counted both as cMATRA and as MATRA"]


def test_genesis_and_emission_reserves_fully_backed_pass(spec, reserve_meta):
    assert supply_findings(spec, reserve_meta, [], 0) == []


def test_genesis_issuance_above_the_cardano_lock_is_refused(spec, metadata_v14):
    no_emission = {"ValidatorEmissionReserve": 0, "AttestationRewardReserve": 0}
    meta = lp.Metadata.from_v14(with_reserves(metadata_v14, no_emission))
    found = supply_findings(spec, meta, [], 0, {"cardano_backing": 975_000 * MATRA})
    assert len(found) == 1 and "counted both as cMATRA and as MATRA" in found[0]


def test_runtime_that_hides_its_emission_reserves_is_refused(spec, meta):
    found = supply_findings(spec, meta, [], 0)
    assert found == ["[4 supply] the runtime metadata does not declare OrinqReceipts.ValidatorEmissionReserve, "
                     "OrinqReceipts.AttestationRewardReserve: what the runtime mints after genesis is unbounded "
                     "here, so the supply cannot be checked against the Cardano lock"]


def test_undeclared_backing_is_refused(spec, reserve_meta):
    found = supply_findings(spec, reserve_meta, [], 0, {})
    assert found == ["[4 supply] supply.cardano_backing must be declared as an integer"]


# ---------------------------------------------------------------------------
# Rule 5: pallets
# ---------------------------------------------------------------------------

def test_runtime_without_perp_engine_passes(meta):
    assert lp.check_pallets(meta) == []


def test_perp_engine_in_the_metadata_is_refused(metadata_v14):
    v14 = copy.deepcopy(metadata_v14)
    v14["pallets"].append({"name": "PerpEngine", "storage": None, "constants": []})
    assert messages(lp.check_pallets(lp.Metadata.from_v14(v14))) == [
        "[5 pallets] PerpEngine is in the runtime metadata"]


# ---------------------------------------------------------------------------
# End to end through the CLI, with the real subwasm
# ---------------------------------------------------------------------------

def subwasm() -> str:
    path = os.environ.get("SUBWASM") or shutil.which("subwasm")
    assert path, "set SUBWASM or put subwasm on PATH: the CLI tests run the real extractor"
    return path


def clean_launch(tmp_path, attestor: bytes) -> dict:
    conf = tmp_path / "rpc.conf"
    conf.write_text("location / { proxy_pass http://rpc-node:9944; }")
    return {
        "roles": {"anchor_signer": [ss58(fresh_account())], "attestors": [ss58(attestor)],
                  "multisig_members": [ss58(fresh_account()) for _ in range(3)]},
        "economics": dict(TUNED, fee_buffer=100 * MATRA),
        "supply": {"cardano_backing": 202_000_000 * MATRA},
        "nodes": [authority("materios-node --validator --rpc-methods safe")],
        "rpc_proxies": [{"name": "public-rpc", "host": "edge", "config": str(conf)}],
    }


def clean_spec(preprod_path, tmp_path, attestor: bytes) -> Path:
    """The preprod genesis with //Alice removed, the tuned rewards stored and one
    attestor endowed at the floor: a spec every rule accepts."""
    spec = lp.load_spec(str(preprod_path))
    del spec.storage[account_key(ALICE)]
    put(spec, "OrinqReceipts", "AttestationRewardPerSigner", (1 * MATRA).to_bytes(16, "little"))
    put(spec, "OrinqReceipts", "EraCapBaselineAttestorCount", (32).to_bytes(4, "little"))
    endow(spec, attestor, FLOOR)
    prefix = lp.storage_key("System", "Account")
    issuance = sum(int.from_bytes(v[16:32], "little") for k, v in spec.storage.items() if k.startswith(prefix))
    put(spec, "Balances", "TotalIssuance", issuance.to_bytes(16, "little"))
    spec.doc["genesis"]["raw"]["top"] = {"0x" + k.hex(): "0x" + v.hex() for k, v in spec.storage.items()}
    path = tmp_path / "clean-raw.json"
    path.write_text(json.dumps(spec.doc))
    return path


def run_cli(tmp_path, spec_path: Path, launch: dict, capsys, key=None, manifest_key=None,
            extra=()) -> tuple[int, str]:
    key = key or signing.SigningKey.generate()
    seed = tmp_path / "launch.key"
    seed.write_text(key.encode().hex())
    signed, launch_path = tmp_path / "signed.json", tmp_path / "launch.json"
    assert lp.main(["sign", "--spec", str(spec_path), "--key", str(seed), "--out", str(signed)]) == 0
    launch_path.write_text(json.dumps(launch))
    capsys.readouterr()
    code = lp.main(["check", "--spec", str(spec_path), "--launch", str(launch_path),
                    "--signed-manifest", str(signed), "--manifest-key", "0x" + (manifest_key or pub(key)).hex(),
                    "--subwasm", subwasm(), *extra])
    return code, capsys.readouterr().out


def test_cli_refuses_the_preprod_spec_naming_the_dev_anchor_signer(preprod_path, tmp_path, capsys):
    launch = clean_launch(tmp_path, PREPROD_ATTESTOR)
    launch["roles"]["anchor_signer"] = [ss58(ALICE)]
    code, out = run_cli(tmp_path, preprod_path, launch, capsys)
    assert code == 1
    assert "MAINNET LAUNCH PREFLIGHT: REFUSE" in out
    assert "[1 dev-keys] roles.anchor_signer[0]: //Alice (sr25519)" in out
    assert "[1 dev-keys] System.Account: //Alice (sr25519) is in genesis" in out
    assert "[2 rewards] OrinqReceipts.AttestationRewardPerSigner stores 10000000, declared 1000000" in out
    assert "[4 supply] roles.attestors[0] is endowed 100000000" in out
    assert "[4 supply] the runtime metadata does not declare OrinqReceipts.ValidatorEmissionReserve" in out


def test_cli_passes_a_clean_launch(preprod_path, tmp_path, capsys, monkeypatch, metadata_v14):
    """No built runtime passes yet (PerpEngine, undeclared emission reserves), so
    the extractor returns the fixture metadata with the reserves declared."""
    monkeypatch.setattr(lp, "subwasm_metadata", lambda code, subwasm: with_reserves(metadata_v14))
    attestor = fresh_account()
    code, out = run_cli(tmp_path, clean_spec(preprod_path, tmp_path, attestor),
                        clean_launch(tmp_path, attestor), capsys)
    assert out.strip() == "MAINNET LAUNCH PREFLIGHT: PASS"
    assert code == 0


def test_cli_names_keys_from_an_extra_table(preprod_path, tmp_path, capsys, monkeypatch, metadata_v14):
    monkeypatch.setattr(lp, "subwasm_metadata", lambda code, subwasm: with_reserves(metadata_v14))
    attestor, exposed = fresh_account(), fresh_account()
    launch = clean_launch(tmp_path, attestor)
    launch["roles"]["multisig_members"][0] = ss58(exposed)
    extra = extra_table(tmp_path, [{"label": "exposed member", "scheme": "sr25519", "public": exposed.hex()}])
    code, out = run_cli(tmp_path, clean_spec(preprod_path, tmp_path, attestor), launch, capsys,
                        extra=["--extra-well-known", str(extra)])
    assert code == 1
    assert "[1 dev-keys] roles.multisig_members[0]: exposed member (sr25519)" in out


def test_cli_refuses_a_manifest_pinned_to_another_key(preprod_path, tmp_path, capsys):
    attestor = fresh_account()
    code, out = run_cli(tmp_path, clean_spec(preprod_path, tmp_path, attestor), clean_launch(tmp_path, attestor),
                        capsys, manifest_key=pub(signing.SigningKey.generate()))
    assert code == 1
    assert "[6 checkpoint] signed manifest signature does not verify" in out


@pytest.mark.parametrize("launch, error", [
    ({"roles": {"oracle": "5Grw"}}, "roles must map each role to a list"),
    ({"roles": {}, "nodes": [{"name": "v1"}]}, "nodes\\[0\\] needs a name and a host"),
    ({"roles": {}, "rpc_proxies": [{"name": "p", "host": "h"}]}, "rpc_proxies\\[0\\] needs"),
    ({"roles": {}, "nodes": [{"name": "v1", "host": "h", "addresses": "10.0.0.1"}]},
     "nodes\\[0\\] addresses must be a list"),
])
def test_malformed_launch_manifest_is_an_input_error(spec, meta, launch, error):
    with pytest.raises(lp.InputError, match=error):
        lp.run_checks(spec, meta, launch, {}, "0x00")


@pytest.mark.parametrize("manifest_key", ["0xzz", "0x" + "00" * 31])
def test_malformed_manifest_key_is_an_input_error(spec, meta, manifest_key):
    with pytest.raises(lp.InputError, match="--manifest-key"):
        lp.run_checks(spec, meta, {"roles": {}}, {}, manifest_key)


def test_non_numeric_rpc_port_is_an_input_error(tmp_path):
    with pytest.raises(lp.InputError, match="is not a port"):
        rpc_findings(tmp_path, [authority("node --rpc-port nine")])


def test_decompression_bomb_is_an_input_error(monkeypatch):
    monkeypatch.setattr(lp, "CODE_BOMB_LIMIT", 1024)
    bomb = lp.ZSTD_PREFIX + zstandard.ZstdCompressor().compress(bytes(4096))
    with pytest.raises(lp.InputError, match="bomb limit"):
        lp.decompressed_code(bomb)


def test_unreadable_signing_key_is_an_input_error_that_does_not_echo_it(preprod_path, tmp_path, capsys):
    key = tmp_path / "bad.key"
    key.write_text("not-a-seed-value")
    assert lp.main(["sign", "--spec", str(preprod_path), "--key", str(key), "--out", str(tmp_path / "o")]) == 2
    err = capsys.readouterr().err
    assert "cannot load the launch signing key" in err and "not-a-seed-value" not in err


def test_cli_refuses_a_non_raw_spec_as_an_input_error(tmp_path, capsys):
    plain = tmp_path / "plain.json"
    plain.write_text(json.dumps({"genesis": {"runtimeGenesis": {"patch": {}}}}))
    code = lp.main(["check", "--spec", str(plain), "--launch", str(plain), "--signed-manifest", str(plain),
                    "--manifest-key", "0x00", "--subwasm", "subwasm"])
    assert code == 2
    assert "needs the raw chain spec" in capsys.readouterr().err
