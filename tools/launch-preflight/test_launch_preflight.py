"""Tests for the mainnet launch preflight.

The preprod v6 fixture is the raw chain spec the preprod network publishes; its
genesis hash was read from a live node, so the genesis-hash test checks this
implementation against the reference one. Cardano is served by a local HTTP
server that answers with Kupo's response shapes.
"""
import copy
import dataclasses
import gzip
import hashlib
import json
import os
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import base58
import cbor2
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
BOB = bytes.fromhex(SP_KEYRING["sr25519"]["//Bob"])
CHARLIE = bytes.fromhex(SP_KEYRING["sr25519"]["//Charlie"])


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


def genesis_accounts(spec: lp.Spec) -> list[bytes]:
    prefix = lp.storage_key("System", "Account")
    return sorted(key[48:] for key in spec.storage if key.startswith(prefix))


def endow(spec: lp.Spec, account: bytes, free: int) -> None:
    """Set an account's free balance and move TotalIssuance with it."""
    old = spec.storage.get(account_key(account))
    delta = free - (int.from_bytes(old[16:32], "little") if old else 0)
    spec.storage[account_key(account)] = bytes(16) + free.to_bytes(16, "little") + bytes(48)
    issuance = int.from_bytes(spec.value("Balances", "TotalIssuance"), "little")
    put(spec, "Balances", "TotalIssuance", (issuance + delta).to_bytes(16, "little"))


def aura_keys(spec: lp.Spec) -> list[bytes]:
    raw = spec.value("Aura", "Authorities")
    count, pos = lp.read_compact(raw, 0)
    return [raw[pos + 32 * i:pos + 32 * i + 32] for i in range(count)]


def messages(findings) -> list[str]:
    return [str(f) for f in findings]


def msig(threshold, *members) -> dict:
    return {"threshold": threshold, "members": [ss58(m) for m in members]}


NO_CARDANO = lp.CardanoView(lock=None, candidates=[])


# ---------------------------------------------------------------------------
# The well-known key table
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scheme", ["sr25519", "ed25519"])
def test_table_holds_every_sp_keyring_key(scheme, known):
    keys = known.keys
    table = {(k.label, k.scheme): k.needle.hex() for k in keys}
    for label, public in SP_KEYRING[scheme].items():
        assert table[(label, scheme)] == public


def test_table_holds_published_ecdsa_alice_and_its_account(known):
    keys = known.keys
    needles = {k.needle.hex(): str(k) for k in keys}
    assert needles[ALICE_ECDSA] == "//Alice (ecdsa)"
    account = hashlib.blake2b(bytes.fromhex(ALICE_ECDSA), digest_size=32).hexdigest()
    assert needles[account] == "//Alice (ecdsa)"


def test_table_holds_retired_published_keys(known):
    keys = known.keys
    retired = [k for k in keys if k.label.startswith("retired")]
    assert {k.scheme for k in retired} == {"sr25519", "ed25519"}


# orynq-sdk commits this observer's seed as a test fixture; its SS58 is published next to it.
ORYNQ_TEST_OBSERVER = "5CfCr47V5Dte6bwxNBE8K9oNnQd9fiay6aDEEkgYtFv7w4Fq"


def test_table_holds_keys_whose_seed_is_committed_to_a_public_repo(known):
    keys = known.keys
    observer = [k for k in keys if k.needle == lp.decode_public_key(ORYNQ_TEST_OBSERVER)]
    assert [str(k) for k in observer] == ["orynq-sdk test key, secret committed to a public repo (sr25519)"]


# partner-chains commits its local environment's keystores. Substrate names each
# keystore file for its key type and public key, and the file holds the phrase.
PARTNER_CHAINS_KEYSTORE = {
    "sr25519": "289c161586d774dda981fdb184d061a28e04bdf81322c545b9c37549e7412f2f",  # aura
    "ed25519": "bfd485365f3765c31aa70502261868e79ca045d4d0f16db70865280e3a741f88",  # gran
    "ecdsa": "0258dc1e341e42ba85b393804c1e8a531485ec3b73b2d5cd2b0bf56cbcaf102a7e",  # crch
}


def test_table_holds_keystore_keys_a_public_repo_commits(known):
    keys = known.keys
    table = {(k.scheme, k.needle.hex()): k.label for k in keys}
    for scheme, public in PARTNER_CHAINS_KEYSTORE.items():
        assert table[(scheme, public)] == "partner-chains test key, secret committed to a public repo"


# Bare `//Name` URIs derive from the dev phrase; public repos commit these as test
# signers. Pinned against @polkadot/keyring 13.5.9.
PUBLIC_REPO_DERIVATIONS = {
    ("//CertDaemon", "sr25519"): "ccc4bf1001496df6f9d4b94f23a3e1775da2f8430c53a257f06ca90589ad481e",
    ("//aegis", "ed25519"): "a42ea701be5e5e6bf2c3af0b8ae5f82e0c138e6899b503d4331d70ba1fdf8a1f",
    ("//Alice//aegis", "ecdsa"): "0241af9170a47690e78249e512d50c4b3aa85147165db20128f23dd268db665c23",
}


def test_table_holds_dev_phrase_derivations_that_public_repos_commit(known):
    keys = known.keys
    table = {(k.label, k.scheme, k.needle.hex()) for k in keys}
    for (path, scheme), public in PUBLIC_REPO_DERIVATIONS.items():
        assert (path, scheme, public) in table


# Substrate reads a numeric junction as a u64, not a string. Pinned against
# @polkadot/keyring 13.5.9; the sr25519 keys also against substrate-interface.
NUMERIC_DEV_PATHS = {
    ("//0", "sr25519"): "2afba9278e30ccf6a6ceb3a8b6e336b70068f045c666f2e7f4f9cc5f47db8972",
    ("//1", "sr25519"): "b606fc73f57f03cdb4c932d475ab426043e429cecc2ffff0d2672b0df8398c48",
    ("//11", "sr25519"): "eeab50338d8e5176d3141802d7b010a55dadcd5f23cf8aaafa724627e967e90e",
    ("//0", "ed25519"): "ffe0b81700cedadde9debaf7e61292d80581d4a37896055ba25f491b96b25ee6",
    ("//1", "ed25519"): "bf3a763d817cee09bf785b9cc6118f58dab5c03f3ace6d524899bcb28ac74f27",
    ("//11", "ed25519"): "efe91956ecf147383f508af0763c66c2a1c833ca9e2db3e8f0b51e5bba494530",
    ("//0", "ecdsa"): "0356d97b3f7456436b315d53bc22f39414ed493db5d76d2edc2ce30a09c7ed9117",
    ("//1", "ecdsa"): "0333022898140662dfea847e3cbfe5e989845ac6766e83472f8b0c650d85e77bae",
    ("//11", "ecdsa"): "03e843f200e30bc5b951c73a96d968db1c0cd05e357d910fce159fc59c40e9d6e2",
}


def test_table_derives_numeric_dev_paths_as_substrate_does(known):
    keys = known.keys
    table = {(k.label, k.scheme): k.needle.hex() for k in keys if len(k.needle) != 32 or k.scheme != "ecdsa"}
    for (path, scheme), public in NUMERIC_DEV_PATHS.items():
        assert table[(path, scheme)] == public, (path, scheme)


# Hardhat and Anvil's first test account (address 0xf39F...2266): its secret is in
# their documentation and in orynq-sdk's tests.
HARDHAT_ACCOUNT_0 = "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75"


def test_table_holds_the_hardhat_test_account(known):
    keys = known.keys
    hits = [k for k in keys if k.needle.hex() == HARDHAT_ACCOUNT_0]
    assert [k.scheme for k in hits] == ["ecdsa"]
    assert "public repo" in hits[0].label


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
    launch = {"roles": {"multisig_members": [ss58(exposed)],
                        "committee": [ss58(hashlib.blake2b(ecdsa_pub, digest_size=32).digest())]}}
    found = dev_key_findings(spec, meta, lp.load_well_known([path]), launch)
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
# Rule 6: checkpoint canary (genesis hash, code hash, chain-spec hash, launch manifest)
# ---------------------------------------------------------------------------

def test_genesis_hash_matches_the_live_preprod_genesis(spec):
    wasm = lp.decompressed_code(spec.code)
    assert lp.runtime_state_version(wasm) == 1
    assert lp.genesis_hash(spec.storage, 1).hex() == PREPROD_GENESIS


def pub(key: signing.SigningKey) -> bytes:
    return key.verify_key.encode()


LAUNCH = {"roles": {}}


def test_signed_manifest_for_this_spec_and_launch_passes(spec):
    key = signing.SigningKey.generate()
    assert lp.check_checkpoint(spec, LAUNCH, lp.signed_manifest(spec, LAUNCH, key), pub(key)) == []


def test_changed_genesis_storage_breaks_genesis_and_spec_hash(preprod_path, tmp_path):
    key = signing.SigningKey.generate()
    signed = lp.signed_manifest(lp.load_spec(str(preprod_path)), LAUNCH, key)
    doc = json.loads(preprod_path.read_text())
    alice_key = "0x" + account_key(ALICE).hex()
    doc["genesis"]["raw"]["top"][alice_key] = "0x" + (bytes(16) + (1).to_bytes(16, "little") + bytes(48)).hex()
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(doc))
    found = messages(lp.check_checkpoint(lp.load_spec(str(tampered)), LAUNCH, signed, pub(key)))
    assert any("genesis_hash is 0x" in m for m in found)
    assert any("chain_spec_hash is 0x" in m for m in found)
    assert not any("code_hash" in m for m in found)


def test_changed_runtime_code_breaks_code_hash(spec):
    key = signing.SigningKey.generate()
    signed = lp.signed_manifest(spec, LAUNCH, key)
    signed["code_hash"] = "0x" + bytes(32).hex()
    found = messages(lp.check_checkpoint(spec, LAUNCH, signed, pub(key)))
    assert any("code_hash is 0x" in m for m in found)
    assert any("signature does not verify" in m for m in found)


def test_launch_manifest_changed_after_signing_is_refused(spec):
    key = signing.SigningKey.generate()
    signed = lp.signed_manifest(spec, {"roles": {}, "supply": {"genesis_lock": {"utxo": "aa" * 32 + "#0"}}}, key)
    moved = {"roles": {}, "supply": {"genesis_lock": {"utxo": "bb" * 32 + "#0"}}}
    found = messages(lp.check_checkpoint(spec, moved, signed, pub(key)))
    assert len(found) == 1 and found[0].startswith("[6 checkpoint] launch_manifest_hash is 0x")


def test_launch_manifest_hash_ignores_key_order_and_whitespace():
    a = {"roles": {"oracle": []}, "supply": {"genesis_lock": {"utxo": "u", "address": "a"}}}
    b = json.loads('{"supply": {"genesis_lock": {"address": "a",  "utxo": "u"}}, "roles": {"oracle": []}}')
    assert lp.launch_manifest_hash(a) == lp.launch_manifest_hash(b)


def test_manifest_signed_by_another_key_is_refused(spec):
    signed = lp.signed_manifest(spec, LAUNCH, signing.SigningKey.generate())
    found = messages(lp.check_checkpoint(spec, LAUNCH, signed, pub(signing.SigningKey.generate())))
    assert found == ["[6 checkpoint] signed manifest signature does not verify under the pinned launch key"]


def test_code_substitutes_are_refused(spec):
    key = signing.SigningKey.generate()
    signed = lp.signed_manifest(spec, LAUNCH, key)
    spec.doc["codeSubstitutes"] = {"1": "0x00"}
    found = messages(lp.check_checkpoint(spec, LAUNCH, signed, pub(key)))
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
    found = messages(lp.check_checkpoint(spec, LAUNCH, {"genesis_hash": "0x00"},
                                         pub(signing.SigningKey.generate())))
    assert len(found) == 1 and "signed manifest is malformed" in found[0]


@pytest.mark.parametrize("argv", [
    "materios-node --validator --wasm-runtime-overrides /srv/overrides",
    ["materios-node", "--validator", "--wasm-runtime-overrides=/srv/overrides"],
])
def test_authority_with_a_wasm_override_is_refused(argv):
    launch = {"nodes": [authority(argv)]}
    assert messages(lp.check_code_overrides(launch)) == [
        "[6 checkpoint] authority val1 runs --wasm-runtime-overrides: a local runtime would replace "
        "the signed runtime code"]


def test_a_shell_wrapped_authority_with_a_wasm_override_is_refused():
    launch = {"nodes": [authority(["/bin/bash", "-lc", "exec materios-node --validator "
                                   "--wasm-runtime-overrides /srv/overrides"])]}
    assert messages(lp.check_code_overrides(launch)) == [
        "[6 checkpoint] authority val1 runs --wasm-runtime-overrides: a local runtime would replace "
        "the signed runtime code"]


def test_wasm_override_on_a_non_authority_is_out_of_scope():
    node = {"name": "rpc", "host": "r", "authority": False, "argv": "materios-node --wasm-runtime-overrides /o"}
    assert lp.check_code_overrides({"nodes": [node]}) == []


# ---------------------------------------------------------------------------
# Rule 1: well-known keys
# ---------------------------------------------------------------------------

def dev_key_findings(spec, meta, known, launch=None, manifest_key=None, cardano=NO_CARDANO):
    launch = {"roles": {}} if launch is None else launch
    return messages(lp.check_dev_keys(spec, meta, launch, cardano, manifest_key or pub(signing.SigningKey.generate()),
                                      known))


def test_preprod_genesis_names_alice_as_an_endowed_account(spec, meta, known):
    found = dev_key_findings(spec, meta, known)
    assert "[1 dev-keys] System.Account: //Alice (sr25519) is in genesis" in found


def test_dev_key_in_sudo_and_authorities_is_named_by_storage_item(spec, meta, known):
    bob_ed = bytes.fromhex(SP_KEYRING["ed25519"]["//Bob"])
    put(spec, "Sudo", "Key", CHARLIE)
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
    launch = {"roles": {"multisig_members": ["//Bob//stash", "not a key"]}}
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] roles.multisig_members[0]: well-known secret URI //Bob//stash" in found
    assert any(m.startswith("[1 dev-keys] roles.multisig_members[1]:") for m in found)
    assert not any("not a key" in m for m in found)


def test_bad_ss58_checksum_is_refused(spec, meta, known):
    good = ss58(fresh_account())
    broken = good[:-1] + ("A" if good[-1] != "A" else "B")
    found = dev_key_findings(spec, meta, known, {"roles": {"oracle": [broken]}})
    assert any("roles.oracle[0]" in m and "checksum" in m for m in found)


def test_fresh_role_keys_add_no_findings(spec, meta, known):
    base = dev_key_findings(spec, meta, known)
    launch = {"roles": {"anchor_signer": [ss58(fresh_account())], "oracle": ["0x" + fresh_account().hex()]}}
    assert sorted(set(dev_key_findings(spec, meta, known, launch)) - set(base)) == []


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


def test_dev_keyring_flag_inside_a_wrapper_is_named(spec, meta, known):
    launch = {"roles": {}, "nodes": [
        {"name": "v1", "host": "h1", "authority": False,
         "argv": ["/bin/bash", "-lc", "exec materios-node --validator '--alice'"]},
        {"name": "v2", "host": "h2", "authority": False,
         "argv": ["docker", "run", "--rm", "img", "bash", "-lc", "materios-node --bob"]},
    ]}
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] node v1: --alice loads the dev keyring" in found
    assert "[1 dev-keys] node v2: --bob loads the dev keyring" in found


def test_any_derivation_of_the_dev_phrase_in_a_launch_config_is_named(spec, meta, known):
    launch = {"roles": {"oracle": ["//PriceFeed"]}, "nodes": [
        {"name": "aw", "host": "h1", "argv": ["anchor-worker", "--suri", "//AnchorSigner"],
         "env": {"ORACLE_URI": "//Oracle//hot/1", "RPC": "wss://rpc.example:443",
                 "DATA": "/var/lib//materios", "CDN": "//cdn.example.org/x"}},
    ]}
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] roles.oracle[0]: well-known secret URI //PriceFeed" in found
    assert "[1 dev-keys] node aw: launch config names //AnchorSigner" in found
    assert "[1 dev-keys] node aw: launch config names //Oracle//hot/1" in found
    assert not any(word in m for m in found for word in ("rpc", "materios", "cdn"))


def test_dev_phrase_uri_with_a_password_is_named_without_the_password(spec, meta, known):
    launch = {"roles": {"oracle": ["//Feed///hunter2"]}, "nodes": [
        {"name": "aw", "host": "h1", "argv": ["worker", "--suri=//Alice///s3cret"],
         "env": {"SIGNER_URI": "//Alice//anchor///quartz-9"}},
    ]}
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] roles.oracle[0]: well-known secret URI //Feed" in found
    assert "[1 dev-keys] node aw: launch config names //Alice" in found
    assert "[1 dev-keys] node aw: launch config names //Alice//anchor" in found
    assert not any(secret in m for m in found for secret in ("hunter2", "s3cret", "quartz"))


def test_dev_mnemonic_in_a_launch_config_is_detected_by_hash(spec, meta, known):
    phrase = "one two three four five six seven eight nine ten eleven twelve"
    known = dataclasses.replace(known, phrase_hash=lp.blake2_256(phrase.encode()).hex())
    launch = {"roles": {}, "nodes": [{"name": "v1", "host": "h1", "argv": [],
                                      "env": {"SEED": f"  {phrase.replace(' ', '   ')}//Alice"}}]}
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] node v1: launch config holds the dev mnemonic" in found


# sp-core's DEV_PHRASE as its seed, which @polkadot/keyring exports as DEV_SEED.
DEV_SEED = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"


def test_table_holds_the_dev_seed_by_its_hash(known):
    assert known.seed_hash == lp.blake2_256(bytes.fromhex(DEV_SEED[2:])).hex()


def sidecar(argv=(), **env) -> dict:
    return {"roles": {}, "nodes": [{"name": "cd", "host": "h1", "authority": False, "argv": list(argv), "env": env}]}


@pytest.mark.parametrize("launch, named", [
    (sidecar(SIGNER_URI="/Attestor0"), "/Attestor0"),
    (sidecar(ORACLE_SURI=" //cert.daemon "), "//cert.daemon"),
    (sidecar(SIGNER_URI="/Oracle//hot///hunter2"), "/Oracle//hot"),
    (sidecar(["cert-daemon", "--suri", "/Attestor1"]), "/Attestor1"),
    (sidecar(["cert-daemon", "--signer-uri=/Attestor2"]), "/Attestor2"),
])
def test_a_secret_uri_setting_with_no_phrase_is_named(spec, meta, known, launch, named):
    found = dev_key_findings(spec, meta, known, launch)
    assert f"[1 dev-keys] node cd: launch config names {named}" in found
    assert not any("hunter2" in m for m in found)


@pytest.mark.parametrize("launch", [
    sidecar(SIGNER_URI=DEV_SEED),
    sidecar(SIGNER_URI=DEV_SEED + "//AnchorSigner"),
    sidecar(["worker", "--seed", "0x" + DEV_SEED[2:].upper()]),
])
def test_the_dev_seed_in_a_launch_config_is_named_without_echoing_it(spec, meta, known, launch):
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] node cd: launch config holds the dev seed" in found
    assert not any(DEV_SEED[2:12] in m.lower() for m in found)


def test_file_paths_are_not_secret_uris(spec, meta, known):
    launch = sidecar(["cert-daemon", "--base-path", "/data", "--config=/etc/cd.toml", "--suri-file", "/run/s"],
                     DATA_DIR="/var/lib/materios", SIGNER_URI_FILE="/run/secrets/signer", SEED_PATH="/k/seed")
    assert not any("node cd" in m for m in dev_key_findings(spec, meta, known, launch))


def test_dev_manifest_signing_key_is_refused(spec, meta, known):
    found = dev_key_findings(spec, meta, known, manifest_key=bytes.fromhex(SP_KEYRING["ed25519"]["//Eve"]))
    assert "[1 dev-keys] manifest signing key: //Eve (ed25519)" in found


def test_dev_key_embedded_in_runtime_code_is_named(spec, meta, known):
    spec.storage[lp.CODE_KEY] = lp.ZSTD_PREFIX + zstandard.ZstdCompressor().compress(
        b"\0asm" + bytes(4) + bytes.fromhex(SP_KEYRING["sr25519"]["//Dave"]))
    found = dev_key_findings(spec, meta, known)
    assert "[1 dev-keys] :code (runtime WASM): //Dave (sr25519) is in genesis" in found


# Multisig accounts. The vector is @polkadot/util-crypto createKeyMulti([//Alice, //Bob,
# //Charlie], 2), the address Polkadot's documentation gives for that multisig.
ALICE_BOB_CHARLIE_2 = "5DjYJStmdZ2rcqXbXGX7TW85JsrW6uG4y9MUcLq2BoPMpRA7"


def test_multisig_account_matches_polkadot_js():
    assert ss58(lp.multisig_account([CHARLIE, ALICE, BOB], 2)) == ALICE_BOB_CHARLIE_2
    assert lp.multisig_account([ALICE, BOB], 1).hex() == \
        "4c5901223c7c52585646634e70dd46ad3faf1270f84a4673b5b4a4e126474073"


def sudo_launch(entry, **roles) -> dict:
    return {"roles": {"sudo": [entry], **roles}}


@pytest.mark.parametrize("threshold", [1, 2])
def test_sudo_multisig_with_a_dev_member_is_refused(spec, meta, known, threshold):
    m1, m2 = fresh_account(), fresh_account()
    put(spec, "Sudo", "Key", lp.multisig_account([ALICE, m1, m2], threshold))
    found = dev_key_findings(spec, meta, known, sudo_launch(msig(threshold, ALICE, m1, m2)))
    assert "[1 dev-keys] roles.sudo[0].members[0]: //Alice (sr25519)" in found
    assert not any("Sudo.Key" in m for m in found)


SUDO_FLAT = ("[1 dev-keys] roles.sudo[0] is a single key: Root must be a multisig with a threshold of at least "
             "2, declared by its members so each one is checked")


def test_sudo_declared_by_its_flat_address_is_refused(spec, meta, known):
    """A wallet shows a multisig as one address; declared that way its members go unchecked."""
    hidden = lp.multisig_account([ALICE, fresh_account(), fresh_account()], 1)
    put(spec, "Sudo", "Key", hidden)
    found = dev_key_findings(spec, meta, known, sudo_launch(ss58(hidden)))
    assert SUDO_FLAT in found
    assert not any("Sudo.Key" in m for m in found)


def test_sudo_multisig_that_one_member_can_use_alone_is_refused(spec, meta, known):
    members = [fresh_account() for _ in range(3)]
    put(spec, "Sudo", "Key", lp.multisig_account(members, 1))
    found = dev_key_findings(spec, meta, known, sudo_launch(msig(1, *members)))
    assert "[1 dev-keys] roles.sudo[0] has threshold 1: any one member alone holds Root" in found


def test_sudo_key_that_is_not_the_declared_multisig_is_refused(spec, meta, known):
    m1, m2, m3 = fresh_account(), fresh_account(), fresh_account()
    hidden = lp.multisig_account([ALICE, m1, m2], 2)
    put(spec, "Sudo", "Key", hidden)
    found = dev_key_findings(spec, meta, known, sudo_launch(msig(2, m1, m2, m3)))
    assert f"[1 dev-keys] Sudo.Key {ss58(hidden)} is not the account roles.sudo declares: " \
           "who holds Root is unchecked" in found


def test_undeclared_sudo_role_leaves_root_unchecked(spec, meta, known):
    found = dev_key_findings(spec, meta, known, {"roles": {}})
    assert "[1 dev-keys] roles.sudo is not declared" in found
    sudo = spec.value("Sudo", "Key")
    assert f"[1 dev-keys] Sudo.Key {ss58(sudo)} is not the account roles.sudo declares: " \
           "who holds Root is unchecked" in found


def test_sudo_declared_as_its_multisig_of_held_keys_passes(spec, meta, known):
    members = [fresh_account() for _ in range(3)]
    put(spec, "Sudo", "Key", lp.multisig_account(members, 2))
    found = dev_key_findings(spec, meta, known, sudo_launch(msig(2, *members)))
    assert not any("roles.sudo" in m or "Sudo.Key" in m for m in found)


def test_sudo_role_with_no_sudo_in_genesis_is_refused(spec, meta, known):
    del spec.storage[lp.storage_key("Sudo", "Key")]
    found = dev_key_findings(spec, meta, known, sudo_launch(ss58(fresh_account())))
    assert "[1 dev-keys] roles.sudo declares a key, but genesis sets no Sudo.Key" in found
    assert not any("Sudo.Key" in m and "is not the account" in m
                   for m in dev_key_findings(spec, meta, known, {"roles": {"sudo": []}}))


def test_nested_multisig_members_are_checked(spec, meta, known):
    inner = msig(2, BOB, fresh_account())
    outer = {"threshold": 2, "members": [inner, ss58(fresh_account())]}
    found = dev_key_findings(spec, meta, known, {"roles": {"recovery_friends": [outer]}})
    assert "[1 dev-keys] roles.recovery_friends[0].members[0].members[0]: //Bob (sr25519)" in found


def test_multisig_that_lists_a_member_twice_is_refused(spec, meta, known):
    member = fresh_account()
    found = dev_key_findings(spec, meta, known, {"roles": {"treasury": [msig(2, member, member)]}})
    assert "[1 dev-keys] roles.treasury[0]: a multisig lists a member twice" in found


def test_every_genesis_account_must_be_declared(spec, meta, known):
    member = fresh_account()
    hidden = lp.multisig_account([ALICE, member], 1)
    endow(spec, hidden, 500_000 * MATRA)
    found = dev_key_findings(spec, meta, known, {"roles": {}})
    assert f"[1 dev-keys] genesis account {ss58(hidden)} is not declared in any role: " \
           "who holds it is unchecked" in found
    declared = {"roles": {"endowed": [ss58(a) for a in genesis_accounts(spec) if a != hidden]
                          + [msig(1, ALICE, member)]}}
    assert not any("is not declared in any role" in m for m in dev_key_findings(spec, meta, known, declared))


def test_genesis_account_declared_as_a_multisig_with_a_dev_member_is_refused(spec, meta, known):
    m1 = fresh_account()
    hidden = lp.multisig_account([ALICE, m1], 1)
    endow(spec, hidden, 500_000 * MATRA)
    launch = {"roles": {"endowed": [msig(1, ALICE, m1)]}}
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] roles.endowed[0].members[0]: //Alice (sr25519)" in found
    assert not any(ss58(hidden) in m for m in found)


def test_every_off_chain_role_must_be_declared(spec, meta, known):
    found = dev_key_findings(spec, meta, known, {"roles": {"attestors": [ss58(fresh_account())]}})
    for role in ("sudo", "anchor_signer", "oracle"):
        assert f"[1 dev-keys] roles.{role} is not declared" in found
    assert not any("roles.attestors is" in m for m in found)


@pytest.mark.parametrize("role", ["anchor_signer", "attestors"])
def test_roles_that_always_run_must_name_a_key(spec, meta, known, role):
    found = dev_key_findings(spec, meta, known, {"roles": {role: []}})
    assert f"[1 dev-keys] roles.{role} is empty: name the key that runs it" in found


def test_oracle_declared_empty_states_that_none_runs(spec, meta, known):
    found = dev_key_findings(spec, meta, known, {"roles": {"oracle": []}})
    assert not any("roles.oracle" in m for m in found)


@pytest.mark.parametrize("doc, message", [
    ({"chainType": "Local", "name": "Materios"},
     "chain spec chainType is 'Local', not 'Live': the anchor worker treats the chain as a test "
     "network and accepts a dev signer"),
    ({"chainType": "Live", "name": "Materios Local Mainnet"},
     "chain spec name 'Materios Local Mainnet' reads as a test network: the anchor worker treats "
     "the chain as one and accepts a dev signer"),
    ({"chainType": "Live", "name": "Materios Preprod v6"},
     "chain spec name 'Materios Preprod v6' reads as a test network: the anchor worker treats "
     "the chain as one and accepts a dev signer"),
    ({"chainType": {"Custom": "staging"}, "name": "Materios"},
     "chain spec chainType is {'Custom': 'staging'}, not 'Live': the anchor worker treats the chain "
     "as a test network and accepts a dev signer"),
])
def test_a_spec_the_anchor_worker_reads_as_a_test_network_is_refused(spec, doc, message):
    spec.doc.update(doc)
    assert messages(lp.check_chain_identity(spec)) == [f"[1 dev-keys] {message}"]


def test_a_live_spec_with_a_plain_name_passes_the_chain_identity_check(spec):
    spec.doc.update({"chainType": "Live", "name": "Materios"})
    assert lp.check_chain_identity(spec) == []


def test_test_network_names_are_one_pattern_shared_with_the_anchor_worker():
    shared = json.loads((HERE / "test_networks.json").read_text())
    assert shared == {"chain_types": ["Development", "Local"],
                      "name_pattern": "\\b(preprod|testnet|devnet|development|local)\\b"}


# ---------------------------------------------------------------------------
# Rule 1 and 3: the Cardano permissioned candidates (the committee after the first rotation)
# ---------------------------------------------------------------------------

def candidate(aura: bytes, gran: bytes | None = None, sidechain: bytes | None = None) -> lp.Candidate:
    return lp.Candidate(sidechain or bytes([2]) + fresh_account(),
                        {"aura": aura, "gran": gran or fresh_account()})


def test_dev_key_in_a_cardano_permissioned_candidate_is_named(spec, meta, known):
    alice_ed = bytes.fromhex(SP_KEYRING["ed25519"]["//Alice"])
    cardano = lp.CardanoView(lock=None, candidates=[candidate(fresh_account()), candidate(ALICE, alice_ed)])
    found = dev_key_findings(spec, meta, known, cardano=cardano)
    assert "[1 dev-keys] Cardano permissioned candidate 1 aura: //Alice (sr25519)" in found
    assert "[1 dev-keys] Cardano permissioned candidate 1 gran: //Alice (ed25519)" in found


def legacy_datum(rows) -> bytes:
    return cbor2.dumps([list(row) for row in rows])


def versioned_datum(appendix, version) -> bytes:
    return cbor2.dumps([cbor2.CBORTag(121, []), appendix, version])


def test_permissioned_candidate_datums_decode_in_every_partner_chains_format():
    sc, aura, gran = bytes([2]) * 33, bytes([1]) * 32, bytes([3]) * 32
    want = [lp.Candidate(sc, {"aura": aura, "gran": gran})]
    assert lp.decode_candidates(legacy_datum([(sc, aura, gran)])) == want
    assert lp.decode_candidates(versioned_datum([[sc, aura, gran]], 0)) == want
    v1 = versioned_datum([[sc, [[b"aura", aura], [b"gran", gran]]]], 1)
    assert lp.decode_candidates(v1) == want


def test_three_legacy_candidates_are_not_read_as_a_versioned_datum():
    rows = [(bytes([2]) * 33, bytes([i]) * 32, bytes([9]) * 32) for i in range(3)]
    assert [c.keys["aura"] for c in lp.decode_candidates(legacy_datum(rows))] == [bytes([i]) * 32 for i in range(3)]


@pytest.mark.parametrize("raw", [
    b"\xff\x00",
    cbor2.dumps({"not": "a list"}),
    versioned_datum([[b"\x02" * 33, b"\x01" * 32]], 0),
    versioned_datum([], 7),
    versioned_datum([[b"\x02" * 33, [[b"toolong", b"\x01"]]]], 1),
])
def test_undecodable_candidate_datum_is_an_input_error(raw):
    with pytest.raises(lp.InputError, match="permissioned candidates"):
        lp.decode_candidates(raw)


def test_permissioned_candidates_policy_is_read_from_genesis(spec):
    assert lp.permissioned_candidates_policy(spec).hex() == \
        "ef2890d1e98247819abcf2df6e891824ed950a4216d36c71ee6f9974"


# ---------------------------------------------------------------------------
# Rule 2: explicit attestor rewards
# ---------------------------------------------------------------------------

VALIDATOR_REWARD_PER_ERA = 102_739_726
TUNED = {"attestation_reward_per_signer": 1 * MATRA, "era_cap_base": 50_000 * MATRA,
         "era_cap_baseline_attestor_count": 32, "validator_reward_per_era": VALIDATOR_REWARD_PER_ERA,
         "treasury_emission_share_perbill": 150_000_000}


@pytest.fixture
def runtime_meta(metadata_v14) -> lp.Metadata:
    return lp.Metadata.from_v14(with_constants(metadata_v14))


def test_undeclared_rewards_are_refused(spec, runtime_meta):
    found = messages(lp.check_rewards(spec, runtime_meta, {"economics": {}}))
    assert len(found) == 5
    assert all("is not declared as an integer" in m for m in found)
    assert "[2 rewards] economics.validator_reward_per_era is not declared as an integer; " \
           "validator rewards must be explicit" in found


def test_genesis_that_dropped_the_tuned_rewards_is_refused(spec, runtime_meta):
    found = messages(lp.check_rewards(spec, runtime_meta, {"economics": TUNED}))
    assert found == [
        "[2 rewards] OrinqReceipts.AttestationRewardPerSigner stores 10000000, declared 1000000",
        "[2 rewards] OrinqReceipts.EraCapBaselineAttestorCount stores 16, declared 32",
    ]


def test_rewards_missing_from_genesis_are_refused(spec, runtime_meta):
    for _, item, _ in lp.REWARD_ITEMS:
        del spec.storage[lp.storage_key("OrinqReceipts", item)]
    found = messages(lp.check_rewards(spec, runtime_meta, {"economics": TUNED}))
    assert found == [f"[2 rewards] OrinqReceipts.{item} is not set in genesis (declared {TUNED[field]})"
                     for field, item, _ in lp.REWARD_ITEMS]


def test_stored_rewards_equal_to_declared_pass(spec, runtime_meta):
    put(spec, "OrinqReceipts", "AttestationRewardPerSigner", (1 * MATRA).to_bytes(16, "little"))
    put(spec, "OrinqReceipts", "EraCapBaselineAttestorCount", (32).to_bytes(4, "little"))
    assert lp.check_rewards(spec, runtime_meta, {"economics": TUNED}) == []


def test_declared_validator_reward_that_differs_from_the_runtime_is_refused(spec, runtime_meta):
    economics = dict(TUNED, validator_reward_per_era=50, treasury_emission_share_perbill=100_000_000)
    found = messages(lp.check_rewards(spec, runtime_meta, {"economics": economics}))
    assert "[2 rewards] OrinqReceipts.ValidatorRewardPerEra is 102739726 in the runtime, declared 50" in found
    assert "[2 rewards] OrinqReceipts.TreasuryEmissionShare is 150000000 in the runtime, declared 100000000" in found


def test_runtime_that_hides_its_validator_reward_is_refused(spec, meta):
    found = messages(lp.check_rewards(spec, meta, {"economics": TUNED}))
    assert "[2 rewards] the runtime metadata does not declare OrinqReceipts.ValidatorRewardPerEra, " \
           "so the validator reward cannot be checked" in found


def test_zero_baseline_is_refused(spec, runtime_meta):
    put(spec, "OrinqReceipts", "EraCapBaselineAttestorCount", bytes(4))
    economics = dict(TUNED, era_cap_baseline_attestor_count=0)
    found = messages(lp.check_rewards(spec, runtime_meta, {"economics": economics}))
    assert "[2 rewards] economics.era_cap_baseline_attestor_count is zero" in found


# ---------------------------------------------------------------------------
# Rule 3: unsafe RPC on authorities
# ---------------------------------------------------------------------------

def rpc_findings(tmp_path, nodes, config=None, proxy_node="edge", kind="nginx", authorities=(), other_targets=()):
    """Rule 3 on a validated launch. A proxy node the test does not declare runs on its own machine."""
    proxies = []
    if config is not None:
        conf = tmp_path / ("proxy.yml" if kind == "cloudflared" else "nginx.conf")
        conf.write_text(config)
        proxies = [{"name": "public-rpc", "node": proxy_node, "kind": kind, "config": str(conf),
                    "other_targets": list(other_targets)}]
        if proxy_node not in {node["name"] for node in nodes}:
            nodes = [*nodes, {"name": proxy_node, "host": proxy_node, "authority": False}]
    launch = {"roles": {}, "supply": VALID_LOCK, "nodes": nodes, "rpc_proxies": proxies}
    lp.validate_launch(launch)
    return messages(lp.check_rpc(launch, list(authorities)))


def authority(argv, host="val1", name="val1", aura=None):
    return {"name": name, "host": host, "authority": True, "aura": "0x" + (aura or fresh_account()).hex(),
            "argv": argv}


UNSAFE_9945 = "materios-node --validator --rpc-methods unsafe --rpc-port 9945"


def test_unsafe_methods_on_an_external_listener_are_refused(tmp_path):
    found = rpc_findings(tmp_path, [authority("materios-node --validator --rpc-methods unsafe --unsafe-rpc-external")])
    assert found == ["[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


def test_unsafe_methods_behind_a_loopback_proxy_on_the_same_host_are_refused(tmp_path):
    nginx = "location /rpc { proxy_pass http://127.0.0.1:9945; }"
    found = rpc_findings(tmp_path, [authority("materios-node --rpc-methods=Unsafe --rpc-port 9945")], nginx, "val1")
    assert found == ["[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_default_methods_on_loopback_are_unsafe_so_a_proxy_is_refused(tmp_path):
    nginx = "upstream chain { server val1:9944; }\nlocation / { proxy_pass http://chain; }"
    found = rpc_findings(tmp_path, [authority(["materios-node", "--validator"])], nginx)
    assert found == ["[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


@pytest.mark.parametrize("argv", [
    "materios-node --validator --rpc-external",
    "materios-node --validator --rpc-methods safe --unsafe-rpc-external",
    "materios-node --validator --rpc-methods safe --rpc-port 9945",
])
def test_safe_methods_pass_even_when_exposed(tmp_path, argv):
    nginx = "location / { proxy_pass http://127.0.0.1:9945; }"
    assert rpc_findings(tmp_path, [authority(argv)], nginx, "val1") == []


def test_proxy_to_another_host_or_port_does_not_implicate_the_authority(tmp_path):
    nginx = "location / { proxy_pass http://rpc-node:9944; } location /b { proxy_pass http://127.0.0.1:9944; }"
    assert rpc_findings(tmp_path, [authority("materios-node --rpc-methods unsafe")], nginx, "edge",
                        other_targets=["rpc-node:9944"]) == []


def test_a_proxy_must_run_on_a_declared_node(tmp_path):
    conf = tmp_path / "tunnel.yml"
    conf.write_text(CLOUDFLARED.format(service="http://localhost:9945"))
    launch = {"roles": {}, "supply": VALID_LOCK, "nodes": [authority(UNSAFE_9945)],
              "rpc_proxies": [{"name": "tunnel", "node": "val1.lan", "kind": "cloudflared", "config": str(conf)}]}
    with pytest.raises(lp.InputError, match="rpc_proxies\\[0\\] runs on val1.lan, which is not a declared node"):
        lp.validate_launch(launch)


@pytest.mark.parametrize("target", ["http://val1.lan:9945", "http://VAL1.internal:9945", "http://10.9.9.9:9945"])
def test_a_proxy_target_that_is_no_declared_address_is_an_input_error(tmp_path, target):
    nginx = f"location / {{ proxy_pass {target}; }}"
    with pytest.raises(lp.InputError, match="forwards to .*, which is no declared node's host or address"):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1")


def test_other_targets_name_routes_that_reach_no_launch_node(tmp_path):
    nginx = "location / { proxy_pass https://rpc.example.org; }"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, other_targets=["rpc.example.org:443"]) == []


def test_loopback_reaches_every_node_on_the_proxy_machine(tmp_path):
    edge = {"name": "edge", "host": "box1", "authority": False}
    nginx = "location / { proxy_pass http://127.0.0.1:9945; }"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945, host="box1"), edge], nginx, "edge") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_proxy_to_another_address_of_the_authority_is_refused(tmp_path):
    node = dict(authority("materios-node --rpc-methods unsafe --rpc-port 9950"), addresses=["10.1.2.3", "val1.lan"])
    nginx = "location /rpc { proxy_pass http://10.1.2.3:9950/; }"
    assert rpc_findings(tmp_path, [node], nginx) == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


@pytest.mark.parametrize("target", [
    "http://LOCALHOST:9945", "http://localhost.:9945", "http://rpc.localhost:9945", "http://127.1:9945",
    "http://127.0.0.2:9945", "http://2130706433:9945", "http://[::ffff:127.0.0.1]:9945",
    "http://[::1]:9945", "http://0.0.0.0:9945", "ws://127.0.0.1:9945",
])
def test_every_spelling_of_the_proxy_host_itself_reaches_the_authority(tmp_path, target):
    nginx = f"location / {{ proxy_pass {target}; }}"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_nginx_stream_proxy_is_a_route(tmp_path):
    nginx = "stream { server { listen 8443; proxy_pass 127.0.0.1:9945; } }"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_nginx_stream_proxy_to_an_upstream_is_a_route(tmp_path):
    nginx = "stream { upstream rpc { server val1:9945 weight=2; } server { listen 8443; proxy_pass rpc; } }"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx) == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


@pytest.mark.parametrize("directive", ["grpc_pass grpc://127.0.0.1:9945", "uwsgi_pass 127.0.0.1:9945",
                                       "fastcgi_pass localhost:9945", "scgi_pass 127.0.0.1:9945"])
def test_every_nginx_forwarding_directive_is_a_route(tmp_path, directive):
    nginx = f"location / {{ {directive}; }}"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_nginx_include_is_followed(tmp_path):
    (tmp_path / "conf.d").mkdir()
    (tmp_path / "conf.d" / "rpc.conf").write_text("location / { proxy_pass http://127.0.0.1:9945; }")
    nginx = "http { server { listen 80; include conf.d/*.conf; } }"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_nginx_include_absolute_path_is_followed(tmp_path):
    route = tmp_path / "route.inc"
    route.write_text("location / { proxy_pass http://127.0.0.1:9945; }")
    nginx = f"http {{ server {{ listen 80; include {route}; }} }}"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_nginx_include_that_cannot_be_read_is_an_input_error(tmp_path):
    nginx = "http { server { listen 80; include /nonexistent/nginx/rpc.inc; location / { proxy_pass http://x:1; } } }"
    with pytest.raises(lp.InputError, match="include /nonexistent/nginx/rpc.inc matches no file"):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1")


def test_nginx_dump_carries_its_includes(tmp_path):
    dump = ("# configuration file /etc/nginx/nginx.conf:\n"
            "stream { include /etc/nginx/streams/*.conf; }\n"
            "http { include /etc/nginx/rpc-route.inc; }\n\n"
            "# configuration file /etc/nginx/rpc-route.inc:\n"
            "server { location / { proxy_pass http://127.0.0.1:9945; } }\n")
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], dump, "val1") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_nginx_dump_missing_an_included_file_is_an_input_error(tmp_path):
    dump = ("# configuration file /etc/nginx/nginx.conf:\n"
            "http { include /etc/nginx/rpc-route.inc; server { location / { proxy_pass http://x:1; } } }\n")
    with pytest.raises(lp.InputError, match="include /etc/nginx/rpc-route.inc"):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], dump, "val1")


@pytest.mark.parametrize("config, error", [
    ("events {}\nhttp { server { listen 80; root /srv; } }", "has no forwarding route"),
    ("location / { proxy_pass http://unix:/run/node.sock; }", "unix socket"),
    ("location / { proxy_pass http://$backend; }", "is a variable"),
    ("location / { uwsgi_pass val1; }", "names no port"),
])
def test_nginx_config_the_preflight_cannot_bound_is_an_input_error(tmp_path, config, error):
    with pytest.raises(lp.InputError, match=error):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], config, "val1")


CLOUDFLARED = """\
tunnel: 00000000-0000-0000-0000-000000000000
credentials-file: /etc/cloudflared/tunnel.json
ingress:
  - hostname: status.example.org
    service: http_status:204
  - hostname: rpc.example.org
    service: {service}
  - service: http_status:404
"""


@pytest.mark.parametrize("service", ["http://localhost:9945", "'ws://127.0.0.1:9945'", "tcp://[::1]:9945",
                                     "https://LOCALHOST:9945/rpc"])
def test_cloudflared_ingress_is_a_route(tmp_path, service):
    config = CLOUDFLARED.format(service=service)
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], config, "val1", "cloudflared") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_cloudflared_single_origin_url_is_a_route(tmp_path):
    config = "tunnel: t\nurl: http://127.0.0.1:9945\n"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], config, "val1", "cloudflared") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


@pytest.mark.parametrize("config, error", [
    (CLOUDFLARED.format(service="unix:/run/node.sock"), "cannot tell which node"),
    (CLOUDFLARED.format(service="bastion"), "cannot tell which node"),
    (CLOUDFLARED.format(service="socks5"), "cannot tell which node"),
    (CLOUDFLARED.format(service="tcp://val1"), "names no port"),
    (CLOUDFLARED.format(service="http://val1:9945") + "warp-routing:\n  enabled: true\n", "warp-routing"),
    (CLOUDFLARED.format(service="http://val1:9945") + "originRequest:\n  bastionMode: true\n", "bastion"),
    (CLOUDFLARED.format(service="tcp://val1:9945") + "originRequest:\n  proxyType: socks\n", "SOCKS"),
    ("tunnel: t\ningress:\n  - service: http_status:404\n", "has no forwarding route"),
    ("ingress: [unclosed", "not YAML"),
])
def test_cloudflared_config_the_preflight_cannot_bound_is_an_input_error(tmp_path, config, error):
    with pytest.raises(lp.InputError, match=error):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], config, "val1", "cloudflared")


def test_non_authority_nodes_are_out_of_scope(tmp_path):
    node = {"name": "rpc", "host": "r", "authority": False, "argv": "materios-node --rpc-methods unsafe --rpc-external"}
    assert rpc_findings(tmp_path, [node]) == []


@pytest.mark.parametrize("endpoint", [
    "listen-addr=0.0.0.0:9944,methods=unsafe",
    "listen-addr=[::]:9955,cors=all,methods=Unsafe",
])
def test_unsafe_experimental_endpoint_on_an_external_address_is_refused(tmp_path, endpoint):
    argv = ["materios-node", "--validator", "--rpc-methods", "safe", "--experimental-rpc-endpoint", endpoint]
    assert rpc_findings(tmp_path, [authority(argv)]) == [
        "[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


def test_loopback_experimental_endpoint_behind_a_proxy_is_refused(tmp_path):
    argv = ["materios-node", "--rpc-methods", "safe", "--experimental-rpc-endpoint", "listen-addr=127.0.0.1:9966"]
    nginx = "location / { proxy_pass http://127.0.0.1:9966; }"
    assert rpc_findings(tmp_path, [authority(argv)], nginx, "val1") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_safe_experimental_endpoint_passes(tmp_path):
    argv = ["materios-node", "--rpc-methods", "safe",
            "--experimental-rpc-endpoint=listen-addr=0.0.0.0:9944,methods=safe"]
    nginx = "location / { proxy_pass http://127.0.0.1:9944; }"
    assert rpc_findings(tmp_path, [authority(argv)], nginx, "val1") == []


def test_experimental_endpoint_without_listen_addr_is_an_input_error(tmp_path):
    argv = ["materios-node", "--experimental-rpc-endpoint", "methods=unsafe"]
    with pytest.raises(lp.InputError, match="listen-addr"):
        rpc_findings(tmp_path, [authority(argv)])


# A systemd unit as a validator bootstrap writes it: a login shell that loads the
# node's environment, then execs the node.
BOOTSTRAP_EXECSTART = ("/bin/bash -lc 'set -a; . /etc/materios/node.env; set +a; "
                       "exec /usr/local/bin/materios-node-spo --validator --chain /etc/materios/mainnet-raw.json "
                       "--rpc-methods unsafe --rpc-port 9945 --unsafe-rpc-external'")
UNSAFE_EXTERNAL = "materios-node --validator --rpc-methods unsafe --unsafe-rpc-external"


@pytest.mark.parametrize("argv", [
    BOOTSTRAP_EXECSTART,
    ["sh", "-c", "exec " + UNSAFE_EXTERNAL],
    ["/bin/bash", "-l", "-c", "mkdir -p /data &&\n" + UNSAFE_EXTERNAL],
    ["bash", "-ec", "exec bash -c 'exec " + UNSAFE_EXTERNAL + "'"],
    ["dash", "-c", "RUST_LOG=info " + UNSAFE_EXTERNAL],
])
def test_a_shell_wrapped_launch_is_read_as_the_node_it_runs(tmp_path, argv):
    assert rpc_findings(tmp_path, [authority(argv)]) == [
        "[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


@pytest.mark.parametrize("argv, error", [
    ("materios-node --validator $RPC_FLAGS", "expands a variable"),
    (["materios-node", "--validator", "${RPC_FLAGS}"], "expands a variable"),
    (["bash", "-lc", "exec materios-node --validator `cat /etc/flags`"], "expands a variable"),
    (["docker", "run", "--rm", "img", "bash", "-lc", "exec " + UNSAFE_EXTERNAL], "runs docker, not a node binary"),
    (["materios-node", "--validator --rpc-methods unsafe --unsafe-rpc-external"], "argument 1 holds several"),
    (["bash", "-lc", UNSAFE_EXTERNAL + " | tee /var/log/node.log"], "uses '|'"),
    (["bash", "-lc", UNSAFE_EXTERNAL + " >> /var/log/node.log 2>&1"], "uses '>>'"),
    (["bash", "-lc", "materios-node --validator || " + UNSAFE_EXTERNAL], "uses '||'"),
    (["bash", "/opt/start-node.sh"], "without -c"),
    (["bash", "-c", "exec materios-node --validator", "arg0"], "must end with its -c script"),
    (["bash", "-lc", "materios-node --validator; echo started"], "runs echo, not a node binary"),
    (["bash", "-lc", "exec materios-node --name 'unbalanced"], "does not parse"),
    ([], "runs nothing, not a node binary"),
])
def test_an_authority_launch_the_preflight_cannot_read_is_an_input_error(tmp_path, argv, error):
    with pytest.raises(lp.InputError, match=error):
        lp.validate_node(authority(argv), "nodes[0]")


def test_a_shell_wrapped_non_authority_validator_is_refused(tmp_path):
    node = {"name": "v9", "host": "h9", "authority": False,
            "argv": ["/bin/bash", "-lc", "exec materios-node --validator --rpc-methods safe"]}
    assert rpc_findings(tmp_path, [node]) == ["[3 rpc] node v9 runs --validator but is not declared an authority"]


def test_validator_not_declared_an_authority_is_refused(tmp_path):
    node = {"name": "v9", "host": "h9", "authority": False,
            "argv": "materios-node --validator --rpc-methods unsafe --rpc-external"}
    assert rpc_findings(tmp_path, [node]) == [
        "[3 rpc] node v9 runs --validator but is not declared an authority"]


def test_unknown_rpc_methods_value_is_refused(tmp_path):
    found = rpc_findings(tmp_path, [authority("materios-node --rpc-methods everything")])
    assert found == ["[3 rpc] node val1: unknown --rpc-methods everything"]


def test_every_authority_needs_a_node_entry(tmp_path):
    listed, missing = fresh_account(), fresh_account()
    authorities = [("genesis Aura.Authorities[0]", listed), ("Cardano permissioned candidate 0", missing)]
    found = rpc_findings(tmp_path, [authority("materios-node --validator --rpc-methods safe", aura=listed)],
                         authorities=authorities)
    assert found == [f"[3 rpc] Cardano permissioned candidate 0 (aura 0x{missing.hex()}) has no authority "
                     "node in the launch manifest: its RPC listeners are unchecked"]


def test_authority_left_out_of_nodes_behind_a_proxy_is_refused(tmp_path):
    nginx = "location / { proxy_pass http://127.0.0.1:9945; }"
    aura = fresh_account()
    found = rpc_findings(tmp_path, [], nginx, authorities=[("genesis Aura.Authorities[0]", aura)])
    assert found == [f"[3 rpc] genesis Aura.Authorities[0] (aura 0x{aura.hex()}) has no authority node in the "
                     "launch manifest: its RPC listeners are unchecked"]


def test_authorities_come_from_genesis_aura_and_the_cardano_candidates(spec):
    extra = fresh_account()
    cardano = lp.CardanoView(lock=None, candidates=[candidate(extra)])
    labels = lp.authorities(spec, cardano)
    assert [aura for _, aura in labels] == aura_keys(spec) + [extra]
    assert labels[0][0] == "genesis Aura.Authorities[0]"
    assert labels[-1][0] == "Cardano permissioned candidate 0"


# ---------------------------------------------------------------------------
# Rule 4: endowments and supply
# ---------------------------------------------------------------------------

# A preprod cert-daemon account. Its chain-spec source endows BondRequirement +
# 100 MATRA; the genesis preprod actually launched with gave it 100 MATRA.
PREPROD_ATTESTOR = bytes.fromhex("44f3bafbc393f24fcfabbf57d4ca73a6a6b5df358cdaa9480a517a97f189964b")
FLOOR = 1_000 * MATRA + 500 + 100 * MATRA
RESERVES = {"ValidatorEmissionReserve": 150_000_000 * MATRA, "AttestationRewardReserve": 50_000_000 * MATRA}
RUNTIME_CONSTANTS = dict(RESERVES, ValidatorRewardPerEra=VALIDATOR_REWARD_PER_ERA)
# Bech32 mainnet enterprise addresses for the payment credential 0x5c * 28: one a script, one a key.
SCRIPT_ADDRESS = "addr1w9w9chzut3w9chzut3w9chzut3w9chzut3w9chzut3w9chqelrggd"
KEY_ADDRESS = "addr1v9w9chzut3w9chzut3w9chzut3w9chzut3w9chzut3w9chqshlgld"
TEST_SCRIPT_ADDRESS = "addr_test1wpw9chzut3w9chzut3w9chzut3w9chzut3w9chzut3w9chqzhh58g"
LOCK_TX = "5a" * 32
LOCK = {"utxo": f"{LOCK_TX}#1", "address": SCRIPT_ADDRESS}


def kupo_output(address=SCRIPT_ADDRESS, assets=None, tx=LOCK_TX, index=1, datum_hash=None) -> dict:
    """An unspent output as Kupo's /matches returns it."""
    return {"transaction_index": 0, "transaction_id": tx, "output_index": index, "address": address,
            "value": {"coins": 2_000_000, "assets": assets or {}},
            "datum_hash": datum_hash, "datum_type": "inline" if datum_hash else None, "script_hash": None,
            "created_at": {"slot_no": 1, "header_hash": "00" * 32}, "spent_at": None}


def locked(amount, address=SCRIPT_ADDRESS, unit=lp.CMATRA_UNIT) -> lp.CardanoView:
    return lp.CardanoView(lock=kupo_output(address, {unit: amount}), candidates=[])


def with_constants(metadata_v14: dict, constants=None) -> dict:
    """The fixture metadata plus the u128 OrinqReceipts constants a runtime
    that declares its emission reserves and validator reward exposes."""
    v14 = copy.deepcopy(metadata_v14)
    pallet = next(p for p in v14["pallets"] if p["name"] == "OrinqReceipts")
    pallet["constants"] = list(pallet.get("constants") or []) + [
        {"name": name, "value": list(value.to_bytes(16, "little"))}
        for name, value in (RUNTIME_CONSTANTS if constants is None else constants).items()]
    return v14


def roster(spec) -> list[str]:
    """One attestor endowed at the floor, so a supply test sees only what it sets up."""
    attestor = fresh_account()
    endow(spec, attestor, FLOOR)
    return [ss58(attestor)]


def issuance_of(spec) -> int:
    return int.from_bytes(spec.value("Balances", "TotalIssuance"), "little")


def supply_findings(spec, meta, attestors, fee_buffer, cardano=None, lock=LOCK):
    if cardano is None:
        cardano = locked(issuance_of(spec) + 200_000_000 * MATRA)
    launch = {"roles": {"attestors": attestors}, "economics": {"fee_buffer": fee_buffer},
              "supply": {"genesis_lock": lock}}
    return messages(lp.check_supply(spec, meta, launch, cardano))


def test_attestor_endowed_at_bond_plus_ed_plus_buffer_passes(spec, runtime_meta):
    attestor = fresh_account()
    endow(spec, attestor, FLOOR)
    assert supply_findings(spec, runtime_meta, [ss58(attestor)], 100 * MATRA) == []


def test_attestor_endowed_one_unit_below_the_floor_is_refused(spec, runtime_meta):
    attestor = fresh_account()
    endow(spec, attestor, FLOOR - 1)
    found = supply_findings(spec, runtime_meta, [ss58(attestor)], 100 * MATRA)
    assert found == [f"[4 supply] roles.attestors[0] is endowed {FLOOR - 1}, below "
                     f"bond + existential deposit + fee buffer = {FLOOR}"]


def test_preprod_genesis_endowed_its_attestors_below_the_bond(spec, runtime_meta):
    found = supply_findings(spec, runtime_meta, [ss58(PREPROD_ATTESTOR)], 0)
    assert found == ["[4 supply] roles.attestors[0] is endowed 100000000, below "
                     "bond + existential deposit + fee buffer = 1000000500"]


def test_unendowed_attestor_is_refused(spec, runtime_meta):
    found = supply_findings(spec, runtime_meta, [ss58(fresh_account())], 0)
    assert len(found) == 1 and "is endowed 0" in found[0]


def test_multisig_attestor_is_sized_by_its_account(spec, runtime_meta):
    members = [fresh_account(), fresh_account()]
    endow(spec, lp.multisig_account(members, 2), FLOOR)
    launch_attestors = [msig(2, *members)]
    assert supply_findings(spec, runtime_meta, launch_attestors, 100 * MATRA) == []


def test_endowment_floor_needs_every_input(spec, runtime_meta):
    found = supply_findings(spec, runtime_meta, [ss58(PREPROD_ATTESTOR)], None)
    assert found[0].startswith("[4 supply] cannot size attestor endowments")


def test_runtime_emission_reserves_above_the_cardano_lock_are_refused(spec, runtime_meta):
    attestors = roster(spec)
    issuance = issuance_of(spec)
    found = supply_findings(spec, runtime_meta, attestors, 0, locked(issuance))
    assert found == [f"[4 supply] Materios can issue {issuance + 200_000_000 * MATRA} (genesis {issuance} "
                     f"+ runtime emission reserves {200_000_000 * MATRA}) against {issuance} cMATRA "
                     f"locked on Cardano at {LOCK_TX}#1: the difference is reserve counted both as "
                     "cMATRA and as MATRA"]


def test_genesis_and_emission_reserves_fully_locked_pass(spec, runtime_meta):
    assert supply_findings(spec, runtime_meta, roster(spec), 0) == []


def test_genesis_issuance_above_the_cardano_lock_is_refused(spec, metadata_v14):
    no_emission = {"ValidatorEmissionReserve": 0, "AttestationRewardReserve": 0}
    meta = lp.Metadata.from_v14(with_constants(metadata_v14, no_emission))
    found = supply_findings(spec, meta, roster(spec), 0, locked(975_000 * MATRA))
    assert len(found) == 1 and "counted both as cMATRA and as MATRA" in found[0]


def test_the_backing_is_what_cardano_holds_not_a_declared_number(spec, runtime_meta):
    """A launch that names the whole 277.5M reserve as backing but locked only
    G on Cardano is refused on what Cardano holds."""
    found = supply_findings(spec, runtime_meta, roster(spec), 0, locked(975_000 * MATRA))
    assert any(f"against {975_000 * MATRA} cMATRA locked on Cardano" in m for m in found)


def test_lock_that_is_spent_or_unindexed_is_refused(spec, runtime_meta):
    found = supply_findings(spec, runtime_meta, roster(spec), 0, lp.CardanoView(lock=None, candidates=[]))
    assert found == [f"[4 supply] the genesis lock {LOCK_TX}#1 is not an unspent output the Kupo index "
                     "holds: nothing backs genesis issuance"]


def test_lock_at_a_key_address_is_refused(spec, runtime_meta):
    lock = dict(LOCK, address=KEY_ADDRESS)
    found = supply_findings(spec, runtime_meta, roster(spec), 0, locked(10**18, KEY_ADDRESS), lock)
    assert found == [f"[4 supply] the genesis lock {LOCK_TX}#1 sits at {KEY_ADDRESS}, whose payment "
                     "credential is a key: its holder can spend the backing"]


def test_lock_somewhere_other_than_declared_is_refused(spec, runtime_meta):
    other = "addr1wxw9chzut3w9chzut3w9chzut3w9chzut3w9chzut3w9chqp5f7c3"
    found = supply_findings(spec, runtime_meta, roster(spec), 0, locked(10**18, other))
    assert f"[4 supply] the genesis lock {LOCK_TX}#1 sits at {other}, not the declared {SCRIPT_ADDRESS}" in found


def test_lock_on_a_test_network_is_refused(spec, runtime_meta):
    lock = dict(LOCK, address=TEST_SCRIPT_ADDRESS)
    found = supply_findings(spec, runtime_meta, roster(spec), 0, locked(10**18, TEST_SCRIPT_ADDRESS), lock)
    assert f"[4 supply] the genesis lock address {TEST_SCRIPT_ADDRESS} is not a Cardano mainnet address" in found


def test_lock_holding_another_token_backs_nothing(spec, runtime_meta):
    cardano = locked(10**18, unit="98c61f406f7c8df11ccff49ca1631d8bca9663894537c6c5ee5ed418.634d41545241")
    found = supply_findings(spec, runtime_meta, roster(spec), 0, cardano)
    assert any("against 0 cMATRA locked on Cardano" in m for m in found)


def test_issuance_below_what_genesis_accounts_hold_is_refused(spec, runtime_meta):
    held = issuance_of(spec)
    put(spec, "Balances", "TotalIssuance", (1).to_bytes(16, "little"))
    found = supply_findings(spec, runtime_meta, [], 0, locked(held + 200_000_000 * MATRA - 1))
    assert f"[4 supply] Balances.TotalIssuance stores 1, but genesis accounts hold {held}" in found
    assert any(f"(genesis {held} + runtime emission reserves" in m for m in found)


def test_missing_issuance_is_refused_and_accounts_still_count(spec, runtime_meta):
    held = issuance_of(spec)
    del spec.storage[lp.storage_key("Balances", "TotalIssuance")]
    found = supply_findings(spec, runtime_meta, [], 0, locked(held + 200_000_000 * MATRA))
    assert f"[4 supply] Balances.TotalIssuance stores 0, but genesis accounts hold {held}" in found


def test_reserved_balances_count_toward_issuance(spec, runtime_meta):
    account = fresh_account()
    spec.storage[account_key(account)] = bytes(32) + (5 * MATRA).to_bytes(16, "little") + bytes(32)
    held = issuance_of(spec) + 5 * MATRA
    found = supply_findings(spec, runtime_meta, [], 0)
    assert f"[4 supply] Balances.TotalIssuance stores {held - 5 * MATRA}, but genesis accounts hold {held}" in found


def test_empty_attestor_roster_is_refused(spec, runtime_meta):
    found = supply_findings(spec, runtime_meta, [], 0)
    assert "[4 supply] roles.attestors names no account: the endowment floor has nothing to check" in found


def with_billing(metadata_v14: dict) -> lp.Metadata:
    """The fixture metadata plus the billing pallet, whose withdrawal path mints MATRA."""
    v14 = copy.deepcopy(metadata_v14)
    v14["pallets"].append({"name": "Billing", "constants": [], "storage": {
        "prefix": "Billing", "entries": [{"name": "Balances"}, {"name": "PendingWithdrawals"}]}})
    return lp.Metadata.from_v14(v14)


def map_key(pallet: str, item: str, account: bytes) -> bytes:
    return lp.storage_key(pallet, item) + hashlib.blake2b(account, digest_size=16).digest() + account


def test_preprod_genesis_sets_only_storage_a_mainnet_genesis_may_set(spec, meta):
    assert lp.check_genesis_storage(spec, meta) == []


def test_a_mint_claim_planted_in_raw_genesis_is_refused(spec, metadata_v14):
    claim = (10**30).to_bytes(16, "little") + bytes(4)
    spec.storage[map_key("Billing", "PendingWithdrawals", fresh_account())] = claim
    spec.storage[map_key("Billing", "PendingWithdrawals", fresh_account())] = claim
    spec.storage[map_key("IntentSettlement", "Credits", fresh_account())] = claim
    assert messages(lp.check_genesis_storage(spec, with_billing(metadata_v14))) == [
        "[4 supply] genesis sets Billing.PendingWithdrawals (2 entries), which a mainnet genesis may not set: "
        "storage outside the genesis allowlist can hold a claim on MATRA that the supply check does not count",
        "[4 supply] genesis sets IntentSettlement.Credits (1 entry), which a mainnet genesis may not set: "
        "storage outside the genesis allowlist can hold a claim on MATRA that the supply check does not count"]


def test_storage_no_runtime_item_declares_is_refused(spec, meta):
    stray = lp.storage_key("Billing", "PendingWithdrawals")
    spec.storage[stray + bytes(48)] = bytes(20)
    spec.storage[b":heappages"] = (4096).to_bytes(8, "little")
    found = messages(lp.check_genesis_storage(spec, meta))
    assert f"[4 supply] genesis sets storage 0x{stray.hex()} (1 entry), which a mainnet genesis may not set: " \
           "storage outside the genesis allowlist can hold a claim on MATRA that the supply check does not count" \
           in found
    assert any(m.startswith("[4 supply] genesis sets :heappages (1 entry)") for m in found)


def test_runtime_that_hides_its_emission_reserves_is_refused(spec, meta):
    found = supply_findings(spec, meta, roster(spec), 0)
    assert found == ["[4 supply] the runtime metadata does not declare OrinqReceipts.ValidatorEmissionReserve, "
                     "OrinqReceipts.AttestationRewardReserve: what the runtime mints after genesis is unbounded "
                     "here, so the supply cannot be checked against the Cardano lock"]


# ---------------------------------------------------------------------------
# Kupo: what Cardano holds
# ---------------------------------------------------------------------------

class Kupo:
    """A local server that answers like Kupo: /health, /matches/<pattern>?unspent, /datums/<hash>."""

    def __init__(self):
        self.routes, self.accept = {}, []
        self.routes["/health"] = {"connection_status": "connected", "most_recent_checkpoint": 1000,
                                  "most_recent_node_tip": 1010}
        kupo = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                kupo.accept.append(self.headers.get("Accept"))
                if self.path not in kupo.routes:
                    self.send_response(404)
                    self.end_headers()
                    return
                body = json.dumps(kupo.routes[self.path]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def serve(self, spec: lp.Spec, lock_output: dict | None, candidates_datum: bytes, lock=LOCK):
        tx, _, index = lock["utxo"].partition("#")
        self.routes[f"/matches/{index}@{tx}?unspent"] = [lock_output] if lock_output else []
        policy = lp.permissioned_candidates_policy(spec).hex()
        datum_hash = hashlib.blake2b(candidates_datum, digest_size=32).hexdigest()
        self.routes[f"/matches/{policy}.*?unspent"] = [
            kupo_output(TEST_SCRIPT_ADDRESS, {policy: 1}, "cc" * 32, 0, datum_hash)]
        self.routes[f"/datums/{datum_hash}"] = {"datum": candidates_datum.hex()}


@pytest.fixture
def kupo():
    server = Kupo()
    yield server
    server.server.shutdown()


def genesis_candidates_datum(spec) -> bytes:
    raw = spec.value("Grandpa", "Authorities")
    count, pos = lp.read_compact(raw, 0)
    grandpa = [raw[pos + 40 * i:pos + 40 * i + 32] for i in range(count)]
    return legacy_datum([(bytes([2]) + fresh_account(), aura, gran) for aura, gran in zip(aura_keys(spec), grandpa)])


def test_cardano_view_reads_the_lock_and_the_candidates_from_kupo(spec, kupo):
    output = kupo_output(assets={lp.CMATRA_UNIT: 7})
    kupo.serve(spec, output, genesis_candidates_datum(spec))
    view = lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})
    assert view.lock == output
    assert [c.keys["aura"] for c in view.candidates] == aura_keys(spec)
    assert set(kupo.accept) == {"application/json"}


def test_kupo_with_no_candidates_datum_is_an_input_error(spec, kupo):
    kupo.serve(spec, None, legacy_datum([]))
    kupo.routes[f"/matches/{lp.permissioned_candidates_policy(spec).hex()}.*?unspent"] = []
    with pytest.raises(lp.InputError, match="no unspent output holding the permissioned candidates token"):
        lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})


def test_kupo_behind_its_node_is_an_input_error(spec, kupo):
    kupo.serve(spec, None, genesis_candidates_datum(spec))
    kupo.routes["/health"] = {"connection_status": "connected", "most_recent_checkpoint": 1000,
                              "most_recent_node_tip": 5000}
    with pytest.raises(lp.InputError, match="Kupo is 4000 slots behind its node"):
        lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})


def test_an_output_kupo_lists_as_spent_is_not_the_lock(spec, kupo):
    spent = dict(kupo_output(assets={lp.CMATRA_UNIT: 7}), spent_at={"slot_no": 2, "header_hash": "11" * 32})
    kupo.serve(spec, spent, genesis_candidates_datum(spec))
    assert lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}}).lock is None


def test_a_spent_candidates_output_is_not_the_committee(spec, kupo):
    kupo.serve(spec, None, genesis_candidates_datum(spec))
    route = f"/matches/{lp.permissioned_candidates_policy(spec).hex()}.*?unspent"
    kupo.routes[route] = [dict(kupo.routes[route][0], spent_at={"slot_no": 2, "header_hash": "11" * 32})]
    with pytest.raises(lp.InputError, match="no unspent output holding the permissioned candidates token"):
        lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})


def test_lock_with_a_non_integer_amount_is_an_input_error(spec, kupo):
    kupo.serve(spec, kupo_output(assets={lp.CMATRA_UNIT: "7"}), genesis_candidates_datum(spec))
    with pytest.raises(lp.InputError, match="genesis lock without an address and integer assets"):
        lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})


@pytest.mark.parametrize("pallet, item, read", [
    ("SessionCommitteeManagement", "MainChainScriptsConfiguration", lp.permissioned_candidates_policy),
    ("Aura", "Authorities", lambda spec: lp.authorities(spec, NO_CARDANO)),
])
def test_empty_committee_storage_is_an_input_error(spec, pallet, item, read):
    put(spec, pallet, item, b"")
    with pytest.raises(lp.InputError, match="does not decode"):
        read(spec)


def test_unreachable_kupo_is_an_input_error(spec):
    with pytest.raises(lp.InputError, match="Kupo request /health failed"):
        lp.cardano_view("http://127.0.0.1:9", spec, {"supply": {"genesis_lock": LOCK}})


def test_kupo_url_must_be_http():
    with pytest.raises(lp.InputError, match="--kupo must be an http"):
        lp.kupo_get("file:///etc/passwd", "/health")


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


def test_perp_engine_under_another_name_is_refused(metadata_v14):
    v14 = copy.deepcopy(metadata_v14)
    v14["pallets"].append({"name": "Perp", "storage": None, "constants": []})
    v14["types"]["types"].append({"id": 10_000, "type": {"path": ["pallet_perp_engine", "pallet", "Call"]}})
    assert messages(lp.check_pallets(lp.Metadata.from_v14(v14))) == [
        "[5 pallets] the runtime metadata carries pallet_perp_engine types: PerpEngine under another name"]


def test_metadata_without_types_is_an_input_error(metadata_v14):
    v14 = {k: v for k, v in metadata_v14.items() if k != "types"}
    with pytest.raises(lp.InputError, match="types"):
        lp.Metadata.from_v14(v14)


# ---------------------------------------------------------------------------
# End to end through the CLI, with the real subwasm
# ---------------------------------------------------------------------------

def subwasm() -> str:
    path = os.environ.get("SUBWASM") or shutil.which("subwasm")
    assert path, "set SUBWASM or put subwasm on PATH: the CLI tests run the real extractor"
    return path


class Launch:
    """A clean launch: the preprod genesis with //Alice removed, Root held by a
    multisig of fresh keys, the tuned rewards stored, one attestor endowed at the
    floor, the chain renamed, every account and authority declared, and Cardano
    holding the lock and the candidates. Every rule accepts it."""

    def __init__(self, preprod_path, tmp_path, kupo):
        spec = lp.load_spec(str(preprod_path))
        del spec.storage[account_key(ALICE)]
        spec.doc.update({"name": "Materios", "id": "materios"})
        put(spec, "OrinqReceipts", "AttestationRewardPerSigner", (1 * MATRA).to_bytes(16, "little"))
        put(spec, "OrinqReceipts", "EraCapBaselineAttestorCount", (32).to_bytes(4, "little"))
        self.sudo_members = [fresh_account() for _ in range(3)]
        put(spec, "Sudo", "Key", lp.multisig_account(self.sudo_members, 2))
        self.attestor = fresh_account()
        endow(spec, self.attestor, FLOOR)
        prefix = lp.storage_key("System", "Account")
        issuance = sum(int.from_bytes(v[16:32], "little") for k, v in spec.storage.items() if k.startswith(prefix))
        put(spec, "Balances", "TotalIssuance", issuance.to_bytes(16, "little"))
        self.spec = spec
        self.tmp_path, self.kupo = tmp_path, kupo
        conf = tmp_path / "rpc.conf"
        conf.write_text("location / { proxy_pass http://rpc-node:9944; }")
        sudo = lp.multisig_account(self.sudo_members, 2)
        self.launch = {
            "roles": {"sudo": [msig(2, *self.sudo_members)], "anchor_signer": [ss58(fresh_account())],
                      "attestors": [ss58(self.attestor)], "oracle": [],
                      "endowed": [ss58(a) for a in genesis_accounts(spec) if a not in (self.attestor, sudo)]},
            "economics": dict(TUNED, fee_buffer=100 * MATRA),
            "supply": {"genesis_lock": LOCK},
            "nodes": [authority("materios-node --validator --rpc-methods safe", f"val{i}", f"val{i}", aura)
                      for i, aura in enumerate(aura_keys(spec))]
            + [{"name": "edge", "host": "edge", "authority": False}],
            "rpc_proxies": [{"name": "public-rpc", "node": "edge", "kind": "nginx", "config": str(conf),
                             "other_targets": ["rpc-node:9944"]}],
        }
        self.lock_output = kupo_output(assets={lp.CMATRA_UNIT: issuance + 200_000_000 * MATRA})
        self.candidates = genesis_candidates_datum(spec)

    def spec_path(self) -> Path:
        self.spec.doc["genesis"]["raw"]["top"] = {"0x" + k.hex(): "0x" + v.hex() for k, v in self.spec.storage.items()}
        path = self.tmp_path / "clean-raw.json"
        path.write_text(json.dumps(self.spec.doc))
        return path

    def run(self, capsys, key=None, manifest_key=None, extra=(), signed_launch=None) -> tuple[int, str]:
        spec_path = self.spec_path()
        self.kupo.serve(lp.load_spec(str(spec_path)), self.lock_output, self.candidates,
                        self.launch["supply"]["genesis_lock"])
        return run_cli(self.tmp_path, spec_path, self.launch, capsys, self.kupo.url, key, manifest_key, extra,
                       signed_launch)


def run_cli(tmp_path, spec_path: Path, launch: dict, capsys, kupo_url: str, key=None, manifest_key=None,
            extra=(), signed_launch=None) -> tuple[int, str]:
    key = key or signing.SigningKey.generate()
    seed = tmp_path / "launch.key"
    seed.write_text(key.encode().hex())
    signed, launch_path = tmp_path / "signed.json", tmp_path / "launch.json"
    launch_path.write_text(json.dumps(signed_launch or launch))
    assert lp.main(["sign", "--spec", str(spec_path), "--launch", str(launch_path), "--key", str(seed),
                    "--out", str(signed)]) == 0
    launch_path.write_text(json.dumps(launch))
    capsys.readouterr()
    code = lp.main(["check", "--spec", str(spec_path), "--launch", str(launch_path),
                    "--signed-manifest", str(signed), "--manifest-key", "0x" + (manifest_key or pub(key)).hex(),
                    "--kupo", kupo_url, "--subwasm", subwasm(), *extra])
    captured = capsys.readouterr()
    return code, captured.out + captured.err


@pytest.fixture
def clean(preprod_path, tmp_path, kupo, monkeypatch, metadata_v14):
    """No built runtime passes yet (PerpEngine, undeclared emission reserves), so
    the extractor returns the fixture metadata with the reserves declared."""
    monkeypatch.setattr(lp, "subwasm_metadata", lambda code, subwasm: with_constants(metadata_v14))
    return Launch(preprod_path, tmp_path, kupo)


def test_cli_refuses_the_preprod_spec_naming_the_dev_anchor_signer(preprod_path, tmp_path, capsys, kupo):
    spec = lp.load_spec(str(preprod_path))
    kupo.serve(spec, kupo_output(assets={lp.CMATRA_UNIT: 975_000 * MATRA}), genesis_candidates_datum(spec))
    launch = {"roles": {"anchor_signer": [ss58(ALICE)], "attestors": [ss58(PREPROD_ATTESTOR)], "oracle": [],
                        "sudo": [ss58(fresh_account())]},
              "economics": dict(TUNED, fee_buffer=100 * MATRA), "supply": {"genesis_lock": LOCK},
              "nodes": [], "rpc_proxies": []}
    code, out = run_cli(tmp_path, preprod_path, launch, capsys, kupo.url)
    assert code == 1
    assert "MAINNET LAUNCH PREFLIGHT: REFUSE" in out
    assert "[1 dev-keys] roles.anchor_signer[0]: //Alice (sr25519)" in out
    assert "[1 dev-keys] System.Account: //Alice (sr25519) is in genesis" in out
    assert "[1 dev-keys] chain spec name 'Materios Preprod v6' reads as a test network" in out
    assert "[1 dev-keys] Sudo.Key 5D1Anh" in out
    assert "[2 rewards] OrinqReceipts.AttestationRewardPerSigner stores 10000000, declared 1000000" in out
    assert "[3 rpc] genesis Aura.Authorities[0]" in out
    assert "[4 supply] roles.attestors[0] is endowed 100000000" in out
    assert "[4 supply] the runtime metadata does not declare OrinqReceipts.ValidatorEmissionReserve" in out


def test_cli_passes_a_clean_launch(clean, capsys):
    code, out = clean.run(capsys)
    assert out.strip() == "MAINNET LAUNCH PREFLIGHT: PASS"
    assert code == 0


@pytest.mark.parametrize("threshold", [1, 2])
def test_cli_refuses_root_held_by_a_multisig_with_a_dev_member(clean, capsys, threshold):
    members = [ALICE, *clean.sudo_members[:2]]
    put(clean.spec, "Sudo", "Key", lp.multisig_account(members, threshold))
    clean.launch["roles"]["sudo"] = [msig(threshold, *members)]
    code, out = clean.run(capsys)
    assert code == 1
    assert "[1 dev-keys] roles.sudo[0].members[0]: //Alice (sr25519)" in out


def test_cli_refuses_root_declared_by_its_flat_address(clean, capsys):
    hidden = lp.multisig_account([ALICE, *clean.sudo_members[:2]], 1)
    put(clean.spec, "Sudo", "Key", hidden)
    clean.launch["roles"]["sudo"] = [ss58(hidden)]
    code, out = clean.run(capsys)
    assert code == 1
    assert SUDO_FLAT in out


def test_cli_refuses_root_held_by_an_undeclared_multisig(clean, capsys):
    hidden = lp.multisig_account([ALICE, *clean.sudo_members[:2]], 2)
    put(clean.spec, "Sudo", "Key", hidden)
    code, out = clean.run(capsys)
    assert code == 1
    assert f"[1 dev-keys] Sudo.Key {ss58(hidden)} is not the account roles.sudo declares" in out


def test_cli_refuses_a_launch_that_leaves_off_chain_roles_out(clean, capsys):
    clean.launch["roles"] = {k: v for k, v in clean.launch["roles"].items() if k in ("attestors", "endowed", "sudo")}
    code, out = clean.run(capsys)
    assert code == 1
    assert "[1 dev-keys] roles.anchor_signer is not declared" in out
    assert "[1 dev-keys] roles.oracle is not declared" in out


def test_cli_refuses_an_authority_left_out_of_the_nodes(clean, capsys):
    dropped = [node for node in clean.launch["nodes"] if node["authority"]][-1]
    clean.launch["nodes"].remove(dropped)
    code, out = clean.run(capsys)
    assert code == 1
    assert f"[3 rpc] genesis Aura.Authorities[3] (aura {dropped['aura']}) has no authority node" in out


def test_cli_refuses_unsafe_rpc_behind_a_cloudflared_tunnel(clean, capsys):
    tunnel = clean.tmp_path / "tunnel.yml"
    tunnel.write_text(CLOUDFLARED.format(service="http://localhost:9945"))
    clean.launch["nodes"][0]["argv"] = UNSAFE_9945
    clean.launch["rpc_proxies"] = [{"name": "tunnel", "node": "val0", "kind": "cloudflared", "config": str(tunnel)}]
    code, out = clean.run(capsys)
    assert code == 1
    assert "[3 rpc] authority val0 serves unsafe RPC methods behind proxy tunnel" in out


@pytest.mark.parametrize("spelling", ["val0.lan", "VAL0.internal", "10.9.9.9"])
def test_cli_refuses_a_same_machine_tunnel_whose_host_is_spelled_differently(clean, capsys, spelling):
    tunnel = clean.tmp_path / "tunnel.yml"
    tunnel.write_text(CLOUDFLARED.format(service=f"http://{spelling}:9945"))
    clean.launch["nodes"][0]["argv"] = UNSAFE_9945
    clean.launch["rpc_proxies"] = [{"name": "tunnel", "node": "val0", "kind": "cloudflared", "config": str(tunnel)}]
    code, out = clean.run(capsys)
    assert code == 2 and f"proxy tunnel forwards to {spelling}:9945, which is no declared node's" in out
    signed = copy.deepcopy(clean.launch)
    clean.launch["rpc_proxies"][0]["node"] = spelling
    code, out = clean.run(capsys, signed_launch=signed)
    assert code == 2 and f"rpc_proxies[0] runs on {spelling}, which is not a declared node" in out


def test_cli_reads_an_authority_through_its_shell_wrapper(clean, capsys):
    clean.launch["nodes"][0]["argv"] = ["/bin/bash", "-lc", "exec materios-node --validator --rpc-methods unsafe "
                                        "--unsafe-rpc-external --alice --wasm-runtime-overrides /srv/o"]
    code, out = clean.run(capsys)
    assert code == 1
    assert "[1 dev-keys] node val0: --alice loads the dev keyring" in out
    assert "[3 rpc] authority val0 serves unsafe RPC methods on an external listener" in out
    assert "[6 checkpoint] authority val0 runs --wasm-runtime-overrides" in out


def test_cli_refuses_the_bootstrap_unit_shape(clean, capsys):
    clean.launch["nodes"][0]["argv"] = BOOTSTRAP_EXECSTART
    code, out = clean.run(capsys)
    assert code == 1
    assert "[3 rpc] authority val0 serves unsafe RPC methods on an external listener" in out


def test_cli_refuses_a_lock_smaller_than_what_materios_can_issue(clean, capsys):
    clean.lock_output = kupo_output(assets={lp.CMATRA_UNIT: 975_000 * MATRA})
    code, out = clean.run(capsys)
    assert code == 1
    assert "counted both as cMATRA and as MATRA" in out


def test_cli_refuses_a_pending_withdrawal_planted_in_raw_genesis(clean, capsys):
    clean.lock_output = kupo_output(assets={lp.CMATRA_UNIT: 10**30})
    stray = lp.storage_key("Billing", "PendingWithdrawals")
    clean.spec.storage[map_key("Billing", "PendingWithdrawals", fresh_account())] = \
        (10**30).to_bytes(16, "little") + bytes(4)
    code, out = clean.run(capsys)
    assert code == 1
    assert f"[4 supply] genesis sets storage 0x{stray.hex()} (1 entry), which a mainnet genesis may not set" in out


def test_cli_refuses_a_negative_fee_buffer_that_would_lower_the_endowment_floor(clean, capsys):
    endow(clean.spec, clean.attestor, 0)
    signed = copy.deepcopy(clean.launch)
    clean.launch["economics"]["fee_buffer"] = -FLOOR
    code, out = clean.run(capsys, signed_launch=signed)
    assert code == 2 and "economics.fee_buffer must be a non-negative integer" in out


def test_cli_refuses_a_launch_manifest_edited_after_signing(clean, capsys):
    signed_launch = copy.deepcopy(clean.launch)
    signed_launch["roles"]["anchor_signer"] = [ss58(fresh_account())]
    code, out = clean.run(capsys, signed_launch=signed_launch)
    assert code == 1
    assert "[6 checkpoint] launch_manifest_hash is 0x" in out


def test_cli_refuses_a_local_chain_type(clean, capsys):
    clean.spec.doc["chainType"] = "Local"
    code, out = clean.run(capsys)
    assert code == 1
    assert "[1 dev-keys] chain spec chainType is 'Local', not 'Live'" in out


def test_cli_refuses_a_dev_key_in_the_cardano_committee(clean, capsys):
    clean.candidates = legacy_datum([(bytes([2]) + fresh_account(), ALICE, fresh_account())])
    clean.launch["nodes"].append(authority("materios-node --validator --rpc-methods safe", "val9", "val9", ALICE))
    code, out = clean.run(capsys)
    assert code == 1
    assert "[1 dev-keys] Cardano permissioned candidate 0 aura: //Alice (sr25519)" in out


def test_cli_refuses_a_numeric_dev_path_key_as_a_role_and_a_genesis_account(clean, capsys):
    one = bytes.fromhex(NUMERIC_DEV_PATHS[("//1", "sr25519")])
    clean.launch["roles"]["anchor_signer"] = [ss58(one)]
    endow(clean.spec, one, 5 * MATRA)
    clean.launch["roles"]["endowed"].append(ss58(one))
    clean.lock_output = kupo_output(assets={lp.CMATRA_UNIT: 10**30})
    code, out = clean.run(capsys)
    assert code == 1
    assert "[1 dev-keys] roles.anchor_signer[0]: //1 (sr25519)" in out
    assert "[1 dev-keys] System.Account: //1 (sr25519) is in genesis" in out


def test_cli_names_keys_from_an_extra_table(clean, capsys):
    exposed = fresh_account()
    clean.launch["roles"]["anchor_signer"] = [ss58(exposed)]
    extra = extra_table(clean.tmp_path, [{"label": "exposed member", "scheme": "sr25519", "public": exposed.hex()}])
    code, out = clean.run(capsys, extra=["--extra-well-known", str(extra)])
    assert code == 1
    assert "[1 dev-keys] roles.anchor_signer[0]: exposed member (sr25519)" in out


def test_cli_refuses_a_manifest_pinned_to_another_key(clean, capsys):
    code, out = clean.run(capsys, manifest_key=pub(signing.SigningKey.generate()))
    assert code == 1
    assert "[6 checkpoint] signed manifest signature does not verify" in out


VALID_LOCK = {"genesis_lock": LOCK}


@pytest.mark.parametrize("launch, error", [
    ([], "launch manifest must be a JSON object"),
    ({"roles": {}, "rpc_proxy": [], "supply": VALID_LOCK}, "unknown launch manifest field rpc_proxy"),
    ({"roles": {"oracle": "5Grw"}, "supply": VALID_LOCK}, "roles.oracle must be a list"),
    ({"roles": {"oracle": [7]}, "supply": VALID_LOCK}, "roles.oracle\\[0\\] must be a public key string"),
    ({"roles": {"sudo": [{"threshold": 0, "members": ["a", "b"]}]}, "supply": VALID_LOCK},
     "roles.sudo\\[0\\] threshold must be an integer from 1 to 2"),
    ({"roles": {"sudo": [{"threshold": 1, "members": ["a"]}]}, "supply": VALID_LOCK},
     "roles.sudo\\[0\\] members must list at least two"),
    ({"roles": {"sudo": [{"threshold": 1, "members": ["a", "b"], "note": 1}]}, "supply": VALID_LOCK},
     "roles.sudo\\[0\\] must hold exactly threshold and members"),
    ({"roles": {}, "economics": [], "supply": VALID_LOCK}, "economics must be an object"),
    ({"roles": {}, "economics": {"fee_buffer": -1}, "supply": VALID_LOCK},
     "economics.fee_buffer must be a non-negative integer"),
    ({"roles": {}, "economics": {"fee_buffer": True}, "supply": VALID_LOCK},
     "economics.fee_buffer must be a non-negative integer"),
    ({"roles": {}, "economics": {"era_cap_base": "50000"}, "supply": VALID_LOCK},
     "economics.era_cap_base must be a non-negative integer"),
    ({"roles": {}, "economics": {"fee_bufer": 1}, "supply": VALID_LOCK}, "unknown economics field fee_bufer"),
    ({"roles": {}}, "supply.genesis_lock is required"),
    ({"roles": {}, "supply": []}, "supply must be an object"),
    ({"roles": {}, "supply": {"cardano_backing": 1, **VALID_LOCK}}, "unknown supply field cardano_backing"),
    ({"roles": {}, "supply": {"genesis_lock": {"utxo": "zz#0", "address": SCRIPT_ADDRESS}}},
     "supply.genesis_lock.utxo must be <64 hex>#<index>"),
    ({"roles": {}, "supply": VALID_LOCK, "nodes": {"a": 1}}, "nodes must be a list"),
    ({"roles": {}, "supply": VALID_LOCK, "nodes": [{"name": "v1"}]}, "nodes\\[0\\] needs a name and a host"),
    ({"roles": {}, "supply": VALID_LOCK, "rpc_proxies": [{"name": "p", "node": "h", "config": "c"}]},
     "rpc_proxies\\[0\\] kind must be nginx or cloudflared"),
    ({"roles": {}, "supply": VALID_LOCK, "rpc_proxies": [{"name": "p", "host": "h", "kind": "nginx", "config": "c"}]},
     "rpc_proxies\\[0\\] has unknown field host"),
    ({"roles": {}, "supply": VALID_LOCK, "nodes": [{"name": "h", "host": "h", "authority": False}],
      "rpc_proxies": [{"name": "p", "node": "h", "kind": "nginx", "config": "c", "other_targets": ["h"]}]},
     "rpc_proxies\\[0\\] other_targets must be host:port strings"),
    ({"roles": {}, "supply": VALID_LOCK, "rpc_proxies": {"p": 1}}, "rpc_proxies must be a list"),
    ({"roles": {}, "supply": VALID_LOCK,
      "nodes": [{"name": "v1", "host": "h", "authority": True, "aura": "0x" + "11" * 32, "addresses": "10.0.0.1"}]},
     "nodes\\[0\\] addresses must be a list of strings"),
    ({"roles": {}, "supply": VALID_LOCK, "nodes": [{"name": "v1", "host": "h", "argv": "materios-node --validator"}]},
     "nodes\\[0\\] must declare authority as true or false"),
    ({"roles": {}, "supply": VALID_LOCK, "nodes": [{"name": "v1", "host": "h", "authority": True}]},
     "nodes\\[0\\] is an authority and must declare its aura public key"),
    ({"roles": {}, "supply": VALID_LOCK,
      "nodes": [{"name": "v1", "host": "h", "authority": False, "env": ["SIGNER_URI=//Alice"]}]},
     "nodes\\[0\\] env must map names to strings"),
    ({"roles": {}, "supply": VALID_LOCK, "nodes": [{"name": "v1", "host": "h", "authority": False, "argv": 7}]},
     "nodes\\[0\\] argv must be a string or a list of strings"),
])
def test_malformed_launch_manifest_is_an_input_error(launch, error):
    with pytest.raises(lp.InputError, match=error):
        lp.validate_launch(launch)


@pytest.mark.parametrize("manifest_key", ["0xzz", "0x" + "00" * 31])
def test_malformed_manifest_key_is_an_input_error(manifest_key):
    with pytest.raises(lp.InputError, match="--manifest-key"):
        lp.pinned_key(manifest_key)


def test_non_numeric_rpc_port_is_an_input_error(tmp_path):
    with pytest.raises(lp.InputError, match="is not a port"):
        rpc_findings(tmp_path, [authority("materios-node --rpc-port nine")])


def test_decompression_bomb_is_an_input_error(monkeypatch):
    monkeypatch.setattr(lp, "CODE_BOMB_LIMIT", 1024)
    bomb = lp.ZSTD_PREFIX + zstandard.ZstdCompressor().compress(bytes(4096))
    with pytest.raises(lp.InputError, match="bomb limit"):
        lp.decompressed_code(bomb)


def test_unreadable_signing_key_is_an_input_error_that_does_not_echo_it(preprod_path, tmp_path, capsys):
    key = tmp_path / "bad.key"
    key.write_text("not-a-seed-value")
    launch = tmp_path / "launch.json"
    launch.write_text(json.dumps({"roles": {}, "supply": VALID_LOCK}))
    assert lp.main(["sign", "--spec", str(preprod_path), "--launch", str(launch), "--key", str(key),
                    "--out", str(tmp_path / "o")]) == 2
    err = capsys.readouterr().err
    assert "cannot load the launch signing key" in err and "not-a-seed-value" not in err


def test_cli_refuses_a_non_raw_spec_as_an_input_error(tmp_path, capsys):
    plain = tmp_path / "plain.json"
    plain.write_text(json.dumps({"genesis": {"runtimeGenesis": {"patch": {}}}}))
    code = lp.main(["check", "--spec", str(plain), "--launch", str(plain), "--signed-manifest", str(plain),
                    "--manifest-key", "0x00", "--kupo", "http://127.0.0.1:9", "--subwasm", "subwasm"])
    assert code == 2
    assert "needs the raw chain spec" in capsys.readouterr().err
