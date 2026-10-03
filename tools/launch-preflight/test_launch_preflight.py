"""Tests for the mainnet launch preflight.

The preprod v6 fixture is the raw chain spec the preprod network publishes; its
genesis hash was read from a live node, so the genesis-hash test checks this
implementation against the reference one. Cardano is served by a local HTTP
server that answers with Kupo's response shapes.
"""
import base64
import copy
import dataclasses
import gzip
import hashlib
import json
import os
import re
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import base58
import cbor2
import pytest
import xxhash
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


NO_CARDANO = lp.CardanoView(lock=None, candidates=[], d_parameter=(0, 0))


def leb128(n: int) -> bytes:
    out = bytearray()
    while True:
        byte, n = n & 0x7F, n >> 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def custom_section(name: bytes, payload: bytes) -> bytes:
    body = leb128(len(name)) + name + payload
    return b"\0" + leb128(len(body)) + body


def zstd_frame(data: bytes) -> bytes:
    return zstandard.ZstdCompressor().compress(data)


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


# partner-chains commits its local environment's Cardano keys; this is the
# verification key committed next to its funded address's signing key.
PARTNER_CHAINS_CARDANO_KEY = "fc014cb5f071f5d6a36cb5a7e5f168c86555989445a23d4abec33d280f71aca4"


def test_table_holds_cardano_signing_keys_a_public_repo_commits(known):
    table = {(k.scheme, k.needle.hex()): k.label for k in known.keys}
    assert table[("ed25519", PARTNER_CHAINS_CARDANO_KEY)] == \
        "partner-chains test key, secret committed to a public repo"


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
    ([{"label": "x", "scheme": "sr25519", "public": "zz"}], "keys\\[0\\] public is not lowercase hex"),
    ([{"label": "x", "scheme": "sr25519", "public": "00" * 31}], "keys\\[0\\] public is 31 bytes"),
])
def test_malformed_extra_table_is_an_input_error(tmp_path, entries, error):
    with pytest.raises(lp.InputError, match=error):
        lp.load_well_known([extra_table(tmp_path, entries)])


# ---------------------------------------------------------------------------
# Hex: each input in the one spelling its writer writes
# ---------------------------------------------------------------------------

SPEC240_RAW = FIXTURES / "preprod-spec240-raw.json"
GUARDIAN_KEY = "0x" + lp.storage_key("RootTimelock", "Guardian").hex()
DELAYS_KEY = "0x" + lp.storage_key("RootTimelock", "Delays").hex()
# 32 bytes whose digits hold letters, so an upper-case spelling differs from it.
DIGITS = "ab" * 32
# Spellings of 0x-hex other than 0x and lower case. impl-serde, which reads a raw spec in the node, reads most as
# other bytes than bytes.fromhex after the first two characters (whitespace or an odd digit shifts every nibble, two
# trailing spaces add a zero byte, a missing 0x keeps two more digits), upper case alike, and 0X or a vertical tab
# not at all.
MISSPELLINGS = {
    "a space after 0x": lambda digits: "0x " + digits,
    "a tab after 0x": lambda digits: "0x\t" + digits,
    "a vertical tab after 0x": lambda digits: "0x\v" + digits,
    "a space inside": lambda digits: "0x" + digits[:4] + " " + digits[4:],
    "spaces at the end": lambda digits: "0x" + digits + "  ",
    "a newline at the end": lambda digits: "0x" + digits + "\n",
    "no 0x": lambda digits: digits,
    "no 0x and a leading byte": lambda digits: "ab" + digits,
    "0X": lambda digits: "0X" + digits,
    "upper case": lambda digits: "0x" + digits.upper(),
    "an odd digit": lambda digits: "0x" + digits + "a",
}
# The same for a key in hex: a key string without 0x is read as SS58, and rule 1 refuses one that does not decode.
HEX_KEY_MISSPELLINGS = {name: spell for name, spell in MISSPELLINGS.items() if spell("").startswith(("0x", "0X"))}
# Spellings of bare hex other than lower case with no 0x: what the key tables and Kupo write.
BARE_MISSPELLINGS = {
    "a 0x prefix": lambda digits: "0x" + digits,
    "a leading space": lambda digits: " " + digits,
    "a space inside": lambda digits: digits[:4] + " " + digits[4:],
    "a newline at the end": lambda digits: digits + "\n",
    "upper case": lambda digits: digits.upper(),
    "an odd digit": lambda digits: digits + "a",
}
MISSPELLED = "is not 0x-prefixed lowercase hex of whole bytes"
BARE_MISSPELLED = "is not lowercase hex of whole bytes with no 0x"


def spelled(spellings: dict):
    return pytest.mark.parametrize("misspell", spellings.values(), ids=spellings.keys())


def raw_spec(tmp_path, edit) -> str:
    """The spec 240 raw spec as a file, its raw storage edited by `edit`."""
    doc = json.loads(SPEC240_RAW.read_text())
    edit(doc["genesis"]["raw"]["top"])
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(doc))
    return str(path)


@spelled(MISSPELLINGS)
def test_a_raw_storage_value_in_another_spelling_is_an_input_error(tmp_path, misspell):
    path = raw_spec(tmp_path, lambda top: top.update({GUARDIAN_KEY: misspell(DIGITS)}))
    with pytest.raises(lp.InputError, match=f"^chain spec raw storage value at {GUARDIAN_KEY} {MISSPELLED}"):
        lp.load_spec(path)


@spelled(MISSPELLINGS)
def test_a_raw_storage_key_in_another_spelling_is_an_input_error(tmp_path, misspell):
    path = raw_spec(tmp_path, lambda top: top.update({misspell(GUARDIAN_KEY[2:]): top.pop(GUARDIAN_KEY)}))
    with pytest.raises(lp.InputError, match=f"^chain spec raw storage key '.*' {MISSPELLED}"):
        lp.load_spec(path)


@pytest.mark.parametrize("value", [7, None, [171, 205], {"0x": "ab"}])
def test_a_raw_storage_value_that_is_not_a_string_is_an_input_error(tmp_path, value):
    path = raw_spec(tmp_path, lambda top: top.update({GUARDIAN_KEY: value}))
    with pytest.raises(lp.InputError, match=f"^chain spec raw storage value at {GUARDIAN_KEY} {MISSPELLED}"):
        lp.load_spec(path)


@pytest.mark.parametrize("entries, error", [
    (f'"{GUARDIAN_KEY}": "0x00", "{GUARDIAN_KEY}": "0x01"', f"an object holds the key '{GUARDIAN_KEY}' twice"),
    (f'"{GUARDIAN_KEY}": "0x00", "{GUARDIAN_KEY[:-1]}\\u{ord(GUARDIAN_KEY[-1]):04x}": "0x01"',
     f"an object holds the key '{GUARDIAN_KEY}' twice"),
    (f'"{GUARDIAN_KEY}": "0x00", "0x{GUARDIAN_KEY[2:].upper()}": "0x01"',
     f"chain spec raw storage key '0x{GUARDIAN_KEY[2:].upper()}' {MISSPELLED}"),
], ids=["twice", "once with a JSON escape", "once in upper case"])
def test_a_raw_storage_key_given_twice_in_any_spelling_is_an_input_error(tmp_path, entries, error):
    doc = json.loads(SPEC240_RAW.read_text())
    doc["genesis"]["raw"]["top"] = {"@": ""}
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(doc).replace('{"@": ""}', "{" + entries + "}"))
    with pytest.raises(lp.InputError, match=re.escape(error)):
        lp.load_spec(str(path))


def test_a_spec_that_repeats_any_key_is_an_input_error(tmp_path):
    """The node refuses a field given twice; the preflight would read the last."""
    path = tmp_path / "raw.json"
    path.write_text(SPEC240_RAW.read_text().replace('"chainType": "Live"', '"chainType": "Local", "chainType": "Live"'))
    with pytest.raises(lp.InputError, match="an object holds the key 'chainType' twice"):
        lp.load_spec(str(path))


def test_a_launch_key_table_that_repeats_a_key_is_an_input_error(monkeypatch, tmp_path):
    """A reviewer would read the first list of pinned keys; the preflight would read the last."""
    path = tmp_path / "launch_keys.json"
    path.write_text('{"keys": ["0x' + "11" * 32 + '"], "keys": ["0x' + DIGITS + '"]}')
    monkeypatch.setattr(lp, "LAUNCH_KEYS", path)
    with pytest.raises(lp.InputError, match="launch_keys.json: an object holds the key 'keys' twice"):
        lp.pinned_launch_keys()


def test_a_key_table_that_repeats_a_key_is_an_input_error(tmp_path):
    """A reviewer would read //Alice in the table; the preflight and the anchor worker would read the last key."""
    path = tmp_path / "exposed.json"
    path.write_text('{"keys": [{"label": "x", "scheme": "sr25519", "public": "' + ALICE.hex() + '", "public": "'
                    + DIGITS + '"}]}')
    with pytest.raises(lp.InputError, match="an object holds the key 'public' twice"):
        lp.load_well_known([path])


@pytest.mark.parametrize("doc", [[], {"genesis": []}, {"genesis": {"raw": []}}, {"genesis": {"raw": {"top": []}}}])
def test_a_spec_with_no_raw_storage_map_is_an_input_error(tmp_path, doc):
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(lp.InputError, match="needs the raw chain spec"):
        lp.load_spec(str(path))


def test_a_spec_with_child_tries_is_an_input_error(tmp_path):
    doc = json.loads(SPEC240_RAW.read_text())
    child = "0x" + b":child_storage:default:a".hex()
    doc["genesis"]["raw"]["childrenDefault"] = {child: {"0x00 ": "0x 01"}}
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(lp.InputError, match="chain spec has child tries"):
        lp.load_spec(str(path))


@pytest.mark.parametrize("name", ["preprod-v6-raw.json.gz", "preprod-spec240-raw.json"])
def test_build_spec_output_loads_byte_for_byte(tmp_path, name):
    """build-spec writes each raw storage key and value as 0x and lower case, so its output loads unchanged."""
    data = (FIXTURES / name).read_bytes()
    text = (gzip.decompress(data) if name.endswith(".gz") else data).decode()
    path = tmp_path / "raw.json"
    path.write_text(text)
    doc = json.loads(text)
    top = doc["genesis"]["raw"]["top"]
    assert all(re.fullmatch(r"0x(?:[0-9a-f]{2})*", spelling) for entry in top.items() for spelling in entry)
    spec = lp.load_spec(str(path))
    assert spec.doc == doc
    assert spec.storage == {bytes.fromhex(key[2:]): bytes.fromhex(value[2:]) for key, value in top.items()}


def test_build_spec_output_stores_each_number_the_preflight_reads_at_the_width_of_its_type(spec, spec240):
    """Every account is an 80-byte AccountInfo filed under its own key, and
    what the accounts hold, free plus reserved, is TotalIssuance."""
    for genesis in (spec, spec240[0]):
        numbers = [("OrinqReceipts", item, width) for _, item, width in REWARD_WIDTHS]
        numbers += [("OrinqReceipts", "BondRequirement", 16), ("Balances", "TotalIssuance", 16),
                    ("Sidechain", "SlotsPerEpoch", 4)]
        for pallet, item, width in numbers:
            assert len(genesis.value(pallet, item)) == width
        accounts = genesis.accounts()
        assert {len(genesis.storage[account_key(account)]) for account in accounts} == {80}
        assert sum(sum(genesis.balance(account)) for account in accounts) == issuance_of(genesis)


@spelled(HEX_KEY_MISSPELLINGS)
def test_a_role_key_in_another_spelling_of_hex_is_an_input_error(misspell):
    launch = {"roles": {"sudo": [msig(2, fresh_account(), fresh_account())]}, "supply": VALID_LOCK}
    launch["roles"]["sudo"][0]["members"].append({"threshold": 2, "members": [ss58(fresh_account()), misspell(DIGITS)]})
    with pytest.raises(lp.InputError, match=rf"^roles\.sudo\[0\]\.members\[2\]\.members\[1\] {MISSPELLED}"):
        lp.validate_launch(launch)


@spelled(HEX_KEY_MISSPELLINGS)
def test_an_aura_key_in_another_spelling_of_hex_is_an_input_error(misspell):
    launch = {"roles": {}, "supply": VALID_LOCK, "nodes": [dict(authority(["materios-node"]), aura=misspell(DIGITS))]}
    with pytest.raises(lp.InputError, match=rf"^nodes\[0\] aura {MISSPELLED}"):
        lp.validate_launch(launch)


@spelled(MISSPELLINGS)
def test_a_lock_script_in_another_spelling_is_an_input_error(misspell):
    launch = {"roles": {}, "supply": {"genesis_lock": dict(LOCK, native_script=misspell(LOCK_SCRIPT))}}
    with pytest.raises(lp.InputError, match=f"^supply.genesis_lock.native_script {MISSPELLED}"):
        lp.validate_launch(launch)


@spelled(MISSPELLINGS)
def test_a_signed_manifest_hash_in_another_spelling_is_an_input_error(spec, misspell):
    key = signing.SigningKey.generate()
    signed = lp.signed_manifest(spec, LAUNCH, key)
    signed["genesis_hash"] = misspell(signed["genesis_hash"][2:])
    with pytest.raises(lp.InputError, match=f"^signed manifest genesis_hash {MISSPELLED}"):
        lp.check_checkpoint(spec, LAUNCH, signed, [pub(key)])


@spelled(MISSPELLINGS)
def test_a_pinned_launch_key_in_another_spelling_is_an_input_error(monkeypatch, tmp_path, misspell):
    path = tmp_path / "launch_keys.json"
    path.write_text(json.dumps({"keys": [misspell(DIGITS)]}))
    monkeypatch.setattr(lp, "LAUNCH_KEYS", path)
    with pytest.raises(lp.InputError, match=rf"^launch_keys.json keys\[0\] {MISSPELLED}"):
        lp.pinned_launch_keys()


@spelled(MISSPELLINGS)
def test_a_manifest_key_in_another_spelling_is_an_input_error(misspell):
    with pytest.raises(lp.InputError, match=f"^--manifest-key {MISSPELLED}"):
        lp.parse_launch_key(misspell(DIGITS))


@spelled({name: spell for name, spell in MISSPELLINGS.items() if name != "a newline at the end"})
def test_a_seed_in_another_spelling_is_an_input_error_that_does_not_echo_it(preprod_path, tmp_path, capsys, misspell):
    """The seed file holds 0x-hex and at most the newline that ends its line."""
    key = tmp_path / "launch.key"
    key.write_text(misspell(DIGITS))
    launch = tmp_path / "launch.json"
    launch.write_text(json.dumps({"roles": {}, "supply": VALID_LOCK}))
    assert lp.main(["sign", "--spec", str(preprod_path), "--launch", str(launch), "--key", str(key),
                    "--out", str(tmp_path / "o")]) == 2
    err = capsys.readouterr().err
    assert f"cannot load the launch signing key from {key}: its seed {MISSPELLED}" in err
    assert "abab" not in err.lower()


@spelled(BARE_MISSPELLINGS)
def test_a_key_table_key_in_another_spelling_is_an_input_error(tmp_path, misspell):
    """The table's spelling is gen_well_known_keys.py's, the one the anchor worker reads."""
    path = extra_table(tmp_path, [{"label": "x", "scheme": "sr25519", "public": misspell(DIGITS)}])
    with pytest.raises(lp.InputError, match=rf"keys\[0\] public {BARE_MISSPELLED}"):
        lp.load_well_known([path])


@pytest.mark.parametrize("field", ["dev_phrase_blake2_256", "dev_seed_blake2_256"])
def test_a_dev_hash_in_another_spelling_is_an_input_error(monkeypatch, tmp_path, field):
    table = json.loads((lp.HERE / "well_known_keys.json").read_text())
    table[field] = table[field].upper()
    (tmp_path / "well_known_keys.json").write_text(json.dumps(table))
    monkeypatch.setattr(lp, "HERE", tmp_path)
    with pytest.raises(lp.InputError, match=f"{field} {BARE_MISSPELLED}"):
        lp.load_well_known()


@spelled(BARE_MISSPELLINGS)
def test_a_datum_kupo_serves_in_another_spelling_is_an_input_error(monkeypatch, misspell):
    datum = cbor2.dumps(bytes.fromhex(DIGITS))
    monkeypatch.setattr(lp, "kupo_get", lambda base, path: {"datum": misspell(datum.hex())})
    with pytest.raises(lp.InputError, match=f"^the datum Kupo serves for the genesis lock {BARE_MISSPELLED}"):
        lp.kupo_datum("http://kupo", hashlib.blake2b(datum, digest_size=32).hexdigest(), "the genesis lock")


# ---------------------------------------------------------------------------
# Rule 6: checkpoint canary (genesis hash, code hash, chain-spec hash, launch manifest)
# ---------------------------------------------------------------------------

def test_genesis_hash_matches_the_live_preprod_genesis(spec):
    wasm = lp.decompressed_code(spec.code)
    assert lp.runtime_state_version(wasm) == 1
    assert lp.genesis_hash(spec.storage, 1).hex() == PREPROD_GENESIS


# sp_api's id of the Core API, blake2_64 of its name, and one whose version the node does not read.
CORE_API = hashlib.blake2b(b"Core", digest_size=8).digest()
OTHER_API = hashlib.blake2b(b"Metadata", digest_size=8).digest()
TRANSACTION_VERSION = (5).to_bytes(4, "little")


def api(version: int, api_id: bytes = CORE_API) -> bytes:
    return api_id + version.to_bytes(4, "little")


def runtime_version(tail: bytes, apis: bytes = b"") -> bytes:
    """A runtime_version section: spec and impl name, the authoring, spec and
    impl versions, a list of APIs, then `tail`."""
    return (lp.compact(8) + b"materios") * 2 + bytes(12) + lp.compact(len(apis) // 12) + apis + tail


def version_wasm(*sections: tuple[bytes, bytes]) -> bytes:
    return b"\0asm\x01\0\0\0" + b"".join(custom_section(name, payload) for name, payload in sections)


def core(version: int, state: bytes) -> bytes:
    """Code whose runtime_apis section declares Core at `version`, with this state version byte."""
    return version_wasm((b"runtime_version", runtime_version(TRANSACTION_VERSION + state)),
                        (b"runtime_apis", api(version)))


# What sc-executor's read_embedded_version and sp-version's state_version() make of each: the Core version comes from
# the first runtime_apis section, else from the version's own list; a state byte is read from Core 4 on, and any
# but 0 is V1.
STATE_VERSIONS = {
    "Core 5 and state 1": (core(5, b"\x01"), 1),
    "Core 5 and state 0": (core(5, b"\x00"), 0),
    "Core 5 and state 2": (core(5, b"\x02"), 1),
    "Core 5 and state 255": (core(5, b"\xff"), 1),
    "Core 4 and state 1": (core(4, b"\x01"), 1),
    "Core 3 and a byte after the transaction version": (core(3, b"\x01"), 0),
    "Core 2 and a byte where Core 4 keeps state": (core(2, b"\x01"), 0),
    "Core 3 and nothing after the transaction version": (core(3, b""), 0),
    "Core 2 and nothing after the API list": (
        version_wasm((b"runtime_version", runtime_version(b"")), (b"runtime_apis", api(2))), 0),
    "Core 4 only in the version's list": (
        version_wasm((b"runtime_version", runtime_version(TRANSACTION_VERSION + b"\x01", api(4)))), 1),
    "no Core API": (version_wasm((b"runtime_version", runtime_version(TRANSACTION_VERSION + b"\x01"))), 0),
    "runtime_apis over the version's list": (
        version_wasm((b"runtime_version", runtime_version(TRANSACTION_VERSION + b"\x01", api(5))),
                     (b"runtime_apis", api(3))), 0),
    "Core after another API": (
        version_wasm((b"runtime_version", runtime_version(TRANSACTION_VERSION + b"\x01")),
                     (b"runtime_apis", api(9, OTHER_API) + api(5))), 1),
    "the first Core of two": (
        version_wasm((b"runtime_version", runtime_version(TRANSACTION_VERSION + b"\x01")),
                     (b"runtime_apis", api(3) + api(5))), 0),
    "the first runtime_apis section of two": (
        version_wasm((b"runtime_version", runtime_version(TRANSACTION_VERSION + b"\x01")),
                     (b"runtime_apis", api(3)), (b"runtime_apis", api(5))), 0),
    "the first runtime_version section of two": (
        version_wasm((b"runtime_version", runtime_version(TRANSACTION_VERSION + b"\x00")),
                     (b"runtime_version", runtime_version(TRANSACTION_VERSION + b"\x01")),
                     (b"runtime_apis", api(5))), 0),
}


@pytest.mark.parametrize("wasm, state_version", STATE_VERSIONS.values(), ids=STATE_VERSIONS.keys())
def test_state_version_is_the_one_the_node_builds_genesis_with(wasm, state_version):
    assert lp.runtime_state_version(wasm) == state_version


# Version sections the node cannot decode, so it builds no genesis from the code.
UNDECODABLE_VERSIONS = {
    "a clipped API entry": (version_wasm((b"runtime_version", runtime_version(TRANSACTION_VERSION + b"\x01")),
                                         (b"runtime_apis", api(5) + b"\x00")), "runtime_apis"),
    "Core 4 and no state byte": (version_wasm((b"runtime_version", runtime_version(TRANSACTION_VERSION)),
                                              (b"runtime_apis", api(4))), "runtime_version"),
    "Core 3 and a clipped transaction version": (
        version_wasm((b"runtime_version", runtime_version(b"\x05\x00")), (b"runtime_apis", api(3))),
        "runtime_version"),
    "a clipped name": (version_wasm((b"runtime_version", lp.compact(8) + b"mat")), "runtime_version"),
    "a clipped API list": (version_wasm((b"runtime_version", runtime_version(b"")[:-1] + lp.compact(2) + api(4))),
                           "runtime_version"),
    # parity-scale-codec refuses a length written in more bytes than it needs.
    "a name length in two bytes": (version_wasm((b"runtime_version", (8 << 2 | 1).to_bytes(2, "little")
                                                 + runtime_version(TRANSACTION_VERSION)[1:])), "runtime_version"),
}


@pytest.mark.parametrize("wasm, section", UNDECODABLE_VERSIONS.values(), ids=UNDECODABLE_VERSIONS.keys())
def test_a_version_section_the_node_cannot_decode_is_an_input_error(wasm, section):
    with pytest.raises(lp.InputError, match=f"^runtime code's {section} section does not decode"):
        lp.runtime_state_version(wasm)


def test_genesis_hash_uses_the_trie_layout_the_node_builds_genesis_with(spec):
    """State 2 is V1 to the node, which puts a value of 33 bytes or more in the trie by its hash."""
    spec.storage[lp.CODE_KEY] = core(5, b"\x02")
    assert lp.spec_genesis_hash(spec) == lp.genesis_hash(spec.storage, 1) != lp.genesis_hash(spec.storage, 0)


def pub(key: signing.SigningKey) -> bytes:
    return key.verify_key.encode()


LAUNCH = {"roles": {}}


def test_signed_manifest_for_this_spec_and_launch_passes(spec):
    key = signing.SigningKey.generate()
    assert lp.check_checkpoint(spec, LAUNCH, lp.signed_manifest(spec, LAUNCH, key), [pub(key)]) == []


def test_changed_genesis_storage_breaks_genesis_and_spec_hash(preprod_path, tmp_path):
    key = signing.SigningKey.generate()
    signed = lp.signed_manifest(lp.load_spec(str(preprod_path)), LAUNCH, key)
    doc = json.loads(preprod_path.read_text())
    alice_key = "0x" + account_key(ALICE).hex()
    doc["genesis"]["raw"]["top"][alice_key] = "0x" + (bytes(16) + (1).to_bytes(16, "little") + bytes(48)).hex()
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(doc))
    found = messages(lp.check_checkpoint(lp.load_spec(str(tampered)), LAUNCH, signed, [pub(key)]))
    assert any("genesis_hash is 0x" in m for m in found)
    assert any("chain_spec_hash is 0x" in m for m in found)
    assert not any("code_hash" in m for m in found)


def test_changed_runtime_code_breaks_code_hash(spec):
    key = signing.SigningKey.generate()
    signed = lp.signed_manifest(spec, LAUNCH, key)
    signed["code_hash"] = "0x" + bytes(32).hex()
    found = messages(lp.check_checkpoint(spec, LAUNCH, signed, [pub(key)]))
    assert any("code_hash is 0x" in m for m in found)
    assert any("signature does not verify" in m for m in found)


def test_launch_manifest_changed_after_signing_is_refused(spec):
    key = signing.SigningKey.generate()
    signed = lp.signed_manifest(spec, {"roles": {}, "supply": {"genesis_lock": {"utxo": "aa" * 32 + "#0"}}}, key)
    moved = {"roles": {}, "supply": {"genesis_lock": {"utxo": "bb" * 32 + "#0"}}}
    found = messages(lp.check_checkpoint(spec, moved, signed, [pub(key)]))
    assert len(found) == 1 and found[0].startswith("[6 checkpoint] launch_manifest_hash is 0x")


def test_launch_manifest_hash_ignores_key_order_and_whitespace():
    a = {"roles": {"oracle": []}, "supply": {"genesis_lock": {"utxo": "u", "address": "a"}}}
    b = json.loads('{"supply": {"genesis_lock": {"address": "a",  "utxo": "u"}}, "roles": {"oracle": []}}')
    assert lp.launch_manifest_hash(a) == lp.launch_manifest_hash(b)


def test_manifest_signed_by_another_key_is_refused(spec):
    signed = lp.signed_manifest(spec, LAUNCH, signing.SigningKey.generate())
    found = messages(lp.check_checkpoint(spec, LAUNCH, signed, [pub(signing.SigningKey.generate())]))
    assert found == ["[6 checkpoint] signed manifest signature does not verify under any launch key checked"]


def test_code_substitutes_are_refused(spec):
    key = signing.SigningKey.generate()
    signed = lp.signed_manifest(spec, LAUNCH, key)
    spec.doc["codeSubstitutes"] = {"1": "0x00"}
    found = messages(lp.check_checkpoint(spec, LAUNCH, signed, [pub(key)]))
    assert "[6 checkpoint] chain spec carries codeSubstitutes" in found


LAST_RUNTIME_UPGRADE = lp.storage_key("System", "LastRuntimeUpgrade")
# The preprod v6 code's version: spec_name "materios", spec_version 208.
V6_SPEC_NAME, V6_SPEC_VERSION = b"\x20materios", 208


def test_the_runtime_version_is_read_from_the_code(spec):
    assert lp.runtime_version(lp.decompressed_code(spec.code)) == (V6_SPEC_NAME, V6_SPEC_VERSION, 1)


def test_the_last_runtime_upgrade_build_spec_writes_passes(spec):
    assert spec.storage[LAST_RUNTIME_UPGRADE] == lp.compact(V6_SPEC_VERSION) + V6_SPEC_NAME
    assert lp.check_last_runtime_upgrade(spec) == []


def test_a_genesis_that_stores_no_last_runtime_upgrade_passes(spec):
    del spec.storage[LAST_RUNTIME_UPGRADE]
    assert lp.check_last_runtime_upgrade(spec) == []


# frame-executive runs the code's migrations when its spec version is above the stored one or its name differs:
# u32::MAX skips every later upgrade's, one below runs them at block 1.
@pytest.mark.parametrize("value", [
    lp.compact(2**32 - 1) + V6_SPEC_NAME, lp.compact(V6_SPEC_VERSION + 1) + V6_SPEC_NAME,
    lp.compact(V6_SPEC_VERSION - 1) + V6_SPEC_NAME, lp.compact(V6_SPEC_VERSION) + b"\x20materiox",
    lp.compact(V6_SPEC_VERSION) + V6_SPEC_NAME + b"\x00", (V6_SPEC_VERSION).to_bytes(4, "little") + V6_SPEC_NAME,
], ids=["u32::MAX", "one above", "one below", "another name", "a trailing byte", "a fixed-width version"])
def test_a_last_runtime_upgrade_other_than_the_one_build_spec_writes_is_refused(spec, value):
    spec.storage[LAST_RUNTIME_UPGRADE] = value
    expected = lp.compact(V6_SPEC_VERSION) + V6_SPEC_NAME
    assert messages(lp.check_last_runtime_upgrade(spec)) == [
        f"[6 checkpoint] System.LastRuntimeUpgrade is 0x{value.hex()}, not 0x{expected.hex()}, spec version 208 of "
        "'materios' as build-spec writes it for this code: the runtime runs its migrations when its spec version is "
        "above the stored one or its name differs, so another value runs them at block 1 or skips them at an upgrade"]


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


@pytest.mark.parametrize("signed, error", [
    ({"genesis_hash": "0x00"}, f"signed manifest code_hash {MISSPELLED}"),
    ([], "signed manifest must be a JSON object"),
])
def test_malformed_manifest_is_an_input_error(spec, signed, error):
    with pytest.raises(lp.InputError, match=f"^{error}"):
        lp.check_checkpoint(spec, LAUNCH, signed, [pub(signing.SigningKey.generate())])


@pytest.mark.parametrize("argv", [
    ["materios-node", "--validator", "--wasm-runtime-overrides", "/srv/overrides"],
    ["materios-node", "--validator", "--wasm-runtime-overrides=/srv/overrides"],
])
def test_authority_with_a_wasm_override_is_refused(argv):
    launch = {"nodes": [authority(argv)]}
    assert messages(lp.check_code_overrides(launch)) == [
        "[6 checkpoint] authority val1 runs --wasm-runtime-overrides: a local runtime would replace "
        "the signed runtime code"]


def test_a_shell_wrapped_authority_with_a_wasm_override_is_refused():
    launch = {"nodes": [authority(["/bin/bash", "--norc", "-c", "exec materios-node --validator "
                                   "--wasm-runtime-overrides /srv/overrides"])]}
    assert messages(lp.check_code_overrides(launch)) == [
        "[6 checkpoint] authority val1 runs --wasm-runtime-overrides: a local runtime would replace "
        "the signed runtime code"]


def test_wasm_override_on_a_non_authority_is_out_of_scope():
    node = {"name": "rpc", "host": "r", "authority": False, "argv": ["materios-node", "--wasm-runtime-overrides", "/o"]}
    assert lp.check_code_overrides({"nodes": [node]}) == []


# ---------------------------------------------------------------------------
# Rule 1: well-known keys
# ---------------------------------------------------------------------------

def dev_key_findings(spec, meta, known, launch=None, manifest_key=None, cardano=NO_CARDANO):
    launch = {"roles": {}} if launch is None else launch
    return messages(lp.check_dev_keys(spec, meta, launch, cardano,
                                      [manifest_key or pub(signing.SigningKey.generate())], known))


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


def test_a_soft_path_role_is_named_as_a_dev_phrase_uri(spec, meta, known):
    launch = {"roles": {"anchor_signer": ["/AnchorSigner///hunter2-password"]}}
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] roles.anchor_signer[0]: well-known secret URI /AnchorSigner" in found
    assert not any("hunter2" in m for m in found)


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
        {"name": "v1", "host": "h1", "argv": ["materios-node", "--validator", "--alice", "--chain", "mainnet.json"]},
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
         "argv": ["/bin/bash", "--norc", "-c", "exec materios-node --validator '--alice'"]},
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
    known = dataclasses.replace(known, phrase_hash=lp.blake2_256(phrase.encode()))
    launch = {"roles": {}, "nodes": [{"name": "v1", "host": "h1", "argv": [],
                                      "env": {"SEED": f"  {phrase.replace(' ', '   ')}//Alice"}}]}
    found = dev_key_findings(spec, meta, known, launch)
    assert "[1 dev-keys] node v1: launch config holds the dev mnemonic" in found


# sp-core's DEV_PHRASE as its seed, which @polkadot/keyring exports as DEV_SEED.
DEV_SEED = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"


def test_table_holds_the_dev_seed_by_its_hash(known):
    assert known.seed_hash == lp.blake2_256(bytes.fromhex(DEV_SEED[2:]))


def sidecar(argv=(), **env) -> dict:
    return {"roles": {}, "nodes": [{"name": "cd", "host": "h1", "authority": False, "argv": list(argv), "env": env}]}


@pytest.mark.parametrize("launch, named", [
    (sidecar(SIGNER_URI="/Attestor0"), "/Attestor0"),
    (sidecar(ORACLE_SURI=" //cert.daemon "), "//cert.daemon"),
    (sidecar(SIGNER_URI="/Oracle//hot///hunter2"), "/Oracle//hot"),
    (sidecar(["cert-daemon", "--suri", "/Attestor1"]), "/Attestor1"),
    (sidecar(["cert-daemon", "--signer-uri=/Attestor2"]), "/Attestor2"),
    (sidecar(["/bin/sh", "-c", "exec cert-daemon --suri /Attestor3"]), "/Attestor3"),
    (sidecar(["bash", "--norc", "-c", "SIGNER_URI=/Attestor4 exec cert-daemon"]), "/Attestor4"),
    (sidecar(["bash", "--norc", "-c", "SIGNER_URI+=/Attestor5 exec cert-daemon"]), "/Attestor5"),
    (sidecar(["systemd-run", "--setenv=SIGNER_URI=/Attestor6", "cert-daemon"]), "/Attestor6"),
    (sidecar(["docker", "run", "-eSIGNER_URI=/Attestor7", "img"]), "/Attestor7"),
    (sidecar(["systemd-run", "-p", "Environment=RUST_LOG=info SIGNER_URI=/Attestor8", "cert-daemon"]), "/Attestor8"),
    (sidecar(["bash", "--norc", "-c", "SIGNER_URI=/Attestor9 exec sh -c 'exec cert-daemon'"]), "/Attestor9"),
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


SKIPPABLE_FRAME = (0x184D2A50).to_bytes(4, "little") + (3).to_bytes(4, "little") + b"abc"
# Compressed runtime code other than the one zstd frame the runtime's build writes behind the prefix.
CODE_FRAMINGS = {
    "a second frame": lambda wasm: zstd_frame(wasm) + zstd_frame(custom_section(b"x", ALICE)),
    "a skippable frame after": lambda wasm: zstd_frame(wasm) + SKIPPABLE_FRAME,
    "a skippable frame before": lambda wasm: SKIPPABLE_FRAME + zstd_frame(wasm),
    "bytes after the frame": lambda wasm: zstd_frame(wasm) + bytes(4),
    "the frame cut by a byte": lambda wasm: zstd_frame(wasm)[:-1],
    "the frame cut in half": lambda wasm: zstd_frame(wasm)[:len(zstd_frame(wasm)) // 2],
    "no frame": lambda wasm: b"",
    "not zstd": lambda wasm: b"\0asm" + bytes(12),
}
NOT_ONE_FRAME = "^runtime code is not one whole zstd frame"


@pytest.mark.parametrize("framing", CODE_FRAMINGS.values(), ids=CODE_FRAMINGS.keys())
def test_runtime_code_in_any_zstd_framing_but_one_whole_frame_is_an_input_error(spec, framing):
    """The node's decoder reads every frame and refuses one cut short, where
    zstandard's readers stop at the end of the first frame or of the input."""
    spec.storage[lp.CODE_KEY] = lp.ZSTD_PREFIX + framing(lp.decompressed_code(spec.code))
    with pytest.raises(lp.InputError, match=NOT_ONE_FRAME):
        lp.spec_genesis_hash(spec)


def test_a_frame_after_one_that_ends_where_a_step_ends_is_an_input_error(spec, monkeypatch):
    """Then the decoder holds no unused input, and only what is left to feed it shows the second frame."""
    first = zstd_frame(lp.decompressed_code(spec.code))
    monkeypatch.setattr(lp, "ZSTD_STEP", len(first))
    spec.storage[lp.CODE_KEY] = lp.ZSTD_PREFIX + first + zstd_frame(custom_section(b"x", ALICE))
    with pytest.raises(lp.InputError, match=NOT_ONE_FRAME):
        lp.spec_genesis_hash(spec)


def test_a_dev_key_in_a_second_zstd_frame_of_the_runtime_code_is_refused(spec, meta, known):
    """The red team's case: the node runs the second frame too, and the dev-key
    scan saw only the first."""
    spec.storage[lp.CODE_KEY] = lp.ZSTD_PREFIX + CODE_FRAMINGS["a second frame"](lp.decompressed_code(spec.code))
    with pytest.raises(lp.InputError, match=NOT_ONE_FRAME):
        dev_key_findings(spec, meta, known)


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


SUDO_POWER = "holds Root"


def lone_holder(rule: str, where: str, key: bytes, paths: list[str], power: str) -> str:
    return (f"[{rule}] {where}: {ss58(key)}, the member at {' and '.join(f'{where}.{p}' for p in paths)}, meets its "
            f"threshold alone by also signing as a nested multisig, so one keyholder alone {power}")


def too_many_signatories(rule: str, where: str, count: int, limit: int = 10) -> str:
    return (f"[{rule}] {where} has {count} members, more than the runtime's Multisig.MaxSignatories {limit}: "
            "pallet_multisig refuses every call signed through it")


def unknown_max_signatories(rule: str, where: str) -> str:
    return (f"[{rule}] {where}: the runtime metadata declares no Multisig.MaxSignatories the preflight can read: "
            "whether pallet_multisig lets this multisig sign is unknown here")


def repeated_member():
    c, d = fresh_account(), fresh_account()
    return {"threshold": 2, "members": [ss58(c), msig(1, c, d)]}, [(c, ["members[0]", "members[1].members[0]"])]


def member_of_two_nested_multisigs():
    c, d, e = fresh_account(), fresh_account(), fresh_account()
    return ({"threshold": 2, "members": [msig(1, c, d), msig(1, c, e)]},
            [(c, ["members[0].members[0]", "members[1].members[0]"])])


def flat_address_of_a_nested_multisig():
    """Either key of the first 1-of-2 signs as it, and so as the flat member of the second."""
    c, d, e = fresh_account(), fresh_account(), fresh_account()
    alias = lp.multisig_account([c, d], 1)
    return ({"threshold": 2, "members": [msig(1, c, d), msig(1, alias, e)]},
            [(c, ["members[0].members[0]"]), (d, ["members[0].members[1]"]), (alias, ["members[1].members[0]"])])


# Multisigs of threshold 2 that one key meets alone, with each such key and where it is a member.
ONE_HOLDER_MULTISIGS = [repeated_member, member_of_two_nested_multisigs, flat_address_of_a_nested_multisig]


def needs_two_through_a_nested_multisig():
    c, d, e = fresh_account(), fresh_account(), fresh_account()
    return {"threshold": 2, "members": [ss58(c), msig(2, d, e)]}


def needs_two_of_three_with_a_nested_1_of_2():
    c, d, e, f = (fresh_account() for _ in range(4))
    return {"threshold": 3, "members": [ss58(c), ss58(d), msig(1, e, f)]}


def needs_one_from_each_of_two_nested_multisigs():
    c, d, e, f = (fresh_account() for _ in range(4))
    return {"threshold": 2, "members": [msig(1, c, d), msig(1, e, f)]}


TWO_HOLDER_MULTISIGS = [needs_two_through_a_nested_multisig, needs_two_of_three_with_a_nested_1_of_2,
                        needs_one_from_each_of_two_nested_multisigs]


def sudo_findings(spec, meta, known, entry) -> list[str]:
    """Rule 1's findings on `entry` as roles.sudo, stored in genesis as the sudo key."""
    put(spec, "Sudo", "Key", lp.role_account(entry))
    return [m for m in dev_key_findings(spec, meta, known, sudo_launch(entry)) if "roles.sudo" in m or "Sudo" in m]


@pytest.mark.parametrize("build", ONE_HOLDER_MULTISIGS, ids=lambda build: build.__name__)
def test_sudo_multisig_one_key_meets_alone_through_a_nested_multisig_is_refused(spec, meta, known, build):
    entry, holders = build()
    assert sudo_findings(spec, meta, known, entry) == [
        lone_holder("1 dev-keys", "roles.sudo[0]", key, paths, SUDO_POWER) for key, paths in sorted(holders)]


@pytest.mark.parametrize("build", TWO_HOLDER_MULTISIGS, ids=lambda build: build.__name__)
def test_sudo_multisig_that_needs_two_keyholders_through_nested_multisigs_passes(spec, meta, known, build):
    assert sudo_findings(spec, meta, known, build()) == []


def test_sudo_multisig_with_more_signatories_than_the_runtime_allows_is_refused(spec, meta, known):
    assert sudo_findings(spec, meta, known, msig(2, *(fresh_account() for _ in range(11)))) == [
        too_many_signatories("1 dev-keys", "roles.sudo[0]", 11)]
    nested = {"threshold": 2, "members": [ss58(fresh_account()), msig(2, *(fresh_account() for _ in range(11)))]}
    assert sudo_findings(spec, meta, known, nested) == [
        too_many_signatories("1 dev-keys", "roles.sudo[0].members[1]", 11)]


def test_sudo_multisig_of_max_signatories_passes(spec, meta, known):
    assert sudo_findings(spec, meta, known, msig(2, *(fresh_account() for _ in range(10)))) == []


@pytest.mark.parametrize("value", [None, b"", bytes(8)], ids=["absent", "empty", "8 bytes"])
def test_sudo_multisig_under_a_runtime_that_hides_max_signatories_is_refused(spec, meta, known, value):
    if value is None:
        del meta.constants[("Multisig", "MaxSignatories")]
    else:
        meta.constants[("Multisig", "MaxSignatories")] = value
    assert sudo_findings(spec, meta, known, msig(2, *(fresh_account() for _ in range(3)))) == [
        unknown_max_signatories("1 dev-keys", "roles.sudo[0]")]


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
# Rule 1 and 3: the Cardano permissioned candidates (the committee the runtime draws)
# ---------------------------------------------------------------------------

def candidate(aura: bytes, gran: bytes | None = None, sidechain: bytes | None = None) -> lp.Candidate:
    return lp.Candidate(sidechain or bytes([2]) + fresh_account(), aura, gran or fresh_account())


def test_dev_key_in_a_cardano_permissioned_candidate_is_named(spec, meta, known):
    alice_ed = bytes.fromhex(SP_KEYRING["ed25519"]["//Alice"])
    alice_ecdsa = bytes.fromhex(ALICE_ECDSA)
    cardano = lp.CardanoView(lock=None, d_parameter=(2, 0),
                             candidates=[candidate(fresh_account()), candidate(ALICE, alice_ed, alice_ecdsa)])
    found = dev_key_findings(spec, meta, known, cardano=cardano)
    assert "[1 dev-keys] Cardano permissioned candidate 1 partner chains key: //Alice (ecdsa)" in found
    assert "[1 dev-keys] Cardano permissioned candidate 1 aura: //Alice (sr25519)" in found
    assert "[1 dev-keys] Cardano permissioned candidate 1 gran: //Alice (ed25519)" in found


def legacy_datum(rows) -> bytes:
    return cbor2.dumps([list(row) for row in rows])


def versioned_datum(appendix, version) -> bytes:
    return cbor2.dumps([cbor2.CBORTag(121, []), appendix, version])


def d_parameter_datum(permissioned: int, registered: int = 0) -> bytes:
    """The D-parameter datum as partner-chains writes it: versioned, at version 0."""
    return versioned_datum([permissioned, registered], 0)


# The node's follower decodes the datum with partner-chains-plutus-data v1.5.1: a legacy bare list, or a versioned
# datum at version 0.
def test_permissioned_candidate_datums_decode_in_every_format_the_node_reads():
    sc, aura, gran = bytes([2]) * 33, bytes([1]) * 32, bytes([3]) * 32
    want = [lp.Candidate(sc, aura, gran)]
    assert lp.decode_candidates(legacy_datum([(sc, aura, gran)])) == want
    assert lp.decode_candidates(versioned_datum([[sc, aura, gran]], 0)) == want


def test_three_legacy_candidates_are_not_read_as_a_versioned_datum():
    rows = [(bytes([2]) * 33, bytes([i]) * 32, bytes([9]) * 32) for i in range(3)]
    assert [c.aura for c in lp.decode_candidates(legacy_datum(rows))] == [bytes([i]) * 32 for i in range(3)]


@pytest.mark.parametrize("raw", [
    b"\xff\x00",
    cbor2.dumps({"not": "a list"}),
    versioned_datum([[b"\x02" * 33, b"\x01" * 32]], 0),
    versioned_datum([], 7),
    versioned_datum([[b"\x02" * 33, [[b"aura", b"\x01" * 32], [b"gran", b"\x03" * 32]]]], 1),
    cbor2.dumps([cbor2.CBORTag(121, []), [[b"\x02" * 33, b"\x01" * 32, b"\x03" * 32]], False]),
], ids=["not CBOR", "a map", "a candidate of two keys", "version 7", "version 1", "a boolean version"])
def test_undecodable_candidate_datum_is_an_input_error(raw):
    with pytest.raises(lp.InputError, match="permissioned candidates"):
        lp.decode_candidates(raw)


def test_the_committee_policies_are_read_from_genesis(spec):
    assert [policy.hex() for policy in lp.committee_policies(spec)] == [
        "38dddaf5198b927b19dac9b28226ab29eddad176d5d81c7748bc2c31",
        "ef2890d1e98247819abcf2df6e891824ed950a4216d36c71ee6f9974"]


def committee_address(spec: lp.Spec, length: int, after: bytes = b"") -> tuple[bytes, bytes]:
    """Genesis MainChainScriptsConfiguration with its committee candidate address repeated or cut to `length` bytes
    before the same two policies, then `after`; returns those policies."""
    raw = spec.value("SessionCommitteeManagement", "MainChainScriptsConfiguration")
    address_len, pos = lp.read_compact(raw, 0)
    policies = raw[pos + address_len:]
    address = (raw[pos:pos + address_len] * 4)[:length]
    put(spec, "SessionCommitteeManagement", "MainChainScriptsConfiguration",
        lp.compact(length) + address + policies + after)
    return policies[:28], policies[28:]


def address_past_bound(length: int) -> str:
    return (f"SessionCommitteeManagement.MainChainScriptsConfiguration holds a {length}-byte committee candidate "
            "address, past the 120 bytes the runtime's MainchainAddress holds: the runtime cannot decode the item and "
            "reads no committee policies, so the node's follower finds no D-parameter and no block is authored")


@pytest.mark.parametrize("length", [0, 120])
def test_committee_policies_after_an_address_the_runtime_decodes_are_read(spec, length):
    policies = committee_address(spec, length)
    assert lp.committee_policies(spec) == policies


# The red team's PoC: an address past the runtime's bound, with the real policies after it, passed every rule while
# the runtime read the default scripts, whose all-zero policies the follower finds no D-parameter under.
@pytest.mark.parametrize("length", [121, 200])
def test_a_committee_address_past_the_runtimes_bound_is_an_input_error(spec, length):
    committee_address(spec, length)
    with pytest.raises(lp.InputError, match="^" + re.escape(address_past_bound(length)) + "$"):
        lp.committee_policies(spec)


def set_committee_address(spec: lp.Spec, address: bytes) -> tuple[bytes, bytes]:
    """Genesis MainChainScriptsConfiguration with `address` before the same two policies; returns those policies."""
    raw = spec.value("SessionCommitteeManagement", "MainChainScriptsConfiguration")
    policies = raw[-2 * 28:]
    put(spec, "SessionCommitteeManagement", "MainChainScriptsConfiguration",
        lp.compact(len(address)) + address + policies)
    return policies[:28], policies[28:]


NOT_UTF8 = ("SessionCommitteeManagement.MainChainScriptsConfiguration holds a committee candidate address that is not "
            "UTF-8: each node's Cardano follower formats it as text to look up registrations, which panics, so every "
            "authority's node exits and no block is authored")
HOLDS_NUL = ("SessionCommitteeManagement.MainChainScriptsConfiguration holds a committee candidate address with a NUL "
             "byte, which the node's Cardano follower cannot pass to its Postgres query: every block's committee "
             "inputs fail and no block is authored")
# The red team's PoC: Display for MainchainAddress is String::from_utf8(..).expect(..), so an address that is not
# UTF-8 panics in either follower's get_candidates, and the node exits; such an address passed every rule.
UNREADABLE_ADDRESSES = {
    "one 0xff byte": (b"\xff", NOT_UTF8),
    "continuation bytes after a prefix": (b"addr_test1" + b"\x80" * 10, NOT_UTF8),
    "120 bytes that are not UTF-8": (b"\xc0" * 120, NOT_UTF8),
    "a surrogate": (b"addr1\xed\xa0\x80", NOT_UTF8),
    "a lone lead byte at the end": (b"addr1\xe2\x82", NOT_UTF8),
    "a NUL byte": (b"addr1\x00w", HOLDS_NUL),
}


@pytest.mark.parametrize("address, refusal", UNREADABLE_ADDRESSES.values(), ids=UNREADABLE_ADDRESSES)
def test_a_committee_address_the_follower_cannot_read_is_an_input_error(spec, address, refusal):
    set_committee_address(spec, address)
    with pytest.raises(lp.InputError, match="^" + re.escape(refusal) + "$"):
        lp.committee_policies(spec)


@pytest.mark.parametrize("address", [b"", b"addr1w" + b"q" * 114, "addr1é€\U0001f600".encode()],
                         ids=["empty", "120 ASCII bytes", "multi-byte UTF-8"])
def test_a_utf8_committee_address_is_read(spec, address):
    assert lp.committee_policies(spec) == set_committee_address(spec, address)


@pytest.mark.parametrize("after", [b"\0", bytes(28)], ids=["a byte", "a third policy"])
def test_committee_scripts_with_bytes_past_the_second_policy_are_an_input_error(spec, after):
    committee_address(spec, 63, after)
    with pytest.raises(lp.InputError, match="^SessionCommitteeManagement.MainChainScriptsConfiguration has "
                                            f"{len(after)} bytes? past its second policy id, which build-spec does "
                                            "not write"):
        lp.committee_policies(spec)


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


# Each attestor reward item and the width of its type in the runtime: u128, u128, u32.
REWARD_WIDTHS = [("attestation_reward_per_signer", "AttestationRewardPerSigner", 16),
                 ("era_cap_base", "EraCapBase", 16),
                 ("era_cap_baseline_attestor_count", "EraCapBaselineAttestorCount", 4)]
A_BYTE_OFF = pytest.mark.parametrize("change", [-1, 1], ids=["a byte short", "a byte long"])


def mis_sized(where: str, size: int, width: int) -> str:
    return f"chain spec raw storage: {where} is {size} byte{'s' * (size != 1)}, not the {width} its type encodes to"


@A_BYTE_OFF
@pytest.mark.parametrize("field, item, width", REWARD_WIDTHS, ids=[item for _, item, _ in REWARD_WIDTHS])
def test_a_reward_stored_at_another_width_is_an_input_error(spec, runtime_meta, field, item, width, change):
    """FRAME reads a value too short for its type as the item's default, here
    zero, and ignores the bytes past its type; the declared number fits either
    way."""
    put(spec, "OrinqReceipts", item, TUNED[field].to_bytes(width + change, "little"))
    with pytest.raises(lp.InputError, match="^" + re.escape(mis_sized(f"OrinqReceipts.{item}", width + change, width))):
        lp.check_rewards(spec, runtime_meta, {"economics": TUNED})


# ---------------------------------------------------------------------------
# Rule 3: unsafe RPC on authorities
# ---------------------------------------------------------------------------

def rpc_findings(tmp_path, nodes, config=None, proxy_node="edge", kind="nginx", authorities=(), other_targets=()):
    """Rule 3 on a validated launch. A proxy node the test does not declare runs on its own machine, and an
    authority whose test gives no cmdline runs its node process with exactly its argv."""
    nodes = [dict(node, cmdline=capture(tmp_path, node["name"], node.get("argv", [])))
             if node["authority"] and "cmdline" not in node else node for node in nodes]
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


BEHIND_PROXY = ["[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def authority(argv, host="val1", name="val1", aura=None):
    return {"name": name, "host": host, "authority": True, "aura": "0x" + (aura or fresh_account()).hex(),
            "grandpa": "0x" + fresh_account().hex(), "argv": argv,
            "exe_sha256": "0x" + hashlib.sha256(b"materios-node").hexdigest()}


def declared(argv, is_authority: bool, **fields) -> dict:
    """A node that runs `argv`, declared an authority, which pins its node binary, or not."""
    node = dict(authority(argv), authority=is_authority, **fields)
    if not is_authority:
        del node["exe_sha256"]
    return node


UNSAFE_9945 = ["materios-node", "--validator", "--rpc-methods", "unsafe", "--rpc-port", "9945"]


def test_unsafe_methods_on_an_external_listener_are_refused(tmp_path):
    argv = ["materios-node", "--validator", "--rpc-methods", "unsafe", "--unsafe-rpc-external"]
    found = rpc_findings(tmp_path, [authority(argv)])
    assert found == ["[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


def test_unsafe_methods_behind_a_loopback_proxy_on_the_same_host_are_refused(tmp_path):
    nginx = "location /rpc { proxy_pass http://127.0.0.1:9945; }"
    argv = ["materios-node", "--rpc-methods=Unsafe", "--rpc-port", "9945"]
    found = rpc_findings(tmp_path, [authority(argv)], nginx, "val1")
    assert found == ["[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_default_methods_on_loopback_are_unsafe_so_a_proxy_is_refused(tmp_path):
    nginx = "upstream chain { server val1:9944; }\nlocation / { proxy_pass http://chain; }"
    found = rpc_findings(tmp_path, [authority(["materios-node", "--validator"])], nginx)
    assert found == ["[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


@pytest.mark.parametrize("argv", [
    ["materios-node", "--validator", "--rpc-external"],
    ["materios-node", "--validator", "--rpc-methods", "safe", "--unsafe-rpc-external"],
    ["materios-node", "--validator", "--rpc-methods", "safe", "--rpc-port", "9945"],
])
def test_safe_methods_pass_even_when_exposed(tmp_path, argv):
    nginx = "location / { proxy_pass http://127.0.0.1:9945; }"
    assert rpc_findings(tmp_path, [authority(argv)], nginx, "val1") == []


def test_proxy_to_another_host_or_port_does_not_implicate_the_authority(tmp_path):
    nginx = "location / { proxy_pass http://rpc-node:9944; } location /b { proxy_pass http://127.0.0.1:9944; }"
    assert rpc_findings(tmp_path, [authority(["materios-node", "--rpc-methods", "unsafe"])], nginx, "edge",
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
    node = dict(authority(["materios-node", "--rpc-methods", "unsafe", "--rpc-port", "9950"]),
                addresses=["10.1.2.3", "val1.lan"])
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


def include_tree(root: Path) -> None:
    """conf.d with the 9945 route in a.conf and in é.conf, whose name is two bytes before .conf, and the 9933 route
    in x.conf."""
    (root / "conf.d").mkdir()
    (root / "conf.d" / "a.conf").write_text("location /rpc { proxy_pass http://127.0.0.1:9945; }\n")
    (root / "conf.d" / "é.conf").write_text("location /e { proxy_pass http://127.0.0.1:9945; }\n")
    (root / "conf.d" / "x.conf").write_text("location /s { proxy_pass http://127.0.0.1:9933; }\n")


# nginx reads an include pattern with glob(3), which reads this syntax apart from Python's glob: glibc negates with
# [^x], takes classes such as [[:alpha:]], escapes with a backslash, and in nginx's C locale matches one byte with ?.
# Through each pattern nginx 1.29.8 served a 9945 route (from a.conf, or from é.conf for ??.conf) where Python's glob
# read x.conf alone or nothing.
@pytest.mark.parametrize("pattern", ["[^x]*.conf", "[[:alpha:]].conf", "\\a*.conf", "??.conf", "[!x]*.conf",
                                     "a.co?f"])
def test_an_nginx_include_glob_that_glob3_reads_apart_is_an_input_error(tmp_path, pattern):
    include_tree(tmp_path)
    nginx = f"events {{}}\nhttp {{ server {{ listen 8080; include conf.d/{pattern}; }} }}\n"
    with pytest.raises(lp.InputError, match=f"nginx include conf.d/{re.escape(pattern)} uses .*cannot resolve"):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1")


# With no *, ? or [ nginx opens the name as written, a backslash included.
def test_an_nginx_include_of_a_literal_name_with_a_backslash_is_followed(tmp_path):
    (tmp_path / "rpc\\.inc").write_text("location /rpc { proxy_pass http://127.0.0.1:9945; }\n")
    nginx = "events {}\nhttp { server { listen 8080; include rpc\\.inc; } }\n"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == BEHIND_PROXY


def test_an_nginx_include_star_glob_reads_every_file_it_names(tmp_path):
    include_tree(tmp_path)
    (tmp_path / "conf.d" / "a.conf").write_text("location /rpc { proxy_pass http://127.0.0.1:9933; }\n")
    nginx = "events {}\nhttp { server { listen 8080; include conf.d/*.conf; } }\n"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == BEHIND_PROXY


# A dump holds each file nginx read, whatever pattern named it.
def test_a_dump_reads_the_files_an_include_glob_named(tmp_path):
    dump = ("# configuration file /etc/nginx/nginx.conf:\nevents {}\nhttp { server { listen 8080; "
            "include /etc/nginx/conf.d/[^x]*.conf; } }\n\n"
            "# configuration file /etc/nginx/conf.d/a.conf:\nlocation /rpc { proxy_pass http://127.0.0.1:9945; }\n")
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], dump, "val1", "nginx-dump") == BEHIND_PROXY


def test_nginx_include_absolute_path_is_followed(tmp_path):
    route = tmp_path / "route.inc"
    route.write_text("location / { proxy_pass http://127.0.0.1:9945; }")
    nginx = f"http {{ server {{ listen 80; include {route}; }} }}"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_nginx_includes_that_nest_without_end_are_an_input_error(tmp_path):
    (tmp_path / "loop.inc").write_text("include loop.inc;\n")
    nginx = "http { include loop.inc; server { location / { proxy_pass http://127.0.0.1:9945; } } }"
    with pytest.raises(lp.InputError, match="nginx includes nest deeper than 8 levels"):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1")


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
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], dump, "val1", "nginx-dump") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


def test_nginx_dump_missing_an_included_file_is_an_input_error(tmp_path):
    dump = ("# configuration file /etc/nginx/nginx.conf:\n"
            "http { include /etc/nginx/rpc-route.inc; server { location / { proxy_pass http://x:1; } } }\n")
    with pytest.raises(lp.InputError, match="include /etc/nginx/rpc-route.inc"):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], dump, "val1", "nginx-dump")


@pytest.mark.parametrize("text", [
    "events {}\nhttp { server { location / { proxy_pass http://127.0.0.1:9945; } } }\n",
    "http { server { location / { proxy_pass http://127.0.0.1:9945; } } }\n"
    "# configuration file /etc/nginx/nginx.conf:\nevents {}\n",
])
def test_nginx_dump_output_is_read_only_where_the_proxy_declares_it(tmp_path, text):
    with pytest.raises(lp.InputError, match="is not `nginx -T` output"):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], text, "val1", "nginx-dump")


# A plain config is read as nginx reads it, a comment that looks like a dump's file header included:
# nginx follows the include from its directory, and serves the 9945 route in rpc.inc.
def test_a_plain_nginx_config_follows_its_includes_whatever_its_comments_say(tmp_path):
    (tmp_path / "rpc.inc").write_text("location /rpc { proxy_pass http://127.0.0.1:9945; }\n")
    nginx = ("# configuration file /etc/nginx/nginx.conf:\n# configuration file /etc/nginx/rpc.inc:\n"
             "events {}\nhttp { server { listen 8080; include rpc.inc; "
             "location /s { proxy_pass http://127.0.0.1:9933; } } }\n")
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == BEHIND_PROXY


def http_routes(upstream: str, rpc: str) -> str:
    """A whole nginx config: this upstream text in its http block, a /s route to a port no node serves unsafe
    methods on, and this /rpc location."""
    return (f"events {{}}\nhttp {{ {upstream}\n  server {{ listen 8080;"
            f"\n    location /s {{ proxy_pass http://127.0.0.1:9933; }}\n    location /rpc {{ {rpc} }} }} }}\n")


# nginx reads a directive the way it reads any other token: a quoted name is the same directive, and a '}' ends
# nothing inside a token (${var} included). Each config passes `nginx -t` on nginx 1.29.8, and nginx proxies
# /rpc to 127.0.0.1:9945.
@pytest.mark.parametrize("nginx", [
    http_routes("", '"proxy_pass" http://127.0.0.1:9945;'),
    http_routes("", "'proxy_pass' http://127.0.0.1:9945;"),
    http_routes("", 'proxy_pass "http://127.0.0.1:9945";'),
    http_routes('upstream rpc { server 127.0.0.1:9933; "server" 127.0.0.1:9945; }', "proxy_pass http://rpc;"),
    http_routes("upstream rpc { hash ${remote_addr}-rpc consistent; server 127.0.0.1:9945; }",
                "proxy_pass http://rpc;"),
    http_routes("upstream rpc { zone z}a 64k; server 127.0.0.1:9945; }", "proxy_pass http://rpc;"),
    http_routes('upstream rpc { zone "z}a" 64k; server 127.0.0.1:9945; }', "proxy_pass http://rpc;"),
    http_routes("upstream RPC { server 127.0.0.1:9945; }", "proxy_pass http://rpc;"),
    http_routes("upstream rpc { server 127.0.0.1:9945; }", "proxy_pass http://RPC;"),
    http_routes('upstream "rp\\"c" { server 127.0.0.1:9945; }', "proxy_pass 'http://rp\"c';"),
    http_routes("", 'if ($http_x != "y") { proxy_pass http://127.0.0.1:9945; }'),
    http_routes("upstream rpc { server 127.0.0.1:9945; }", "proxy_pass http://rpc;")
    + "stream { upstream rpc { server 10.9.9.9:9945; } server { listen 9000; proxy_pass rpc; } }\n",
])
def test_every_nginx_spelling_of_a_route_is_read(tmp_path, nginx):
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1",
                        other_targets=["rpc:80", 'rp"c:80', "10.9.9.9:9945"]) == BEHIND_PROXY


# A scripting module opens its own connections: nginx 1.29.8 with its bundled njs module serves /rpc from
# 127.0.0.1:9945 through js_content and ngx.fetch, with no forwarding directive. A build may also carry njs, perl
# or lua statically.
@pytest.mark.parametrize("nginx", [
    "load_module /usr/lib/nginx/modules/ngx_http_js_module.so;\n"
    + http_routes("js_import main from rpc.js;", "js_content main.rpc;"),
    http_routes("js_import main from rpc.js;", "js_content main.rpc;"),
    http_routes("", "content_by_lua_file /srv/rpc.lua;"),
    http_routes("perl_modules perl/lib; perl_require rpc.pm;", "perl rpc::handler;"),
    "load_module modules/ngx_http_xslt_filter_module.so;\n" + http_routes("", "proxy_pass http://127.0.0.1:9945;"),
])
def test_an_nginx_module_that_runs_code_is_an_input_error(tmp_path, nginx):
    with pytest.raises(lp.InputError, match="runs code inside nginx"):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1")


# A forwarding directive nginx does not ship (OpenResty's redis2_pass, memc_pass, postgres_pass) comes with a module
# the preflight does not read. nginx 1.29.8 and its dynamic modules name no other directive that ends in _pass.
@pytest.mark.parametrize("directive", ["redis2_pass 127.0.0.1:9945", "memc_pass 127.0.0.1:9945", "postgres_pass db"])
def test_a_forwarding_directive_from_another_module_is_an_input_error(tmp_path, directive):
    with pytest.raises(lp.InputError, match=f"{directive.split()[0]} forwards through a module .*cannot resolve"):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], http_routes("", f"{directive};"), "val1")


def test_nginx_directives_that_only_start_with_a_forward_name_are_read_through(tmp_path):
    rpc = "proxy_pass_header Server; proxy_pass_request_headers on; proxy_pass http://127.0.0.1:9945;"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], http_routes("", rpc), "val1") == BEHIND_PROXY


def test_a_quoted_nginx_include_is_followed(tmp_path):
    (tmp_path / "rpc.inc").write_text("location /rpc { proxy_pass http://127.0.0.1:9945; }\n")
    nginx = ('events {}\nhttp { server { listen 8080; "include" rpc.inc; '
             "location /s { proxy_pass http://127.0.0.1:9933; } } }\n")
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == BEHIND_PROXY


def test_an_upstream_reads_the_servers_its_include_names(tmp_path):
    (tmp_path / "servers.inc").write_text("server 127.0.0.1:9945;\n")
    nginx = ("events {}\nhttp { upstream rpc { include servers.inc; }\n"
             "  server { listen 8080; location /rpc { proxy_pass http://rpc; } } }\n")
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == BEHIND_PROXY


# nginx ends a target's host and port at '/' or '?' (ngx_parse_inet_url): nginx 1.29.8 served /rpc from
# 127.0.0.1:9945 through each of these.
@pytest.mark.parametrize("upstream, target", [
    ("upstream rpc { server 127.0.0.1:9945; }", "http://rpc?x"),
    ("", "http://127.0.0.1:9945?x"),
])
def test_a_proxy_target_ends_its_host_at_a_query(tmp_path, upstream, target):
    nginx = http_routes(upstream, f"proxy_pass {target};")
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == BEHIND_PROXY


# The upstream server parameters that leave the server's address as written.
def test_upstream_server_parameters_that_keep_its_address_are_read_through(tmp_path):
    upstream = ("upstream rpc { server val1:9945 weight=2 max_conns=10 max_fails=3 fail_timeout=10s backup; "
                "server 10.9.9.9:1 down; }")
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], http_routes(upstream, "proxy_pass http://rpc;"), "val1",
                        other_targets=["10.9.9.9:1"]) == BEHIND_PROXY


# With service= nginx takes the port, and the host it connects to, from a DNS SRV record while it runs, and with
# resolve it resolves the name again while it runs. nginx 1.29.8 served /rpc from 127.0.0.1:9945 through the first
# upstream, where the preflight read val1:80. Any other parameter is one the preflight does not read: drain comes
# with a build that has the sticky module.
@pytest.mark.parametrize("kind", ["nginx", "nginx-dump"])
@pytest.mark.parametrize("text, parameter", [
    (http_routes("resolver 127.0.0.1 ipv6=off valid=1s;\n  upstream rpc { zone rpc 64k; "
                 "server val1 service=_rpc._tcp resolve; }", "proxy_pass http://rpc;"), "service=_rpc._tcp"),
    (http_routes("resolver 127.0.0.1 valid=1s; upstream rpc { zone rpc 64k; server val1:9945 resolve; }",
                 "proxy_pass http://rpc;"), "resolve"),
    (http_routes("upstream rpc { zone rpc 64k; server val1:9945 drain; }", "proxy_pass http://rpc;"), "drain"),
    (http_routes("", "return 204;") + "stream { resolver 127.0.0.1 valid=1s; upstream rpc { zone rpc 64k; "
     "server val1:9945 resolve; } server { listen 9000; proxy_pass rpc; } }\n", "resolve"),
], ids=["service", "resolve", "drain", "stream-resolve"])
def test_an_upstream_server_nginx_resolves_while_it_runs_is_an_input_error(tmp_path, text, parameter, kind):
    if kind == "nginx-dump":
        text = "# configuration file /etc/nginx/nginx.conf:\n" + text
    with pytest.raises(lp.InputError, match=f"server val1(:9945)? takes {re.escape(parameter)}; .*cannot resolve"):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], text, "val1", kind)


# In a dump, an included file shows under its own header, apart from the block that includes it, and a comment in
# a file can read as a header. So a server outside an upstream block in its own file could serve any upstream:
# nginx serves 127.0.0.1:9945 in upstream rpc from up.d/a.conf, and in the second dump a comment in a.conf would
# move it under tail.d. Each dump is what `nginx -T` prints for those files.
DUMP_MAIN = ("# configuration file /etc/nginx/nginx.conf:\n"
             "events {}\nhttp { upstream rpc { server 10.9.9.9:1; include /etc/nginx/up.d/*.conf; }\n"
             "  server { listen 8080; location /rpc { proxy_pass http://rpc; } } include /etc/nginx/tail.d/*.conf; }\n"
             "\n# configuration file /etc/nginx/up.d/a.conf:\n")


@pytest.mark.parametrize("included", [
    "server 127.0.0.1:9945;\n",
    "# configuration file /etc/nginx/tail.d/x.conf:\nserver 127.0.0.1:9945;\n",
])
def test_a_dump_that_cannot_show_which_upstream_a_server_serves_is_an_input_error(tmp_path, included):
    with pytest.raises(lp.InputError, match="server 127.0.0.1:9945 sits outside any upstream block"):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], DUMP_MAIN + included + "\n", "val1", "nginx-dump",
                     other_targets=["10.9.9.9:1"])


@pytest.mark.parametrize("config, error", [
    ("events {}\nhttp { server { listen 80; root /srv; } }", "has no forwarding route"),
    ("location / { proxy_pass http://unix:/run/node.sock; }", "unix socket"),
    ("location / { proxy_pass http://$backend; }", "is a variable"),
    ("location / { uwsgi_pass val1; }", "names no port"),
    ("http { server 127.0.0.1:9945; server { location / { proxy_pass http://127.0.0.1:9933; } } }",
     "server 127.0.0.1:9945 sits outside any upstream block"),
    ("upstream rpc { } location / { proxy_pass http://rpc; }", "upstream rpc has no server"),
    ("location / { proxy_pass http://127.0.0.1:9945;", "unexpected end of file"),
    ("location / { proxy_pass http://127.0.0.1:9945; } }", "unexpected '}'"),
    ('location / { proxy_pass "http://127.0.0.1:9945"x; }', "unexpected 'x'"),
    ("location / { proxy_pass http://127.0.0.1:9933; }\nproxy_pass http://127.0.0.1:9945", "unexpected end of file"),
    ("location / { ; proxy_pass http://127.0.0.1:9945; }", "unexpected ';'"),
    ("location / { proxy_pass http://127.0.0.1:9945 }", "unexpected '}'"),
    ("include a b; location / { proxy_pass http://127.0.0.1:9945; }", "include takes one file name"),
    ("upstream rpc { server; } location / { proxy_pass http://rpc; }", "a server directive names no address"),
    ("upstream rpc b { server 127.0.0.1:9945; } location / { proxy_pass http://rpc; }", "upstream takes one name"),
])
def test_nginx_config_the_preflight_cannot_bound_is_an_input_error(tmp_path, config, error):
    with pytest.raises(lp.InputError, match=error):
        rpc_findings(tmp_path, [authority(UNSAFE_9945)], config, "val1")


# nginx starts a comment only at a '#' that begins a token, outside quotes and not escaped (ngx_conf_read_token).
# `nginx -t` on nginx 1.29.8 reads a directive after each of these '#'s on the same line.
@pytest.mark.parametrize("before", [
    "add_header X-Frag a#b;",
    'add_header X-Frag "#";',
    "add_header X-Frag 'a #b';",
    "add_header X-Frag \\#b;",
    "add_header X-Frag a}#b;",
    "add_header X-Frag a${host}#b;",
    'add_header X-Frag "a\\"#b";',
    'add_header X-Frag "a\\" #b";',
    "add_header X-Frag 'a\\' #b';",
    "server_name a${#b;",
])
def test_a_hash_that_does_not_start_an_nginx_token_is_not_a_comment(tmp_path, before):
    nginx = f"location /rpc {{ {before} proxy_pass http://127.0.0.1:9945; }}"
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


# And `nginx -t` reads each of these '#'s as a comment to the end of its line.
@pytest.mark.parametrize("nginx", [
    "location / { proxy_pass http://rpc-node:9944; }\n# location /rpc { proxy_pass http://127.0.0.1:9945; }",
    "location / { proxy_pass http://rpc-node:9944; # proxy_pass http://127.0.0.1:9945;\n}",
    "location / { proxy_pass http://rpc-node:9944;#proxy_pass http://127.0.0.1:9945;\n}",
    "location / {#proxy_pass http://127.0.0.1:9945;\nproxy_pass http://rpc-node:9944; }",
    "location / { proxy_pass http://rpc-node:9944; }#proxy_pass http://127.0.0.1:9945;",
    'location / { add_header X-Frag "a" ;#proxy_pass http://127.0.0.1:9945;\nproxy_pass http://rpc-node:9944; }',
])
def test_an_nginx_comment_hides_the_rest_of_its_line(tmp_path, nginx):
    assert rpc_findings(tmp_path, [authority(UNSAFE_9945)], nginx, "val1", other_targets=["rpc-node:9944"]) == []


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
    node = {"name": "rpc", "host": "r", "authority": False,
            "argv": ["materios-node", "--rpc-methods", "unsafe", "--rpc-external"]}
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


# sc-cli takes the flag with num_args = 1..: one flag collects every word up to the next option.
@pytest.mark.parametrize("values", [
    ["listen-addr=127.0.0.1:9955,methods=safe", "listen-addr=0.0.0.0:9956,methods=unsafe"],
    ["listen-addr=127.0.0.1:9955", "listen-addr=[::1]:9957,methods=safe", "listen-addr=[::]:9956,methods=unsafe"],
])
def test_every_value_after_one_experimental_endpoint_flag_is_a_listener(tmp_path, values):
    argv = ["materios-node", "--validator", "--experimental-rpc-endpoint", *values, "--rpc-methods", "safe"]
    assert rpc_findings(tmp_path, [authority(argv)]) == [
        "[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


def test_a_later_value_of_one_experimental_endpoint_flag_behind_a_proxy_is_refused(tmp_path):
    argv = ["materios-node", "--rpc-methods", "safe", "--experimental-rpc-endpoint",
            "listen-addr=127.0.0.1:9955,methods=safe", "listen-addr=127.0.0.1:9966"]
    nginx = "location / { proxy_pass http://127.0.0.1:9966; }"
    assert rpc_findings(tmp_path, [authority(argv)], nginx, "val1") == [
        "[3 rpc] authority val1 serves unsafe RPC methods behind proxy public-rpc"]


# The node trims each option, its key and its value before matching them.
@pytest.mark.parametrize("endpoint", [
    "listen-addr=0.0.0.0:9956, methods=unsafe",
    " listen-addr = 0.0.0.0:9956 , methods = unsafe ",
    "listen-addr=0.0.0.0:9956,\tmethods=unsafe",
])
def test_experimental_endpoint_options_are_read_trimmed(tmp_path, endpoint):
    argv = ["materios-node", "--validator", "--rpc-methods", "safe", "--experimental-rpc-endpoint", endpoint]
    assert rpc_findings(tmp_path, [authority(argv)]) == [
        "[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


# A login shell that loads the node's settings from a file, then execs the node.
LOGIN_SHELL_LAUNCH = ["/bin/bash", "-lc", "set -a; . /etc/node/node.env; set +a; "
                      "exec materios-node --validator --rpc-methods safe"]
# A wrapper that runs no file: the node's settings are in the unit's environment.
SELF_CONTAINED_NODE = ["materios-node", "--validator", "--chain", "/srv/chain/raw.json", "--rpc-methods", "unsafe",
                       "--unsafe-rpc-external"]
SELF_CONTAINED_LAUNCH = ["/bin/bash", "--norc", "-c", "set -eu; umask 077; exec " + " ".join(SELF_CONTAINED_NODE)]
UNSAFE_EXTERNAL = "materios-node --validator --rpc-methods unsafe --unsafe-rpc-external"
SAFE_NODE = "exec materios-node --validator --rpc-methods safe"


@pytest.mark.parametrize("argv, running", [
    (SELF_CONTAINED_LAUNCH, SELF_CONTAINED_NODE),
    (["sh", "-c", "exec " + UNSAFE_EXTERNAL], UNSAFE_EXTERNAL.split()),
    (["/bin/bash", "--norc", "-e", "-c", "mkdir -p /data &&\n" + UNSAFE_EXTERNAL], UNSAFE_EXTERNAL.split()),
    (["bash", "--norc", "-ec", "exec bash --norc -c 'exec " + UNSAFE_EXTERNAL + "'"], UNSAFE_EXTERNAL.split()),
    (["dash", "-c", "RUST_LOG=info " + UNSAFE_EXTERNAL], UNSAFE_EXTERNAL.split()),
])
def test_a_shell_wrapped_launch_is_read_as_the_node_it_runs(tmp_path, argv, running):
    node = dict(authority(argv), cmdline=capture(tmp_path, "val1", running))
    assert rpc_findings(tmp_path, [node]) == [
        "[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


@pytest.mark.parametrize("argv, error", [
    (["materios-node", "--validator", "$RPC_FLAGS"], "expands a variable"),
    (["materios-node", "--validator", "${RPC_FLAGS}"], "expands a variable"),
    (["bash", "-lc", "exec materios-node --validator `cat /etc/flags`"], "expands a variable"),
    (["docker", "run", "--rm", "img", "bash", "-lc", "exec " + UNSAFE_EXTERNAL], "runs docker, not a node binary"),
    (["materios-node", "--validator --rpc-methods unsafe --unsafe-rpc-external"], "argument 1 holds several"),
    (["bash", "--norc", "-c", UNSAFE_EXTERNAL + " | tee /var/log/node.log"], "uses '|'"),
    (["bash", "--norc", "-c", UNSAFE_EXTERNAL + " >> /var/log/node.log 2>&1"], "uses '>>'"),
    (["bash", "--norc", "-c", "materios-node --validator || " + UNSAFE_EXTERNAL], "uses '||'"),
    (["bash", "/opt/start-node.sh"], "without -c"),
    (["bash", "--norc", "-c", "exec materios-node --validator", "arg0"], "must end with its -c script"),
    (["bash", "--norc", "-c", "materios-node --validator; echo started"], "runs echo, not a node binary"),
    (["bash", "--norc", "-c", "exec materios-node --name 'unbalanced"], "does not parse"),
    ([], "runs nothing, not a node binary"),
])
def test_an_authority_launch_the_preflight_cannot_read_is_an_input_error(tmp_path, argv, error):
    with pytest.raises(lp.InputError, match=error):
        lp.validate_node(authority(argv), "nodes[0]")


# systemd rewrites an ExecStart line before execve: it decodes C escapes such as \xNN, expands % specifiers
# (%i is the instance, as in materios@--unsafe-rpc-external.service), reads a leading '@' as "the next word is
# argv[0]" and a ';' word as the start of another command. A shell or a container runtime splits by its own rules.
@pytest.mark.parametrize("is_authority", [True, False])
@pytest.mark.parametrize("argv", [
    "/usr/local/bin/materios-node --validator --rpc-methods unsafe --unsafe-rpc-e\\x78ternal",
    "/bin/bash -c 'exec materios-node --validator --rpc-methods unsafe --unsafe-rpc-e\\x78ternal'",
    "/usr/local/bin/materios-node --validator --rpc-methods safe --wasm-runtime-overrid\\x65s /srv/o",
    "/usr/local/bin/materios-node --validator --rpc-methods unsafe %i",
    "@/usr/local/bin/materios-node --rpc-methods=safe --rpc-methods=unsafe --unsafe-rpc-external",
    "materios-node --rpc-methods safe --version ; materios-node --rpc-methods unsafe --unsafe-rpc-external",
    "materios-node --validator --rpc-methods safe",
])
def test_a_command_line_string_is_an_input_error(argv, is_authority):
    node = declared(argv, is_authority)
    with pytest.raises(lp.InputError, match="argv must be a list of strings: the words the process receives"):
        lp.validate_node(node, "nodes[0]")


@pytest.mark.parametrize("argv", [
    ["bash", "--norc", "-c", UNSAFE_EXTERNAL + "; exec materios-node --validator --rpc-methods safe"],
    ["bash", "--norc", "-c",
     "materios-node --validator --wasm-runtime-overrides /srv/o && exec materios-node --validator"],
    ["sh", "-c", "RUST_LOG=info materios-node; exec bash --norc -c '" + SAFE_NODE + "'"],
])
def test_a_launch_that_starts_a_node_before_its_last_command_is_an_input_error(argv):
    with pytest.raises(lp.InputError, match="starts a node before its last command"):
        lp.validate_node(authority(argv), "nodes[0]")


@pytest.mark.parametrize("earlier", [
    "materios-node build-spec --chain /srv/chain/raw.json --raw --disable-default-bootnode",
    "materios-node purge-chain -y --chain /srv/chain/raw.json --base-path /data",
])
def test_a_node_subcommand_that_opens_no_chain_database_before_the_node_process_is_not_a_node(tmp_path, earlier):
    argv = ["bash", "--norc", "-c", f"{earlier}; exec {UNSAFE_EXTERNAL}"]
    node = dict(authority(argv), cmdline=capture(tmp_path, "val1", UNSAFE_EXTERNAL.split()))
    assert rpc_findings(tmp_path, [node]) == [
        "[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


# The red team's PoC: a subcommand that opens the chain database (export-blocks, check-block, export-state) writes
# the genesis of its own --chain into the base path, and the node then starts from that database whatever its
# --chain names. The node takes no other subcommand, and clap refuses an unknown one only once the node binary runs.
PRIMING_SUBCOMMANDS = [
    "materios-node export-blocks --chain raw.json --base-path /data --from 0 --to 0",
    "materios-node check-block --chain raw.json --base-path /data 0",
    "materios-node export-state --chain raw.json --base-path /data 0",
    "materios-node import-blocks --chain raw.json --base-path /data --binary /srv/blocks.bin",
    "materios-node revert --chain raw.json --base-path /data 0",
    "materios-node-spo key generate-node-key --file /data/node-key",
    "materios-node help",
]


@pytest.mark.parametrize("earlier", PRIMING_SUBCOMMANDS)
def test_a_node_subcommand_that_can_open_the_chain_database_before_the_node_is_an_input_error(earlier):
    node = authority(["sh", "-c", f"{earlier}; cd /srv/materios; {SAFE_NODE} --chain raw.json --base-path /data"])
    with pytest.raises(lp.InputError, match=re.escape(
            f"authority val1: its launch runs the node subcommand {earlier.split()[1]!r} before its last command; the "
            "preflight reads only build-spec and purge-chain there, which open no chain database: another "
            "subcommand can write a genesis into the base path the node then starts from, whatever its --chain "
            "names")):
        lp.validate_node(node, "nodes[0]")


# Any program before the node can start one the preflight never reads: a launcher prefix, eval,
# or a node binary under another name, a builtin's name included.
@pytest.mark.parametrize("earlier", [
    "nohup " + UNSAFE_EXTERNAL,
    "setsid " + UNSAFE_EXTERNAL,
    "env RUST_LOG=info " + UNSAFE_EXTERNAL,
    "/usr/bin/env " + UNSAFE_EXTERNAL,
    "nice -n 5 " + UNSAFE_EXTERNAL,
    "timeout 100d " + UNSAFE_EXTERNAL,
    "command " + UNSAFE_EXTERNAL,
    "exec -a materios " + UNSAFE_EXTERNAL,
    "stdbuf -oL " + UNSAFE_EXTERNAL,
    "sudo -u node " + UNSAFE_EXTERNAL,
    "eval '" + UNSAFE_EXTERNAL + "'",
    "/opt/node/validator-copy --validator --rpc-methods unsafe --unsafe-rpc-external",
    "/opt/node/export --rpc-methods unsafe --unsafe-rpc-external",
])
def test_a_launch_that_runs_another_program_before_its_node_is_an_input_error(earlier):
    with pytest.raises(lp.InputError, match="runs .+ before its last command|runs eval, whose string"):
        lp.validate_node(authority(["bash", "--norc", "-c", earlier + "; " + SAFE_NODE]), "nodes[0]")


def test_a_wasm_override_on_a_prefixed_earlier_node_is_an_input_error():
    launch = {"nodes": [authority(["bash", "--norc", "-c",
                                   "nohup materios-node --validator --wasm-runtime-overrides /srv/o; "
                                   + SAFE_NODE])]}
    with pytest.raises(lp.InputError, match="runs nohup before its last command"):
        lp.check_code_overrides(launch)


def test_setup_commands_before_the_node_are_read_through(tmp_path):
    argv = ["bash", "--norc", "-ec", "set -u; export RUST_LOG=info; cd /data; umask 077; ulimit -n 65536; "
                                     "mkdir -p /data/db && RUST_BACKTRACE=1 exec " + UNSAFE_EXTERNAL]
    node = dict(authority(argv), cmdline=capture(tmp_path, "val1", UNSAFE_EXTERNAL.split()))
    assert rpc_findings(tmp_path, [node]) == [
        "[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


# A file the shell runs before or inside its script (a login or interactive shell's startup files,
# a sourced file, $BASH_ENV, zsh's zshenv) can start or replace the node, and the preflight cannot read it.
@pytest.mark.parametrize("argv, error", [
    (["bash", "-lc", SAFE_NODE], "login or interactive shell"),
    (["bash", "-l", "-c", SAFE_NODE], "login or interactive shell"),
    (["bash", "--login", "-c", SAFE_NODE], "login or interactive shell"),
    (["bash", "-ic", SAFE_NODE], "login or interactive shell"),
    (["sh", "-c", "exec bash -elc '" + SAFE_NODE + "'"], "login or interactive shell"),
    (LOGIN_SHELL_LAUNCH, "login or interactive shell"),
    (["bash", "--norc", "-c", "set -a; . /etc/node/node.env; set +a; " + SAFE_NODE], "sources a file"),
    (["bash", "--norc", "-c", "source /etc/node/node.env && " + SAFE_NODE], "sources a file"),
    (["bash", "--norc", "-c", "export BASH_ENV=/etc/node/rc; exec bash --norc -c '" + SAFE_NODE + "'"],
     "sets BASH_ENV"),
    (["bash", "--norc", "-c", "BASH_ENV=/etc/node/rc exec bash --norc -c '" + SAFE_NODE + "'"], "sets BASH_ENV"),
    (["zsh", "-c", SAFE_NODE], "runs zsh, not a node binary"),
])
def test_a_launch_that_runs_a_file_the_preflight_cannot_read_is_an_input_error(argv, error):
    with pytest.raises(lp.InputError, match=error):
        lp.validate_node(authority(argv), "nodes[0]")


# bash -c runs ~/.bashrc and /etc/bash.bashrc before its script when SSH_CLIENT or SSH2_CLIENT is set or its stdin
# is a socket, unless it is given --norc: bash 5.2.21 ran the rc file with SSH_CLIENT set and with a socketpair on
# stdin, under the names bash and /usr/bin/bash, and ran none with --norc or under the name sh. It takes a long
# option only before its short ones: `bash -e --norc -c` stops at "--: invalid option".
@pytest.mark.parametrize("argv, error", [
    (["bash", "-c", SAFE_NODE], "runs bash -c without --norc"),
    (["/usr/bin/bash", "-ec", SAFE_NODE], "runs bash -c without --norc"),
    (["sh", "-c", "exec bash -c '" + SAFE_NODE + "'"], "runs bash -c without --norc"),
    (["bash", "--noprofile", "-c", SAFE_NODE], "runs bash -c without --norc"),
    (["bash", "-e", "--norc", "-c", SAFE_NODE], "gives --norc after a short option"),
])
def test_a_bash_that_can_run_its_rc_files_is_an_input_error(argv, error):
    with pytest.raises(lp.InputError, match=error):
        lp.validate_node(authority(argv), "nodes[0]")


def test_a_sidecar_bash_that_can_run_its_rc_files_is_an_input_error(spec, meta, known):
    with pytest.raises(lp.InputError, match="runs bash -c without --norc"):
        dev_key_findings(spec, meta, known, sidecar(["bash", "-c", "exec cert-daemon"]))


@pytest.mark.parametrize("argv", [
    ["bash", "--norc", "-c", SAFE_NODE],
    ["/bin/bash", "--noprofile", "--norc", "-ec", SAFE_NODE],
    ["sh", "-c", SAFE_NODE],
    ["sh", "-c", "exec bash --norc -c '" + SAFE_NODE + "'"],
])
def test_a_shell_that_runs_no_rc_file_is_read_through(argv):
    assert lp.node_process(authority(argv)) == SAFE_NODE.split()[1:]


# bash rewrites these words before the node sees them: brace, filename and tilde expansion, and a comment.
@pytest.mark.parametrize("script", [
    "exec materios-node --validator {--rpc-methods=unsafe,--unsafe-rpc-external}",
    "exec materios-node --validator {--wasm-runtime-overrides,/srv/o}",
    "exec materios-node {--validator,--alice}",
    "exec materios-node --validator --rpc-methods unsafe {--unsafe-rpc-external}",
    "export {RUST_LOG,BASH_ENV}=/etc/node/rc; exec bash --norc -c '" + SAFE_NODE + "'",
    "cd /srv; mkdir -p ./--unsafe-rpc-external; exec materios-node --validator --rpc-methods unsafe --unsafe-rpc-e*",
    "exec materios-node --validator --rpc-methods unsafe --unsafe-rpc-externa?",
    "exec materios-node --validator --rpc-methods unsafe --unsafe-rpc-externa[l]",
    "exec materios-node --validator --rpc-port 9945 # --rpc-methods safe",
    "exec materios-node --validator --rpc-port 9945;# --rpc-methods safe",
    "exec materios-node --validator --base-path ~/data",
])
def test_a_script_word_the_shell_rewrites_is_an_input_error(script):
    with pytest.raises(lp.InputError, match="that the shell rewrites"):
        lp.validate_node(authority(["bash", "--norc", "-c", script]), "nodes[0]")


# bash drops a backslash-newline, so the words on either side join.
@pytest.mark.parametrize("script", [
    "exec materios-node --validator --rpc-methods unsafe --unsafe-rpc-\\\nexternal",
    "exec materios-node --validator --rpc-methods unsafe \"--unsafe-rpc-\\\nexternal\"",
    "RUST_LOG=info \\\nexec materios-node --validator --rpc-methods safe",
])
def test_a_script_line_continuation_is_an_input_error(script):
    with pytest.raises(lp.InputError, match="continues a line with a backslash"):
        lp.validate_node(authority(["bash", "--norc", "-c", script]), "nodes[0]")


# A tilde expands to a home directory: a phraseless secret URI to the node that reads it.
@pytest.mark.parametrize("script", ["exec cert-daemon --suri ~", "SIGNER_URI=~ exec cert-daemon"])
def test_a_sidecar_script_word_the_shell_rewrites_is_an_input_error(spec, meta, known, script):
    with pytest.raises(lp.InputError, match="that the shell rewrites"):
        dev_key_findings(spec, meta, known, sidecar(["sh", "-c", script]))


# execve ends each argument and setting at a NUL byte, so the process would get less than the word says.
@pytest.mark.parametrize("argv, env", [
    (["materios-node", "--validator", "--rpc-methods", "unsafe", "--unsafe-rpc-external\x00"], {}),
    (["materios-node", "--validator", "--unsafe-rpc-external", "--rpc-methods\x00x", "unsafe"], {}),
    (["bash", "--norc", "-c", "exec materios-node --validator --rpc-port 9945 --name x\x00 --rpc-methods safe"], {}),
    (["materios-node", "--validator"], {"RUST_LOG": "info\x00"}),
])
def test_a_launch_word_holding_a_nul_byte_is_an_input_error(argv, env):
    with pytest.raises(lp.InputError, match="holds a NUL byte"):
        lp.validate_node(dict(authority(argv), env=env), "nodes[0]")


# bash splits words at spaces and tabs only: a carriage return stays inside the word.
def test_a_carriage_return_does_not_split_a_script_word():
    script = "exec materios-node --validator --rpc-port 9945 --name val\r--rpc-methods\rsafe"
    with pytest.raises(lp.InputError, match="argument 5 holds several arguments"):
        lp.validate_node(authority(["bash", "--norc", "-c", script]), "nodes[0]")


def test_a_hash_inside_a_script_word_is_read_literally(tmp_path):
    running = "materios-node --validator --name val#1 --rpc-methods unsafe --unsafe-rpc-external"
    node = dict(authority(["bash", "--norc", "-c", "exec " + running]),
                cmdline=capture(tmp_path, "val1", running.split()))
    assert rpc_findings(tmp_path, [node]) == [
        "[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


# Settings the shell or the dynamic loader acts on: a file or code it runs (BASH_ENV, a BASH_FUNC_ import,
# PS4 under xtrace, ENV, LD_PRELOAD), options it starts with (SHELLOPTS, BASHOPTS), or where a name resolves (PATH).
LOADER_SETTINGS = ["BASH_ENV", "BASH_FUNC_materios-node%%", "PS4", "SHELLOPTS", "BASHOPTS", "ENV", "PATH",
                   "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"]


def loader_error(name: str) -> str:
    return f"sets {re.escape(name)}, which changes what the shell or the dynamic loader runs"


@pytest.mark.parametrize("is_authority", [True, False])
@pytest.mark.parametrize("name", LOADER_SETTINGS)
def test_an_environment_that_changes_what_the_shell_or_loader_runs_is_an_input_error(name, is_authority):
    node = declared(["bash", "--norc", "-c", SAFE_NODE], is_authority, env={name: "/srv/x"})
    with pytest.raises(lp.InputError, match=loader_error(name)):
        lp.validate_node(node, "nodes[0]")


@pytest.mark.parametrize("is_authority", [True, False])
@pytest.mark.parametrize("name, script", [
    ("PS4", "export PS4=x; " + SAFE_NODE),
    ("PS4", "PS4=x; " + SAFE_NODE),
    ("SHELLOPTS", "SHELLOPTS=xtrace exec bash --norc -c '" + SAFE_NODE + "'"),
    ("BASHOPTS", "export BASHOPTS=x; " + SAFE_NODE),
    ("ENV", "export ENV=/srv/rc; " + SAFE_NODE),
    ("PATH", "PATH=/srv/bin " + SAFE_NODE),
    ("PATH", "PATH+=:/srv/bin " + SAFE_NODE),
    ("LD_PRELOAD", "LD_PRELOAD=/srv/x.so " + SAFE_NODE),
    ("LD_AUDIT", "exec env LD_AUDIT=/srv/x.so materios-node --validator"),
])
def test_a_script_setting_that_changes_what_the_shell_or_loader_runs_is_an_input_error(name, script, is_authority):
    node = declared(["bash", "--norc", "-c", script], is_authority)
    with pytest.raises(lp.InputError, match=loader_error(name)):
        lp.validate_node(node, "nodes[0]")


# An authority's environment is an allowlist: what else could run code or change the node goes unread.
@pytest.mark.parametrize("name", ["GCONV_PATH", "OPENSSL_CONF", "MALLOC_CONF", "USE_MAIN_CHAIN_FOLLOWER_MOCK",
                                  "MITHRIL_CLIENT_BIN", "HOME"])
def test_an_authority_setting_outside_the_allowlist_is_an_input_error(name):
    node = dict(authority(["bash", "--norc", "-c", SAFE_NODE]), env={name: "/srv/x"})
    with pytest.raises(lp.InputError, match=f"sets {name}, which is not a setting an authority may set"):
        lp.validate_node(node, "nodes[0]")


@pytest.mark.parametrize("name, script", [
    ("GCONV_PATH", "export GCONV_PATH=/srv/gconv; " + SAFE_NODE),
    ("GCONV_PATH", "GCONV_PATH+=/srv/gconv " + SAFE_NODE),
    ("USE_MAIN_CHAIN_FOLLOWER_MOCK", "USE_MAIN_CHAIN_FOLLOWER_MOCK=true " + SAFE_NODE),
    ("MITHRIL_CLIENT_BIN", "MITHRIL_CLIENT_BIN=/srv/mithril; export MITHRIL_CLIENT_BIN; " + SAFE_NODE),
    ("OPENSSL_CONF", "exec bash --norc -c 'OPENSSL_CONF=/srv/o.cnf " + SAFE_NODE + "'"),
])
def test_an_authority_script_setting_outside_the_allowlist_is_an_input_error(name, script):
    with pytest.raises(lp.InputError, match=f"sets {name}, which is not a setting an authority may set"):
        lp.validate_node(authority(["bash", "--norc", "-c", script]), "nodes[0]")


def test_an_authority_may_set_logging_the_time_zone_and_its_node_settings(tmp_path):
    env = {"RUST_LOG": "info", "RUST_BACKTRACE": "1", "RUST_LIB_BACKTRACE": "0", "TZ": "UTC",
           "MAIN_CHAIN_FOLLOWER": "yaci", "DB_SYNC_POSTGRES_CONNECTION_STRING": "postgres://follower@db:5432/cexplorer",
           "CARDANO_SECURITY_PARAMETER": "2160", "CARDANO_ACTIVE_SLOTS_COEFF": "0.05", "BLOCK_STABILITY_MARGIN": "0",
           "MC__FIRST_EPOCH_TIMESTAMP_MILLIS": "1596059091000", "MC__EPOCH_DURATION_MILLIS": "432000000",
           "MC__FIRST_EPOCH_NUMBER": "208", "MC__FIRST_SLOT_NUMBER": "4492800", "MC__SLOT_DURATION_MILLIS": "1000",
           "SIDECHAIN_BLOCK_BENEFICIARY": "0x" + fresh_account().hex(),
           "MITHRIL_AGGREGATOR_ENDPOINT": "https://aggregator.example.org/aggregator",
           "MITHRIL_GENESIS_VERIFICATION_KEY": "5b3139312c36362c3134302c3138355d"}
    script = "set -a; export TZ=UTC; set +a; RUST_LOG=info exec " + UNSAFE_EXTERNAL
    node = dict(authority(["bash", "--norc", "-euc", script]), env=env,
                cmdline=capture(tmp_path, "val1", UNSAFE_EXTERNAL.split()))
    assert rpc_findings(tmp_path, [node]) == [
        "[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


# -x runs $PS4 as code before each command; -v, -k and the rest change what a command gets or the shell prints.
@pytest.mark.parametrize("argv, option", [
    (["bash", "--norc", "-c", "set -x; " + SAFE_NODE], "-x"),
    (["bash", "--norc", "-c", "set -eux; " + SAFE_NODE], "-eux"),
    (["bash", "--norc", "-c", "set -o xtrace; " + SAFE_NODE], "-o"),
    (["bash", "--norc", "-c", "set -v; " + SAFE_NODE], "-v"),
    (["bash", "--norc", "-c", "set -k; " + SAFE_NODE], "-k"),
    (["bash", "-xc", SAFE_NODE], "-xc"),
    (["bash", "-e", "-x", "-c", SAFE_NODE], "-x"),
    (["sh", "-c", "exec bash -kc '" + SAFE_NODE + "'"], "-kc"),
])
def test_a_shell_option_the_preflight_does_not_read_is_an_input_error(argv, option):
    with pytest.raises(lp.InputError, match=f"sets shell option {option};"):
        lp.validate_node(authority(argv), "nodes[0]")


# bash 5.2 sources the file before the exec in each of these.
@pytest.mark.parametrize("script, error", [
    (". /etc/cert-daemon.env; exec cert-daemon", "sources a file with ."),
    ("builtin source /etc/cert-daemon.env; exec cert-daemon", "sources a file with source"),
    ("command . /etc/cert-daemon.env; exec cert-daemon", "sources a file with ."),
    ("command -p source /etc/cert-daemon.env; exec cert-daemon", "sources a file with source"),
    ("builtin command builtin . /etc/cert-daemon.env; exec cert-daemon", "sources a file with ."),
    ("eval '. /etc/cert-daemon.env'; exec cert-daemon", "runs eval, whose string"),
    ("trap '. /etc/cert-daemon.env' DEBUG; exec cert-daemon", "runs trap, whose string"),
])
def test_a_sidecar_that_runs_a_file_or_string_it_cannot_read_is_an_input_error(spec, meta, known, script, error):
    with pytest.raises(lp.InputError, match=error):
        dev_key_findings(spec, meta, known, sidecar(["sh", "-c", script]))


# A setting reaches a program however a word hands it over: after a short option (docker -e), after '='
# (systemd-run --setenv=), or after whitespace in a settings string.
@pytest.mark.parametrize("argv", [
    ["systemd-run", "--setenv=LD_PRELOAD=/srv/x.so", "cert-daemon"],
    ["docker", "run", "-eLD_PRELOAD=/srv/x.so", "img"],
    ["env", "-SLD_PRELOAD=/srv/x.so", "cert-daemon"],
    ["bash", "--norc", "-c", "exec systemd-run -p 'Environment=RUST_LOG=info LD_PRELOAD=/srv/x.so' cert-daemon"],
])
def test_a_loader_setting_handed_over_inside_a_word_is_an_input_error(argv):
    with pytest.raises(lp.InputError, match=loader_error("LD_PRELOAD")):
        lp.validate_node(sidecar(argv)["nodes"][0], "nodes[0]")


# GNU env -S splits a string by its own quoting and escapes: `\_` separates two words, so X=1\_LD_PRELOAD=...
# sets LD_PRELOAD (env 9.4 makes ld.so preload the file).
@pytest.mark.parametrize("argv", [
    ["env", "-S", "X=1\\_LD_PRELOAD=/srv/x.so cert-daemon"],
    ["env", "-iS", "X=1\\_LD_PRELOAD=/srv/x.so cert-daemon"],
    ["env", "--split-str", "X=1\\_SIGNER_URI=/Attestor0 cert-daemon"],
    ["env", "--split-string=X=1\\_SIGNER_URI=/Attestor0 cert-daemon"],
    ["nohup", "env", "-u", "HOME", "-S", "X=1\\_SIGNER_URI=/Attestor0 cert-daemon"],
    ["bash", "--norc", "-c", "exec env -S 'X=1\\_LD_PRELOAD=/srv/x.so' cert-daemon"],
])
def test_env_splitting_a_string_is_an_input_error(argv):
    with pytest.raises(lp.InputError, match="runs env -S"):
        lp.validate_node(sidecar(argv)["nodes"][0], "nodes[0]")


@pytest.mark.parametrize("argv", [
    ["env", "-uS", "cert-daemon"],
    ["env", "-u", "S", "RUST_LOG=info", "cert-daemon", "-S", "x"],
    ["env", "--unset", "S", "cert-daemon"],
])
def test_env_options_that_split_no_string_are_read_through(argv):
    lp.validate_node(sidecar(argv)["nodes"][0], "nodes[0]")


def test_a_shell_wrapped_non_authority_validator_is_refused(tmp_path):
    node = {"name": "v9", "host": "h9", "authority": False,
            "argv": ["/bin/bash", "--norc", "-c", "exec materios-node --validator --rpc-methods safe"]}
    assert rpc_findings(tmp_path, [node]) == ["[3 rpc] node v9 runs --validator but is not declared an authority"]


def test_validator_not_declared_an_authority_is_refused(tmp_path):
    node = {"name": "v9", "host": "h9", "authority": False,
            "argv": ["materios-node", "--validator", "--rpc-methods", "unsafe", "--rpc-external"]}
    assert rpc_findings(tmp_path, [node]) == [
        "[3 rpc] node v9 runs --validator but is not declared an authority"]


def test_unknown_rpc_methods_value_is_refused(tmp_path):
    found = rpc_findings(tmp_path, [authority(["materios-node", "--rpc-methods", "everything"])])
    assert found == ["[3 rpc] node val1: unknown --rpc-methods everything"]


def test_every_authority_needs_a_node_entry(tmp_path):
    listed, missing = fresh_account(), fresh_account()
    authorities = [("genesis Aura.Authorities[0]", listed), ("Cardano permissioned candidate 0", missing)]
    found = rpc_findings(tmp_path, [authority(["materios-node", "--validator", "--rpc-methods", "safe"], aura=listed)],
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
    cardano = lp.CardanoView(lock=None, candidates=[candidate(extra)], d_parameter=(1, 0))
    labels = lp.authorities(spec, cardano)
    assert [aura for _, aura in labels] == aura_keys(spec) + [extra]
    assert labels[0][0] == "genesis Aura.Authorities[0]"
    assert labels[-1][0] == "Cardano permissioned candidate 0"


# ---------------------------------------------------------------------------
# Rule 9: the genesis committee
# ---------------------------------------------------------------------------

def grandpa_keys(spec: lp.Spec) -> list[bytes]:
    raw = spec.value("Grandpa", "Authorities")
    count, pos = lp.read_compact(raw, 0)
    return [raw[pos + 40 * i:pos + 40 * i + 32] for i in range(count)]


def grandpa_list(*voters: tuple[bytes, int]) -> bytes:
    return lp.compact(len(voters)) + b"".join(key + weight.to_bytes(8, "little") for key, weight in voters)


def cross_chain_key() -> bytes:
    """The shape of a compressed ECDSA public key: a parity byte, then 32 bytes."""
    return bytes([2]) + fresh_account()


def genesis_members(spec: lp.Spec) -> list[tuple[bytes, bytes, bytes]]:
    """The preprod genesis authors as committee members: a fresh cross-chain key each, then its aura and grandpa
    keys."""
    return [(cross_chain_key(), aura, gran) for aura, gran in zip(aura_keys(spec), grandpa_keys(spec))]


def committee_value(members, epoch: int = 0) -> bytes:
    return epoch.to_bytes(8, "little") + lp.compact(len(members)) + b"".join(b"".join(m) for m in members)


def session_value(members) -> bytes:
    return lp.compact(len(members)) + b"".join(lp.blake2_256(cc) + aura + gran for cc, aura, gran in members)


def seat(spec: lp.Spec, members) -> None:
    """Genesis as build-spec writes it for a committee of `members`: the committee, and the Aura authors, GRANDPA
    voters and session validators the session genesis seats from it."""
    put(spec, "SessionCommitteeManagement", "CurrentCommittee", committee_value(members))
    put(spec, "Aura", "Authorities", lp.compact(len(members)) + b"".join(aura for _, aura, _ in members))
    put(spec, "Grandpa", "Authorities", grandpa_list(*((gran, 1) for _, _, gran in members)))
    put(spec, "Session", "ValidatorsAndKeys", session_value(members))


def members_launch(members, extra=()) -> dict:
    """An authority for each member, declaring its aura and grandpa keys."""
    return rpc_launch([dict(authority(["materios-node"], f"val{i}", f"val{i}", aura), grandpa="0x" + gran.hex())
                       for i, (_, aura, gran) in enumerate(members)] + list(extra))


def committee_findings(spec: lp.Spec, meta: lp.Metadata, launch: dict) -> list[str]:
    return messages(lp.check_committee(spec, meta, launch))


@pytest.fixture
def seated(spec):
    """The preprod genesis with its authors seated as its committee, and a launch that declares them."""
    members = genesis_members(spec)
    seat(spec, members)
    return spec, members, members_launch(members)


COMMITTEE = "genesis SessionCommitteeManagement.CurrentCommittee"
EMPTY_COMMITTEE = ("the runtime seats the genesis committee at every rotation whose Cardano draw fails, as a fresh "
                   "chain's first draw does, and GRANDPA refuses an empty authority set, so the chain halts there")
LEFT_OUT = "the runtime leaves it out at every rotation whose Cardano draw fails"
NOT_THE_SESSION = ("[9 committee] genesis Session.ValidatorsAndKeys is not the genesis committee as the session "
                   "genesis writes it, each member's account (blake2-256 of its cross-chain key) with its aura and "
                   "grandpa keys, in the committee's order: the session keys it holds are unchecked")


def pair(aura: bytes, gran: bytes) -> str:
    return f"(aura 0x{aura.hex()}, grandpa 0x{gran.hex()})"


def left_out(i: int, aura: bytes, gran: bytes) -> str:
    return (f"[9 committee] authority val{i}'s aura and grandpa key pair {pair(aura, gran)} is not in {COMMITTEE}: "
            f"{LEFT_OUT}")


def test_a_genesis_committee_of_the_declared_authorities_passes(seated, meta):
    spec, _, launch = seated
    assert committee_findings(spec, meta, launch) == []


# What build-spec writes before #57: Aura and GRANDPA seeded directly, and no committee. A fresh chain's first draw
# fails, and the runtime then seats the empty committee.
def test_the_build_spec_genesis_with_an_empty_committee_is_refused(spec, meta):
    members = genesis_members(spec)
    assert committee_findings(spec, meta, members_launch(members)) == [
        f"[9 committee] {COMMITTEE} is empty: {EMPTY_COMMITTEE}"] + [
        left_out(i, aura, gran) for i, (_, aura, gran) in enumerate(members)]


def test_a_genesis_with_no_committee_is_refused(seated, meta):
    spec, members, launch = seated
    del spec.storage[lp.storage_key("SessionCommitteeManagement", "CurrentCommittee")]
    assert committee_findings(spec, meta, launch) == [
        "[9 committee] genesis sets no SessionCommitteeManagement.CurrentCommittee, which build-spec always writes: "
        f"the runtime reads an empty one, and {EMPTY_COMMITTEE}"] + [
        left_out(i, aura, gran) for i, (_, aura, gran) in enumerate(members)] + [NOT_THE_SESSION]


# The red team's PoC: an outsider as the genesis committee, with Aura, GRANDPA and the Cardano candidates all the
# declared authorities'. The first rotation's draw fails, and the runtime seats the outsider as the only author and
# voter.
def test_an_outsider_in_the_genesis_committee_is_refused(seated, meta):
    spec, members, launch = seated
    outsider = (cross_chain_key(), fresh_account(), fresh_account())
    put(spec, "SessionCommitteeManagement", "CurrentCommittee", committee_value([outsider]))
    assert committee_findings(spec, meta, launch) == [
        f"[9 committee] {COMMITTEE}[0] {pair(*outsider[1:])} is not a declared authority's aura and grandpa key pair: "
        "the runtime seats it, unchecked, at every rotation whose Cardano draw fails"] + [
        left_out(i, aura, gran) for i, (_, aura, gran) in enumerate(members)] + [NOT_THE_SESSION]


def at_epoch(epoch: int) -> str:
    return (f"[9 committee] {COMMITTEE} serves epoch {epoch}, not the 0 build-spec writes: the node takes only an "
            "epoch-0 committee as the genesis one, and otherwise asks Cardano at block 1 for the committee of the "
            "epoch after it instead of the current one's, which it cannot derive for an epoch that began before "
            "Cardano's first, so the chain never authors block 1")


# The red team's PoC: the declared committee at another epoch than build-spec's passed every rule, and the node's
# Ariadne data provider then fails block 1's inherent data at every slot (u64::MAX wraps to epoch 0 in the runtime).
@pytest.mark.parametrize("epoch", [1, 2, 1000, 2**64 - 1])
def test_a_genesis_committee_at_an_epoch_other_than_zero_is_refused(seated, meta, epoch):
    spec, members, launch = seated
    put(spec, "SessionCommitteeManagement", "CurrentCommittee", committee_value(members, epoch))
    assert committee_findings(spec, meta, launch) == [at_epoch(epoch)]


def test_every_declared_authority_must_sit_in_the_genesis_committee(seated, meta):
    spec, members, launch = seated
    seat(spec, members[:3])
    _, aura, gran = members[3]
    assert committee_findings(spec, meta, launch) == [
        left_out(3, aura, gran),
        f"[9 committee] authority val3's aura key 0x{aura.hex()} is not in genesis Aura.Authorities: it authors no "
        "block",
        f"[9 committee] authority val3's grandpa key 0x{gran.hex()} is not in genesis Grandpa.Authorities: it does not "
        "vote on finality"]


def test_an_authority_listed_twice_in_the_genesis_committee_is_refused(seated, meta):
    spec, members, launch = seated
    put(spec, "SessionCommitteeManagement", "CurrentCommittee", committee_value(members + [members[1]]))
    assert committee_findings(spec, meta, launch) == [
        f"[9 committee] {COMMITTEE}[4] repeats member 1's cross-chain key: each authority sits in the committee "
        "once, under its own key",
        f"[9 committee] {COMMITTEE}[4] {pair(*members[1][1:])} is listed before: each authority sits in the committee "
        "once",
        NOT_THE_SESSION]


def test_two_genesis_committee_members_under_one_cross_chain_key_are_refused(seated, meta):
    spec, members, launch = seated
    shared = [members[0], (members[0][0], *members[1][1:]), *members[2:]]
    seat(spec, shared)
    assert committee_findings(spec, meta, launch) == [
        f"[9 committee] {COMMITTEE}[1] repeats member 0's cross-chain key: each authority sits in the committee "
        "once, under its own key"]


@pytest.mark.parametrize("members", [1, 3])
def test_a_genesis_committee_over_the_runtimes_max_validators_is_refused(seated, meta, members):
    spec, _, launch = seated
    meta.constants[("SessionCommitteeManagement", "MaxValidators")] = members.to_bytes(4, "little")
    assert committee_findings(spec, meta, launch) == [
        f"[9 committee] {COMMITTEE} lists 4 members, more than the runtime's SessionCommitteeManagement.MaxValidators "
        f"{members}: the runtime cannot decode it and reads an empty committee, and {EMPTY_COMMITTEE}"]


def test_a_genesis_committee_of_max_validators_passes(seated, meta):
    spec, _, launch = seated
    meta.constants[("SessionCommitteeManagement", "MaxValidators")] = (4).to_bytes(4, "little")
    assert committee_findings(spec, meta, launch) == []


@pytest.mark.parametrize("value", [None, b"", bytes(8)], ids=["absent", "empty", "8 bytes"])
def test_a_genesis_committee_under_a_runtime_that_hides_max_validators_is_refused(seated, meta, value):
    spec, _, launch = seated
    if value is None:
        del meta.constants[("SessionCommitteeManagement", "MaxValidators")]
    else:
        meta.constants[("SessionCommitteeManagement", "MaxValidators")] = value
    assert committee_findings(spec, meta, launch) == [
        "[9 committee] the runtime metadata declares no SessionCommitteeManagement.MaxValidators the preflight can "
        "read: whether the runtime can decode the genesis committee is unknown here"]


# parity-scale-codec refuses a length in more bytes than it needs: the runtime would read such a committee as
# undecodable, and so empty.
@pytest.mark.parametrize("raw", [
    bytes(7),
    committee_value([(bytes([2]) * 33, bytes(32), bytes(32))])[:-1],
    committee_value([(bytes([2]) * 33, bytes(32), bytes(32))]) + b"\0",
    bytes(8) + (1 << 2 | 1).to_bytes(2, "little") + bytes(97),
], ids=["shorter than its epoch", "a byte short", "a byte long", "a length in two bytes"])
def test_a_genesis_committee_that_does_not_decode_is_an_input_error(seated, meta, raw):
    spec, _, launch = seated
    put(spec, "SessionCommitteeManagement", "CurrentCommittee", raw)
    with pytest.raises(lp.InputError, match="SessionCommitteeManagement.CurrentCommittee does not decode as a u64 "
                                            "epoch and a list of 97-byte members"):
        committee_findings(spec, meta, launch)


def test_a_genesis_author_no_authority_declares_is_refused(seated, meta):
    spec, members, launch = seated
    outsider = fresh_account()
    put(spec, "Aura", "Authorities", lp.compact(5) + b"".join(aura for _, aura, _ in members) + outsider)
    assert committee_findings(spec, meta, launch) == [
        f"[9 committee] genesis Aura.Authorities[4] 0x{outsider.hex()} is not a declared authority's aura key: it "
        "authors blocks unchecked"]


def test_a_genesis_author_listed_twice_is_refused(seated, meta):
    spec, members, launch = seated
    aura = [aura for _, aura, _ in members]
    put(spec, "Aura", "Authorities", lp.compact(5) + b"".join(aura) + aura[2])
    assert committee_findings(spec, meta, launch) == [
        f"[9 committee] genesis Aura.Authorities[4] 0x{aura[2].hex()} is listed before: it authors the slots of two "
        "authorities"]


@pytest.mark.parametrize("item, width", [("Aura", 32), ("Grandpa", 40)])
def test_a_genesis_authority_list_whose_length_is_not_in_its_fewest_bytes_is_an_input_error(seated, meta, item,
                                                                                            width):
    spec, _, launch = seated
    raw = spec.value(item, "Authorities")
    count, pos = lp.read_compact(raw, 0)
    put(spec, item, "Authorities", (count << 2 | 1).to_bytes(2, "little") + raw[pos:])
    with pytest.raises(lp.InputError, match=f"{item}.Authorities does not decode as a list of 32-byte keys"):
        committee_findings(spec, meta, launch)


# The red team's PoC: a GRANDPA voter no declared authority holds finalized the chain unchecked.
def test_a_genesis_grandpa_voter_no_authority_declares_is_refused(seated, meta):
    spec, members, launch = seated
    outsider = fresh_account()
    put(spec, "Grandpa", "Authorities", grandpa_list((outsider, 1)))
    assert committee_findings(spec, meta, launch) == [
        f"[9 committee] genesis Grandpa.Authorities[0] 0x{outsider.hex()} is not a declared authority's grandpa key: "
        "who finalizes is unchecked"] + [
        f"[9 committee] authority val{i}'s grandpa key 0x{gran.hex()} is not in genesis Grandpa.Authorities: it does "
        "not vote on finality" for i, (_, _, gran) in enumerate(members)]


# Weight 0 drops a voter and 2 counts one twice; the test covers both sides of 1 and the u64 ends.
@pytest.mark.parametrize("weight", [0, 2, 3, 2**64 - 1])
def test_a_genesis_grandpa_voter_of_weight_other_than_one_is_refused(seated, meta, weight):
    spec, members, launch = seated
    keys = [gran for _, _, gran in members]
    put(spec, "Grandpa", "Authorities", grandpa_list((keys[0], weight), *((key, 1) for key in keys[1:])))
    assert committee_findings(spec, meta, launch) == [
        f"[9 committee] genesis Grandpa.Authorities[0] 0x{keys[0].hex()} has weight {weight}, not the 1 build-spec "
        f"writes: it counts as {weight} voters toward finality"]


def test_a_genesis_grandpa_voter_listed_twice_is_refused(seated, meta):
    spec, members, launch = seated
    keys = [gran for _, _, gran in members]
    put(spec, "Grandpa", "Authorities", grandpa_list(*((key, 1) for key in keys), (keys[2], 1)))
    assert committee_findings(spec, meta, launch) == [
        f"[9 committee] genesis Grandpa.Authorities[4] 0x{keys[2].hex()} is listed before: it counts twice toward "
        "finality"]


def test_an_authority_that_declares_another_grandpa_key_than_genesis_is_refused(seated, meta):
    spec, members, _ = seated
    other = fresh_account()
    declared = [members[0][:2] + (other,), *members[1:]]
    _, aura, gran = members[0]
    assert committee_findings(spec, meta, members_launch(declared)) == [
        f"[9 committee] {COMMITTEE}[0] {pair(aura, gran)} is not a declared authority's aura and grandpa key pair: "
        "the runtime seats it, unchecked, at every rotation whose Cardano draw fails",
        left_out(0, aura, other),
        f"[9 committee] genesis Grandpa.Authorities[0] 0x{gran.hex()} is not a declared authority's grandpa key: who "
        "finalizes is unchecked",
        f"[9 committee] authority val0's grandpa key 0x{other.hex()} is not in genesis Grandpa.Authorities: it does "
        "not vote on finality"]


def test_a_genesis_with_no_grandpa_voters_is_refused(seated, meta):
    spec, _, launch = seated
    del spec.storage[lp.storage_key("Grandpa", "Authorities")]
    assert committee_findings(spec, meta, launch) == [
        "[9 committee] genesis sets no Grandpa.Authorities, which build-spec always writes: who finalizes is "
        "unchecked"]


@pytest.mark.parametrize("raw", [lp.compact(1) + bytes(39), lp.compact(1) + bytes(41), b""])
def test_grandpa_voters_that_do_not_decode_are_an_input_error(seated, meta, raw):
    spec, _, launch = seated
    put(spec, "Grandpa", "Authorities", raw)
    with pytest.raises(lp.InputError, match="Grandpa.Authorities does not decode as a list of 32-byte keys and "
                                            "u64 weights"):
        committee_findings(spec, meta, launch)


def set_id_session_key(set_id: int) -> bytes:
    """Grandpa.SetIdSession's key for a set id: Twox64Concat of the u64."""
    encoded = set_id.to_bytes(8, "little")
    return (lp.storage_key("Grandpa", "SetIdSession") + xxhash.xxh64(encoded, seed=0).intdigest().to_bytes(8, "little")
            + encoded)


def test_build_spec_starts_grandpa_at_set_0_in_session_0(spec, spec240):
    """What pallet_grandpa's genesis writes in both preprod genesis: the set id 0 as a u64, and the one SetIdSession
    entry, set 0 beginning in session 0 (a u32)."""
    prefix = lp.storage_key("Grandpa", "SetIdSession")
    for genesis in (spec, spec240[0]):
        assert genesis.value("Grandpa", "CurrentSetId") == bytes(8)
        assert {key: value for key, value in genesis.storage.items() if key.startswith(prefix)} == {
            set_id_session_key(0): bytes(4)}


def other_set_id(set_id: int) -> str:
    return (f"[9 committee] genesis Grandpa.CurrentSetId is {set_id}, not the 0 build-spec writes: every GRANDPA "
            "client starts the genesis authority set at set id 0, and a node that warp- or state-syncs takes the "
            "runtime's instead, so it holds another set id than the one its peers sign votes and justifications "
            "under")


OTHER_SET_ID_SESSION = ("[9 committee] genesis Grandpa.SetIdSession is not the one entry build-spec writes, set 0 "
                        "beginning in session 0: the GRANDPA set history it holds is unchecked")


# The red team's PoC: genesis CurrentSetId u64::MAX passed every rule, and an offline node answers
# GrandpaApi_current_set_id with it at genesis while sc-consensus-grandpa starts the genesis set at 0.
@pytest.mark.parametrize("set_id", [1, 2**64 - 1])
def test_a_genesis_grandpa_set_id_other_than_0_is_refused(seated, meta, set_id):
    spec, _, launch = seated
    put(spec, "Grandpa", "CurrentSetId", set_id.to_bytes(8, "little"))
    assert committee_findings(spec, meta, launch) == [other_set_id(set_id)]


def test_a_genesis_that_sets_no_grandpa_set_id_passes(seated, meta):
    """The runtime reads an absent CurrentSetId as its default, 0."""
    spec, _, launch = seated
    del spec.storage[lp.storage_key("Grandpa", "CurrentSetId")]
    assert committee_findings(spec, meta, launch) == []


@A_BYTE_OFF
def test_a_grandpa_set_id_stored_at_another_width_is_an_input_error(seated, meta, change):
    spec, _, launch = seated
    put(spec, "Grandpa", "CurrentSetId", bytes(8 + change))
    with pytest.raises(lp.InputError, match="^" + re.escape(mis_sized("Grandpa.CurrentSetId", 8 + change, 8))):
        committee_findings(spec, meta, launch)


@pytest.mark.parametrize("entries", [
    {set_id_session_key(0): (1).to_bytes(4, "little")},
    {set_id_session_key(0): bytes(4), set_id_session_key(1): (5).to_bytes(4, "little")},
    {set_id_session_key(1): bytes(4)},
    {},
    {set_id_session_key(0): bytes(5)},
    {set_id_session_key(0)[:-1]: bytes(4)},
], ids=["set 0 in session 1", "a later set", "set 1 only", "none", "a long session index", "a short key"])
def test_a_genesis_grandpa_set_history_other_than_build_specs_is_refused(seated, meta, entries):
    spec, _, launch = seated
    prefix = lp.storage_key("Grandpa", "SetIdSession")
    for key in [key for key in spec.storage if key.startswith(prefix)]:
        del spec.storage[key]
    spec.storage.update(entries)
    assert committee_findings(spec, meta, launch) == [OTHER_SET_ID_SESSION]


@pytest.mark.parametrize("kind", ["aura", "grandpa"])
def test_two_authorities_that_declare_one_key_are_refused(seated, meta, kind):
    spec, members, launch = seated
    launch["nodes"][1][kind] = launch["nodes"][0][kind]
    found = committee_findings(spec, meta, launch)
    assert f"[9 committee] authority val1 declares the {kind} key authority val0 declares: two nodes that sign with " \
           "one key equivocate" in found


# build-spec's session genesis writes each member under its cross-chain key's account. The preprod builder's
# session.initialValidators, which names each by its aura key, is not what a seated committee writes.
def test_session_validators_that_are_not_the_genesis_committee_are_refused(seated, meta):
    spec, members, launch = seated
    put(spec, "Session", "ValidatorsAndKeys",
        lp.compact(4) + b"".join(aura + aura + gran for _, aura, gran in members))
    assert committee_findings(spec, meta, launch) == [NOT_THE_SESSION]


@pytest.mark.parametrize("value", [None, b"\0", "reordered"], ids=["absent", "empty", "reordered"])
def test_session_validators_other_than_the_committee_in_its_order_are_refused(seated, meta, value):
    spec, members, launch = seated
    key = lp.storage_key("Session", "ValidatorsAndKeys")
    if value is None:
        del spec.storage[key]
    else:
        spec.storage[key] = session_value(members[::-1]) if value == "reordered" else value
    assert committee_findings(spec, meta, launch) == [NOT_THE_SESSION]


@pytest.mark.parametrize("item, value", [
    ("QueuedKeys", lp.compact(1) + bytes(32) + bytes(64)),
    ("Validators", lp.compact(1) + bytes(32)),
    ("Validators", b"\0\0"),
])
def test_a_genesis_that_fills_the_pallet_session_stub_is_refused(seated, meta, item, value):
    spec, _, launch = seated
    put(spec, "PalletSession", item, value)
    assert committee_findings(spec, meta, launch) == [
        f"[9 committee] genesis PalletSession.{item} is 0x{value.hex()}, not the empty list build-spec writes: the "
        "session keys it holds are unchecked"]


def test_a_genesis_that_leaves_out_the_pallet_session_stub_passes(seated, meta):
    spec, _, launch = seated
    for item in ("QueuedKeys", "Validators"):
        del spec.storage[lp.storage_key("PalletSession", item)]
    assert committee_findings(spec, meta, launch) == []


# ---------------------------------------------------------------------------
# Rule 9: how long each session lasts
# ---------------------------------------------------------------------------

PREPROD_SLOTS_PER_EPOCH = 600


def session_findings(spec: lp.Spec, meta: lp.Metadata, slots=None, declared=PREPROD_SLOTS_PER_EPOCH) -> list[str]:
    """Rule 9's session check with genesis storing `slots` per epoch, unless the test leaves the preprod value, and
    the launch declaring `declared`, or nothing for None."""
    if slots is not None:
        put(spec, "Sidechain", "SlotsPerEpoch", slots.to_bytes(4, "little"))
    return messages(lp.check_sessions(spec, meta, {} if declared is None else {"slots_per_epoch": declared}))


def not_dividing(slots: int) -> str:
    return (f"[9 committee] genesis Sidechain.SlotsPerEpoch {slots}: a session of {slots} slots of 6000 ms does not "
            "divide Cardano's 432000000 ms epoch, as partner-chains' sidechain-slots requires: a session longer than "
            "a Cardano epoch skips the committees Cardano holds for the epochs it spans, and the node cannot draw "
            "block 1's committee in a session that began before Cardano's first epoch")


ZERO_SLOTS = ("[9 committee] genesis Sidechain.SlotsPerEpoch is 0: the runtime divides each block's slot by it as it "
              "initializes the block, so block 1 traps and the chain never authors a block")


@pytest.mark.parametrize("slots", [1, 60, PREPROD_SLOTS_PER_EPOCH, 72_000])
def test_a_declared_session_that_divides_cardanos_epoch_passes(spec, meta, slots):
    assert session_findings(spec, meta, slots, slots) == []


# The red team's PoC: the runtime's Sidechain::on_initialize divides by genesis SlotsPerEpoch in every block, and the
# node's slot config reads the same storage.
def test_a_genesis_of_zero_slots_per_epoch_is_refused(spec, meta):
    assert session_findings(spec, meta, 0, 0) == [ZERO_SLOTS]


# 700 slots divides no Cardano epoch; 144,000 is two of them; the node's Ariadne data provider fails block 1 at every
# slot once a session is long enough to have begun before Cardano's first epoch, as u32::MAX slots is.
@pytest.mark.parametrize("slots", [700, 144_000, 2**32 - 1])
def test_a_session_that_does_not_divide_cardanos_epoch_is_refused(spec, meta, slots):
    assert session_findings(spec, meta, slots, slots) == [not_dividing(slots)]


def test_a_genesis_session_other_than_the_declared_one_is_refused(spec, meta):
    assert session_findings(spec, meta, 60) == [
        "[9 committee] genesis Sidechain.SlotsPerEpoch is 60, not the 600 the launch declares: each session, and "
        "each committee, lasts another length than the one signed"]


def test_an_undeclared_session_length_is_refused(spec, meta):
    assert session_findings(spec, meta, declared=None) == [
        "[9 committee] the launch declares no slots_per_epoch: how long each session, and each committee, lasts is "
        "unchecked"]


def test_a_genesis_that_sets_no_session_length_is_refused(spec, meta):
    del spec.storage[lp.storage_key("Sidechain", "SlotsPerEpoch")]
    assert session_findings(spec, meta) == [
        "[9 committee] genesis sets no Sidechain.SlotsPerEpoch, which build-spec always writes: the runtime reads "
        "partner-chains' default of 60 slots"]


@A_BYTE_OFF
def test_a_session_length_stored_at_another_width_is_an_input_error(spec, meta, change):
    put(spec, "Sidechain", "SlotsPerEpoch", PREPROD_SLOTS_PER_EPOCH.to_bytes(4 + change, "little"))
    with pytest.raises(lp.InputError, match="^" + re.escape(mis_sized("Sidechain.SlotsPerEpoch", 4 + change, 4))):
        session_findings(spec, meta)


@pytest.mark.parametrize("value", [None, bytes(4), bytes(8)], ids=["absent", "4 bytes", "zero"])
def test_a_session_under_a_runtime_that_hides_its_slot_duration_is_refused(spec, meta, value):
    if value is None:
        del meta.constants[("Aura", "SlotDuration")]
    else:
        meta.constants[("Aura", "SlotDuration")] = value
    assert session_findings(spec, meta) == [
        "[9 committee] the runtime metadata declares no Aura.SlotDuration above 0 the preflight can read: whether a "
        "session divides Cardano's epoch is unknown here"]


@pytest.mark.parametrize("value", ["600", 600.0, True, -1, 2**32], ids=["a string", "a float", "a bool", "negative",
                                                                        "past u32"])
def test_a_session_length_that_is_not_a_u32_is_an_input_error(value):
    with pytest.raises(lp.InputError, match="^slots_per_epoch must be a u32"):
        lp.validate_launch({"roles": {}, "supply": VALID_LOCK, "slots_per_epoch": value})


# ---------------------------------------------------------------------------
# Rule 9: the Cardano settings every authority's follower shares
# ---------------------------------------------------------------------------

# Cardano mainnet's Shelley-era layout (epoch 208 from slot 4,492,800 at 2020-07-29T21:44:51Z, 432,000 one-second
# slots an epoch) and its shelley-genesis.json securityParam and activeSlotsCoeff, as the node's follower reads them.
MAINNET_FOLLOWER = {
    "MC__FIRST_EPOCH_TIMESTAMP_MILLIS": "1596059091000", "MC__EPOCH_DURATION_MILLIS": "432000000",
    "MC__FIRST_EPOCH_NUMBER": "208", "MC__FIRST_SLOT_NUMBER": "4492800", "MC__SLOT_DURATION_MILLIS": "1000",
    "CARDANO_SECURITY_PARAMETER": "2160", "CARDANO_ACTIVE_SLOTS_COEFF": "0.05",
}
NO_FOLLOWER = ("[9 committee] the launch declares no cardano_follower, the Cardano settings every authority's "
               "follower must share: the preflight holds each authority to Cardano mainnet's")
FOLLOWER_DIVERGES = ("a node derives Cardano's epochs and slots, and which Cardano blocks are stable, from these "
                     "settings, so one whose settings differ from its peers' draws another committee or judges "
                     "another Cardano block stable, and refuses the committee changes and blocks they make")


def follower_node(name: str = "val1", env: dict = MAINNET_FOLLOWER, script: str | None = None) -> dict:
    """An authority whose unit gives it `env`, and that runs its node directly or through `bash --norc -c script`."""
    argv = ["materios-node", "--validator"] if script is None else ["bash", "--norc", "-c", script]
    return dict(authority(argv, name, name), env=dict(env))


def follower_findings(*nodes, declared=MAINNET_FOLLOWER) -> list[str]:
    launch = {"nodes": list(nodes)}
    if declared is not None:
        launch["cardano_follower"] = dict(declared)
    return messages(lp.check_follower(launch))


def not_mainnets(name: str, value: str) -> str:
    return (f"[9 committee] cardano_follower sets {name} to {value!r}, not Cardano mainnet's "
            f"{MAINNET_FOLLOWER[name]!r}: the node derives Cardano's epochs and slots, and which Cardano blocks are "
            "stable, from these settings, so on any other it asks Cardano for another epoch's committee, or none, "
            "and cites Cardano blocks its peers on Cardano's own settings refuse")


def not_set(node: str, name: str, value: str) -> str:
    return (f"[9 committee] authority {node} does not set {name}, which every authority sets to the {value!r} the "
            f"launch declares: {FOLLOWER_DIVERGES}")


def sets_other(node: str, word: str, name: str, value: str) -> str:
    return (f"[9 committee] authority {node} sets {word!r}, not the {value!r} the launch declares for {name}: "
            f"{FOLLOWER_DIVERGES}")


def test_authorities_on_cardano_mainnets_follower_settings_pass():
    exports = "; ".join(f"export {name}={value}" for name, value in MAINNET_FOLLOWER.items())
    prefixed = " ".join(f"{name}={value}" for name, value in MAINNET_FOLLOWER.items())
    nodes = [follower_node("val0"), follower_node("val1", {}, f"set -e; {exports}; exec materios-node --validator"),
             follower_node("val2", {}, f"{prefixed} exec materios-node --validator"),
             follower_node("val3", script="export MC__FIRST_EPOCH_NUMBER; exec materios-node --validator"),
             dict(follower_node("edge", {}), authority=False)]
    assert follower_findings(*nodes) == []


def test_a_launch_that_declares_no_cardano_follower_is_refused():
    assert follower_findings(follower_node(), declared=None) == [NO_FOLLOWER]


def test_a_launch_that_declares_no_cardano_follower_holds_its_authorities_to_cardano_mainnets():
    node = follower_node(env=dict(MAINNET_FOLLOWER, CARDANO_SECURITY_PARAMETER="432"))
    assert follower_findings(node, declared=None) == [
        NO_FOLLOWER, sets_other("val1", "CARDANO_SECURITY_PARAMETER=432", "CARDANO_SECURITY_PARAMETER", "2160")]


# The red team's provider test: preprod's layout asks for an epoch the mainnet follower has no data for, a first epoch
# in 2030 never authors (TimestampTooSmall), an epoch length of 0 panics (division by zero), one-day epochs read no
# committee data. k and f set how deep and how old a cited Cardano block must be. Each value is held in the one
# spelling Cardano's own is written in.
OTHER_FOLLOWER_SETTINGS = {
    "preprod's first epoch": ("MC__FIRST_EPOCH_TIMESTAMP_MILLIS", "1655769600000"),
    "a first epoch in 2030": ("MC__FIRST_EPOCH_TIMESTAMP_MILLIS", "1893456000000"),
    "epochs of 0 ms": ("MC__EPOCH_DURATION_MILLIS", "0"),
    "one-day epochs": ("MC__EPOCH_DURATION_MILLIS", "86400000"),
    "another first epoch": ("MC__FIRST_EPOCH_NUMBER", "4"),
    "another first slot": ("MC__FIRST_SLOT_NUMBER", "86400"),
    "2-second slots": ("MC__SLOT_DURATION_MILLIS", "2000"),
    "k of 2161": ("CARDANO_SECURITY_PARAMETER", "2161"),
    "preprod's k": ("CARDANO_SECURITY_PARAMETER", "432"),
    "f of 0.1": ("CARDANO_ACTIVE_SLOTS_COEFF", "0.1"),
    "a leading zero": ("MC__FIRST_EPOCH_NUMBER", "0208"),
    "a plus sign": ("MC__FIRST_EPOCH_NUMBER", "+208"),
    "a trailing space": ("MC__FIRST_EPOCH_NUMBER", "208 "),
    "f in exponent form": ("CARDANO_ACTIVE_SLOTS_COEFF", "5e-2"),
    "f with a trailing zero": ("CARDANO_ACTIVE_SLOTS_COEFF", "0.050"),
}


@pytest.mark.parametrize("name, value", OTHER_FOLLOWER_SETTINGS.values(), ids=OTHER_FOLLOWER_SETTINGS)
def test_a_declared_follower_setting_other_than_cardano_mainnets_is_refused(name, value):
    declared = dict(MAINNET_FOLLOWER, **{name: value})
    assert follower_findings(follower_node(env=declared), declared=declared) == [not_mainnets(name, value)]


@pytest.mark.parametrize("name", MAINNET_FOLLOWER)
def test_an_authority_that_does_not_set_a_follower_setting_is_refused(name):
    env = {key: value for key, value in MAINNET_FOLLOWER.items() if key != name}
    assert follower_findings(follower_node(env=env)) == [not_set("val1", name, MAINNET_FOLLOWER[name])]


# Each way an authority's launch hands its node a setting: its unit's env, an assignment before the node, an export or
# a bare assignment in its script, an append, and an assignment before a nested shell, which its node inherits; and
# spellings the node reads as the same number, held to the declared one.
OTHER_EPOCH = {
    "env": ({"MC__FIRST_EPOCH_NUMBER": "209"}, None, "MC__FIRST_EPOCH_NUMBER=209"),
    "before the node": ({}, "MC__FIRST_EPOCH_NUMBER=209 exec materios-node --validator", "MC__FIRST_EPOCH_NUMBER=209"),
    "an export": ({}, "export MC__FIRST_EPOCH_NUMBER=209; exec materios-node --validator",
                  "MC__FIRST_EPOCH_NUMBER=209"),
    "a bare assignment": ({}, "MC__FIRST_EPOCH_NUMBER=209; exec materios-node --validator",
                          "MC__FIRST_EPOCH_NUMBER=209"),
    "an append": ({}, "MC__FIRST_EPOCH_NUMBER+=9; exec materios-node --validator", "MC__FIRST_EPOCH_NUMBER+=9"),
    "before a nested shell": ({}, "MC__FIRST_EPOCH_NUMBER=209 exec bash --norc -c 'exec materios-node --validator'",
                              "MC__FIRST_EPOCH_NUMBER=209"),
    "a leading zero": ({"MC__FIRST_EPOCH_NUMBER": "0208"}, None, "MC__FIRST_EPOCH_NUMBER=0208"),
    "a plus sign": ({"MC__FIRST_EPOCH_NUMBER": "+208"}, None, "MC__FIRST_EPOCH_NUMBER=+208"),
    "a trailing space": ({"MC__FIRST_EPOCH_NUMBER": "208 "}, None, "MC__FIRST_EPOCH_NUMBER=208 "),
}


@pytest.mark.parametrize("env, script, word", OTHER_EPOCH.values(), ids=OTHER_EPOCH)
def test_an_authority_follower_setting_other_than_the_declared_one_is_refused(env, script, word):
    node = follower_node(env=dict(MAINNET_FOLLOWER, **env), script=script)
    assert follower_findings(node) == [sets_other("val1", word, "MC__FIRST_EPOCH_NUMBER", "208")]


# The spec-239 red team's one new liveness risk: authorities on a mixed Cardano epoch configuration, where the
# divergent node refuses an honest committee change.
def test_an_authority_whose_follower_differs_from_its_peers_is_refused():
    nodes = [follower_node("val0"), follower_node("val1"),
             follower_node("val2", dict(MAINNET_FOLLOWER, MC__EPOCH_DURATION_MILLIS="86400000"))]
    assert follower_findings(*nodes) == [
        sets_other("val2", "MC__EPOCH_DURATION_MILLIS=86400000", "MC__EPOCH_DURATION_MILLIS", "432000000")]


def test_authorities_are_held_to_the_declared_settings_even_where_those_are_not_cardano_mainnets():
    declared = dict(MAINNET_FOLLOWER, CARDANO_SECURITY_PARAMETER="432")
    assert follower_findings(follower_node(), declared=declared) == [
        not_mainnets("CARDANO_SECURITY_PARAMETER", "432"),
        sets_other("val1", "CARDANO_SECURITY_PARAMETER=2160", "CARDANO_SECURITY_PARAMETER", "432")]


@pytest.mark.parametrize("follower", [
    [], "MC__FIRST_EPOCH_NUMBER=208", {k: v for k, v in MAINNET_FOLLOWER.items() if k != "MC__FIRST_SLOT_NUMBER"},
    dict(MAINNET_FOLLOWER, BLOCK_STABILITY_MARGIN="0"), dict(MAINNET_FOLLOWER, MC__FIRST_EPOCH_NUMBER=208),
], ids=["a list", "a string", "a setting missing", "another setting", "a number"])
def test_a_cardano_follower_that_is_not_the_settings_as_strings_is_an_input_error(follower):
    with pytest.raises(lp.InputError, match="^cardano_follower must map exactly MC__FIRST_EPOCH_TIMESTAMP_MILLIS, "):
        lp.validate_launch({"roles": {}, "supply": VALID_LOCK, "cardano_follower": follower})


# ---------------------------------------------------------------------------
# Rule 9: the committee Cardano draws
# ---------------------------------------------------------------------------

def cardano_findings(spec: lp.Spec, launch: dict, cardano: lp.CardanoView) -> list[str]:
    return messages(lp.check_candidate_authorities(launch, cardano))


def genesis_authors_on_cardano(spec: lp.Spec, grans=None) -> lp.CardanoView:
    """The authors genesis names as Cardano's permissioned candidates, each with the genesis GRANDPA key at its
    index unless the test gives other gran keys."""
    grans = grandpa_keys(spec) if grans is None else grans
    return lp.CardanoView(lock=None, candidates=[candidate(aura, gran) for aura, gran in zip(aura_keys(spec), grans)],
                          d_parameter=(len(grans), 0))


def voter_launch(spec: lp.Spec) -> dict:
    return members_launch(genesis_members(spec))


def test_cardano_candidates_that_vote_with_their_authorities_grandpa_keys_pass(spec):
    assert cardano_findings(spec, voter_launch(spec), genesis_authors_on_cardano(spec)) == []


# The red team's PoC: the committee Cardano seats votes with the candidates' gran keys, and an outsider's key in one of
# them finalized unchecked.
def test_a_cardano_candidate_whose_gran_key_is_not_its_authoritys_grandpa_key_is_refused(spec):
    keys, outsider = grandpa_keys(spec), fresh_account()
    cardano = genesis_authors_on_cardano(spec, [outsider, *keys[1:]])
    assert cardano_findings(spec, voter_launch(spec), cardano) == [
        f"[9 committee] Cardano permissioned candidate 0 gran 0x{outsider.hex()} is not the grandpa key authority val0 "
        "declares with its aura key: once the committee is drawn from Cardano it votes on finality unchecked"]


# Each candidate's key must be its own authority's: one authority's key on two candidates would count twice.
def test_a_cardano_candidate_that_carries_another_authoritys_grandpa_key_is_refused(spec):
    keys = grandpa_keys(spec)
    cardano = genesis_authors_on_cardano(spec, [keys[1], keys[0], *keys[2:]])
    assert cardano_findings(spec, voter_launch(spec), cardano) == [
        f"[9 committee] Cardano permissioned candidate {i} gran 0x{keys[1 - i].hex()} is not the grandpa key authority "
        f"val{i} declares with its aura key: once the committee is drawn from Cardano it votes on finality unchecked"
        for i in (0, 1)]


# Rule 3 refuses a candidate whose aura key no authority declares; it has no declared grandpa key to hold here.
def test_a_cardano_candidate_no_authority_declares_is_left_to_rule_3(spec):
    view = genesis_authors_on_cardano(spec)
    cardano = dataclasses.replace(view, candidates=[*view.candidates, candidate(fresh_account())])
    assert cardano_findings(spec, voter_launch(spec), cardano) == []


def off_cardano(name: str, aura: bytes) -> str:
    return (f"[9 committee] authority {name}'s aura key 0x{aura.hex()} is on no Cardano permissioned candidate: every "
            "committee drawn from Cardano leaves it out, so it stops authoring and voting at the first draw, and the "
            "committee is smaller than the launch declares")


# The red team's PoC: a datum naming 2 of the 4 declared authorities, with a D-parameter of (2, 0), passed. Ariadne
# seats every candidate when all fit, and the live-quorum floor's quorum for 2 is 2, so the first draw seats a
# committee of 2 that tolerates no fault.
@pytest.mark.parametrize("kept", [2, 3, 0])
def test_a_cardano_datum_that_leaves_out_a_declared_authority_is_refused(spec, kept):
    view = genesis_authors_on_cardano(spec)
    cardano = lp.CardanoView(lock=None, candidates=view.candidates[:kept], d_parameter=(kept, 0))
    assert cardano_findings(spec, voter_launch(spec), cardano) == [
        off_cardano(f"val{i}", aura) for i, aura in enumerate(aura_keys(spec)) if i >= kept]


def test_an_authority_whose_aura_key_is_only_a_candidates_gran_key_is_left_out(spec):
    auras = aura_keys(spec)
    view = genesis_authors_on_cardano(spec, [auras[3], *grandpa_keys(spec)[1:3]])
    cardano = lp.CardanoView(lock=None, candidates=view.candidates, d_parameter=(3, 0))
    assert cardano_findings(spec, voter_launch(spec), cardano) == [
        f"[9 committee] Cardano permissioned candidate 0 gran 0x{auras[3].hex()} is not the grandpa key authority val0 "
        "declares with its aura key: once the committee is drawn from Cardano it votes on finality unchecked",
        off_cardano("val3", auras[3])]


def draw_findings(meta: lp.Metadata, candidates: list[lp.Candidate], d_parameter=None) -> list[str]:
    """What rule 9 finds in a candidates datum, and a D-parameter of one permissioned seat per candidate unless the
    test gives one."""
    view = lp.CardanoView(lock=None, candidates=candidates, d_parameter=d_parameter or (len(candidates), 0))
    return messages(lp.check_cardano_committee(meta, view))


def fresh_candidates(count: int) -> list[lp.Candidate]:
    return [candidate(fresh_account()) for _ in range(count)]


NO_DRAW = "fewer than the 2 it draws a committee from, so every rotation seats the genesis committee again"


def test_candidates_each_seated_by_the_d_parameter_pass(meta):
    assert draw_findings(meta, fresh_candidates(4)) == []


@pytest.mark.parametrize("seats", [5, 32], ids=["a spare seat", "MaxValidators"])
def test_a_d_parameter_with_permissioned_seats_to_spare_passes(meta, seats):
    assert draw_findings(meta, fresh_candidates(4), (seats, 0)) == []


# The red team's PoC: one candidate, so Ariadne selects fewer than two distinct validators and returns none, and the
# runtime re-seats the genesis committee at every rotation.
@pytest.mark.parametrize("count", [0, 1])
def test_a_datum_the_runtime_draws_no_committee_from_is_refused(meta, count):
    assert draw_findings(meta, fresh_candidates(count)) == [
        f"[9 committee] the permissioned candidates datum holds {count} candidate{'s' * (count != 1)} the runtime can "
        f"seat, {NO_DRAW}"]


# The red team's PoC: partner chains keys of 32 bytes, which Ariadne filters out, leaving no candidate to draw.
def test_candidates_ariadne_drops_are_refused(meta):
    candidates = [lp.Candidate(fresh_account(), c.aura, c.gran) for c in fresh_candidates(4)]
    assert draw_findings(meta, candidates) == [
        f"[9 committee] Cardano permissioned candidate {i} has a 32-byte partner chains key, not 33 bytes: Ariadne "
        "drops it" for i in range(4)] + [
        f"[9 committee] the permissioned candidates datum holds 0 candidates the runtime can seat, {NO_DRAW}"]


@pytest.mark.parametrize("field, size, width, name", [
    ("partner_chains_key", 34, 33, "partner chains key"),
    ("aura", 31, 32, "aura key"),
    ("gran", 33, 32, "gran key"),
])
def test_a_candidate_with_a_key_of_another_length_is_refused(meta, field, size, width, name):
    candidates = fresh_candidates(3)
    candidates[1] = dataclasses.replace(candidates[1], **{field: bytes([2]) * size})
    assert draw_findings(meta, candidates) == [
        f"[9 committee] Cardano permissioned candidate 1 has a {size}-byte {name}, not {width} bytes: Ariadne drops "
        "it"]


# The runtime's input sanitizer keeps the first of candidates that share any key.
@pytest.mark.parametrize("field, name", [("partner_chains_key", "partner chains key"), ("aura", "aura key"),
                                         ("gran", "gran key")])
def test_a_candidate_that_repeats_a_key_is_refused(meta, field, name):
    candidates = fresh_candidates(3)
    candidates.append(dataclasses.replace(fresh_candidates(1)[0], **{field: getattr(candidates[0], field)}))
    assert draw_findings(meta, candidates, (4, 0)) == [
        f"[9 committee] Cardano permissioned candidate 3 repeats candidate 0's {name}: the runtime keeps the first and "
        "drops it"]


def test_a_datum_that_repeats_its_only_other_candidate_draws_no_committee(meta):
    only = fresh_candidates(1)[0]
    assert draw_findings(meta, [only, only]) == [
        f"[9 committee] Cardano permissioned candidate 1 repeats candidate 0's {name}: the runtime keeps the first and "
        "drops it" for name in ("partner chains key", "aura key", "gran key")] + [
        f"[9 committee] the permissioned candidates datum holds 1 candidate the runtime can seat, {NO_DRAW}"]


def test_a_d_parameter_that_seats_registered_candidates_is_refused(meta):
    assert draw_findings(meta, fresh_candidates(4), (4, 2)) == [
        "[9 committee] the D-parameter seats 2 registered candidates: a Cardano stake pool that registers joins the "
        "committee, and the preflight reads no registration"]


# The red team's PoC: one permissioned seat for three candidates, so the draw seats one and no committee is drawn.
@pytest.mark.parametrize("seats", [0, 1, 2])
def test_a_d_parameter_that_seats_fewer_than_the_candidates_is_refused(meta, seats):
    assert draw_findings(meta, fresh_candidates(3), (seats, 0)) == [
        f"[9 committee] the D-parameter seats {seats} permissioned candidate{'s' * (seats != 1)}, fewer than the 3 the "
        "datum holds: Ariadne draws the seats at random, with repeats, so a declared authority can be left out and a "
        "draw can fall below two members"]


def test_a_d_parameter_over_max_validators_is_refused(meta):
    assert draw_findings(meta, fresh_candidates(4), (33, 0)) == [
        "[9 committee] the D-parameter seats 33 permissioned candidates, more than the 32 members a committee holds "
        "(SessionCommitteeManagement.MaxValidators): the runtime refuses a whole draw past a cap of its own that its "
        "metadata does not declare, so the preflight holds the D-parameter to what a committee holds"]


# A runtime that hides MaxValidators is refused once, by the genesis committee check.
def test_the_d_parameter_is_not_bounded_under_a_runtime_that_hides_max_validators(meta):
    del meta.constants[("SessionCommitteeManagement", "MaxValidators")]
    assert draw_findings(meta, fresh_candidates(4), (33, 0)) == []


@pytest.mark.parametrize("raw, want", [
    (d_parameter_datum(4, 0), (4, 0)),
    (cbor2.dumps([7, 1]), (7, 1)),
    (d_parameter_datum(65535, 65535), (65535, 65535)),
], ids=["version 0", "legacy", "u16 maxima"])
def test_d_parameter_datums_decode_in_every_format_the_node_reads(raw, want):
    assert lp.decode_d_parameter(raw) == want


@pytest.mark.parametrize("raw", [
    b"\xff",
    versioned_datum([4, 0], 1),
    cbor2.dumps([4]),
    cbor2.dumps([4, 0, 0]),
    d_parameter_datum(-1, 0),
    d_parameter_datum(65536, 0),
    d_parameter_datum(True, 0),
    cbor2.dumps([cbor2.CBORTag(121, []), [4, 0], True]),
    cbor2.dumps([b"\x04", 0]),
], ids=["not CBOR", "version 1", "one number", "three numbers", "negative", "past u16", "a boolean",
        "a boolean version", "bytes"])
def test_undecodable_d_parameter_datum_is_an_input_error(raw):
    with pytest.raises(lp.InputError, match="the D-parameter datum"):
        lp.decode_d_parameter(raw)


@pytest.mark.parametrize("grandpa", [None, "0x" + "ab" * 31, "not a key"])
def test_an_authority_must_declare_its_grandpa_key(grandpa):
    node = {k: v for k, v in authority(["materios-node"]).items() if k != "grandpa"}
    if grandpa is not None:
        node["grandpa"] = grandpa
    with pytest.raises(lp.InputError, match="nodes\\[0\\] is an authority and must declare its grandpa public key"):
        lp.validate_node(node, "nodes[0]")


# An authority's node process argv, as the kernel holds it: each word ended by a NUL, as `cat /proc/<pid>/cmdline`
# saves it.
def capture(tmp_path: Path, name: str, argv: list[str]) -> str:
    path = tmp_path / f"{name}.cmdline"
    path.write_bytes(b"".join(word.encode() + b"\0" for word in argv))
    return str(path)


def rpc_launch(nodes) -> dict:
    launch = {"roles": {}, "supply": VALID_LOCK, "nodes": nodes, "rpc_proxies": []}
    lp.validate_launch(launch)
    return launch


def test_an_authority_is_checked_with_the_argv_its_running_node_process_has(tmp_path):
    argv = ["/usr/local/bin/materios-node", "--validator", "--rpc-methods", "unsafe", "--unsafe-rpc-external"]
    node = dict(authority(argv), cmdline=capture(tmp_path, "val1", argv))
    assert messages(lp.check_rpc(rpc_launch([node]), [])) == [
        "[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


def test_a_shell_wrapped_authority_is_checked_with_its_running_node_process(tmp_path):
    node = dict(authority(["sh", "-c", "exec " + UNSAFE_EXTERNAL]),
                cmdline=capture(tmp_path, "val1", UNSAFE_EXTERNAL.split()))
    assert messages(lp.check_rpc(rpc_launch([node]), [])) == [
        "[3 rpc] authority val1 serves unsafe RPC methods on an external listener"]


def test_an_authority_with_no_captured_cmdline_is_an_input_error():
    launch = rpc_launch([authority(["materios-node", "--validator", "--rpc-methods", "safe"])])
    with pytest.raises(lp.InputError, match="authority val1: give its running node process's /proc/<pid>/cmdline"):
        lp.check_rpc(launch, [])


# Whatever the launch's reading gets wrong, the node runs with the argv the kernel holds: a process started some
# other way, or a launch the preflight misread, cannot be resolved.
@pytest.mark.parametrize("running, error", [
    (UNSAFE_EXTERNAL.split(), "word 3 of its running node process differs from its launch"),
    (SAFE_NODE.split()[1:] + ["--unsafe-rpc-external"], "its running node process has 5 words, its launch gives 4"),
    (["/usr/local/bin/materios-node", *SAFE_NODE.split()[2:]], "word 0 of its running node process differs"),
])
def test_a_running_node_process_that_differs_from_its_launch_is_an_input_error(tmp_path, running, error):
    node = dict(authority(["sh", "-c", SAFE_NODE]), cmdline=capture(tmp_path, "val1", running))
    with pytest.raises(lp.InputError, match=f"authority val1: {error}"):
        lp.check_rpc(rpc_launch([node]), [])


@pytest.mark.parametrize("raw, error", [
    (b"materios-node --validator --rpc-methods safe", "is not a /proc/<pid>/cmdline capture"),
    (b"", "is not a /proc/<pid>/cmdline capture"),
    (b"materios-node\0--name\0\xff\0", "is not UTF-8"),
])
def test_a_cmdline_that_is_not_a_proc_capture_is_an_input_error(tmp_path, raw, error):
    path = tmp_path / "val1.cmdline"
    path.write_bytes(raw)
    node = dict(authority(["materios-node", "--validator", "--rpc-methods", "safe"]), cmdline=str(path))
    with pytest.raises(lp.InputError, match=error):
        lp.check_rpc(rpc_launch([node]), [])


def test_an_unreadable_cmdline_is_an_input_error(tmp_path):
    node = dict(authority(["materios-node"]), cmdline=str(tmp_path / "missing.cmdline"))
    with pytest.raises(lp.InputError, match="cannot read cmdline"):
        lp.check_rpc(rpc_launch([node]), [])


@pytest.mark.parametrize("node, error", [
    ({"name": "edge", "host": "edge", "authority": False, "cmdline": "/proc/1/cmdline"},
     "nodes\\[0\\] cmdline is read for an authority only"),
    (dict(authority(["materios-node"]), cmdline=7), "nodes\\[0\\] cmdline must be the path of a /proc/<pid>/cmdline"),
])
def test_a_misplaced_cmdline_is_an_input_error(node, error):
    with pytest.raises(lp.InputError, match=error):
        lp.validate_node(node, "nodes[0]")


# ---------------------------------------------------------------------------
# Rule 3, live: what each public RPC URL serves
# ---------------------------------------------------------------------------

# The preprod node's rpc_methods answer: a node lists every method it registers, the unsafe ones included, under
# --rpc-methods safe too (sc-rpc-server utils.rs).
NODE_METHODS = json.loads((FIXTURES / "node-rpc-methods.json").read_text())
# The methods whose sc-rpc handler calls check_if_safe, at polkadot-stable2409-4.
UNSAFE_CLASS = {
    # substrate/client/rpc/src/author/mod.rs
    "author_insertKey", "author_rotateKeys", "author_hasKey", "author_hasSessionKeys", "author_removeExtrinsic",
    # substrate/client/rpc/src/system/mod.rs
    "system_peers", "system_unstable_networkState", "system_addReservedPeer", "system_removeReservedPeer",
    "system_addLogFilter", "system_resetLogFilter",
    # substrate/client/rpc/src/offchain/mod.rs
    "offchain_localStorageSet", "offchain_localStorageGet",
    # substrate/client/rpc/src/state/mod.rs
    "state_getPairs", "state_queryStorage", "state_traceBlock",
    # substrate/utils/frame/rpc/system/src/lib.rs
    "system_dryRun", "system_dryRunAt",
}
UNSAFE_REFUSED = {"error": {"code": -32601, "message": "RPC call is unsafe to be called externally"}}
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def test_the_safe_set_is_every_node_method_whose_handler_serves_it_under_safe():
    assert lp.SAFE_RPC_METHODS == set(NODE_METHODS) - UNSAFE_CLASS
    assert UNSAFE_CLASS < set(NODE_METHODS)


# system_peers calls check_if_safe and then only reads the peer list (sc-rpc system/mod.rs).
def test_the_probe_calls_an_unsafe_method_that_only_reads():
    assert lp.UNSAFE_PROBE == "system_peers"


def _ws_frame(stream) -> tuple[int, bytes] | None:
    """(opcode, payload) of one client frame, which RFC 6455 masks."""
    head = stream.read(2)
    if len(head) < 2:
        return None
    size = head[1] & 0x7F
    if size >= 126:
        size = int.from_bytes(stream.read(2 if size == 126 else 8), "big")
    mask = stream.read(4)
    return head[0] & 0x0F, bytes(b ^ mask[i % 4] for i, b in enumerate(stream.read(size)))


def _ws_text(payload: bytes) -> bytes:
    size = len(payload)
    head = bytes([size]) if size < 126 else bytes([126]) + size.to_bytes(2, "big") if size < 65536 \
        else bytes([127]) + size.to_bytes(8, "big")
    return b"\x81" + head + payload


class RpcEndpoint:
    """A local server that answers JSON-RPC over HTTP POST and over a WebSocket at one address, like a node or a
    proxy in front of one. Per transport: the rpc_methods list, and the answer part (result or error) to any other
    method, -32601 when it has none. Unset, it answers like a filter that serves only safe methods."""

    def __init__(self):
        self.methods = {"http": sorted(lp.SAFE_RPC_METHODS), "ws": sorted(lp.SAFE_RPC_METHODS)}
        self.answers = {"http": {}, "ws": {}}
        self.http_status, self.upgrade = 200, True
        # Notifications a WebSocket carries before each answer.
        self.ws_notifications = 0
        self.calls = []
        endpoint = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                call = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                body = json.dumps(endpoint.answer(call, "http")).encode()
                self.send_response(endpoint.http_status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                key = self.headers.get("Sec-WebSocket-Key")
                if not endpoint.upgrade or key is None:
                    self.send_error(403)
                    return
                self.send_response(101)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                accept = base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()
                self.send_header("Sec-WebSocket-Accept", accept)
                self.end_headers()
                while (frame := _ws_frame(self.rfile)) is not None and frame[0] != 8:
                    reply = endpoint.answer(json.loads(frame[1]), "ws")
                    notification = {"jsonrpc": "2.0", "method": "chain_newHead", "params": {"subscription": "s"}}
                    for _ in range(endpoint.ws_notifications):
                        self.wfile.write(_ws_text(json.dumps(notification).encode()))
                    self.wfile.write(_ws_text(json.dumps(reply).encode()))
                self.wfile.write(b"\x88\x00")
                self.close_connection = True

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/rpc"
        self.ws_url = "ws" + self.url[len("http"):]

    def answer(self, call: dict, transport: str) -> dict:
        self.calls.append((transport, call["method"]))
        listed = {"result": {"version": 1, "methods": self.methods[transport]}}
        missing = {"error": {"code": -32601, "message": "Method not found"}}
        default = listed if call["method"] == "rpc_methods" else missing
        return {"jsonrpc": "2.0", "id": call["id"]} | self.answers[transport].get(call["method"], default)

    def run_unsafe_node(self, *transports: str) -> None:
        """What a node run with --rpc-methods unsafe answers."""
        for transport in transports or ("http", "ws"):
            self.methods[transport] = NODE_METHODS
            self.answers[transport] = {"system_peers": {"result": []}}


@pytest.fixture
def endpoint():
    server = RpcEndpoint()
    yield server
    server.server.shutdown()


def public_findings(*urls) -> list[str]:
    launch = {"roles": {}, "supply": VALID_LOCK, "public_rpc": list(urls)}
    lp.validate_launch(launch)
    return messages(lp.check_public_rpc(launch))


def test_a_public_endpoint_that_lists_only_safe_methods_and_refuses_an_unsafe_one_passes(endpoint):
    assert public_findings(endpoint.url) == []
    assert endpoint.calls == [("http", "rpc_methods"), ("http", "system_peers"),
                              ("ws", "rpc_methods"), ("ws", "system_peers")]


def test_a_websocket_url_is_probed_over_http_too(endpoint):
    assert public_findings(endpoint.ws_url) == []
    assert {transport for transport, _ in endpoint.calls} == {"http", "ws"}


def test_a_public_endpoint_in_front_of_an_unsafe_node_is_refused(endpoint):
    endpoint.run_unsafe_node()
    unsafe = ", ".join(sorted(UNSAFE_CLASS))
    assert public_findings(endpoint.url) == [
        f"[3 rpc] public RPC {endpoint.url} lists methods outside the safe set: {unsafe}",
        f"[3 rpc] public RPC {endpoint.url} answers system_peers, which a node serves only with unsafe methods on",
        f"[3 rpc] public RPC {endpoint.ws_url} lists methods outside the safe set: {unsafe}",
        f"[3 rpc] public RPC {endpoint.ws_url} answers system_peers, which a node serves only with unsafe methods on"]


# A node run with --rpc-methods safe refuses each unsafe call but lists every unsafe method.
def test_a_safe_node_behind_a_public_url_lists_its_unsafe_methods(endpoint):
    for transport in ("http", "ws"):
        endpoint.methods[transport] = NODE_METHODS
        endpoint.answers[transport] = {"system_peers": UNSAFE_REFUSED}
    found = public_findings(endpoint.url)
    assert [f.split(" lists ")[0] for f in found] == [f"[3 rpc] public RPC {endpoint.url}",
                                                      f"[3 rpc] public RPC {endpoint.ws_url}"]


# A proxy can send the WebSocket upgrade somewhere other than the HTTP calls.
def test_a_websocket_route_to_an_unsafe_node_behind_a_filtered_http_route_is_refused(endpoint):
    endpoint.run_unsafe_node("ws")
    found = public_findings(endpoint.url)
    assert found and all(f.startswith(f"[3 rpc] public RPC {endpoint.ws_url} ") for f in found)


def test_an_endpoint_that_lists_a_method_no_node_has_is_refused(endpoint):
    endpoint.methods["http"] = [*endpoint.methods["http"], "debug_dumpKeystore"]
    assert public_findings(endpoint.url) == [
        f"[3 rpc] public RPC {endpoint.url} lists methods outside the safe set: debug_dumpKeystore"]


def test_every_public_rpc_url_must_be_declared():
    assert messages(lp.check_public_rpc({"roles": {}})) == [
        "[3 rpc] public_rpc is not declared: the public RPC endpoints go unprobed; list every public RPC URL, "
        "or [] when the launch serves none"]
    assert messages(lp.check_public_rpc({"public_rpc": []})) == []


@pytest.mark.parametrize("change, error", [
    (lambda e: setattr(e, "http_status", 502), "public RPC http://.* answered rpc_methods with HTTP 502"),
    (lambda e: setattr(e, "upgrade", False), "public RPC ws://.*: rpc_methods failed"),
    (lambda e: e.answers["http"].update(rpc_methods={"error": {"code": -32601, "message": "Method not found"}}),
     "did not answer rpc_methods with a list of methods"),
    (lambda e: e.methods.update(http={"methods": "all"}), "did not answer rpc_methods with a list of methods"),
    (lambda e: e.methods.update(ws=[1, 2]), "did not answer rpc_methods with a list of methods"),
    (lambda e: e.answers["ws"].update(system_peers={"error": {"code": -32999, "message": "rate limited"}}),
     "answered system_peers with error -32999: the preflight cannot resolve whether it serves unsafe methods"),
    (lambda e: e.answers["http"].update(system_peers={"error": "unsafe"}), "did not answer system_peers as JSON-RPC"),
    (lambda e: e.answers["http"].update(system_peers={"error": {"message": "unsafe"}}),
     "did not answer system_peers as JSON-RPC"),
    (lambda e: e.answers["ws"].update(system_peers={"error": {"code": "-32601", "message": "unsafe"}}),
     "did not answer system_peers as JSON-RPC"),
])
def test_a_public_endpoint_the_preflight_cannot_read_is_an_input_error(endpoint, change, error):
    change(endpoint)
    with pytest.raises(lp.InputError, match=error):
        public_findings(endpoint.url)


@pytest.mark.parametrize("change", [
    {"id": True}, {"id": 2}, {"id": "1"}, {"jsonrpc": "1.0"}, {"error": {"code": -32601, "message": "x"}},
])
def test_an_answer_that_is_not_a_json_rpc_answer_to_the_call_is_an_input_error(endpoint, monkeypatch, change):
    answer = endpoint.answer
    monkeypatch.setattr(endpoint, "answer", lambda call, transport: dict(answer(call, transport), **change))
    with pytest.raises(lp.InputError, match="did not answer rpc_methods as JSON-RPC 2.0"):
        public_findings(endpoint.url)


def test_a_websocket_answer_after_notifications_is_read(endpoint):
    endpoint.ws_notifications = lp.PUBLIC_RPC_MESSAGES - 1
    assert public_findings(endpoint.url) == []


def test_a_websocket_that_sends_no_answer_is_an_input_error(endpoint):
    endpoint.ws_notifications = lp.PUBLIC_RPC_MESSAGES
    with pytest.raises(lp.InputError, match=f"sent no answer to rpc_methods in {lp.PUBLIC_RPC_MESSAGES} messages"):
        public_findings(endpoint.url)


@pytest.mark.parametrize("transport", ["http", "ws"])
def test_an_answer_over_the_size_limit_is_an_input_error(endpoint, monkeypatch, transport):
    monkeypatch.setattr(lp, "PUBLIC_RPC_LIMIT", 256)
    if transport == "ws":
        endpoint.methods["http"] = ["rpc_methods"]
    with pytest.raises(lp.InputError, match=f"public RPC {transport}://.*rpc_methods.* 256 bytes"):
        public_findings(endpoint.url)


# A proxy the environment names would stand between the probe and the URL.
def test_the_probe_reaches_each_url_directly_whatever_proxy_the_environment_names(endpoint, monkeypatch):
    for name in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    assert public_findings(endpoint.url) == []


def test_an_unreachable_public_rpc_url_is_an_input_error():
    with pytest.raises(lp.InputError, match="public RPC http://127.0.0.1:9/rpc: rpc_methods failed"):
        public_findings("http://127.0.0.1:9/rpc")


@pytest.mark.parametrize("urls, error", [
    ("https://rpc.example.org", "public_rpc must be a list of URLs"),
    (["ftp://rpc.example.org"], "public_rpc\\[0\\] must be an http, https, ws or wss URL"),
    (["rpc.example.org:443"], "public_rpc\\[0\\] must be an http, https, ws or wss URL"),
    (["https:///rpc"], "public_rpc\\[0\\] must be an http, https, ws or wss URL"),
    (["https://user:pw@rpc.example.org"], "public_rpc\\[0\\] must name no user, password or fragment"),
    (["https://rpc.example.org/#x"], "public_rpc\\[0\\] must name no user, password or fragment"),
    (["https://rpc.example.org:99999"], "public_rpc\\[0\\] must be an http, https, ws or wss URL"),
])
def test_a_malformed_public_rpc_list_is_an_input_error(urls, error):
    with pytest.raises(lp.InputError, match=error):
        lp.validate_launch({"roles": {}, "supply": VALID_LOCK, "public_rpc": urls})


# ---------------------------------------------------------------------------
# Rule 4: endowments and supply
# ---------------------------------------------------------------------------

# A preprod cert-daemon account. Its chain-spec source endows BondRequirement +
# 100 MATRA; the genesis preprod actually launched with gave it 100 MATRA.
PREPROD_ATTESTOR = bytes.fromhex("44f3bafbc393f24fcfabbf57d4ca73a6a6b5df358cdaa9480a517a97f189964b")
FLOOR = 1_000 * MATRA + 500 + 100 * MATRA
RESERVES = {"ValidatorEmissionReserve": 150_000_000 * MATRA, "AttestationRewardReserve": 50_000_000 * MATRA}
RUNTIME_CONSTANTS = dict(RESERVES, ValidatorRewardPerEra=VALIDATOR_REWARD_PER_ERA)
# Native scripts over the key hashes 01.., 02.., 03.. and their mainnet enterprise
# addresses, as pycardano encodes and hashes them: atLeast 2 of the three keys; the
# same after slot 100; one key's signature.
LOCK_SCRIPT = ("830302838200581c" + "01" * 28 + "8200581c" + "02" * 28 + "8200581c" + "03" * 28)
SCRIPT_ADDRESS = "addr1w99zyl0mtukm2xlax6d087y52x2pjrs0wsaumrzh84gakhqnqy0wu"
TIMED_LOCK_SCRIPT = "82018282041864" + LOCK_SCRIPT
TIMED_SCRIPT_ADDRESS = "addr1w8thxxkxkj9q7vuf9z3s276u5dzvgxgt9r86txvzygx7u9crpmwwj"
ONE_KEY_SCRIPT = "8200581c" + "01" * 28
ONE_KEY_SCRIPT_ADDRESS = "addr1wx9xkldmpy849sj5y7ezg2w98gm3y0qd2pq2f8l2hxf2u7c4xydnh"
# Bech32 enterprise addresses for the payment credential 0x5c * 28: a mainnet key, a testnet script.
KEY_ADDRESS = "addr1v9w9chzut3w9chzut3w9chzut3w9chzut3w9chzut3w9chqshlgld"
TEST_SCRIPT_ADDRESS = "addr_test1wpw9chzut3w9chzut3w9chzut3w9chzut3w9chzut3w9chqzhh58g"
LOCK_TX = "5a" * 32
LOCK = {"utxo": f"{LOCK_TX}#1", "address": SCRIPT_ADDRESS, "native_script": "0x" + LOCK_SCRIPT}


def script_address(script) -> str:
    """The mainnet enterprise address of a native script, given as CBOR hex or as its decoded form."""
    raw = bytes.fromhex(script) if isinstance(script, str) else cbor2.dumps(script)
    data = bytes([0x71]) + hashlib.blake2b(b"\0" + raw, digest_size=28).digest()
    values, acc, bits = [], 0, 0
    for byte in data:
        acc, bits = (acc << 8) | byte, bits + 8
        while bits >= 5:
            bits -= 5
            values.append((acc >> bits) & 31)
    if bits:
        values.append((acc << (5 - bits)) & 31)
    hrp = [ord(c) >> 5 for c in "addr"] + [0] + [ord(c) & 31 for c in "addr"]
    checksum = lp.bech32_polymod(hrp + values + [0] * 6) ^ 1
    values += [(checksum >> 5 * (5 - i)) & 31 for i in range(6)]
    return "addr1" + "".join(lp.BECH32_CHARSET[v] for v in values)


def kupo_output(address=SCRIPT_ADDRESS, assets=None, tx=LOCK_TX, index=1, datum_hash=None) -> dict:
    """An unspent output as Kupo's /matches returns it."""
    return {"transaction_index": 0, "transaction_id": tx, "output_index": index, "address": address,
            "value": {"coins": 2_000_000, "assets": assets or {}},
            "datum_hash": datum_hash, "datum_type": "inline" if datum_hash else None, "script_hash": None,
            "created_at": {"slot_no": 1, "header_hash": "00" * 32}, "spent_at": None}


def locked(amount, address=SCRIPT_ADDRESS, unit=lp.CMATRA_UNIT) -> lp.CardanoView:
    return lp.CardanoView(lock=kupo_output(address, {unit: amount}), candidates=[], d_parameter=(0, 0))


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


GENESIS_DATUM = object()


def lock_findings(spec, lock=LOCK, output=None, datum=GENESIS_DATUM):
    """The genesis lock rule. By default the lock output sits at the declared
    address with an inline datum that is this genesis hash."""
    output = kupo_output(lock["address"], {lp.CMATRA_UNIT: 1}) if output is None else output
    datum = cbor2.dumps(lp.spec_genesis_hash(spec)) if datum is GENESIS_DATUM else datum
    cardano = lp.CardanoView(lock=output or None, candidates=[], d_parameter=(0, 0), lock_datum=datum)
    return messages(lp.check_genesis_lock(spec, {"supply": {"genesis_lock": lock}}, cardano, lp.load_well_known()))


def test_the_test_address_encoder_matches_pycardano():
    assert script_address(LOCK_SCRIPT) == SCRIPT_ADDRESS
    assert script_address(TIMED_LOCK_SCRIPT) == TIMED_SCRIPT_ADDRESS
    assert script_address(ONE_KEY_SCRIPT) == ONE_KEY_SCRIPT_ADDRESS


@pytest.mark.parametrize("script, address", [(LOCK_SCRIPT, SCRIPT_ADDRESS), (TIMED_LOCK_SCRIPT, TIMED_SCRIPT_ADDRESS)])
def test_a_lock_two_key_holders_must_sign_for_with_this_genesis_datum_passes(spec, script, address):
    assert lock_findings(spec, {"utxo": f"{LOCK_TX}#1", "address": address, "native_script": "0x" + script}) == []


ALICE_CARDANO_KEY = hashlib.blake2b(bytes.fromhex(SP_KEYRING["ed25519"]["//Alice"]), digest_size=28).digest()
K1, K2, K3 = (bytes([i]) * 28 for i in (1, 2, 3))


@pytest.mark.parametrize("script, holders", [
    ([0, K1], 1),
    ([3, 2, [[0, K1], [0, K1]]], 1),
    ([3, 2, [[0, K1], [0, ALICE_CARDANO_KEY], [0, K2]]], 1),
    ([3, 2, [[0, K1], [0, hashlib.blake2b(bytes.fromhex(PARTNER_CHAINS_CARDANO_KEY), digest_size=28).digest()]]], 1),
    ([2, [[0, K1], [3, 2, [[0, K1], [0, K2], [0, K3]]]]], 1),
    ([1, []], 0),
    ([4, 100], 0),
    ([3, 0, [[0, K1], [0, K2]]], 0),
])
def test_a_lock_fewer_than_two_key_holders_can_spend_is_refused(spec, script, holders):
    lock = {"utxo": f"{LOCK_TX}#1", "address": script_address(script),
            "native_script": "0x" + cbor2.dumps(script).hex()}
    assert lock_findings(spec, lock) == [
        f"[4 supply] the genesis lock's native script can be spent by {holders} key holder"
        f"{'' if holders == 1 else 's'} (a well-known key counts as anyone's): fewer than two can move the backing"]


def test_a_lock_no_signature_can_satisfy_passes_the_signer_count(spec):
    script = [2, []]
    lock = {"utxo": f"{LOCK_TX}#1", "address": script_address(script),
            "native_script": "0x" + cbor2.dumps(script).hex()}
    assert lock_findings(spec, lock) == []


def test_a_lock_at_another_script_than_declared_is_refused(spec):
    lock = dict(LOCK, native_script="0x" + ONE_KEY_SCRIPT)
    assert lock_findings(spec, lock) == [
        f"[4 supply] the genesis lock address {SCRIPT_ADDRESS} pays to script "
        f"{hashlib.blake2b(bytes.fromhex('00' + LOCK_SCRIPT), digest_size=28).hexdigest()}, not the declared "
        f"native script {hashlib.blake2b(bytes.fromhex('00' + ONE_KEY_SCRIPT), digest_size=28).hexdigest()}; "
        "a lock the preflight cannot read as a native script is refused"]


def test_lock_that_is_spent_or_unindexed_is_refused(spec):
    assert lock_findings(spec, output={}) == [
        f"[4 supply] the genesis lock {LOCK_TX}#1 is not an unspent output the Kupo index holds: "
        "nothing backs genesis issuance"]


def test_lock_at_a_key_address_is_refused(spec):
    lock = dict(LOCK, address=KEY_ADDRESS)
    assert lock_findings(spec, lock) == [
        f"[4 supply] the genesis lock address {KEY_ADDRESS} pays to a key: its holder can spend the backing"]


def test_lock_somewhere_other_than_declared_is_refused(spec):
    other = kupo_output(TIMED_SCRIPT_ADDRESS, {lp.CMATRA_UNIT: 1})
    assert f"[4 supply] the genesis lock {LOCK_TX}#1 sits at {TIMED_SCRIPT_ADDRESS}, not the declared " \
           f"{SCRIPT_ADDRESS}" in lock_findings(spec, output=other)


@pytest.mark.parametrize("address, reason", [
    (TEST_SCRIPT_ADDRESS, "is not a Cardano mainnet address"),
    (SCRIPT_ADDRESS[:-1] + ("q" if SCRIPT_ADDRESS[-1] != "q" else "p"), "is not a valid bech32 address"),
    ("addr1" + SCRIPT_ADDRESS[5:].upper(), "is not a valid bech32 address"),
])
def test_a_lock_address_that_is_not_a_mainnet_address_is_refused(spec, address, reason):
    assert f"[4 supply] the genesis lock address {address} {reason}" in lock_findings(spec, dict(LOCK, address=address))


@pytest.mark.parametrize("raw", ["ff", cbor2.dumps([0, b"short"]).hex(), cbor2.dumps([9, 1]).hex(),
                                 cbor2.dumps([3, True, []]).hex(), cbor2.dumps({"k": 1}).hex()])
def test_an_undecodable_lock_script_is_an_input_error(spec, raw):
    lock = dict(LOCK, address=script_address(raw), native_script="0x" + raw)
    with pytest.raises(lp.InputError, match="the genesis lock native script does not decode"):
        lock_findings(spec, lock)


def test_a_lock_with_no_inline_datum_is_refused(spec):
    assert lock_findings(spec, datum=None) == [
        f"[4 supply] the genesis lock {LOCK_TX}#1 carries no inline datum: nothing binds it to this genesis, "
        "so one lock could back two chains"]


def test_a_lock_made_for_another_genesis_is_refused(spec):
    genesis = lp.spec_genesis_hash(spec).hex()
    for datum in (cbor2.dumps(bytes(32)), cbor2.dumps([bytes.fromhex(genesis), bytes(32)]), b"\xff"):
        assert lock_findings(spec, datum=datum) == [
            f"[4 supply] the genesis lock {LOCK_TX}#1 carries a datum that is not this genesis hash 0x{genesis}: "
            "it was not made for this chain"]


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


@A_BYTE_OFF
@pytest.mark.parametrize("pallet, item", [("OrinqReceipts", "BondRequirement"), ("Balances", "TotalIssuance")])
def test_a_supply_number_stored_at_another_width_is_an_input_error(spec, runtime_meta, pallet, item, change):
    """Both are u128: 16 bytes."""
    attestors = roster(spec)
    stored = int.from_bytes(spec.value(pallet, item), "little")
    put(spec, pallet, item, stored.to_bytes(16 + change, "little"))
    with pytest.raises(lp.InputError, match="^" + re.escape(mis_sized(f"{pallet}.{item}", 16 + change, 16))):
        supply_findings(spec, runtime_meta, attestors, 100 * MATRA)


@pytest.mark.parametrize("size", [48, 79, 81])
@pytest.mark.parametrize("whose", ["an attestor", "another account"])
def test_an_account_stored_at_another_width_is_an_input_error(spec, runtime_meta, whose, size):
    """An account is AccountInfo<u32, AccountData<u128>>, 80 bytes: FRAME
    reads a shorter one as an empty account."""
    attestor = fresh_account()
    endow(spec, attestor, FLOOR)
    key = account_key(attestor if whose == "an attestor" else PREPROD_ATTESTOR)
    spec.storage[key] = (spec.storage[key] + bytes(1))[:size]
    error = mis_sized(f"System.Account value at 0x{key.hex()}", size, 80)
    with pytest.raises(lp.InputError, match="^" + re.escape(error)):
        supply_findings(spec, runtime_meta, [ss58(attestor)], 100 * MATRA)


@pytest.mark.parametrize("misfile", [lambda key: key[:32] + bytes(16) + key[48:], lambda key: key[:-1],
                                     lambda key: key + bytes(1)],
                         ids=["under another hash", "a byte short", "a byte long"])
def test_an_account_filed_under_another_key_is_an_input_error(spec, meta, runtime_meta, known, misfile):
    """The runtime finds an account under blake2_128 of it followed by its 32
    bytes; what genesis files under any other key no account holds."""
    key = account_key(PREPROD_ATTESTOR)
    wrong = misfile(key)
    spec.storage[wrong] = spec.storage.pop(key)
    error = "^" + re.escape(f"chain spec raw storage: the System.Account key 0x{wrong.hex()} is not blake2_128 of a "
                            "32-byte account followed by that account")
    with pytest.raises(lp.InputError, match=error):
        lp.check_dev_keys(spec, meta, {}, NO_CARDANO, [], known)
    with pytest.raises(lp.InputError, match=error):
        supply_findings(spec, runtime_meta, [], 0)


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


def test_every_item_the_preprod_v6_genesis_sets_is_on_the_allowlist(spec, meta):
    """Rule 4 reads which items genesis sets, not what they hold."""
    assert lp.check_genesis_storage(spec, meta) == []


@pytest.fixture
def spec240() -> tuple[lp.Spec, lp.Metadata]:
    """The preprod genesis spec 240 builds, less its :code, and that code's
    metadata trimmed to what the preflight reads. The README's Tests section
    gives the commands that build both."""
    v14 = json.loads((FIXTURES / "spec240-metadata.json").read_text())["V14"]
    return lp.load_spec(str(FIXTURES / "preprod-spec240-raw.json")), lp.Metadata.from_v14(v14)


def version_fields(version: bytes) -> tuple[bytes, int, int]:
    """The spec name, as SCALE encodes it, the spec version and the transaction version of a SCALE RuntimeVersion."""
    length, cursor = lp.read_compact(version, 0)
    name = version[:cursor + length]
    length, cursor = lp.read_compact(version, cursor + length)  # the impl name
    cursor += length
    spec_version = int.from_bytes(version[cursor + 4:cursor + 8], "little")  # past the authoring version
    count, cursor = lp.read_compact(version, cursor + 12)
    cursor += lp.API_ENTRY * count
    return name, spec_version, int.from_bytes(version[cursor:cursor + 4], "little")


def test_the_spec240_fixtures_are_the_runtime_this_source_builds(spec240):
    """The fixtures stand for the runtime this tree builds: its metadata's
    System.Version and the LastRuntimeUpgrade build-spec writes carry the spec
    and transaction versions the runtime source declares."""
    source = (HERE.parent.parent / "partnerchain" / "runtime" / "src" / "lib.rs").read_text()
    declared = [int(re.search(rf"\n\s*{field}: (\d+),", source).group(1))
                for field in ("spec_version", "transaction_version")]
    spec, meta = spec240
    name, spec_version, transaction_version = version_fields(meta.constants[("System", "Version")])
    assert (name, [spec_version, transaction_version]) == (b"\x20materios", declared)
    assert spec.value("System", "LastRuntimeUpgrade") == lp.compact(spec_version) + name


def test_every_item_the_spec240_preprod_genesis_sets_is_on_the_allowlist(spec240):
    """Rule 4 reads which items genesis sets, not what they hold: rule 7
    refuses this genesis's Root timelock delays and guardian."""
    assert lp.check_genesis_storage(*spec240) == []


@pytest.mark.parametrize("item", ["Tasks", "CounterForTasks", "NextTaskId", "PendingGuardianChange", "Approval"])
def test_a_genesis_that_starts_the_root_timelock_queue_is_refused(spec240, item):
    spec, meta = spec240
    put(spec, "RootTimelock", item, bytes(36))
    assert messages(lp.check_genesis_storage(spec, meta)) == [
        f"[4 supply] genesis sets RootTimelock.{item} (1 entry), which a mainnet genesis may not set: "
        "storage outside the genesis allowlist can hold a claim on MATRA that the supply check does not count"]


def test_a_well_known_root_timelock_guardian_is_refused(spec240, known):
    spec, meta = spec240
    spec.storage[lp.CODE_KEY] = b""
    put(spec, "RootTimelock", "Guardian", BOB)
    found = messages(lp.check_dev_keys(spec, meta, {}, NO_CARDANO, [], known))
    assert "[1 dev-keys] RootTimelock.Guardian: //Bob (sr25519) is in genesis" in found


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

    def serve(self, spec: lp.Spec, lock_output: dict | None, candidates_datum: bytes, lock=LOCK, lock_datum=b"",
              d_parameter=None):
        """The lock, and the outputs that hold the D-parameter and permissioned candidates tokens with their datums:
        a D-parameter of 32 permissioned seats and no registered one, unless the test gives its datum."""
        tx, _, index = lock["utxo"].partition("#")
        if lock_output and lock_datum:
            lock_hash = hashlib.blake2b(lock_datum, digest_size=32).hexdigest()
            lock_output = dict(lock_output, datum_hash=lock_hash, datum_type="inline")
            self.routes[f"/datums/{lock_hash}"] = {"datum": lock_datum.hex()}
        self.routes[f"/matches/{index}@{tx}?unspent"] = [lock_output] if lock_output else []
        d_policy, candidates_policy = (policy.hex() for policy in scripts_policies(spec))
        for policy, datum, holder in ((d_policy, d_parameter or d_parameter_datum(32), "dd" * 32),
                                      (candidates_policy, candidates_datum, "cc" * 32)):
            datum_hash = hashlib.blake2b(datum, digest_size=32).hexdigest()
            self.routes[f"/matches/{policy}.*?unspent"] = [
                kupo_output(TEST_SCRIPT_ADDRESS, {policy: 1}, holder, 0, datum_hash)]
            self.routes[f"/datums/{datum_hash}"] = {"datum": datum.hex()}


def scripts_policies(spec: lp.Spec) -> tuple[bytes, bytes]:
    """The D-parameter and permissioned candidates policies, the last 56 bytes of genesis
    MainChainScriptsConfiguration, read here apart from the preflight so Kupo serves them whatever it makes of the
    address before them."""
    raw = spec.value("SessionCommitteeManagement", "MainChainScriptsConfiguration")
    return raw[-2 * 28:-28], raw[-28:]


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
    datum = cbor2.dumps(bytes(32))
    kupo.serve(spec, output, genesis_candidates_datum(spec), lock_datum=datum)
    view = lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})
    assert view.lock["value"] == output["value"] and view.lock["datum_type"] == "inline"
    assert view.lock_datum == datum
    assert [c.aura for c in view.candidates] == aura_keys(spec)
    assert view.d_parameter == (32, 0)
    assert set(kupo.accept) == {"application/json"}


def test_a_lock_datum_kupo_serves_under_another_hash_is_an_input_error(spec, kupo):
    kupo.serve(spec, kupo_output(assets={lp.CMATRA_UNIT: 7}), genesis_candidates_datum(spec), lock_datum=b"\x40")
    route = next(r for r in kupo.routes if r.startswith("/datums/") and kupo.routes[r] == {"datum": "40"})
    kupo.routes[route] = {"datum": "41"}
    with pytest.raises(lp.InputError, match="does not hash to"):
        lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})


COMMITTEE_TOKENS = pytest.mark.parametrize("policy, what", [(0, "D-parameter"), (1, "permissioned candidates")])


def token_route(spec, policy: int) -> str:
    return f"/matches/{lp.committee_policies(spec)[policy].hex()}.*?unspent"


@COMMITTEE_TOKENS
def test_kupo_with_no_committee_datum_is_an_input_error(spec, kupo, policy, what):
    kupo.serve(spec, None, legacy_datum([]))
    kupo.routes[token_route(spec, policy)] = []
    with pytest.raises(lp.InputError, match=f"no unspent output holding the {what} token"):
        lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})


# The node's follower reads the output created last that holds the token under the empty asset name: the preflight
# reads one only when it is the only unspent one.
@COMMITTEE_TOKENS
def test_two_unspent_outputs_holding_a_committee_token_are_an_input_error(spec, kupo, policy, what):
    kupo.serve(spec, None, genesis_candidates_datum(spec))
    route = token_route(spec, policy)
    kupo.routes[route] = kupo.routes[route] * 2
    with pytest.raises(lp.InputError, match=f"Kupo has 2 unspent outputs holding the {what} token"):
        lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})


@COMMITTEE_TOKENS
def test_a_committee_token_under_another_asset_name_is_not_read(spec, kupo, policy, what):
    kupo.serve(spec, None, genesis_candidates_datum(spec))
    route = token_route(spec, policy)
    held = kupo.routes[route][0]
    named = lp.committee_policies(spec)[policy].hex() + ".6d617472"
    kupo.routes[route] = [dict(held, value={"coins": 2_000_000, "assets": {named: 1}})]
    with pytest.raises(lp.InputError, match=f"no unspent output holding the {what} token"):
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


@COMMITTEE_TOKENS
def test_a_spent_committee_output_is_not_read(spec, kupo, policy, what):
    kupo.serve(spec, None, genesis_candidates_datum(spec))
    route = token_route(spec, policy)
    kupo.routes[route] = [dict(kupo.routes[route][0], spent_at={"slot_no": 2, "header_hash": "11" * 32})]
    with pytest.raises(lp.InputError, match=f"no unspent output holding the {what} token"):
        lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})


def test_lock_with_a_non_integer_amount_is_an_input_error(spec, kupo):
    kupo.serve(spec, kupo_output(assets={lp.CMATRA_UNIT: "7"}), genesis_candidates_datum(spec))
    with pytest.raises(lp.InputError, match="genesis lock without an address and integer assets"):
        lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})


@pytest.mark.parametrize("pallet, item, read", [
    ("SessionCommitteeManagement", "MainChainScriptsConfiguration", lp.committee_policies),
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
# Rule 7: the Root timelock's guardian and delays
# ---------------------------------------------------------------------------

# The runtime's mainnet delays and MaxDelay, in 6-second blocks, and the delays preprod stores.
DAYS = 14_400
MAINNET_DELAYS = (DAYS, 7 * DAYS, 30 * DAYS)
MAX_DELAY = 90 * DAYS
TESTNET_DELAYS = (30, 300, 1_200)
# The keyholders of node/src/chain_spec_preprod.rs: preprod's sudo key is their 2-of-3
# multisig and its guardian their 3-of-3.
PREPROD_KEYHOLDERS = [bytes.fromhex(key) for key in (
    "5678cd421ed824dd2f8860b54da0e44b41acfd646fd813644722efd65aa65b5b",
    "44d1c084f7a17e2beb080cd51c85bc2e214cfce1914b0ad384bb4eed99e79776",
    "ea7ea02ece50453978981b20bef4ec39181349122996534d8aceb01da22f4400")]
SHARED = (": the guardian must be held by keyholders apart from the sudo key's, or whoever takes Root also holds "
          "its veto")
GUARDIAN_FLAT = ("[7 timelock] roles.guardian[0] is a single key: the guardian must be a multisig with a threshold "
                 "of at least 2, declared by its members so each one is checked")
UNDECLARED_GUARDIAN = ("[7 timelock] roles.guardian must declare the one guardian genesis names: who can veto Root "
                       "is unchecked")
NO_GUARDIAN = ("[7 timelock] genesis sets no RootTimelock.Guardian: nothing apart from the sudo key can veto the Root "
               "calls it queues")
HIDDEN_BOUNDS = ("[7 timelock] the runtime metadata declares no RootTimelock.DefaultDelays and RootTimelock.MaxDelay "
                 "the preflight can read: how long mainnet must hold Root's calls is unknown here")
GUARDIAN_POWER = "can veto Root's queued calls or co-sign them early"


def nested_members(entry) -> list[str]:
    return [f"[7 timelock] roles.guardian[0].members[{i}] is a multisig: the runtime takes the guardian's veto ahead "
            "of fee-paying calls only when a member key signs it through one as_multi, so a veto through a nested "
            "multisig can be crowded out of blocks"
            for i, member in enumerate(entry["members"]) if isinstance(member, dict)]


def delays(*blocks: int) -> bytes:
    return b"".join(block.to_bytes(4, "little") for block in blocks)


def timelock_launch(sudo_members, guardian) -> dict:
    return {"roles": {"sudo": [msig(2, *sudo_members)], "guardian": [guardian]}}


@pytest.fixture
def guarded(spec240):
    """The spec 240 preprod genesis with Root held by a 2-of-3 multisig of fresh
    keys, and the timelock guarded by a 2-of-3 multisig of other fresh keys at
    the mainnet delays."""
    spec, meta = spec240
    sudo, guardian = [fresh_account() for _ in range(3)], [fresh_account() for _ in range(3)]
    put(spec, "Sudo", "Key", lp.multisig_account(sudo, 2))
    put(spec, "RootTimelock", "Guardian", lp.multisig_account(guardian, 2))
    put(spec, "RootTimelock", "Delays", delays(*MAINNET_DELAYS))
    return spec, meta, sudo, guardian


def guardian_findings(spec, meta, sudo, entry) -> list[str]:
    """Rule 7's guardian check, with `entry` stored in genesis as the guardian and declared as roles.guardian."""
    put(spec, "RootTimelock", "Guardian", lp.role_account(entry))
    return messages(lp.check_guardian(spec, meta, timelock_launch(sudo, entry)))


def delay_findings(spec, meta, *blocks: int) -> list[str]:
    put(spec, "RootTimelock", "Delays", delays(*blocks))
    return messages(lp.check_delays(spec, meta))


def test_the_spec240_metadata_declares_the_mainnet_delays_and_their_ceiling(spec240):
    _, meta = spec240
    assert meta.constants[("RootTimelock", "DefaultDelays")] == delays(*MAINNET_DELAYS)
    assert meta.constants[("RootTimelock", "MaxDelay")] == MAX_DELAY.to_bytes(4, "little")


def test_a_guardian_apart_from_the_sudo_key_at_the_mainnet_delays_passes(guarded):
    spec, meta, sudo, guardian = guarded
    assert lp.check_guardian(spec, meta, timelock_launch(sudo, msig(2, *guardian))) == []
    assert lp.check_delays(spec, meta) == []


def test_the_spec240_preprod_timelock_is_refused_on_mainnet(spec240):
    spec, meta = spec240
    assert spec.value("Sudo", "Key") == lp.multisig_account(PREPROD_KEYHOLDERS, 2)
    launch = timelock_launch(PREPROD_KEYHOLDERS, msig(3, *PREPROD_KEYHOLDERS))
    assert messages(lp.check_guardian(spec, meta, launch)) == [
        f"[7 timelock] roles.guardian[0].members[{i}] {ss58(key)} is also roles.sudo[0].members[{i}]{SHARED}"
        for i, key in enumerate(PREPROD_KEYHOLDERS)]
    assert messages(lp.check_delays(spec, meta)) == [
        f"[7 timelock] RootTimelock.Delays holds {name} calls {blocks} blocks, below the {least} the runtime sets "
        "for mainnet" for name, blocks, least in zip(("recovery", "standard", "long"), TESTNET_DELAYS, MAINNET_DELAYS)]


def test_a_genesis_with_no_guardian_is_refused(guarded):
    """The runtime's genesis builder lets a dev sudo key go unguarded; a mainnet launch has no dev key to excuse it."""
    spec, meta, sudo, guardian = guarded
    del spec.storage[lp.storage_key("RootTimelock", "Guardian")]
    assert messages(lp.check_guardian(spec, meta, timelock_launch(sudo, msig(2, *guardian)))) == [NO_GUARDIAN]


@pytest.mark.parametrize("count", [None, 0, 2])
def test_a_guardian_not_declared_as_one_entry_is_refused(guarded, count):
    spec, meta, sudo, guardian = guarded
    launch = timelock_launch(sudo, msig(2, *guardian))
    if count is None:
        del launch["roles"]["guardian"]
    else:
        launch["roles"]["guardian"] = [msig(2, *guardian)] * count
    assert messages(lp.check_guardian(spec, meta, launch)) == [UNDECLARED_GUARDIAN]


def test_a_guardian_declared_by_its_flat_address_is_refused(guarded):
    """A wallet shows a multisig as one address; declared that way its members go unchecked."""
    spec, meta, sudo, guardian = guarded
    assert guardian_findings(spec, meta, sudo, ss58(lp.multisig_account(guardian, 2))) == [GUARDIAN_FLAT]


def test_a_guardian_one_member_can_use_alone_is_refused(guarded):
    spec, meta, sudo, guardian = guarded
    assert guardian_findings(spec, meta, sudo, msig(1, *guardian)) == [
        "[7 timelock] roles.guardian[0] has threshold 1: any one member alone can veto Root's queued calls or "
        "co-sign them early"]


@pytest.mark.parametrize("build", ONE_HOLDER_MULTISIGS, ids=lambda build: build.__name__)
def test_a_guardian_one_key_meets_alone_through_a_nested_multisig_is_refused(guarded, build):
    """One keyholder signs as_multi as itself and again as the nested multisig, so its
    threshold of 2 is nominal."""
    spec, meta, sudo, _ = guarded
    entry, holders = build()
    assert guardian_findings(spec, meta, sudo, entry) == [
        lone_holder("7 timelock", "roles.guardian[0]", key, paths, GUARDIAN_POWER) for key, paths in sorted(holders)
    ] + nested_members(entry)


@pytest.mark.parametrize("build", TWO_HOLDER_MULTISIGS, ids=lambda build: build.__name__)
def test_a_guardian_that_needs_two_keyholders_through_nested_multisigs_is_refused_for_its_nesting(guarded, build):
    spec, meta, sudo, _ = guarded
    entry = build()
    assert guardian_findings(spec, meta, sudo, entry) == nested_members(entry)


def test_a_guardian_with_a_nested_multisig_member_is_refused(guarded):
    """A nested member's veto wraps one as_multi in another, which the runtime does not take first: the runtime
    test a_veto_through_a_nested_multisig_member_is_not_taken_first shows it."""
    spec, meta, sudo, guardian = guarded
    entry = {"threshold": 2, "members": [ss58(guardian[0]), ss58(guardian[1]), msig(2, guardian[2], fresh_account())]}
    assert guardian_findings(spec, meta, sudo, entry) == [
        "[7 timelock] roles.guardian[0].members[2] is a multisig: the runtime takes the guardian's veto ahead of "
        "fee-paying calls only when a member key signs it through one as_multi, so a veto through a nested multisig "
        "can be crowded out of blocks"]


def test_a_guardian_with_more_signatories_than_the_runtime_allows_is_refused(guarded):
    """pallet_multisig refuses as_multi from a multisig of more than MaxSignatories: such a guardian never vetoes."""
    spec, meta, sudo, guardian = guarded
    assert guardian_findings(spec, meta, sudo, msig(2, *(fresh_account() for _ in range(11)))) == [
        too_many_signatories("7 timelock", "roles.guardian[0]", 11)]
    nested = {"threshold": 2, "members": [ss58(guardian[0]), msig(2, *(fresh_account() for _ in range(11)))]}
    assert guardian_findings(spec, meta, sudo, nested) == [
        too_many_signatories("7 timelock", "roles.guardian[0].members[1]", 11), *nested_members(nested)]
    assert guardian_findings(spec, meta, sudo, msig(1, *(fresh_account() for _ in range(11)))) == [
        too_many_signatories("7 timelock", "roles.guardian[0]", 11),
        f"[7 timelock] roles.guardian[0] has threshold 1: any one member alone {GUARDIAN_POWER}"]


def test_a_guardian_of_max_signatories_passes(guarded):
    spec, meta, sudo, _ = guarded
    assert guardian_findings(spec, meta, sudo, msig(2, *(fresh_account() for _ in range(10)))) == []


def test_the_signatory_bound_is_the_runtime_constant(guarded):
    spec, meta, sudo, _ = guarded
    assert meta.constants[("Multisig", "MaxSignatories")] == (10).to_bytes(4, "little")
    meta.constants[("Multisig", "MaxSignatories")] = (3).to_bytes(4, "little")
    assert guardian_findings(spec, meta, sudo, msig(2, *(fresh_account() for _ in range(3)))) == []
    assert guardian_findings(spec, meta, sudo, msig(2, *(fresh_account() for _ in range(4)))) == [
        too_many_signatories("7 timelock", "roles.guardian[0]", 4, 3)]


@pytest.mark.parametrize("value", [None, b"", bytes(8)], ids=["absent", "empty", "8 bytes"])
def test_a_guardian_under_a_runtime_that_hides_max_signatories_is_refused(guarded, value):
    spec, meta, sudo, guardian = guarded
    if value is None:
        del meta.constants[("Multisig", "MaxSignatories")]
    else:
        meta.constants[("Multisig", "MaxSignatories")] = value
    assert guardian_findings(spec, meta, sudo, msig(2, *guardian)) == [
        unknown_max_signatories("7 timelock", "roles.guardian[0]")]


def test_a_guardian_that_is_not_the_declared_multisig_is_refused(guarded):
    """A multisig holding //Alice, declared as a multisig of fresh keys."""
    spec, meta, sudo, guardian = guarded
    hidden = lp.multisig_account([ALICE, *guardian[:2]], 2)
    put(spec, "RootTimelock", "Guardian", hidden)
    assert messages(lp.check_guardian(spec, meta, timelock_launch(sudo, msig(2, *guardian)))) == [
        f"[7 timelock] RootTimelock.Guardian {ss58(hidden)} is not the account roles.guardian declares: "
        "who can veto Root is unchecked"]


def test_a_guardian_multisig_with_a_dev_member_is_refused(guarded, known):
    """Genesis holds only the multisig's account, a hash; rule 1 finds the dev key among the declared members."""
    spec, meta, sudo, guardian = guarded
    entry = msig(2, ALICE, *guardian[:2])
    assert guardian_findings(spec, meta, sudo, entry) == []
    spec.storage[lp.CODE_KEY] = b""
    found = messages(lp.check_dev_keys(spec, meta, timelock_launch(sudo, entry), NO_CARDANO, [], known))
    assert "[1 dev-keys] roles.guardian[0].members[0]: //Alice (sr25519)" in found
    assert not any("RootTimelock.Guardian" in m for m in found)


def test_a_guardian_that_is_the_sudo_key_is_refused(guarded):
    spec, meta, sudo, _ = guarded
    found = guardian_findings(spec, meta, sudo, msig(2, *sudo))
    assert found[0] == "[7 timelock] RootTimelock.Guardian is Sudo.Key: the sudo key would veto and co-sign its own " \
                       "Root calls"
    account = ss58(lp.multisig_account(sudo, 2))
    assert found[1] == f"[7 timelock] roles.guardian[0] {account} is also roles.sudo[0]{SHARED}"


def test_a_guardian_of_the_sudo_keyholders_under_another_threshold_is_refused(guarded):
    spec, meta, sudo, _ = guarded
    assert guardian_findings(spec, meta, sudo, msig(3, *sudo)) == [
        f"[7 timelock] roles.guardian[0].members[{i}] {ss58(key)} is also roles.sudo[0].members[{i}]{SHARED}"
        for i, key in enumerate(sudo)]


def test_a_guardian_sharing_one_keyholder_with_the_sudo_key_is_refused(guarded):
    spec, meta, sudo, guardian = guarded
    assert guardian_findings(spec, meta, sudo, msig(2, sudo[1], *guardian[:2])) == [
        f"[7 timelock] roles.guardian[0].members[0] {ss58(sudo[1])} is also roles.sudo[0].members[1]{SHARED}"]


def test_a_guardian_with_the_sudo_account_as_a_member_is_refused(guarded):
    spec, meta, sudo, guardian = guarded
    account = lp.multisig_account(sudo, 2)
    assert guardian_findings(spec, meta, sudo, msig(2, account, guardian[0])) == [
        f"[7 timelock] roles.guardian[0].members[0] {ss58(account)} is also roles.sudo[0]{SHARED}"]


def test_a_sudo_keyholder_nested_inside_the_guardian_is_refused(guarded):
    spec, meta, sudo, guardian = guarded
    entry = {"threshold": 2, "members": [msig(2, sudo[2], guardian[0]), ss58(guardian[1])]}
    assert guardian_findings(spec, meta, sudo, entry) == [
        *nested_members(entry), f"[7 timelock] roles.guardian[0].members[0].members[0] {ss58(sudo[2])} is also "
        f"roles.sudo[0].members[2]{SHARED}"]


def test_a_guardian_member_that_is_the_genesis_sudo_key_is_refused_when_roles_sudo_does_not_say_so(guarded):
    spec, meta, _, guardian = guarded
    key = fresh_account()
    put(spec, "Sudo", "Key", key)
    entry = msig(2, key, *guardian[:2])
    put(spec, "RootTimelock", "Guardian", lp.role_account(entry))
    assert messages(lp.check_guardian(spec, meta, {"roles": {"guardian": [entry]}})) == [
        f"[7 timelock] roles.guardian[0].members[0] {ss58(key)} is also Sudo.Key{SHARED}"]


def test_a_guardian_key_that_does_not_decode_leaves_its_refusal_to_rule_1(guarded):
    spec, meta, sudo, guardian = guarded
    entry = {"threshold": 2, "members": ["//Bob", ss58(guardian[0])]}
    assert lp.check_guardian(spec, meta, timelock_launch(sudo, entry)) == []


def test_a_guardian_key_that_does_not_decode_leaves_the_rest_of_rule_7_standing(guarded):
    spec, meta, sudo, guardian = guarded
    entry = {"threshold": 2, "members": ["//Bob", ss58(guardian[0])]}
    launch = timelock_launch(sudo, entry)
    put(spec, "RootTimelock", "Guardian", spec.value("Sudo", "Key"))
    assert messages(lp.check_guardian(spec, meta, launch)) == [
        "[7 timelock] RootTimelock.Guardian is Sudo.Key: the sudo key would veto and co-sign its own Root calls"]
    del spec.storage[lp.storage_key("RootTimelock", "Guardian")]
    assert messages(lp.check_guardian(spec, meta, launch)) == [NO_GUARDIAN]
    oversized = {"threshold": 2, "members": ["//Bob", *(ss58(fresh_account()) for _ in range(10))]}
    assert messages(lp.check_guardian(spec, meta, timelock_launch(sudo, oversized))) == [
        NO_GUARDIAN, too_many_signatories("7 timelock", "roles.guardian[0]", 11)]


def test_a_sudo_key_that_does_not_decode_leaves_the_guardian_checked(guarded):
    spec, meta, sudo, guardian = guarded
    hidden = lp.multisig_account([ALICE, *guardian[:2]], 2)
    put(spec, "RootTimelock", "Guardian", hidden)
    launch = {"roles": {"sudo": [{"threshold": 2, "members": ["//Alice", ss58(sudo[0])]}],
                        "guardian": [msig(2, *guardian)]}}
    assert messages(lp.check_guardian(spec, meta, launch)) == [
        f"[7 timelock] RootTimelock.Guardian {ss58(hidden)} is not the account roles.guardian declares: "
        "who can veto Root is unchecked"]


def test_the_mainnet_delays_and_delays_up_to_max_delay_pass(spec240):
    spec, meta = spec240
    assert delay_findings(spec, meta, *MAINNET_DELAYS) == []
    assert delay_findings(spec, meta, MAX_DELAY, MAX_DELAY, MAX_DELAY) == []


@pytest.mark.parametrize("index, name", enumerate(("recovery", "standard", "long")))
def test_a_delay_one_block_below_the_mainnet_delay_is_refused(spec240, index, name):
    spec, meta = spec240
    blocks = [*MAINNET_DELAYS]
    blocks[index] -= 1
    assert delay_findings(spec, meta, *blocks) == [
        f"[7 timelock] RootTimelock.Delays holds {name} calls {blocks[index]} blocks, below the "
        f"{MAINNET_DELAYS[index]} the runtime sets for mainnet"]


@pytest.mark.parametrize("long", [MAX_DELAY + 1, 2**32 - 1])
def test_a_long_delay_above_max_delay_is_refused(spec240, long):
    spec, meta = spec240
    assert delay_findings(spec, meta, DAYS, 7 * DAYS, long) == [
        f"[7 timelock] RootTimelock.Delays holds long calls {long} blocks, above the runtime's MaxDelay {MAX_DELAY}: "
        "a guardian change, or a cut to the long delay itself, would wait longer than the runtime lets any delay be"]


def test_delays_out_of_the_runtime_order_are_refused(spec240):
    spec, meta = spec240
    assert delay_findings(spec, meta, 20 * DAYS, 7 * DAYS, 30 * DAYS) == [
        f"[7 timelock] RootTimelock.Delays (recovery {20 * DAYS}, standard {7 * DAYS}, long {30 * DAYS} blocks) "
        "breaks the order 0 < recovery <= standard <= long that the runtime's genesis builder asserts"]


def test_a_standard_delay_above_the_long_delay_is_refused_within_every_other_bound(spec240):
    """Each delay at least its mainnet delay and long at most MaxDelay: only the order refuses."""
    spec, meta = spec240
    assert delay_findings(spec, meta, DAYS, 60 * DAYS, 30 * DAYS) == [
        f"[7 timelock] RootTimelock.Delays (recovery {DAYS}, standard {60 * DAYS}, long {30 * DAYS} blocks) "
        "breaks the order 0 < recovery <= standard <= long that the runtime's genesis builder asserts"]


def test_zero_delays_are_refused(spec240):
    spec, meta = spec240
    found = delay_findings(spec, meta, 0, 0, 0)
    assert len(found) == 4
    assert "[7 timelock] RootTimelock.Delays holds recovery calls 0 blocks, below the 14400 the runtime sets for " \
           "mainnet" in found
    assert found[-1].startswith("[7 timelock] RootTimelock.Delays (recovery 0, standard 0, long 0 blocks) breaks")


def test_the_bounds_are_the_runtime_constants(spec240):
    spec, meta = spec240
    meta.constants[("RootTimelock", "DefaultDelays")] = delays(10, 20, 30)
    meta.constants[("RootTimelock", "MaxDelay")] = (40).to_bytes(4, "little")
    assert delay_findings(spec, meta, 10, 20, 40) == []
    assert delay_findings(spec, meta, 10, 19, 41) == [
        "[7 timelock] RootTimelock.Delays holds standard calls 19 blocks, below the 20 the runtime sets for mainnet",
        "[7 timelock] RootTimelock.Delays holds long calls 41 blocks, above the runtime's MaxDelay 40: a guardian "
        "change, or a cut to the long delay itself, would wait longer than the runtime lets any delay be"]


@pytest.mark.parametrize("constants", [
    {"DefaultDelays": None}, {"MaxDelay": None}, {"DefaultDelays": None, "MaxDelay": None},
    {"DefaultDelays": bytes(11)}, {"MaxDelay": b""},
])
def test_a_runtime_that_hides_its_timelock_bounds_is_refused(spec240, constants):
    spec, meta = spec240
    for name, value in constants.items():
        if value is None:
            del meta.constants[("RootTimelock", name)]
        else:
            meta.constants[("RootTimelock", name)] = value
    assert messages(lp.check_delays(spec, meta)) == [HIDDEN_BOUNDS]


def test_a_runtime_with_no_root_timelock_is_refused(spec, meta):
    assert messages(lp.check_delays(spec, meta)) == [HIDDEN_BOUNDS]
    assert NO_GUARDIAN in messages(lp.check_guardian(spec, meta, {"roles": {}}))


@pytest.mark.parametrize("raw", [b"", bytes(11), bytes(13), bytes(24)], ids=lambda raw: f"{len(raw)} bytes")
def test_delays_that_do_not_decode_are_refused(spec240, raw):
    spec, meta = spec240
    put(spec, "RootTimelock", "Delays", raw)
    assert messages(lp.check_delays(spec, meta)) == [
        f"[7 timelock] RootTimelock.Delays is {len(raw)} bytes, not three 4-byte block counts"]


def test_a_genesis_that_stores_no_delays_is_refused(spec240):
    spec, meta = spec240
    del spec.storage[lp.storage_key("RootTimelock", "Delays")]
    assert messages(lp.check_delays(spec, meta)) == [
        "[7 timelock] genesis sets no RootTimelock.Delays, which every genesis the runtime builds sets: how long "
        "Root's calls wait is unchecked"]


# ---------------------------------------------------------------------------
# Rule 8: the genesis each authority's own node binary builds
# ---------------------------------------------------------------------------

# materios-node export-blocks, answering what the attestation asks: block 0 of the chain its --chain names, a raw
# spec file or a chain built into the node, written as export-blocks --binary writes it. It builds a file's genesis
# with the preflight's own computation, so these tests see the attestation's plumbing; test_node_attestation.py
# runs the real node. KNOBS: tamper builds another state root, fail builds none from a file, built_in_panics none
# from a built-in chain, export writes other bytes, log records each call.
FAKE_NODE = '''#!@PYTHON@
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, @HERE@)
import launch_preflight as lp

KNOBS = @KNOBS@
if "log" in KNOBS:
    registrations = os.environ.get("MAIN_CHAIN_FOLLOWER_MOCK_REGISTRATIONS_FILE")
    chain_file = next((Path(word.partition("=")[2] or sys.argv[i + 1]) for i, word in enumerate(sys.argv)
                       if word.partition("=")[0] == "--chain"), None)
    with open(KNOBS["log"], "a") as log:
        log.write(json.dumps({"argv": sys.argv, "cwd": os.getcwd(), "cwd_files": os.listdir("."),
                              "env": dict(os.environ),
                              "registrations": registrations and Path(registrations).read_text(),
                              "chain_sha256": chain_file and chain_file.is_file()
                              and hashlib.sha256(chain_file.read_bytes()).hexdigest()}) + "\\n")
VALUED = {"--base-path", "--from", "--to", "--database", "--db", "--db-cache", "--state-pruning", "--pruning",
          "--blocks-pruning", "--keep-blocks", "--tracing-targets", "--tracing-receiver"}
FLAGS = {"--binary", "--detailed-log-output", "--disable-log-color", "--enable-log-reloading"}
args, chain, dev, out, i = sys.argv[1:], None, False, None, 1
assert args[0] == "export-blocks", args
while i < len(args):
    name, given, value = args[i].partition("=")
    if name == "--chain":
        chain, i = (value, i + 1) if given else (args[i + 1], i + 2)
    elif name in VALUED:
        i += 1 if given else 2
    elif name in ("--log", "-l") or args[i].startswith("-l"):
        i += 1
        while not given and len(name) == 2 + 3 * (name == "--log") and i < len(args) and not args[i].startswith("-"):
            i += 1
    elif args[i] == "--dev":
        dev, i = True, i + 1
    elif args[i] in FLAGS:
        i += 1
    elif args[i].startswith("-"):
        sys.exit(f"error: unexpected argument '{args[i]}' found")
    else:
        out, i = args[i], i + 1
chain = chain if chain is not None else "dev" if dev else ""
if chain in ("", "dev", "local", "preprod"):
    if KNOBS.get("built_in_panics"):
        sys.exit("Thread 'main' panicked at 'genesis authorities is non-empty; all weights are non-zero; qed.'")
    root, version = lp.blake2_256(chain.encode()), 1
elif not os.path.exists(chain):
    sys.exit(f"Error: Input(\\"Error opening spec file `{chain}`: No such file or directory (os error 2)\\")")
else:
    try:
        spec = lp.load_spec(chain)
    except lp.InputError as e:
        sys.exit(f"Error: Input(\\"Error parsing spec file: {e}\\")")
    if KNOBS.get("fail"):
        sys.exit("Error: Service(Other(\\"the fake node builds no genesis\\"))")
    version = lp.runtime_state_version(lp.decompressed_code(spec.code))
    root = lp.trie_root(spec.storage, version)
if KNOBS.get("tamper"):
    root = bytes([root[0] ^ 1]) + root[1:]
header = bytes(32) + lp.compact(0) + root + lp.trie_root({}, version) + lp.compact(0)
Path(out).write_bytes(bytes.fromhex(KNOBS["export"]) if "export" in KNOBS
                      else (2).to_bytes(8, "little") + header + b"\\0\\0")
'''


def fake_node(tmp_path: Path, **knobs) -> Path:
    path = tmp_path / ("fake-node-" + hashlib.sha256(repr(sorted(knobs.items())).encode()).hexdigest()[:12])
    path.write_text(FAKE_NODE.replace("@PYTHON@", sys.executable).replace("@HERE@", repr(str(HERE)))
                    .replace("@KNOBS@", repr(knobs)))
    path.chmod(0o755)
    return path


def sha256_pin(path: Path) -> str:
    return "0x" + hashlib.sha256(path.read_bytes()).hexdigest()


def node_calls(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


# Where an authority's machine keeps the chain spec its node loads: no file of that name is on this host.
def authority_chain(tmp_path: Path) -> str:
    return str(tmp_path / "authority-fs" / "mainnet-raw.json")


# An authority's running node's answer to chain_getBlockHash [0] on its local RPC, as curl saves it.
def served(tmp_path: Path, name: str, genesis: bytes) -> str:
    path = tmp_path / f"{name}.genesis.json"
    path.write_text(json.dumps({"jsonrpc": "2.0", "result": "0x" + genesis.hex(), "id": 1}))
    return str(path)


# What the running node answers system_chain, system_chainType and system_properties with: the name, chain type
# (Live when the spec names none) and properties (none as {}) of the chain spec it started from.
SERVED_IDENTITY = {"served_chain": ("system_chain", lambda doc: doc.get("name")),
                   "served_chain_type": ("system_chainType", lambda doc: doc.get("chainType", "Live")),
                   "served_properties": ("system_properties", lambda doc: doc.get("properties") or {})}


def answer(tmp_path: Path, name: str, field: str, result) -> str:
    """An authority's running node's JSON-RPC answer, as curl saves it from its local RPC."""
    path = tmp_path / f"{name}.{field}.json"
    path.write_text(json.dumps({"jsonrpc": "2.0", "result": result, "id": 1}))
    return str(path)


def served_identity(tmp_path: Path, name: str, doc: dict, **results) -> dict:
    """The served_chain, served_chain_type and served_properties captures of a node started from the spec `doc`,
    unless the test gives other results."""
    return {field: answer(tmp_path, name, field, results.get(field, expected(doc)))
            for field, (_, expected) in SERVED_IDENTITY.items()}


# The authority's machine booted at BOOT (/proc/stat btime) and its node process started an hour later (starttime,
# in USER_HZ ticks after boot); its chain spec path was set up a minute before that.
BOOT = 1_700_000_000
STARTED_TICKS = 3_600 * 100
STARTED = BOOT + 3_600
SET_UP = STARTED - 60
DIRECTORY, REGULAR_FILE, SYMBOLIC_LINK = 0o40755, 0o100644, 0o120777


def process_stat(started_ticks: int = STARTED_TICKS, comm: str = "materios-node") -> str:
    """/proc/<pid>/stat: the pid, the command name in parentheses, then 50 fields, starttime the 20th after them."""
    fields = ["S", "1", *["0"] * 17, str(started_ticks), *["0"] * 30]
    return f"4242 ({comm}) " + " ".join(fields) + "\n"


SYSTEM_STAT = f"cpu  1 2 3 4 5 6 7 0 0 0\ncpu0 1 2 3 4 5 6 7 0 0 0\nintr 7\nctxt 9\nbtime {BOOT}\nprocesses 4242\n"


def chain_value(argv: list[str]) -> str | None:
    """The value of the --chain an argv gives, if any."""
    for i, word in enumerate(argv):
        if word == "--chain" and i + 1 < len(argv):
            return argv[i + 1]
        if word.startswith("--chain="):
            return word.partition("=")[2]
    return None


def lookup(value: str) -> list[str]:
    """Each step of the path lookup for --chain `value`, as its stat capture names it: from the process's root
    directory for an absolute path, its working directory for a relative one."""
    parts = [part for part in value.split("/") if part not in ("", ".")]
    return ["/".join(parts[:i + 1]) for i in range(len(parts))]


def stat_lines(value: str, changed: dict | None = None, modes: dict | None = None) -> str:
    """What `stat -c '%Z %f %n'` prints for each step of the lookup of `value`: its ctime, its mode in hex and its
    name, every step a directory set up at SET_UP and the last a regular file, unless the test gives other ctimes or
    modes."""
    steps = lookup(value)
    changed, modes = changed or {}, modes or {}
    return "".join(f"{changed.get(step, SET_UP)} "
                   f"{modes.get(step, REGULAR_FILE if step == steps[-1] else DIRECTORY):x} {step}\n" for step in steps)


def process_captures(tmp_path: Path, name: str, value: str | None, changed: dict | None = None,
                     started_ticks: int = STARTED_TICKS) -> dict:
    """An authority's process_stat, system_stat and chain_spec_stat captures, for the --chain `value` its node
    process runs with."""
    paths = {field: tmp_path / f"{name}.{field}" for field in ("process_stat", "system_stat", "chain_spec_stat")}
    paths["process_stat"].write_text(process_stat(started_ticks))
    paths["system_stat"].write_text(SYSTEM_STAT)
    paths["chain_spec_stat"].write_text(stat_lines(value, changed) if value is not None else "")
    return {field: str(path) for field, path in paths.items()}


def attested(tmp_path, spec_path: Path, argv=None, exe=None, chain_spec: bytes | None = None, name="val0") -> dict:
    """An authority whose node process runs `argv`, from the binary `exe` and pinned to it, whose --chain file is a
    copy of `spec_path` unless the test gives other bytes, set up before the node started, and whose running node
    serves the genesis the preflight computes from `spec_path` and the chain it names."""
    exe = exe or fake_node(tmp_path)
    argv = argv or ["materios-node", "--validator", "--chain", authority_chain(tmp_path), "--rpc-methods", "safe"]
    copied = tmp_path / f"{name}.chain.json"
    copied.write_bytes(spec_path.read_bytes() if chain_spec is None else chain_spec)
    return dict(authority(argv, name, name), cmdline=capture(tmp_path, name, argv), exe=str(exe),
                exe_sha256=sha256_pin(exe), chain_spec=str(copied),
                served_genesis=served(tmp_path, name, lp.spec_genesis_hash(lp.load_spec(str(spec_path)))),
                **served_identity(tmp_path, name, json.loads(spec_path.read_text())),
                **process_captures(tmp_path, name, chain_value(argv)))


def node_findings(spec_path: Path, *nodes) -> list[str]:
    return messages(lp.check_node_genesis(lp.load_spec(str(spec_path)), rpc_launch(list(nodes))))


def preprod_genesis_hex(spec_path: Path) -> str:
    return lp.spec_genesis_hash(lp.load_spec(str(spec_path))).hex()


def test_an_authority_whose_node_builds_the_computed_genesis_passes(tmp_path, preprod_path):
    assert node_findings(preprod_path, attested(tmp_path, preprod_path)) == []


def test_an_authority_whose_node_builds_another_genesis_is_refused(tmp_path, preprod_path):
    node = attested(tmp_path, preprod_path, exe=fake_node(tmp_path, tamper=True))
    found = node_findings(preprod_path, node)
    assert len(found) == 1
    assert found[0].startswith("[8 node] authority val0: its node builds genesis 0x")
    assert found[0].endswith(f" from the checked chain spec, and the preflight computes 0x"
                             f"{preprod_genesis_hex(preprod_path)}: the signed genesis hash and the lock's datum "
                             "bind the preflight's, not the chain this authority starts")


REHEARSAL_GENESIS = lp.blake2_256(b"a rehearsal's genesis")


def serves_another_genesis(spec_path: Path) -> str:
    return (f"[8 node] authority val0: its running node serves genesis 0x{REHEARSAL_GENESIS.hex()} as block 0, and "
            f"the preflight computes 0x{preprod_genesis_hex(spec_path)}: it started from another chain spec, or from "
            "a database its base path already held, not the chain the signed genesis hash and the lock's datum bind")


# A fresh start from the node's argv and --chain file builds the checked genesis, and the node that runs does not:
# its base path held a database of another genesis (a rehearsal's), or its --chain file was overwritten after it
# started.
def test_an_authority_whose_running_node_serves_another_genesis_is_refused(tmp_path, preprod_path):
    node = dict(attested(tmp_path, preprod_path), served_genesis=served(tmp_path, "val0", REHEARSAL_GENESIS))
    assert node_findings(preprod_path, node) == [serves_another_genesis(preprod_path)]


def test_the_genesis_a_running_node_serves_is_checked_whatever_else_refuses(tmp_path, preprod_path):
    node = dict(attested(tmp_path, preprod_path), served_genesis=served(tmp_path, "val0", REHEARSAL_GENESIS),
                exe_sha256="0x" + hashlib.sha256(b"the release binary").hexdigest())
    found = node_findings(preprod_path, node)
    assert found[0] == serves_another_genesis(preprod_path)
    assert found[1].startswith("[8 node] authority val0 runs a node binary whose sha256 is 0x") and len(found) == 2


GENESIS_ANSWER = '{"jsonrpc": "2.0", "result": "0x%s", "id": 1}'


@pytest.mark.parametrize("answer, error", [
    (b"\xff not json", "is not JSON"),
    (b'{"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": 1}', "is not a JSON-RPC"),
    (b'{"jsonrpc": "2.0", "result": null, "id": 1}', "is not a JSON-RPC"),
    (('{"result": "0x%s", "id": 1}' % ("ab" * 32)).encode(), "is not a JSON-RPC"),
    (('["0x%s"]' % ("ab" * 32)).encode(), "is not a JSON-RPC"),
    ((GENESIS_ANSWER % ("AB" * 32)).encode(), "result is not 0x-prefixed lowercase hex"),
    ((GENESIS_ANSWER % ("ab" * 31)).encode(), "holds no 32-byte block hash"),
    (('{"jsonrpc": "2.0", "result": "0x%s", "result": "0x%s", "id": 1}' % ("ab" * 32, "cd" * 32)).encode(),
     "is not JSON: an object holds the key 'result' twice"),
], ids=["not JSON", "an error", "a null result", "no jsonrpc", "not an object", "upper case", "31 bytes",
        "two results"])
def test_a_served_genesis_capture_that_is_not_a_block_hash_answer_is_an_input_error(tmp_path, preprod_path, answer,
                                                                                    error):
    path = tmp_path / "answer.json"
    path.write_bytes(answer)
    node = dict(attested(tmp_path, preprod_path), served_genesis=str(path))
    where = re.escape(f"authority val0: served_genesis {path}")
    with pytest.raises(lp.InputError, match=f"{where}.*{re.escape(error)}"):
        node_findings(preprod_path, node)


# The red team's PoC: a node started on a spec with the checked genesis, another chain type and name and a code
# substitute, whose file was then overwritten with the checked spec. Every capture but what it serves is the checked
# launch's.
@pytest.mark.parametrize("field, result", [
    ("served_chain", "Local Testnet"),
    ("served_chain_type", "Local"),
    ("served_properties", {"ss58Format": 42, "tokenDecimals": 18, "tokenSymbol": "MATRA"}),
    ("served_properties", {"ss58Format": 42.0, "tokenDecimals": 6, "tokenSymbol": "MATRA"}),
], ids=["another name", "another chain type", "other properties", "42.0 for 42"])
def test_an_authority_whose_running_node_serves_another_chain_is_refused(tmp_path, preprod_path, field, result):
    doc = json.loads(preprod_path.read_text())
    method, expected = SERVED_IDENTITY[field]
    node = dict(attested(tmp_path, preprod_path), **{field: answer(tmp_path, "val0", field, result)})
    assert node_findings(preprod_path, node) == [
        f"[8 node] authority val0: its running node answers {method} with {json.dumps(result)}, where the checked "
        f"chain spec gives {json.dumps(expected(doc))}: it runs another chain spec than the checked one"]


# sc-chain-spec reads a spec that names no chainType as Live and one with no properties as {}.
def test_a_spec_with_no_chain_type_or_properties_is_served_as_the_node_reads_it(tmp_path, preprod_path):
    doc = json.loads(preprod_path.read_text())
    del doc["chainType"], doc["properties"]
    path = tmp_path / "bare-raw.json"
    path.write_text(json.dumps(doc))
    node = attested(tmp_path, path)
    assert json.loads(Path(node["served_chain_type"]).read_text())["result"] == "Live"
    assert json.loads(Path(node["served_properties"]).read_text())["result"] == {}
    assert node_findings(path, node) == []


@pytest.mark.parametrize("field", SERVED_IDENTITY)
@pytest.mark.parametrize("content, error", [
    (b"\xff", "is not JSON"),
    (b'{"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": 1}',
     "is not a JSON-RPC 2.0 answer with a result"),
    (b'{"result": "Materios", "id": 1}', "is not a JSON-RPC 2.0 answer with a result"),
], ids=["not JSON", "an error", "no jsonrpc"])
def test_a_served_chain_capture_that_is_not_an_answer_is_an_input_error(tmp_path, preprod_path, field, content, error):
    path = tmp_path / "answer.json"
    path.write_bytes(content)
    node = dict(attested(tmp_path, preprod_path), **{field: str(path)})
    with pytest.raises(lp.InputError, match=f"authority val0: {field} {re.escape(str(path))} {error}"):
        node_findings(preprod_path, node)


def changed_after_start(step: str, ctime: int, started: str = f"{STARTED}.00") -> str:
    return (f"[8 node] authority val0: {step}, on the path its --chain names, changed at {ctime} (its ctime), not a "
            f"full second before its node process started at {started}: the path may have named another chain spec "
            "when the node read it, and the node keeps the one it read")


# The red team's swap: the spec file overwritten once the node runs, so the file its --chain names now is the checked
# spec and the node runs what it read before.
def test_a_chain_spec_file_changed_after_its_node_started_is_refused(tmp_path, preprod_path):
    node = attested(tmp_path, preprod_path)
    step = lookup(authority_chain(tmp_path))[-1]
    node.update(process_captures(tmp_path, "val0", authority_chain(tmp_path), {step: STARTED + 5}))
    assert node_findings(preprod_path, node) == [changed_after_start(step, STARTED + 5)]


# A directory renamed into the path once the node runs moves the checked spec under the name the node read another
# spec from, and the file itself keeps its old ctime; the directory's own ctime shows the rename.
def test_a_directory_on_the_chain_spec_path_changed_after_its_node_started_is_refused(tmp_path, preprod_path):
    node = attested(tmp_path, preprod_path)
    step = lookup(authority_chain(tmp_path))[-2]
    node.update(process_captures(tmp_path, "val0", authority_chain(tmp_path), {step: STARTED + 30}))
    assert node_findings(preprod_path, node) == [changed_after_start(step, STARTED + 30)]


# The kernel reports ctime and the boot time in whole seconds, rounded down, and the start in hundredths: a step is
# refused unless it changed a full second before the earliest the process can have started.
@pytest.mark.parametrize("ctime, started_ticks, refused", [
    (STARTED - 2, STARTED_TICKS, False),
    (STARTED - 1, STARTED_TICKS, False),
    (STARTED - 1, STARTED_TICKS - 1, True),
    (STARTED, STARTED_TICKS + 50, True),
    (STARTED - 1, STARTED_TICKS + 50, False),
])
def test_a_chain_spec_path_is_refused_unless_it_changed_a_full_second_before_the_start(
        tmp_path, preprod_path, ctime, started_ticks, refused):
    node = attested(tmp_path, preprod_path)
    step = lookup(authority_chain(tmp_path))[-1]
    node.update(process_captures(tmp_path, "val0", authority_chain(tmp_path), {step: ctime}, started_ticks))
    start = BOOT * 100 + started_ticks
    assert node_findings(preprod_path, node) == (
        [changed_after_start(step, ctime, f"{start // 100}.{start % 100:02d}")] if refused else [])


@pytest.mark.parametrize("value, steps", [
    ("raw.json", ["raw.json"]),
    ("./spec//raw.json", ["spec", "spec/raw.json"]),
    ("/srv/materios/mainnet-raw.json", ["srv", "srv/materios", "srv/materios/mainnet-raw.json"]),
])
def test_the_chain_spec_path_is_checked_step_by_step_from_where_its_lookup_starts(tmp_path, preprod_path, value,
                                                                                  steps):
    assert lookup(value) == steps
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--chain", value])
    assert node_findings(preprod_path, node) == []


def test_a_chain_spec_path_that_climbs_is_an_input_error(tmp_path, preprod_path):
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--chain", "../spec/raw.json"])
    with pytest.raises(lp.InputError, match=re.escape("authority val0: --chain '../spec/raw.json' climbs with '..'")):
        node_findings(preprod_path, node)


@pytest.mark.parametrize("content", [
    "",
    f"{SET_UP} 41ed srv\n{SET_UP} 81a4 srv/mainnet-raw.json\n",
    stat_lines("/srv/other/mainnet-raw.json"),
    stat_lines("/srv/materios/mainnet-raw.json").rstrip("\n"),
    stat_lines("/srv/materios/mainnet-raw.json").replace(" 41ed ", " 41ED "),
    stat_lines("/srv/materios/mainnet-raw.json").replace(f"{SET_UP} ", f"{SET_UP}.5 ", 1),
    stat_lines("/srv/materios/mainnet-raw.json") + f"{SET_UP} 81a4 srv/materios/mainnet-raw.json\n",
], ids=["empty", "other steps", "another path", "no newline at the end", "upper-case mode", "a fraction",
        "a step twice"])
def test_a_chain_spec_stat_capture_that_does_not_list_the_lookup_is_an_input_error(tmp_path, preprod_path, content):
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--chain", "/srv/materios/mainnet-raw.json"])
    Path(node["chain_spec_stat"]).write_text(content)
    with pytest.raises(lp.InputError, match=re.escape(
            f"authority val0: chain_spec_stat {node['chain_spec_stat']} is not what stat -c '%Z %f %n' prints for "
            "each step of the lookup of --chain '/srv/materios/mainnet-raw.json': srv, srv/materios, "
            "srv/materios/mainnet-raw.json")):
        node_findings(preprod_path, node)


# The node follows a symbolic link, and a link re-pointed once it runs keeps no trace in the file it names.
@pytest.mark.parametrize("step, mode, kind", [
    ("srv/materios", SYMBOLIC_LINK, "a directory"),
    ("srv/materios/mainnet-raw.json", SYMBOLIC_LINK, "a regular file"),
    ("srv/materios/mainnet-raw.json", DIRECTORY, "a regular file"),
    ("srv", REGULAR_FILE, "a directory"),
])
def test_a_chain_spec_path_through_anything_but_directories_to_a_file_is_an_input_error(
        tmp_path, preprod_path, step, mode, kind):
    value = "/srv/materios/mainnet-raw.json"
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--chain", value])
    Path(node["chain_spec_stat"]).write_text(stat_lines(value, modes={step: mode}))
    with pytest.raises(lp.InputError, match=re.escape(
            f"authority val0: {step}, on the path its --chain names, is not {kind} (mode {mode:o}): the preflight "
            "checks a path of directories to a regular file")):
        node_findings(preprod_path, node)


@pytest.mark.parametrize("content", [
    "4242 materios-node S 1\n",
    "4242 (materios-node) S 1 0 0\n",
    process_stat().replace(f" {STARTED_TICKS} ", " 36000x "),
    process_stat().rstrip("\n"),
], ids=["no command name", "too few fields", "a starttime that is not a number", "no newline at the end"])
def test_a_process_stat_capture_that_is_not_proc_pid_stat_is_an_input_error(tmp_path, preprod_path, content):
    node = attested(tmp_path, preprod_path)
    Path(node["process_stat"]).write_text(content)
    with pytest.raises(lp.InputError, match=re.escape(f"authority val0: process_stat {node['process_stat']} is not a "
                                                      "/proc/<pid>/stat capture")):
        node_findings(preprod_path, node)


# The command name is whatever the process set, parentheses and spaces included: the fields start after the last ')'.
def test_a_process_stat_capture_is_read_past_any_command_name(tmp_path, preprod_path):
    node = attested(tmp_path, preprod_path)
    Path(node["process_stat"]).write_text(process_stat(comm="x) S 1 2 3 (y"))
    assert node_findings(preprod_path, node) == []


@pytest.mark.parametrize("content", ["cpu  1 2 3\nctxt 9\n", f"btime {BOOT}.5\n", f"btime {BOOT}\nbtime {BOOT}\n"],
                         ids=["no btime", "a fraction", "btime twice"])
def test_a_system_stat_capture_without_one_boot_time_is_an_input_error(tmp_path, preprod_path, content):
    node = attested(tmp_path, preprod_path)
    Path(node["system_stat"]).write_text(content)
    with pytest.raises(lp.InputError, match=re.escape(f"authority val0: system_stat {node['system_stat']} is not a "
                                                      "/proc/stat capture with one btime line")):
        node_findings(preprod_path, node)


# A chain built into the node is refused before its path is read: it names no file on the authority's machine.
def test_the_path_of_a_chain_built_into_the_node_is_not_read(tmp_path, preprod_path):
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--chain", "preprod"])
    del node["chain_spec_stat"], node["process_stat"], node["system_stat"]
    assert node_findings(preprod_path, node)[0].startswith("[8 node] authority val0: --chain 'preprod' builds genesis")


def test_an_authority_running_another_binary_than_its_pin_is_refused_and_that_binary_is_not_run(tmp_path,
                                                                                                preprod_path):
    log = tmp_path / "calls.jsonl"
    node = attested(tmp_path, preprod_path, exe=fake_node(tmp_path, log=str(log)))
    pinned = node["exe_sha256"]
    node["exe_sha256"] = "0x" + hashlib.sha256(b"the release binary").hexdigest()
    assert node_findings(preprod_path, node) == [
        f"[8 node] authority val0 runs a node binary whose sha256 is {pinned}, not its pinned exe_sha256 "
        f"{node['exe_sha256']}: only the pinned binary is run to attest its genesis"]
    assert node_calls(log) == []


def test_an_authority_whose_chain_spec_file_is_not_the_checked_spec_is_refused(tmp_path, preprod_path):
    other = json.loads(preprod_path.read_text())
    other["bootNodes"] = ["/dns/boot.example/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"]
    other = json.dumps(other).encode()
    found = node_findings(preprod_path, attested(tmp_path, preprod_path, chain_spec=other))
    assert found == [
        f"[8 node] authority val0: its --chain file, as captured, is not the checked chain spec (sha256 "
        f"0x{hashlib.sha256(other).hexdigest()}, the spec's 0x{hashlib.sha256(preprod_path.read_bytes()).hexdigest()})"
        ": its node loads another chain spec"]


@pytest.mark.parametrize("chain, built_in", [([], "local"), (["--dev"], "dev")], ids=["no --chain", "--dev"])
def test_an_authority_that_names_no_chain_spec_file_is_refused(tmp_path, preprod_path, chain, built_in):
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--validator", *chain, "--rpc-methods", "safe"])
    assert node_findings(preprod_path, node) == [
        f"[8 node] authority val0 gives no --chain: its node loads the chain built into it as {built_in}, not the "
        "checked chain spec"]


@pytest.mark.parametrize("words, name", [
    (["--chain", "local"], "local"), (["--chain", "dev"], "dev"), (["--chain=dev"], "dev"),
    (["--chain", "preprod"], "preprod"), (["--chain", ""], ""), (["--chain="], ""),
])
def test_a_chain_built_into_the_node_is_refused(tmp_path, preprod_path, words, name):
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--validator", *words, "--rpc-methods", "safe"])
    found = node_findings(preprod_path, node)
    assert len(found) == 1
    assert re.fullmatch(rf"\[8 node\] authority val0: --chain {re.escape(repr(name))} builds genesis 0x[0-9a-f]{{64}} "
                        rf"with no file of that name here: the node takes it as a chain built into it, not the "
                        rf"checked chain spec", found[0]), found[0]


# A chain built into the node can fail to build here (the node's local chain panics once it has built genesis), and
# a node that fails is not one that read --chain as a file: only its own error for that missing file says it did.
@pytest.mark.parametrize("words, name", [(["--chain", "local"], "local"), (["--chain="], "")])
def test_a_node_that_fails_on_a_chain_name_without_missing_that_file_is_an_input_error(
        tmp_path, preprod_path, words, name):
    node = attested(tmp_path, preprod_path, argv=["materios-node", *words],
                    exe=fake_node(tmp_path, built_in_panics=True))
    with pytest.raises(lp.InputError, match=re.escape(
            f"authority val0: its node builds no genesis from --chain {name!r} here, and does not report it as a "
            "missing file: the preflight cannot tell whether the node reads it as a file or as a chain built into it "
            "(Thread 'main' panicked at")):
        node_findings(preprod_path, node)


def test_an_authority_that_loads_its_chain_spec_by_a_relative_path_is_attested(tmp_path, preprod_path):
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--chain", "raw.json", "--validator"])
    assert node_findings(preprod_path, node) == []


def test_a_chain_spec_path_that_names_the_checked_spec_on_this_host_is_attested(tmp_path, preprod_path):
    here = tmp_path / "here-raw.json"
    here.write_bytes(preprod_path.read_bytes())
    log = tmp_path / "calls.jsonl"
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--chain", str(here)],
                    exe=fake_node(tmp_path, log=str(log)))
    assert node_findings(preprod_path, node) == []
    assert [call["argv"][call["argv"].index("--chain") + 1] == str(here) for call in node_calls(log)] == [True, False]


def test_a_chain_spec_path_that_names_another_file_on_this_host_is_an_input_error(tmp_path, preprod_path):
    here = tmp_path / "here-raw.json"
    here.write_text("{}")
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--chain", str(here)])
    with pytest.raises(lp.InputError, match=f"authority val0: --chain {re.escape(repr(str(here)))} names a file on "
                                            "this host that is not the checked chain spec"):
        node_findings(preprod_path, node)


# A file here that cannot be read (/proc/self/mem is a regular file whose first page is unmapped, so reading it fails
# for root too), and a path whose lookup fails (a name longer than a directory entry can hold).
@pytest.mark.parametrize("path, error", [
    ("/proc/self/mem", "Input/output error"),
    ("/srv/" + "x" * 256 + "/mainnet-raw.json", "File name too long"),
], ids=["an unreadable file", "a name too long"])
def test_a_chain_spec_path_this_host_cannot_read_is_an_input_error(tmp_path, preprod_path, path, error):
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--chain", path])
    with pytest.raises(lp.InputError, match=f"authority val0: cannot read --chain {re.escape(repr(path))} on this "
                                            f"host: {error}"):
        node_findings(preprod_path, node)


def test_cli_refuses_an_authority_whose_chain_spec_path_this_host_cannot_read_as_unreadable(clean, capsys):
    with_node_argv(clean, ["--chain", "/proc/self/mem"])
    code, out = clean.run(capsys)
    assert code == 2 and "authority val0: cannot read --chain '/proc/self/mem' on this host" in out, out


def test_the_node_runs_offline_on_a_fresh_base_path_with_only_the_options_export_blocks_reads(tmp_path, preprod_path):
    log = tmp_path / "calls.jsonl"
    argv = ["/usr/local/bin/materios-node", "--chain", authority_chain(tmp_path), "--base-path", "/data/materios",
            "--validator", "--name", "val0", "--port", "30333", "--bootnodes", "/ip4/10.0.0.1/tcp/30333/p2p/12D3Koo",
            "/ip4/10.0.0.2/tcp/30333/p2p/12D3Koo", "--rpc-port", "9945", "--rpc-cors", "all", "--rpc-methods", "safe",
            "--rpc-max-connections", "5000", "--pool-limit", "32768", "--pool-kbytes", "65536",
            "--keystore-path", "/data/keys", "--password-filename", "/run/pw", "--node-key-file", "/data/node-key",
            "--state-pruning", "archive", "--db", "rocksdb", "--db-cache", "1024", "-lsync=debug",
            "--telemetry-url", "wss://telemetry.example/submit 0", "--no-mdns", "--prometheus-external"]
    node = attested(tmp_path, preprod_path, argv=argv, exe=fake_node(tmp_path, log=str(log)))
    assert node_findings(preprod_path, node) == []
    calls = node_calls(log)
    assert len(calls) == 2
    for call in calls:
        base = call["argv"][call["argv"].index("--base-path") + 1]
        assert not base.startswith("/data") and "/data/materios" not in call["argv"]
        assert call["cwd_files"] == [] and base != call["cwd"]
        assert call["argv"][1:4] == ["export-blocks", "--chain", call["argv"][3]]
        assert call["argv"][4:] == ["--state-pruning", "archive", "--db", "rocksdb", "--db-cache", "1024",
                                    "-lsync=debug", "--base-path", base, "--from", "0", "--to", "0", "--binary",
                                    call["argv"][-1]]
        # Python itself adds LC_CTYPE when it coerces the C locale (PEP 538).
        assert set(call["env"]) - {"LC_CTYPE"} == {
            "USE_MAIN_CHAIN_FOLLOWER_MOCK", "MAIN_CHAIN_FOLLOWER_MOCK_REGISTRATIONS_FILE",
            "MC__FIRST_EPOCH_TIMESTAMP_MILLIS", "MC__EPOCH_DURATION_MILLIS", "MC__FIRST_EPOCH_NUMBER",
            "MC__FIRST_SLOT_NUMBER", "MC__SLOT_DURATION_MILLIS"}
        assert json.loads(call["registrations"]) == []
    as_launched, on_its_spec = calls
    assert as_launched["argv"][3] == authority_chain(tmp_path) and as_launched["chain_sha256"] is False
    assert on_its_spec["argv"][3] != authority_chain(tmp_path)
    assert on_its_spec["chain_sha256"] == hashlib.sha256(preprod_path.read_bytes()).hexdigest()


def test_authorities_that_give_their_node_the_same_options_share_its_runs(tmp_path, preprod_path):
    log = tmp_path / "calls.jsonl"
    exe = fake_node(tmp_path, log=str(log))
    chain = ["--chain", authority_chain(tmp_path)]
    nodes = [attested(tmp_path, preprod_path, argv=["materios-node", *chain, "--name", name], exe=exe, name=name)
             for name in ("val0", "val1", "val2")]
    assert node_findings(preprod_path, *nodes) == []
    assert len(node_calls(log)) == 2


NOT_GENESIS = "authority val0: its node's export of block 0 is not one genesis block"
COUNT, ROOTS = (2).to_bytes(8, "little").hex(), "33" * 64


# A block 0 export that differs from genesis in one field only: its parent, its number, its digest, what follows it.
@pytest.mark.parametrize("knobs, error", [
    ({"fail": True}, "authority val0: its node builds no genesis from the checked chain spec: Error: Service"),
    ({"export": "00"}, NOT_GENESIS),
    ({"export": COUNT + "22" * 32 + "00" + ROOTS + "00" + "0000"}, NOT_GENESIS),
    ({"export": COUNT + "00" * 32 + "04" + ROOTS + "00" + "0000"}, NOT_GENESIS),
    ({"export": COUNT + "00" * 32 + "00" + ROOTS + "04" + "0000"}, NOT_GENESIS),
    ({"export": COUNT + "00" * 32 + "00" + ROOTS + "00" + "0400"}, NOT_GENESIS),
    ({"export": COUNT + "00" * 32 + "00" + ROOTS + "00" + "000000"}, NOT_GENESIS),
], ids=["no genesis", "one byte", "a parent", "number 1", "a digest item", "an extrinsic", "a trailing byte"])
def test_a_node_that_exports_no_genesis_block_is_an_input_error(tmp_path, preprod_path, knobs, error):
    node = attested(tmp_path, preprod_path, exe=fake_node(tmp_path, **knobs))
    with pytest.raises(lp.InputError, match=re.escape(error)):
        node_findings(preprod_path, node)


# Bytes no binfmt handler claims, so no host execs them; an ELF for another machine runs where qemu-user is registered.
def test_a_binary_this_host_cannot_run_is_an_input_error(tmp_path, preprod_path):
    exe = tmp_path / "not-a-program"
    exe.write_bytes(b"not a program\n")
    exe.chmod(0o755)
    with pytest.raises(lp.InputError, match="authority val0: cannot run its node binary on this host"):
        node_findings(preprod_path, attested(tmp_path, preprod_path, exe=exe))


@pytest.mark.parametrize("field, error", [
    ("exe", "authority val0: give a copy of its running node process's /proc/<pid>/exe as exe"),
    ("chain_spec", "authority val0: give a copy of the file its node's --chain names, taken on its machine, as "
                   "chain_spec"),
    ("served_genesis", "authority val0: give its running node's answer to chain_getBlockHash [0], saved from its "
                       "local RPC, as served_genesis"),
    ("served_chain", "authority val0: give its running node's answer to system_chain, saved from its local RPC, as "
                     "served_chain"),
    ("served_chain_type", "authority val0: give its running node's answer to system_chainType, saved from its local "
                          "RPC, as served_chain_type"),
    ("served_properties", "authority val0: give its running node's answer to system_properties, saved from its local "
                          "RPC, as served_properties"),
    ("process_stat", "authority val0: give a copy of its node process's /proc/<pid>/stat as process_stat"),
    ("system_stat", "authority val0: give a copy of its machine's /proc/stat as system_stat"),
    ("chain_spec_stat", "authority val0: give what stat -c '%Z %f %n' prints for each step of the lookup of its "
                        "--chain path as chain_spec_stat"),
])
def test_an_authority_with_a_capture_missing_is_an_input_error(tmp_path, preprod_path, field, error):
    node = attested(tmp_path, preprod_path)
    del node[field]
    with pytest.raises(lp.InputError, match=re.escape(error)):
        node_findings(preprod_path, node)


CAPTURES = ["exe", "chain_spec", "served_genesis", *SERVED_IDENTITY, "process_stat", "system_stat", "chain_spec_stat"]


@pytest.mark.parametrize("field", CAPTURES)
def test_an_unreadable_capture_is_an_input_error(tmp_path, preprod_path, field):
    node = dict(attested(tmp_path, preprod_path), **{field: str(tmp_path / "missing")})
    with pytest.raises(lp.InputError, match=f"authority val0: cannot read {field} "):
        node_findings(preprod_path, node)


def test_a_spec_that_names_telemetry_endpoints_is_an_input_error(tmp_path, preprod_path):
    doc = json.loads(preprod_path.read_text())
    doc["telemetryEndpoints"] = [["wss://telemetry.example/submit", 0]]
    path = tmp_path / "telemetry-raw.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(lp.InputError, match="the chain spec names telemetryEndpoints"):
        node_findings(path, attested(tmp_path, path))


def test_a_launch_with_no_authority_runs_no_node(preprod_path):
    assert lp.check_node_genesis(lp.load_spec(str(preprod_path)), rpc_launch([])) == []


# How export-blocks is given an authority's node options: as the node reads them, each with its values.
@pytest.mark.parametrize("argv, words", [
    (["materios-node", "--chain", "a.json", "--validator"], ["--chain", "a.json"]),
    (["materios-node", "--chain=a.json", "--name", "v", "--detailed-log-output"],
     ["--chain=a.json", "--detailed-log-output"]),
    (["materios-node", "--dev", "--validator"], ["--dev"]),
    (["materios-node", "--bootnodes", "/ip4/1", "/ip4/2", "--chain", "a.json"], ["--chain", "a.json"]),
    (["materios-node", "--log", "info", "sync=debug", "--rpc-methods", "safe"], ["--log", "info", "sync=debug"]),
    (["materios-node", "--log=info", "-l", "a", "b", "-lc", "-l=d"], ["--log=info", "-l", "a", "b", "-lc", "-l=d"]),
    (["materios-node", "-d", "/data", "-d/data", "--base-path=/d", "--tmp", "--chain", "x"], ["--chain", "x"]),
    (["materios-node", "--experimental-rpc-endpoint", "listen-addr=0.0.0.0:9944", "-", "--db", "paritydb"],
     ["--db", "paritydb"]),
    (["materios-node", "--pruning", "archive", "--keep-blocks", "archive", "--database=rocksdb"],
     ["--pruning", "archive", "--keep-blocks", "archive", "--database=rocksdb"]),
    (["materios-node", "--telemetry-url", "wss://t.example/submit 0", "--password", "hunter2"], []),
])
def test_export_blocks_gets_the_node_options_it_reads_as_the_node_reads_them(argv, words):
    assert lp.attested_options(argv, "authority val0") == words


@pytest.mark.parametrize("argv, error", [
    (["materios-node", "--frobnicate"], "gives --frobnicate, an option the preflight does not know"),
    (["materios-node", "--frobnicate=hunter2"], "gives --frobnicate, an option the preflight does not know"),
    (["materios-node", "-x"], "gives -x, an option the preflight does not know"),
    (["materios-node", "--help"], "gives --help, an option the preflight does not know"),
    (["materios-node", "--", "--chain", "x"], "gives --, an option the preflight does not know"),
    (["materios-node", "export-blocks", "--chain", "x"], "word 1 of its node argv is not an option"),
    (["materios-node", "--chain", "x", "stray"], "word 3 of its node argv is not an option"),
    (["materios-node", "--chain"], "--chain takes a value its node argv does not give"),
    (["materios-node", "--name", "--chain", "x"], "--name takes a value its node argv does not give"),
    (["materios-node", "--bootnodes", "--chain", "x"], "--bootnodes takes a value its node argv does not give"),
    (["materios-node", "--validator=true"], "--validator takes no value"),
    (["materios-node", "--chain", "a", "--chain=b"], "gives --chain 2 times, which the node refuses"),
    (["materios-node", "--dev", "--chain", "a"], "gives --dev with --chain, which the node refuses"),
])
def test_a_node_argv_the_preflight_cannot_read_as_the_node_does_is_an_input_error(argv, error):
    with pytest.raises(lp.InputError, match=f"^authority val0: {re.escape(error)}"):
        lp.attested_options(argv, "authority val0")


def test_an_option_value_is_never_echoed(tmp_path):
    with pytest.raises(lp.InputError) as raised:
        lp.attested_options(["materios-node", "--password", "hunter2", "hunter3"], "authority val0")
    assert "hunter" not in str(raised.value)


def test_an_authority_node_argv_is_read_when_the_manifest_is_validated():
    node = dict(authority(["materios-node", "--chain", "x", "--frobnicate"]), exe_sha256="0x" + "ab" * 32)
    with pytest.raises(lp.InputError, match="gives --frobnicate, an option the preflight does not know"):
        lp.validate_node(node, "nodes[0]")


@pytest.mark.parametrize("pin, error", [
    (None, "nodes\\[0\\] is an authority and must pin the sha256 of its node binary as exe_sha256"),
    ("0x" + "ab" * 31, "nodes\\[0\\] is an authority and must pin the sha256 of its node binary as exe_sha256"),
    ("0x" + "AB" * 32, "nodes\\[0\\] exe_sha256 is not 0x-prefixed lowercase hex"),
])
def test_an_authority_must_pin_its_node_binary(pin, error):
    node = {k: v for k, v in authority(["materios-node", "--chain", "x"]).items() if k != "exe_sha256"}
    if pin is not None:
        node["exe_sha256"] = pin
    with pytest.raises(lp.InputError, match=error):
        lp.validate_node(node, "nodes[0]")


@pytest.mark.parametrize("field", [*CAPTURES, "exe_sha256"])
def test_node_attestation_fields_are_read_for_an_authority_only(field):
    with pytest.raises(lp.InputError, match=f"nodes\\[0\\] {field} is read for an authority only"):
        lp.validate_node({"name": "edge", "host": "edge", "authority": False, field: "x"}, "nodes[0]")


@pytest.mark.parametrize("field", CAPTURES)
def test_a_capture_that_is_not_a_path_is_an_input_error(field):
    with pytest.raises(lp.InputError, match=f"nodes\\[0\\] {field} must be the path of a capture"):
        lp.validate_node(dict(authority(["materios-node", "--chain", "x"]), **{field: 7}), "nodes[0]")


# ---------------------------------------------------------------------------
# End to end through the CLI, with the real subwasm
# ---------------------------------------------------------------------------

def subwasm() -> str:
    path = os.environ.get("SUBWASM") or shutil.which("subwasm")
    assert path, "set SUBWASM or put subwasm on PATH: the CLI tests run the real extractor"
    return path


class Launch:
    """A clean launch: the preprod genesis with //Alice removed, Root held by a
    multisig of fresh keys and its timelock guarded by a multisig of other fresh
    keys at the mainnet delays, the tuned rewards stored, one attestor endowed at
    the floor, the chain renamed, every account and authority declared, the
    authorities seated as the genesis committee, Cardano holding the lock and
    those authorities as the candidates, a public RPC URL that serves only safe
    methods, and authorities that load the spec from its own file, pinned to a
    node binary that builds the genesis the preflight computes. Every rule
    accepts it."""

    def __init__(self, preprod_path, tmp_path, kupo, endpoint):
        spec = lp.load_spec(str(preprod_path))
        del spec.storage[account_key(ALICE)]
        spec.doc.update({"name": "Materios", "id": "materios"})
        put(spec, "OrinqReceipts", "AttestationRewardPerSigner", (1 * MATRA).to_bytes(16, "little"))
        put(spec, "OrinqReceipts", "EraCapBaselineAttestorCount", (32).to_bytes(4, "little"))
        self.sudo_members = [fresh_account() for _ in range(3)]
        put(spec, "Sudo", "Key", lp.multisig_account(self.sudo_members, 2))
        guardian_members = [fresh_account() for _ in range(3)]
        put(spec, "RootTimelock", "Guardian", lp.multisig_account(guardian_members, 2))
        put(spec, "RootTimelock", "Delays", delays(*MAINNET_DELAYS))
        self.attestor = fresh_account()
        endow(spec, self.attestor, FLOOR)
        prefix = lp.storage_key("System", "Account")
        issuance = sum(int.from_bytes(v[16:32], "little") for k, v in spec.storage.items() if k.startswith(prefix))
        put(spec, "Balances", "TotalIssuance", issuance.to_bytes(16, "little"))
        self.members = genesis_members(spec)
        seat(spec, self.members)
        self.spec = spec
        self.tmp_path, self.kupo = tmp_path, kupo
        conf = tmp_path / "rpc.conf"
        conf.write_text("location / { proxy_pass http://rpc-node:9944; }")
        sudo = lp.multisig_account(self.sudo_members, 2)
        self.launch = {
            "roles": {"sudo": [msig(2, *self.sudo_members)], "guardian": [msig(2, *guardian_members)],
                      "anchor_signer": [ss58(fresh_account())],
                      "attestors": [ss58(self.attestor)], "oracle": [],
                      "endowed": [ss58(a) for a in genesis_accounts(spec) if a not in (self.attestor, sudo)]},
            "economics": dict(TUNED, fee_buffer=100 * MATRA),
            "supply": {"genesis_lock": LOCK},
            "slots_per_epoch": PREPROD_SLOTS_PER_EPOCH,
            "cardano_follower": dict(MAINNET_FOLLOWER),
            "nodes": [{"name": "edge", "host": "edge", "authority": False}],
            "rpc_proxies": [{"name": "public-rpc", "node": "edge", "kind": "nginx", "config": str(conf),
                             "other_targets": ["rpc-node:9944"]}],
            "public_rpc": [endpoint.url],
        }
        self.endpoint = endpoint
        self.lock_output = kupo_output(assets={lp.CMATRA_UNIT: issuance + 200_000_000 * MATRA})
        # None serves this genesis hash as the lock's inline datum.
        self.lock_datum = None
        self.node_exe = fake_node(tmp_path)
        self.launch["nodes"][:0] = [self.authority(f"val{i}", aura, gran)
                                    for i, (_, aura, gran) in enumerate(self.members)]
        # The argv each authority's node process runs with, where a test gives one other than its launch argv.
        self.running = {}
        # The bytes of the file each authority's --chain names, where a test gives other than the checked spec.
        self.chain_files = {}
        # The genesis each authority's running node serves, where a test gives other than the computed one.
        self.served = {}
        # What each authority's running node answers system_chain, system_chainType or system_properties with,
        # where a test gives other than the checked spec's, by capture field.
        self.answers = {}
        # The ctime of a step of each authority's --chain path, where a test gives one other than SET_UP.
        self.changed = {}
        self.launch_key = signing.SigningKey.generate()
        self.candidates = legacy_datum(self.members)
        self.d_parameter = d_parameter_datum(len(self.members))

    def authority(self, name: str, aura: bytes, grandpa: bytes) -> dict:
        """An authority that runs the fake node, pinned to it, on the spec from its own file."""
        node = authority(["materios-node", "--validator", "--chain", authority_chain(self.tmp_path), "--rpc-methods",
                          "safe"], name, name, aura)
        return dict(node, grandpa="0x" + grandpa.hex(), env=dict(MAINNET_FOLLOWER),
                    cmdline=str(self.tmp_path / f"{name}.cmdline"), exe=str(self.node_exe),
                    exe_sha256=sha256_pin(self.node_exe), chain_spec=str(self.tmp_path / f"{name}.chain.json"),
                    served_genesis=str(self.tmp_path / f"{name}.genesis.json"),
                    **{field: str(self.tmp_path / f"{name}.{field}.json") for field in SERVED_IDENTITY},
                    **{field: str(self.tmp_path / f"{name}.{field}")
                       for field in ("process_stat", "system_stat", "chain_spec_stat")})

    def spec_path(self) -> Path:
        self.spec.doc["genesis"]["raw"]["top"] = {"0x" + k.hex(): "0x" + v.hex() for k, v in self.spec.storage.items()}
        path = self.tmp_path / "clean-raw.json"
        path.write_text(json.dumps(self.spec.doc))
        return path

    def prepare(self) -> Path:
        """Write each authority's captures and the spec, serve Cardano for that spec, and return its path."""
        for node in self.launch["nodes"]:
            if node["authority"] and isinstance(node.get("argv"), list) and "cmdline" in node:
                capture(self.tmp_path, node["name"], self.running.get(node["name"], node["argv"]))
        spec_path = self.spec_path()
        for node in self.launch["nodes"]:
            if node["authority"] and "chain_spec" in node:
                Path(node["chain_spec"]).write_bytes(self.chain_files.get(node["name"], spec_path.read_bytes()))
        spec = lp.load_spec(str(spec_path))
        for node in self.launch["nodes"]:
            if node["authority"] and "served_genesis" in node:
                served(self.tmp_path, node["name"], self.served.get(node["name"], lp.spec_genesis_hash(spec)))
            if node["authority"]:
                served_identity(self.tmp_path, node["name"], spec.doc, **self.answers.get(node["name"], {}))
                running = self.running.get(node["name"], node.get("argv", []))
                process_captures(self.tmp_path, node["name"], chain_value(running), self.changed.get(node["name"]))
        datum = cbor2.dumps(lp.spec_genesis_hash(spec)) if self.lock_datum is None else self.lock_datum
        self.kupo.serve(spec, self.lock_output, self.candidates, self.launch["supply"]["genesis_lock"], datum,
                        self.d_parameter)
        return spec_path

    def run(self, capsys, key=None, manifest_key=None, extra=(), signed_launch=None) -> tuple[int, str]:
        return run_cli(self.tmp_path, self.prepare(), self.launch, capsys, self.kupo.url, key or self.launch_key,
                       manifest_key, extra, signed_launch)

    def run_respelled(self, capsys, respell) -> tuple[int, int, str]:
        """`sign`, then `check`, on this launch's spec with its raw storage then rewritten by `respell`."""
        spec_path = self.prepare()
        doc = json.loads(spec_path.read_text())
        respell(doc["genesis"]["raw"]["top"])
        spec_path.write_text(json.dumps(doc))
        return sign_and_check(self.tmp_path, spec_path, self.launch, capsys, self.kupo.url, self.launch_key)


def pin_launch_keys(monkeypatch, tmp_path, *keys: bytes) -> None:
    path = tmp_path / "launch_keys.json"
    path.write_text(json.dumps({"keys": ["0x" + key.hex() for key in keys]}))
    monkeypatch.setattr(lp, "LAUNCH_KEYS", path)


def sign_and_check(tmp_path, spec_path: Path, launch: dict, capsys, kupo_url: str, key=None, manifest_key=None,
                   extra=(), signed_launch=None) -> tuple[int, int, str]:
    """Sign with `key`, then check against the pinned launch keys, or against
    `manifest_key` given on the command line. Returns both exit codes and what
    the check printed."""
    key = key or signing.SigningKey.generate()
    seed = tmp_path / "launch.key"
    seed.write_text("0x" + key.encode().hex() + "\n")
    signed, launch_path = tmp_path / "signed.json", tmp_path / "launch.json"
    launch_path.write_text(json.dumps(signed_launch or launch))
    signing_code = lp.main(["sign", "--spec", str(spec_path), "--launch", str(launch_path), "--key", str(seed),
                            "--out", str(signed)])
    launch_path.write_text(json.dumps(launch))
    capsys.readouterr()
    given = [] if manifest_key is None else ["--manifest-key", "0x" + manifest_key.hex()]
    code = lp.main(["check", "--spec", str(spec_path), "--launch", str(launch_path),
                    "--signed-manifest", str(signed), *given, "--kupo", kupo_url, "--subwasm", subwasm(), *extra])
    captured = capsys.readouterr()
    return signing_code, code, captured.out + captured.err


def run_cli(tmp_path, spec_path: Path, launch: dict, capsys, kupo_url: str, key=None, manifest_key=None,
            extra=(), signed_launch=None) -> tuple[int, str]:
    signing_code, code, out = sign_and_check(tmp_path, spec_path, launch, capsys, kupo_url, key, manifest_key,
                                             extra, signed_launch)
    assert signing_code == 0
    return code, out


def with_timelock(metadata_v14: dict) -> dict:
    """The fixture metadata plus spec 240's RootTimelock pallet: its storage
    and the delay constants rule 7 reads."""
    v14 = copy.deepcopy(metadata_v14)
    spec240 = json.loads((FIXTURES / "spec240-metadata.json").read_text())["V14"]
    v14["pallets"].append(next(p for p in spec240["pallets"] if p["name"] == "RootTimelock"))
    return v14


@pytest.fixture
def clean(preprod_path, tmp_path, kupo, endpoint, monkeypatch, metadata_v14):
    """The spec's code is the preprod v6 runtime, which declares neither its
    emission reserves nor its validator reward per era and has no Root
    timelock, so the extractor returns its metadata with both declared and
    spec 240's timelock added."""
    monkeypatch.setattr(lp, "subwasm_metadata", lambda code, subwasm: with_timelock(with_constants(metadata_v14)))
    launch = Launch(preprod_path, tmp_path, kupo, endpoint)
    pin_launch_keys(monkeypatch, tmp_path, pub(launch.launch_key))
    return launch


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
    assert NO_GUARDIAN in out
    assert HIDDEN_BOUNDS in out


def test_cli_passes_a_clean_launch(clean, capsys):
    code, out = clean.run(capsys)
    assert out.strip() == "MAINNET LAUNCH PREFLIGHT: PASS"
    assert code == 0


def with_node_argv(clean, words) -> None:
    for node in clean.launch["nodes"]:
        if node["authority"]:
            node["argv"] = ["materios-node", "--validator", *words, "--rpc-methods", "safe"]


# The red team's PoC: an authority whose node loads a chain built into it, or another file, passed every rule.
@pytest.mark.parametrize("words, refusal", [
    ([], "[8 node] authority val0 gives no --chain: its node loads the chain built into it as local"),
    (["--chain", "local"], "[8 node] authority val0: --chain 'local' builds genesis 0x"),
    (["--chain", "dev"], "[8 node] authority val0: --chain 'dev' builds genesis 0x"),
    (["--chain=dev"], "[8 node] authority val0: --chain 'dev' builds genesis 0x"),
    (["--chain", "preprod"], "[8 node] authority val0: --chain 'preprod' builds genesis 0x"),
], ids=["no --chain (node loads local)", "--chain local", "--chain dev", "--chain=dev", "--chain preprod"])
def test_cli_refuses_an_authority_that_loads_a_chain_built_into_its_node(clean, capsys, words, refusal):
    with_node_argv(clean, words)
    code, out = clean.run(capsys)
    assert code == 1 and refusal in out, out


def test_cli_refuses_an_authority_that_loads_another_chain_spec_file(clean, capsys):
    with_node_argv(clean, ["--chain", str(clean.tmp_path / "authority-fs" / "other-raw.json")])
    clean.chain_files["val1"] = b'{"name": "another chain"}'
    code, out = clean.run(capsys)
    assert code == 1
    assert "[8 node] authority val1: its --chain file, as captured, is not the checked chain spec" in out, out


# The red team's PoC: every capture truthful, the setup command's `--chain raw.json` resolved in the unit's working
# directory and the node's in /srv/materios, so the node starts from the genesis the setup command wrote.
@pytest.mark.parametrize("setup", PRIMING_SUBCOMMANDS[:3])
def test_cli_refuses_a_launch_that_primes_the_base_path_with_a_node_subcommand(clean, capsys, setup):
    running = ["materios-node", "--validator", "--chain", "raw.json", "--base-path", "/data", "--rpc-methods", "safe"]
    for node in clean.launch["nodes"]:
        if node["authority"]:
            node["argv"] = ["sh", "-c", f"{setup}; cd /srv/materios; exec {' '.join(running)}"]
            clean.running[node["name"]] = running
    signing_code, code, out = sign_and_check(clean.tmp_path, clean.prepare(), clean.launch, capsys, clean.kupo.url,
                                             clean.launch_key)
    assert (signing_code, code) == (2, 2), out
    assert f"authority val0: its launch runs the node subcommand {setup.split()[1]!r} before its last command" in out


# The red team's PoC: an outsider's gran key in the permissioned candidates datum passed every rule.
def test_cli_refuses_a_cardano_datum_that_leaves_out_declared_authorities(clean, capsys):
    clean.candidates = legacy_datum(clean.members[:2])
    clean.d_parameter = d_parameter_datum(2)
    code, out = clean.run(capsys)
    assert code == 1, out
    for i, (_, aura, _) in enumerate(clean.members[2:], 2):
        assert off_cardano(f"val{i}", aura) in out, out


def test_cli_refuses_a_cardano_candidate_that_votes_with_a_key_no_authority_declares(clean, capsys):
    outsider = fresh_account()
    clean.candidates = legacy_datum([(bytes([2]) + fresh_account(), aura, outsider if i == 0 else gran)
                                     for i, (aura, gran) in enumerate(zip(aura_keys(clean.spec),
                                                                          grandpa_keys(clean.spec)))])
    code, out = clean.run(capsys)
    assert code == 1, out
    assert f"[9 committee] Cardano permissioned candidate 0 gran 0x{outsider.hex()} is not the grandpa key" in out


# The red team's PoC: an outsider as the genesis committee, and a candidates datum Ariadne draws no committee from, so
# every rotation seats the outsider as the only author and voter.
def test_cli_refuses_a_genesis_committee_no_authority_declares(clean, capsys):
    outsider = (cross_chain_key(), fresh_account(), fresh_account())
    put(clean.spec, "SessionCommitteeManagement", "CurrentCommittee", committee_value([outsider]))
    clean.candidates = legacy_datum(clean.members[:1])
    code, out = clean.run(capsys)
    assert code == 1, out
    assert f"[9 committee] {COMMITTEE}[0] {pair(*outsider[1:])} is not a declared authority's aura and grandpa key " \
           "pair" in out, out
    assert f"[9 committee] the permissioned candidates datum holds 1 candidate the runtime can seat, {NO_DRAW}" in out


# The red team's PoC: genesis SlotsPerEpoch 0 traps every block's initialization, and u32::MAX slots leaves block 1
# no Cardano epoch to draw from; both passed every rule.
@pytest.mark.parametrize("slots, refusal", [(0, ZERO_SLOTS), (2**32 - 1, not_dividing(2**32 - 1))])
def test_cli_refuses_a_genesis_session_that_stops_the_chain(clean, capsys, slots, refusal):
    put(clean.spec, "Sidechain", "SlotsPerEpoch", slots.to_bytes(4, "little"))
    clean.launch["slots_per_epoch"] = slots
    code, out = clean.run(capsys)
    assert code == 1 and refusal in out, out


def test_cli_refuses_a_launch_that_declares_no_session_length(clean, capsys):
    del clean.launch["slots_per_epoch"]
    code, out = clean.run(capsys)
    assert code == 1 and "[9 committee] the launch declares no slots_per_epoch" in out, out


def test_cli_refuses_a_launch_that_declares_no_cardano_follower(clean, capsys):
    del clean.launch["cardano_follower"]
    code, out = clean.run(capsys)
    assert code == 1 and NO_FOLLOWER in out, out


# The red team's PoC: an authority on another Cardano layout than mainnet's passed every rule, and its node's Ariadne
# provider never authors (a first epoch in 2030) or panics (epochs of 0 ms).
@pytest.mark.parametrize("name, value", [("MC__FIRST_EPOCH_TIMESTAMP_MILLIS", "1893456000000"),
                                         ("MC__EPOCH_DURATION_MILLIS", "0")])
def test_cli_refuses_an_authority_on_another_cardano_layout(clean, capsys, name, value):
    clean.launch["nodes"][1]["env"][name] = value
    code, out = clean.run(capsys)
    assert code == 1 and sets_other("val1", f"{name}={value}", name, MAINNET_FOLLOWER[name]) in out, out


def test_cli_refuses_a_committee_address_past_the_runtimes_bound_as_unreadable(clean, capsys):
    committee_address(clean.spec, 121)
    code, out = clean.run(capsys)
    assert code == 2 and address_past_bound(121) in out, out


@pytest.mark.parametrize("address, refusal", [(b"\xff", NOT_UTF8), (b"addr1\x00", HOLDS_NUL)], ids=["0xff", "NUL"])
def test_cli_refuses_a_committee_address_the_follower_cannot_read_as_unreadable(clean, capsys, address, refusal):
    set_committee_address(clean.spec, address)
    code, out = clean.run(capsys)
    assert code == 2 and refusal in out, out


def test_cli_refuses_a_genesis_committee_at_another_epoch(clean, capsys):
    put(clean.spec, "SessionCommitteeManagement", "CurrentCommittee", committee_value(clean.members, epoch=1))
    code, out = clean.run(capsys)
    assert code == 1 and at_epoch(1) in out, out


def test_cli_refuses_a_genesis_grandpa_set_id_other_than_0(clean, capsys):
    put(clean.spec, "Grandpa", "CurrentSetId", (2**64 - 1).to_bytes(8, "little"))
    code, out = clean.run(capsys)
    assert code == 1 and other_set_id(2**64 - 1) in out, out


def test_cli_refuses_a_d_parameter_that_seats_registered_candidates(clean, capsys):
    clean.d_parameter = d_parameter_datum(len(clean.members), 1)
    code, out = clean.run(capsys)
    assert code == 1 and "[9 committee] the D-parameter seats 1 registered candidate: " in out, out


def test_cli_refuses_a_candidates_datum_the_node_cannot_decode_as_unreadable(clean, capsys):
    clean.candidates = versioned_datum([[cc, [[b"aura", aura], [b"gran", gran]]] for cc, aura, gran in clean.members],
                                       1)
    code, out = clean.run(capsys)
    assert code == 2 and "the permissioned candidates datum has version 1" in out, out


def test_cli_refuses_the_build_spec_genesis_with_an_empty_committee(clean, capsys):
    put(clean.spec, "SessionCommitteeManagement", "CurrentCommittee", committee_value([]))
    put(clean.spec, "Session", "ValidatorsAndKeys", session_value([]))
    code, out = clean.run(capsys)
    assert code == 1 and f"[9 committee] {COMMITTEE} is empty: {EMPTY_COMMITTEE}" in out, out


def test_cli_refuses_an_authority_whose_node_builds_another_genesis(clean, capsys):
    exe = fake_node(clean.tmp_path, tamper=True)
    for node in clean.launch["nodes"]:
        if node["authority"]:
            node.update(exe=str(exe), exe_sha256=sha256_pin(exe))
    code, out = clean.run(capsys)
    assert code == 1 and "[8 node] authority val0: its node builds genesis 0x" in out, out


def test_cli_refuses_an_authority_running_another_binary_than_its_pin(clean, capsys):
    clean.launch["nodes"][0]["exe"] = str(fake_node(clean.tmp_path, tamper=True))
    code, out = clean.run(capsys)
    assert code == 1 and "[8 node] authority val0 runs a node binary whose sha256 is 0x" in out, out


def test_cli_refuses_an_authority_whose_running_node_serves_another_genesis(clean, capsys):
    clean.served["val1"] = REHEARSAL_GENESIS
    code, out = clean.run(capsys)
    assert code == 1, out
    assert f"[8 node] authority val1: its running node serves genesis 0x{REHEARSAL_GENESIS.hex()} as block 0" in out


def test_cli_refuses_an_authority_whose_running_node_serves_another_chain_name(clean, capsys):
    clean.answers["val2"] = {"served_chain": "Local Testnet", "served_chain_type": "Local"}
    code, out = clean.run(capsys)
    assert code == 1, out
    assert '[8 node] authority val2: its running node answers system_chain with "Local Testnet", where the checked ' \
           'chain spec gives "Materios"' in out
    assert '[8 node] authority val2: its running node answers system_chainType with "Local", where the checked chain ' \
           'spec gives "Live"' in out


def test_cli_refuses_an_authority_whose_chain_spec_file_changed_after_its_node_started(clean, capsys):
    step = lookup(authority_chain(clean.tmp_path))[-1]
    clean.changed["val1"] = {step: STARTED + 1}
    code, out = clean.run(capsys)
    assert code == 1, out
    assert f"[8 node] authority val1: {step}, on the path its --chain names, changed at {STARTED + 1} (its " \
           "ctime)" in out


def test_cli_refuses_an_authority_with_no_served_genesis_as_unreadable(clean, capsys):
    del clean.launch["nodes"][0]["served_genesis"]
    code, out = clean.run(capsys)
    assert code == 2 and "authority val0: give its running node's answer to chain_getBlockHash [0]" in out, out


def test_cli_refuses_an_authority_with_no_captured_binary_as_unreadable(clean, capsys):
    del clean.launch["nodes"][0]["exe"]
    code, out = clean.run(capsys)
    assert code == 2 and "authority val0: give a copy of its running node process's /proc/<pid>/exe" in out, out


def test_cli_refuses_a_guardian_held_by_the_sudo_keyholders(clean, capsys):
    put(clean.spec, "RootTimelock", "Guardian", lp.multisig_account(clean.sudo_members, 3))
    clean.launch["roles"]["guardian"] = [msig(3, *clean.sudo_members)]
    code, out = clean.run(capsys)
    assert code == 1
    assert f"[7 timelock] roles.guardian[0].members[0] {ss58(clean.sudo_members[0])} is also " \
           f"roles.sudo[0].members[0]{SHARED}" in out


def test_cli_refuses_a_genesis_with_no_guardian(clean, capsys):
    del clean.spec.storage[lp.storage_key("RootTimelock", "Guardian")]
    code, out = clean.run(capsys)
    assert code == 1
    assert NO_GUARDIAN in out


def test_cli_refuses_the_testnet_timelock_delays(clean, capsys):
    put(clean.spec, "RootTimelock", "Delays", delays(*TESTNET_DELAYS))
    code, out = clean.run(capsys)
    assert code == 1
    assert "[7 timelock] RootTimelock.Delays holds standard calls 300 blocks, below the 100800 the runtime sets " \
           "for mainnet" in out


def respell_timelock(misspell):
    return lambda top: top.update({key: misspell(top[key][2:]) for key in (GUARDIAN_KEY, DELAYS_KEY)})


# The red team's rule 7 exploits: raw storage the preflight read as the declared guardian and the mainnet delays,
# which the node loads as another guardian and delays past MaxDelay (a space after 0x, or no 0x and a leading byte),
# or as no guardian at all (trailing spaces make the node file it under the key followed by a zero byte).
TIMELOCK_EXPLOITS = {
    "a space after 0x": (respell_timelock(MISSPELLINGS["a space after 0x"]), f"value at {GUARDIAN_KEY}"),
    "no 0x and a leading byte": (respell_timelock(MISSPELLINGS["no 0x and a leading byte"]),
                                 f"value at {GUARDIAN_KEY}"),
    "spaces after the guardian key": (lambda top: top.update({GUARDIAN_KEY + "  ": top.pop(GUARDIAN_KEY)}),
                                      f"key '{GUARDIAN_KEY}  '"),
}


@pytest.mark.parametrize("respell, entry", TIMELOCK_EXPLOITS.values(), ids=TIMELOCK_EXPLOITS.keys())
def test_cli_refuses_a_timelock_the_node_would_load_as_other_bytes(clean, capsys, respell, entry):
    signing_code, code, out = clean.run_respelled(capsys, respell)
    assert (signing_code, code) == (2, 2), out
    assert f"MAINNET LAUNCH PREFLIGHT: REFUSE (input) chain spec raw storage {entry} {MISSPELLED}" in out


def test_cli_refuses_a_balance_the_node_would_load_4096_times_larger(clean, capsys):
    """The red team's rule 4 exploit: a space after 0x shifts every nibble of an
    account's balance, which the preflight read as within the lock."""
    extra = fresh_account()
    endow(clean.spec, extra, int.from_bytes(bytes([0x0F] * 9), "little"))
    clean.launch["roles"]["endowed"].append(ss58(extra))
    issuance = int.from_bytes(clean.spec.value("Balances", "TotalIssuance"), "little")
    clean.lock_output = kupo_output(assets={lp.CMATRA_UNIT: issuance + sum(RESERVES.values())})
    key = "0x" + account_key(extra).hex()
    signing_code, code, out = clean.run_respelled(capsys, lambda top: top.update({key: "0x " + top[key][2:]}))
    assert (signing_code, code) == (2, 2), out
    assert f"MAINNET LAUNCH PREFLIGHT: REFUSE (input) chain spec raw storage value at {key} {MISSPELLED}" in out


def cut(pallet: str, item: str, size: int):
    def edit(clean) -> tuple[str, int, int]:
        raw = clean.spec.value(pallet, item)
        put(clean.spec, pallet, item, raw[:size])
        return f"{pallet}.{item}", size, len(raw)
    return edit


def cut_attestor(size: int):
    def edit(clean) -> tuple[str, int, int]:
        key = account_key(clean.attestor)
        clean.spec.storage[key] = clean.spec.storage[key][:size]
        return f"System.Account value at 0x{key.hex()}", size, 80
    return edit


# The red team's rules 2 and 4 exploit: numbers cut to the bytes that hold them, which the preflight read as the
# declared values and FRAME, which cannot decode them as their types, reads as zero.
SHORT_SCALE = {
    "the era cap baseline in 1 byte": cut("OrinqReceipts", "EraCapBaselineAttestorCount", 1),
    "the reward per signer in 3 bytes": cut("OrinqReceipts", "AttestationRewardPerSigner", 3),
    "the issuance in 15 bytes": cut("Balances", "TotalIssuance", 15),
    "the attestor's account in 48 bytes": cut_attestor(48),
}


@pytest.mark.parametrize("edit", SHORT_SCALE.values(), ids=SHORT_SCALE.keys())
def test_cli_refuses_a_number_the_node_would_read_as_zero(clean, capsys, edit):
    where, size, width = edit(clean)
    code, out = clean.run(capsys)
    assert code == 2, out
    assert f"MAINNET LAUNCH PREFLIGHT: REFUSE (input) {mis_sized(where, size, width)}" in out


def test_cli_refuses_the_red_teams_short_scale_genesis(clean, capsys):
    for edit in SHORT_SCALE.values():
        edit(clean)
    code, out = clean.run(capsys)
    assert code == 2, out
    assert "MAINNET LAUNCH PREFLIGHT: REFUSE (input) chain spec raw storage: " in out


def set_guardian(clean, entry) -> None:
    put(clean.spec, "RootTimelock", "Guardian", lp.role_account(entry))
    clean.launch["roles"]["guardian"] = [entry]


def test_cli_refuses_a_guardian_one_keyholder_runs_through_a_nested_multisig(clean, capsys):
    entry, [(key, paths)] = repeated_member()
    set_guardian(clean, entry)
    code, out = clean.run(capsys)
    assert code == 1
    assert lone_holder("7 timelock", "roles.guardian[0]", key, paths, GUARDIAN_POWER) in out


def test_cli_refuses_root_one_keyholder_runs_through_a_nested_multisig(clean, capsys):
    entry, [(key, paths)] = repeated_member()
    put(clean.spec, "Sudo", "Key", lp.role_account(entry))
    clean.launch["roles"]["sudo"] = [entry]
    code, out = clean.run(capsys)
    assert code == 1
    assert lone_holder("1 dev-keys", "roles.sudo[0]", key, paths, SUDO_POWER) in out


@pytest.mark.parametrize("count, code", [(10, 0), (11, 1)])
def test_cli_bounds_the_guardian_by_the_runtime_max_signatories(clean, capsys, count, code):
    set_guardian(clean, msig(2, *(fresh_account() for _ in range(count))))
    exit_code, out = clean.run(capsys)
    assert exit_code == code, out
    assert (too_many_signatories("7 timelock", "roles.guardian[0]", count) in out) == (code == 1)


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


def test_cli_refuses_a_public_rpc_url_in_front_of_an_unsafe_node(clean, capsys):
    clean.endpoint.run_unsafe_node("ws")
    code, out = clean.run(capsys)
    assert code == 1
    assert f"[3 rpc] public RPC {clean.endpoint.ws_url} answers system_peers, which a node serves only with unsafe " \
           "methods on" in out


def test_cli_refuses_an_unreachable_public_rpc_url_as_unreadable(clean, capsys):
    clean.launch["public_rpc"] = ["https://127.0.0.1:9/rpc"]
    code, out = clean.run(capsys)
    assert code == 2 and "public RPC https://127.0.0.1:9/rpc: rpc_methods failed" in out


def test_cli_refuses_a_launch_that_does_not_declare_its_public_rpc(clean, capsys):
    del clean.launch["public_rpc"]
    code, out = clean.run(capsys)
    assert code == 1 and "[3 rpc] public_rpc is not declared" in out


# A node started some other way than its launch says, or a launch the preflight misread.
def test_cli_refuses_an_authority_whose_running_node_differs_from_its_launch(clean, capsys):
    clean.running["val0"] = UNSAFE_EXTERNAL.split()
    code, out = clean.run(capsys)
    assert code == 2 and "authority val0: word 2 of its running node process differs from its launch" in out


def test_cli_refuses_an_upstream_whose_port_comes_from_dns_srv_as_unreadable(clean, capsys):
    conf = clean.tmp_path / "srv.conf"
    conf.write_text(http_routes("resolver 127.0.0.1 valid=1s; upstream rpc { zone rpc 64k; "
                                "server val0 service=_rpc._tcp resolve; }", "proxy_pass http://rpc;"))
    clean.launch["nodes"][0]["argv"] = UNSAFE_9945
    clean.launch["rpc_proxies"] = [{"name": "public-rpc", "node": "val0", "kind": "nginx", "config": str(conf)}]
    code, out = clean.run(capsys)
    assert code == 2 and "server val0 takes service=_rpc._tcp; " in out and "cannot resolve" in out


def test_cli_refuses_an_include_glob_nginx_reads_apart_as_unreadable(clean, capsys):
    include_tree(clean.tmp_path)
    conf = clean.tmp_path / "nginx.conf"
    conf.write_text("events {}\nhttp { server { listen 8080; include conf.d/[^x]*.conf; } }\n")
    clean.launch["nodes"][0]["argv"] = UNSAFE_9945
    clean.launch["rpc_proxies"] = [{"name": "public-rpc", "node": "val0", "kind": "nginx", "config": str(conf)}]
    code, out = clean.run(capsys)
    assert code == 2 and "nginx include conf.d/[^x]*.conf uses '['" in out and "cannot resolve" in out


def test_cli_reads_an_authority_through_its_shell_wrapper(clean, capsys):
    running = ("materios-node --validator --rpc-methods unsafe --unsafe-rpc-external --alice "
               "--wasm-runtime-overrides /srv/o")
    clean.launch["nodes"][0]["argv"] = ["/bin/bash", "--norc", "-c", "exec " + running]
    clean.running["val0"] = running.split()
    code, out = clean.run(capsys)
    assert code == 1
    assert "[1 dev-keys] node val0: --alice loads the dev keyring" in out
    assert "[3 rpc] authority val0 serves unsafe RPC methods on an external listener" in out
    assert "[6 checkpoint] authority val0 runs --wasm-runtime-overrides" in out


def test_cli_refuses_a_login_shell_launch_as_unreadable(clean, capsys):
    signed = copy.deepcopy(clean.launch)
    clean.launch["nodes"][0]["argv"] = LOGIN_SHELL_LAUNCH
    code, out = clean.run(capsys, signed_launch=signed)
    assert code == 2
    assert "node val0: runs a login or interactive shell" in out


def test_cli_refuses_brace_expanded_node_flags_as_unreadable(clean, capsys):
    signed = copy.deepcopy(clean.launch)
    clean.launch["nodes"][0]["argv"] = ["/bin/bash", "--norc", "-c",
                                        "exec materios-node --validator {--rpc-methods=unsafe,"
                                        "--unsafe-rpc-external} {--wasm-runtime-overrides,/srv/o}"]
    code, out = clean.run(capsys, signed_launch=signed)
    assert code == 2
    assert "node val0: its shell command has a word holding '{' that the shell rewrites" in out


def test_cli_refuses_a_command_line_string_as_unreadable(clean, capsys):
    signed = copy.deepcopy(clean.launch)
    clean.launch["nodes"][0]["argv"] = "/usr/local/bin/materios-node --validator --rpc-methods unsafe " \
                                       "--unsafe-rpc-e\\x78ternal"
    code, out = clean.run(capsys, signed_launch=signed)
    assert code == 2
    assert "nodes[0] argv must be a list of strings" in out


def test_cli_refuses_unsafe_rpc_in_a_self_contained_unit(clean, capsys):
    clean.launch["nodes"][0]["argv"] = SELF_CONTAINED_LAUNCH
    clean.running["val0"] = SELF_CONTAINED_NODE
    code, out = clean.run(capsys)
    assert code == 1
    assert "[3 rpc] authority val0 serves unsafe RPC methods on an external listener" in out


def test_cli_refuses_a_lock_one_key_holder_can_spend(clean, capsys):
    clean.launch["supply"]["genesis_lock"] = dict(LOCK, address=ONE_KEY_SCRIPT_ADDRESS,
                                                  native_script="0x" + ONE_KEY_SCRIPT)
    clean.lock_output = dict(clean.lock_output, address=ONE_KEY_SCRIPT_ADDRESS)
    code, out = clean.run(capsys)
    assert code == 1
    assert "[4 supply] the genesis lock's native script can be spent by 1 key holder" in out


def test_cli_refuses_a_lock_made_for_another_genesis(clean, capsys):
    clean.lock_datum = cbor2.dumps(bytes(32))
    code, out = clean.run(capsys)
    assert code == 1
    assert f"[4 supply] the genesis lock {LOCK_TX}#1 carries a datum that is not this genesis hash" in out


def test_cli_refuses_a_lock_with_no_datum(clean, capsys):
    clean.lock_datum = b""
    code, out = clean.run(capsys)
    assert code == 1
    assert f"[4 supply] the genesis lock {LOCK_TX}#1 carries no inline datum" in out


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


def test_cli_refuses_an_authority_that_overrides_the_signed_runtime(clean, capsys):
    clean.launch["nodes"][1]["argv"] = ["materios-node", "--validator", "--rpc-methods", "safe",
                                        "--wasm-runtime-overrides", "/srv/o"]
    code, out = clean.run(capsys)
    assert code == 1
    assert "[6 checkpoint] authority val1 runs --wasm-runtime-overrides: a local runtime would replace the signed " \
           "runtime code" in out


# The red team's PoC: a GRANDPA voter no declared authority holds.
def test_cli_refuses_a_genesis_grandpa_voter_no_authority_declares(clean, capsys):
    clean.spec.storage[lp.storage_key("Grandpa", "Authorities")] = grandpa_list((fresh_account(), 1))
    code, out = clean.run(capsys)
    assert code == 1 and "is not a declared authority's grandpa key: who finalizes is unchecked" in out, out


# The red team's composition PoC: a spec version no upgrade reaches, so no later runtime runs its migrations.
def test_cli_refuses_a_last_runtime_upgrade_that_no_upgrade_reaches(clean, capsys):
    stored = clean.spec.storage[LAST_RUNTIME_UPGRADE]
    _, name = lp.read_compact(stored, 0)
    clean.spec.storage[LAST_RUNTIME_UPGRADE] = lp.compact(2**32 - 1) + stored[name:]
    code, out = clean.run(capsys)
    assert code == 1 and "[6 checkpoint] System.LastRuntimeUpgrade is 0x" in out, out


def test_cli_refuses_a_genesis_that_turns_on_the_cardano_observation(clean, capsys):
    put(clean.spec, "NativeTokenManagement", "MainChainScriptsConfiguration", ntm_scripts(SCRIPT_ADDRESS.encode()))
    code, out = clean.run(capsys)
    assert code == 1
    assert f"[6 checkpoint] genesis turns on the Cardano deposit observation for {SCRIPT_ADDRESS}" in out


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
    clean.launch["nodes"].append(clean.authority("val9", ALICE, fresh_account()))
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


def test_cli_refuses_a_launch_key_that_is_not_pinned(clean, capsys):
    other = signing.SigningKey.generate()
    code, out = clean.run(capsys, key=other, manifest_key=pub(other))
    assert code == 1
    assert out.splitlines()[1:] == [
        f"  [6 checkpoint] launch key 0x{pub(other).hex()} is not pinned in launch_keys.json: a signature under it "
        "proves only that the artifacts match the key this run was handed"]


def test_cli_refuses_a_manifest_no_pinned_key_signed(clean, capsys):
    code, out = clean.run(capsys, key=signing.SigningKey.generate())
    assert code == 1
    assert "[6 checkpoint] signed manifest signature does not verify under any launch key checked" in out


def test_cli_refuses_a_launch_when_no_key_is_pinned(clean, capsys, monkeypatch, tmp_path):
    pin_launch_keys(monkeypatch, tmp_path)
    code, out = clean.run(capsys)
    assert code == 1
    assert "[6 checkpoint] no launch key is pinned in launch_keys.json: nothing authorizes this launch" in out


def test_the_repo_pins_launch_keys_as_ed25519_public_keys():
    assert all(len(key) == 32 for key in lp.pinned_launch_keys())


@pytest.mark.parametrize("doc", [[], {"keys": "0x00"}, {"keys": ["0xzz"]}, {"keys": ["0x" + "00" * 31]}])
def test_a_malformed_launch_key_table_is_an_input_error(monkeypatch, tmp_path, doc):
    path = tmp_path / "launch_keys.json"
    path.write_text(json.dumps(doc))
    monkeypatch.setattr(lp, "LAUNCH_KEYS", path)
    with pytest.raises(lp.InputError, match="launch_keys.json"):
        lp.pinned_launch_keys()


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
    ({"roles": {}, "supply": {"genesis_lock": dict(LOCK, utxo="zz#0")}},
     "supply.genesis_lock.utxo must be <64 hex>#<index>"),
    ({"roles": {}, "supply": {"genesis_lock": {"utxo": LOCK["utxo"], "address": SCRIPT_ADDRESS}}},
     "supply.genesis_lock is required"),
    ({"roles": {}, "supply": {"genesis_lock": dict(LOCK, native_script="0xzz")}},
     f"supply.genesis_lock.native_script {MISSPELLED}"),
    ({"roles": {}, "supply": {"genesis_lock": dict(LOCK, datum="00")}}, "unknown supply.genesis_lock field datum"),
    ({"roles": {}, "supply": VALID_LOCK, "nodes": {"a": 1}}, "nodes must be a list"),
    ({"roles": {}, "supply": VALID_LOCK, "nodes": [{"name": "v1"}]}, "nodes\\[0\\] needs a name and a host"),
    ({"roles": {}, "supply": VALID_LOCK, "rpc_proxies": [{"name": "p", "node": "h", "config": "c"}]},
     "rpc_proxies\\[0\\] kind must be nginx, nginx-dump or cloudflared"),
    ({"roles": {}, "supply": VALID_LOCK, "rpc_proxies": [{"name": "p", "host": "h", "kind": "nginx", "config": "c"}]},
     "rpc_proxies\\[0\\] has unknown field host"),
    ({"roles": {}, "supply": VALID_LOCK, "nodes": [{"name": "h", "host": "h", "authority": False}],
      "rpc_proxies": [{"name": "p", "node": "h", "kind": "nginx", "config": "c", "other_targets": ["h"]}]},
     "rpc_proxies\\[0\\] other_targets must be host:port strings"),
    ({"roles": {}, "supply": VALID_LOCK, "rpc_proxies": {"p": 1}}, "rpc_proxies must be a list"),
    ({"roles": {}, "supply": VALID_LOCK,
      "nodes": [{"name": "v1", "host": "h", "authority": True, "aura": "0x" + "11" * 32, "addresses": "10.0.0.1"}]},
     "nodes\\[0\\] addresses must be a list of strings"),
    ({"roles": {}, "supply": VALID_LOCK,
      "nodes": [{"name": "v1", "host": "h", "argv": ["materios-node", "--validator"]}]},
     "nodes\\[0\\] must declare authority as true or false"),
    ({"roles": {}, "supply": VALID_LOCK, "nodes": [{"name": "v1", "host": "h", "authority": True}]},
     "nodes\\[0\\] is an authority and must declare its aura public key"),
    ({"roles": {}, "supply": VALID_LOCK,
      "nodes": [{"name": "v1", "host": "h", "authority": False, "env": ["SIGNER_URI=//Alice"]}]},
     "nodes\\[0\\] env must map names to strings"),
    ({"roles": {}, "supply": VALID_LOCK, "nodes": [{"name": "v1", "host": "h", "authority": False, "argv": 7}]},
     "nodes\\[0\\] argv must be a list of strings"),
])
def test_malformed_launch_manifest_is_an_input_error(launch, error):
    with pytest.raises(lp.InputError, match=error):
        lp.validate_launch(launch)


@pytest.mark.parametrize("manifest_key", ["0xzz", "0x" + "00" * 31])
def test_malformed_manifest_key_is_an_input_error(manifest_key):
    with pytest.raises(lp.InputError, match="--manifest-key"):
        lp.parse_launch_key(manifest_key)


def test_non_numeric_rpc_port_is_an_input_error(tmp_path):
    with pytest.raises(lp.InputError, match="is not a port"):
        rpc_findings(tmp_path, [authority(["materios-node", "--rpc-port", "nine"])])


def test_decompression_bomb_is_an_input_error(monkeypatch):
    monkeypatch.setattr(lp, "CODE_BOMB_LIMIT", 1024)
    bomb = lp.ZSTD_PREFIX + zstandard.ZstdCompressor().compress(bytes(4096))
    with pytest.raises(lp.InputError, match="bomb limit"):
        lp.decompressed_code(bomb)


def test_runtime_code_at_the_bomb_limit_decompresses(monkeypatch):
    monkeypatch.setattr(lp, "CODE_BOMB_LIMIT", 1024)
    code = bytes(range(256)) * 4
    assert lp.decompressed_code(lp.ZSTD_PREFIX + zstd_frame(code)) == code
    with pytest.raises(lp.InputError, match="bomb limit"):
        lp.decompressed_code(lp.ZSTD_PREFIX + zstd_frame(code + b"\0"))


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
